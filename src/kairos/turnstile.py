"""Cloudflare Turnstile on the anonymous accountless surface — obligation A1, issue #31.

**The hole this closes.** `POST {prefix}/new` in `KAIROS_AUTH=capability` is the
only unauthenticated poll-creation path in Kairos, and in that mode a created
poll immediately sends mail — the manage link, from the operator's own sender
and domain, to an address the caller chose. A per-IP rate limit does not change
the shape of that: it bounds one source and a motivated attacker has thousands.
A human check bounds *creating a poll at all*, which is what A2's send-gate then
hangs off.

**Where the check runs, and why it is not middleware.** Two POSTs, both inside
`KAIROS_AUTH=capability`, both anonymous:

    POST {prefix}/new           a creator's whole poll
    POST {prefix}/manage/link   "mail me a new link" for an address that already
                                created a poll here — #68 flagged this one as
                                having no abuse owner at all, and it is a
                                nuisance-mail cannon pointed at an arbitrary
                                victim address (see that route's docstring)

Each calls `verify()` directly rather than through a FastAPI middleware,
because the position matters and a middleware cannot choose it. The check has to
come **after** the CSRF token (cheap, local, and it rejects drive-bys without a
network round trip) and **before** the expensive work — before the slot grid is
expanded on `/new`, before any row is written, before any SMTP connection is
opened. A middleware runs either side of both, or neither.

**The browser's `success` is a claim, not a fact.** `cf-turnstile-response` is
whatever the page chose to send. The only thing that decides is a server-side
`siteverify` POST to Cloudflare carrying the *secret*, and `verify()` treats
every answer other than `success: true` plus a matching `action` (and hostname,
when configured) as a refusal.

**Fail closed, including when Cloudflare is unreachable.** Every refusal shape —
absent token, garbage token, a token already spent, a token minted for the other
form, a token whose `secret` is wrong, a DNS failure, a 500 — answers "no", and
an unreachable verifier is the same answer. The reasoning is in `verify()`; the
short version is that the availability cost is one env var away and visible in a
boot log, while a fail-open here is the whole problem this issue exists to
close, and the attacker cannot make our egress to Cloudflare fail on demand.
No retries: a retry multiplies the dependency and the latency.

**The config fails in the strict direction, and out loud.** `KAIROS_TURNSTILE` is
`off` / `on`; unset means `on` when `KAIROS_HOSTED` is on (the switch that
already means "a deployment *we* operate") and `off` otherwise, so ADR-0001/0002
leave self-host and ETH byte-for-byte alone. An **unrecognised value reads as
`on`**. That direction is not a convention inherited from #67 — it is the direction
#67 had to adopt while fixing an incident, in which `KAIROS_HOSTED=enabled` silently
selected the permissive reach policy (`reach.policy()`); see `parse_mode`. The costs
are not symmetric here either — a self-hoster who meant otherwise sets
`KAIROS_TURNSTILE=off` and is back to exactly the pre-#31 behaviour, and
`boot_warnings()` says so by name. And a deployment that turns the gate on **without
a site key and a secret refuses to boot** (the same shape as `capability`'s
`SESSION_SECRET` gate, for the same reason: a green boot followed by a dead creation
path is the worst answer available), so "the gate is on" is never something an
operator believes rather than knows.

**Click-to-load, and no flag.** Nothing from Cloudflare is fetched until the
person presses a button — no script, no widget, no third-party cookie on a page
view. That is what keeps obligation **P1** true ("strictly-necessary cookies
only, no consent banner") in the configuration that actually ships, and it is
the mechanism ADR-0012 names for exactly this reason. The alternative — load the
widget eagerly behind a per-deployment flag — would mean shipping a flag whose
other state falsifies our own privacy page, so there is no flag; the price is one
extra click on the two forms, stated where the button is. `/privacy` discloses it
either way, which is obligation **P4**.

**One outbound HTTP seam, not a new dependency.** `httpx` is a *dev* dependency
of this repo, not a runtime one, and the runtime HTTP path is `oidc`'s
`UrllibTransport` — stdlib, one injectable module attribute (`oidc.http`), and
what every test in `tests/test_oidc.py` substitutes. This module reuses it
rather than importing httpx at runtime, which would be a new dependency in the
shipped image for a JSON POST. The transport is reached through this module's
own `http` attribute, so tests here substitute their own fake and never open a
socket.
"""

import logging
import os
from typing import NamedTuple
from urllib.parse import urlencode

from kairos import settings
from kairos.oidc import OidcError, UrllibTransport

log = logging.getLogger("kairos.turnstile")

# The endpoint is Cloudflare's and is not configurable: it is not a deployment
# knob, it is the definition of what a siteverify request *is*. A setting that
# could point it elsewhere would be a way to turn verification into a self-signed
# yes, and nothing else in the app offers that.
SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

# The widget's script. Referenced from the facade include; a deployment cannot
# point it elsewhere either, because the token is only meaningful to the endpoint
# above and a token from another origin would not verify.
SCRIPT_URL = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"

# The form field Cloudflare's own implicit-render integration uses, so a
# deployment that replaces the facade with the standard snippet keeps working.
RESPONSE_FIELD = "cf-turnstile-response"

# One action per gated form. `action` is echoed by siteverify and is free, so a
# token solved for the creation form cannot be replayed at the re-link form
# (the same reason #30 gave the two anonymous forms separate CSRF uids), and a
# token minted for *some other site* that somehow shares this deployment's
# secret is refused as well.
ACTION_NEW_POLL = "kairos-new-poll"
ACTION_MANAGE_LINK = "kairos-manage-link"

# siteverify is a single small JSON POST to a well-known anycast endpoint. Ten
# seconds (oidc's default) would let an unreachable Cloudflare hold a worker for
# ten seconds per anonymous request, which is a free amplification primitive; five
# is far above the p99 and fails into the same refusal either way.
HTTP_TIMEOUT = 5

ON = "on"
OFF = "off"

_TRUE = ("1", "on", "true", "yes", "y", "required")
_FALSE = ("0", "off", "false", "no", "n", "f", "disabled")


# Cloudflare's documented *testing* secrets, from
# https://developers.cloudflare.com/turnstile/troubleshooting/testing/
#
# They are here because they are a trap, not because they are useful in production.
# Measured against the live endpoint: `1x…AA` answers `success: true` for **any**
# response string, and returns no `action` at all. So a deployment configured with one
# has no human check — every token verifies — and, because `verify` requires a
# matching `action` (below), every anonymous POST is *also* refused. A gate that is
# simultaneously decorative and broken is exactly the state `identity_report` and
# `boot_warnings` exist to make impossible to miss.
TEST_SECRETS = frozenset({
    "1x0000000000000000000000000000000AA",  # always passes
    "2x0000000000000000000000000000000AA",  # always fails
    "3x0000000000000000000000000000000AA",  # answers "already spent"
})


def is_test_secret() -> bool:
    """Is this deployment verifying against Cloudflare's public test keys?"""
    return secret() in TEST_SECRETS


class Verdict(NamedTuple):
    """What the check decided, and what to tell the person who failed it.

    `reason` is the machine-readable shape, for the log line; `heading`/`detail`
    are what a creator reads. `detail` is never empty when `ok` is False, so a
    caller cannot render an empty refusal by accident — an anonymous form that
    refuses without saying why is indistinguishable from a broken form.
    """

    ok: bool
    reason: str = ""
    heading: str = ""
    detail: str = ""
    status_code: int = 400


OK = Verdict(True, "not-required")

_UNREACHABLE_HEADING = "The human check could not be completed"

# One sentence for every "I could not verify" refusal, with only the cause varying.
# Three near-identical paragraphs would be three chances to end up claiming something
# untrue about a third party, and the *shape* here is the part that has to be right:
# what did NOT happen, and that a person can try again. Written once.
_UNVERIFIABLE = (
    "{why} Kairos refused this request rather than assume a machine was a person. "
    "Nothing happened: no poll was created and no mail was sent. Try again in a moment."
)


# -- Configuration, read at call time ---------------------------------------


def _raw(name: str) -> str:
    """An environment variable, trimmed, or "".

    Read at call time rather than frozen at import, the way `reach._raw()` reads
    `KAIROS_POLL_REACH`: a value exported after import — or set by a test's
    `monkeypatch.setenv` — has to be visible through the same door the process
    boots with, or one spelling of the knob is honoured and the other silently
    ignored. The import-time gate below is the only thing that must not be
    dynamic, and it exists precisely because a boot is the one moment where
    "wrong" has to be expensive.
    """
    return os.environ.get(name, "").strip()


def parse_mode(raw: str) -> str:
    """`KAIROS_TURNSTILE` as `on` or `off`. **Unknown is `on`.**

    The fail-closed reading, and it is a direction #67's `reach.policy()` had to
    choose *because of an incident*, not because it established a convention:
    `settings.HOSTED` reads an unrecognised value as *off*, so `KAIROS_HOSTED=enabled`
    quietly selected `open` reach on the deployment that had just asked to be treated
    as hosted. That is a bug that was fixed, not a precedent to copy — and this
    docstring should not tell a future reader that a bug is a pattern, because the
    honest lesson is narrower: *a knob that decides whether an anonymous caller may
    make this deployment send mail must not be switchable by misspelling the knob that
    turns it on.* A gate is the case where the costs are least symmetric.

    Unset is not a misspelling and is handled by the caller (`required()`).

    **A blank value is unset, not `on`, and that is deliberate.** `parse_mode("")`
    does return `on` — it is not in `_FALSE` — but `required()` never routes a
    set-blank value here: it tests `if raw:` first, so `KAIROS_TURNSTILE=` and
    `KAIROS_TURNSTILE="   "` are read as *unset* and fall through to
    `KAIROS_HOSTED`. So on a self-hosted deployment the blank spelling reads **off**,
    which is the opposite of what the `on` branch of this function would suggest.

    That is still the safe direction, and worth being precise about why rather than
    asserting it: blanking the variable out of a compose file is overwhelmingly an
    operator removing the gate, not an operator enabling it under protest, and
    `required()` returning `False` makes `boot_warnings()` emit the "the human check
    is OFF" warning by name. The outcome is loud in every spelling. What this
    docstring must not do is claim a reading the call graph does not implement.
    """
    # Only one spelling is a refusal, and it is the one that has to be spelled
    # exactly. Every other value — a listed true, a typo, a blank — is `on`.
    return OFF if raw.strip().lower() in _FALSE else ON


def mode_unknown() -> bool:
    """Is `KAIROS_TURNSTILE` set to something this module does not recognise?

    Split out from `parse_mode` because the two answers are used for different
    jobs: `parse_mode` decides what is *in force* (the strict reading), and this
    decides whether to *say so at boot*. A knob nobody misspelled is not a
    warning.
    """
    raw = _raw("KAIROS_TURNSTILE")
    return bool(raw) and raw.lower() not in _TRUE + _FALSE


def _capability_mode() -> bool:
    """Is this the accountless mode the gate exists in?

    Written against `settings.AUTH_MODE` rather than importing
    `capability.enabled()` because `capability` imports *this* module (it gates
    `POST /manage/link`), and the reverse edge would be a cycle. A test asserts
    the two spellings agree, so they cannot drift.
    """
    return settings.AUTH_MODE == "capability"


def required() -> bool:
    """Must an anonymous POST on this deployment pass the human check?

    Three inputs, in this order:

      * not the accountless mode → **no**. The gated routes do not exist in any
        other mode (they 404), and ADR-0001/0002 require every other deployment to
        behave exactly as it did.
      * `KAIROS_TURNSTILE` says → **that**, either way. An explicit setting is an
        operator's decision and is not second-guessed.
      * unset → **`on` when `KAIROS_HOSTED` is on or unrecognised, `off`
        otherwise.** Reusing the one switch that already means "a deployment we
        operate" rather than inventing a second notion of hosted-ness that could
        disagree with it. Unrecognised counts as hosted here, for the reason
        `parse_mode` gives.

      * **set but blank → treated as unset**, not as an opinion. `KAIROS_TURNSTILE=`
        is what an operator writes when removing the gate from a compose file, so it
        defers to `KAIROS_HOSTED`; on a self-hosted deployment that means off, loudly
        (see `parse_mode` and `boot_warnings`).
    """
    if not _capability_mode():
        return False
    raw = _raw("KAIROS_TURNSTILE")
    if raw:
        return parse_mode(raw) == ON
    return bool(settings.HOSTED or settings.HOSTED_UNKNOWN)


def site_key() -> str:
    """The public key the browser needs. Safe to render; not a secret."""
    return _raw("KAIROS_TURNSTILE_SITE_KEY")


def secret() -> str:
    """The private key siteverify needs. Never rendered, never logged."""
    return _raw("KAIROS_TURNSTILE_SECRET")


def expected_hostnames() -> tuple[str, ...]:
    """Hostnames a token for this deployment may claim, or ().

    `KAIROS_TURNSTILE_HOSTNAMES` when set; otherwise the host of
    `KAIROS_PUBLIC_URL`, which is nearly free in the mode this gate exists in:
    capability mode already refuses to run without that variable being *usable*
    and warns when it is unset (`capability.boot_warnings`), and it is the same
    string the manage-link credential is built from — so in the hosted deployment
    it is the host Cloudflare's dashboard will have on the sitekey anyway.

    Binding the hostname is defence in depth, not the primary control: Cloudflare
    already refuses a token used on a domain the sitekey does not list. What it
    buys is that a *stolen* secret plus a token obtained on a domain the operator
    does own cannot be replayed here. Empty means "do not check", which is the
    self-host posture (ADR-0001/0002) and never the hosted one.
    """
    explicit = _raw("KAIROS_TURNSTILE_HOSTNAMES")
    if explicit:
        return tuple(h.strip().lower() for h in explicit.split(",") if h.strip())
    public = _raw("KAIROS_PUBLIC_URL")
    if public:
        host = public.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        if host:
            return (host.lower(),)
    return ()


def identity_report() -> str:
    """One boot line: whether the human check is in force, and what it is.

    Same convention as `capability.identity_report()` and `oidc.identity_report()`:
    "is the abuse control on" is not something an operator can infer from a
    working form. Unconditional, so a self-hoster reads "not in use" rather than
    silence.
    """
    if not _capability_mode():
        return f"poll-creation human check: not in use (owner auth: {settings.AUTH_MODE})"
    if not required():
        return (
            "poll-creation human check: OFF (KAIROS_TURNSTILE=off) -- anonymous poll "
            "creation is ungated"
        )
    if is_test_secret():
        return (
            "poll-creation human check: Cloudflare's PUBLIC TEST KEYS -- every token "
            "verifies, so this is NOT a check"
        )
    hosts = expected_hostnames()
    where = f", hostname-bound to {', '.join(hosts)}" if hosts else ", hostname not bound"
    return f"poll-creation human check: Cloudflare Turnstile, server-verified{where}"


def boot_warnings() -> list[str]:
    """The states where the gate is not what an operator believes it is.

    Returned, not logged here, for `main.create_app` to print next to the INFO
    line — the `oidc.boot_warnings` convention.

    Each one is a *misconfiguration*, not a refusal: the deployment still boots,
    because refusing here would break the self-host topology ADR-0001/0002
    protect. The one thing that refuses is below `if required()`, at import, and
    it is a missing secret rather than an unrecognised spelling.
    """
    warnings = []
    if not _capability_mode():
        return warnings
    if mode_unknown():
        warnings.append(
            f"KAIROS_TURNSTILE={_raw('KAIROS_TURNSTILE')!r} is not a value Kairos recognises, so "
            f"it says neither 'on' nor 'off' and is read as ON — the fail-closed direction, "
            f"because this knob decides whether an anonymous caller can make this deployment "
            f"send mail. Fix the spelling, or set KAIROS_TURNSTILE=off if this really is a "
            f"self-hosted deployment."
        )
    if not required():
        warnings.append(
            "KAIROS_AUTH=capability is on with the poll-creation human check OFF, so anyone who "
            "can reach this app can create polls and have a manage link mailed from your "
            "sender and domain. This is a deliberate operator choice; set KAIROS_TURNSTILE=on "
            "(with KAIROS_TURNSTILE_SITE_KEY and KAIROS_TURNSTILE_SECRET) before exposing it."
        )
    elif not expected_hostnames():
        warnings.append(
            "the poll-creation human check cannot bind the hostname: KAIROS_PUBLIC_URL is unset "
            "and KAIROS_TURNSTILE_HOSTNAMES is empty, so a stolen secret plus a token obtained "
            "on another host the operator owns would be accepted here. Cloudflare still refuses "
            "a token from a domain the sitekey does not list — this is the layer above that one."
        )
    if is_test_secret():
        # A warning rather than a refusal, because the keys are public, documented,
        # and the natural way to try this flow locally — and because the consequence
        # is not subtle enough to need a refusal to be discovered: `verify` requires
        # a matching `action`, these keys report none, so every anonymous POST is
        # answered "Human check could not be confirmed". Both halves of the failure
        # are in this sentence, because an operator who fixes only one of them still
        # has no check.
        warnings.append(
            f"KAIROS_TURNSTILE_SECRET={secret()!r} is one of Cloudflare's PUBLIC TESTING keys, "
            f"not a real widget secret. Siteverify answers success for ANY response string and "
            f"reports no action, so this deployment has no human check at all AND every "
            f"anonymous submission will be refused with 'Human check could not be confirmed'. "
            f"Create a real widget at https://dash.cloudflare.com/ and use its secret."
        )
    return warnings


# A deployment that believes it has the gate and does not must not boot. The
# alternative is a green boot line, a form nobody can complete and an ERROR per
# anonymous request, which is the shape `capability`'s `SESSION_SECRET` gate was
# written to refuse. Deliberately at import, like that one, and gated on
# `required()` so a stray variable cannot take down a deployment that never opted
# in.
if required() and not (site_key() and secret()):
    raise RuntimeError(
        "KAIROS_AUTH=capability with the poll-creation human check on requires "
        "KAIROS_TURNSTILE_SITE_KEY (public, rendered into the page) and "
        "KAIROS_TURNSTILE_SECRET (private, sent to Cloudflare's siteverify). Create a "
        "widget at https://dash.cloudflare.com/ and paste both keys in. Refusing to boot is "
        "deliberate — the alternative is a deployment that believes it gates anonymous "
        "creation and cannot verify a single request."
    )


# -- The verification --------------------------------------------------------

# A module attribute on purpose, exactly like `oidc.http`: a fake serves the
# whole flow with no network, and the seam is one attribute rather than a
# constructor argument threaded through the route.
http = UrllibTransport()


def _unverifiable(reason: str, why: str) -> Verdict:
    """A refusal for "the verifier did not answer", sharing one sentence."""
    return _refuse(reason, _UNREACHABLE_HEADING, _UNVERIFIABLE.format(why=why), 503)


def _refuse(reason: str, heading: str, detail: str, status_code: int = 400) -> Verdict:
    # "reason" only. Never the token, never the secret, never an address: the peer
    # is not logged either, because behind a proxy it is the proxy and an operator
    # reading a refusal wants to know what the verifier said, not which load balancer
    # it went out of. S7, and the same reasoning as #30's "no creator address in any
    # log line".
    log.warning("anonymous form refused by the human check: reason=%s", reason)
    return Verdict(False, reason, heading, detail, status_code)


ABSENT_DETAIL = (
    "This deployment asks everyone who fills this in to prove they are a person, so it "
    "cannot be used to make a machine mail strangers. The check did not run, so nothing "
    "happened: no poll was created and no mail was sent. Turn on JavaScript, press "
    "“I'm human”, and submit again."
)


def verify(request, form, *, action: str) -> Verdict:
    """Is this POST's human check satisfied? A `Verdict`, never an exception.

    Two shapes of refusal, one answer:

      * **the form claims nothing** — no token field, or an empty one. Cloudflare's
        own answer would be a refusal, so this short-circuits to the same refusal
        without spending a request on it. An absent token is by far the most
        common abuse attempt and must not be the most expensive one.

      * **the form claims something** — a token is posted to `siteverify` with the
        secret, and only `success: true` plus a matching `action` (and hostname,
        when configured) passes. `action` is compared against what siteverify
        *reports*, never against anything sent in the request: the request has no
        `action` parameter to send, because Cloudflare reads it from the token.

    **Fail closed on every other case**, and specifically on *not knowing*:
    Cloudflare unreachable, DNS failure, a 500, a body that is not JSON. That is a
    judgement call, and the opposite one was available. Fail open would keep a
    free product working through a third-party outage, and it is rejected because
    the outage is not the interesting case — the interesting case is an attacker
    who wants the gate skipped, and every path that produces "I could not check"
    here is reachable by whoever can break our egress to Cloudflare, or by
    nothing at all. Meanwhile the cost of failing closed is one `KAIROS_TURNSTILE`
    away, is stated in a boot warning, and produces an ERROR per attempt rather
    than a silent success. An anti-spam gate that a third party's availability
    controls is not a gate.

    `remoteip` is deliberately **not** sent. It is optional, and behind a reverse
    proxy — which the hosted deployment is — the transport peer is the proxy, so
    the field would name the wrong address and could refuse honest creators.
    Cloudflare binds the token to the sitekey's domains and makes it single-use,
    which is what the check is for.
    """
    if not required():
        return OK

    token = str(form.get(RESPONSE_FIELD) or "").strip()
    if not token:
        return _refuse("absent", "Human check missing", ABSENT_DETAIL)

    body = urlencode({
        "secret": secret(),
        "response": token,
        # No `action` here, deliberately. Cloudflare's siteverify *request*
        # parameters are `secret`, `response`, `remoteip` and `idempotency_key`;
        # `action` is echoed from the token the widget minted, and sending it is
        # silently ignored. An earlier version of this file sent it anyway, which
        # implied the request binds the action when the real binding is entirely
        # in the token — and a test asserted `sent["action"]`, which cemented the
        # impression. The check below reads `payload["action"]`, which is the
        # value that matters, and it is a real one: a token solved on the other
        # form does not match.
    }).encode()
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        response = http.fetch(SITEVERIFY_URL, method="POST", data=body,
                              headers=headers, timeout=HTTP_TIMEOUT)
    except OidcError as exc:
        # `oidc.UrllibTransport` is the app's one outbound seam (see the module
        # docstring); its failure type is named `OidcError` because it predates
        # this caller. It is translated here, at the boundary, into the refusal
        # this module owns.
        log.error("siteverify unreachable (%s); refusing %s fail-closed", exc, action)
        return _unverifiable("unreachable",
                             "Kairos could not reach the service that verifies the human check, so")

    if response.status != 200:
        log.error("siteverify answered HTTP %s; refusing %s fail-closed", response.status, action)
        return _unverifiable(f"http-{response.status}",
                             "The service that verifies the human check did not answer properly, so")

    try:
        payload = response.json()
    except OidcError as exc:
        log.error("siteverify answered with unparseable JSON (%s); refusing %s", exc, action)
        return _unverifiable("unparseable",
                             "The service that verifies the human check answered something Kairos "
                             "could not read, so")

    if payload.get("success") is not True:
        # `is not True`, not a falsiness test, and the strictness is the point: this
        # is the one predicate whose entire job is deciding whether a human check
        # passed, and `if not payload.get("success")` accepts the JSON *string*
        # `"false"` and the integer `1` as success — both truthy. Measured against a
        # real siteverify socket, a payload of `{"success": "false"}` produced a 200
        # and a created poll. Not exploitable today (Cloudflare answers a real
        # boolean, the endpoint is not configurable, and TLS pins it), but the
        # docstring above promises "only `success: true` passes" and this code did
        # not keep that promise in the one place where a future upstream change, a
        # proxy, or a test double would be felt.
        #
        # Cloudflare's `error-codes` is the operator's diagnostic and is worth a
        # log line; `invalid-input-secret` in particular means the *secret* is
        # wrong, which no amount of retrying fixes.
        codes = payload.get("error-codes") or []
        reason = f"rejected:{','.join(str(c) for c in codes) or 'unspecified'}"
        log.warning("siteverify refused a token: %s", reason)
        return _refuse(
            reason,
            "Human check failed",
            "That check did not pass, so nothing happened: no poll was created and no mail was "
            "sent. Press “I'm human” again and submit — the verification is single-use, so a "
            "page that has been sitting open for a while needs a fresh one.",
        )

    # The action is what keeps a token from crossing between the two gated
    # forms, and it is free: siteverify echoes the value the widget was rendered
    # with. A mismatch is a refusal, not a warning — and so is an *absent* one,
    # because "the verifier did not say which form this was solved on" and "this was
    # solved on the other form" are the same answer: we cannot prove it, and this app
    # has two gated forms. That strictness is also why Cloudflare's testing keys
    # cannot be used here (see `is_test_secret`): they return no `action`, which
    # means every anonymous POST is refused, loudly, rather than passing unverified.
    if payload.get("action") != action:
        reported = payload.get("action")
        log.warning("siteverify reported action %r where %r was required", reported, action)
        if reported:
            return _refuse("action-mismatch", "Human check failed",
                           "That check was started on a different form, so it does not count "
                           "here. Reload the page and press “I'm human” again.")
        return _refuse("action-missing", "Human check could not be confirmed",
                       "The service that verifies the human check did not say which form the "
                       "check was started on, so Kairos refused this request rather than assume "
                       "a machine was a person. Nothing happened: no poll was created and no "
                       "mail was sent. If you are the operator, check that "
                       "KAIROS_TURNSTILE_SECRET is this widget's real secret and not one of "
                       "Cloudflare's public test keys, which cannot work here.",
                       503)

    hosts = expected_hostnames()
    if hosts and str(payload.get("hostname") or "").lower() not in hosts:
        log.warning("siteverify returned hostname %r, not one of %s",
                    payload.get("hostname"), ", ".join(hosts))
        return _refuse("hostname-mismatch", "Human check failed",
                       "That check was completed on a different site, so it does not count "
                       "here. Reload the page and try again.")

    return Verdict(True, "verified")


class Disclosure(NamedTuple):
    """The `/privacy` third-party paragraph as *text*, never as markup.

    Two fields rather than one HTML string, and that is the whole design. The
    paragraph is rendered by an autoescaping template (`select_autoescape` in
    `kairos.templating`), so a string carrying `<strong>` arrives on the page as
    literal angle brackets — which is what a browser-found bug in review caught on
    this exact paragraph. The two available repairs were `|safe` or dropping the
    emphasis, and `|safe` is the wrong one *here specifically*: this is the one page
    whose entire purpose is truthfulness, and `|safe` there is a standing
    invitation for someone to interpolate operator-controlled text into it later
    (`KAIROS_LEGAL_EXTRA`, rendered escaped a few lines below on purpose).

    So the emphasis is the template's, not this module's: it writes
    `<strong>{{ turnstile.lead }}</strong> {{ turnstile.body }}` and both halves stay
    escaped. That keeps the paragraph readable, keeps it honest, and means a future
    edit that adds a variable here produces escaped punctuation rather than markup.
    `test_the_disclosure_renders_as_markup_not_as_escaped_text` pins the rendering;
    a test that greps for substrings that survive escaping is what let the bug
    through.
    """

    lead: str
    body: str


def disclosure() -> Disclosure | None:
    """The `/privacy` paragraph for this deployment, or `None` when it needs none.

    Obligation **P4**: "if Turnstile/analytics added, disclose". Rendered from
    `required()` at request time, so the page cannot claim the check is absent
    while the check is running, or name a third party on a deployment that never
    contacted one.

    What it says is the part that has to be *true*, and the interesting sentence is
    the middle one. A Turnstile widget loads third-party JavaScript from
    `challenges.cloudflare.com` and, once it runs, that origin necessarily sees the
    visitor's IP address and the page it happened on. What the facade changes is
    *when*: nothing is fetched at all until the person presses the button, so a page
    view costs no third-party request, sets no third-party cookie, and requires no
    consent — which is why obligation **P1**'s "no consent banner" sentence survives
    this issue unchanged, and why there is no flag that could select the other state.

    Deliberately not claimed, because Kairos cannot observe it: whether the widget
    sets a cookie of its own once loaded, or what Cloudflare retains. Those are the
    operator's to answer in `KAIROS_LEGAL_EXTRA`, and the honest shape here is a
    "no analytics, no advertising" sentence plus "may set a cookie of its own to
    avoid asking twice", which is a statement about behaviour rather than a promise
    about a third party's internals.

    The "may set a cookie of its own" clause and P1's cookie paragraph have to
    agree, and did not at first: the cookie paragraph made a blanket "no third-party
    cookies" claim that this sentence contradicts. P1 is now worded as the narrower
    true thing — nothing loads from a third party until a button is pressed, which
    is the *reason* no banner is needed — rather than as a promise about a third
    party's cookie jar, which Kairos cannot observe.
    """
    if not required():
        return None
    return Disclosure(
        lead="Human check (Cloudflare Turnstile).",
        body=(
            "Creating a poll, and asking for a new management link, are gated by Cloudflare "
            "Turnstile so this deployment cannot be used to make a machine send mail to "
            "strangers. Nothing is loaded from Cloudflare until you press the button that starts "
            "the check — opening either page contacts no third party at all. After you press it "
            "your browser talks to challenges.cloudflare.com, which necessarily sees your IP "
            "address and the page it happened on, and the widget may set a cookie of its own to "
            "avoid asking twice. There is no analytics, no advertising and no cross-site "
            "tracking, and because nothing loads without your click no consent banner is "
            "required."
        ),
    )


def widget_ctx(action: str) -> dict:
    """Template context for the click-to-load facade, or `{}` when it is off.

    `{}` — empty, and therefore falsy — so every template can ask
    `{% if turnstile %}` and every mode that does not gate renders the form
    exactly as it did before this issue — which is the byte-for-byte property
    ADR-0001/0002 ask of self-host and ETH, asserted rather than intended.
    """
    if not required():
        return {}
    key = site_key()
    if not key:
        # Unreachable in practice: the import gate refuses to boot without it
        # whenever the check is required. Rendering nothing beats rendering a
        # widget that cannot verify.
        return {}
    return {"sitekey": key, "action": action, "field": RESPONSE_FIELD,
            "script_url": SCRIPT_URL}
