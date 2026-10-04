"""Obligation A1 (Turnstile) and obligation A2's send-gate — issue #31.

The last step of the hosted chain: #29 made management one predicate and added
`manage_verified_at`, #30 built the accountless console and stamped that column
on the first link exchange, and this makes the anonymous surface abuse-resistant
rather than a free spam cannon.

What is pinned here, because each of these is a way the feature could be *claimed*
and be false:

1. **Inert by default, and inert in every other auth mode** (ADR-0001/0002). The
   shared `new_poll.html` renders **byte for byte** as it did before this issue
   when the gate is off — asserted by rendering it with and without the context key
   and comparing the two strings, not by reading the diff.
2. **The config fails in the strict direction and says so.** An unrecognised
   `KAIROS_TURNSTILE` reads as `on` (#67's `reach.policy()` precedent), a
   `KAIROS_HOSTED` that reads unknown counts as hosted, and a gate that is on
   without both keys **refuses to boot**. The worst outcome available here is a
   gate that is off because a knob was misspelled.
3. **The browser's claim is not the fact.** `success: true` from the *form* is
   refused; only a server-side `siteverify` POST decides, and it sends the secret.
   The action must match, so a token cannot cross between the two gated forms.
4. **Fail closed, including on "I could not check".** Unreachable, 500 and
   unparseable are refusals, exactly once each, with no retry — and the reasoning
   for not failing open is in the test's name rather than in a comment somewhere.
5. **The check runs before the expensive work.** A refused `POST /new` never
   expands the slot grid: a call-order assertion *and* a `tracemalloc` ceiling,
   because a check that runs after the work produces the same 400.
6. **`POST /manage/link` has an abuse owner** (#68 flagged it: with shipped
   defaults a third party could aim unbounded nuisance mail at a victim address).
   It is gated by the same check, and a *verified* creator is exempt.
7. **The send-gate's semantics.** NULL `manage_verified_at` means *may not send* —
   including an absent key, and including every poll that predates the column, so
   it ships closed. The creation mail and the re-link mail are deliberately not
   gated, or the gate would be unreachable. And every mail-sending path on every
   surface consults the one predicate, asserted as a spy-guard the way #29's S6
   guard is.
8. **P1/P4.** `/privacy` names the third party on a deployment that uses one,
   says nothing on one that does not, and the "no consent banner is required"
   sentence is unchanged — because nothing loads until the person asks it to.
"""

import json
import re
import sqlite3
import tracemalloc
from pathlib import Path
from urllib.parse import parse_qsl

import pytest
from fastapi.testclient import TestClient

from kairos import api, capability, db, email_service, main, settings, turnstile, web
from kairos.csrf import make_csrf
from kairos.oidc import OidcError, Response

SRC = Path(__file__).resolve().parent.parent / "src" / "kairos"

SITE_KEY = "1x00000000000000000000AA"
SECRET = "0x0000000000000000000000000000000AA"
# Two tokens, because Cloudflare's are single-use and several of these tests make
# two requests (create a poll, then ask for a link). Minting a second one is what a
# real browser would do.
TOKEN = "XXXX.DUMMY.TOKEN.XXXX"
TOKEN2 = "YYYY.DUMMY.TOKEN.YYYY"


# -- the fake third party ---------------------------------------------------


class FakeCloudflare:
    """A siteverify that behaves the way Cloudflare's does, closely enough that a
    test cannot pass by stubbing the wrong thing.

    Substituted for `turnstile.http`, so the whole flow runs with no socket open —
    the same injectable-transport shape `oidc.http` has, and the reason `httpx`
    (a *dev* dependency here) never has to be imported at runtime.

    The three rules it reproduces are the ones a test could otherwise paper over: a
    wrong secret is refused with `invalid-input-secret`, an unrecognised token with
    `invalid-input-response`, and an accepted token is **spent** — Cloudflare makes
    tokens single-use, and a replay therefore comes back as
    `timeout-or-duplicate`. `action` and `hostname` are echoed from the request
    unless pinned, so the action check is exercised by submitting the *other*
    action rather than by a canned payload.
    """

    def __init__(self, *, accepts=(TOKEN, TOKEN2), secret=SECRET, action=None, hostname=None,
                 status=200, exc=None, body=None, error_codes=None, refuse=False,
                 omit_action=False):
        self.accepts = set(accepts)
        self.spent: set[str] = set()
        self.secret = secret
        self.action = action
        # `omit_action` reproduces Cloudflare's *testing* keys, which return no
        # action at all rather than echoing one.
        self.omit_action = omit_action
        self.hostname = hostname or "kairos.example.org"
        self.status = status
        self.exc = exc
        self.body = body
        # `error_codes` forces a refusal with those codes; `refuse` refuses with
        # none at all, which Cloudflare does and which must still be a refusal.
        self.error_codes = error_codes
        self.refuse = refuse
        self.calls: list[dict] = []

    def fetch(self, url, *, method="GET", data=None, headers=None, timeout=None):
        self.calls.append({"url": url, "method": method, "data": data,
                           "headers": headers or {}, "timeout": timeout})
        if self.exc is not None:
            raise self.exc
        if self.body is not None or self.status != 200:
            raw = self.body if self.body is not None else b"{}"
            return Response(self.status, {"content-type": "application/json"}, raw)

        form = dict(parse_qsl(data.decode()))
        if self.error_codes:
            payload = {"success": False, "error-codes": list(self.error_codes)}
        elif self.refuse:
            payload = {"success": False}
        elif form.get("secret") != self.secret:
            payload = {"success": False, "error-codes": ["invalid-input-secret"]}
        elif form.get("response") in self.spent:
            payload = {"success": False, "error-codes": ["timeout-or-duplicate"]}
        elif form.get("response") not in self.accepts:
            payload = {"success": False, "error-codes": ["invalid-input-response"]}
        else:
            self.spent.add(form["response"])  # single use, as Cloudflare's is
            payload = {"success": True, "hostname": self.hostname}
            if not self.omit_action:
                payload["action"] = self.action or form.get("action")
        return Response(200, {"content-type": "application/json"},
                        json.dumps(payload).encode())

    def form(self, index=0) -> dict:
        return dict(parse_qsl(self.calls[index]["data"].decode()))


# -- fixtures ---------------------------------------------------------------


class _FakeRelay:
    def __init__(self):
        self.sent: list = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def send_message(self, msg):
        self.sent.append(msg)


@pytest.fixture
def relay(monkeypatch):
    fake = _FakeRelay()
    monkeypatch.setattr(email_service, "SMTP_HOST", "smtp.example.net")
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@example.org")
    monkeypatch.setattr(email_service, "_smtp_session", lambda: fake)
    monkeypatch.setattr(email_service, "_last_refusal_logged", None)
    return fake


@pytest.fixture
def cap_mode(monkeypatch):
    """This process's view of the accountless mode (as tests/test_capability.py)."""
    monkeypatch.setattr(settings, "AUTH_MODE", "capability")
    monkeypatch.setitem(web.env.globals, "CAPABILITY", True)
    return settings


@pytest.fixture
def cloudflare(monkeypatch):
    """A siteverify that accepts `TOKEN` and nothing else, installed by default."""
    fake = FakeCloudflare()
    monkeypatch.setattr(turnstile, "http", fake)
    return fake


@pytest.fixture
def gated(monkeypatch, cloudflare):
    """`KAIROS_TURNSTILE=on` with both keys, in the accountless mode."""
    monkeypatch.setenv("KAIROS_TURNSTILE", "on")
    monkeypatch.setenv("KAIROS_TURNSTILE_SITE_KEY", SITE_KEY)
    monkeypatch.setenv("KAIROS_TURNSTILE_SECRET", SECRET)
    monkeypatch.setenv("KAIROS_TURNSTILE_HOSTNAMES", "kairos.example.org")
    return cloudflare


class Live:
    def __init__(self, client, path, relay):
        self.client, self.path, self.relay = client, path, relay

    @property
    def polls(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute("SELECT * FROM sched_polls").fetchall()]
        conn.close()
        return rows

    def poll(self):
        assert len(self.polls) == 1, f"expected one poll, found {len(self.polls)}"
        return self.polls[0]

    def reset_mail(self):
        self.relay.sent.clear()


@pytest.fixture
def live(tmp_path, monkeypatch, cap_mode, relay):
    """A capability-mode app on a real SQLite file with working mail, gate off."""
    path = tmp_path / "ts.db"
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{path}")
    monkeypatch.setattr(settings, "API_KEY", "testkey")
    db.init_schema()
    with TestClient(main.create_app(), base_url="https://testserver",
                    follow_redirects=False) as client:
        yield Live(client, path, relay)


def _form(**extra):
    base = {
        "title": "Retreat",
        "creator_email": "ada@example.org",
        "dates": ["2026-12-01"],
        "mode": "full_day",
        "timezone": "Europe/Zurich",
        "csrf": make_csrf(capability.ANON_FORM_UID),
    }
    base.update(extra)
    return base


def _new(live, **extra):
    return live.client.post("/scheduler/new", data=_form(**extra))


def _token(**extra):
    return _form(**{turnstile.RESPONSE_FIELD: TOKEN, **extra})


def _exchange(live):
    poll = live.poll()
    live.client.get(f"/scheduler/manage/{poll['admin_token']}")
    return live.client.post(f"/scheduler/manage/{poll['admin_token']}", data={})


API = {"Authorization": "Bearer testkey"}


def _link(live, email, **extra):
    return live.client.post("/scheduler/manage/link", data={
        "email": email, "csrf": make_csrf(capability.LINK_FORM_UID), **extra})


# -- 1. inert unless asked for (ADR-0001/0002) ------------------------------


def test_the_check_is_inert_outside_the_accountless_mode(monkeypatch):
    """Header mode is the ETH deployment. Nothing here may change for it."""
    monkeypatch.setenv("KAIROS_TURNSTILE", "on")
    monkeypatch.setenv("KAIROS_TURNSTILE_SITE_KEY", SITE_KEY)
    monkeypatch.setenv("KAIROS_TURNSTILE_SECRET", SECRET)
    assert settings.AUTH_MODE == "header", "the test env mirrors ETH (conftest.py)"
    assert turnstile.required() is False
    assert turnstile.verify(None, {}, action=turnstile.ACTION_NEW_POLL).ok is True


def test_unset_is_off_for_a_self_hoster_and_on_for_a_hosted_one(monkeypatch, cap_mode):
    monkeypatch.delenv("KAIROS_TURNSTILE", raising=False)
    monkeypatch.setattr(settings, "HOSTED", False)
    monkeypatch.setattr(settings, "HOSTED_UNKNOWN", False)
    assert turnstile.required() is False, "self-host must be untouched (ADR-0001/0002)"
    monkeypatch.setattr(settings, "HOSTED", True)
    assert turnstile.required() is True
    monkeypatch.setattr(settings, "HOSTED", False)
    monkeypatch.setattr(settings, "HOSTED_UNKNOWN", True)
    assert turnstile.required() is True, (
        "KAIROS_HOSTED=enabled once read as 'not hosted', which turned the strict "
        "poll-reach policy off on the deployment that asked for hosted (#67)"
    )


def test_an_explicit_setting_wins_over_hosted(monkeypatch, cap_mode):
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setenv("KAIROS_TURNSTILE", "off")
    assert turnstile.required() is False, "an operator may say no, and is warned at boot"
    monkeypatch.setenv("KAIROS_TURNSTILE", "1")
    monkeypatch.setattr(settings, "HOSTED", False)
    assert turnstile.required() is True, "a self-hoster may say yes too"


def test_the_creation_form_is_byte_for_byte_what_it_was_when_the_gate_is_off():
    """The strongest form of ADR-0001/0002 available for a shared template.

    `new_poll.html` serves header/demo/oidc as well as capability mode, so "the
    other modes are unchanged" is a claim about bytes. Rendered twice — once with
    `turnstile={}` and once with the key absent entirely, which is what every
    non-capability render does — and compared. A `{% if %}` that forgot to be
    conditional, or a stray newline from an include, fails here.
    """
    context = capability.new_poll_context()
    assert context["turnstile"] == {}, "the gate is off by default, so no widget context"

    def render(ctx):
        return web.env.get_template("new_poll.html").render(**ctx)

    with_key = render(context)
    without_key = render({k: v for k, v in context.items() if k != "turnstile"})
    assert with_key == without_key
    assert "turnstile" not in with_key
    assert "challenges.cloudflare.com" not in without_key


def test_a_self_host_form_never_mentions_a_third_party(live):
    """The same claim for the route, in the mode that actually serves it."""
    body = live.client.get("/scheduler/new").text
    assert "challenges.cloudflare.com" not in body
    assert "data-turnstile" not in body


def test_the_eth_deployment_serves_the_creation_form_it_always_did(tmp_path, monkeypatch):
    """The literal unchanged-path evidence, on the deployment the ADR is about.

    `tests/conftest.py` mirrors ETH (prefix `/scheduler`, header auth), so this app
    *is* the ETH shape: an authenticated owner behind a proxy, no accountless mode,
    no creator-address field, and — the point — not one byte about a human check or
    a third party. If the gate ever leaks into the shared template rather than the
    capability branch, this is the test that notices.
    """
    assert settings.AUTH_MODE == "header"
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/eth.db")
    db.init_schema()
    with TestClient(main.create_app(), base_url="https://testserver") as client:
        body = client.get("/scheduler/new", headers={"X-User": "ada"}).text
    for forbidden in ("data-turnstile", "challenges.cloudflare.com",
                      turnstile.RESPONSE_FIELD, "I'm human", "creator_email"):
        assert forbidden not in body, f"the ETH creation form now mentions {forbidden!r}"
    assert 'action="/scheduler/new"' in body and "Create Poll" in body


def test_the_mode_test_and_the_deployment_test_agree():
    """`turnstile._capability_mode()` duplicates `capability.enabled()` to avoid an
    import cycle (`capability` imports this module to gate `/manage/link`). Two
    spellings of one question is one question too many; this is what keeps them
    from drifting apart silently.
    """
    assert turnstile._capability_mode() == capability.enabled()


# -- 2. config fails loudly, in the strict direction ------------------------


@pytest.mark.parametrize("spelling", ["enabled", "YES!", "2", "required-ish", "true-ish"])
def test_an_unrecognised_spelling_means_on_and_is_logged(monkeypatch, cap_mode, spelling):
    """The #67 lesson, applied to a knob that decides who may send mail.

    `settings.HOSTED` reads unknown as *off*, so `KAIROS_HOSTED=enabled` quietly
    made a hosted deployment permissive. Here the same shape would silently remove
    the gate from the deployment that asked for it — the worst outcome available,
    because nothing downstream would report it.
    """
    monkeypatch.setenv("KAIROS_TURNSTILE", spelling)
    monkeypatch.setenv("KAIROS_TURNSTILE_SITE_KEY", SITE_KEY)
    monkeypatch.setenv("KAIROS_TURNSTILE_SECRET", SECRET)
    assert turnstile.required() is True
    assert turnstile.mode_unknown() is True
    warning = "\n".join(turnstile.boot_warnings())
    assert spelling in warning and "read as ON" in warning
    assert "KAIROS_TURNSTILE=off" in warning, "the warning must name the way back"


@pytest.mark.parametrize("spelling", ["on", "1", "true", "yes", "y", "off", "0", "false", "no", "n"])
def test_every_spelling_of_on_and_off_is_enumerated_not_guessed(monkeypatch, cap_mode, spelling):
    """Both sets are spelled out, exactly like `settings.HOSTED_TRUE/FALSE`.

    Guessing is how `Y` and `n` ended up meaning the opposite of what an operator
    meant; an enumerated set makes "unrecognised" a state that cannot be reached by
    a plausible typo, so the strict fallback stays for genuinely wrong values.
    """
    monkeypatch.setenv("KAIROS_TURNSTILE", spelling)
    monkeypatch.setenv("KAIROS_TURNSTILE_SITE_KEY", SITE_KEY)
    monkeypatch.setenv("KAIROS_TURNSTILE_SECRET", SECRET)
    expected = "on" if spelling in ("on", "1", "true", "yes", "y") else "off"
    assert turnstile.required() is (expected == "on")
    assert turnstile.mode_unknown() is False


def test_a_gate_that_is_on_without_its_keys_refuses_to_boot(cap_mode, monkeypatch):
    """The `SESSION_SECRET` gate's shape, for the same reason.

    A deployment that believes it gates anonymous creation and cannot verify a
    single request is worse than one that refuses to start: the first boots green
    and 400s every creator with a reason about a third party.
    """
    monkeypatch.setenv("KAIROS_TURNSTILE", "on")
    monkeypatch.delenv("KAIROS_TURNSTILE_SITE_KEY", raising=False)
    monkeypatch.delenv("KAIROS_TURNSTILE_SECRET", raising=False)
    monkeypatch.setenv("KAIROS_TURNSTILE_HOSTNAMES", "")
    with pytest.raises(RuntimeError) as excinfo:
        _reimport_turnstile()
    message = str(excinfo.value)
    assert "KAIROS_TURNSTILE_SITE_KEY" in message and "KAIROS_TURNSTILE_SECRET" in message
    assert "Refusing to boot" in message


def test_the_same_variables_cannot_take_down_a_deployment_that_does_not_use_them(monkeypatch):
    """A stray `KAIROS_TURNSTILE` must not break self-host or ETH (ADR-0001/0002).

    The mirror of `test_a_gate_that_is_on_without_its_keys_refuses_to_boot`: the
    refusal is gated on the gate being required, so it costs every other
    deployment nothing.
    """
    monkeypatch.setenv("KAIROS_TURNSTILE", "on")
    monkeypatch.delenv("KAIROS_TURNSTILE_SITE_KEY", raising=False)
    monkeypatch.delenv("KAIROS_TURNSTILE_SECRET", raising=False)
    assert settings.AUTH_MODE == "header"
    _reimport_turnstile()  # must not raise


def _reimport_turnstile():
    """Execute `turnstile.py` again under a *different* module name.

    Deliberately not a reload: nothing is removed from `sys.modules`, so this
    cannot leak into another test module (which is how deleting `kairos.*` entries
    broke seven unrelated tests once). It exists to reach the module-level
    `os.environ` reads, which patching an already-parsed constant cannot.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("kairos_turnstile_import_probe",
                                                  SRC / "turnstile.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_hosted_deployment_with_the_gate_off_is_warned_about(monkeypatch, cap_mode):
    monkeypatch.setenv("KAIROS_TURNSTILE", "off")
    monkeypatch.setattr(settings, "HOSTED", True)
    warning = "\n".join(turnstile.boot_warnings())
    assert "human check OFF" in warning and "before exposing" in warning


def test_every_boot_says_whether_the_gate_is_in_force(monkeypatch, cap_mode):
    """`identity_report`, for the same reason `capability.identity_report` exists:
    a working form looks identical either way."""
    monkeypatch.setattr(settings, "HOSTED", False)
    monkeypatch.setattr(settings, "HOSTED_UNKNOWN", False)
    monkeypatch.delenv("KAIROS_TURNSTILE", raising=False)
    assert "OFF" in turnstile.identity_report(), "a self-hosted capability deployment must say so"

    monkeypatch.setattr(settings, "AUTH_MODE", "header")
    assert "not in use" in turnstile.identity_report()

    monkeypatch.setattr(settings, "AUTH_MODE", "capability")
    monkeypatch.setenv("KAIROS_TURNSTILE", "on")
    monkeypatch.setenv("KAIROS_TURNSTILE_SITE_KEY", SITE_KEY)
    monkeypatch.setenv("KAIROS_TURNSTILE_SECRET", SECRET)
    monkeypatch.setenv("KAIROS_TURNSTILE_HOSTNAMES", "kairos.example.org")
    report = turnstile.identity_report()
    assert "Turnstile" in report and "server-verified" in report
    assert "kairos.example.org" in report


# -- 3. the browser's claim is not the fact ---------------------------------


def _request(**env):
    from starlette.requests import Request

    return Request({"type": "http", "method": "POST", "path": "/scheduler/new",
                    "headers": [], "client": ("203.0.113.9", 51000), "scheme": "https"})


def test_a_token_the_page_invented_is_refused(live, gated):
    """`success` from the browser is a claim. Only siteverify decides — and the
    fabricated one is spent a request finding out, which is the point of asking the
    party that can tell."""
    assert _new(live, **{turnstile.RESPONSE_FIELD: "forged"}).status_code == 400
    assert len(gated.calls) == 1
    assert "Human check failed" in _new(live, **{turnstile.RESPONSE_FIELD: "forged"}).text
    assert live.polls == [], "a refused check must not create a poll"
    assert live.relay.sent == [], "and must not send the manage link"


def test_the_check_is_skipped_entirely_when_no_token_was_posted(live, gated):
    """The common case is the common abuse attempt, so it is the cheap one."""
    assert _new(live).status_code == 400
    assert gated.calls == []
    body = live.client.post("/scheduler/new", data=_form()).text
    assert "JavaScript" in body, "the refusal must say what to do about it"


def test_a_verified_token_is_the_only_thing_that_passes(cap_mode, gated):
    """The one shape that passes, asserted on what was actually sent."""
    verdict = turnstile.verify(_request(), {turnstile.RESPONSE_FIELD: TOKEN},
                               action=turnstile.ACTION_NEW_POLL)
    assert verdict.ok is True
    assert len(gated.calls) == 1, "one request, and no retry (see the next test)"
    call = gated.calls[0]
    assert call["url"] == turnstile.SITEVERIFY_URL
    assert call["method"] == "POST"
    sent = gated.form()
    assert sent["secret"] == SECRET, "the siteverify POST must carry the secret"
    assert sent["response"] == TOKEN
    assert sent["action"] == turnstile.ACTION_NEW_POLL


def test_remoteip_is_deliberately_not_sent(cap_mode, gated):
    """A decision worth pinning, because it looks like an oversight otherwise.

    Behind a reverse proxy — which the hosted deployment is — the transport peer is
    the proxy, so `remoteip` would name the wrong address and could refuse honest
    creators. Cloudflare binds the token to the sitekey's domains and makes it
    single-use, which is what the check is for.
    """
    turnstile.verify(_request(), {turnstile.RESPONSE_FIELD: TOKEN},
                     action=turnstile.ACTION_NEW_POLL)
    assert "remoteip" not in gated.form()


@pytest.mark.parametrize("codes,refuse,reason", [
    (("invalid-input-response",), False, "invalid-input-response"),
    (("invalid-input-secret",), False, "invalid-input-secret"),
    (("missing-input-secret",), False, "missing-input-secret"),
    (None, True, "unspecified"),
])
def test_every_refusal_siteverify_can_return_is_a_refusal(monkeypatch, cap_mode, codes, refuse,
                                                          reason):
    monkeypatch.setenv("KAIROS_TURNSTILE", "on")
    monkeypatch.setenv("KAIROS_TURNSTILE_SITE_KEY", SITE_KEY)
    monkeypatch.setenv("KAIROS_TURNSTILE_SECRET", SECRET)
    fake = FakeCloudflare(error_codes=codes, refuse=refuse)
    monkeypatch.setattr(turnstile, "http", fake)
    verdict = turnstile.verify(_request(), {turnstile.RESPONSE_FIELD: TOKEN},
                               action=turnstile.ACTION_NEW_POLL)
    assert verdict.ok is False
    assert reason in verdict.reason
    assert verdict.detail, "a refusal with no sentence is a broken form, not a refusal"


def test_a_token_that_has_been_spent_is_refused(monkeypatch, cap_mode, gated):
    """Cloudflare's tokens are single-use and expire in minutes; a replayed one comes
    back as `timeout-or-duplicate`. Kairos adds no replay store of its own, so this
    is worth pinning: it asserts we take the answer rather than treating any
    `success` as permanent."""
    form = {turnstile.RESPONSE_FIELD: TOKEN}
    assert turnstile.verify(_request(), form, action=turnstile.ACTION_NEW_POLL).ok is True
    second = turnstile.verify(_request(), form, action=turnstile.ACTION_NEW_POLL)
    assert second.ok is False
    assert "timeout-or-duplicate" in second.reason


def test_a_token_that_carries_no_action_is_refused(monkeypatch, cap_mode, gated):
    """A verifier that does not say *which form* the check was started on.

    "The other form" and "it did not say" are the same answer — we cannot prove it,
    and this app has two gated forms — so both are refusals, and the second is a 503
    because it is an operator's problem rather than a visitor's.

    This is also Cloudflare's **testing keys** in the flesh, measured against the
    live endpoint: `1x…AA` answers `success: true` for any response string and
    returns no `action` at all. The next test is the boot line for that deployment.
    """
    gated.omit_action = True
    verdict = turnstile.verify(_request(), {turnstile.RESPONSE_FIELD: TOKEN},
                               action=turnstile.ACTION_NEW_POLL)
    assert verdict.ok is False
    assert verdict.reason == "action-missing"
    assert verdict.status_code == 503
    assert "test keys" in verdict.detail, "the refusal must name the likely cause"


def test_a_deployment_on_cloudeflares_public_test_keys_is_told_so(monkeypatch, cap_mode):
    """The footgun, named.

    Those keys are documented, public, and the obvious way to try the flow locally.
    Configured with one, the check verifies every token — so a deployment can look
    gated and be entirely ungated. `identity_report` and `boot_warnings` exist for
    exactly this class of state, and both halves of the failure (no check, and every
    POST refused for the missing `action`) have to be in the sentence, because fixing
    only one of them still leaves no control.
    """
    monkeypatch.setenv("KAIROS_TURNSTILE", "on")
    monkeypatch.setenv("KAIROS_TURNSTILE_SITE_KEY", "1x00000000000000000000AA")
    monkeypatch.setenv("KAIROS_TURNSTILE_SECRET", "1x0000000000000000000000000000000AA")
    monkeypatch.setenv("KAIROS_TURNSTILE_HOSTNAMES", "kairos.example.org")
    assert turnstile.is_test_secret() is True
    assert "NOT a check" in turnstile.identity_report()
    warning = "\n".join(turnstile.boot_warnings())
    assert "PUBLIC TESTING keys" in warning
    assert "no human check at all" in warning
    assert "https://dash.cloudflare.com/" in warning, "the warning must say what to do"

    monkeypatch.setenv("KAIROS_TURNSTILE_SECRET", "a-real-looking-secret")
    assert turnstile.is_test_secret() is False
    assert "PUBLIC TESTING keys" not in "\n".join(turnstile.boot_warnings())


def test_a_token_solved_for_the_other_form_is_refused(monkeypatch, cap_mode, gated):
    """`action` is free, so the two gated forms cannot share a token.

    The same reason #30 gave the two anonymous forms separate CSRF uids: one form's
    proof must not be replayable at the other.
    """
    # Cloudflare reports the action the token was minted for, which here is the
    # creation form. A fresh token, so this is refused for the *action* and not for
    # having been spent -- the two are different defects and only one is ours to fix.
    gated.action = turnstile.ACTION_NEW_POLL
    verdict = turnstile.verify(_request(), {turnstile.RESPONSE_FIELD: TOKEN},
                               action=turnstile.ACTION_MANAGE_LINK)
    assert verdict.ok is False and verdict.reason == "action-mismatch"
    assert turnstile.verify(_request(), {turnstile.RESPONSE_FIELD: TOKEN2},
                            action=turnstile.ACTION_NEW_POLL).ok is True


def test_a_token_from_another_host_is_refused(monkeypatch, cap_mode, gated):
    """Defence in depth above Cloudflare's own sitekey/domain binding."""
    gated.hostname = "evil.example"
    verdict = turnstile.verify(_request(), {turnstile.RESPONSE_FIELD: TOKEN},
                               action=turnstile.ACTION_NEW_POLL)
    assert verdict.reason == "hostname-mismatch"


def test_the_hostname_check_is_derived_from_public_url_when_it_is_not_configured(monkeypatch):
    """Nearly free in this mode: capability mode already insists on PUBLIC_URL, and
    it is the same string the manage-link credential is built from."""
    monkeypatch.delenv("KAIROS_TURNSTILE_HOSTNAMES", raising=False)
    monkeypatch.setenv("KAIROS_PUBLIC_URL", "https://polls.example.org/scheduler")
    assert turnstile.expected_hostnames() == ("polls.example.org",)
    monkeypatch.delenv("KAIROS_PUBLIC_URL", raising=False)
    assert turnstile.expected_hostnames() == ()


def test_no_verifier_answer_is_a_token(live, gated):
    """`live` exists to prove the whole route, not just the predicate."""
    assert _new(live, **{turnstile.RESPONSE_FIELD: TOKEN}).status_code == 200
    assert len(live.polls) == 1
    assert len(live.relay.sent) == 1, "the manage link went out, so the check passed"


def test_neither_the_secret_nor_the_token_reaches_a_log_line(live, gated, caplog):
    """Obligation S7. The refusal log names a *reason*, never the material."""
    with caplog.at_level("DEBUG", logger="kairos.turnstile"):
        _new(live, **{turnstile.RESPONSE_FIELD: TOKEN})
    _new(live, **{turnstile.RESPONSE_FIELD: "a-token-that-was-refused"})
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert SECRET not in text, "the siteverify secret must never be logged"
    assert TOKEN not in text and "a-token-that-was-refused" not in text
    assert turnstile.site_key() == SITE_KEY, "the site key is public; the secret is not"


# -- 4. fail closed, including on "I could not check" -----------------------


@pytest.mark.parametrize("answer,reason,status", [
    (FakeCloudflare(exc=OidcError("POST https://challenges.cloudflare.com failed: no route to host")),
     "unreachable", 503),
    (FakeCloudflare(status=500), "http-500", 503),
    (FakeCloudflare(body=b"<html>maintenance</html>"), "unparseable", 503),
])
def test_an_unverifiable_check_is_refused_rather_than_assumed_human(gated, cap_mode,
                                                                   monkeypatch, answer,
                                                                   reason, status):
    """Fail closed, on the third party's availability too.

    The judgement, once: a gate that a third party's uptime controls is not a gate,
    and every "I could not check" path here is reachable only by whoever can break
    our egress to Cloudflare. The cost of this choice is one `KAIROS_TURNSTILE=off`
    away and an ERROR per attempt — the cost of the other one is the feature this
    issue exists to ship.
    """
    monkeypatch.setattr(turnstile, "http", answer)
    verdict = turnstile.verify(_request(), {turnstile.RESPONSE_FIELD: TOKEN},
                               action=turnstile.ACTION_NEW_POLL)
    assert verdict.ok is False
    assert verdict.reason == reason
    assert verdict.status_code == status
    assert verdict.detail, "an operator's outage must still produce a sentence a human can read"
    assert len(answer.calls) == 1, "no retry: a retry multiplies the dependency and the latency"


def test_an_unreachable_check_does_not_create_a_poll_or_send_mail(live, gated, monkeypatch):
    monkeypatch.setattr(turnstile, "http",
                        FakeCloudflare(exc=OidcError("no route to host")))
    response = _new(live, **{turnstile.RESPONSE_FIELD: TOKEN})
    assert response.status_code == 503
    assert live.polls == []
    assert live.relay.sent == []


def test_the_timeout_is_bounded(monkeypatch):
    """Ten seconds (oidc's default) would let an unreachable Cloudflare hold a
    worker per anonymous request, which is a free amplification primitive."""
    assert turnstile.HTTP_TIMEOUT < oidc_default_timeout()


def oidc_default_timeout():
    from kairos import oidc

    return oidc.HTTP_TIMEOUT


# -- 5. the check runs before the expensive work ----------------------------


def test_a_refused_check_never_expands_the_slot_grid(live, gated, monkeypatch):
    """The placement, not the outcome.

    `_expand_time_slots` multiplies dates by a per-date iteration count before it
    knows whether the poll is acceptable; #30 measured 992 dates at a one-minute
    increment building 1.4 million slot dicts, +2.2 GB across sixteen concurrent
    requests, every one of them answering 400. A gate that ran after that loop would
    produce the same 400 and cost the same memory, so the assertion is that the loop
    never runs — by call order, and by a ceiling on what the refusal allocated.
    """
    expanded = []
    monkeypatch.setattr(web, "_expand_time_slots",
                        lambda form, dates: expanded.append(dates) or ([], None))
    payload = _form(mode="time_slot", start_time_all="00:00", end_time_all="23:59",
                    increment="1", dates=["2026-01-05"] * 992)

    tracemalloc.start()
    try:
        response = live.client.post(
            "/scheduler/new", data={**payload, turnstile.RESPONSE_FIELD: ""})
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert response.status_code == 400
    assert expanded == [], "the grid was built before the check refused"
    assert peak < 8 * 1024 * 1024, (
        f"the refusal allocated {peak / 1024 / 1024:.0f} MB — the check is running "
        f"after the expansion, not before it"
    )
    assert live.polls == []


def test_the_check_runs_after_the_csrf_token_so_a_drive_by_costs_no_request(live, gated):
    """Order is a decision: CSRF is local, and a drive-by should not be able to
    spend this deployment's outbound budget. `#30` measured 26 such posts in a
    single drive-by."""
    forged = _form()
    forged["csrf"] = "not-a-real-token"
    assert live.client.post("/scheduler/new", data=forged).status_code == 403
    assert gated.calls == []


def test_the_check_is_not_consulted_for_an_authenticated_creation(live, gated, monkeypatch):
    """The gate is on the *accountless* branch. Header mode creates polls without
    it, and that is the ETH deployment's behaviour (ADR-0002), unchanged."""
    assert turnstile._capability_mode() is True  # this fixture is capability mode
    calls = []
    monkeypatch.setattr(turnstile, "verify",
                        lambda *a, **k: calls.append(k) or turnstile.OK)
    monkeypatch.setattr(settings, "AUTH_MODE", "header")
    # The form's CSRF is bound to the anonymous uid, which a header-mode owner does
    # not use; this test is about the human check, so the binding is stubbed the way
    # test_manage's owner fixture stubs it.
    monkeypatch.setattr(web, "require_csrf", lambda user, form: None)
    response = live.client.post("/scheduler/new", data=_form(), headers={"X-User": "ada"})
    assert calls == [], "the check must not run for an authenticated owner"
    assert response.status_code == 302, "and the poll is created exactly as before"


# -- 6. POST /manage/link has an abuse owner (#68) --------------------------


def test_an_anonymous_link_request_without_a_check_sends_no_mail(live, gated):
    """With shipped defaults a third party could aim unbounded nuisance mail at a
    victim address: the CSRF token is on every /manage page and scrapable in one
    request, and KAIROS_RATE_LIMIT defaults off. The link goes to the victim, so it
    cannot *take* a poll — but it spends this deployment's mail reputation."""
    assert _new(live, **{turnstile.RESPONSE_FIELD: TOKEN}).status_code == 200
    live.reset_mail()

    assert _link(live, "ada@example.org").status_code == 400
    assert live.relay.sent == [], "no mail without the check"
    assert "JavaScript" in _link(live, "ada@example.org").text


def test_the_re_link_form_mails_once_the_check_passes(live, gated):
    assert _new(live, **{turnstile.RESPONSE_FIELD: TOKEN}).status_code == 200
    live.reset_mail()

    assert _link(live, "ada@example.org",
                 **{turnstile.RESPONSE_FIELD: TOKEN2}).status_code == 200
    assert len(live.relay.sent) == 1


def test_a_verified_creator_is_not_asked_to_prove_it_again(live, gated):
    """They are already proof-of-human for this deployment, and the recovery path is
    where a stressed person is.

    Note what it does *not* allow: the exemption is read off a live capability, and
    one can only be obtained by having received a manage mail — so a first-time
    attacker still faces the check. What it does allow is a verified creator posting
    a victim's address, which is one nuisance mail per `send`-budget window.
    """
    assert _new(live, **{turnstile.RESPONSE_FIELD: TOKEN}).status_code == 200
    assert _exchange(live).status_code == 302
    live.reset_mail()
    assert _link(live, "ada@example.org").status_code == 200, "no token, still mailed"
    assert len(live.relay.sent) == 1


def test_the_form_carries_the_check_but_a_verified_console_does_not(live, gated):
    """A control the server ignores would spend a third-party request and teach the
    creator that the button is decoration."""
    signed_out = live.client.get("/scheduler/manage").text
    assert "data-turnstile" in signed_out and turnstile.RESPONSE_FIELD in signed_out

    assert _new(live, **{turnstile.RESPONSE_FIELD: TOKEN}).status_code == 200
    _exchange(live)
    console = live.client.get("/scheduler/manage").text
    assert "data-turnstile" not in console


# -- 7. the send-gate: NULL means may not send ------------------------------


def test_a_poll_with_no_verification_may_not_send(live):
    """The rule, and the live hole it closes: an API-created poll has NULL until a
    human opens a link, with no browser and no inbox anywhere in the loop."""
    assert _new(live).status_code == 200
    poll = live.poll()
    assert poll["manage_verified_at"] is None, "creation does not verify anyone"

    allowed, reason = capability.send_allowed(db.get_poll(poll["id"]))
    assert allowed is False and reason == "manage_verified_at is NULL"


def test_an_absent_column_reads_as_null_never_as_allowed(cap_mode):
    """`can_manage`'s docstring warns about `None in (None, None)`; the same shape
    would make a renamed column read as 'verified'."""
    assert capability.send_allowed({"id": "p1"})[0] is False
    assert capability.send_allowed({"id": "p1", "manage_verified_at": None})[0] is False
    assert capability.send_allowed(
        {"id": "p1", "manage_verified_at": "2026-01-01 00:00:00"})[0] is True


def test_the_gate_is_inert_in_every_other_auth_mode(monkeypatch):
    """The compatibility argument. In header/oidc mode the creator is identified by
    the proxy or the IdP, the column is dead, and ETH must keep working."""
    monkeypatch.setattr(settings, "AUTH_MODE", "header")
    assert capability.send_allowed({"id": "p1", "manage_verified_at": None}) == (True, "")


@pytest.mark.parametrize("method,path,body,module", [
    ("post", "/scheduler/api/polls/{id}/nudge", {"force": False}, "web"),
    ("post", "/scheduler/api/polls/{id}/email-decision", {}, "api"),
    ("post", "/scheduler/api/polls/{id}/invite", {"emails": ["a@b.ch"]}, "api"),
    ("post", "/scheduler/api/polls/{id}/slots",
     {"dates": ["2026-07-01"], "notify": True}, "api"),
])
def test_the_api_cannot_mail_on_behalf_of_an_unverified_poll(live, method, path, body, module):
    """Obligation A2 on the surface where it is actually reachable.

    `imip-decision` is left out because it refuses on configuration before the gate
    and would not exercise anything; it is covered by the predicate guard below.
    """
    assert _new(live).status_code == 200
    poll = live.poll()

    before = len(live.relay.sent)
    response = getattr(live.client, method)(path.format(id=poll["id"]), json=body, headers=API)
    assert response.status_code == 403, response.text
    assert "manage link" in response.json()["detail"], "the refusal must name the fix"
    assert len(live.relay.sent) == before, "a refused send must not open SMTP"


def test_a_verified_poll_may_send(live):
    assert _new(live).status_code == 200
    poll = live.poll()
    _exchange(live)
    assert db.get_poll(poll["id"])["manage_verified_at"] is not None
    assert capability.send_allowed(db.get_poll(poll["id"]))[0] is True


def test_the_creation_and_re_link_mail_are_deliberately_not_gated(live):
    """Otherwise the gate would be unreachable: the verification mail is how a
    creator becomes verifiable in the first place."""
    assert _new(live).status_code == 200
    assert len(live.relay.sent) == 1, "the creator's own manage link went out"
    live.reset_mail()
    assert _link(live, "ada@example.org").status_code == 200
    assert len(live.relay.sent) == 1


def test_every_pre_existing_row_is_refused_so_the_gate_ships_closed(live):
    """`manage_verified_at` was added by #29 with no backfill, so there is no window
    in which an old row reads as verified. Asserted against the real column."""
    assert _new(live).status_code == 200
    poll = live.poll()
    conn = sqlite3.connect(live.path)
    conn.execute("UPDATE sched_polls SET manage_verified_at = NULL")
    conn.commit()
    conn.close()
    assert capability.send_allowed(db.get_poll(poll["id"]))[0] is False


# -- 8. the guard: one predicate, every send path ---------------------------


class _Reached(Exception):
    """Raised by the spy, so the test stops at the gate."""


def test_every_mail_sending_route_on_the_api_consults_the_gate(monkeypatch, live):
    """A2's CI enforcement, in the shape #29's S6 guard uses: spy on the predicate
    and stop there, so this asserts *where* the gate runs and nothing about what a
    route does afterwards.

    `nudge` is not in the list on purpose — it is reached inside the shared
    `nudge_participants`, which is the one chokepoint for all five reminder paths on
    all three surfaces, and it is asserted separately below rather than duplicated
    at every call site.
    """
    reached = []

    def guard(poll):
        reached.append(poll["id"])
        raise _Reached

    monkeypatch.setattr(api, "require_sendable", guard)
    assert _new(live).status_code == 200
    poll_id = live.poll()["id"]
    for path, body in [
        (f"/scheduler/api/polls/{poll_id}/invite", {"emails": ["a@b.ch"]}),
        (f"/scheduler/api/polls/{poll_id}/email-decision", {}),
        (f"/scheduler/api/polls/{poll_id}/slots", {"dates": ["2026-07-01"], "notify": True}),
    ]:
        with pytest.raises(_Reached):
            live.client.post(path, json=body, headers=API)
    assert reached == [poll_id] * 3


def test_a_slots_request_without_notify_never_reaches_the_gate(monkeypatch, live):
    """Adding a date is not sending, and must not be refused for asking."""
    reached = []

    def guard(poll):
        reached.append(poll["id"])
        raise _Reached

    monkeypatch.setattr(api, "require_sendable", guard)
    live.client.post("/scheduler/api/polls/p1/slots",
                     json={"dates": ["2026-07-01"], "notify": False}, headers=API)
    assert reached == []


def test_every_reminder_surface_reaches_the_gate_in_one_place(monkeypatch, live, cap_mode):
    """One call in `nudge_participants` covers five routes: this module's `remind`
    and `remind-selected`, the API's `nudge` and `add_slots(notify=True)`, and the
    accountless console's `remind`. The guard proves the chokepoint is really on
    the path rather than trusting the comment that says it is."""
    reached = []

    def guard(poll):
        reached.append(poll["id"])
        raise _Reached

    assert _new(live).status_code == 200
    monkeypatch.setattr(web, "require_sendable", guard)
    poll = db.get_poll(live.poll()["id"])

    from starlette.requests import Request

    request = Request({"type": "http", "method": "POST", "path": "/",
                       "headers": [], "client": ("203.0.113.9", 5000), "scheme": "https"})
    for attempt in (
        lambda: web.nudge_participants(request, poll, {"name": "t", "email": "a@b.ch"}),
        lambda: web.nudge_participants(request, poll, {"name": "t"}, only_emails={"a@b.ch"},
                                        force=True),
    ):
        with pytest.raises(_Reached):
            attempt()
    assert reached == [poll["id"], poll["id"]]
    assert capability.require_sendable is not guard, "the console has its own name for it"


def test_the_console_actions_reach_the_gate(monkeypatch, live):
    reached = []

    def guard(poll):
        reached.append(poll["id"])
        raise _Reached

    monkeypatch.setattr(capability, "require_sendable", guard)
    assert _new(live).status_code == 200
    poll = live.poll()
    csrf = make_csrf(poll["id"])
    _exchange(live)  # the exchange itself must not be gated

    for action in ("remind", "email-decision"):
        with pytest.raises(_Reached):
            live.client.post(f"/scheduler/manage/{poll['id']}/{action}",
                             data={"csrf": csrf})
    assert reached == [poll["id"], poll["id"]]


def test_the_decision_mail_on_the_web_owner_surface_reaches_the_gate(monkeypatch, live):
    """Unreachable in capability mode (`get_user` returns None, so the route answers
    401 first) and called anyway: a gate that is only on the reachable paths is not
    a predicate, it is a patch."""
    reached = []

    def guard(poll):
        reached.append(poll["id"])
        raise _Reached

    assert _new(live).status_code == 200
    monkeypatch.setattr(web, "get_user", lambda request: {"uid": "ada", "name": "Ada"})
    monkeypatch.setattr(web, "require_csrf", lambda user, form: None)
    monkeypatch.setattr(web, "require_sendable", guard)
    poll = dict(live.poll())
    poll["creator_id"] = "ada"
    monkeypatch.setattr(web, "get_poll", lambda pid: dict(poll))
    with pytest.raises(_Reached):
        live.client.post(f"/scheduler/polls/{poll['id']}/email-decision", data={})
    assert reached == [poll["id"]]


def test_the_predicate_is_not_reimplemented_at_a_call_site():
    """A tripwire, like #29's: catches the column being read inline instead. Modest
    on purpose — it only catches the exact shape, which is the likely mistake."""
    offenders = [m for m in ("web.py", "api.py", "capability.py")
                 if re.search(r'manage_verified_at\s*(?!.*# )', (SRC / m).read_text())
                 and "require_sendable" not in (SRC / m).read_text()]
    assert not offenders, f"{offenders} read manage_verified_at without the predicate"
    assert 'poll.get("manage_verified_at")' in (SRC / "capability.py").read_text()


# -- 9. P1 / P4 ------------------------------------------------------------


def test_privacy_names_the_third_party_only_where_there_is_one(monkeypatch, cap_mode):
    monkeypatch.setattr(settings, "OPERATOR", "Example Lab")
    with TestClient(main.create_app(), base_url="https://testserver") as client:
        plain = client.get("/scheduler/privacy").text
        assert "Turnstile" not in plain
        assert "no consent banner is required" in plain

        monkeypatch.setenv("KAIROS_TURNSTILE", "on")
        monkeypatch.setenv("KAIROS_TURNSTILE_SITE_KEY", SITE_KEY)
        monkeypatch.setenv("KAIROS_TURNSTILE_SECRET", SECRET)
        gated_privacy = client.get("/scheduler/privacy").text
    assert "challenges.cloudflare.com" in gated_privacy
    assert "Nothing is loaded from Cloudflare until you press the button" in gated_privacy
    # P1 survives because the facade is unconditional: the sentence is the same one
    # the page has always carried, not a weakened version of it.
    assert "No tracking, no analytics, no third-party cookies; therefore no consent " \
           "banner is required." in gated_privacy


def test_the_facade_loads_nothing_until_it_is_asked(live, gated):
    """The mechanism P1 rests on, asserted on the rendered page: Cloudflare's origin
    appears once, as a `data-script` attribute for the JS to read — never in a
    `<script src>` or `<iframe src>`, which a browser would fetch on page view."""
    body = live.client.get("/scheduler/new").text
    assert body.count("challenges.cloudflare.com") == 1
    assert 'data-script="https://challenges.cloudflare.com' in body
    assert "<script src=\"https://challenges.cloudflare.com" not in body
    assert "challenges.cloudflare.com" not in re.sub(
        r'data-script="[^"]*"', "", body), "nothing else may reference the third party"
    assert f'name="{turnstile.RESPONSE_FIELD}"' in body
    assert "turnstile.js" in body, "the facade's own script is same-origin"


def test_no_facade_survives_a_verified_console_render(live, gated):
    assert _new(live, **{turnstile.RESPONSE_FIELD: TOKEN}).status_code == 200
    _exchange(live)
    assert "challenges.cloudflare.com" not in live.client.get("/scheduler/manage").text


def test_the_two_forms_are_given_different_actions():
    """The property the action field buys, asserted on the templates rather than on
    the constants: a token solved on one form cannot be replayed at the other."""
    assert turnstile.ACTION_NEW_POLL != turnstile.ACTION_MANAGE_LINK
    for action in (turnstile.ACTION_NEW_POLL, turnstile.ACTION_MANAGE_LINK):
        assert re.fullmatch(r"[a-zA-Z0-9_-]{1,32}", action), "Cloudflare's own limit"
