"""Per-poll *reach*: which polls a caller may read, on every surface.

Issues #63 and #64, which are one defect on two surfaces.

**The defect.** The web UI and the API answered the same question about the same
row differently, and the weaker answer was the machine-facing one. `GET
/polls/{id}` carried every respondent's name and per-slot availability to any
holder of a `polls:read` key, and `GET /polls` listed the whole instance to the
same key; on the web, `view_poll` rendered a stranger's poll and its whole
availability grid, while rendering the participants table only to the owner. A
capability (a scope, #51) answers *what a caller may do*; nothing answered *which
polls that is*, because nothing in the data model attaches an identity to a poll
that two different API keys could tell apart. That is reach, and this module is it.

**The model.** One predicate, `can_reach`, consulted by both surfaces:

    open      any authenticated caller reaches any poll. This is the rule that has
              always existed. It is the default everywhere except a deployment
              that declared itself hosted, and it is what the ETH group deployment
              needs (ADR-0002: in header mode the authenticating proxy *is* the
              tenant boundary — Kairos has no group membership of its own to scope
              reads with).
    scoped    reach is per poll, and is the union of two things:
                * management authority — `can_manage` (#29): the poll's
                  `creator_id` / `owner_id`, or possession of its `admin_token`.
                  Management implies reach on any surface, so #30's
                  `/manage/<token>` route gets reach without being told about it.
                * *being named on the poll* — the web surface only: an invite
                  addressed to the caller, or a response already bound to the
                  caller's uid or address. This is the scoped-visibility answer to
                  "ETH shares polls across a group": invited people and people who
                  have already answered keep working, and only an unrelated identity
                  loses the page. It does *not* apply to a bearer key, because a key
                  is not a person: every API principal shares the uid `"api"`, so an
                  identity rule would hand every key every poll it made — the same
                  fail-open shape #29's review caught in `can_manage`.

**Why a policy switch and not a flat owner check.** ADR-0001/0002 forbid changing
the self-host and ETH behaviour, and the hard constraint here is that every read
which is legal today stays legal in the default configuration — which, for a
self-hoster, is `open`. So the default is `open`, the strict policy is one variable
away, and `KAIROS_HOSTED` — the knob that already means "a deployment *we* operate",
and already gates mail identity (M1/#48) — turns it on by default, because the
hosted accountless product is the multi-tenant case where `open` *is* the IDOR. A
deployment that predates this file keeps the rule it had; the deployment where the
defect is a genuine vulnerability gets the fix without anyone having to remember a
flag.

**Two enforcement points, one predicate.** On the API surface reach is a pure
function of the poll id in the path and the key's grant, so it is enforced by the
route's `api_scope(..., reach=True)` declaration, ahead of the handler, where the
CI audit can see it (`guard_reach`). On the web surface the decision needs the poll
row and the caller's rows, so the routes ask in one line where they already have
the poll (`can_reach`). Both call `can_reach`; neither re-decides the rule.

**Both enforcement points fail closed on their own inputs.** A declaration of
`reach=True` that cannot identify *which* poll is refused (`required_poll_id`
raises) rather than allowed through, because "I could not tell" and "you may read
it" must never be the same answer; and the poll id is read off the route's path
*template* rather than by matching the literal name `poll_id`, so a route that
spells its parameter `{pid}` is guarded and audited exactly like one that spells it
`{poll_id}`. The first review of this PR found both halves of that missing at once
and demonstrated the consequence: a rogue `{pid}` route handed a `polls:read` key
every respondent on the instance while the suite stayed green.

**What each surface answers with a refusal, and why it differs.** The API surface
answers 403 and never consults the poll, so "not yours" and "does not exist" are
literally the same code path — it cannot tell them apart, which is the whole reason
there is no existence oracle there. The web surface *has* to read the poll to
decide (its rule includes "named on this poll"), so it could tell them apart and
therefore must not: a web refusal is **the missing poll's own 404, byte for byte**,
rendered by one shared function (`web._not_yours_or_gone`) that both the missing
and the refusing branch call — same status, same heading, same empty detail, same
body. A 60-byte sentence on the refusal only was measured on the live app by the
second review and was still an oracle; the identity has to be in the bytes, not in
the status code. That is also why there is no `require_reach` counterpart to
`require_manage` (#29): a helper that raised one status for a refusal while the
route raised another for a missing poll *was* the oracle. The ICS is the same idea
one line long — one branch, one bare `HTTPException(404)`.

**What is deliberately not modelled here.** Per-account reach (#32) and per-plan
reach (#33). Both need an identity the data model does not have yet:
`creator_id` on an API-created poll is the literal string `"api"` for *every* key,
so nothing downstream can infer "the key that made this poll" from the row — which
is also why a key cannot be auto-granted reach over the poll it just created.
`can_reach` is the seam: it takes a poll and a caller and nothing else, so adding
"and this poll's owner is this account" is a local change here.
"""

import logging
from typing import NamedTuple

from fastapi import HTTPException, Request

from kairos import settings
from kairos.auth import can_manage, get_user
from kairos.db import get_invites, get_responses

log = logging.getLogger("kairos.reach")

POLICIES = ("open", "scoped")
OPEN = "open"
SCOPED = "scoped"

# The spelling of an instance-wide grant in `KAIROS_API_KEYS` (`KEY:scopes~*`).
ALL_POLL_CLAIM = "*"


class EveryPoll:
    """The sentinel for "this caller reaches every poll on the instance".

    An object rather than `None` or `"*"` on purpose. #29's review found a real
    fail-open in exactly this shape — `None in (None, None)` granted management of
    every poll whose ownership columns were NULL — so a *missing* value here must
    never read as a value that means "everything". Absent is nothing.
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover — a log/debug affordance
        return "<every poll>"


EVERY_POLL = EveryPoll()

# What a principal reaches: `EVERY_POLL`, or a frozenset of poll ids.
Grant = "EveryPoll | frozenset[str]"


class Reached(NamedTuple):
    """A caller's reach as `whoami` reports it. Never the credential."""

    polls: list[str] | str
    policy: str


# -- The policy --------------------------------------------------------------


def _raw() -> str:
    """`KAIROS_POLL_REACH`, or "".

    The `settings.X or os.environ[...]` shape is `scoping.keyring()`'s, and is
    here for the same reason: a value exported after import (or set by a test's
    `monkeypatch.setenv`) has to be visible through either door, or one spelling of
    the knob is honoured and the other silently ignored.
    """
    import os

    return settings.POLL_REACH or os.environ.get("KAIROS_POLL_REACH", "")


def policy() -> str:
    """The reach policy in force: `"open"` or `"scoped"`. Read at call time.

    Unset means `scoped` when `KAIROS_HOSTED` is on and `open` otherwise. That
    default is the whole compatibility argument, and it reuses the one switch that
    already declares "this is a deployment we operate" rather than inventing a
    second notion of hosted-ness that could disagree with it.

    **An unrecognised `KAIROS_HOSTED` is `scoped` here, deliberately against the
    mail gate's reading.** `settings` enumerates both spellings — `settings.HOSTED_
    TRUE` (`1/on/true/yes/y`) and `settings.HOSTED_FALSE` (`0/off/false/no/n/f`) —
    and anything else leaves `HOSTED` False with `HOSTED_UNKNOWN` True, which the
    M1 gate reads as *off*: the safe direction for a self-hoster whose relay
    authenticates their own mail. This function used to inherit that reading, and
    the consequence was that `KAIROS_HOSTED=enabled` (and, before the sets were
    spelled out, `Y` and `n`) quietly selected `open`, the permissive policy, on the
    deployment that had just asked to be treated as hosted — a typo was a fail-open
    on the exact control that made HOSTED matter, and `n`, the likeliest spelling of
    "not hosted", made a self-hoster strict. The two readings now differ on purpose,
    because the costs are not symmetric. Getting the mail gate wrong costs a warning
    about DNS records nobody here can publish; getting *this* wrong costs every
    respondent name on the instance. So an unknown value is read as "the operator
    meant hosted, and misspelled it" and gets the strict policy, which is also the
    recoverable one — a self-hoster who meant otherwise sets `KAIROS_POLL_REACH=open`
    and gets back exactly the pre-#63 behaviour, and `boot_warnings` says so by name.

    An unrecognised `KAIROS_POLL_REACH` refuses — a `RuntimeError` here fails the
    boot, because `scoping.boot_report` calls this at startup — rather than
    falling back to either reading. A typo that silently picked `open` would leave
    an operator believing a control is in force that is not; one that silently
    picked `scoped` would lock a deployment out of its own polls. Both are worse
    than a refusal at boot.
    """
    raw = _raw().strip().lower()
    if not raw:
        return SCOPED if settings.HOSTED or settings.HOSTED_UNKNOWN else OPEN
    if raw not in POLICIES:
        raise RuntimeError(f"KAIROS_POLL_REACH: {raw!r} is not a reach policy (known: {', '.join(POLICIES)})")
    return raw


def boot_warnings() -> list[str]:
    """Reach warnings: a control an operator believes is in force and is not.

    The same convention as `oidc.boot_warnings` — returned, not logged here, and
    printed as `log.warning` next to the INFO boot line by `main.create_app`.
    Reach was INFO-only, which is exactly the wrong level for the two states where
    the deployment is not what the operator believes:

      * `KAIROS_HOSTED` set to something unrecognised, which `policy` now reads as
        hosted (`scoped`) while the mail gate reads it as off. Both readings are
        correct for their own control; an operator holding only the boot log
        should not have to guess which one is in force.
      * `scoped` in header mode with no trusted-proxy CIDRs, where reach is exactly
        as strong as a header anybody can assert. Without a CIDR list the app
        trusts every peer, so `X-User: <creator uid>` is reach on demand and the
        strict policy is decorative.
    """
    warnings = []
    if settings.HOSTED_UNKNOWN:
        warnings.append(
            f"KAIROS_HOSTED={settings.HOSTED_RAW!r} is not a value Kairos recognises, so it says "
            f"neither 'hosted' nor 'self-hosted'. Poll reach is therefore SCOPED — the fail-closed "
            f"reading, because this knob decides who may read which poll — while the mail gate "
            f"(M1) still reads it as OFF. Fix the spelling, or set KAIROS_POLL_REACH=open if "
            f"this really is a self-hosted deployment."
        )
    if policy() == SCOPED and settings.AUTH_MODE == "header" and not settings.TRUSTED_PROXY_NETWORKS:
        warnings.append(
            "poll reach is SCOPED in header mode with no KAIROS_TRUSTED_PROXY_CIDRS: reach is "
            "then only as strong as the identity headers, so anyone who can reach this port can "
            "assert X-User: <a creator uid> and reach that creator's polls. Put the app behind a "
            "proxy and name its CIDRs, or treat reach as decorative."
        )
    return warnings


# -- Who reaches what --------------------------------------------------------


def grant_for(principal: dict | None) -> Grant:
    """The reach grant a principal carries. Default-deny.

    Absent is *nothing*: a hand-built principal, a stub in a test, or a code path
    that resolved a key without recording its grant must not be read as
    "instance-wide". The one caller that does reach every poll is the principal
    `scoping.resolve` builds for the legacy `KAIROS_API_KEY`, and it says so with
    `EVERY_POLL` rather than by omission.
    """
    if principal is None:
        return frozenset()
    return principal.get("polls", frozenset())


def key_reaches(principal: dict | None, poll_id: str) -> bool:
    """May this bearer key read this poll id? All of reach on the API surface.

    A pure function of the id and the grant — no database read — and that is the
    property that lets `guard_reach` run ahead of the handler without costing a
    query, decide before the route has looked at a row, and refuse an id without
    ever distinguishing "exists but not yours" from "does not exist".

    `grant_for` is the fail-closed half: a principal with no claim reaches nothing.
    """
    grant = grant_for(principal)
    return grant is EVERY_POLL or poll_id in grant


def named_on_poll(
    poll_id: str,
    user: dict | None,
    *,
    participants: tuple[list[dict], list[dict]] | None = None,
) -> bool:
    """Is this identity named on this poll — invited, or already answered?

    Two independent matches, because the two ways somebody becomes a participant
    leave different traces:

      * **uid** — `public.py` binds `user_id` onto the response it writes for an
        authenticated respondent, so a signed-in participant matches exactly.
      * **address** — an invite is addressed to an address, and an anonymous
        respondent is bound to one (`respondent_email`). Lowercased and stripped,
        because both sides are typed by hand.

    The address is only as trustworthy as the identity carrying it: in header mode
    the proxy vouches for it, in OIDC mode the IdP does. Reach never invents an
    identity; it asks what the deployment already decided this caller is.

    `participants` is the `(responses, invites)` pair a caller already has in hand,
    so the poll page — which fetches both for the grid anyway — does not pay for
    them twice. Omitted, they are read here.

    Fails closed with no identity, and with an identity that has no address: these
    comparisons are the only thing standing between a stranger and a group's
    participant list.
    """
    user = user or {}
    uid, email = user.get("uid"), (user.get("email") or "").strip().lower()
    if not uid and not email:
        return False
    if participants is None:
        participants = (get_responses(poll_id), get_invites(poll_id))
    responses, invites = participants
    if uid and any(r.get("user_id") == uid for r in responses):
        return True
    if not email:
        return False
    if any((r.get("respondent_email") or "").strip().lower() == email for r in responses):
        return True
    return any((i.get("email") or "").strip().lower() == email for i in invites)


def can_reach(
    poll: dict,
    request: Request,
    *,
    user: dict | None = None,
    principal: dict | None = None,
    token: str | None = None,
    participants: tuple[list[dict], list[dict]] | None = None,
) -> bool:
    """May the caller of `request` read `poll`? The one predicate both surfaces ask.

    `user` is an already-resolved web identity and `principal` an already-resolved
    bearer key; each surface passes the one it resolved, so neither `auth.get_user`
    (a documented runtime seam) nor the keyring is walked twice for one request.

    `token` is a management capability the caller presented, forwarded to
    `can_manage` and never sniffed out of the request — for #30's anonymous
    `/manage/<token>` route, which is a reader of this poll as much as a manager of
    it. Nothing on the current web surface passes one.

    Reach is *not* management. It says "this row is yours to read"; a caller who
    reaches a poll may still be refused every mutating route on it, and management
    authority is `can_manage` (#29). The other direction does hold — a manager
    always reaches — which is why `can_manage` is consulted first, and why #30's
    anonymous `/manage/<admin_token>` route inherits reach from it.
    """
    if policy() == OPEN:
        return True
    if principal is not None:
        return key_reaches(principal, poll["id"])
    # No key on this request: a web identity. `can_manage` resolves it itself when
    # the caller has not, which is what an unauthenticated route wants.
    if can_manage(poll, request, token=token, user=user):
        return True
    return named_on_poll(
        poll["id"],
        user if user is not None else get_user(request),
        participants=participants,
    )


def _refuse_key(principal: dict, poll_id: str) -> None:
    """403 for a bearer key that was not granted this poll, naming what it holds.

    Legible for the reason `enforce`'s is (#51): an agent that meets a 403 it was
    never told about cannot plan, and an operator cannot debug a grant they never
    wrote. Never names the key — only its digest, in the log line, on the same rule
    every other credential in this app follows.
    """
    grant = grant_for(principal)
    held = "every poll" if grant is EVERY_POLL else ", ".join(sorted(grant)) or "no polls"
    log.warning("key %s may not reach poll %s (reach: %s)", principal.get("key_id", "?"), poll_id, held)
    raise HTTPException(
        403,
        f"This API key may not reach poll {poll_id}. It reaches: {held}. "
        f"Ask the operator to grant it reach (KAIROS_API_KEYS, '~<poll-id>'), "
        f"or to widen the deployment's KAIROS_POLL_REACH.",
    )


def only_reachable(polls: list[dict], request: Request, **kwargs) -> list[dict]:
    """`polls` filtered to what the caller may reach — `GET /polls` under `scoped`.

    Empty rather than 403, deliberately, and this answers the question #63 left open:
    the list route is *legal* for a scoped reader, it simply has nothing in scope,
    and a 403 there would tell a correctly-scoped agent that something is wrong with
    its configuration when the configuration it has is exactly right. Discoverability
    comes from `whoami`, which reports the reach instead of the list hiding it.

    Under `open` this returns the argument unchanged without asking the predicate
    about a single row — so the default configuration does not even walk the polls.
    """
    if policy() == OPEN:
        return polls
    return [poll for poll in polls if can_reach(poll, request, **kwargs)]


# -- The route-side seam -----------------------------------------------------

# The path segment a poll id follows, in both surfaces' shapes (`/polls/{...}`,
# `/api/polls/{...}`). Structural on purpose: the first review of this PR found
# `poll_id_of` and the audit both matching the literal name `poll_id`, so a route
# that spelled its parameter `{pid}` was unguarded *and* invisible to the audit.
# The singular is listed too so a route spelled `/poll/{poll_id}` is not a hole of
# the same kind; nothing on the live route table is spelled that way, and the one
# route with a `poll` segment (`POST /api/imip/poll`) ends in it, so it reads as no
# poll route either way.
_POLL_SEGMENTS = ("polls", "poll")

# The house spelling, used only where there is no route template to read (a
# hand-built scope, a test). Never as the rule: the rule is `poll_param`.
_POLL_ID = "poll_id"


def _segments(path: str) -> list[str]:
    return [s for s in str(path or "").split("/") if s]


def names_poll(path: str) -> bool:
    """Does this route's path identify a poll — one, or a set of them?

    The question both audits ask, and deliberately **wider** than `poll_param`.
    A route under a `polls` segment that is not the bare collection is a route
    *about* polls: it names one in the path, or it names some in a body or a query
    string, and either way it has to say where its authorization comes from. Only
    the collection itself (`/polls`, with nothing after it) is exempt — it is the
    one route whose whole answer is "what the caller reaches".

    The wider shape exists because the narrow one had a hole the second review
    found and demonstrated: `POST /api/polls/export`, with ids in the body,
    satisfied #51's scope audit *and* the reach audit while being unguarded, and
    answered 200 with `{"exported": ["p1", "p2", "p3"]}` to a key granted `p1`
    alone. Same for `/polls/bulk/{x}` and `/polls/export`. A path shape cannot tell
    us where such a route keeps its ids, so the rule is not "I found a parameter" —
    it is "this is a poll route, so where is the guard?". Nothing in the live route
    table is affected; that is what makes it safe to widen.
    """
    segments = _segments(path)
    for i, segment in enumerate(segments):
        if segment in _POLL_SEGMENTS:
            return i + 1 < len(segments)  # the bare collection names no single poll
    return False


def poll_param(path: str) -> str | None:
    """The path-parameter name that holds the poll id in `path`, or None.

    Found *structurally* — the `{...}` parameter immediately following the `polls`
    segment — rather than by matching a literal `{poll_id}`, because the name a
    route happens to use is a spelling and not the rule. A route that writes
    `/polls/{pid}` is guarded by exactly the same predicate as one that writes
    `/polls/{poll_id}`, and the CI audit asks the same question of both.

    None for a route this shape cannot resolve — `/polls`, or `/polls/export`, whose
    ids are somewhere this cannot see. Those are the routes `required_poll_id`
    refuses, and `names_poll` is what puts them in front of the audit.
    """
    segments = _segments(path)
    for i, segment in enumerate(segments):
        if segment not in _POLL_SEGMENTS or i + 1 >= len(segments):
            continue
        candidate = segments[i + 1]
        if len(candidate) > 2 and candidate.startswith("{") and candidate.endswith("}"):
            return candidate[1:-1]
    return None


def route_path(request: Request) -> str:
    """The path template of the route serving `request`, or "".

    Read off the scope's route object rather than off the request URL, because the
    *template* is what says which parameter is the poll id — the concrete path has
    the id's value in it and no name.
    """
    route = (request.scope or {}).get("route")
    return getattr(route, "path_format", "") or getattr(route, "path", "") or ""


def poll_id_of(request: Request) -> str | None:
    """The poll id in this request's path, or None if the route names no poll.

    Read from `request.path_params` — a dependency runs before the handler and
    before its arguments are bound, and the path params are the one thing already
    resolved on the scope by then — but *which* parameter is looked up comes from
    the route's own template (`poll_param`), never from a hard-coded name.

    None rather than raising for a route with no poll in its path: a declared reach
    on such a route reaches no poll, and `required_poll_id` is what turns that into
    a refusal. The audit test is what makes sure no *poll-id* route forgot to
    declare one, and it asks the same structural question.
    """
    params = request.path_params or {}
    name = poll_param(route_path(request))
    if name:
        return params.get(name)
    return params.get(_POLL_ID)


def required_poll_id(request: Request) -> str:
    """`poll_id_of(request)`, or a loud failure — never a silent pass.

    The rule `guard_reach` turns into a decision. A declared reach whose route does
    not resolve to exactly one poll is *not* an authorization anyone can evaluate,
    and the two available answers are both wrong in the same direction: guessing
    "no poll, therefore nothing to refuse" hands the caller whatever the handler
    reads, which is #63's defect with a new name on it. So the guard refuses the
    request (a 500, not a 403 — this is a bug in the route, not a caller's
    mistake) and says which route and what it expected.
    """
    poll_id = poll_id_of(request)
    if not poll_id:
        raise RuntimeError(
            f"{route_path(request) or '(unknown route)'}: reach was declared but no poll id "
            f"resolves from this request's path — expected a '{{...}}' parameter after "
            f"'/polls/'. If this route takes its ids from a body or a query string, "
            f"reach cannot be declared here: authorize each id against the caller's grant "
            f"yourself. Refusing rather than allowing an authorization that cannot name "
            f"its poll."
        )
    return poll_id


def guard_reach(request: Request, principal: dict) -> None:
    """The declared half: enforce reach before a poll-id route's handler runs.

    Called by `scoping.api_scope` for every route declaring `reach=True`, with the
    principal it has just resolved, so a poll-id route is authorized by its
    *declaration* rather than by remembering to call something — the property the
    audit test checks against the live route table, which is what stops a new
    poll-id route shipping with no reach. The same principal is left on
    `request.state.api_principal` for the route's own use.

    Three properties follow from reach on this surface being a pure function of the
    path id, and all three are worth having:

    * **no query.** Under `open` this returns immediately, so the default
      configuration spends not one statement more than before this file existed; under
      `scoped` it decides without reading the poll, so a caller who may not reach a
      poll cannot even make the app look the row up.
    * **no existence oracle.** An id the key was not granted gets 403 whether or not
      a poll with that id exists; no code path here can tell the difference. Poll
      ids are UUID4, so the oracle would have been worthless anyway — not having one
      is a property, not a fix.
    * **no silent pass.** `reach=True` on a route whose poll id does not resolve is
      a `RuntimeError`, not a `return` (see `required_poll_id`). The first review of
      this PR shipped the silent pass, and it was not theoretical: a route naming its
      parameter `{pid}` skipped the check entirely while the audit — matching the
      same literal — reported the route table clean, and a `polls:read` key read
      every respondent on the instance with the suite green.
    """
    if policy() == OPEN:
        return
    poll_id = required_poll_id(request)
    if not key_reaches(principal, poll_id):
        _refuse_key(principal, poll_id)


def reached_by(principal: dict | None) -> Reached:
    """What `whoami` reports: the caller's reach, and the policy in force.

    Readable on purpose, on #51's discoverability argument: an agent that meets a
    403 it was never told about cannot plan. Never the key, and never more than it
    has to say — `"*"` for an instance-wide grant, because an agent that has to diff
    a forty-entry poll list to learn "you may read everything" will not read it at
    all.
    """
    grant = grant_for(principal)
    return Reached(polls="*" if grant is EVERY_POLL else sorted(grant), policy=policy())
