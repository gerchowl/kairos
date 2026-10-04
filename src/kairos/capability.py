"""Accountless poll management by emailed capability link — `KAIROS_AUTH=capability`.

Issue #30: step 2 of the hosted chain (#29 `admin_token` + one `require_manage`
predicate → this → #31 Turnstile + the `manage_verified_at` send-gate). A poll is
managed with **no account and no proxy**: possession of a link that was mailed to
the creator *is* the credential, which is the same shape as the `public_token`
and invite tokens this app already hands out and has always treated as secrets.

The flow, in the order the requests happen:

    POST {prefix}/new                 creator supplies an email address; the poll
                                     is created with owner_id NULL and a minted
                                     admin_token, and the manage link is MAILED
    GET  {prefix}/manage/<token>      interstitial — "open your poll". Renders a
                                     form; does NOT consume the token, because a
                                     mail-scanner prefetch would (see below)
    POST {prefix}/manage/<token>      the exchange: authorize with the token,
                                     stamp manage_verified_at, ROTATE the token,
                                     set a signed capability cookie, 302 to
                                     {prefix}/manage — a URL with no token in it
    GET  {prefix}/manage              the console: one poll, and from here on the
                                     session cookie is the credential
    POST {prefix}/manage/<id>/<act>   close / reopen / decide / invite / remind /
                                     email-decision / edit / delete
    POST {prefix}/manage/link         "email me a new link" for an address that
                                     already created a poll here

**A magic link is not a session, and the exchange is the difference.** The token
in the URL is minted once, at creation, and is consumed by the first successful
exchange — `rotate_admin_token` replaces it in the row and the *new* value is
what goes into the cookie. So the link that travelled through an inbox stops
working the moment anyone opens it, and a link copied out of browser history, out
of a proxy log, or out of a forwarded mail is worthless. What the browser holds
afterwards is a signed, time-limited cookie (`KAIROS_CAPABILITY_SESSION_HOURS`,
default 12h — #53's owner-session lifetime, for the same reason: a working day,
and a scheduling poll is a short-lived artefact). The cookie carries the
capability itself, so rotation retires older cookies too, instead of leaving them
as parallel credentials nobody remembers to revoke.

**Lifetimes, stated plainly rather than invented.** The emailed link has **no
clock**: it does not expire, exactly like `public_token` and invite tokens, which
never have. It expires by *use*, and that is the only expiry on it. How long that
is worth is a product decision (#33), not one to smuggle in as a default TTL. The
session cookie is bounded at 12h and is re-minted by opening a fresh link.

**Two-step exchange, on purpose.** Link prefetching — Outlook Safe Links,
Proofpoint, and every corporate URL scanner — follows links in inbound mail with a
GET. A GET that consumed the token would spend the creator's only credential
before they clicked anything, and the failure would look like "Kairos lost my
poll". So the GET renders a page and the POST consumes the token, which also
keeps the cookie-setting off a GET.

**Rotation is a real cost, and it is paid down.** One link, one browser: opening
it on a second device fails, because the first exchange already rotated the token.
That is the intended trade — a link usable twice from two devices is a link
somebody forwarded and forgot about — and `POST /manage/link` is the way back: it
re-mails a link to an address that already created a poll here. The answer is
identical in the *body* whether or not anything matched, so the response is not an
address oracle; the response *time* was one (a match opens SMTP, a miss does not —
87x measured), and is now held to a floor. See `LINK_REQUEST_FLOOR_SECONDS` for
what that does and does not fix, and for why the honest sentence is longer than the
one this paragraph used to be.

**A capability in a URL is in the access log.** `GET /manage/<token>` puts the live
token in whatever the front end writes down, and for a link nobody ever opens it
stays valid forever *and* stays in the log forever. Kairos never writes a token to
its own logs — no log line in this file carries one, and that is asserted — but the
access log is the reverse proxy's or uvicorn's, and the token is in the request
line. So the README and `docs/design/{multitenancy-hosting,self-host-hardening}.md`
say so plainly, because this is the one credential in the app whose exposure is
decided entirely outside it: the mitigations that exist are single use (the token
dies the moment it is exchanged), `Referrer-Policy: no-referrer` on the one page
whose URL carries it, and no creator address in any log line — and the mitigation
left is the operator's, redact that path or keep those logs short-lived. There is
no logout route in this mode, so a shared browser ends its session by expiry or by
opening a fresh link, not by a button — deliberate for this issue (a logout that
cannot revoke the *link* would be a misleading half-measure) and worth revisiting
with #32's accounts.

**Every anonymous POST here is CSRF-bound.** `POST /new` and `POST /manage/link`
both carry a token minted by this app and both check it, against a constant uid
rather than a session — the same bargain the creation form has always made. It
proves the POST came from a page Kairos rendered; it does not prove who sent it, so
it is not an authorisation control and is not described as one. It does mean an
unrelated website cannot make a visitor's browser have this deployment send mail
(`LINK_FORM_UID` for the detail).

**What this composes with, and what it deliberately does not touch.**

  * #29's `require_manage(poll, request, token=...)` is the *only* thing that
    authorizes anything here, called with no `user` — exactly the anonymous
    capability shape it was documented for. It fails closed on a NULL
    `admin_token` and on an absent uid. No route in this file compares a token or
    an owner by hand.
  * #37's `rate_limit` is charged on the token routes (`read`) and on the re-link
    request (`send`, the budget every SMTP-opening route already draws on). No
    new rule name, so `KAIROS_RATE_LIMIT_<RULE>` keeps one vocabulary.
  * #51's `charge_poll_recipients` is charged by the send action, so this console
    draws on the same per-poll budget as the owner UI and the API — one ceiling,
    not two kept in step by review (ADR-0012).
  * #48's `is_configured()` is consulted before a poll is created, because in
    this mode outbound mail is not a poll feature — it is *how the credential is
    delivered*. A deployment that cannot send cannot run this mode honestly, and
    says so instead of minting a poll nobody can open.
  * `auth.get_user` is untouched and returns None here: there is no account to
    resolve, and the documented runtime seam keeps its shape. The console is its
    own small surface rather than a mode-dependent rewrite of `web.py`, which is
    what keeps #63/#64 (per-poll authorization on the owner and API surfaces) from
    having to know this mode exists.

**#31 built on this, and what it added.** `mark_manage_verified` writes
`manage_verified_at` on the first successful exchange — #29 handed that write to
that issue, and the column was otherwise dead. `require_sendable` below now reads
it (obligation A2) and every outbound path consults that one predicate; and
`POST /new` and `POST /manage/link` now run Cloudflare Turnstile server-side
(obligation A1, `kairos.turnstile`). Neither the send-gate nor the human check
touches the two routes that mail *the creator's own address* — creation and
`POST /manage/link` — because those are how a creator becomes verifiable in the
first place, and gating them would close the hole by deleting the feature.

Env-only (ADR-0003) and parsed here rather than in `settings.py`, the way
`oidc.py` keeps the whole OIDC mode in one file: a stray `KAIROS_CAPABILITY_*` in
a self-hoster's environment must not break a deployment that never opted in
(ADR-0001/0002), so an unusable value is a boot warning and never an import error
outside this mode. The exception is `SESSION_SECRET`, which is not a policy knob but
a requirement of the mode — see the gate beside `SESSION_HOURS` for why that one
refuses to boot and lands nowhere else.
"""

import logging
import os
import secrets
import time
from itertools import islice

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, SignatureExpired

from kairos import settings
from kairos.auth import _serializer, can_manage, get_base_url, require_manage
from kairos.csrf import make_csrf, require_csrf
from kairos.db import (
    add_slots,
    create_invite,
    create_poll,
    delete_poll,
    get_invites,
    get_poll,
    get_poll_by_admin_token,
    get_responses,
    list_polls_by_creator_email,
    log_contact,
    mark_manage_verified,
    rotate_admin_token,
    update_poll,
)
from kairos.email_service import is_configured, send_decision_email, send_manage_email, sender_refusal
from kairos.helpers import TIMEZONES, convergence, env, expected_counts, format_slot
from kairos.http import form_data, valid_email
from kairos.oidc import _is_https
from kairos.ratelimit import RateLimited, caller_key, limiter, rate_limit
from kairos.scoping import charge_poll_recipients
from kairos.templating import render
from kairos.turnstile import ACTION_MANAGE_LINK, ACTION_NEW_POLL, widget_ctx
from kairos.turnstile import required as turnstile_required
from kairos.turnstile import verify as verify_human

log = logging.getLogger("kairos.capability")

P = settings.PREFIX
router = APIRouter(prefix=P) if P else APIRouter()

SESSION_COOKIE = "kairos_cap"
# Scoped to the console, narrower than the app-wide path #53 uses for its own
# session cookie: a management capability is the *only* credential here, so it has
# no business travelling to /p/<token> or /p/i/<token>.
SESSION_PATH = f"{P}/manage" if P else "/manage"

DEFAULT_SESSION_HOURS = 12
BOOT_WARNINGS: list[str] = []

# The CSRF binding for the *anonymous creation form*. A poll can be created
# without an account, but not without a token this app minted, so the form binds
# to a constant uid exactly the way `demo` mode binds to "demo": it proves the
# POST came from a page this app rendered, not that anybody is signed in. The
# console's own forms bind to the poll id instead.
ANON_FORM_UID = "anon:new-poll"

# The same binding for the *re-link* form, which is on every `/manage` page and
# which an unrelated website can reach with nothing but a victim's browser. Without
# it this route was the one anonymous POST in the feature that a drive-by could
# fire: 26 cross-origin form posts, no cookie and no token, and 26 manage-link
# mails sent from this deployment to an address the attacker chose — mail this app
# can send, from the operator's own sender and domain, on demand, for free. That is
# not a way to *take* a capability (the mail goes to the address that already owns
# one, so the attacker learns nothing they could not read), but it is a way to make
# somebody else's deployment send mail they never asked for, which is a reputation
# problem for the operator and a spam problem for everyone else.
#
# A separate uid from the creation form's, so one page's token cannot be replayed
# at the other. It proves the same thing — a page this app rendered — and it does
# not pretend to be more: the uid is a constant, so a direct attacker scrapes it
# off `/manage` in one request, exactly as they scrape the creation token off
# `/new`. What it removes is the drive-by primitive, which is what CSRF is for.
#
# **What it does NOT remove, and why this route still needed an owner (#31).** A
# direct attacker scrapes that token in one request, so CSRF is a one-request
# speed bump against a nuisance-mail cannon: with `KAIROS_RATE_LIMIT` off, posting
# a victim's address here makes this deployment mail them manage links from the
# operator's own domain, repeatedly, for free. Cloudflare Turnstile is what closes
# it — see `request_link` and `KAIROS_TURNSTILE`.
LINK_FORM_UID = "anon:manage-link"

# `sched_polls.creator_id` is NOT NULL and an accountless poll has no creator to
# put there. See `anonymous_creator_id` for why that is a sentinel and not a
# migration.
ANON_CREATOR_PREFIX = "anon:"

# How many links one re-link request may send. Not an anti-spam measure — the
# rate limit is — just a ceiling on how many SMTP messages one form post can
# open, so a deployment with a thousand polls on one address does not turn one
# click into a thousand messages. Pinned by a test: it is the only bound on the
# fan-out, and a bound nobody asserts is a number that gets widened by accident.
MAX_LINKS_PER_REQUEST = 10

# The floor on how long `POST /manage/link` takes to answer, in seconds.
#
# The response body is identical whether or not anything matched — verified, and
# pinned by a test, modulo the per-render CSRF binding, which is a function of the
# clock rather than of the address. The *time* was not identical: a match opens one
# SMTP connection per poll and a miss opens none, which measured 87x (0.254s hit vs
# 0.003s miss) against a real relay. That is the same oracle in a channel nobody
# looks at, and it is not a harmless one: it confirms which addresses have created a
# poll here, and the Subject line of the mail a real hit triggers ("Your manage link:
# Quarterly planning") then leaks the poll titles, so one timing bit buys a list.
#
# A floor is the honest fix here and not a complete one: it equalises the two cases
# only while the relay answers inside it. A relay slower than the floor still shows
# through, and the real answer — queueing the mail and answering before SMTP — is a
# delivery change, not a route change, so it is not this issue's to make. Stated
# rather than implied, because a doc that says "not an address oracle" when it
# means "not in the body" is what let this through in the first place.
#
# The price, stated because it is real: a *miss* used to answer in 3ms and now
# occupies a worker for 0.3s, so this converts a cheap refusal into a held thread.
# It is the right direction of trade (a rate-limit-free capability deployment is
# already documented at boot as an open mail relay, and a matching address was
# already paying SMTP latency), it is bounded by `LINK_REQUEST_FLOOR_SECONDS` rather
# than by the attacker, and `KAIROS_RATE_LIMIT=on` — which boot already insists on
# for this mode — puts a ceiling on it.
LINK_REQUEST_FLOOR_SECONDS = 0.3

# Slots one anonymous accountless creation may insert. Sized above any real
# meeting (a full week of 15-minute slots over a 12-hour day is ~576) and below
# anything a single POST should be able to write.
#
# Enforced **twice**, and both times matter. `web._expand_time_slots` asks
# `slot_cap_refusal` for the verdict *before* building the grid, from the
# multiplication of dates and per-date iterations, because that is the only
# placement that bounds the work: the same request with 992 dates and a one-minute
# increment is 1.4 million slot dicts, and on the pre-fix tree sixteen concurrent
# copies of it measured **+2.2 GB** — truncated only by the 2.5 GB address-space cap
# on that test server, ~6 GB uncapped — while every request cheerfully returned 400
# afterwards, the refusal arriving after the memory had already been spent and
# `/health` still answering 200 throughout. The same burst after the fix: **+4 MB**.
# The check in `create_accountless_poll`, after the list exists, is the second line of
# defence and the one that states the number to a creator; it can no longer be the
# thing that bounds anything, and its comment says so.
#
# One function, one number, one sentence: the two call sites must not be able to
# disagree about what "too large" means, because they are the same policy asked
# twice about the same poll — once as a prediction and once as a fact.
MAX_SLOTS_PER_ACCOUNTLESS_POLL = 1000


def slot_cap_refusal(n_slots: int, n_dates: int = 0) -> str | None:
    """The refusal sentence for an accountless poll over the slot cap, or None.

    `n_slots` is a slot *count* in both call sites, which is what makes them
    comparable: before the loop it is `dates × per-date iterations`, after it,
    `len(slots)`. The two must agree, and a test asserts they do on the boundary.

    `n_dates` only sharpens the sentence — "992 dates over that window" tells a
    creator what to change, "too large" does not.

    Not consulted outside this mode, which is the documented posture rather than an
    oversight: the owner's own form has never been capped (`create_accountless_poll`
    says why), an owner-mode request is authenticated, and a cap for every
    deployment is a policy change this issue is not making. The anonymous surface is
    what #30 created, and it is what this bounds.
    """
    if not enabled() or n_slots <= MAX_SLOTS_PER_ACCOUNTLESS_POLL:
        return None
    shape = f" {n_dates:,} dates over that window would create" if n_dates else " That would create"
    return (
        f"That poll is too large.{shape} {n_slots:,} slots, and this deployment creates "
        f"accountless polls with up to {MAX_SLOTS_PER_ACCOUNTLESS_POLL:,}. Use fewer dates "
        f"or a longer increment, split it into two polls, or ask the operator to raise the "
        f"limit."
    )


def enabled() -> bool:
    return settings.AUTH_MODE == "capability"


def _require_enabled() -> None:
    if not enabled():
        raise HTTPException(404)


def parse_session_hours(raw: str, warn=BOOT_WARNINGS.append) -> int:
    """`KAIROS_CAPABILITY_SESSION_HOURS` as a positive number of hours.

    Normalised, never raised, for the reason `settings._parse_networks` gets to
    raise and this does not: this variable is *unused* in every other mode, so a
    refusal here would be an import error that breaks the self-hoster and the ETH
    deployment that export nothing at all (ADR-0001/0002) in order to catch a
    typo in a mode they never enabled. So it warns, naming the knob, and falls
    back to the documented default — which is the safe direction, since the thing
    a silently-ignored value would cost is an unbounded cookie.
    """
    raw = raw.strip()
    if not raw:
        return DEFAULT_SESSION_HOURS
    try:
        hours = int(raw)
    except ValueError:
        hours = 0
    if hours <= 0:
        warn(
            f"KAIROS_CAPABILITY_SESSION_HOURS: {raw!r} is not a positive number of hours, "
            f"so the capability session lasts the default {DEFAULT_SESSION_HOURS}h"
        )
        return DEFAULT_SESSION_HOURS
    return hours


SESSION_HOURS_RAW = os.environ.get("KAIROS_CAPABILITY_SESSION_HOURS", "").strip()
# Parsed under the mode gate, not before it: parsing first would let one pasted
# value take down a deployment that never asked for this mode (the exact
# regression oidc.py's allowlist gate exists to prevent, and the reason its test
# re-imports the module rather than patching the parsed values).
SESSION_HOURS = parse_session_hours(SESSION_HOURS_RAW) if enabled() else DEFAULT_SESSION_HOURS
SESSION_MAX_AGE = SESSION_HOURS * 3600

# SESSION_SECRET is the one variable in this file that refuses to boot, and the
# difference from `KAIROS_CAPABILITY_SESSION_HOURS` above is the difference between
# a default and a requirement. The lifetime is a policy the operator can have an
# opinion about and a bad value for still fails safe (an unbounded cookie, as
# `parse_session_hours` says). The secret is not optional at all: it signs the
# capability cookie, which is the only credential the whole console has, and
# `settings.session_secret()` raises at first use — so the deployment booted green,
# `GET /manage` answered 200 from the "no session" branch, and the two routes that
# actually mint or verify a cookie 500'd. That is the worst shape a hard requirement
# can take: a healthy boot log and a broken mode.
#
# Gated on the mode for exactly the reason the parse above is, so it costs every
# other deployment nothing: a stray KAIROS_AUTH is not a reason to break a self-hoster
# who never asked for this mode, and #53 already establishes the pattern (an OIDC
# deployment with no owner allowlist refuses to boot). Test re-imports the module
# rather than patching a parsed constant, for the same reason oidc's does.
if enabled() and not os.environ.get("SESSION_SECRET", ""):
    raise RuntimeError(
        "KAIROS_AUTH=capability requires SESSION_SECRET: the capability cookie is the "
        "credential for the entire management console and is signed with it. Set it to a "
        "random value (openssl rand -hex 32). Refusing to boot is deliberate — the mode "
        "cannot work without it, and a green boot followed by a 500 on /new is not a "
        "better answer."
    )


# -- The placeholder creator ------------------------------------------------


def anonymous_creator_id() -> str:
    """A per-poll, unguessable placeholder for `creator_id` on an accountless poll.

    **Why a sentinel and not a migration.** `creator_id` is `NOT NULL`; an
    accountless poll has no creator to put there, so #29's author left the
    decision here. The options were relaxing the constraint or documenting a
    placeholder.

    Relaxing it means `creator_id VARCHAR(36) NULL`, and on SQLite — the default
    dialect, and the one every self-hoster is on — a column's nullability cannot
    be altered at all. The only route is the twelve-step table rebuild (new table,
    copy, drop, rename) run inside `init_schema()`, which executes on *every*
    boot against the operator's live poll table with five child tables pointing at
    it. `get_connection()` sets `PRAGMA foreign_keys = ON` per connection, and
    dropping a parent table under that pragma cascades to every response, slot,
    invite, contact-log and notification row in the database. A data migration
    that can delete the poll is not a price worth paying for a field whose only
    remaining job is "was there an account?". On MySQL the statement is one line,
    but on 5.7 it is a blocking table copy. `init_schema`'s entire history is
    `_ensure_column` + `_ensure_index` — additive, idempotent, no data movement —
    and a schema-rebuild migration is how that property is lost.

    So: a placeholder, with three properties, each closing a specific way a
    sentinel could leak.

    1. **Unguessable, per poll.** 14 bytes from the OS CSPRNG. A *constant*
       sentinel ("anon", "accountless") is a fail-open in #29's identity
       comparison the moment anyone can present it as a uid — a header-mode
       deployment that later flips back, or a `get_user` seam that returns it.
       At 112 bits nobody can present it, and this module never prints or logs
       one. It *does* appear as `creator_id` in a REST response, exactly as any
       other creator string does, and that is not a leak: it is not the
       credential (`admin_token` is, and `api._without_secrets` strips it), it is
       derived from nothing an attacker can see, and it grants nothing —
       `can_manage` needs the value itself, not knowledge of it.
    2. **Unique per poll.** `db.list_polls(creator_id)` is the dashboard's only
       query, so a *shared* sentinel would make `list_polls` return every
       accountless poll in the deployment the moment anything ever passed it.
       Unique-per-poll makes the worst case one row: the same poll.
    3. **Unmistakably not an identity.** The `anon:` prefix reads as "no creator"
       in a database dump and can never collide with a header uid, an OIDC
       subject or a future account id, all of which are opaque strings chosen
       somewhere else.

    `owner_id` is NULL on these polls, which is where #29 already said the
    accountless marker lives. The placeholder is not a credential and nothing
    authorizes on it.
    """
    return f"{ANON_CREATOR_PREFIX}{secrets.token_hex(14)}"  # 33 chars, fits VARCHAR(36)


def creator_actor(poll: dict) -> dict:
    """The `user`-shaped dict the shared send helpers expect.

    They take `user` for a display name and a Reply-To and nothing else (`web.
    nudge_participants`, `email_service.send_decision_email`). There is no account
    here, so the name is the same generic fallback the owner UI uses when a proxy
    supplies no display name, and the reply address is the creator's own — the
    one thing an accountless poll still knows about its owner, and the reason a
    participant can reply.
    """
    return {"name": "The organizer", "email": poll.get("creator_email"), "source": "capability"}


# -- The send-gate (obligation A2) ------------------------------------------

# What a refusal says, to whoever is refused. One sentence pair, not one per
# surface: a gate whose message is written twice is a gate whose two messages drift,
# and the API caller is the audience that matters most here because they are the one
# who can act on it.
#
# It names the fix rather than the rule. An agent holding a `mail:send` key is being
# told the *poll* is not allowed to mail yet, not that its scope is wrong, and the
# thing it can do about that is ask a human to open a link — so that is what it says.
# No address and no poll title: this refusal lands in a log nobody here controls.
SEND_GATE_DETAIL = (
    "This poll may not send mail yet: nobody has opened the manage link for the "
    "address that created it, so Kairos will not mail anyone else on its behalf. "
    "Ask that creator to open the link Kairos mailed them — or to request a new one "
    f"at {P}/manage — and try again. This is what stops a deployment being used to "
    "send mail to a stranger."
)


def send_allowed(poll: dict) -> tuple[bool, str]:
    """May this deployment send mail to anyone but `poll`'s own creator?

    `(True, "")` or `(False, <reason>)`. The reason is for the log line; callers
    show `SEND_GATE_DETAIL`, which is written for the person who has to fix it.

    **The rule is one column, read strictly.** `manage_verified_at` is stamped by
    `mark_manage_verified` on the first successful exchange of the manage link, and
    it is never cleared. It is NULL on:

      * **every poll that predates #30**, and
      * **every poll created through the REST API**, which is the live hole: an
        agent can create a poll, name any recipients and ask for the mail, with no
        browser and no inbox anywhere in the loop.

    NULL therefore means *not verified*, and a poll that cannot be verified cannot
    send. That is the whole gate, and it ships closed by construction: the column
    was added by #29 with no backfill, so there is no window in which a
    pre-existing row reads as verified.

    **Absent is NULL.** The row is read with `.get()`, so a poll dict that predates
    the column — or a stub in a test — is refused, never allowed. A gate whose
    missing input reads as "allowed" is the exact defect #29's `can_manage`
    docstring warns about for the sibling predicate, and it is why this one is
    `.get(...) is not None` rather than a truthiness check that a future rename
    could invert.

    **Only in this mode.** Outside `KAIROS_AUTH=capability` the answer is always
    yes, and that is the compatibility argument rather than a gap: the creator
    there is identified by the proxy or the IdP (ADR-0002/0013), so there is no
    address to verify and the column is dead — while the ETH and self-host
    deployments must keep behaving byte-for-byte (ADR-0001/0002). Gating them on a
    column nothing can ever set would have been a silent, total outage of their
    mail.

    **`POST /manage/link` and the creation mail are not gated**, deliberately: they
    mail the *creator's own* address, they are how a creator becomes verified in
    the first place, and gating them would make the gate unreachable. A2 is about
    mail to *third parties*, so a gate that blocked the verification mail would
    close the hole by removing the feature.
    """
    if not enabled():
        return True, ""
    if poll.get("manage_verified_at") is not None:
        return True, ""
    return False, "manage_verified_at is NULL"


def require_sendable(poll: dict) -> dict:
    """`poll` if it may send mail to a third party, else 403.

    The one predicate every outbound path consults, the way `auth.require_manage`
    is the one predicate every mutating route consults (obligation S6). It returns
    the poll so a call site reads `poll = require_sendable(poll)`.

    **403, and it is the same shape on every surface**, because it is one function
    rather than a per-surface rendering. On the API it is the useful answer: a key
    holding `mail:send` is being told the *poll* is not yet allowed to mail, not
    that its scope is wrong, and `SEND_GATE_DETAIL` names the fix. On the web owner
    console it would be a bare JSON detail — that path is unreachable in this mode
    (`get_user` returns None, so the route answers 401 first), and it is called
    there anyway as defence in depth: a console session *cannot* exist unverified,
    because the only way to hold one is the exchange that stamps the column.

    **The check runs before the work, not after it.** Every call site is ahead of
    the slot expansion, the row write or the SMTP connection, and a test asserts the
    position rather than the outcome: a gate that ran after `charge_poll_recipients`
    would spend the poll's whole mail allowance on a request it is about to refuse.
    """
    allowed, reason = send_allowed(poll)
    if not allowed:
        # Poll id, never an address: the refusal is about a poll the caller
        # cannot see, and creator addresses do not go in this deployment's logs.
        log.warning("send refused for poll %s: %s", poll.get("id"), reason)
        raise HTTPException(403, SEND_GATE_DETAIL)
    return poll


def session_verifies_creator(request: Request) -> bool:
    """Does this request hold a live capability for a poll whose creator is verified?

    Read from the capability cookie rather than from the form, because possession
    of the link is the whole credential model (#30) and there is nothing else to
    ask. `can_manage` is consulted, not just a cookie parse, so a retired or
    rotated capability does not buy an exemption — the same predicate
    `console_route` uses, for the same reason.

    True only for a poll that is *itself* verified: the answer to "may this person
    make this deployment send mail to somebody?" is a property of the poll, not of
    the browser. A creator who has lost their link and re-opened it in a new
    browser therefore has to solve the check again, which is the point.
    """
    session = read_session(request)
    if not session:
        return False
    poll = get_poll(session["pid"])
    if not poll or not can_manage(poll, request, token=session["at"]):
        return False
    return send_allowed(poll)[0]


# -- The capability cookie --------------------------------------------------


def _cookie_kwargs(request: Request) -> dict:
    # `_is_https` is oidc's, reused rather than restated: it resolves
    # KAIROS_PUBLIC_URL → X-Forwarded-Proto → the ASGI scheme in that order, with
    # the reasoning written down once. Same judgement, same order.
    return {"path": SESSION_PATH, "httponly": True, "samesite": "lax", "secure": _is_https(request)}


def mint_session(response, request: Request, poll: dict, token: str) -> None:
    """Put the (rotated) capability in a signed, time-limited cookie."""
    response.set_cookie(
        SESSION_COOKIE,
        _serializer(salt="cap-session").dumps({"pid": poll["id"], "at": token}),
        max_age=SESSION_MAX_AGE,
        **_cookie_kwargs(request),
    )


def read_session(request: Request) -> dict | None:
    """`{"pid", "at"}` from a valid, unexpired capability cookie, or None.

    Anything unparseable is None rather than an exception: a tampered cookie is a
    wrong credential, and #29's predicate is what says so. The signature is
    verified with the deployment's SESSION_SECRET, so the cookie cannot be
    forged; the payload's own `at` is then re-checked against the row by
    `require_manage`, which is the check that matters after a rotation.
    """
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return None
    try:
        data = _serializer(salt="cap-session").loads(raw, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired, ValueError, TypeError):
        return None
    if not isinstance(data, dict) or not data.get("pid") or not data.get("at"):
        return None
    return data


def manage_path(token: str) -> str:
    return f"{P}/manage/{token}"


def manage_url(request: Request, token: str) -> str:
    return f"{get_base_url(request)}{manage_path(token)}"


def _hold_for(floor_seconds: float, started: float) -> None:
    """Spend the rest of `floor_seconds` since `started`, doing nothing.

    A constant-time response on the one route whose work is *supposed* to depend
    on data the caller does not own. Sleep, not fake work: a decoy SMTP round trip
    would send mail to make a timing claim true, and a CPU spin would burn a core to
    avoid holding a thread — the wrong trade for a route whose whole problem is
    exhaustion. `time.monotonic`, because the wall clock can go backwards and the
    wrong answer would be a negative sleep.

    Only ever a floor, so the honest limit is stated where the constant is: a
    caller that takes *longer* than the floor still shows through, and this does not
    pretend otherwise.
    """
    remaining = floor_seconds - (time.monotonic() - started)
    if remaining > 0:
        time.sleep(remaining)


# -- Pages ------------------------------------------------------------------


def _mail_note() -> str:
    """Why outbound mail is unusable here, in the operator's terms.

     `sender_refusal()` rather than a generic "mail is off", because the two
     problems have different fixes (#48's M1 identity gate versus a missing SMTP
    _HOST) and an operator sent to the wrong knob wastes an afternoon.
    """
    if is_configured():
        return ""
    refusal = sender_refusal()
    return refusal.message if refusal else "Outbound mail is not configured on this deployment."


def _link_page(request: Request, heading: str, detail: str, status_code: int = 200, msg=None):
    """The 'you have no usable capability' page, with the way back on it.

    One template for every state that is not the console, because they differ
    only in the sentence at the top — and because the link-request form has to be
    reachable from all of them, or a creator who spent their link has no way to
    spend it twice.
    """
    return render(
        env,
        "manage.html",
        title=heading,
        user=None,
        stage="signed_out",
        heading=heading,
        detail=detail,
        status_code=status_code,
        noindex=True,
        error=status_code >= 400,
        mail_ok=is_configured(),
        mail_note=_mail_note(),
        # Its own binding, not the console's: there is no session on this page, and
        # the link-request form below is the one POST here (see LINK_FORM_UID).
        link_csrf=make_csrf(LINK_FORM_UID),
        # #31: the human check that form posts. `{}` when the gate is off, which is
        # every mode but this one and every deployment that has not asked for it.
        turnstile=widget_ctx(ACTION_MANAGE_LINK),
        msg=msg,
    )


def anon_error(heading: str, detail: str, back: str | None = None, status_code: int = 400):
    """A form refusal with no user behind it.

    `web._error_page` builds the notification navbar from an owner uid, so it
    cannot render an accountless submission's errors; this goes through the same
    template without one. Same status codes, same look, no invented identity.
    """
    return render(env, "message.html", status_code=status_code, title=heading, heading=heading,
                  detail=detail, error=True, user=None, noindex=True,
                  back=back, back_label="Back")


def signed_out(request: Request, msg: str | None = None):
    # `msg` matters here: `delete` redirects back to a poll that no longer exists,
    # so the flash can only be shown on this page.
    return _link_page(
        request,
        "Open your manage link",
        "Manage links are emailed when you create a poll and work once. "
        "Open the one we sent you, or ask for a new one below.",
        msg=msg,
    )


def console(poll: dict, request: Request, *, msg: str | None = None):
    """The capability console: one poll, its share link, and its actions."""
    from kairos.web import decided_slot_of  # lazy; see manage_action's note

    responses = get_responses(poll["id"])
    invites = get_invites(poll["id"])
    total, pending_n = expected_counts(invites, responses)
    decided = decided_slot_of(poll)
    return render(
        env,
        "manage.html",
        title=poll["title"],
        user={"name": poll.get("creator_email") or "Poll organizer", "email": poll.get("creator_email")},
        poll=poll,
        slots=poll["slots"],
        invites=invites,
        responses=responses,
        total=total,
        pending_n=pending_n,
        conv=convergence(poll, responses, invites),
        decided_label=format_slot(decided, poll["mode"]) if decided else None,
        share_url=f"{get_base_url(request)}{P}/p/{poll['public_token']}",
        timezones=TIMEZONES,
        csrf_token=make_csrf(poll["id"]),
        # The footer link-request form posts to a route that has no session, so it
        # carries its own binding rather than this page's poll-id one.
        link_csrf=make_csrf(LINK_FORM_UID),
        # ...and it is behind `{% if mail_ok %}` like the other two stages, which
        # means a console rendered without these two showed no way back in at all —
        # just an empty red paragraph where the form should be, on the one page
        # where a creator who has already spent their link is most likely to look.
        mail_ok=is_configured(),
        mail_note=_mail_note(),
        # The same gate as the signed-out page's form, because it posts to the same
        # route -- but waived for a console holder, who has already opened a manage
        # link and so is exempt (`session_verifies_creator`). Rendered from the same
        # question the route asks, so the widget is never a click that decides
        # nothing: a control the server ignores would spend a third-party request
        # and teach the creator that the button is decoration.
        turnstile={} if send_allowed(poll)[0] else widget_ctx(ACTION_MANAGE_LINK),
        msg=msg,
        session_hours=SESSION_HOURS,
        noindex=True,
    )


_MSG_TEXT = {
    "saved": "Poll updated.",
    "closed": "Poll closed.",
    "reopened": "Poll reopened — it accepts responses again.",
    "decided": "Time decided!",
    "invited": "Invitee added — send them the reminder below.",
    "duplicate": "That address is already on the list.",
    "nudged": "Reminders sent.",
    "nonudge": "Nobody needed a reminder — everyone is up to date or was nudged recently.",
    "emailed": "The final date has been emailed.",
    "deleted": "Poll deleted.",
}


def _msg_text(query_params) -> str | None:
    """The console's flash text, falling back to the owner UI's table.

    `web._MSG_TEXT` rather than a second copy of two sentences that have to stay in
    step: `mailfail` and `mailblocked` exist to send an operator to *different*
    knobs (#48), and two copies of that distinction is one copy too many.
    """
    from kairos import web

    key = query_params.get("msg", "")
    return _MSG_TEXT.get(key) or web._MSG_TEXT.get(key)


# -- Routes -----------------------------------------------------------------
# Registered unconditionally and 404ing themselves in every other mode, so the
# route table has the same shape in every mode (oidc.py's reasoning: the route
# audit in tests/test_ratelimit.py reads that table, and a mode-dependent table
# would make it assert against the environment).


@router.get("/manage", include_in_schema=False)
def console_route(request: Request):
    """The console.

    `can_manage`, not `require_manage`: an absent, forged or retired capability
    gets a page that says how to get a new link, not a bare 403.
    """
    _require_enabled()
    flash = _msg_text(request.query_params)
    session = read_session(request)
    if not session:
        return signed_out(request, msg=flash)
    poll = get_poll(session["pid"])
    # `user` is deliberately not passed: this is the anonymous capability shape
    # #29 documented, and the cookie's `at` is the credential. An absent uid
    # fails closed.
    if not poll or not can_manage(poll, request, token=session["at"]):
        return signed_out(request, msg=flash)
    return console(poll, request, msg=_msg_text(request.query_params))


def _dead_link(request: Request):
    """One answer for "no such link", "not yours" and "already spent"."""
    return _link_page(
        request,
        "This link is not valid",
        "Manage links work once. If you already opened this one, ask for a new link below.",
        404,
    )


# DECLARATION ORDER IS LOAD-BEARING HERE: `/manage/link` has to be registered
# before `/manage/{token}`, or Starlette matches the literal path as a token and
# every re-link request 404s as "not a valid link". A test pins it.
@router.post("/manage/link", include_in_schema=False, dependencies=[Depends(rate_limit("send"))])
def request_link(request: Request, form=Depends(form_data)):
    """Mail a fresh manage link for an address that already created a poll here.

    The recovery path a single-use link makes necessary (a cleared inbox, a
    second device, an eaten prefetch). It is not an account system and grants
    nothing by itself: it mails a capability to the address that already owns it,
    which is the same trust the magic link itself rests on.

    The answer is identical whether or not anything matched, so it cannot be used
    to learn which addresses have polls here — and it never says how many it sent.
    Identical in the *body*, that is; the response time is held to a floor too, so
    the SMTP fan-out is not an oracle in a second channel (see
    `LINK_REQUEST_FLOOR_SECONDS` for what the floor does and does not fix).

    The budget is `send`, the one every SMTP-opening route already draws on, and
    the fan-out is charged *in links* rather than in requests: one post can open up
    to `MAX_LINKS_PER_REQUEST` SMTP connections, so charging it a single unit would
    make the operator's `send` limit ten times weaker on exactly this route. The
    route-level dependency charges the request; `charge_link_fanout` charges what
    the request goes on to send.

    **The human check is here too (#31), which is where #68 said the abuse owner
    was missing.** With shipped defaults a third party could post a victim's
    address — the CSRF token in `LINK_FORM_UID` is on every `/manage` page and
    scrapable in one request, and `KAIROS_RATE_LIMIT` defaults off — and have this
    deployment mail that victim up to `MAX_LINKS_PER_REQUEST` manage links per post,
    from the operator's own sender and domain, forever. It cannot *take* a poll
    (the link goes to the address that owns it) and it learns nothing (the answer
    is identical either way), so what it buys an attacker is a nuisance: our
    reputation, the victim's inbox, and a spam-complaint rate, which A3's own note
    calls the thing that actually destroys a domain.

    Turnstile is the answer for the same reason it is the answer on `/new`: the
    per-IP budget was measured at a 1.11x effect elsewhere in this repo, and
    evasion by address rotation is not the problem here anyway — the axis that
    matters is one attacker aiming many requests at *one* victim, which an
    address-keyed budget stops at the cost of silently mailing nothing to a real
    creator who asks twice (and saying so nowhere, because the body may not
    differ). A per-address cooldown was considered and rejected for exactly that
    reason.

    The price, stated because it is real: the recovery path now depends on a third
    party being reachable. That is the same trade the creation path makes, it is
    bounded by one `KAIROS_TURNSTILE=off`, and the alternative — leaving the only
    ungated mail-triggering POST in the feature unwatched — is the thing #68 asked
    #31 to fix.

    **Verified creators skip the check** (`session_verifies_creator`). They are
    already proof-of-human for this deployment, and asking again is friction with
    no security gain. Note what that does *not* allow: the exemption is read off a
    live capability, and one cannot be obtained without having received a manage
    mail — so an attacker's first request still faces the check. What it does
    allow is a *verified* creator posting a victim's address, which is one nuisance
    mail per `send`-budget window, bounded and rate-limited, and is the price of
    not making a creator re-prove themselves to recover a link they legitimately
    lost.
    """
    _require_enabled()
    if not is_configured():
        return _link_page(request, "Email is not available", _mail_note(), 503)
    # Same shape as the creation form's check and for the same reason: this posts
    # mail from the operator's domain, and a form on a public page is exactly what
    # another site can submit on a visitor's behalf. See LINK_FORM_UID.
    require_anon_csrf(form, LINK_FORM_UID)
    # ...and then the human check, which is a *replacement* for the per-request
    # budget here rather than a companion to it. Order matters: CSRF first because
    # it is local and a drive-by should not cost an outbound request, then the
    # check, then the SMTP fan-out. Nothing is written and no connection is opened
    # before the check answers.
    if not session_verifies_creator(request):
        verdict = verify_human(request, form, action=ACTION_MANAGE_LINK)
        if not verdict.ok:
            return _link_page(request, verdict.heading, verdict.detail, verdict.status_code)
    started = time.monotonic()
    email = valid_email(form.get("email", ""))
    if email:
        # Filter, then cap — never cap, then filter. `list_polls_by_creator_email`
        # is newest-first and every poll minted after #29 has a token, so slicing
        # first meant a creator with ten recent polls and one older poll (a pre-#29
        # row with no capability, or an API-created one) got *no link at all* from
        # the one route that exists to get them back in. `islice` over a generator
        # says the order out loud and stops the walk once the cap is reached.
        matching = list(
            islice((p for p in list_polls_by_creator_email(email) if p.get("admin_token")),
                   MAX_LINKS_PER_REQUEST)
        )
        _charge_fanout(request, len(matching))
        for poll in matching:
            send_manage_email(email, poll["title"], manage_url(request, poll["admin_token"]))
    _hold_for(LINK_REQUEST_FLOOR_SECONDS, started)
    return _link_page(
        request,
        "Check your inbox",
        "If that address created a poll on this deployment, a fresh manage "
        "link is on its way. It works once.",
    )


@router.get("/manage/{token}", include_in_schema=False, dependencies=[Depends(rate_limit("read"))])
def manage_link(token: str, request: Request):
    """The emailed link. Renders the confirmation; does NOT consume the token.

    A GET that consumed the capability would be defeated by link prefetching
    (Outlook Safe Links, Proofpoint, and every corporate URL scanner follow links
    in inbound mail), which spends the creator's only credential before they click
    anything. `manage_exchange` below is the exchange.
    """
    _require_enabled()
    poll = get_poll_by_admin_token(token)
    if not poll or not can_manage(poll, request, token=token):
        return _dead_link(request)
    return render(
        env,
        "manage.html",
        title=poll["title"],
        user=None,
        stage="open",
        noindex=True,
        poll=poll,
        manage_path=manage_path(token),
        session_hours=SESSION_HOURS,
        mail_ok=is_configured(),
        mail_note=_mail_note(),
        # This is the one page whose URL carries a credential, so the same-origin
        # assets it loads must not put that URL in their Referer. Cheap, and it is
        # the only place a capability is ever in a rendered document.
        headers={"Referrer-Policy": "no-referrer"},
    )


@router.post("/manage/{token}", include_in_schema=False, dependencies=[Depends(rate_limit("read"))])
def manage_exchange(token: str, request: Request):
    """The exchange: authorize with the token, verify, rotate, mint the cookie."""
    _require_enabled()
    poll = get_poll_by_admin_token(token)
    if not poll:
        return _dead_link(request)
    # #29's predicate is this route's authorization, exactly as documented: a
    # token, no identity. Not a redundant re-check of the lookup — it is where a
    # token that stopped matching between the two statements is caught, and it is
    # the single line a reader looks for to see *how* this route authorizes.
    require_manage(poll, request, token=token)

    # A race for one link resolves here, and only the winner proceeds: the swap
    # below is a compare-and-swap on the token presented, so two exchanges produce
    # one winner and one refusal rather than two winners whose first cookie is dead
    # on arrival.
    rotated = rotate_admin_token(poll["id"], token)
    if not rotated:
        # Another exchange of the same link won between our lookup and this
        # statement, or the row carries no capability at all. Refuse rather than
        # mint a session around a capability that has already been replaced.
        log.warning("could not rotate the management capability for poll %s", poll["id"])
        return _dead_link(request)

    # Obligation A2's precondition, written for the first time here (#29 handed
    # the write to this issue, and the column is otherwise dead): the creator's
    # address is demonstrably deliverable *and* demonstrably theirs, because they
    # opened what we sent it. #31 reads this column to gate sending; nothing here
    # gates on it.
    #
    # After the swap, not before. The loser of a race reaches neither line now, and
    # that is the point: this column is what #31 will gate sends on, so a request
    # that did not win the capability must not be able to stamp it. Stamping first
    # meant the loser of a rotation — a link prefetcher replaying a token a moment
    # after the creator used it — set the very flag that says "this address is
    # verified".
    if mark_manage_verified(poll["id"]):
        log.info("manage link opened for poll %s (first open: email verified)", poll["id"])

    # The cookie carries the NEW capability, so this exchange is the only way in
    # and the link is spent. The log line names the poll, never the token.
    response = RedirectResponse(f"{P}/manage", status_code=302)
    mint_session(response, request, poll, rotated)
    return response


def charge(request: Request, rule: str, cost: int = 1) -> None:
    """Charge a named budget from inside a handler. 429 when spent.

    The route-level `rate_limit(...)` dependency is the right tool when a whole
    route costs one request against one rule. Neither is true for either of the
    two places this is used, and both are the reason it exists rather than a
    call to the dependency:

      * `POST /manage/link` costs `send` *per recipient it mails* — one post can
        open up to `MAX_LINKS_PER_REQUEST` SMTP connections, so charging it a
        single unit would make the operator's `send` limit that many times weaker
        on exactly this route;
      * `POST /manage/{id}/{action}` is one route carrying several rules —
        `invite` grows the participants table, `send` opens SMTP, `read` and
        `edit` cost nothing — and a dependency cannot see the action in the path.

    `ratelimit.check` already takes a cost for exactly this reason (#51's per-poll
    budget counts recipients, not requests); what was missing is a way to charge
    *more than one unit*, or a rule that depends on the request, and copying that
    ten-line block a second time would be the wrong answer to "the numbers must be
    in step". Fail-open on an internal fault, with the same reasoning as every
    other call site: a bug in a counter must not read as a broken console, and
    nothing else on these paths depends on it.

    Unattributable callers (no peer in scope -- a unix-socket listener) are charged
    to nobody, exactly as `ratelimit.caller_key` decides, rather than being folded
    into one shared bucket that would lock out the operator's own deployment.
    """
    if not settings.RATE_LIMIT_ENABLED or cost <= 0:
        return
    key = caller_key(request)
    if key is None:
        return
    limit, window = settings.RATE_LIMITS.get(rule, (0, 0))
    if limit <= 0:
        return
    try:
        allowed, retry_after = limiter.check(rule, limit, window, key, cost=cost)
    except Exception:
        log.exception("rate limiter failed; allowing the request")
        return
    if not allowed:
        log.warning("rate limit %s exceeded by peer %s", rule, key)
        raise RateLimited(rule, retry_after)


def _charge_fanout(request: Request, count: int) -> None:
    """`count` recipients against `send`. See `charge`."""
    charge(request, "send", cost=count)


# Every mutating console action on one route, for the reason #29 put the predicate
# behind one name: authorization is decided once, in one place, and a new action
# cannot ship without passing through it. The action name is a fixed vocabulary,
# so an unknown one is a 404 rather than a fallthrough.
_ACTIONS = ("close", "reopen", "decide", "invite", "remind", "email-decision", "edit", "delete")


@router.post("/manage/{poll_id}/{action}", include_in_schema=False)
def manage_action(poll_id: str, action: str, request: Request, form=Depends(form_data)):
    _require_enabled()
    # Vocabulary first, then the same order as `web._owner_action` — capability
    # (401), CSRF (403), authority (403). Checking the name first is not a leak: the
    # names are in this file, which is public, and it means a garbage action costs
    # no database round trip and no session lookup at all.
    if action not in _ACTIONS:
        raise HTTPException(404, "Not found")
    session = read_session(request)
    if not session:
        raise HTTPException(401, "No management session — open your manage link")
    require_csrf({"uid": session["pid"]}, form)
    poll = get_poll(session["pid"])
    if not poll or poll["id"] != poll_id:
        # The session names exactly one poll. A path pointing at another is not a
        # "not the owner" case, it is a request for a poll this capability does
        # not speak for — and the answer is the same either way.
        raise HTTPException(404, "Not found")
    require_manage(poll, request, token=session["at"])

    # Lazy, and the one import cycle in this file: `web` imports `capability` at
    # module scope (for the accountless creation branch), so this module cannot
    # import it back at module scope. Resolved at call time, by which point both
    # are loaded. The helpers below are deliberately web's and not copies: the
    # reminder engine's per-participant cooldown and its per-poll budget must hold
    # across surfaces, which is only true if there is one of each.
    from kairos import web

    handler = {
        "close": _close,
        "reopen": _reopen,
        "decide": _decide,
        "invite": _invite,
        "remind": _remind,
        "email-decision": _email_decision,
        "edit": _edit,
        "delete": _delete,
    }[action]
    return handler(request, form, poll, web)


def _back(msg: str, **params):
    """Back to the console with a flash. Never carries a token."""
    query = f"msg={msg}"
    for key, value in params.items():
        if value:
            query += f"&{key}={value}"
    return RedirectResponse(f"{P}/manage?{query}", status_code=302)


def _close(request, form, poll, web):
    update_poll(poll["id"], status="closed")
    return _back("closed")


def _reopen(request, form, poll, web):
    update_poll(poll["id"], status="open", decided_slot_id=None)
    return _back("reopened")


def _decide(request, form, poll, web):
    slot_id = form.get("slot_id")
    if not slot_id:
        raise HTTPException(400, "slot_id required")
    if slot_id not in {s["id"] for s in poll["slots"]}:
        # web.decide_poll's check, for web.decide_poll's reason: a slot id from
        # another poll must not be able to name this poll's decision.
        raise HTTPException(400, "slot_id does not belong to this poll")
    update_poll(poll["id"], status="decided", decided_slot_id=slot_id)
    return _back("decided")


def _invite(request, form, poll, web):
    # The same budget the owner UI's `invite_submit` draws on: this grows the
    # participants table and opens SMTP on the next reminder.
    charge(request, "invite")
    email = valid_email(form.get("email", ""))
    if not email:
        raise HTTPException(400, "Not a valid email address")
    if any(i["email"].lower() == email.lower() for i in get_invites(poll["id"])):
        return _back("duplicate")
    create_invite(
        poll["id"], email, required=not form.get("optional"), name=form.get("name", "").strip() or None
    )
    return _back("invited")


def _remind(request, form, poll, web):
    # `send`, for the same reason `web.remind_participants`' callers charge it:
    # this opens an SMTP connection per recipient. A capability cookie is a bearer
    # credential, which is exactly the shape `mail:force` exists to constrain on
    # the API -- the per-peer budget has to hold here too, not only the per-poll
    # one that `nudge_participants` charges internally.
    charge(request, "send")
    # A2, before the budget is spent: the shared `nudge_participants` charges the
    # poll's whole recipient allowance internally, and a request that is about to
    # be refused must not have drawn that down first. Unreachable in practice —
    # holding a console session means having opened the manage link, which is what
    # stamps the column — and called anyway, because "the one predicate every send
    # path consults" is only true if the consult is really there.
    require_sendable(poll)
    if poll["status"] != "open":
        raise HTTPException(400, "Poll is not open")
    counts = web.nudge_participants(request, poll, creator_actor(poll))
    if not (counts["invited"] or counts["updated"]):
        return _back("nonudge")
    return _back("nudged", inv=counts["invited"], upd=counts["updated"])


def _email_decision(request, form, poll, web):
    from kairos.ics import build_ics

    charge(request, "send")  # see `_remind`: SMTP per recipient
    require_sendable(poll)   # A2, before the per-poll allowance is spent
    slot = web.decided_slot_of(poll)
    if not slot:
        raise HTTPException(400, "Poll has no decided date yet")
    poll_url = f"{get_base_url(request)}{P}/p/{poll['public_token']}"
    actor = creator_actor(poll)
    recipients = web.recipient_emails(poll["id"])
    # The same per-poll send budget the owner UI and the API charge (#51): one
    # allowance for one poll, whichever surface asks for it (ADR-0012's parity).
    charge_poll_recipients(poll["id"], len(recipients))
    sent = send_decision_email(
        recipients,
        poll["title"],
        format_slot(slot, poll["mode"]),
        poll_url,
        build_ics(poll, slot, poll_url),
        actor["name"],
        note=form.get("note", "").strip(),
        reply_to=actor["email"],
    )
    for email in sent:
        log_contact(poll["id"], email, "decision")
    if not sent:
        # web's own "which knob" answer, reused: a sender identity the M1 gate
        # refused and a relay that was never configured are different problems, and
        # the person reading this is the poll's creator rather than the operator.
        return _back(web._mail_failure_msg())
    return _back("emailed", n=len(sent))


def _edit(request, form, poll, web):
    # Everything validated before anything written, so a refused edit leaves the
    # poll exactly as it was rather than half-applied.
    title = form.get("title", "").strip()
    if not title:
        raise HTTPException(400, "Title is required")
    timezone = form.get("timezone", "Europe/Zurich").strip()
    # web's own check, called rather than restated: the creation form and this one
    # must not disagree about which timezones exist.
    if not web._valid_timezone(timezone):
        raise HTTPException(400, "Unknown timezone")
    # web.edit_poll_submit's semantics: additive, so a response to an existing date
    # survives a later edit.
    #
    # `cap=` is this console's own ceiling on `new dates × the poll's time grid`, and
    # it is the same number and the same sentence as accountless *creation* — one
    # bound, asked twice, which is the discipline that caught the previous two
    # versions of this defect on the creation path. It is needed here because this
    # form is a single comma-separated field (so `max_fields` never sees the dates)
    # multiplied by a grid that grows with every edit. The owner form and the API pass
    # no cap and are unchanged.
    slots = web.expand_new_dates(
        poll, _parse_dates(form.getlist("dates")), cap=MAX_SLOTS_PER_ACCOUNTLESS_POLL
    )

    update_poll(
        poll["id"],
        title=title,
        description=form.get("description", "").strip() or None,
        timezone=timezone,
    )
    if slots:
        add_slots(poll["id"], slots)
    return _back("saved")


def _parse_dates(values) -> list[str]:
    """ISO dates from the console's comma-separated field, or a 400.

    The owner's edit form is a date picker that posts one `dates` field per date;
    this console's is a text box, so it splits — and it validates, because the
    value lands in a `DATE` column that `dbconn` reads back through a strict
    converter: an unparseable date is stored happily and then raises on the *next*
    read of the poll, which is a 500 on an ordinary page view rather than a 400 at
    the keystroke that caused it.

    **The split is also why this function needs its own ceiling.** Splitting on commas
    means `max_fields` counts *fields*, not dates, so one field is unbounded input: a
    ~1 MB `dates` value is 95,000 valid dates, parsed and held in a list before any
    cap downstream gets a say. Bounded here rather than downstream because a check
    that runs after the list exists cannot bound what building it cost — the same
    lesson as the creation path, applied to the one function that manufactures the
    input.

    The ceiling is the slot cap, not a second number: every date named here becomes at
    least one slot, so a request naming more dates than the deployment's slot ceiling
    could never be accepted anyway, and the refusal in `expand_new_dates` would catch
    it a step later. Stated as one ceiling on one request. The trade-off, stated
    rather than hidden: a creator who pastes more than the ceiling's worth of dates —
    including dates already on the poll, which `expand_new_dates` would deduplicate —
    is refused rather than trimmed. The field is empty by default and labelled "Add
    dates", so that is a paste, not the normal path.
    """
    from datetime import date

    parsed = []
    for value in values:
        for part in value.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                date.fromisoformat(part)
            except ValueError:
                raise HTTPException(400, f"{part!r} is not a date (expected YYYY-MM-DD)") from None
            parsed.append(part)
            if len(parsed) > MAX_SLOTS_PER_ACCOUNTLESS_POLL:
                # Refused *here*, so the 95,000th date is never appended and never
                # validated: the loop stops one past the ceiling, not one short of it
                # after the work.
                raise HTTPException(
                    400,
                    f"That edit names more than {MAX_SLOTS_PER_ACCOUNTLESS_POLL:,} dates, "
                    f"and this deployment adds at most {MAX_SLOTS_PER_ACCOUNTLESS_POLL:,} "
                    f"slots per request. Add them in batches.",
                )
    return parsed


def _delete(request, form, poll, web):
    delete_poll(poll["id"])
    return _back("deleted")


# -- Accountless creation (called from web.py) ------------------------------


def new_poll_context() -> dict:
    """Template context for `new_poll.html` in capability mode.

    No user and no dashboard; `csrf_token` is bound to `ANON_FORM_UID`, and
    `capability=True` is what makes the form ask for an email address and say
    where the manage link goes.
    """
    return {
        "user": None,
        "title": "New Poll",
        "timezones": TIMEZONES,
        "csrf_token": make_csrf(ANON_FORM_UID),
        "capability": True,
        "mail_ok": is_configured(),
        "mail_note": _mail_note(),
        # #31: the click-to-load human check on the anonymous creation form. `{}`
        # when the gate is off, so `new_poll.html` renders byte-for-byte as it did
        # in every mode and every deployment that does not gate.
        "turnstile": widget_ctx(ACTION_NEW_POLL),
    }


def require_anon_csrf(form, uid: str = ANON_FORM_UID) -> None:
    """The anonymous-form CSRF check, for whichever anonymous form is posting.

    `uid` rather than a fixed constant because there are two of them and they bind
    to different pages (`ANON_FORM_UID` for creation, `LINK_FORM_UID` for the
    re-link request), and one form's token must not be replayable at the other.
    """
    require_csrf({"uid": uid}, form)


def create_accountless_poll(
    request: Request,
    form,
    *,
    title: str,
    description: str | None,
    mode: str,
    timezone: str,
    slots: list[dict],
):
    """Create the poll, mail the creator its manage link, and say what happened.

    Refuses rather than creating a poll nobody can reach: in this mode outbound
    mail is the credential-delivery channel, so a deployment that cannot send
    cannot run this mode honestly. Creating the row anyway would produce a poll
    whose management link exists in no inbox and cannot be retrieved — the exact
    failure this route exists to prevent.
    """
    if not is_configured():
        return _link_page(request, "Email is not available", _mail_note(), 503)
    over_cap = slot_cap_refusal(len(slots))
    if over_cap:
        # The *second* line of defence, and no longer the one that bounds anything.
        # It used to be the only one, with a comment describing exactly the defect it
        # could not prevent: an uncapped `dates` field times (end - start) / increment
        # rows per date, from an anonymous POST, refused only once the rows existed.
        # Sixteen concurrent 992-date requests allocated 6 GB and every one of them
        # returned this 400. `web._expand_time_slots` now asks `slot_cap_refusal`
        # before it builds anything, so reaching here with an over-cap list means the
        # prediction and the fact disagree — which is why they are the same function
        # and the same number, and why a test pins the boundary from both sides.
        #
        # It stays because it is the check that can see a list nobody predicted (a
        # future caller building slots by another route), and because it is the one
        # that states the ceiling to a creator in the console's own voice.
        return _link_page(request, "That poll is too large", over_cap, 400)
    email = valid_email(form.get("creator_email", ""))
    if not email:
        return _link_page(
            request,
            "Email address required",
            "We mail your manage link there — it is the only way back into a poll that has no account.",
            400,
        )
    poll = create_poll(
        anonymous_creator_id(), title, description, mode, timezone, slots, owner_id=None, creator_email=email
    )
    sent = send_manage_email(email, poll["title"], manage_url(request, poll["admin_token"]))
    # No address, and that is deliberate. This is the only INFO line in the mode
    # that would have carried a stranger's address, in a log an operator ships to a
    # third-party collector, for a poll the operator cannot see. The poll id is
    # enough to find the row; whoever wants the address has it in the database.
    log.info("accountless poll %s created (link mailed: %s)", poll["id"], sent)
    if not sent:
        # The row exists; the credential does not. Say exactly that, and offer
        # the one thing that can fix it, rather than a bare error.
        return _link_page(
            request,
            "Your poll was created, but the link could not be sent",
            f'This deployment could not reach your mailbox. Your poll "{poll["title"]}" '
            "is saved — try again below in a moment, or ask the operator.",
            503,
        )
    return _link_page(
        request,
        "Check your inbox",
        f"We sent your manage link to {email}. Open it to manage your poll — it works "
        "once, and it is the only way back in.",
    )


def identity_report() -> str:
    """One boot line: which identity boundary is in force, and how narrow.

    Same reasoning as `mail_identity_report()` and `oidc.identity_report()`: a
    green boot must not be the only evidence an operator has about which control
    decided who may manage a poll.
    """
    if not enabled():
        return f"owner auth: {settings.AUTH_MODE} (capability links not in use)"
    return (
        "owner auth: capability (no account; management by the emailed manage link, "
        f"single use — the exchange rotates admin_token and mints a {SESSION_HOURS}h "
        f"cookie {SESSION_COOKIE}; manage_verified_at stamped on first open)"
    )


def boot_warnings() -> list[str]:
    """What an operator has to know before the first creator, not after.

    Each of these is a *precondition of this mode* rather than a defect: the
    deployment still boots, because refusing here would break the self-host
    topology ADR-0001/0002 protect, and every one of them shows up as a
    confusing page rather than an error the moment a creator tries to use it.
    A missing `SESSION_SECRET` is deliberately *not* one of them — it is not
    survivable, so it refuses to boot at import instead (see the gate above).
    The same is true of a human check that is on without its keys, which
    `turnstile` refuses at import for the same reason.
    """
    warnings = list(BOOT_WARNINGS)
    if not enabled():
        return warnings
    if not is_configured():
        warnings.append(
            "KAIROS_AUTH=capability is on but outbound mail is unusable, so no "
            "manage link can be delivered and poll creation is refused. Set "
            "SMTP_HOST (and in a hosted deployment KAIROS_HOSTED + "
            "KAIROS_FROM_DOMAIN)."
        )
    if not settings.RATE_LIMIT_ENABLED:
        warnings.append(
            "KAIROS_AUTH=capability is on with KAIROS_RATE_LIMIT off, so poll "
            "creation and manage-link re-requests are unbounded per source: anyone "
            "who can reach this app can have mail sent from its domain. Set "
            "KAIROS_RATE_LIMIT=on (and KAIROS_TRUSTED_PROXY_CIDRS, which it "
            "depends on) before exposing this deployment."
        )
    if turnstile_required() and not settings.RATE_LIMIT_ENABLED:
        # Not a duplicate of the warning above, and the reason is the point: the
        # human check bounds *creating* a poll and *asking for a link*, but a
        # verified creator's own sends are not gated by it, and every send path
        # still draws on a per-peer budget that is currently not in force. The
        # check is not a substitute for the limiter; it is the ceiling on top of it.
        warnings.append(
            "the poll-creation human check is on and KAIROS_RATE_LIMIT is off: the "
            "check bounds who may create a poll, but not how much mail one verified "
            "creator can send afterwards. Turn the limiter on as well."
        )
    if not settings.PUBLIC_URL:
        # Weaker than the other three, hence a warning rather than a refusal: with
        # KAIROS_TRUSTED_PROXY_CIDRS set, only a trusted peer can reach the app at
        # all (#47), so a caller cannot dictate the host here. A deployment without
        # that allowlist derives the origin from caller-supplied headers, and the
        # origin of a *credential* URL is not something to guess.
        warnings.append(
            "KAIROS_PUBLIC_URL is unset, so manage links are built from request "
            "headers — which a caller controls unless KAIROS_TRUSTED_PROXY_CIDRS "
            "restricts who can reach the app. A manage link IS a credential, so set "
            "both before exposing this deployment."
        )
    # The human check's *own* states are `turnstile.boot_warnings`, logged by
    # `main.create_app` under its own logger. This one is about this mode's
    # operational contract, so it belongs here: the check is in force, the limiter
    # that bounds what one verified creator can then send is not.
    return warnings
