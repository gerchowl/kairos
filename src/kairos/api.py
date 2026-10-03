"""Kairos REST API — full parity with the web UI, agent-friendly.

Auth: `Authorization: Bearer <KAIROS_API_KEY>` over HTTPS. The key is a
service identity with access to ALL polls (single-team tool); pass `creator`
on poll creation to attribute a poll to a real account so it appears on that
user's dashboard and they can manage it in the web UI.

**Reach** (issues #63/#64). A scope says what a key may *do*; reach says which
*polls* it may do it to. Every route below that names a poll declares
`api_scope(..., reach=True)`, so a `polls:read` key reads the polls it was granted
rather than every poll on the instance -- and in the default configuration reads
exactly what it did before this file existed. See `kairos.reach` for the policy,
and `GET /api/whoami` for what the presenting key reaches.

**Scopes** (issue #51). Every route below declares the capability it needs, as
`api_scope("...")`, and a key without it gets 403 -- so a read-only key cannot
reach a mail-sending route by construction rather than by review. The single
`KAIROS_API_KEY` still holds every capability (the paragraph above is still
exactly true of it); least-privilege keys come from `KAIROS_API_KEYS`, and
`GET .../whoami` reports what the presenting key may do. Outbound mail is
additionally bounded three ways: a recipient-list cap per request, a per-poll
send budget shared with the web UI, and per-key rate limits under
`KAIROS_RATE_LIMIT=on`.

Outbound mail triggered via the API is sent as the service address with the
poll creator's name/Reply-To by default; override per call with
`sender_name` / `reply_to`.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from kairos import settings
from kairos.auth import get_base_url
from kairos.db import (
    add_response,
    add_slots,
    bump_slot_sequence,
    create_invite,
    create_poll,
    delete_poll,
    find_response_by_email,
    get_contact_log,
    get_invites,
    get_poll,
    get_responses,
    get_slot_sequence,
    list_polls,
    log_contact,
    make_short_link,
    update_poll,
    update_response,
)
from kairos.email_service import (
    send_decision_email,
    send_imip,
    send_invite_email,
    sender_refusal,
    webcal_from,
)
from kairos.helpers import convergence, format_slot
from kairos.ics import build_ics, build_request_ics
from kairos.notifications import notify_new_response
from kairos.reach import only_reachable, reached_by
from kairos.scoping import api_scope, charge_force, charge_poll_recipients, check_recipient_list, enforce
from kairos.web import (
    _valid_timezone,
    decided_slot_of,
    expand_new_dates,
    ics_response,
    nudge_participants,
    recipient_emails,
)

P = settings.PREFIX
router = APIRouter(prefix=f"{P}/api")


# -- Request/Response models --

class SlotIn(BaseModel):
    date: str
    start_time: str | None = None
    end_time: str | None = None

class PollCreate(BaseModel):
    title: str
    description: str | None = None
    mode: str  # full_day or time_slot
    timezone: str = "Europe/Zurich"
    slots: list[SlotIn]
    creator: str | None = None  # account uid — attributes the poll to a real user
    # Where a management link may be sent for this poll (#29/#30). Recorded,
    # not acted on: nothing mails it yet, and the response never carries it.
    creator_email: str | None = None

class PollUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    timezone: str | None = None
    status: str | None = None  # open | closed (use /decide for decided)

class ResponseCreate(BaseModel):
    name: str
    email: str | None = None
    availabilities: dict[str, str]  # slot_id -> yes/maybe/no

class InviteCreate(BaseModel):
    emails: list[str]
    required: bool = True
    sender_name: str | None = None
    reply_to: str | None = None

class DecideIn(BaseModel):
    slot_id: str

class SlotsAdd(BaseModel):
    dates: list[str]  # YYYY-MM-DD; time_slot polls expand over the time grid
    notify: bool = False
    sender_name: str | None = None
    reply_to: str | None = None

class MailIn(BaseModel):
    note: str = ""
    sender_name: str | None = None
    reply_to: str | None = None

class NudgeIn(BaseModel):
    emails: list[str] | None = None  # restrict to these participants
    force: bool = False              # operator intent: bypass cooldown/gating
    sender_name: str | None = None
    reply_to: str | None = None


# -- Helpers --

# Fields that must never leave the process in an API response. `admin_token` is a
# bearer management capability (ADR-0001): whoever holds it manages the poll with
# no API key, indefinitely, so a response that started carrying it would turn the
# operator's single bearer key into a permanent per-poll credential — strictly more
# than the key already is, and durable across key rotation. `creator_email` is the
# creator's own address, which no response carried before these columns existed.
# The token stays inside the process until #30 has a manage link to put it in.
_NEVER_SERIALIZED = ("admin_token", "creator_email")


def _without_secrets(poll: dict) -> dict:
    """`poll` without the never-serialized fields -- a copy, not an in-place pop.

    Copying rather than popping is the point: an in-place version whose return
    value a caller forgets (or discards, as `list_polls_endpoint` once did)
    leaks the token silently, and the leak would look like a working refactor.
    """
    return {k: v for k, v in poll.items() if k not in _NEVER_SERIALIZED}


def _get_or_404(poll_id: str) -> dict:
    """The poll, or a 404. Existence only.

    Reach is deliberately *not* decided here (issues #63/#64). On this surface a
    key's reach is a pure function of the poll id in the path and the ids its grant
    names, so it needs no row -- which means the check can live in the route's
    `api_scope(..., reach=True)` declaration, ahead of the handler, where the CI
    audit can see it, instead of in a helper every route has to remember to call
    (`reach.guard_reach`). One declaration, one place, no second thing to forget.
    """
    poll = get_poll(poll_id)
    if not poll:
        raise HTTPException(404, "Poll not found")
    return poll


def _actor(poll: dict, sender_name: str | None = None, reply_to: str | None = None) -> dict:
    """Mail sender identity: explicit override, else generic brand.

    Deployments with a user directory can monkeypatch this to resolve the
    poll creator's account (a deployment adapter can)."""
    return {"name": sender_name or settings.BRAND, "email": reply_to}


def _share_url(request: Request, poll: dict) -> str:
    return f"{get_base_url(request)}{P}/p/{poll['public_token']}"


def _poll_detail(request: Request, poll: dict) -> dict:
    poll["responses"] = get_responses(poll["id"])
    poll["invites"] = get_invites(poll["id"])
    poll["convergence"] = convergence(poll, poll["responses"], poll["invites"])
    poll["share_url"] = _share_url(request, poll)
    return _without_secrets(poll)


# -- Endpoints --

@router.get("/ping")
def api_ping():
    return {"pong": True, "app": "scheduler"}


@router.get("/whoami")
def whoami(user: dict = Depends(api_scope())):
    """What this key may do — the discoverability half of least privilege.

    An agent holding a scoped key that meets four 403s it was never told about
    cannot plan, so the capabilities are readable over the API rather than only
    documented in an operator's env file. Reports the key's digest, never the
    key, and only what this key holds — not the whole vocabulary.
    """
    return {"scopes": sorted(user["scopes"]), "key_id": user["key_id"],
            "tier": user.get("tier"),
            # Reach as well as capability (issue #63): the two are different
            # questions, and an agent refused a poll deserves to learn from one
            # call that it was refused the poll, not its capability — including
            # which of the two reach rules the deployment is running.
            "polls": reached_by(user).polls,
            "reach_policy": reached_by(user).policy}


@router.post("/polls")
def create_poll_endpoint(body: PollCreate, request: Request, user: dict = Depends(api_scope("polls:write"))):
    if body.mode not in ("full_day", "time_slot"):
        raise HTTPException(400, "mode must be 'full_day' or 'time_slot'")
    if not _valid_timezone(body.timezone):
        raise HTTPException(400, f"Unknown timezone: {body.timezone}")
    if body.mode == "time_slot":
        for s in body.slots:
            if not s.start_time or not s.end_time:
                raise HTTPException(400, "time_slot mode requires start_time and end_time for each slot")
    creator_id = body.creator or user["uid"]
    from kairos.http import valid_email

    creator_email = valid_email(body.creator_email) if body.creator_email else None
    if body.creator_email and not creator_email:
        raise HTTPException(400, f"Invalid email address: {body.creator_email}")
    slots = [s.model_dump() for s in body.slots]
    # owner_id == creator_id: the API attributes a poll either to the named user
    # or to the service identity that made it, and that is its owner (ADR-0009).
    poll = create_poll(creator_id, body.title, body.description, body.mode, body.timezone,
                       slots, creator_id, creator_email)
    poll["share_url"] = _share_url(request, poll)
    return _without_secrets(poll)


@router.get("/polls")
def list_polls_endpoint(request: Request, user: dict = Depends(api_scope("polls:read"))):
    # Scoped by reach, not by scope (issue #63): a `polls:read` key used to enumerate
    # the whole instance here. Under `open` the argument comes back unchanged and
    # unexamined; under `scoped` it is the caller's reach -- and an empty list,
    # rather than a 403, is what a correctly-scoped key with no grant is owed.
    polls = only_reachable(list_polls(), request, principal=user)
    for poll in polls:
        poll["share_url"] = _share_url(request, poll)
    # Scrubbed on the way out, from the return value -- see _without_secrets.
    return [_without_secrets(poll) for poll in polls]


@router.get("/polls/{poll_id}")
def get_poll_endpoint(
    poll_id: str, request: Request, user: dict = Depends(api_scope("polls:read", reach=True))
):
    return _poll_detail(request, _get_or_404(poll_id))


@router.patch("/polls/{poll_id}")
def update_poll_endpoint(poll_id: str, body: PollUpdate, request: Request,
                         user: dict = Depends(api_scope("polls:write", reach=True))):
    _get_or_404(poll_id)
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(400, "No fields to update")
    if "status" in updates and updates["status"] not in ("open", "closed"):
        raise HTTPException(400, "status must be 'open' or 'closed' — use POST .../decide to decide")
    if "timezone" in updates and not _valid_timezone(updates["timezone"]):
        raise HTTPException(400, f"Unknown timezone: {updates['timezone']}")
    if updates.get("status") == "open":
        updates["decided_slot_id"] = None  # reopen clears the decision
    update_poll(poll_id, **updates)
    return _poll_detail(request, get_poll(poll_id))


class InvitePatch(BaseModel):
    name: str | None = None
    email: str | None = None
    required: bool | None = None


@router.patch("/polls/{poll_id}/invites/{invite_id}")
def patch_invite_endpoint(poll_id: str, invite_id: str, body: InvitePatch,
                          user: dict = Depends(api_scope("polls:write", reach=True))):
    """Edit an invitee's name/email/required flag."""
    _get_or_404(poll_id)
    from kairos.db import update_invite
    if body.email is not None:
        from kairos.http import valid_email
        if not valid_email(body.email):
            raise HTTPException(400, "Invalid email address")
    if not update_invite(invite_id, name=body.name, email=body.email, required=body.required):
        raise HTTPException(404, "Invite not found or no fields given")
    return {"updated": True}


@router.delete("/polls/{poll_id}/invites/{invite_id}")
def delete_invite_endpoint(poll_id: str, invite_id: str,
                           user: dict = Depends(api_scope("polls:write", reach=True))):
    """Remove an invitee (and their linked response, if any)."""
    _get_or_404(poll_id)
    from kairos.db import delete_invite, delete_response, get_responses
    for r in get_responses(poll_id):
        if r.get("invite_id") == invite_id:
            delete_response(r["id"])
    if not delete_invite(invite_id):
        raise HTTPException(404, "Invite not found")
    return {"deleted": True}


class ResponsePatch(BaseModel):
    name: str | None = None
    email: str | None = None
    required: bool | None = None


@router.patch("/polls/{poll_id}/responses/{response_id}")
def patch_response_endpoint(poll_id: str, response_id: str, body: ResponsePatch,
                            user: dict = Depends(api_scope("polls:write", reach=True))):
    """Edit a respondent's name/email or toggle required (via-link people
    count as required for convergence unless marked optional)."""
    _get_or_404(poll_id)
    from kairos.db import update_response_contact
    if body.email is not None:
        from kairos.http import valid_email
        if not valid_email(body.email):
            raise HTTPException(400, "Invalid email address")
    if not update_response_contact(response_id, name=body.name, email=body.email,
                                   required=body.required):
        raise HTTPException(404, "Response not found or no fields given")
    return {"updated": True}


@router.delete("/polls/{poll_id}/responses/{response_id}")
def delete_response_endpoint(poll_id: str, response_id: str,
                             user: dict = Depends(api_scope("polls:write", reach=True))):
    """Remove a response (walk-in or invited)."""
    _get_or_404(poll_id)
    from kairos.db import delete_response
    if not delete_response(response_id):
        raise HTTPException(404, "Response not found")
    return {"deleted": True}


@router.delete("/polls/{poll_id}")
def delete_poll_endpoint(poll_id: str, user: dict = Depends(api_scope("polls:write", reach=True))):
    _get_or_404(poll_id)
    delete_poll(poll_id)
    return {"deleted": True}


@router.post("/polls/{poll_id}/decide")
def decide_endpoint(poll_id: str, body: DecideIn, request: Request,
                    user: dict = Depends(api_scope("polls:write", reach=True))):
    poll = _get_or_404(poll_id)
    if body.slot_id not in {s["id"] for s in poll["slots"]}:
        raise HTTPException(400, "slot_id does not belong to this poll")
    update_poll(poll_id, status="decided", decided_slot_id=body.slot_id)
    return _poll_detail(request, get_poll(poll_id))


@router.post("/polls/{poll_id}/slots")
def add_slots_endpoint(poll_id: str, body: SlotsAdd, request: Request,
                       user: dict = Depends(api_scope("polls:write", reach=True))):
    poll = _get_or_404(poll_id)
    # `notify` mails, so it needs mail:send on top of polls:write — otherwise a key
    # scoped "edit this poll" reaches every inbox through a route whose name promises
    # none of that. Checked *first*, before any row is written: a refused request
    # that has already mutated state is worse than no request at all to whoever
    # reads the audit log afterwards. (kairos.scoping, issue #51)
    if body.notify:
        enforce(user, "mail:send")
    for d in body.dates:
        try:
            datetime.strptime(d, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(400, f"Invalid date: {d!r} (expected YYYY-MM-DD)") from None
    slots = expand_new_dates(poll, body.dates)
    added = add_slots(poll_id, slots) if slots else []
    nudged = None
    if body.notify and added:
        nudged = nudge_participants(request, get_poll(poll_id),
                                    _actor(poll, body.sender_name, body.reply_to))
    return {"added": added, "nudged": nudged}


@router.post("/polls/{poll_id}/respond")
def respond_endpoint(poll_id: str, body: ResponseCreate,
                     user: dict = Depends(api_scope("respond", reach=True))):
    poll = _get_or_404(poll_id)
    if poll["status"] != "open":
        raise HTTPException(400, "Poll is not open")
    valid_slot_ids = {s["id"] for s in poll["slots"]}
    for slot_id in body.availabilities:
        if slot_id not in valid_slot_ids:
            raise HTTPException(400, f"Invalid slot_id: {slot_id}")
        if body.availabilities[slot_id] not in ("yes", "maybe", "no"):
            raise HTTPException(400, "availability must be 'yes', 'maybe', or 'no'")
    # Upsert by email so repeated submissions edit instead of duplicating
    existing = find_response_by_email(poll_id, body.email) if body.email else None
    if existing:
        return update_response(existing["id"], body.name, body.availabilities, email=body.email)
    response = add_response(poll_id, body.name, body.email, body.availabilities)
    notify_new_response(poll_id, body.name)
    return response


@router.get("/polls/{poll_id}/responses")
def get_responses_endpoint(poll_id: str, user: dict = Depends(api_scope("polls:read", reach=True))):
    _get_or_404(poll_id)
    return get_responses(poll_id)


@router.post("/polls/{poll_id}/invite")
def invite_endpoint(poll_id: str, body: InviteCreate, request: Request,
                    user: dict = Depends(api_scope("mail:send", reach=True))):
    # The ONLY route whose recipient list comes straight from the caller, and so
    # the only one with a hard per-request ceiling: the schema puts no bound on
    # `emails`, and a caller who is refused still holds every address and can send
    # them in batches. Every other send path fans out over a poll's own
    # participants, where a long list is a real meeting rather than an attack, so
    # those are bounded by the per-poll budget (429, retryable) instead. Charged
    # before a single row is written, let alone a message sent.
    check_recipient_list(len(body.emails), what="email addresses")
    poll = _get_or_404(poll_id)
    actor = _actor(poll, body.sender_name, body.reply_to)
    base = get_base_url(request)
    results = []
    from email.utils import parseaddr

    from kairos.http import valid_email
    # entries may be bare addresses or RFC 5322 "Name <addr>" pairs
    parsed = [(parseaddr(e)[0] or None, parseaddr(e)[1]) for e in body.emails]
    bad = [e for (_, e) in parsed if not valid_email(e)]
    if bad:
        raise HTTPException(400, f"Invalid email address(es): {', '.join(bad)}")
    names = {e: n for (n, e) in parsed}
    body.emails = [e for (_, e) in parsed]
    # The per-poll budget, keyed on the poll rather than the key, so it holds
    # whichever credential asks and however the calls are split up.
    charge_poll_recipients(poll_id, len(body.emails))
    for email in body.emails:
        invite = create_invite(poll_id, email, required=body.required,
                                name=names.get(email))
        invite_url = f"{base}{P}/p/i/{invite['token']}"
        sub = webcal_from(invite_url) if settings.FEED_ENABLED else None
        sent = send_invite_email(email, poll["title"], invite_url,
                                 actor["name"], reply_to=actor["email"], subscribe_url=sub)
        if sent:
            log_contact(poll_id, email, "invite", invite["id"])
        # Obligation M1: `email_sent: false` is ambiguous on its own -- it means either
        # "mail is not configured" or "the M1 gate is refusing this sender". An API caller
        # holding the operator's API key can be told which, so an unattended agent does not
        # retry a send that can never succeed. The web UI shows a generic variant instead,
        # because there the reader is a poll owner rather than the operator.
        entry = {"email": email, "invite_url": invite_url,
                 "required": body.required, "email_sent": sent}
        if not sent and (refusal := sender_refusal()) is not None:
            entry["email_blocked"] = refusal.code
            entry["blocked_reason"] = refusal.message
        results.append(entry)
    return {"invites": results}


@router.get("/polls/{poll_id}/invites")
def get_invites_endpoint(poll_id: str, user: dict = Depends(api_scope("polls:read", reach=True))):
    _get_or_404(poll_id)
    return get_invites(poll_id)


@router.post("/polls/{poll_id}/nudge")
def nudge_endpoint(poll_id: str, body: NudgeIn, request: Request,
                   user: dict = Depends(api_scope("mail:send", reach=True))):
    """Smart reminders. `force=True` bypasses the 24h cooldown — an operator
    affordance for a human in the UI, so from here it takes its own scope AND its
    own, much tighter budget (issue #51).

    `emails=[...]` narrows the *audience*; only addresses already on the poll are
    mailed, so a long list is not a fan-out and gets no per-request ceiling. What
    bounds it is the poll's own send budget, charged in `nudge_participants` —
    which is also what bounds the same operation from the web UI."""
    if body.force:
        enforce(user, "mail:force")
        charge_force(user)
    poll = _get_or_404(poll_id)
    if poll["status"] != "open":
        raise HTTPException(400, "Poll is not open")
    only = {e.strip().lower() for e in body.emails} if body.emails else None
    # The poll's own budget is charged inside nudge_participants, so the web UI's
    # remind / remind-selected spend the same one.
    return nudge_participants(request, poll, _actor(poll, body.sender_name, body.reply_to),
                              only_emails=only, force=body.force)


@router.get("/polls/{poll_id}/contacts")
def contacts_endpoint(poll_id: str, user: dict = Depends(api_scope("polls:read", reach=True))):
    """Outbound-mail audit trail for a poll, newest first."""
    _get_or_404(poll_id)
    return get_contact_log(poll_id)


@router.post("/polls/{poll_id}/email-decision")
def email_decision_endpoint(poll_id: str, body: MailIn, request: Request,
                            user: dict = Depends(api_scope("mail:send", reach=True))):
    poll = _get_or_404(poll_id)
    slot = decided_slot_of(poll)
    if not slot:
        raise HTTPException(400, "Poll has no decided date yet")
    actor = _actor(poll, body.sender_name, body.reply_to)
    poll_url = _share_url(request, poll)
    # Recipients come from the poll, not from the request, so this fan-out is
    # bounded by the per-poll budget rather than refused outright — a poll with
    # more participants than the per-request cap is a real meeting, not an attack.
    # Charged here and in the web UI's equivalent, so the two surfaces share one
    # allowance.
    recipients = recipient_emails(poll_id)
    charge_poll_recipients(poll_id, len(recipients))
    sent = send_decision_email(
        recipients, poll["title"], format_slot(slot, poll["mode"]),
        poll_url, build_ics(poll, slot, poll_url), actor["name"],
        note=body.note, reply_to=actor["email"])
    for email in sent:
        log_contact(poll_id, email, "decision")
    return {"sent": len(sent), "recipients": sent}


@router.get("/polls/{poll_id}/event.ics")
def event_ics_endpoint(
    poll_id: str, request: Request, user: dict = Depends(api_scope("polls:read", reach=True))
):
    return ics_response(_get_or_404(poll_id), request)


@router.post("/imip/poll")
def imip_poll_endpoint(user: dict = Depends(api_scope("imip:poll"))):
    """Run one IMAP poll cycle for inbound iMIP replies; returns the count
    applied. Operators schedule this (cron / systemd timer hitting the API).
    No-op unless KAIROS_IMIP + IMAP host are configured."""
    from kairos.imip_inbound import poll_mailbox
    return {"applied": poll_mailbox()}


@router.post("/polls/{poll_id}/imip-decision")
def imip_decision_endpoint(poll_id: str, request: Request,
                           user: dict = Depends(api_scope("mail:send", reach=True))):
    """Hybrid-C finalist step: send a native iMIP REQUEST for the decided slot
    to every participant, so they get real Accept/Maybe/Decline buttons and
    their reply flows back via the IMAP poller. Replies route to IMIP_ORGANIZER."""
    if not (settings.IMIP_ENABLED and settings.IMIP_ORGANIZER):
        raise HTTPException(400, "iMIP not configured (KAIROS_IMIP / KAIROS_IMIP_ORGANIZER)")
    poll = _get_or_404(poll_id)
    slot = decided_slot_of(poll)
    if not slot:
        raise HTTPException(400, "Poll has no decided date yet")
    # First send for this poll's finalist stays at SEQUENCE:0 — a first-seen
    # event at SEQUENCE>0 confuses some clients (notably Gmail's RSVP rendering).
    # Only a re-send (a prior decision already went out) bumps it to an update.
    prior = any(c.get("kind") == "decision" for c in get_contact_log(poll_id))
    seq = bump_slot_sequence(slot["id"]) if prior else get_slot_sequence(slot["id"])
    poll_url = _share_url(request, poll)
    label = format_slot(slot, poll["mode"])
    subject = f"Invitation: {poll['title']} — {label}"
    base = get_base_url(request)
    invites = {i["email"]: i for i in get_invites(poll_id)}
    # The same per-poll budget every other send path charges (see email-decision).
    targets = recipient_emails(poll_id)
    charge_poll_recipients(poll_id, len(targets))
    sent = []
    for email in targets:
        inv = invites.get(email)
        # Per-invitee one-click RSVP links in the DESCRIPTION: Gmail renders these
        # (clickable) in its event card even when it suppresses native RSVP for a
        # Gmail-organized invite, so every client gets a working Accept/Maybe/Decline.
        if inv and settings.FEED_ENABLED:
            sid, tok = slot["id"], inv["token"]

            def short(av, sid=sid, tok=tok):  # our own tiny-url; capability kept private
                code = make_short_link(f"{P}/p/i/{tok}/s/{sid}/{av}")
                return f"{base}{P}/v/{code}"
            desc = (f"{poll['title']} — {label}\n\nRSVP (one click):\n"
                    f"Accept: {short('yes')}\nMaybe: {short('maybe')}\nDecline: {short('no')}\n\nPoll: {poll_url}")
        else:
            desc = f"{poll['title']} — {label}\nPoll: {poll_url}"
        ics = build_request_ics(poll, slot, email,
                                organizer_email=settings.IMIP_ORGANIZER,
                                organizer_name=settings.IMIP_ORGANIZER_NAME,
                                sequence=seq, url=poll_url, description=desc)
        if send_imip(email, subject, desc, ics, "REQUEST",
                     settings.IMIP_ORGANIZER, settings.IMIP_ORGANIZER_NAME):
            log_contact(poll_id, email, "decision")
            sent.append(email)
    return {"sent": len(sent), "recipients": sent}
