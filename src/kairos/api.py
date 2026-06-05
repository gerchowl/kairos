"""Kairos REST API — full parity with the web UI, agent-friendly.

Auth: `Authorization: Bearer <SCHEDULER_API_KEY>` over HTTPS. The key is a
service identity with access to ALL polls (single-team tool); pass `creator`
on poll creation to attribute a poll to a real account so it appears on that
user's dashboard and they can manage it in the web UI.

Outbound mail triggered via the API is sent as the service address with the
poll creator's name/Reply-To by default; override per call with
`sender_name` / `reply_to`.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from kairos import settings
from kairos.auth import get_base_url, require_api_key
from kairos.db import (
    add_response,
    add_slots,
    create_invite,
    create_poll,
    delete_poll,
    find_response_by_email,
    get_contact_log,
    get_invites,
    get_poll,
    get_responses,
    list_polls,
    log_contact,
    update_poll,
    update_response,
)
from kairos.email_service import send_decision_email, send_invite_email
from kairos.helpers import convergence, format_slot
from kairos.ics import build_ics
from kairos.notifications import notify_new_response
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

def _get_or_404(poll_id: str) -> dict:
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
    return poll


# -- Endpoints --

@router.get("/ping")
def api_ping():
    return {"pong": True, "app": "scheduler"}


@router.post("/polls")
def create_poll_endpoint(body: PollCreate, request: Request, user: dict = Depends(require_api_key)):
    if body.mode not in ("full_day", "time_slot"):
        raise HTTPException(400, "mode must be 'full_day' or 'time_slot'")
    if not _valid_timezone(body.timezone):
        raise HTTPException(400, f"Unknown timezone: {body.timezone}")
    if body.mode == "time_slot":
        for s in body.slots:
            if not s.start_time or not s.end_time:
                raise HTTPException(400, "time_slot mode requires start_time and end_time for each slot")
    creator_id = body.creator or user["uid"]
    slots = [s.model_dump() for s in body.slots]
    poll = create_poll(creator_id, body.title, body.description, body.mode, body.timezone, slots)
    poll["share_url"] = _share_url(request, poll)
    return poll


@router.get("/polls")
def list_polls_endpoint(request: Request, user: dict = Depends(require_api_key)):
    polls = list_polls()
    for poll in polls:
        poll["share_url"] = _share_url(request, poll)
    return polls


@router.get("/polls/{poll_id}")
def get_poll_endpoint(poll_id: str, request: Request, user: dict = Depends(require_api_key)):
    return _poll_detail(request, _get_or_404(poll_id))


@router.patch("/polls/{poll_id}")
def update_poll_endpoint(poll_id: str, body: PollUpdate, request: Request,
                         user: dict = Depends(require_api_key)):
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


@router.delete("/polls/{poll_id}/invites/{invite_id}")
def delete_invite_endpoint(poll_id: str, invite_id: str, user: dict = Depends(require_api_key)):
    """Remove an invitee (and their linked response, if any)."""
    _get_or_404(poll_id)
    from kairos.db import delete_invite, delete_response, get_responses
    for r in get_responses(poll_id):
        if r.get("invite_id") == invite_id:
            delete_response(r["id"])
    if not delete_invite(invite_id):
        raise HTTPException(404, "Invite not found")
    return {"deleted": True}


@router.delete("/polls/{poll_id}/responses/{response_id}")
def delete_response_endpoint(poll_id: str, response_id: str, user: dict = Depends(require_api_key)):
    """Remove a response (walk-in or invited)."""
    _get_or_404(poll_id)
    from kairos.db import delete_response
    if not delete_response(response_id):
        raise HTTPException(404, "Response not found")
    return {"deleted": True}


@router.delete("/polls/{poll_id}")
def delete_poll_endpoint(poll_id: str, user: dict = Depends(require_api_key)):
    _get_or_404(poll_id)
    delete_poll(poll_id)
    return {"deleted": True}


@router.post("/polls/{poll_id}/decide")
def decide_endpoint(poll_id: str, body: DecideIn, request: Request,
                    user: dict = Depends(require_api_key)):
    poll = _get_or_404(poll_id)
    if body.slot_id not in {s["id"] for s in poll["slots"]}:
        raise HTTPException(400, "slot_id does not belong to this poll")
    update_poll(poll_id, status="decided", decided_slot_id=body.slot_id)
    return _poll_detail(request, get_poll(poll_id))


@router.post("/polls/{poll_id}/slots")
def add_slots_endpoint(poll_id: str, body: SlotsAdd, request: Request,
                       user: dict = Depends(require_api_key)):
    poll = _get_or_404(poll_id)
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
def respond_endpoint(poll_id: str, body: ResponseCreate, user: dict = Depends(require_api_key)):
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
def get_responses_endpoint(poll_id: str, user: dict = Depends(require_api_key)):
    _get_or_404(poll_id)
    return get_responses(poll_id)


@router.post("/polls/{poll_id}/invite")
def invite_endpoint(poll_id: str, body: InviteCreate, request: Request,
                    user: dict = Depends(require_api_key)):
    poll = _get_or_404(poll_id)
    actor = _actor(poll, body.sender_name, body.reply_to)
    base = get_base_url(request)
    results = []
    from kairos.http import valid_email
    bad = [e for e in body.emails if not valid_email(e)]
    if bad:
        raise HTTPException(400, f"Invalid email address(es): {', '.join(bad)}")
    for email in body.emails:
        invite = create_invite(poll_id, email, required=body.required)
        invite_url = f"{base}{P}/p/i/{invite['token']}"
        sent = send_invite_email(email, poll["title"], invite_url,
                                 actor["name"], reply_to=actor["email"])
        if sent:
            log_contact(poll_id, email, "invite", invite["id"])
        results.append({"email": email, "invite_url": invite_url,
                        "required": body.required, "email_sent": sent})
    return {"invites": results}


@router.get("/polls/{poll_id}/invites")
def get_invites_endpoint(poll_id: str, user: dict = Depends(require_api_key)):
    _get_or_404(poll_id)
    return get_invites(poll_id)


@router.post("/polls/{poll_id}/nudge")
def nudge_endpoint(poll_id: str, body: NudgeIn, request: Request,
                   user: dict = Depends(require_api_key)):
    poll = _get_or_404(poll_id)
    if poll["status"] != "open":
        raise HTTPException(400, "Poll is not open")
    only = {e.strip().lower() for e in body.emails} if body.emails else None
    return nudge_participants(request, poll, _actor(poll, body.sender_name, body.reply_to),
                              only_emails=only, force=body.force)


@router.get("/polls/{poll_id}/contacts")
def contacts_endpoint(poll_id: str, user: dict = Depends(require_api_key)):
    """Outbound-mail audit trail for a poll, newest first."""
    _get_or_404(poll_id)
    return get_contact_log(poll_id)


@router.post("/polls/{poll_id}/email-decision")
def email_decision_endpoint(poll_id: str, body: MailIn, request: Request,
                            user: dict = Depends(require_api_key)):
    poll = _get_or_404(poll_id)
    slot = decided_slot_of(poll)
    if not slot:
        raise HTTPException(400, "Poll has no decided date yet")
    actor = _actor(poll, body.sender_name, body.reply_to)
    poll_url = _share_url(request, poll)
    sent = send_decision_email(
        recipient_emails(poll_id), poll["title"], format_slot(slot, poll["mode"]),
        poll_url, build_ics(poll, slot, poll_url), actor["name"],
        note=body.note, reply_to=actor["email"])
    for email in sent:
        log_contact(poll_id, email, "decision")
    return {"sent": len(sent), "recipients": sent}


@router.get("/polls/{poll_id}/event.ics")
def event_ics_endpoint(poll_id: str, request: Request, user: dict = Depends(require_api_key)):
    return ics_response(_get_or_404(poll_id), request)
