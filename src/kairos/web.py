from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from kairos import settings
from kairos.auth import get_base_url, get_user
from kairos.csrf import make_csrf, require_csrf
from kairos.db import (
    add_slots,
    create_invite,
    create_poll,
    delete_invite,
    delete_response,
    get_contact_log,
    get_invites,
    get_notifications,
    get_poll,
    get_responses,
    list_polls,
    log_contact,
    mark_all_notifications_read,
    mark_invite_notified,
    mark_notification_read,
    mark_response_notified,
    update_invite,
    update_poll,
    update_response_contact,
)
from kairos.dbconn import db_now
from kairos.email_service import send_decision_email, send_invite_email, send_update_emails
from kairos.helpers import (
    TIMEZONES,
    convergence,
    env,
    expected_counts,
    fmt_time,
    format_slot,
    participant_states,
    slot_counts,
    slot_gaps,
    timeslot_payload,
)
from kairos.http import form_data, valid_email
from kairos.ics import build_ics
from kairos.templating import render

P = settings.PREFIX
router = APIRouter(prefix=P) if P else APIRouter()


def _login_or_401(next_path: str):
    """Owner pages: redirect to the deployment's sign-in page, or explain."""
    if settings.LOGIN_URL:
        return RedirectResponse(f"{settings.LOGIN_URL}?next={next_path}", status_code=302)
    return render(env, "message.html", status_code=401, title="Sign in required",
                  heading="Sign in required", error=True, user=None,
                  detail="This page is for poll owners. Sign in via your organization's portal or identity proxy.")

_MSG_TEXT = {
    "invited": "Invitee added — select them in the table to send the invite mail.",
    "removed": "Participant removed.",
    "updated": "Participant updated.",
    "duplicate": "That address is already on the list.",
    "closed": "Poll closed.",
    "decided": "Time decided!",
    "saved": "Poll updated.",
    "reopened": "Poll reopened — it accepts responses again.",
    "mailfail": "Email not sent — SMTP is not configured or no recipient has an email address.",
}


def _msg_text(query_params) -> str | None:
    msg = query_params.get("msg", "")
    n = query_params.get("n", "0")
    if msg == "emailed":
        return f"Final date emailed to {n} recipient{'' if n == '1' else 's'}."
    if msg == "nudged":
        inv, upd = query_params.get("inv", "0"), query_params.get("upd", "0")
        parts = []
        if inv != "0":
            parts.append(f"{inv} invite reminder{'' if inv == '1' else 's'}")
        if upd != "0":
            parts.append(f"{upd} new-dates notice{'' if upd == '1' else 's'}")
        return "Reminders sent: " + " and ".join(parts) + "."
    if msg == "nonudge":
        return "Nobody needed a reminder — everyone is up to date or was nudged recently."
    return _MSG_TEXT.get(msg)


def _nav_ctx(user: dict) -> dict:
    """Notification bubble + CSRF for the navbar (all authed pages)."""
    notifs = get_notifications(user["uid"], unread_only=True)
    return {"notif_count": len(notifs), "notifs": notifs[:8],
            "csrf_token": make_csrf(user["uid"])}


def _valid_timezone(tz: str) -> bool:
    from zoneinfo import ZoneInfo
    try:
        ZoneInfo(tz)
        return True
    except Exception:
        return False


def _owner_action(request: Request, form, poll_id: str) -> tuple[dict, dict]:
    """Auth + CSRF + ownership gate shared by all owner POST actions."""
    user = get_user(request)
    if not user:
        raise HTTPException(401)
    require_csrf(user, form)
    poll = get_poll(poll_id)
    if not poll or poll["creator_id"] != user["uid"]:
        raise HTTPException(403, "Not the poll owner")
    return user, poll


def expand_new_dates(poll: dict, dates: list[str]) -> list[dict]:
    """Slots for genuinely-new dates; time_slot polls reuse the poll's time grid."""
    existing = {str(s["date"]) for s in poll["slots"]}
    new_dates = [d for d in dates if d and d not in existing]
    time_pairs = sorted({(fmt_time(s["start_time"]), fmt_time(s["end_time"]))
                         for s in poll["slots"] if s.get("start_time")})
    if poll["mode"] == "time_slot" and time_pairs:
        return [{"date": d, "start_time": st, "end_time": et}
                for d in new_dates for st, et in time_pairs]
    return [{"date": d} for d in new_dates]


def decided_slot_of(poll: dict) -> dict | None:
    if poll["status"] != "decided" or not poll["decided_slot_id"]:
        return None
    return next((s for s in poll["slots"] if s["id"] == poll["decided_slot_id"]), None)


def recipient_emails(poll_id: str) -> list[str]:
    """Everyone reachable for this poll: respondents + invitees, deduped."""
    emails = []
    for r in get_responses(poll_id):
        if r.get("respondent_email"):
            emails.append(r["respondent_email"].strip().lower())
    for inv in get_invites(poll_id):
        if inv.get("email"):
            emails.append(inv["email"].strip().lower())
    return sorted(set(emails))


def ics_response(poll: dict, request: Request) -> Response:
    slot = decided_slot_of(poll)
    if not slot:
        raise HTTPException(404, "No decided date for this poll")
    url = f"{get_base_url(request)}{P}/p/{poll['public_token']}"
    return Response(content=build_ics(poll, slot, url), media_type="text/calendar",
                    headers={"Content-Disposition": 'attachment; filename="kairos-event.ics"'})


def _error_page(user: dict, heading: str, detail: str, back: str, status_code: int = 400):
    return render(env, "message.html", status_code=status_code, user=user,
                  title=heading, heading=heading, detail=detail, back=back, error=True,
                  **_nav_ctx(user))


# -- Routes --

@router.get("/")
def dashboard(request: Request):
    user = get_user(request)
    if not user:
        return _login_or_401(f"{P}/")

    polls = list_polls(user["uid"])
    for poll_row in polls:
        poll_row["conv"] = convergence(poll_row, get_responses(poll_row["id"]),
                                       get_invites(poll_row["id"]))
        poll_row["invite_count"] = len(get_invites(poll_row["id"]))

    return render(env, "dashboard.html", user=user, title="Kairos",
                  polls=polls, **_nav_ctx(user))


@router.get("/new")
def new_poll_page(request: Request):
    user = get_user(request)
    if not user:
        return _login_or_401(f"{P}/new")
    return render(env, "new_poll.html", user=user, title="New Poll",
                  timezones=TIMEZONES, **_nav_ctx(user))


@router.post("/new")
def create_poll_submit(request: Request, form=Depends(form_data)):
    user = get_user(request)
    if not user:
        return _login_or_401(f"{P}/new")
    require_csrf(user, form)

    title = form.get("title", "").strip()
    description = form.get("description", "").strip() or None
    mode = form.get("mode", "full_day")
    timezone = form.get("timezone", "Europe/Zurich").strip()

    if not title:
        return _error_page(user, "New Poll", "Title is required.", f"{P}/new")
    if not _valid_timezone(timezone):
        return _error_page(user, "New Poll", "Unknown timezone.", f"{P}/new")

    dates = form.getlist("dates")

    slots = []
    if mode == "time_slot":
        start_all = form.get("start_time_all", "09:00")
        end_all = form.get("end_time_all", "17:00")
        increment = int(form.get("increment", "30"))
        if not start_all or not end_all:
            return _error_page(user, "New Poll",
                               "Start and end times are required for time slot mode.",
                               f"{P}/new")
        t_start = datetime.strptime(start_all, "%H:%M")
        t_end = datetime.strptime(end_all, "%H:%M")
        for date in dates:
            if not date:
                continue
            t = t_start
            while t + timedelta(minutes=increment) <= t_end:
                t_next = t + timedelta(minutes=increment)
                slots.append({
                    "date": date,
                    "start_time": t.strftime("%H:%M"),
                    "end_time": t_next.strftime("%H:%M"),
                })
                t = t_next
    else:
        for date in dates:
            if not date:
                continue
            slots.append({"date": date})

    if not slots:
        return _error_page(user, "New Poll", "At least one date is required.", f"{P}/new")

    poll = create_poll(user["uid"], title, description, mode, timezone, slots)
    return RedirectResponse(f"{P}/polls/{poll['id']}", status_code=302)


@router.get("/polls/{poll_id}")
def view_poll(poll_id: str, request: Request):
    user = get_user(request)
    if not user:
        return _login_or_401(f"{P}/polls/{poll_id}")

    poll = get_poll(poll_id)
    if not poll:
        return _error_page(user, "Poll not found", "", f"{P}/", status_code=404)

    # Mark poll notifications as read
    notifs = get_notifications(user["uid"], unread_only=True)
    for n in notifs:
        if n["poll_id"] == poll_id:
            mark_notification_read(n["id"])

    responses = get_responses(poll_id)
    slots = poll["slots"]
    invites = get_invites(poll_id)
    total, pending_n = expected_counts(invites, responses)
    share_url = f"{get_base_url(request)}{P}/p/{poll['public_token']}"

    decided_slot = decided_slot_of(poll)
    decided_label = format_slot(decided_slot, poll["mode"]) if decided_slot else None
    is_owner = poll["creator_id"] == user["uid"]
    decidable = is_owner and poll["status"] == "open"

    is_ts = bool(poll["mode"] == "time_slot" and slots and slots[0].get("start_time"))
    ctx = {"is_ts": is_ts}
    if is_ts:
        ctx["ts_payload"] = timeslot_payload(slots, responses, max(total, 1),
                                             tz=poll.get("timezone") or "Europe/Zurich")
        ctx["ts_payload"]["decidable"] = decidable
    else:
        ctx["counts"] = slot_counts(slots, responses)
        ctx["gaps"] = slot_gaps(slots)

    def _part_payload(rows, user):
        return {
            "open": poll["status"] == "open",
            "csrf": make_csrf(user["uid"]),
            "update_url": f"{P}/polls/{poll_id}/participants/update",
            "invite_url": f"{P}/polls/{poll_id}/invite",
            "remove_url": f"{P}/polls/{poll_id}/participants/remove",
            "rows": [{
                "kind": "invite" if r["invite_id"] else "response",
                "ref": r["invite_id"] or r["response_id"],
                "name": r["name"] or "",
                "email": r["email"],
                "optional": not r["required"],
                "via_link": not r["invited"],
                "state": r["state"],
                "last_contact": (f"{r['last_contact']['kind']} · {str(r['last_contact']['sent_at'])[:16]}"
                                 if r["last_contact"] else ""),
                "contacts_n": len(r["contacts"]),
                "trail": "\n".join(f"{c['kind']} {str(c['sent_at'])[:16]}" for c in r["contacts"]),
            } for r in rows],
        }

    participants = (participant_states(poll, responses, invites, get_contact_log(poll_id))
                    if is_owner else [])

    return render(env, "poll.html", user=user, title=poll["title"],
                  poll=poll, responses=responses, invites=invites,
                  part_payload=_part_payload(participants, user),
                  participants=participants,
                  total=total, pending_n=pending_n, share_url=share_url,
                  decided_label=decided_label, **_nav_ctx(user),
                  is_owner=is_owner, decidable=decidable,
                  recipients_n=len(recipient_emails(poll_id)) if decided_label else 0,
                  msg_text=_msg_text(request.query_params), **ctx)


@router.post("/notifications/read-all")
def notifications_read_all(request: Request, form=Depends(form_data)):
    user = get_user(request)
    if not user:
        raise HTTPException(401)
    require_csrf(user, form)
    mark_all_notifications_read(user["uid"])
    return RedirectResponse(request.headers.get("referer") or f"{P}/", status_code=302)


@router.post("/polls/{poll_id}/close")
def close_poll(poll_id: str, request: Request, form=Depends(form_data)):
    _owner_action(request, form, poll_id)
    update_poll(poll_id, status="closed")
    return RedirectResponse(f"{P}/polls/{poll_id}?msg=closed", status_code=302)


@router.post("/polls/{poll_id}/reopen")
def reopen_poll(poll_id: str, request: Request, form=Depends(form_data)):
    _owner_action(request, form, poll_id)
    update_poll(poll_id, status="open", decided_slot_id=None)
    return RedirectResponse(f"{P}/polls/{poll_id}?msg=reopened", status_code=302)


@router.post("/polls/{poll_id}/decide")
def decide_poll(poll_id: str, request: Request, form=Depends(form_data)):
    _user, poll = _owner_action(request, form, poll_id)
    slot_id = form.get("slot_id")
    if not slot_id:
        raise HTTPException(400, "slot_id required")
    if slot_id not in {s["id"] for s in poll["slots"]}:
        raise HTTPException(400, "slot_id does not belong to this poll")
    update_poll(poll_id, status="decided", decided_slot_id=slot_id)
    return RedirectResponse(f"{P}/polls/{poll_id}?msg=decided", status_code=302)


@router.get("/polls/{poll_id}/edit")
def edit_poll_page(poll_id: str, request: Request):
    user = get_user(request)
    if not user:
        return _login_or_401(f"{P}/polls/{poll_id}/edit")
    poll = get_poll(poll_id)
    if not poll:
        return _error_page(user, "Poll not found", "", f"{P}/", status_code=404)
    if poll["creator_id"] != user["uid"]:
        return _error_page(user, "Not allowed", "Only the poll owner can edit it.",
                           f"{P}/polls/{poll_id}", status_code=403)
    existing_dates = sorted({str(s["date"]) for s in poll["slots"]})
    times = sorted({(fmt_time(s["start_time"]), fmt_time(s["end_time"]))
                    for s in poll["slots"] if s.get("start_time")})
    return render(env, "edit_poll.html", user=user, title=f"Edit: {poll['title']}",
                  poll=poll, existing_dates=existing_dates, times=times,
                  timezones=TIMEZONES, **_nav_ctx(user))


@router.post("/polls/{poll_id}/edit")
def edit_poll_submit(poll_id: str, request: Request, form=Depends(form_data)):
    user, poll = _owner_action(request, form, poll_id)

    title = form.get("title", "").strip()
    if not title:
        return _error_page(user, "Edit Poll", "Title is required.",
                           f"{P}/polls/{poll_id}/edit")
    timezone = form.get("timezone", "Europe/Zurich").strip()
    if not _valid_timezone(timezone):
        return _error_page(user, "Edit Poll", "Unknown timezone.",
                           f"{P}/polls/{poll_id}/edit")
    update_poll(poll_id, title=title,
                description=form.get("description", "").strip() or None,
                timezone=timezone)

    # Additive date edit: new dates get slots, existing slots (and their
    # responses) are untouched.
    slots = expand_new_dates(poll, form.getlist("dates"))
    if slots:
        add_slots(poll_id, slots)

        if form.get("notify"):
            # Refetch so the nudge engine sees the just-added slots, then let
            # it work out who actually needs mail (idempotent, state-driven).
            counts = nudge_participants(request, get_poll(poll_id), user)
            if counts["invited"] or counts["updated"]:
                return RedirectResponse(
                    f"{P}/polls/{poll_id}?msg=nudged&inv={counts['invited']}&upd={counts['updated']}",
                    status_code=302)

    return RedirectResponse(f"{P}/polls/{poll_id}?msg=saved", status_code=302)


NUDGE_COOLDOWN = timedelta(hours=24)


def nudge_participants(request: Request, poll: dict, user: dict,  # noqa: C901 — a state machine: per-participant timestamp gating is clearer flat than split
                       only_emails: set[str] | None = None, force: bool = False) -> dict:
    """State-driven, idempotent reminders — safe to trigger repeatedly.

    Per participant, derived purely from timestamps:
    - invitee without a response -> invite reminder, at most once per
      NUDGE_COOLDOWN (so a later click can re-remind, but not spam)
    - participant whose response predates the newest slots -> "new dates
      added" notice, at most once per slot addition (notified_at >= newest
      slot blocks repeats until more dates appear)
    - everyone else -> skipped

    only_emails restricts to those addresses; force is operator intent
    ("email exactly these people now"): it bypasses cooldown/already-told
    gating, and up-to-date participants get a plain reminder.
    Every send lands in the contact audit log.
    """
    base = get_base_url(request)
    sender, reply = user.get("name", "Someone"), user.get("email")
    now = db_now()
    responses = get_responses(poll["id"])
    invites = get_invites(poll["id"])
    slot_times = [s["created_at"] for s in poll["slots"] if s.get("created_at")]
    latest_slot_at = max(slot_times, default=None)
    by_invite = {r["invite_id"]: r for r in responses if r.get("invite_id")}
    by_email = {(r.get("respondent_email") or "").lower(): r
                for r in responses if r.get("respondent_email")}
    counts = {"invited": 0, "updated": 0, "skipped": 0}

    def targeted(email: str) -> bool:
        return only_emails is None or email.lower() in only_emails

    def needs_update(resp, notified_at) -> bool:
        if not latest_slot_at or not resp.get("updated_at") or resp["updated_at"] >= latest_slot_at:
            return False
        return force or not (notified_at and notified_at >= latest_slot_at)

    def n_new_for(resp) -> int:
        return sum(1 for t in slot_times if t > resp["updated_at"])

    def send_reminder(email, url, invite_id=None):
        if send_invite_email(email, poll["title"], url, sender, reply_to=reply, reminder=True):
            log_contact(poll["id"], email, "reminder", invite_id)
            counts["invited"] += 1
            return True
        return False

    def send_update(email, url, resp, invite_id=None):
        if send_update_emails([(email, url)], poll["title"], sender,
                              reply_to=reply, n_dates=n_new_for(resp)):
            log_contact(poll["id"], email, "update", invite_id)
            counts["updated"] += 1
            return True
        return False

    for inv in invites:
        if not targeted(inv["email"]):
            continue
        url = f"{base}{P}/p/i/{inv['token']}"
        resp = by_invite.get(inv["id"]) or by_email.get(inv["email"].lower())
        if resp is None:
            in_cooldown = inv.get("notified_at") and now - inv["notified_at"] < NUDGE_COOLDOWN
            if in_cooldown and not force:
                counts["skipped"] += 1
                continue
            if send_reminder(inv["email"], url, inv["id"]):
                mark_invite_notified(inv["id"])
        elif needs_update(resp, inv.get("notified_at")):
            if send_update(inv["email"], url, resp, inv["id"]):
                mark_invite_notified(inv["id"])
        elif force:
            # explicitly selected but up to date: plain reminder
            send_reminder(inv["email"], url, inv["id"])
        else:
            counts["skipped"] += 1

    invite_emails = {i["email"].lower() for i in invites}
    public_url = f"{base}{P}/p/{poll['public_token']}"
    for resp in responses:
        email = (resp.get("respondent_email") or "").lower()
        if not email or email in invite_emails or not targeted(email):
            continue
        if needs_update(resp, resp.get("notified_at")):
            if send_update(email, public_url, resp):
                mark_response_notified(resp["id"])
        elif force:
            send_reminder(email, public_url)
        else:
            counts["skipped"] += 1
    return counts


@router.post("/polls/{poll_id}/remind-selected")
def remind_selected(poll_id: str, request: Request, form=Depends(form_data)):
    """Operator-picked addresses: bypasses idempotency gating (still logged)."""
    user, poll = _owner_action(request, form, poll_id)
    if poll["status"] != "open":
        raise HTTPException(400, "Poll is not open")
    emails = {e.strip().lower() for e in form.getlist("emails") if e.strip()}
    if not emails:
        return RedirectResponse(f"{P}/polls/{poll_id}?msg=nonudge", status_code=302)
    counts = nudge_participants(request, poll, user, only_emails=emails, force=True)
    if not (counts["invited"] or counts["updated"]):
        return RedirectResponse(f"{P}/polls/{poll_id}?msg=mailfail", status_code=302)
    return RedirectResponse(
        f"{P}/polls/{poll_id}?msg=nudged&inv={counts['invited']}&upd={counts['updated']}",
        status_code=302)


@router.post("/polls/{poll_id}/remind")
def remind_participants(poll_id: str, request: Request, form=Depends(form_data)):
    user, poll = _owner_action(request, form, poll_id)
    if poll["status"] != "open":
        raise HTTPException(400, "Poll is not open")
    counts = nudge_participants(request, poll, user)
    if not (counts["invited"] or counts["updated"]):
        return RedirectResponse(f"{P}/polls/{poll_id}?msg=nonudge", status_code=302)
    return RedirectResponse(
        f"{P}/polls/{poll_id}?msg=nudged&inv={counts['invited']}&upd={counts['updated']}",
        status_code=302)


@router.get("/polls/{poll_id}/event.ics")
def poll_ics(poll_id: str, request: Request):
    user = get_user(request)
    if not user:
        return _login_or_401(f"{P}/polls/{poll_id}")
    poll = get_poll(poll_id)
    if not poll:
        raise HTTPException(404)
    return ics_response(poll, request)


@router.post("/polls/{poll_id}/email-decision")
def email_decision(poll_id: str, request: Request, form=Depends(form_data)):
    user, poll = _owner_action(request, form, poll_id)
    slot = decided_slot_of(poll)
    if not slot:
        raise HTTPException(400, "Poll has no decided date yet")

    poll_url = f"{get_base_url(request)}{P}/p/{poll['public_token']}"
    sent = send_decision_email(
        recipient_emails(poll_id),
        poll["title"],
        format_slot(slot, poll["mode"]),
        poll_url,
        build_ics(poll, slot, poll_url),
        user.get("name", "The organizer"),
        note=form.get("note", "").strip(),
        reply_to=user.get("email"),
    )
    for email in sent:
        log_contact(poll_id, email, "decision")
    if not sent:
        return RedirectResponse(f"{P}/polls/{poll_id}?msg=mailfail", status_code=302)
    return RedirectResponse(f"{P}/polls/{poll_id}?msg=emailed&n={len(sent)}", status_code=302)


@router.post("/polls/{poll_id}/invite")
def invite_submit(poll_id: str, request: Request, form=Depends(form_data)):
    user, poll = _owner_action(request, form, poll_id)
    email = valid_email(form.get("email", ""))
    if not email:
        raise HTTPException(400, "Not a valid email address")
    if any(i["email"].lower() == email.lower() for i in get_invites(poll_id)):
        return RedirectResponse(f"{P}/polls/{poll_id}?msg=duplicate", status_code=302)
    # add-only: the participants table sends the actual mail (Email selected /
    # smart reminders) — keeps adding cheap and sending deliberate
    create_invite(poll_id, email, required=not form.get("optional"),
                  name=form.get("name", "").strip() or None)
    return RedirectResponse(f"{P}/polls/{poll_id}?msg=invited", status_code=302)


@router.post("/polls/{poll_id}/participants/update")
def update_participant(poll_id: str, request: Request, form=Depends(form_data)):
    """Inline row edit: name/email for both kinds, required only for invites."""
    _user, _poll = _owner_action(request, form, poll_id)
    kind, ref = form.get("kind", ""), form.get("ref", "")
    name = form.get("name", "").strip()
    email = valid_email(form.get("email", "")) if form.get("email") else None
    if form.get("email") and not email:
        raise HTTPException(400, "Not a valid email address")
    if kind == "invite" and ref:
        update_invite(ref, name=name, email=email,
                      required=not form.get("optional"))
    elif kind == "response" and ref:
        update_response_contact(ref, name=name or None, email=email,
                                required=not form.get("optional"))
    else:
        raise HTTPException(400, "Bad participant reference")
    return RedirectResponse(f"{P}/polls/{poll_id}?msg=updated", status_code=302)


@router.post("/polls/{poll_id}/participants/remove")
def remove_participant(poll_id: str, request: Request, form=Depends(form_data)):
    _user, _poll = _owner_action(request, form, poll_id)
    kind, ref = form.get("kind", ""), form.get("ref", "")
    if kind == "invite" and ref:
        # an invite's linked response (if any) goes too — the person was uninvited
        for r in get_responses(poll_id):
            if r.get("invite_id") == ref:
                delete_response(r["id"])
        delete_invite(ref)
    elif kind == "response" and ref:
        delete_response(ref)
    else:
        raise HTTPException(400, "Bad participant reference")
    return RedirectResponse(f"{P}/polls/{poll_id}?msg=removed", status_code=302)
