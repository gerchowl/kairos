from fastapi import APIRouter, Depends, HTTPException, Request, Response

from kairos import settings
from kairos.auth import RESPONSE_REF_MAX_AGE, get_user, load_response_ref, sign_response_ref
from kairos.db import (
    add_response,
    find_response_by_email,
    find_response_by_user,
    get_invite_by_token,
    get_invites,
    get_poll,
    get_poll_by_token,
    get_response,
    get_responses,
    make_short_link,
    mark_invite_responded,
    update_response,
)
from kairos.helpers import (
    env,
    expected_counts,
    format_slot,
    fullday_grid_data,
    fullday_weeks,
    slot_counts,
    slot_gaps,
    timeslot_payload,
)
from kairos.http import form_data, valid_email
from kairos.ics import build_feed_ics
from kairos.notifications import notify_all_responded, notify_new_response
from kairos.templating import render
from kairos.web import get_base_url, ics_response

P = settings.PREFIX
router = APIRouter(prefix=f"{P}/p")

RESP_COOKIE_PREFIX = "sched_resp_"


def _not_found(heading: str, detail: str = ""):
    return render(env, "message.html", status_code=404, title="Not Found",
                  heading=heading, detail=detail, error=True, noindex=True)


def _existing_response(request: Request, poll: dict, email: str | None = None) -> tuple[dict | None, dict | None]:
    """Resolve the visitor's prior response: account > email > browser cookie.

    Returns (response, user). The response carries slot_availabilities so the
    grid can be pre-filled and edited on every revisit.
    """
    user = get_user(request)
    if user:
        resp = find_response_by_user(poll["id"], user["uid"])
        if resp:
            return resp, user
    if email:
        resp = find_response_by_email(poll["id"], email)
        if resp:
            return resp, user
    rid = load_response_ref(request.cookies.get(RESP_COOKIE_PREFIX + poll["id"]))
    if rid:
        resp = get_response(rid)
        if resp and resp["poll_id"] == poll["id"]:
            return resp, user
    return None, user


def _render_poll_page(poll: dict, action: str, request: Request,
                      invite: dict | None = None, msg: str = "",
                      existing_override: tuple | None = None):
    responses = get_responses(poll["id"])
    invites = get_invites(poll["id"])
    total, pending_n = expected_counts(invites, responses)
    is_open = poll["status"] == "open"
    slots = poll["slots"]

    if existing_override is not None:
        # Just-saved submit: the cookie isn't on this request yet — use the
        # response we wrote so the page renders in its "Saved" state.
        existing, user = existing_override
    else:
        existing, user = _existing_response(request, poll, invite["email"] if invite else None)
    saved = existing["slot_availabilities"] if existing else None
    prefill_name = ((existing or {}).get("respondent_name")
                    or (invite.get("name") if invite else None)
                    or (user or {}).get("name") or "")
    prefill_email = ((existing or {}).get("respondent_email")
                     or (invite["email"] if invite else None)
                     or (user or {}).get("email") or "")

    decided_label = None
    if poll["status"] == "decided" and poll["decided_slot_id"]:
        decided_slot = next((s for s in slots if s["id"] == poll["decided_slot_id"]), None)
        if decided_slot:
            decided_label = format_slot(decided_slot, poll["mode"])

    is_ts = bool(poll["mode"] == "time_slot" and slots and slots[0].get("start_time"))
    ctx = {"is_ts": is_ts}
    if is_ts:
        ctx["ts_payload"] = timeslot_payload(slots, responses, max(total, 1), interactive=is_open,
                                             tz=poll.get("timezone") or "Europe/Zurich")
        ctx["ts_payload"]["saved"] = saved
    else:
        ctx["counts"] = slot_counts(slots, responses)
        ctx["gaps"] = slot_gaps(slots)
        if is_open:
            weeks = fullday_weeks(slots)
            ctx["weeks"] = weeks
            ctx["fullday_payload"] = {"grid": fullday_grid_data(weeks), "saved": saved}

    return render(env, "public_poll.html", title=poll["title"], poll=poll,
                  responses=responses, total=total, pending_n=pending_n,
                  is_open=is_open, action=action, prefill_email=prefill_email,
                  prefill_name=prefill_name, msg=msg, decided_label=decided_label, **ctx)


def _parse_availabilities(poll: dict, form) -> dict:
    availabilities = {}
    for slot in poll["slots"]:
        av = form.get(f"av_{slot['id']}", "no")
        if av not in ("yes", "maybe", "no"):
            av = "no"
        availabilities[slot["id"]] = av
    return availabilities


def _handle_submit(request: Request, poll: dict, action: str, form, invite: dict | None = None):
    """Shared submit flow: upsert by account/email/cookie, then re-render."""
    if poll["status"] != "open":
        return _render_poll_page(poll, action, request, invite=invite)

    name = form.get("name", "").strip()
    raw_email = form.get("email", "").strip()
    email = (valid_email(raw_email) if raw_email else None) or (invite["email"] if invite else None)
    if raw_email and not valid_email(raw_email):
        return render(env, "message.html", status_code=400, title="Error",
                      heading="Error", detail="That email address doesn't look valid.",
                      error=True, noindex=True, back=action, back_label="Go back")

    if not name:
        return render(env, "message.html", status_code=400, title="Error",
                      heading="Error", detail="Name is required.", error=True,
                      noindex=True, back=action, back_label="Go back")

    availabilities = _parse_availabilities(poll, form)
    existing, user = _existing_response(request, poll, email)

    if existing:
        update_response(existing["id"], name, availabilities,
                        user_id=(user or {}).get("uid"), email=email)
        response_id = existing["id"]
        msg = "Your response has been updated!"
    else:
        resp = add_response(poll["id"], name, email, availabilities,
                            user_id=(user or {}).get("uid"),
                            invite_id=invite["id"] if invite else None)
        response_id = resp["id"]
        if invite:
            mark_invite_responded(invite["id"])
        notify_new_response(poll["id"], name)
        if invite:
            notify_all_responded(poll["id"])
        msg = "Your response has been recorded!"

    saved_resp = {"id": response_id, "poll_id": poll["id"], "respondent_name": name,
                  "respondent_email": email, "user_id": (user or {}).get("uid"),
                  "slot_availabilities": availabilities}
    page = _render_poll_page(poll, action, request, invite=invite, msg=msg,
                             existing_override=(saved_resp, user))
    if not user:
        # Anonymous: remember this response in the browser so revisits can edit it
        page.set_cookie(RESP_COOKIE_PREFIX + poll["id"], sign_response_ref(response_id),
                        max_age=RESPONSE_REF_MAX_AGE, httponly=True, secure=True,
                        samesite="lax", path=f"{P}/p")
    return page


def _feed_response(poll: dict, request: Request, invite_token: str | None = None) -> Response:
    """Read-only candidate-slot feed (.ics) for a still-open poll."""
    responses = get_responses(poll["id"])
    total, _ = expected_counts(get_invites(poll["id"]), responses)
    base = get_base_url(request)
    # Short, self-hosted vote links keep the plain-text DESCRIPTION clean.
    def shorten(path):
        return f"{base}{P}/v/{make_short_link(path)}"
    body = build_feed_ics(poll, poll["slots"], responses,
                          base_url=base, prefix=P, invite_token=invite_token,
                          total_expected=total, shorten=shorten)
    return Response(content=body, media_type="text/calendar",
                    headers={"Content-Disposition": 'inline; filename="kairos-candidates.ics"'})


def _record_single_vote(request: Request, poll: dict, invite: dict, slot_id: str, availability: str):
    """Deep-link vote: upsert just this one slot on the invitee's response,
    leaving any other slot answers untouched."""
    email = invite["email"]
    existing, user = _existing_response(request, poll, email)
    if existing:
        update_response(existing["id"], existing["respondent_name"],
                        {slot_id: availability},
                        user_id=(user or {}).get("uid"), email=email)
    else:
        name = invite.get("name") or email
        add_response(poll["id"], name, email, {slot_id: availability},
                     user_id=(user or {}).get("uid"), invite_id=invite["id"])
        mark_invite_responded(invite["id"])
        notify_new_response(poll["id"], name)
        notify_all_responded(poll["id"])


# -- Public poll routes --

@router.get("/{token}/event.ics")
def public_poll_ics(token: str, request: Request):
    poll = get_poll_by_token(token)
    if not poll:
        raise HTTPException(404)
    # While open, an enabled deployment serves the subscribe-able candidate
    # feed; once decided (or feed disabled) it's the single confirmed event.
    if settings.FEED_ENABLED and poll["status"] == "open":
        return _feed_response(poll, request)
    return ics_response(poll, request)


@router.get("/{token}")
def view_public_poll(token: str, request: Request):
    poll = get_poll_by_token(token)
    if not poll:
        return _not_found("Poll not found", "This link may be invalid or expired.")
    return _render_poll_page(poll, f"{P}/p/{token}", request)


@router.post("/{token}")
def submit_public_response(token: str, request: Request, form=Depends(form_data)):
    poll = get_poll_by_token(token)
    if not poll:
        return _not_found("Poll not found")
    return _handle_submit(request, poll, f"{P}/p/{token}", form)


# -- Invite-based routes --

@router.get("/i/{invite_token}")
def view_invite_poll(invite_token: str, request: Request):
    invite = get_invite_by_token(invite_token)
    if not invite:
        return _not_found("Invalid invite link", "This invite may be invalid or expired.")

    poll = get_poll(invite["poll_id"])
    if not poll:
        return _not_found("Poll not found")

    return _render_poll_page(poll, f"{P}/p/i/{invite_token}", request, invite=invite)


@router.post("/i/{invite_token}")
def submit_invite_response(invite_token: str, request: Request, form=Depends(form_data)):
    invite = get_invite_by_token(invite_token)
    if not invite:
        return _not_found("Invalid invite link")

    poll = get_poll(invite["poll_id"])
    if not poll:
        return _not_found("Poll not found")

    return _handle_submit(request, poll, f"{P}/p/i/{invite_token}", form, invite=invite)


# -- Reverse-calendar feed + deep-link voting (gated on KAIROS_FEED) --

@router.get("/i/{invite_token}/feed.ics")
def invite_feed_ics(invite_token: str, request: Request):
    """Per-invitee candidate feed: every slot carries deep-link vote URLs."""
    if not settings.FEED_ENABLED:
        raise HTTPException(404)
    invite = get_invite_by_token(invite_token)
    if not invite:
        raise HTTPException(404)
    poll = get_poll(invite["poll_id"])
    if not poll:
        raise HTTPException(404)
    return _feed_response(poll, request, invite_token=invite_token)


@router.get("/i/{invite_token}/agent.json")
def invite_agent_json(invite_token: str, request: Request):
    """Agent-native invitee surface: the invite link IS the identity (no API key).
    Returns the options, your current vote, and the one-click vote URLs — so you
    can hand your assistant the invite link and it can RSVP for you."""
    if not settings.FEED_ENABLED:
        raise HTTPException(404)
    invite = get_invite_by_token(invite_token)
    if not invite:
        raise HTTPException(404)
    poll = get_poll(invite["poll_id"])
    if not poll:
        raise HTTPException(404)
    base = get_base_url(request)
    responses = get_responses(poll["id"])
    mine = next((r for r in responses
                 if (r.get("respondent_email") or "").lower() == (invite["email"] or "").lower()), None)
    mine_av = (mine or {}).get("slot_availabilities", {})
    slots = []
    for s in poll["slots"]:
        avs = [r["slot_availabilities"].get(s["id"]) for r in responses]
        vb = f"{base}{P}/p/i/{invite_token}/s/{s['id']}"
        slots.append({
            "id": s["id"], "label": format_slot(s, poll["mode"]),
            "tally": {"yes": avs.count("yes"), "maybe": avs.count("maybe"), "no": avs.count("no")},
            "your_vote": mine_av.get(s["id"]),
            "vote": {"yes": f"{vb}/yes", "maybe": f"{vb}/maybe", "no": f"{vb}/no"},
        })
    return {
        "poll": {"title": poll["title"], "status": poll["status"], "timezone": poll.get("timezone")},
        "you": {"name": invite.get("name"), "email": invite["email"]},
        "slots": slots,
        "subscribe": f"webcal://{request.url.hostname}{P}/p/i/{invite_token}/feed.ics",
        "docs": f"{base}{P}/llms.txt",
        "how_to_vote": "GET any slot's vote URL (yes|maybe|no) to cast/replace your answer. "
                       "No auth needed — this invite link is your identity; keep it private.",
    }


@router.get("/i/{invite_token}/s/{slot_id}/{availability}")
def deep_link_vote(invite_token: str, slot_id: str, availability: str, request: Request):
    """Tapped from a calendar event body: record one slot's answer, then land
    on the poll page — the instant-feedback surface (the feed itself lags)."""
    if not settings.FEED_ENABLED:
        raise HTTPException(404)
    if availability not in ("yes", "maybe", "no"):
        return _not_found("Invalid vote", "Use accept, maybe, or decline.")
    invite = get_invite_by_token(invite_token)
    if not invite:
        return _not_found("Invalid invite link", "This invite may be invalid or expired.")
    poll = get_poll(invite["poll_id"])
    if not poll:
        return _not_found("Poll not found")

    action = f"{P}/p/i/{invite_token}"
    slot = next((s for s in poll["slots"] if s["id"] == slot_id), None)
    if not slot:
        return _not_found("Unknown slot", "That option is no longer part of this poll.")
    if poll["status"] != "open":
        return _render_poll_page(poll, action, request, invite=invite,
                                 msg="This poll is closed — your vote was not changed.")

    _record_single_vote(request, poll, invite, slot_id, availability)
    label = {"yes": "Accepted", "maybe": "Maybe", "no": "Declined"}[availability]
    return _render_poll_page(poll, action, request, invite=invite,
                             msg=f"{label}: {format_slot(slot, poll['mode'])}. Updated tally below.")
