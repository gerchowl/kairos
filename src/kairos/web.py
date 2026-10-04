from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from kairos import capability, settings
from kairos.auth import can_manage, get_base_url, get_user, require_manage
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
    resolve_short_link,
    update_invite,
    update_poll,
    update_response_contact,
)
from kairos.dbconn import db_now
from kairos.email_service import (
    send_decision_email,
    send_invite_email,
    send_update_emails,
    sender_refusal,
    webcal_from,
)
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
from kairos.ratelimit import rate_limit
from kairos.scoping import charge_poll_recipients
from kairos.templating import render

P = settings.PREFIX
router = APIRouter(prefix=P) if P else APIRouter()


def _login_or_401(next_path: str):
    """Owner pages: redirect to the deployment's sign-in page, or explain."""
    # ---- issue #30, KAIROS_AUTH=capability --------------------------------
    # There is no sign-in in this mode and none is coming: the manage link *is*
    # the credential. Redirecting to a proxy login page that does not exist, or
    # telling someone to sign in when nobody can, is the one answer this mode
    # cannot give. The /manage page carries the "email me a new link" box.
    if capability.enabled():
        return render(env, "message.html", status_code=401, title="Manage link required",
                      heading="This page needs a manage link", error=True, user=None,
                      detail=f"This deployment manages polls by emailed link, with no "
                             f"accounts. Open the link we sent you, or request a new "
                             f"one at {P}/manage.")
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
    # Obligation M1: a refused sender is a different problem from an unconfigured
    # one, and telling an operator their SMTP is missing when it is set correctly
    # sends them to the wrong knob. Deliberately carries no addresses: in a hosted
    # deployment the person reading this is a poll owner, not the operator. The
    # specific reason is already in the server log at ERROR.
    "mailblocked": "Email not sent — this deployment’s outbound mail is blocked by "
                    "its mail-identity policy (the sending address is not authorised for "
                    "this domain). See the server log for the reason.",
}


def _mail_failure_msg() -> str:
    """Which flash key explains a send that produced nothing.

    A refusal takes precedence over mailfail: if the M1 gate is blocking, then SMTP being
    configured or not is beside the point, and mailfail would name the wrong cause. The
    refusal is a process-wide condition, so consulting it here cannot mislead when the
    real reason was an empty recipient list.
    """
    return "mailblocked" if sender_refusal() else "mailfail"


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


# The slot-step bounds for `time_slot` mode, and the one place they are enforced.
#
# `increment` is a form field and this loop is a `while`, which is the whole
# problem: `while t + timedelta(minutes=increment) <= t_end` with `increment == 0`
# never advances `t`, so it appends a slot forever. In owner modes that is one
# authenticated user's own request; since #30 this form is also the *anonymous*
# accountless creation path, so `increment=0` (or `-5`) is a remote
# unauthenticated OOM — measured against a real uvicorn, one such POST took the
# process from 59 MB to 2.1 GB without answering, and anyio's 40-thread default
# meant ~40 of them were enough to take the deployment down. A non-numeric value
# was a plain `ValueError` → 500 on the same line.
#
# So the bound is *here*, before the loop, not in a size check after it: the cap in
# `capability.MAX_SLOTS_PER_ACCOUNTLESS_POLL` refuses a poll that is too big, but a
# check that runs once the list exists cannot bound what building the list costs.
# These two numbers make one loop iteration per minute of the window at worst, so a
# single date is bounded by the day — 1440 iterations, 1440 slots.
#
# **Per date is not enough, and that was the second version of this bug.** The grid
# is `dates × per-date iterations`, `dates` is an uncapped repeated field, and
# Starlette's `max_fields` ceiling caps *fields*, not slots. So one 17 KB body with
# 992 dates and a one-minute increment is 1.4 million slot dicts from a request with
# no credential. Measured on the pre-fix tree at sixteen concurrent: **+2.2 GB**,
# truncated only by the 2.5 GB address-space cap I put on that server to spare the
# machine (~6 GB uncapped, per the review that found it), every request returning 400
# "too large" afterwards and `/health` answering 200 throughout. The refusal arrived
# after the memory was spent. Hence the product is checked before the loop, below,
# from the same arithmetic the loop performs. After the fix, the same burst: **+4 MB**.
MIN_INCREMENT_MINUTES = 1
MAX_INCREMENT_MINUTES = 1440


def _bounded_int(raw: str, low: int, high: int) -> int | None:
    """`raw` as an int inside `low..high`, or None — never an exception.

    One parser for both numeric form fields on this path, because a form field is
    a string typed by a stranger: `int()` on it is a 500 waiting for a value like
    `"1.5"`, and `max(1, int(raw))` is a 500 that a sanitizer makes worse.
    """
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return value if low <= value <= high else None


def _parse_clock(raw: str):
    """A `HH:MM` form field as a datetime, or None.

    `strptime` is the parser; the None is the part that matters. A `start_time_all`
    of `"25:00"` raised out of the route rather than being refused, and since #30
    the route is anonymous, so an unparseable clock was a 500 on it — the same shape
    as the unvalidated `increment` above, on the two lines beside it, and fixed in
    the same place.
    """
    try:
        return datetime.strptime(raw.strip(), "%H:%M")
    except (AttributeError, ValueError):
        return None


def _expand_time_slots(form, dates) -> tuple[list[dict], str | None]:
    """The `time_slot` grid for `dates`, or the sentence that refuses it.

    Its own function so that every bound is visibly attached to the loop it
    protects. That is not tidiness: the loop is a `while` over a form field, the
    route is anonymous since #30, and the two facts together are what made
    `increment=0` an unauthenticated OOM — a check that lives in another function,
    or after the list is built, is not a bound on the loop. The refusals are
    returned rather than rendered so this stays free of auth-mode shape: the caller
    owns `_fail`, which is the one thing that differs between the modes.
    """
    start_all = form.get("start_time_all", "09:00")
    end_all = form.get("end_time_all", "17:00")
    if not start_all or not end_all:
        return [], "Start and end times are required for time slot mode."
    t_start = _parse_clock(start_all)
    t_end = _parse_clock(end_all)
    if t_start is None or t_end is None:
        return [], "Start and end times must be given as HH:MM."
    increment = _bounded_int(form.get("increment", "30"), MIN_INCREMENT_MINUTES, MAX_INCREMENT_MINUTES)
    if increment is None:
        return [], (
            f"Increment must be a whole number of minutes between "
            f"{MIN_INCREMENT_MINUTES} and {MAX_INCREMENT_MINUTES}."
        )

    # **The product, before any of it exists.** Two facts about this loop that are
    # easy to hold one at a time and impossible to hold separately:
    #
    #   * `per_date` is the loop's own arithmetic — `(t_end - t_start) // increment`
    #     is exactly how many whole steps fit, which is how many times the `while`
    #     below runs. No float, no estimate, and no second copy of the rule to drift
    #     out of step with it.
    #   * `n_dates` counts what the loop actually iterates, not what the body
    #     contained: the loop skips empty fields, so counting those would refuse a
    #     submission the loop was going to answer "At least one date is required".
    #
    # So `n_dates * per_date` is the slot count this input produces, and asking
    # `capability` whether that is allowed costs one integer multiplication. That is
    # the entire fix: the grid below is only ever built when its size is already known
    # to be acceptable.
    #
    # Exact for a forward window. For a *reversed* one (`end` before `start`) the
    # floor division of a negative timedelta is negative — `12:00→00:00` at one minute
    # predicts −720 — where the loop builds nothing, so the prediction is below the
    # output rather than equal to it. That direction is the safe one and always is:
    # a negative count is never over the ceiling, so the request is accepted, builds
    # zero slots, and is answered "At least one date is required" by the caller.
    # Checked over all 12.4M reversed (start, end, increment) combinations: the
    # prediction is never above the loop's output.
    n_dates = sum(1 for date in dates if date)
    per_date = (t_end - t_start) // timedelta(minutes=increment)
    refusal = capability.slot_cap_refusal(n_dates * per_date, n_dates)
    if refusal:
        return [], refusal

    slots = []
    for date in dates:
        if not date:
            continue
        t = t_start
        # Bounded twice over now, and the first bound is the load-bearing one:
        # `increment >= 1` means `t` advances every iteration (so the `while`
        # terminates at all), and `n_dates * per_date <= the cap` above means the
        # list cannot exceed what was just checked.
        while t + timedelta(minutes=increment) <= t_end:
            t_next = t + timedelta(minutes=increment)
            slots.append({
                "date": date,
                "start_time": t.strftime("%H:%M"),
                "end_time": t_next.strftime("%H:%M"),
            })
            t = t_next
    return slots, None


def _owner_action(request: Request, form, poll_id: str) -> tuple[dict, dict]:
    """Auth + CSRF + management-authority gate shared by all owner POST actions.

    Three steps in a fixed order -- no identity (401), then CSRF (403), then
    `require_manage` (403) -- which is the order and the status codes of every
    version before #29. Only the ownership test moved: it is now the one shared
    predicate (obligation S6) instead of a copy per route.
    """
    user = get_user(request)
    if not user:
        raise HTTPException(401)
    require_csrf(user, form)
    poll = get_poll(poll_id)
    if not poll:
        raise HTTPException(403, "Not the poll owner")
    return user, require_manage(poll, request, user=user)


def expand_new_dates(poll: dict, dates: list[str], *, cap: int | None = None) -> list[dict]:
    """Slots for genuinely-new dates; time_slot polls reuse the poll's time grid.

    **`cap` is the ceiling on `new_dates × time-pairs`, and it is checked before the
    comprehension rather than after it.** Both factors come from the request or from
    the poll, and the product is what actually lands in the database:

      * `dates` — on the capability console this arrives as ONE comma-separated field
        that `_parse_dates` splits, so Starlette's `max_fields` ceiling never sees the
        dates at all. One ~1 MB field is 95,000 valid dates; the review that found
        this measured a 220 KB body with 20,000 dates against a poll carrying 125
        distinct time pairs — **2,500,000 slot rows, 2,501,000 written, +1.1 GB,
        14 s, status 302**. Not refused, because nothing here looked.
      * `time_pairs` — the poll's *own* grid, which grows by up to one edit's worth
        of slots every time. So even a single new date becomes expensive eventually,
        and only the product says so.

    The owner form and the REST API pass no `cap` and keep their existing behaviour:
    the owner path is bounded by `max_fields` (about 90x lower per request) and the
    API is #51/#63/#64's surface with its own budget. This parameter exists so the
    capability console can ask for the ceiling at its own call site rather than
    having a mode check reach into a shared helper and silently change two other
    surfaces.
    """
    existing = {str(s["date"]) for s in poll["slots"]}
    new_dates = [d for d in dates if d and d not in existing]
    time_pairs = sorted({(fmt_time(s["start_time"]), fmt_time(s["end_time"]))
                         for s in poll["slots"] if s.get("start_time")})
    on_grid = poll["mode"] == "time_slot" and time_pairs
    # Every date yields at least one slot, so this is the minimum the comprehension
    # below can produce and never an over-estimate of it.
    per_date = len(time_pairs) if on_grid else 1
    product = len(new_dates) * per_date
    if cap is not None and product > cap:
        raise HTTPException(
            400,
            # `slot_cap_refusal` words it and knows the mode; the `or` is for a caller
            # that passes a cap outside this mode, where it deliberately has no opinion.
            capability.slot_cap_refusal(product, len(new_dates))
            or f"That edit would add {product:,} slots, over the limit of {cap:,}.",
        )
    if on_grid:
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

@router.get("/v/{code}")
def short_link(code: str):
    """Self-hosted tiny-url: resolve a short code to its target and redirect.
    Keeps capability vote URLs short in plain-text calendar DESCRIPTIONs."""
    target = resolve_short_link(code)
    if not target:
        raise HTTPException(404)
    return RedirectResponse(target, status_code=307)


@router.get("/")
def dashboard(request: Request):
    # ---- issue #30, KAIROS_AUTH=capability --------------------------------
    # No dashboard exists in this mode, deliberately. `list_polls` is keyed on an
    # owner uid, and accountless polls are never listed anywhere (ADR-0009 --
    # `sched_polls.owner_id` is NULL for them and nothing lists by absence), so
    # the front page is the creation form rather than a list of other people's
    # polls. The per-poll dashboard is #32's, alongside accounts and claim.
    if capability.enabled():
        return new_poll_page(request)
    user = get_user(request)
    if not user:
        return _login_or_401(f"{P}/")

    polls = list_polls(user["uid"])
    for poll_row in polls:
        # Fetch invites once and reuse. This called get_invites() twice per poll
        # with identical arguments -- once for convergence, once for invite_count.
        # Measured against real SQLite: the dashboard costs 3N+2 SQL statements
        # for N polls (was 4N+2), see tests/test_dashboard_queries.py.
        #
        # That is a real saving and NOT the fix for hosted. 3N+2 still exhausts
        # the Cloudflare free tier's 50 D1 subrequests per invocation at 16 polls
        # with no responses, and at 8 polls once each poll has any responses,
        # because list_polls() also runs a COUNT(*) per poll. Hosted needs
        # convergence denormalised onto sched_polls (making this 1 query) or the
        # grid loaded per poll as a JS island. Tracked in PLAN.md.
        invites = get_invites(poll_row["id"])
        poll_row["conv"] = convergence(poll_row, get_responses(poll_row["id"]), invites)
        poll_row["invite_count"] = len(invites)

    return render(env, "dashboard.html", user=user, title="Kairos",
                  polls=polls, **_nav_ctx(user))


@router.get("/new")
def new_poll_page(request: Request):
    # ---- issue #30, KAIROS_AUTH=capability --------------------------------
    # The same form, without a user behind it: `new_poll_context` carries the CSRF
    # binding for an anonymous submit and the auth-mode flag that makes the
    # template ask for a creator address.
    if capability.enabled():
        return render(env, "new_poll.html", **capability.new_poll_context())
    user = get_user(request)
    if not user:
        return _login_or_401(f"{P}/new")
    return render(env, "new_poll.html", user=user, title="New Poll",
                  timezones=TIMEZONES, **_nav_ctx(user))


@router.post("/new")
def create_poll_submit(request: Request, form=Depends(form_data),
                       _=Depends(rate_limit("create"))):
    # ---- issue #30, KAIROS_AUTH=capability --------------------------------
    # The same form, the same `create` budget, one difference: there is no identity
    # to authorize, so the credential is minted and *mailed* instead. This is the
    # only unauthenticated poll-creation path in the app, which is why #31's
    # Turnstile check belongs on this branch and nowhere else, and why the branch
    # is kept to the auth head, the refusal renderer and the create tail.
    accountless = capability.enabled()
    user = get_user(request)
    if accountless:
        capability.require_anon_csrf(form)
    else:
        if not user:
            return _login_or_401(f"{P}/new")
        require_csrf(user, form)

    def _fail(detail, heading="New Poll"):
        """A form refusal, in whichever shape this mode has a user for.

        `_error_page` builds the notification navbar from an owner uid, which an
        accountless submission does not have, so the accountless refusal goes
        through the same template without one. The signature mirrors
        `_error_page`'s (heading, detail) so the four call sites read the same as
        the ones they replaced, and the page title stays "New Poll" rather than
        becoming the sentence.
        """
        return (capability.anon_error(heading, detail, back=f"{P}/new") if accountless
                else _error_page(user, heading, detail, f"{P}/new"))

    title = form.get("title", "").strip()
    description = form.get("description", "").strip() or None
    mode = form.get("mode", "full_day")
    timezone = form.get("timezone", "Europe/Zurich").strip()

    if not title:
        return _fail("Title is required.")
    if not _valid_timezone(timezone):
        return _fail("Unknown timezone.")

    dates = form.getlist("dates")

    slots = []
    if mode == "time_slot":
        slots, error = _expand_time_slots(form, dates)
        if error:
            return _fail(error)
    else:
        for date in dates:
            if not date:
                continue
            slots.append({"date": date})

    if not slots:
        return _fail("At least one date is required.")

    # ---- issue #30: the create tail. Everything above is shared; here the modes
    # diverge -- an accountless poll has no owner_id and a per-poll placeholder
    # creator (see capability.anonymous_creator_id for why that is not a
    # migration), and its manage link goes out by mail.
    if accountless:
        return capability.create_accountless_poll(
            request, form, title=title, description=description, mode=mode,
            timezone=timezone, slots=slots)
    # owner_id is the authenticated owner (ADR-0009); in header mode that is the
    # same uid as creator_id, and creator_email stays NULL because only the
    # hosted accountless flow mails a management link (#30).
    poll = create_poll(user["uid"], title, description, mode, timezone, slots,
                       owner_id=user["uid"])
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
    is_owner = can_manage(poll, request, user=user)
    conv = convergence(poll, responses, invites)
    # matrix-click decide is only wired when the strip renders the select
    decidable = is_owner and poll["status"] == "open" and conv["state"] in ("ready", "partial")

    is_ts = bool(poll["mode"] == "time_slot" and slots and slots[0].get("start_time"))
    ctx = {"is_ts": is_ts}
    if is_ts:
        ctx["ts_payload"] = timeslot_payload(slots, responses, max(total, 1),
                                             tz=poll.get("timezone") or "Europe/Zurich")
        ctx["ts_payload"]["decidable"] = decidable
    else:
        ctx["counts"] = slot_counts(slots, responses)
        ctx["gaps"] = slot_gaps(slots)

    def _fmt_day(ts) -> str:
        from datetime import date as _date
        try:
            return _date.fromisoformat(str(ts)[:10]).strftime("%d %b %Y")
        except ValueError:
            return str(ts)[:10]

    def _part_payload(rows, user):
        return {
            "open": poll["status"] == "open",
            "csrf": make_csrf(user["uid"]),
            "update_url": f"{P}/polls/{poll_id}/participants/update",
            "invite_url": f"{P}/polls/{poll_id}/invite",
            "remind_url": f"{P}/polls/{poll_id}/remind",
            "remind_selected_url": f"{P}/polls/{poll_id}/remind-selected",
            "remove_url": f"{P}/polls/{poll_id}/participants/remove",
            "rows": [{
                "kind": "invite" if r["invite_id"] else "response",
                "ref": r["invite_id"] or r["response_id"],
                "name": r["name"] or "",
                "email": r["email"],
                "optional": not r["required"],
                "via_link": not r["invited"],
                "joined": (("\u2709" if r["invited"] else "\U0001f517") + " "
                           + _fmt_day(r["joined_at"])) if r["joined_at"] else "",
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
                  conv={**conv, "stale_n": sum(1 for pp in participants if pp["state"] == "stale")},
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
    if not can_manage(poll, request, user=user):
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


def _nudge_target_count(invites, responses, only_emails) -> int:
    """How many addresses a nudge *aims at*, whether or not it mails them all.

    The upper bound, deliberately: the send loop then skips anyone already
    current, and charging only what goes out would make bypassing the cooldown
    cheaper to abuse than respecting it. An address reachable both as an invitee
    and as a walk-in counts once, because the loop sends it once.
    """
    invite_emails = {i["email"].lower() for i in invites}
    targets = set()
    for inv in invites:
        email = inv["email"].lower()
        if only_emails is None or email in only_emails:
            targets.add(email)
    for resp in responses:
        email = (resp.get("respondent_email") or "").lower()
        if email and email not in invite_emails and (only_emails is None or email in only_emails):
            targets.add(email)
    return len(targets)


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

    Charged against the poll's send budget (issue #51) before anything goes out,
    and against the addresses it *targets* rather than the ones it ends up mailing
    (see `_nudge_target_count`). The charge lives here, once, so the API's
    `nudge` and `add_slots(notify=True)` and the UI's `remind` / `remind-selected`
    all draw on one per-poll allowance -- which is how ADR-0012's parity
    invariant holds: one ceiling, not two kept in step by review.
    """
    base = get_base_url(request)
    sender, reply = user.get("name", "Someone"), user.get("email")
    now = db_now()
    responses = get_responses(poll["id"])
    invites = get_invites(poll["id"])
    charge_poll_recipients(poll["id"], _nudge_target_count(invites, responses, only_emails))
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
        sub = webcal_from(url) if settings.FEED_ENABLED else None
        if send_invite_email(email, poll["title"], url, sender, reply_to=reply,
                             reminder=True, subscribe_url=sub):
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
def remind_selected(poll_id: str, request: Request, form=Depends(form_data),
                    _=Depends(rate_limit("send"))):
    """Operator-picked addresses: bypasses idempotency gating (still logged)."""
    user, poll = _owner_action(request, form, poll_id)
    if poll["status"] != "open":
        raise HTTPException(400, "Poll is not open")
    emails = {e.strip().lower() for e in form.getlist("emails") if e.strip()}
    if not emails:
        return RedirectResponse(f"{P}/polls/{poll_id}?msg=nonudge", status_code=302)
    counts = nudge_participants(request, poll, user, only_emails=emails, force=True)
    if not (counts["invited"] or counts["updated"]):
        return RedirectResponse(f"{P}/polls/{poll_id}?msg={_mail_failure_msg()}",
                                status_code=302)
    return RedirectResponse(
        f"{P}/polls/{poll_id}?msg=nudged&inv={counts['invited']}&upd={counts['updated']}",
        status_code=302)


@router.post("/polls/{poll_id}/remind")
def remind_participants(poll_id: str, request: Request, form=Depends(form_data),
                        _=Depends(rate_limit("send"))):
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
def email_decision(poll_id: str, request: Request, form=Depends(form_data),
                   _=Depends(rate_limit("send"))):
    user, poll = _owner_action(request, form, poll_id)
    slot = decided_slot_of(poll)
    if not slot:
        raise HTTPException(400, "Poll has no decided date yet")

    poll_url = f"{get_base_url(request)}{P}/p/{poll['public_token']}"
    # The same per-poll send budget the API's email-decision charges (issue #51):
    # one allowance for one poll, whichever surface asks for it.
    recipients = recipient_emails(poll_id)
    charge_poll_recipients(poll_id, len(recipients))
    sent = send_decision_email(
        recipients,
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
        return RedirectResponse(f"{P}/polls/{poll_id}?msg={_mail_failure_msg()}",
                                status_code=302)
    return RedirectResponse(f"{P}/polls/{poll_id}?msg=emailed&n={len(sent)}", status_code=302)


@router.post("/polls/{poll_id}/invite")
def invite_submit(poll_id: str, request: Request, form=Depends(form_data),
                  _=Depends(rate_limit("invite"))):
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
