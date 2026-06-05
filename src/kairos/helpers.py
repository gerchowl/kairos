"""Scheduler view helpers — pure data computation for templates and grid JS.

No markup lives here: HTML belongs in templates/, dynamic painting in
static/*.js (which reads the JSON payloads built below).
"""

from datetime import datetime, timedelta
from pathlib import Path

from kairos.templating import create_env

env = create_env(Path(__file__).parent / "templates")


# -- Time formatting --

def fmt_time(t) -> str:
    """Format a TIME column value (timedelta or str) as zero-padded HH:MM."""
    if hasattr(t, 'total_seconds'):
        total = int(t.total_seconds())
        h, m = divmod(total // 60, 60)
        return f"{h:02d}:{m:02d}"
    s = str(t)
    parts = s.split(':')
    if len(parts) >= 2:
        return f"{int(parts[0]):02d}:{int(parts[1]):02d}"
    return s


def format_slot(slot: dict, mode: str) -> str:
    """Format a slot for display: date only or date + time range."""
    date = str(slot["date"])
    if mode == "time_slot" and slot.get("start_time") and slot.get("end_time"):
        return f"{date} {fmt_time(slot['start_time'])}–{fmt_time(slot['end_time'])}"
    return date


env.globals["format_slot"] = format_slot


# -- Heatmap computation --

def compute_heatmap(slots: list[dict], responses: list[dict], total_expected: int) -> dict:
    """Compute per-slot heatmap data: intensity, count text, tooltip.

    Returns {slot_id: {"alpha", "count", "tip"}}. Consumed by grid.js, which
    derives the actual colors from the active theme's CSS custom properties
    (--color-yes / --sched-heat-base) so light and dark both work.
    """
    heatmap = {}
    for s in slots:
        sid = s["id"]
        yes_n = sum(1 for r in responses if r["slot_availabilities"].get(sid) == "yes")
        maybe_n = sum(1 for r in responses if r["slot_availabilities"].get(sid) == "maybe")
        ratio = yes_n / total_expected if total_expected else 0
        maybe_ratio = maybe_n / total_expected if total_expected else 0
        alpha = min(ratio + maybe_ratio * 0.3, 1.0) if yes_n + maybe_n else 0.0
        count_text = ""
        if yes_n or maybe_n:
            parts = []
            if yes_n:
                parts.append(str(yes_n))
            if maybe_n:
                parts.append(f"?{maybe_n}")
            count_text = " ".join(parts)
        names_yes = [r["respondent_name"] for r in responses if r["slot_availabilities"].get(sid) == "yes"]
        names_maybe = [r["respondent_name"] for r in responses if r["slot_availabilities"].get(sid) == "maybe"]
        tip_parts = []
        if names_yes:
            tip_parts.append("Yes: " + ", ".join(names_yes))
        if names_maybe:
            tip_parts.append("Maybe: " + ", ".join(names_maybe))
        heatmap[sid] = {"alpha": round(alpha, 3), "count": count_text, "tip": " | ".join(tip_parts)}
    return heatmap


# -- Summary counts --

def slot_counts(slots: list[dict], responses: list[dict]) -> list[dict]:
    """Per-slot yes/maybe/no counts for the summary bar row."""
    counts = []
    for s in slots:
        avs = [r["slot_availabilities"].get(s["id"]) for r in responses]
        counts.append({
            "yes": sum(1 for a in avs if a == "yes"),
            "maybe": sum(1 for a in avs if a == "maybe"),
            "no": sum(1 for a in avs if a == "no"),
        })
    return counts


def expected_counts(invites: list[dict], responses: list[dict]) -> tuple[int, int]:
    """(total_expected, pending_n) given invites and responses so far."""
    pending_n = sum(1 for inv in invites if not inv["responded"]) if invites else 0
    total = max(len(invites), len(responses)) if invites else len(responses)
    return total, pending_n


# -- Date gaps (visual separator after non-consecutive day columns) --

def date_gaps(dates: list[str]) -> list[int]:
    """Column indices after which dates aren't consecutive."""
    objs = [datetime.strptime(d, "%Y-%m-%d") for d in dates]
    return [i for i in range(len(objs) - 1) if (objs[i + 1] - objs[i]).days > 1]


def slot_gaps(slots: list[dict]) -> list[int]:
    """date_gaps over a poll's (date-ordered) slots — for the full-day grid."""
    return date_gaps([str(s["date"]) for s in slots])


# -- Time-slot grid payload (consumed by grid.js initTsGrid) --

def timeslot_payload(slots: list[dict], responses: list[dict],
                     total_expected: int, interactive: bool = False,
                     tz: str = "Europe/Zurich") -> dict:
    """Data for the when2meet-style grid: dates=columns, times=rows, heatmap.

    Each grid entry carries the slot's UTC epoch so grid.js can show the
    viewer's local time when their browser timezone differs from the poll's.
    """
    from zoneinfo import ZoneInfo
    try:
        tzinfo = ZoneInfo(tz)
    except Exception:
        tzinfo = ZoneInfo("Europe/Zurich")

    dates = sorted({str(s["date"]) for s in slots})
    times = sorted({(fmt_time(s["start_time"]), fmt_time(s["end_time"])) for s in slots})
    slot_map = {(str(s["date"]), fmt_time(s["start_time"])): s for s in slots}
    date_objs = [datetime.strptime(d, "%Y-%m-%d") for d in dates]
    gaps = date_gaps(dates)

    grid = []
    for ri, (start_t, _end_t) in enumerate(times):
        for ci, d in enumerate(dates):
            slot = slot_map.get((d, start_t))
            if slot:
                h, m = int(start_t[:2]), int(start_t[3:5])
                local = datetime.strptime(d, "%Y-%m-%d").replace(hour=h, minute=m, tzinfo=tzinfo)
                grid.append({"id": slot["id"], "row": ri, "col": ci,
                             "epoch": int(local.timestamp())})

    return {
        "tz": tz,
        "grid": grid,
        "dates": [{"date": d, "label": date_objs[i].strftime("%b %d"), "day": date_objs[i].strftime("%a")}
                  for i, d in enumerate(dates)],
        "times": [t[0][:5] for t in times],
        "heatmap": compute_heatmap(slots, responses, total_expected),
        "gaps": gaps,
        # Row index i gets a gap below when times aren't back-to-back
        "time_gaps": [i for i in range(len(times) - 1) if times[i][1] != times[i + 1][0]],
        "interactive": interactive,
    }


# -- Full-day response calendar (rows rendered in template, painted by grid.js) --

def fullday_weeks(slots: list[dict]) -> list[dict]:
    """Calendar weeks (Mon-aligned) spanning the poll's dates."""
    slot_dates = {str(s["date"]): s["id"] for s in slots}
    all_dates = sorted(slot_dates)
    first = datetime.strptime(all_dates[0], "%Y-%m-%d")
    last = datetime.strptime(all_dates[-1], "%Y-%m-%d")
    week_start = first - timedelta(days=first.weekday())
    week_end = last + timedelta(days=6 - last.weekday())

    weeks = []
    d = week_start
    while d <= week_end:
        days = []
        for i in range(7):
            day = d + timedelta(days=i)
            ds = day.strftime("%Y-%m-%d")
            days.append({
                "date": ds,
                "day": day.day,
                "month": day.month,
                "slot_id": slot_dates.get(ds),
                "is_slot": ds in slot_dates,
            })
        weeks.append({"num": d.isocalendar()[1], "days": days})
        d += timedelta(days=7)
    return weeks


def fullday_grid_data(weeks: list[dict]) -> list[dict]:
    """Slot grid positions for grid.js: [{id, row, col}]."""
    grid = []
    for ri, week in enumerate(weeks):
        for ci, day in enumerate(week["days"]):
            if day["is_slot"]:
                grid.append({"id": day["slot_id"], "row": ri, "col": ci})
    return grid


MONTH_NAMES = ['', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
               'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
env.globals["MONTH_NAMES"] = MONTH_NAMES


# -- Timezone choices (proper IANA names, no legacy aliases) --

def _timezones() -> list[str]:
    from zoneinfo import available_timezones
    prefixes = ("Africa/", "America/", "Asia/", "Atlantic/", "Australia/",
                "Europe/", "Indian/", "Pacific/")
    return sorted(tz for tz in available_timezones()
                  if tz.startswith(prefixes) or tz == "UTC")


TIMEZONES = _timezones()


# -- Participant states (the granular per-person view of the nudge engine) --

def participant_states(poll: dict, responses: list[dict], invites: list[dict],
                       contact_log: list[dict]) -> list[dict]:
    """Per-participant row for the owner's panel: invitees + walk-in
    respondents with an email, each with state and contact trail.

    state: pending (no response) | stale (responded before the newest slots)
           | current (up to date)
    """
    slot_times = [s["created_at"] for s in poll["slots"] if s.get("created_at")]
    latest_slot_at = max(slot_times, default=None)
    by_invite = {r["invite_id"]: r for r in responses if r.get("invite_id")}
    by_email = {(r.get("respondent_email") or "").lower(): r
                for r in responses if r.get("respondent_email")}
    log_by_email: dict[str, list[dict]] = {}
    for entry in contact_log:
        log_by_email.setdefault(entry["email"], []).append(entry)

    def state_of(resp) -> str:
        if resp is None:
            return "pending"
        if latest_slot_at and resp.get("updated_at") and resp["updated_at"] < latest_slot_at:
            return "stale"
        return "current"

    def row(email, invite, resp):
        contacts = log_by_email.get(email.lower(), [])
        return {
            "email": email,
            "invite_id": invite["id"] if invite else None,
            "response_id": (resp or {}).get("id"),
            "required": (invite.get("required", True) if invite
                         else bool((resp or {}).get("required", True))),
            "invited": invite is not None,
            "name": (invite or {}).get("name") or (resp or {}).get("respondent_name"),
            "state": state_of(resp),
            "responded_at": (resp or {}).get("updated_at"),
            "last_contact": contacts[0] if contacts else None,
            "contacts": contacts,
        }

    rows = []
    seen = set()
    for inv in invites:
        resp = by_invite.get(inv["id"]) or by_email.get(inv["email"].lower())
        rows.append(row(inv["email"], inv, resp))
        seen.add(inv["email"].lower())
    for resp in responses:
        email = (resp.get("respondent_email") or "").lower()
        if email and email not in seen:
            rows.append(row(resp["respondent_email"], None, resp))
            seen.add(email)
    return rows


# -- Convergence: how close is an open poll to a workable date? --

def convergence(poll: dict, responses: list[dict], invites: list[dict]) -> dict:  # noqa: C901 — one state machine, clearer flat
    """Single source of truth for poll status — feeds the dashboard dot AND
    the poll page's status strip, including the presentation payload.

    States (open polls; required = required invitees + via-link respondents
    not marked optional):
      collecting — required input still missing (or no responses at all)
      ready      — some slot works (yes) for everyone -> decide!
      partial    — some slot works for all REQUIRED participants only
                   (never reported when there is no required set — a
                   "partial of nobody" is incoherent; it falls to blocked)
      blocked    — no slot works even for the required set; no_dates=True
                   when the poll has no slots at all
    Extra payload: best_slot_id (most yes, then earliest), excluded (names
    dropped by deciding the best slot in partial), blockers (who we wait
    on), all_optional, responses, pending_required.
    Closed/decided polls pass through as their status.
    """
    if poll["status"] != "open":
        return {"state": poll["status"]}

    by_invite = {r["invite_id"]: r for r in responses if r.get("invite_id")}
    by_email = {(r.get("respondent_email") or "").lower(): r
                for r in responses if r.get("respondent_email")}

    def resp_of(inv):
        return by_invite.get(inv["id"]) or by_email.get(inv["email"].lower())

    required_inv = [i for i in invites if i.get("required", True)]
    pending_req = [i for i in required_inv if resp_of(i) is None]
    required_resps = [r for r in (resp_of(i) for i in required_inv) if r is not None]

    # via-link respondents (no invite) count as required unless the owner
    # marked them optional — being uninvited is provenance, not importance
    invite_emails = {i["email"].lower() for i in invites}
    walkins = [r for r in responses
               if not r.get("invite_id")
               and (r.get("respondent_email") or "").lower() not in invite_emails]
    required_resps += [r for r in walkins if r.get("required", True)]

    base = {"responses": len(responses), "pending_required": len(pending_req),
            "blockers": [i.get("name") or i["email"] for i in pending_req],
            "all_optional": not required_inv and not any(
                r.get("required", True) for r in walkins)}

    slots = poll.get("slots")  # dashboard rows don't carry slots — optional
    if slots is not None and not slots:
        return {"state": "blocked", "no_dates": True, **base}
    if not responses or pending_req:
        return {"state": "collecting", **base}

    def works_for(resps, slot_id):
        return all(r["slot_availabilities"].get(slot_id) == "yes" for r in resps)

    def yes_count(slot_id):
        return sum(1 for r in responses
                   if r["slot_availabilities"].get(slot_id) == "yes")

    slot_order = {sl["id"]: i for i, sl in enumerate(slots or [])}

    def best(slot_id_list):
        # most yes votes first, then earliest in the poll's slot order
        return min(slot_id_list,
                   key=lambda sid: (-yes_count(sid), slot_order.get(sid, 1 << 30)))

    slot_ids = {sid for r in responses for sid in r["slot_availabilities"]}
    all_ok = [sid for sid in slot_ids if works_for(responses, sid)]
    if all_ok:
        return {"state": "ready", "slots": len(all_ok),
                "best_slot_id": best(all_ok), **base}
    if required_resps:  # a required consensus only means something if it exists
        req_ok = [sid for sid in slot_ids if works_for(required_resps, sid)]
        if req_ok:
            bsid = best(req_ok)
            excluded = [r.get("respondent_name") or r.get("respondent_email") or "?"
                        for r in responses
                        if r["slot_availabilities"].get(bsid) != "yes"]
            return {"state": "partial", "slots": len(req_ok),
                    "best_slot_id": bsid, "excluded": excluded, **base}
    return {"state": "blocked", **base}
