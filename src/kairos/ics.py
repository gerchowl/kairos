"""iCalendar (.ics) generation for decided polls — stdlib only.

One VEVENT for the decided slot: all-day for full_day polls, a concrete
UTC-converted interval (via the poll's IANA timezone) for time_slot polls.
"""

from datetime import date as date_t
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo


def _esc(text: str) -> str:
    """Escape TEXT per RFC 5545 (backslash, semicolon, comma, newline)."""
    return (text.replace("\\", "\\\\").replace(";", "\\;")
            .replace(",", "\\,").replace("\n", "\\n"))


def _fold(line: str) -> str:
    """Fold content lines longer than 75 octets (continuation = space)."""
    out, raw = [], line.encode()
    while len(raw) > 75:
        cut = 75
        while cut > 0 and (raw[cut] & 0xC0) == 0x80:  # don't split UTF-8 sequences
            cut -= 1
        out.append(raw[:cut].decode())
        raw = b" " + raw[cut:]
    out.append(raw.decode())
    return "\r\n".join(out)


def _as_date(d) -> date_t:
    return d if isinstance(d, date_t) else datetime.strptime(str(d), "%Y-%m-%d").date()


def _hm(t) -> tuple[int, int]:
    """Hour/minute from a TIME value (timedelta from MySQL, str from SQLite, or time)."""
    if hasattr(t, "total_seconds"):
        return divmod(int(t.total_seconds()) // 60, 60)
    if isinstance(t, str):
        h, m = t.split(":")[:2]
        return int(h), int(m)
    return t.hour, t.minute


def _utc(d: date_t, t, tz: ZoneInfo) -> str:
    h, m = _hm(t)
    local = datetime(d.year, d.month, d.day, h, m, tzinfo=tz)
    return local.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _dt_lines(poll: dict, slot: dict) -> tuple[str, str]:
    """DTSTART/DTEND content lines for a slot: UTC interval for time_slot polls
    (via the poll's IANA tz), exclusive all-day DATE values otherwise."""
    d = _as_date(slot["date"])
    if slot.get("start_time") and slot.get("end_time"):
        tz = ZoneInfo(poll.get("timezone") or "Europe/Zurich")
        return (f"DTSTART:{_utc(d, slot['start_time'], tz)}",
                f"DTEND:{_utc(d, slot['end_time'], tz)}")
    return (f"DTSTART;VALUE=DATE:{d.strftime('%Y%m%d')}",
            f"DTEND;VALUE=DATE:{(d + timedelta(days=1)).strftime('%Y%m%d')}")


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


_UID_HOST = "@kairos.local"


def slot_uid(poll_id: str, slot_id: str) -> str:
    """Stable per-slot UID — reused across feed refreshes, iMIP REQUEST and
    CANCEL so a client tracks one event through its whole lifecycle."""
    return f"kairos-{poll_id}-{slot_id}{_UID_HOST}"


def parse_slot_uid(uid: str) -> tuple[str, str] | None:
    """Inverse of slot_uid: (poll_id, slot_id) from a reply's UID, else None.

    Both ids are fixed-width uuid4 (36 chars), so the inner '{poll}-{slot}'
    splits unambiguously despite the hyphens inside each uuid."""
    if not uid.startswith("kairos-") or not uid.endswith(_UID_HOST):
        return None
    mid = uid[len("kairos-"):-len(_UID_HOST)]
    if len(mid) != 73 or mid[36] != "-":  # 36 + '-' + 36
        return None
    return mid[:36], mid[37:]


def _tally(slot_id: str, responses: list[dict]) -> tuple[int, int, int]:
    """(yes, maybe, no) counts for a slot across responses."""
    avs = [r["slot_availabilities"].get(slot_id) for r in responses]
    return (sum(a == "yes" for a in avs),
            sum(a == "maybe" for a in avs),
            sum(a == "no" for a in avs))


def _slot_status(yes: int, maybe: int, total_expected: int) -> str:
    """Convergence label mirrored into the event for machines + color."""
    if total_expected and yes >= total_expected:
        return "ready"
    if yes or maybe:
        return "partial"
    return "open"


# RFC 7986 COLOR (CSS3 names) by convergence — the overlay becomes the heatmap.
_STATUS_COLOR = {"ready": "green", "partial": "orange"}


def build_feed_ics(poll: dict, slots: list[dict], responses: list[dict], *,
                   base_url: str = "", prefix: str = "",
                   invite_token: str | None = None,
                   total_expected: int = 0, shorten=None) -> str:
    """Read-only candidate-slot feed (flavor B): one TENTATIVE VEVENT per slot,
    each carrying the live tally, convergence color, and — for an invite feed —
    deep-link Accept/Maybe/Decline URLs the calendar surfaces in the event body.

    NOTE: subscribed feeds are eventually-consistent (Google ~daily, not
    controllable). The deep-link landing page, not this feed, is the
    instant-feedback surface. See docs/design/reverse-calendar-imip.md.
    """
    poll_url = f"{base_url}{prefix}/p/{poll['public_token']}"
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//kairos//scheduler//EN",
        "METHOD:PUBLISH",
        "CALSCALE:GREGORIAN",
        f"X-WR-CALNAME:{_esc(poll['title'])} — Kairos",
        "REFRESH-INTERVAL;VALUE=DURATION:PT15M",
        "X-PUBLISHED-TTL:PT15M",
    ]
    stamp = _now_stamp()
    for slot in slots:
        dtstart, dtend = _dt_lines(poll, slot)
        yes, maybe, no = _tally(slot["id"], responses)
        status = _slot_status(yes, maybe, total_expected)
        desc = [f"{yes} yes · {maybe} maybe · {no} no"]
        if invite_token:
            for lbl, av in (("Accept", "yes"), ("Maybe", "maybe"), ("Decline", "no")):
                path = f"{prefix}/p/i/{invite_token}/s/{slot['id']}/{av}"
                desc.append(f"{lbl}: {shorten(path) if shorten else base_url + path}")
        desc.append(poll_url)
        lines += [
            "BEGIN:VEVENT",
            f"UID:{slot_uid(poll['id'], slot['id'])}",
            f"DTSTAMP:{stamp}",
            dtstart,
            dtend,
            f"SUMMARY:{_esc(poll['title'])}",
            f"DESCRIPTION:{_esc(chr(10).join(desc))}",
            f"URL:{poll_url}",
            "STATUS:TENTATIVE",
            f"X-KAIROS-POLL-ID:{poll['id']}",
            f"X-KAIROS-SLOT-STATUS:{status}",
        ]
        if status in _STATUS_COLOR:
            lines.append(f"COLOR:{_STATUS_COLOR[status]}")
        lines.append("END:VEVENT")
    lines.append("END:VCALENDAR")
    return "\r\n".join(_fold(li) for li in lines) + "\r\n"


def _imip_ics(poll: dict, slot: dict, *, method: str, status: str,
              organizer_email: str, organizer_name: str | None,
              attendee_email: str, attendee_name: str | None,
              sequence: int, partstat: str, rsvp: bool,
              url: str | None = None, description: str | None = None) -> str:
    """One iMIP VEVENT (REQUEST or CANCEL) addressed to a single attendee.

    ORGANIZER is the mailbox Kairos polls for replies (so a client's
    METHOD:REPLY comes back where we can read it). UID/SEQUENCE track the slot
    across its whole lifecycle. See docs/design/reverse-calendar-imip.md.
    """
    dtstart, dtend = _dt_lines(poll, slot)
    org_cn = f";CN={_esc(organizer_name)}" if organizer_name else ""
    att_cn = f";CN={_esc(attendee_name)}" if attendee_name else ""
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//kairos//scheduler//EN",
        f"METHOD:{method}",
        "CALSCALE:GREGORIAN",
        "BEGIN:VEVENT",
        f"UID:{slot_uid(poll['id'], slot['id'])}",
        f"DTSTAMP:{_now_stamp()}",
        f"SEQUENCE:{sequence}",
        dtstart,
        dtend,
        f"SUMMARY:{_esc(poll['title'])}",
        f"ORGANIZER{org_cn}:mailto:{organizer_email}",
        (f"ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT={partstat};"
         f"RSVP={'TRUE' if rsvp else 'FALSE'}{att_cn}:mailto:{attendee_email}"),
        f"STATUS:{status}",
    ]
    desc = description if description is not None else poll.get("description")
    if desc:
        lines.append(f"DESCRIPTION:{_esc(desc)}")
    if url:
        lines.append(f"URL:{url}")
    lines += ["END:VEVENT", "END:VCALENDAR"]
    return "\r\n".join(_fold(li) for li in lines) + "\r\n"


def build_request_ics(poll: dict, slot: dict, attendee_email: str, *,
                      organizer_email: str, organizer_name: str | None = None,
                      sequence: int = 0, attendee_name: str | None = None,
                      url: str | None = None, description: str | None = None) -> str:
    """iMIP METHOD:REQUEST — surfaces native Accept/Maybe/Decline in the client.

    description overrides the poll's own; used to embed per-invitee deep-link
    vote URLs, which Gmail renders (clickable) in its event card even when it
    suppresses native RSVP for a Gmail-organized invite."""
    return _imip_ics(poll, slot, method="REQUEST", status="CONFIRMED",
                     organizer_email=organizer_email, organizer_name=organizer_name,
                     attendee_email=attendee_email, attendee_name=attendee_name,
                     sequence=sequence, partstat="NEEDS-ACTION", rsvp=True,
                     url=url, description=description)


def build_cancel_ics(poll: dict, slot: dict, attendee_email: str, *,
                     organizer_email: str, organizer_name: str | None = None,
                     sequence: int = 1) -> str:
    """iMIP METHOD:CANCEL — clients auto-remove the event (losing slots on decide)."""
    return _imip_ics(poll, slot, method="CANCEL", status="CANCELLED",
                     organizer_email=organizer_email, organizer_name=organizer_name,
                     attendee_email=attendee_email, attendee_name=None,
                     sequence=sequence, partstat="NEEDS-ACTION", rsvp=False)


def build_ics(poll: dict, slot: dict, url: str | None = None) -> str:
    """VCALENDAR with the decided slot as a confirmed event."""
    dtstart, dtend = _dt_lines(poll, slot)

    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//kairos//scheduler//EN",
        "METHOD:PUBLISH",
        "BEGIN:VEVENT",
        f"UID:kairos-{poll['id']}@kairos.local",
        f"DTSTAMP:{_now_stamp()}",
        dtstart,
        dtend,
        f"SUMMARY:{_esc(poll['title'])}",
    ]
    if poll.get("description"):
        lines.append(f"DESCRIPTION:{_esc(poll['description'])}")
    if url:
        lines.append(f"URL:{url}")
    lines += ["STATUS:CONFIRMED", "END:VEVENT", "END:VCALENDAR"]
    return "\r\n".join(_fold(li) for li in lines) + "\r\n"
