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


def build_ics(poll: dict, slot: dict, url: str | None = None) -> str:
    """VCALENDAR with the decided slot as a confirmed event."""
    d = _as_date(slot["date"])
    if slot.get("start_time") and slot.get("end_time"):
        tz = ZoneInfo(poll.get("timezone") or "Europe/Zurich")
        dtstart = f"DTSTART:{_utc(d, slot['start_time'], tz)}"
        dtend = f"DTEND:{_utc(d, slot['end_time'], tz)}"
    else:
        dtstart = f"DTSTART;VALUE=DATE:{d.strftime('%Y%m%d')}"
        dtend = f"DTEND;VALUE=DATE:{(d + timedelta(days=1)).strftime('%Y%m%d')}"

    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//kairos//scheduler//EN",
        "METHOD:PUBLISH",
        "BEGIN:VEVENT",
        f"UID:kairos-{poll['id']}@kairos.local",
        f"DTSTAMP:{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
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
