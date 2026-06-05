"""ICS generation unit tests."""

from datetime import date, time, timedelta

from kairos.ics import build_ics

POLL = {"id": "p1", "title": "Team retreat, June; planning", "description": "Two\nlines",
        "timezone": "Europe/Zurich", "status": "decided", "decided_slot_id": "t1"}


def test_timeslot_event_utc_conversion():
    slot = {"id": "t1", "date": date(2026, 6, 8), "start_time": time(9, 0), "end_time": time(9, 30)}
    ics = build_ics(POLL, slot, "https://x/p/tok")
    # June in Zurich = CEST (UTC+2): 09:00 local -> 07:00Z
    assert "DTSTART:20260608T070000Z" in ics
    assert "DTEND:20260608T073000Z" in ics
    assert "SUMMARY:Team retreat\\, June\\; planning" in ics
    assert "DESCRIPTION:Two\\nlines" in ics
    assert "URL:https://x/p/tok" in ics
    assert "STATUS:CONFIRMED" in ics
    assert ics.endswith("END:VCALENDAR\r\n")
    assert "\r\n" in ics


def test_timeslot_accepts_mysql_timedelta():
    slot = {"id": "t1", "date": "2026-01-15",  # CET (UTC+1) in winter
            "start_time": timedelta(hours=14), "end_time": timedelta(hours=15, minutes=30)}
    ics = build_ics(POLL, slot)
    assert "DTSTART:20260115T130000Z" in ics
    assert "DTEND:20260115T143000Z" in ics


def test_fullday_event_is_all_day():
    slot = {"id": "s1", "date": date(2026, 6, 8), "start_time": None, "end_time": None}
    ics = build_ics(POLL, slot)
    assert "DTSTART;VALUE=DATE:20260608" in ics
    assert "DTEND;VALUE=DATE:20260609" in ics  # exclusive end = next day


def test_long_lines_are_folded():
    long_poll = dict(POLL, title="x" * 200)
    slot = {"id": "s1", "date": date(2026, 6, 8), "start_time": None, "end_time": None}
    ics = build_ics(long_poll, slot)
    for line in ics.split("\r\n"):
        assert len(line.encode()) <= 76  # 75 + leading fold space
