"""ICS generation unit tests."""

from datetime import date, time, timedelta

from kairos.ics import build_cancel_ics, build_feed_ics, build_ics, build_request_ics, slot_uid

POLL = {"id": "p1", "title": "Team retreat, June; planning", "description": "Two\nlines",
        "timezone": "Europe/Zurich", "status": "decided", "decided_slot_id": "t1"}

FEED_POLL = {"id": "p9", "title": "Sprint sync", "timezone": "Europe/Zurich",
             "status": "open", "public_token": "pubtok"}
FEED_SLOTS = [
    {"id": "s1", "date": date(2026, 7, 6), "start_time": time(9, 0), "end_time": time(9, 30)},
    {"id": "s2", "date": date(2026, 7, 7), "start_time": None, "end_time": None},
]


def _unfold(ics: str) -> str:
    """RFC 5545 unfolding (what a client does before rendering)."""
    return ics.replace("\r\n ", "").replace("\r\n\t", "")


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


# -- Reverse-calendar candidate feed (build_feed_ics) --

def test_feed_has_one_tentative_vevent_per_slot():
    feed = build_feed_ics(FEED_POLL, FEED_SLOTS, [], base_url="https://x", prefix="/s")
    assert feed.count("BEGIN:VEVENT") == 2
    assert feed.count("STATUS:TENTATIVE") == 2
    assert "STATUS:CONFIRMED" not in feed
    assert "METHOD:PUBLISH" in feed
    assert "X-WR-CALNAME:Sprint sync — Kairos" in feed
    assert "REFRESH-INTERVAL;VALUE=DURATION:PT15M" in feed
    # stable per-slot UIDs
    assert f"UID:{slot_uid('p9', 's1')}" in feed
    assert f"UID:{slot_uid('p9', 's2')}" in feed
    # time_slot slot converts to UTC; full_day slot is all-day
    assert "DTSTART:20260706T070000Z" in feed
    assert "DTSTART;VALUE=DATE:20260707" in feed


def test_feed_tally_reflects_responses():
    responses = [
        {"slot_availabilities": {"s1": "yes"}},
        {"slot_availabilities": {"s1": "maybe", "s2": "no"}},
    ]
    feed = build_feed_ics(FEED_POLL, FEED_SLOTS, responses, base_url="https://x", total_expected=2)
    assert "1 yes · 1 maybe · 0 no" in feed  # s1
    assert "0 yes · 0 maybe · 1 no" in feed  # s2


def test_feed_status_and_color_by_convergence():
    # s1 gets unanimous yes from the 2 expected -> ready/green; s2 stays open
    responses = [{"slot_availabilities": {"s1": "yes"}}, {"slot_availabilities": {"s1": "yes"}}]
    feed = build_feed_ics(FEED_POLL, FEED_SLOTS, responses, base_url="https://x", total_expected=2)
    assert "X-KAIROS-SLOT-STATUS:ready" in feed
    assert "COLOR:green" in feed
    assert "X-KAIROS-SLOT-STATUS:open" in feed
    assert "X-KAIROS-POLL-ID:p9" in feed


def test_feed_deep_links_only_with_invite_token():
    public = _unfold(build_feed_ics(FEED_POLL, FEED_SLOTS, [], base_url="https://x", prefix="/s"))
    assert "/s/p/i/" not in public  # no per-slot vote links without an identity
    inv = _unfold(build_feed_ics(FEED_POLL, FEED_SLOTS, [], base_url="https://x", prefix="/s",
                                 invite_token="invtok"))
    assert "https://x/s/p/i/invtok/s/s1/yes" in inv
    assert "https://x/s/p/i/invtok/s/s1/maybe" in inv
    assert "https://x/s/p/i/invtok/s/s1/no" in inv


def test_feed_lines_are_folded():
    feed = build_feed_ics(dict(FEED_POLL, title="y" * 200), FEED_SLOTS, [], base_url="https://x")
    for line in feed.split("\r\n"):
        assert len(line.encode()) <= 76


# -- iMIP REQUEST / CANCEL (build_request_ics / build_cancel_ics) --

_SLOT = {"id": "s1", "date": date(2026, 7, 6), "start_time": time(9, 0), "end_time": time(9, 30)}


def test_request_is_imip_invitation():
    ics = _unfold(build_request_ics(FEED_POLL, _SLOT, "bob@x.ch",
                                    organizer_email="replies@kairos.ch", organizer_name="Kairos",
                                    sequence=0, attendee_name="Bob"))
    assert "METHOD:REQUEST" in ics
    assert "ORGANIZER;CN=Kairos:mailto:replies@kairos.ch" in ics
    assert "ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;CN=Bob:mailto:bob@x.ch" in ics
    assert "SEQUENCE:0" in ics
    assert "STATUS:CONFIRMED" in ics
    assert f"UID:{slot_uid('p9', 's1')}" in ics
    assert "DTSTART:20260706T070000Z" in ics  # 09:00 CEST -> UTC


def test_cancel_revokes_same_uid():
    ics = build_cancel_ics(FEED_POLL, _SLOT, "bob@x.ch",
                           organizer_email="replies@kairos.ch", sequence=2)
    assert "METHOD:CANCEL" in ics
    assert "STATUS:CANCELLED" in ics
    assert "SEQUENCE:2" in ics
    # same UID as the REQUEST so the client tombstones the right event
    assert f"UID:{slot_uid('p9', 's1')}" in ics


def test_request_escapes_attendee_cn():
    ics = _unfold(build_request_ics(FEED_POLL, _SLOT, "x@y.ch",
                                    organizer_email="o@z.ch", attendee_name="Doe, Jane"))
    assert "CN=Doe\\, Jane:mailto:x@y.ch" in ics
