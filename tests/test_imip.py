"""iMIP outbound: message assembly (REQUEST/CANCEL) + per-slot SEQUENCE state."""

from datetime import date, time

from kairos.email_service import build_imip_message
from kairos.ics import build_cancel_ics, build_request_ics

POLL = {"id": "p1", "title": "Standup", "timezone": "Europe/Zurich"}
SLOT = {"id": "s1", "date": date(2026, 7, 6), "start_time": time(9, 0), "end_time": time(9, 30)}


def _calendar_part(msg):
    return next(p for p in msg.walk() if p.get_content_type() == "text/calendar")


def test_request_message_routes_replies_to_organizer():
    ics = build_request_ics(POLL, SLOT, "bob@x.ch",
                            organizer_email="replies@kairos.ch", organizer_name="Kairos")
    msg = build_imip_message("bob@x.ch", "You're invited: Standup", "Pick a time.",
                             ics, "REQUEST", "replies@kairos.ch", "Kairos")
    assert msg["To"] == "bob@x.ch"
    # From is the ORGANIZER mailbox -> client REPLY lands in the polled inbox
    assert "replies@kairos.ch" in msg["From"]
    assert "Reply-To" not in msg
    cal = _calendar_part(msg)
    assert cal.get_param("method") == "REQUEST"
    assert "METHOD:REQUEST" in cal.get_payload(decode=True).decode()


def test_cancel_message_carries_cancel_method():
    ics = build_cancel_ics(POLL, SLOT, "bob@x.ch",
                           organizer_email="replies@kairos.ch", sequence=2)
    msg = build_imip_message("bob@x.ch", "Cancelled: Standup", "No longer needed.",
                             ics, "CANCEL", "replies@kairos.ch", "Kairos")
    cal = _calendar_part(msg)
    assert cal.get_param("method") == "CANCEL"
    assert "METHOD:CANCEL" in cal.get_payload(decode=True).decode()
