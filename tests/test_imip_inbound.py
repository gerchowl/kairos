"""Inbound iMIP: parse METHOD:REPLY + fold PARTSTAT back into the poll."""

import pytest
from fastapi.testclient import TestClient

from kairos.ics import parse_slot_uid, slot_uid
from kairos.imip_inbound import apply_reply, parse_reply


def _reply(uid, email, partstat, sequence=0, method="REPLY"):
    return (
        f"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:{method}\r\nBEGIN:VEVENT\r\n"
        f"UID:{uid}\r\nSEQUENCE:{sequence}\r\n"
        f"ATTENDEE;PARTSTAT={partstat};CN=Bob:mailto:{email}\r\n"
        "END:VEVENT\r\nEND:VCALENDAR\r\n"
    )


# -- pure parse --

def test_parse_reply_extracts_fields():
    r = parse_reply(_reply("kairos-p-s@kairos.local", "bob@x.ch", "ACCEPTED", 3))
    assert r == {"uid": "kairos-p-s@kairos.local", "email": "bob@x.ch",
                 "partstat": "ACCEPTED", "sequence": 3}


def test_parse_ignores_non_reply_and_incomplete():
    assert parse_reply(_reply("u", "b@x.ch", "ACCEPTED", method="REQUEST")) is None
    no_partstat = "BEGIN:VCALENDAR\r\nMETHOD:REPLY\r\nUID:u\r\nEND:VCALENDAR\r\n"
    assert parse_reply(no_partstat) is None


def test_slot_uid_round_trips():
    uid = slot_uid("11111111-1111-4111-8111-111111111111",
                   "22222222-2222-4222-8222-222222222222")
    assert parse_slot_uid(uid) == ("11111111-1111-4111-8111-111111111111",
                                   "22222222-2222-4222-8222-222222222222")
    assert parse_slot_uid("garbage") is None


# -- apply (sqlite-backed) --

@pytest.fixture
def poll_ctx(tmp_path, monkeypatch):
    from kairos import settings
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/k.db")
    monkeypatch.setattr(settings, "API_KEY", "k")
    from kairos.main import create_app
    with TestClient(create_app(), base_url="https://testserver") as c:
        poll = c.post("/scheduler/api/polls", headers={"Authorization": "Bearer k"}, json={
            "title": "Reply test", "mode": "full_day", "creator": "alice",
            "slots": [{"date": "2026-07-06"}]}).json()
        from kairos.db import create_invite
        create_invite(poll["id"], "bob@x.ch", required=True, name="Bob")
        yield poll


def test_accepted_reply_records_availability(poll_ctx):
    from kairos.db import get_responses
    pid, sid = poll_ctx["id"], poll_ctx["slots"][0]["id"]
    assert apply_reply(parse_reply(_reply(slot_uid(pid, sid), "bob@x.ch", "ACCEPTED"))) is True
    resp = get_responses(pid)
    assert len(resp) == 1 and resp[0]["slot_availabilities"][sid] == "yes"
    assert resp[0]["respondent_email"] == "bob@x.ch"


def test_partstat_maps_maybe_and_no(poll_ctx):
    from kairos.db import get_responses
    pid, sid = poll_ctx["id"], poll_ctx["slots"][0]["id"]
    apply_reply(parse_reply(_reply(slot_uid(pid, sid), "bob@x.ch", "TENTATIVE")))
    assert get_responses(pid)[0]["slot_availabilities"][sid] == "maybe"
    apply_reply(parse_reply(_reply(slot_uid(pid, sid), "bob@x.ch", "DECLINED")))
    assert get_responses(pid)[0]["slot_availabilities"][sid] == "no"


def test_unknown_attendee_is_rejected(poll_ctx):
    from kairos.db import get_responses
    pid, sid = poll_ctx["id"], poll_ctx["slots"][0]["id"]
    assert apply_reply(parse_reply(_reply(slot_uid(pid, sid), "stranger@x.ch", "ACCEPTED"))) is False
    assert get_responses(pid) == []


def test_unknown_uid_is_rejected(poll_ctx):
    bad = slot_uid("00000000-0000-4000-8000-000000000000", poll_ctx["slots"][0]["id"])
    assert apply_reply(parse_reply(_reply(bad, "bob@x.ch", "ACCEPTED"))) is False


def test_stale_sequence_is_dropped(poll_ctx):
    from kairos.db import bump_slot_sequence, get_responses
    pid, sid = poll_ctx["id"], poll_ctx["slots"][0]["id"]
    bump_slot_sequence(sid)  # current sequence now 1; a SEQUENCE:0 reply is stale
    assert apply_reply(parse_reply(_reply(slot_uid(pid, sid), "bob@x.ch", "ACCEPTED", 0))) is False
    assert get_responses(pid) == []


def test_imip_poll_endpoint_noop_and_authed(tmp_path, monkeypatch):
    from kairos import settings
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/k.db")
    monkeypatch.setattr(settings, "API_KEY", "k")
    from kairos.main import create_app
    with TestClient(create_app(), base_url="https://testserver") as c:
        # unconfigured -> no-op count, but the endpoint exists + is authed
        r = c.post("/scheduler/api/imip/poll", headers={"Authorization": "Bearer k"})
        assert r.status_code == 200 and r.json() == {"applied": 0}
        assert c.post("/scheduler/api/imip/poll").status_code in (401, 403)
