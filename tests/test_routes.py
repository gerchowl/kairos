"""Route-level smoke tests with a stubbed DB — catches route/template context drift."""

from datetime import date, time

import pytest
from fastapi.testclient import TestClient

from kairos import main, public, web

POLL = {
    "id": "p1", "creator_id": "testuser", "title": "Retreat",
    "description": "desc", "mode": "time_slot", "timezone": "Europe/Zurich",
    "status": "open", "decided_slot_id": None, "public_token": "tok123",
    "slots": [
        {"id": "t1", "date": date(2026, 6, 8), "start_time": time(9, 0), "end_time": time(9, 30)},
        {"id": "t2", "date": date(2026, 6, 8), "start_time": time(9, 30), "end_time": time(10, 0)},
    ],
}

RESPONSES = [
    {"id": "r1", "respondent_name": "Alice", "slot_availabilities": {"t1": "yes"}},
]

USER = {"uid": "u1", "name": "Lars Test", "email": "lars@ethz.ch"}


@pytest.fixture
def store(monkeypatch):
    """In-memory response store wired into public.py."""
    state = {"responses": {}, "added": [], "updated": []}

    def add_response(poll_id, name, email, avails, user_id=None, invite_id=None):
        rid = f"r{len(state['responses']) + 10}"
        resp = {"id": rid, "poll_id": poll_id, "respondent_name": name,
                "respondent_email": email, "user_id": user_id,
                "slot_availabilities": avails}
        state["responses"][rid] = resp
        state["added"].append(resp)
        return resp

    def update_response(rid, name, avails, user_id=None, email=None):
        resp = state["responses"][rid]
        resp.update(respondent_name=name, slot_availabilities=avails)
        if user_id:
            resp["user_id"] = user_id
        if email:
            resp["respondent_email"] = email
        state["updated"].append(rid)
        return resp

    monkeypatch.setattr(public, "get_poll_by_token", lambda token: POLL if token == "tok123" else None)
    monkeypatch.setattr(public, "get_responses", lambda pid: RESPONSES)
    monkeypatch.setattr(public, "get_invites", lambda pid: [])
    monkeypatch.setattr(public, "add_response", add_response)
    monkeypatch.setattr(public, "update_response", update_response)
    monkeypatch.setattr(public, "get_response", lambda rid: state["responses"].get(rid))
    monkeypatch.setattr(public, "find_response_by_user", lambda pid, uid: next(
        (r for r in state["responses"].values() if r.get("user_id") == uid and r["poll_id"] == pid), None))
    monkeypatch.setattr(public, "find_response_by_email", lambda pid, email: next(
        (r for r in state["responses"].values()
         if r.get("respondent_email") == email and r["poll_id"] == pid), None))
    monkeypatch.setattr(public, "get_user", lambda request: state.get("user"))
    monkeypatch.setattr(public, "notify_new_response", lambda *a: None)
    return state


@pytest.fixture
def client(store):
    # https base: the anonymous-response cookie is Secure
    return TestClient(main.app, base_url="https://testserver", raise_server_exceptions=True)


def test_web_requires_auth(client):
    r = client.get("/scheduler/", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"].startswith("/login")


def test_public_poll_renders(client):
    r = client.get("/scheduler/p/tok123")
    assert r.status_code == 200
    assert "ts-grid-data" in r.text
    assert "Save Response" in r.text
    assert 'id="save-btn"' in r.text
    assert "noindex" in r.text


def test_public_poll_not_found(client):
    r = client.get("/scheduler/p/nope")
    assert r.status_code == 404
    assert "Poll not found" in r.text


def test_public_submit_requires_name(client):
    r = client.post("/scheduler/p/tok123", data={"name": " "})
    assert r.status_code == 400
    assert "Name is required" in r.text


def test_anonymous_response_persists_via_cookie(client, store):
    r = client.post("/scheduler/p/tok123", data={"name": "Eve", "av_t1": "yes", "av_t2": "maybe"})
    assert r.status_code == 200
    assert "recorded" in r.text
    assert "sched_resp_p1" in r.headers.get("set-cookie", "")
    assert len(store["added"]) == 1

    # Revisit: saved availabilities load back into the grid, name prefilled
    r2 = client.get("/scheduler/p/tok123")
    assert '"saved": {"t1": "yes", "t2": "maybe"}' in r2.text.replace("&#34;", '"') or "maybe" in r2.text
    assert 'value="Eve"' in r2.text

    # Resubmit: updates the same response instead of duplicating
    r3 = client.post("/scheduler/p/tok123", data={"name": "Eve", "av_t1": "no", "av_t2": "no"})
    assert "updated" in r3.text
    assert len(store["added"]) == 1
    assert store["updated"]


def test_authed_user_binds_and_prefills(client, store):
    store["user"] = USER
    r = client.get("/scheduler/p/tok123")
    assert 'value="Lars Test"' in r.text  # name auto-filled from account
    assert 'value="lars@ethz.ch"' in r.text

    r2 = client.post("/scheduler/p/tok123", data={"name": "Lars Test", "av_t1": "yes"})
    assert "recorded" in r2.text
    assert store["added"][0]["user_id"] == "u1"  # bound to account
    assert "sched_resp_p1" not in r2.headers.get("set-cookie", "")  # no cookie needed

    # Re-login from anywhere: response found by uid
    r3 = client.get("/scheduler/p/tok123")
    assert 'value="Lars Test"' in r3.text
    assert "saved" in r3.text


def test_fullday_public_poll(client, store, monkeypatch):
    fullday = dict(POLL, mode="full_day", slots=[
        {"id": "s1", "date": date(2026, 6, 8), "start_time": None, "end_time": None},
        {"id": "s2", "date": date(2026, 6, 15), "start_time": None, "end_time": None},
    ])
    monkeypatch.setattr(public, "get_poll_by_token", lambda token: fullday)
    monkeypatch.setattr(public, "get_responses", lambda pid: [
        {"id": "r1", "respondent_name": "Alice", "slot_availabilities": {"s1": "yes"}},
    ])
    r = client.get("/scheduler/p/tok123")
    assert r.status_code == 200
    assert "fullday-cal-data" in r.text
    assert "sched-bar" in r.text
    assert "sched-gap-after" in r.text  # Jun 8 -> Jun 15 gap stripe


def test_static_js_served(client):
    for f in ("grid.js", "cal-select.js"):
        r = client.get(f"/scheduler/static/{f}")
        assert r.status_code == 200, f
        assert "javascript" in r.headers["content-type"]


def test_robots(client):
    r = client.get("/scheduler/robots.txt")
    assert "Disallow: /scheduler/p/" in r.text


def test_web_post_unauthed_401(client):
    r = client.post("/scheduler/polls/p1/close", data={})
    assert r.status_code == 401


def test_public_ics_download(client, monkeypatch):
    decided = dict(POLL, status="decided", decided_slot_id="t1")
    monkeypatch.setattr(public, "get_poll_by_token", lambda token: decided)
    r = client.get("/scheduler/p/tok123/event.ics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/calendar")
    assert "attachment" in r.headers["content-disposition"]
    assert "DTSTART:20260608T070000Z" in r.text  # 09:00 CEST -> UTC
    assert "SUMMARY:Retreat" in r.text


def test_public_ics_404_when_not_decided(client):
    r = client.get("/scheduler/p/tok123/event.ics")  # poll is open
    assert r.status_code == 404


def test_decided_public_page_links_ics(client, monkeypatch):
    decided = dict(POLL, status="decided", decided_slot_id="t1")
    monkeypatch.setattr(public, "get_poll_by_token", lambda token: decided)
    r = client.get("/scheduler/p/tok123")
    assert "Final date" in r.text
    assert "/scheduler/p/tok123/event.ics" in r.text


def test_email_decision_sends_to_all(client, store, monkeypatch):
    decided = dict(POLL, status="decided", decided_slot_id="t1")
    sent = {}

    def fake_send(recipients, title, label, url, ics, sender, note="", reply_to=None):
        sent.update(recipients=recipients, title=title, label=label, ics=ics,
                    note=note, reply_to=reply_to)
        return list(recipients)

    monkeypatch.setattr(web, "get_user", lambda request: dict(USER, uid="testuser"))
    monkeypatch.setattr(web, "get_poll", lambda pid: decided)
    monkeypatch.setattr(web, "get_responses", lambda pid: [
        {"id": "r1", "respondent_name": "A", "respondent_email": "a@x.ch", "slot_availabilities": {}},
        {"id": "r2", "respondent_name": "B", "respondent_email": "A@X.ch", "slot_availabilities": {}},  # dup, case
        {"id": "r3", "respondent_name": "C", "respondent_email": None, "slot_availabilities": {}},
    ])
    monkeypatch.setattr(web, "get_invites", lambda pid: [{"id": "i1", "email": "b@y.ch", "responded": False}])
    monkeypatch.setattr(web, "send_decision_email", fake_send)
    monkeypatch.setattr(web, "require_csrf", lambda user, form: None)
    monkeypatch.setattr(web, "log_contact", lambda *a, **k: None)

    r = client.post("/scheduler/polls/p1/email-decision", data={"note": "see you there"},
                    follow_redirects=False)
    assert r.status_code == 302
    assert "msg=emailed&n=2" in r.headers["location"]
    assert sent["recipients"] == ["a@x.ch", "b@y.ch"]  # deduped, no empty
    assert "BEGIN:VCALENDAR" in sent["ics"]
    assert sent["note"] == "see you there"
    assert sent["reply_to"] == USER["email"]  # replies go to the poll owner


def test_email_sender_identity():
    """Mail is sent AS the service address; the owner is display-name + Reply-To."""
    from kairos import email_service
    msg = email_service.build_decision_message(
        "to@x.ch", "Retreat", "2026-06-08", "https://x/p/t",
        "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n", "Lars Gerchow",
        note="hi", reply_to="lars@ethz.ch")
    assert msg["From"] == f"Lars Gerchow via Kairos <{email_service.SMTP_FROM}>"
    assert msg["Reply-To"] == "lars@ethz.ch"
    assert msg["To"] == "to@x.ch"
    ics_part = msg.get_payload()[-1]
    assert ics_part.get_filename() == email_service.ICS_FILENAME
    assert "BEGIN:VCALENDAR" in ics_part.get_payload(decode=True).decode()

    inv = email_service.build_invite_message("to@x.ch", "Retreat", "https://x/i/t",
                                             "Lars Gerchow", reply_to="lars@ethz.ch")
    assert "via Kairos" in inv["From"]
    assert inv["Reply-To"] == "lars@ethz.ch"


def test_email_decision_requires_decided(client, monkeypatch):
    monkeypatch.setattr(web, "get_user", lambda request: dict(USER, uid="testuser"))
    monkeypatch.setattr(web, "get_poll", lambda pid: POLL)  # open
    monkeypatch.setattr(web, "require_csrf", lambda user, form: None)
    r = client.post("/scheduler/polls/p1/email-decision", data={})
    assert r.status_code == 400


@pytest.fixture
def owner(monkeypatch):
    monkeypatch.setattr(web, "get_user", lambda request: dict(USER, uid="testuser"))
    monkeypatch.setattr(web, "require_csrf", lambda user, form: None)
    monkeypatch.setattr(web, "get_poll", lambda pid: POLL)
    monkeypatch.setattr(web, "get_contact_log", lambda pid: [])
    monkeypatch.setattr(web, "log_contact", lambda *a, **k: None)


def test_edit_poll_updates_and_adds_dates(client, owner, monkeypatch):
    updated, added = {}, {}
    monkeypatch.setattr(web, "update_poll", lambda pid, **f: updated.update(f) or True)
    monkeypatch.setattr(web, "add_slots", lambda pid, slots: added.update(slots=slots) or slots)

    r = client.post("/scheduler/polls/p1/edit", data={
        "title": "Retreat v2", "description": "new desc", "timezone": "Europe/Zurich",
        "dates": ["2026-06-08", "2026-06-22"],  # 06-08 already exists -> skipped
    }, follow_redirects=False)
    assert r.status_code == 302 and "msg=saved" in r.headers["location"]
    assert updated["title"] == "Retreat v2"
    # only the genuinely new date, expanded over the poll's existing time grid
    assert [s["date"] for s in added["slots"]] == ["2026-06-22", "2026-06-22"]
    assert {(s["start_time"], s["end_time"]) for s in added["slots"]} == {
        ("09:00", "09:30"), ("09:30", "10:00")}


def test_edit_with_notify_runs_nudge_engine(client, owner, monkeypatch):
    monkeypatch.setattr(web, "update_poll", lambda pid, **f: True)
    monkeypatch.setattr(web, "add_slots", lambda pid, slots: slots)
    monkeypatch.setattr(web, "nudge_participants",
                        lambda req, poll, user: {"invited": 1, "updated": 2, "skipped": 0})
    r = client.post("/scheduler/polls/p1/edit", data={
        "title": "Retreat", "timezone": "Europe/Zurich",
        "dates": ["2026-06-22"], "notify": "1",
    }, follow_redirects=False)
    assert "msg=nudged&inv=1&upd=2" in r.headers["location"]


def test_edit_without_new_dates_sends_nothing(client, owner, monkeypatch):
    monkeypatch.setattr(web, "update_poll", lambda pid, **f: True)
    called = []
    monkeypatch.setattr(web, "send_update_emails", lambda *a, **k: called.append(1) or 0)
    r = client.post("/scheduler/polls/p1/edit", data={
        "title": "Retreat", "timezone": "Europe/Zurich",
        "dates": ["2026-06-08"], "notify": "1",  # date already exists
    }, follow_redirects=False)
    assert "msg=saved" in r.headers["location"]
    assert not called


def test_reopen_poll(client, owner, monkeypatch):
    updated = {}
    monkeypatch.setattr(web, "update_poll", lambda pid, **f: updated.update(f) or True)
    r = client.post("/scheduler/polls/p1/reopen", data={}, follow_redirects=False)
    assert r.status_code == 302 and "msg=reopened" in r.headers["location"]
    assert updated == {"status": "open", "decided_slot_id": None}


def test_nudge_engine_state_driven(client, owner, monkeypatch):
    """Per-participant state decides who gets mail — pending vs stale vs done."""
    from datetime import datetime as dt
    from datetime import timedelta as td
    t0 = dt(2026, 6, 1, 12, 0)
    slot_new = t0 + td(days=3)
    poll = dict(POLL, slots=[
        dict(POLL["slots"][0], created_at=t0),
        dict(POLL["slots"][1], created_at=slot_new),  # added later
    ])
    monkeypatch.setattr(web, "get_poll", lambda pid: poll)
    monkeypatch.setattr(web, "get_invites", lambda pid: [
        {"id": "i1", "email": "pending@x.ch", "token": "ta", "responded": False, "notified_at": None},
        {"id": "i2", "email": "recent@x.ch", "token": "tb", "responded": False,
         "notified_at": dt.now() - td(hours=1)},                                   # cooldown skip
        {"id": "i3", "email": "stale@x.ch", "token": "tc", "responded": True, "notified_at": None},
        {"id": "i4", "email": "told@x.ch", "token": "tq", "responded": True,
         "notified_at": slot_new + td(hours=1)},                                   # already told
    ])
    monkeypatch.setattr(web, "get_responses", lambda pid: [
        {"id": "r1", "invite_id": "i3", "respondent_email": "stale@x.ch", "respondent_name": "S",
         "updated_at": t0 + td(days=1), "notified_at": None, "slot_availabilities": {}},
        {"id": "r2", "invite_id": "i4", "respondent_email": "told@x.ch", "respondent_name": "T",
         "updated_at": t0 + td(days=1), "notified_at": None, "slot_availabilities": {}},
        {"id": "r3", "invite_id": None, "respondent_email": "fresh@y.ch", "respondent_name": "F",
         "updated_at": slot_new + td(hours=2), "notified_at": None, "slot_availabilities": {}},
        {"id": "r4", "invite_id": None, "respondent_email": "old@y.ch", "respondent_name": "O",
         "updated_at": t0, "notified_at": None, "slot_availabilities": {}},
    ])
    inv_sent, upd_sent, marked = [], [], []
    monkeypatch.setattr(web, "send_invite_email", lambda to, *a, **k: inv_sent.append(to) or True)
    monkeypatch.setattr(web, "send_update_emails",
                        lambda recipients, *a, **k: upd_sent.append(recipients[0]) or 1)
    monkeypatch.setattr(web, "mark_invite_notified", lambda iid: marked.append(("inv", iid)))
    monkeypatch.setattr(web, "mark_response_notified", lambda rid: marked.append(("resp", rid)))

    r = client.post("/scheduler/polls/p1/remind", data={}, follow_redirects=False)
    assert "msg=nudged&inv=1&upd=2" in r.headers["location"]
    assert inv_sent == ["pending@x.ch"]                    # pending+cold only
    urls = dict(upd_sent)
    assert set(urls) == {"stale@x.ch", "old@y.ch"}         # stale only
    assert "/scheduler/p/i/tc" in urls["stale@x.ch"]       # invitee -> personal link
    assert "/scheduler/p/tok123" in urls["old@y.ch"]       # respondent -> public link
    assert ("inv", "i1") in marked and ("inv", "i3") in marked and ("resp", "r4") in marked


def test_nudge_idempotent_when_everyone_current(client, owner, monkeypatch):
    """Second click sends nothing: everyone responded after the latest slots."""
    from datetime import datetime as dt
    t0 = dt(2026, 6, 1, 12, 0)
    poll = dict(POLL, slots=[dict(s, created_at=t0) for s in POLL["slots"]])
    monkeypatch.setattr(web, "get_poll", lambda pid: poll)
    monkeypatch.setattr(web, "get_invites", lambda pid: [
        {"id": "i1", "email": "done@x.ch", "token": "ta", "responded": True, "notified_at": None},
    ])
    monkeypatch.setattr(web, "get_responses", lambda pid: [
        {"id": "r1", "invite_id": "i1", "respondent_email": "done@x.ch", "respondent_name": "D",
         "updated_at": t0.replace(hour=13), "notified_at": None, "slot_availabilities": {}},
    ])
    sends = []
    monkeypatch.setattr(web, "send_invite_email", lambda *a, **k: sends.append(1) or True)
    monkeypatch.setattr(web, "send_update_emails", lambda *a, **k: sends.append(1) or 1)
    r = client.post("/scheduler/polls/p1/remind", data={}, follow_redirects=False)
    assert "msg=nonudge" in r.headers["location"]
    assert not sends


def test_participant_states():
    from datetime import datetime as dt
    from datetime import timedelta as td

    from kairos.helpers import participant_states
    t0 = dt(2026, 6, 1, 12, 0)
    poll = dict(POLL, slots=[dict(POLL["slots"][0], created_at=t0),
                             dict(POLL["slots"][1], created_at=t0 + td(days=3))])
    invites = [
        {"id": "i1", "email": "pend@x.ch", "required": True},
        {"id": "i2", "email": "old@x.ch", "required": False},
    ]
    responses = [
        {"id": "r1", "invite_id": "i2", "respondent_email": "old@x.ch", "respondent_name": "O",
         "updated_at": t0 + td(days=1), "slot_availabilities": {}},
        {"id": "r2", "invite_id": None, "respondent_email": "walk@y.ch", "respondent_name": "W",
         "updated_at": t0 + td(days=4), "slot_availabilities": {}},
    ]
    log = [
        {"email": "pend@x.ch", "kind": "reminder", "sent_at": t0 + td(days=2)},
        {"email": "pend@x.ch", "kind": "invite", "sent_at": t0},
    ]
    rows = {r["email"]: r for r in participant_states(poll, responses, invites, log)}
    assert rows["pend@x.ch"]["state"] == "pending"
    assert rows["pend@x.ch"]["last_contact"]["kind"] == "reminder"
    assert len(rows["pend@x.ch"]["contacts"]) == 2
    assert rows["old@x.ch"]["state"] == "stale"      # responded before newest slot
    assert rows["old@x.ch"]["required"] is False
    assert rows["walk@y.ch"]["state"] == "current"   # responded after
    assert rows["walk@y.ch"]["invited"] is False


def test_remind_selected_forces_and_logs(client, owner, monkeypatch):
    """Operator-picked addresses get mail regardless of cooldown; all logged."""
    from datetime import datetime as dt
    from datetime import timedelta as td
    now = dt.now()
    monkeypatch.setattr(web, "get_invites", lambda pid: [
        # in cooldown — force overrides it
        {"id": "i1", "email": "cool@x.ch", "token": "ta", "responded": False,
         "notified_at": now - td(hours=1)},
        # not selected — untouched
        {"id": "i2", "email": "other@x.ch", "token": "tb", "responded": False, "notified_at": None},
    ])
    monkeypatch.setattr(web, "get_responses", lambda pid: [])
    sent, logged = [], []
    monkeypatch.setattr(web, "send_invite_email", lambda to, *a, **k: sent.append(to) or True)
    monkeypatch.setattr(web, "log_contact", lambda pid, email, kind, iid=None: logged.append((email, kind)))
    monkeypatch.setattr(web, "mark_invite_notified", lambda iid: None)
    monkeypatch.setattr(web, "mark_response_notified", lambda rid: None)
    r = client.post("/scheduler/polls/p1/remind-selected",
                    data={"emails": ["cool@x.ch"]}, follow_redirects=False)
    assert "msg=nudged&inv=1" in r.headers["location"]
    assert sent == ["cool@x.ch"]                 # cooldown bypassed, other not mailed
    assert logged == [("cool@x.ch", "reminder")]  # audit trail written


def test_invite_rejects_fake_email(client, owner, monkeypatch):
    monkeypatch.setattr(web, "get_invites", lambda pid: [])
    r = client.post("/scheduler/polls/p1/invite", data={"email": "test@test"})
    assert r.status_code == 400 and "valid email" in r.text
    monkeypatch.setattr(web, "create_invite", lambda pid, email, required=True, name=None:
                        {"id": "i9", "token": "t9", "email": email})
    r = client.post("/scheduler/polls/p1/invite",
                    data={"email": "Real.Person@example.org"}, follow_redirects=False)
    assert r.status_code == 302
