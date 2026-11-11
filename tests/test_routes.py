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



# -- Issue #88: public voting lives under /p/, the root stays clean --
#
# Two regression guards for the proxy contract the README's "Protecting owner
# pages with a reverse proxy" section rests on: (1) every public-link
# generator emits the `{P}/p/...` form, so a bypass policy on `/p` covers
# every share link, and (2) no root-level catch-all exists that would turn
# `/scheduler/<anything>` into a 301 — such a catch-all would 301 unknown
# pages (which the client caches forever), silently rewrite POSTs to
# GET-only routes (`POST /scheduler/health` -> `/scheduler/p/health`), and
# make a `host/*` Cloudflare Access bypass unsafely cover the owner surface.


def test_no_root_catch_all_shadows_literal_or_fabricates_redirects():
    """The app must NOT register a greedy `/{token}` (or `/{token}/event.ics`,
    or POST `/{token}`) at the root of the prefix. Three failure modes we are
    guarding against: a bogus GET at the root path 301s to `/p/<bogus>`
    (confuses CDN caches and SEO), a POST to an unknown root path 307s to
    `/p/...` (silently rewrites a method a GET-only literal should 405 for),
    and a GET `/foo.ics` 301s to `/p/foo.ics` (makes the proxy's bypass
    policy on `/p` accidentally relevant to root paths).

    Enumerated here so a future PR that re-introduces a catch-all under the
    prefix root (however well-intentioned) breaks this test. A later route
    that lives under `/p/...`, `/v/...`, `/api/...` is fine -- the probes
    below only hit the bare root of the prefix.
    """
    probe = TestClient(main.app, base_url="https://testserver",
                       raise_server_exceptions=False)

    # Bogus one-segment root paths. Each one must either answer itself (a
    # literal route that happens to share the name -- 200, 401, 404, 405...)
    # or 404 -- never a 301/307 to `{P}/p/<name>`.
    bogus = [
        ("GET", "/scheduler/does-not-exist-abc"),
        ("GET", "/scheduler/favicon.ico"),
        ("GET", "/scheduler/does-not-exist-abc/event.ics"),
        ("POST", "/scheduler/does-not-exist-abc"),
    ]
    for method, path in bogus:
        resp = probe.request(method, path, follow_redirects=False)
        loc = resp.headers.get("location", "")
        assert not (resp.status_code in (301, 307) and loc.startswith("/scheduler/p/")), (
            f"{method} {path} is being swallowed by a root catch-all: "
            f"status={resp.status_code} location={loc} -- a bypass on `/p` "
            f"must not reach arbitrary root paths through a redirect."
        )
        # And a truly unknown one-segment path must 404 -- not 200, not 405.
        assert resp.status_code == 404, (
            f"{method} {path} answered {resp.status_code}; an unknown root "
            f"path must 404 so the reverse proxy's path-prefix policy stays "
            f"meaningful (no catch-all under the prefix root)."
        )


def test_literal_single_segment_routes_answer_themselves():
    """Walking the live route table, every literal single-segment path
    registered under the prefix answers itself (never a redirect built from
    its name). If a future PR adds a root catch-all that swallows these,
    this test fails together with the one above.

    Enumerated below (not just inferred from the walk) so a new literal
    someone forgets to register also shows up here.
    """
    def _walk(router):
        # This FastAPI version keeps `include_router` as an `_IncludedRouter`
        # wrapper rather than flattening, so a plain `app.routes` walk finds
        # no endpoints under included routers (identical pattern to the
        # route-audit in tests/test_ratelimit.py).
        for route in getattr(router, "routes", []):
            inner = getattr(route, "original_router", None)
            if inner is not None:
                yield from _walk(inner)
            elif getattr(route, "routes", None):
                yield from _walk(route)
            else:
                yield route

    literals = set()
    for route in _walk(main.app):
        path = getattr(route, "path", None) or ""
        if type(route).__name__ == "Mount":
            # The /static mount matches by prefix; it is not a single-segment
            # literal and is probed separately below.
            continue
        if not path.startswith("/scheduler"):
            continue
        rest = path[len("/scheduler"):].lstrip("/")
        if "/" in rest or "{" in rest:
            continue
        for method in getattr(route, "methods", {"GET"}) - {"HEAD"}:
            literals.add((method, path))

    expected = {
        ("GET", "/scheduler/"),              # dashboard
        ("GET", "/scheduler/new"),           # new poll page
        ("POST", "/scheduler/new"),          # create poll submit
        ("GET", "/scheduler/manage"),        # capability console entry
        ("GET", "/scheduler/tokens"),        # owner API-token panel
        ("POST", "/scheduler/tokens"),       # mint owner token
        ("GET", "/scheduler/login"),         # OIDC sign-in page
        ("GET", "/scheduler/health"),        # liveness/readiness probe
        ("GET", "/scheduler/llms.txt"),      # agent discovery
        ("GET", "/scheduler/robots.txt"),    # crawler policy
    }
    assert expected <= literals, f"missing literal routes: {sorted(expected - literals)}"

    probe = TestClient(main.app, base_url="https://testserver",
                       raise_server_exceptions=False)
    for method, path in sorted(literals):
        if method != "GET":
            # GET is enough to show the route answers itself. POST literals
            # (`/new`, `/tokens`) would need CSRF and are covered by the
            # route-table enumeration above.
            continue
        resp = probe.request(method, path, follow_redirects=False)
        # A literal route may answer 200, 401, 404, 503, ... -- the one answer
        # it must never give is "301/307 -> /scheduler/p/<name>".
        loc = resp.headers.get("location", "")
        assert not (resp.status_code in (301, 307) and loc.startswith("/scheduler/p/")), (
            f"{method} {path} is shadowed by a root catch-all: "
            f"status={resp.status_code} location={loc}"
        )


def test_static_mount_serves_assets(client):
    """Static assets serve under `/static/...`. Not directly about #88 --
    sanity-checks that the mount isn't accidentally broken by a future root
    change (a catch-all or a middleware)."""
    r = client.get("/scheduler/static/grid.js", follow_redirects=False)
    assert r.status_code == 200
    assert "javascript" in r.headers["content-type"]


# -- Issue #88: every public-link generator emits the /p/ form --
#
# The audit here drives the REAL routes (web form, API, public, capability
# manage console) against a real SQLite DB with a fake SMTP relay, captures
# everything they emit (HTTP response bodies, sent mail bodies, llms.txt), and
# refuses any URL whose path is the bare `{P}/<token>` form for a poll's
# `public_token` or an invite's `token`.
#
# Driving the routes (rather than hand-constructing URLs and calling the link
# builders directly) is the test's teeth: every one-line revert to the bare
# form at web.py's `share_url` (owner view), api.py's `_share_url`, public.py's
# agent.json vote URLs, web.py's nudge/reminder invite URL, and the capability
# console's share link / decision poll URL — breaks this guard, because each of
# those sites is on the path of one of the responses or emails we scan.


def _forbid_bare_token_form(blob: str, label: str, *, token: str,
                            prefix: str, good_leaders: tuple,
                            host_anchor: str = "testserver") -> None:
    """A bare `{host}{prefix}/{token}` substring that is NOT part of any good
    form (`{host}{prefix}/<leader>/{token}` for `leader` in `good_leaders`) is
    the regression we are catching.

    The hostname is in the anchor on purpose: without it, `/{token}` at an
    empty prefix is a substring of `/p/{token}` (position 2, after the `/p`)
    and would false-positive. Every URL emitted here is built from
    `get_base_url(request)` or `request.url.hostname`, so the TestClient's
    `base_url='https://testserver'` makes `testserver` a reliable anchor. The
    substring search is otherwise scheme-agnostic: `https://x/<P>/<tok>` and
    `webcal://x/<P>/<tok>` would both be caught.
    """
    bad = f"{host_anchor}{prefix}/{token}"
    goods = tuple(f"{host_anchor}{prefix}/{leader}/{token}"
                  for leader in good_leaders)
    idx = 0
    while True:
        j = blob.find(bad, idx)
        if j < 0:
            break
        matched = next((g for g in goods if blob[j:j + len(g)] == g), None)
        if matched:
            idx = j + len(matched)
            continue
        raise AssertionError(
            f"{label}: bare `{bad}` found where only {goods} are allowed "
            f"(context: ...{blob[max(0, j - 40):j + len(bad) + 40]!r}...)"
        )


def _unfold_ics(blob: str) -> str:
    """RFC 5545 folds at 75 octets with `\r\n ` continuation; unfold so the
    token substring is contiguous when it sits across a fold boundary.
    `\r\n\t` is the older HTAB-folded form some writers still emit."""
    return blob.replace("\r\n ", "").replace("\r\n\t", "")


def _decoded_parts(msg) -> list[str]:
    """Return each leaf payload of an email message as decoded text.

    `msg.as_string()` encodes text/plain and text/html parts as base64 (the
    default Content-Transfer-Encoding here), which hides the URL substrings a
    scan of the raw stringification would otherwise see. Walk the tree,
    decode each leaf, and return it as str — so a reminder URL sitting in a
    base64-encoded text/plain body is still auditable.
    """
    parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            parts.append(payload.decode(charset, errors="replace"))
        except (LookupError, UnicodeDecodeError):
            parts.append(payload.decode("utf-8", errors="replace"))
    return parts


def test_link_generators_through_real_code_paths(tmp_path, monkeypatch):
    """E2E audit: drive the REAL routes against a real SQLite poll with
    FEED+IMIP on and SMTP captured, then assert every outbound URL carrying a
    poll-scoped token is under the `{P}/p/` or `{P}/p/i/` form.

    Surfaces exercised, with the link generator in parentheses:

    - Create poll via web form (`POST /new`) + list via `GET /` (web.py)
    - Create / list / detail via API (api.py:`_share_url`)
    - API `event.ics` for an open poll — serves the candidate feed
      (ics.build_feed_ics)
    - Owner view of the poll page (web.py's `share_url`, rendered into
      poll.html) — mutation #1 target
    - Invite via web form, invite via API (api.py:`invite_url`) — the API
      response carries the invite URL; the API also sends an invite email,
      whose body contains the URL
    - Nudge via web (`POST /polls/{id}/remind`) — sends a reminder email with
      the invite URL from web.py:`url = f"{base}{P}/p/i/{inv['token']}"` —
      mutation #4 target
    - Decide + email-decision via web and API — decision email with the ICS
      attachment (ics.build_ics) and the poll URL (web.py:`poll_url` /
      api.py:`_share_url`)
    - API `imip-decision` — iMIP REQUEST email with poll URL (also an ics.py
      build_request_ics path through the deep-link `{v}/<code>` short-link
      affordance, which this guard checks is never the bare root form)
    - Public pages: `GET /p/<token>`, `/p/<token>/event.ics` (decided + open),
      `/p/i/<token>`, `/p/i/<token>/feed.ics`, `/p/i/<token>/agent.json`
      (public.py:`vb` — mutation #3 target)
    - `GET /llms.txt` — the static agent-discovery doc; a bare `{P}/<token>`
      example there would tell agents to use the legacy form

    Separately: `test_link_generators_through_real_code_paths_empty_prefix`
    reruns this audit's core surfaces under `KAIROS_PREFIX=''` in a fresh
    interpreter, so the module-level `P = settings.PREFIX` consumers are
    re-imported rather than patched after the fact.
    """
    from kairos import api, db, email_service, main, settings, web  # noqa: F401
    from kairos.csrf import make_csrf

    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/k.db")
    monkeypatch.setenv("KAIROS_API_KEY", "k")
    monkeypatch.setattr(settings, "FEED_ENABLED", True)
    monkeypatch.setattr(settings, "IMIP_ENABLED", True)
    monkeypatch.setattr(settings, "IMIP_ORGANIZER", "replies@kairos.example")
    monkeypatch.setattr(settings, "IMIP_ORGANIZER_NAME", "Kairos")

    sent: list = []

    class _FakeSMTP:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def send_message(self, msg):
            sent.append(msg)

    monkeypatch.setattr(email_service, "SMTP_HOST", "smtp.example.net")
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@example.org")
    monkeypatch.setattr(email_service, "_smtp_session", lambda: _FakeSMTP())
    monkeypatch.setattr(email_service, "_last_refusal_logged", None)

    prefix = "/scheduler"
    hdr = {"X-User": "owner", "X-Email": "owner@x.ch", "X-Name": "Owner"}
    api_hdr = {"Authorization": "Bearer k"}
    csrf_owner = make_csrf("owner")

    # Every body we must audit, collected as (label, text). Email bodies are
    # appended after the client exits, so one flat list covers every surface.
    scanned: list[tuple[str, str]] = []

    def scan(label: str, resp) -> str:
        """Capture a response body for the audit and return it unchanged."""
        body = resp.text if hasattr(resp, "text") else str(resp)
        scanned.append((label, body))
        return body

    with TestClient(main.create_app(), base_url="https://testserver",
                    headers=hdr) as c:
        # ---- 1. Create a poll via the web form.
        r = c.post(f"{prefix}/new", data={
            "title": "WebPoll", "mode": "full_day",
            "timezone": "Europe/Zurich",
            "dates": ["2026-06-08", "2026-06-09"],
            "csrf": csrf_owner,
        }, follow_redirects=False)
        assert r.status_code == 302, r.text

        web_poll = next(p for p in db.list_polls() if p["title"] == "WebPoll")
        pid_w, tok_w = web_poll["id"], web_poll["public_token"]

        # ---- 2. Create a poll via the API; the response includes `share_url`.
        r = c.post(f"{prefix}/api/polls", headers=api_hdr, json={
            "title": "ApiPoll", "mode": "time_slot", "creator": "owner",
            "slots": [{"date": "2026-07-06", "start_time": "09:00",
                       "end_time": "09:30"},
                      {"date": "2026-07-06", "start_time": "09:30",
                       "end_time": "10:00"}],
        })
        assert r.status_code == 200, r.text
        api_poll = r.json()
        pid_a, tok_a = api_poll["id"], api_poll["public_token"]
        scan("POST /api/polls", r)

        # ---- 3. API GETs: list, detail, event.ics (open -> feed).
        scan("GET /api/polls (list)",
             c.get(f"{prefix}/api/polls", headers=api_hdr))
        scan("GET /api/polls/{id}",
             c.get(f"{prefix}/api/polls/{pid_a}", headers=api_hdr))
        scan("GET /api/polls/{id}/event.ics (open=feed)",
             c.get(f"{prefix}/api/polls/{pid_a}/event.ics", headers=api_hdr))

        # ---- 4. Owner view (web). Renders `share_url` into poll.html —
        #         mutation #1's target (web.py:611).
        r = c.get(f"{prefix}/polls/{pid_w}")
        assert r.status_code == 200, r.text
        scan("GET /polls/{id} (owner view)", r)
        # Dashboard — exercises the list page too.
        scan("GET / (dashboard)", c.get(f"{prefix}/"))

        # ---- 5. Invite via the web form and via the API.
        r = c.post(f"{prefix}/polls/{pid_w}/invite", data={
            "email": "alice@x.ch", "csrf": csrf_owner,
        }, follow_redirects=False)
        assert r.status_code == 302, r.text
        inv_w = next(i for i in db.get_invites(pid_w) if i["email"] == "alice@x.ch")
        tok_iw = inv_w["token"]

        r = c.post(f"{prefix}/api/polls/{pid_a}/invite", headers=api_hdr,
                   json={"emails": ["bob@x.ch"], "required": True})
        assert r.status_code == 200, r.text
        scan("POST /api/polls/{id}/invite", r)
        inv_a = next(i for i in db.get_invites(pid_a) if i["email"] == "bob@x.ch")
        tok_ia = inv_a["token"]

        # ---- 6. Remind via the web (POST /polls/{id}/remind). Alice is a
        #         pending+cold invite, so the nudge engine sends her a reminder
        #         email whose URL comes from web.py:873 — mutation #4's target.
        r = c.post(f"{prefix}/polls/{pid_w}/remind", data={"csrf": csrf_owner},
                   follow_redirects=False)
        assert r.status_code == 302, r.text
        assert "msg=nudged&inv=1" in r.headers["location"], r.headers

        # ---- 7. API nudge for the same reason on the API poll.
        r = c.post(f"{prefix}/api/polls/{pid_a}/nudge", headers=api_hdr,
                   json={"force": False, "emails": None})
        assert r.status_code == 200, r.text
        scan("POST /api/polls/{id}/nudge", r)

        # ---- 8. Decide + email-decision on the web poll. The decision email
        #         carries the poll URL (web.py:967) and the .ics (ics.build_ics).
        slots_w = db.get_poll(pid_w)["slots"]
        r = c.post(f"{prefix}/polls/{pid_w}/decide", data={
            "slot_id": slots_w[0]["id"], "csrf": csrf_owner,
        }, follow_redirects=False)
        assert r.status_code == 302, r.text

        r = c.post(f"{prefix}/polls/{pid_w}/email-decision", data={
            "note": "see you then", "csrf": csrf_owner,
        }, follow_redirects=False)
        assert r.status_code == 302, r.text

        # ---- 9. Decide + email-decision + imip-decision on the API poll.
        slots_a = db.get_poll(pid_a)["slots"]
        r = c.post(f"{prefix}/api/polls/{pid_a}/decide", headers=api_hdr,
                   json={"slot_id": slots_a[0]["id"]})
        assert r.status_code == 200, r.text
        scan("POST /api/polls/{id}/decide", r)

        r = c.post(f"{prefix}/api/polls/{pid_a}/email-decision",
                   headers=api_hdr, json={"note": "final"})
        assert r.status_code == 200, r.text
        scan("POST /api/polls/{id}/email-decision", r)

        r = c.post(f"{prefix}/api/polls/{pid_a}/imip-decision",
                   headers=api_hdr)
        assert r.status_code == 200, r.text
        scan("POST /api/polls/{id}/imip-decision", r)

        # ---- 10. Public surfaces.
        scan("GET /p/<token> (public page)",
             c.get(f"{prefix}/p/{tok_w}"))
        scan("GET /p/<token>/event.ics (decided)",
             c.get(f"{prefix}/p/{tok_w}/event.ics"))
        # The API poll is also decided — its public page + ics exercises
        # another path through _share_url / build_ics.
        scan("GET /p/<tok-api>", c.get(f"{prefix}/p/{tok_a}"))
        scan("GET /p/<tok-api>/event.ics",
             c.get(f"{prefix}/p/{tok_a}/event.ics"))

        # Invite pages + feed + agent.json. public.py:310's `vb` is mutation
        # #3's target; agent.json is where that line surfaces.
        scan("GET /p/i/<tok> (invite page)",
             c.get(f"{prefix}/p/i/{tok_iw}"))
        scan("GET /p/i/<tok>/feed.ics",
             c.get(f"{prefix}/p/i/{tok_iw}/feed.ics"))
        scan("GET /p/i/<tok>/agent.json",
             c.get(f"{prefix}/p/i/{tok_iw}/agent.json"))
        scan("GET /p/i/<tok-api>/agent.json",
             c.get(f"{prefix}/p/i/{tok_ia}/agent.json"))

        # ---- 11. llms.txt — the agent-discovery doc; a bare `{P}/<token>`
        #          example there would tell agents to use the legacy form.
        llms_body = scan("GET /llms.txt", c.get(f"{prefix}/llms.txt"))
        assert f"{prefix}/p/i/<token>" in llms_body
        assert f"{prefix}/<token>" not in llms_body

    # ---- 12. Email bodies (what the fake SMTP captured). text/plain and
    #          text/html parts default to base64 Content-Transfer-Encoding,
    #          which hides the URL substrings from a scan of `msg.as_string()`;
    #          `_decoded_parts` walks the tree and decodes each leaf. ICS
    #          attachments are also decoded here (as text/calendar), with the
    #          `\r\n ` continuation lines unfolded so a folded token substring
    #          is contiguous.
    assert sent, "expected the fake SMTP to have captured some messages"
    for i, msg in enumerate(sent):
        subj = msg["Subject"] or "(no subject)"
        for k, part in enumerate(_decoded_parts(msg)):
            scanned.append((f"SMTP #{i} part #{k}: {subj!r}",
                            _unfold_ics(part)))

    # ---- 13. The audit itself.
    # The poll's `public_token` may ONLY appear in a URL as `{P}/p/{token}`.
    # An invite's `token` may ONLY appear as `{P}/p/i/{token}`. The short-link
    # table maps `{P}/v/<code>` to `/p/i/<token>/s/...`, resolved server-side,
    # so a /v/ short link does not contain the raw token and the audit never
    # sees it in a bare form.
    token_leaders = [
        (tok_w, ("p",)),
        (tok_a, ("p",)),
        (tok_iw, ("p/i",)),
        (tok_ia, ("p/i",)),
    ]
    for token, leaders in token_leaders:
        for label, body in scanned:
            _forbid_bare_token_form(_unfold_ics(body), label,
                                    token=token, prefix=prefix,
                                    good_leaders=leaders)

    # ---- 14. Positive assertions: every link we expected to see appeared at
    #          least once. A guard that passes because the body was EMPTY
    #          (SMTP never captured anything, a route 500'd silently) must
    #          itself fail; this closes that loophole.
    want = {
        f"{prefix}/p/{tok_w}":  "share link for web poll",
        f"{prefix}/p/{tok_a}":  "share link for API poll",
        f"{prefix}/p/i/{tok_iw}": "invite link for web invite",
        f"{prefix}/p/i/{tok_ia}": "invite link for API invite",
    }
    seen = dict.fromkeys(want, 0)
    for _label, body in scanned:
        unfolded = _unfold_ics(body)
        for k in want:
            if k in unfolded:
                seen[k] += 1
    missing = [f"{k} ({v})" for k, v in want.items() if seen[k] == 0]
    assert not missing, f"never saw the /p/ form for: {missing}"


def test_link_generators_through_real_code_paths_capability_mode(tmp_path, monkeypatch):
    """Same audit, on the capability-mode routes — the one surface with its
    own link generators: the mailed `/manage/<admin_token>` link and the
    console's `share_url` + decision `poll_url` (capability.py:880, 1361).

    Exercised:

    - Anon creation via `POST /new` — the manage link is MAILED, body captured
    - `GET  /manage/<token>` — interstitial, renders `manage_path`
    - `POST /manage/<token>` — exchange, mints capability cookie, 302 to
      `/manage`
    - `GET  /manage` — console (share_url + capability.py's templates)
    - `POST /manage/link` — "email me a new link", second manage email
    - `POST /manage/<id>/decide` and `/email-decision` — capability.py:1361
    """
    from kairos import capability, db, email_service, main, settings, web
    from kairos.csrf import make_csrf

    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/k.db")
    monkeypatch.setattr(settings, "AUTH_MODE", "capability")
    monkeypatch.setitem(web.env.globals, "CAPABILITY", True)
    monkeypatch.setattr(settings, "FEED_ENABLED", True)

    sent: list = []

    class _FakeSMTP:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def send_message(self, msg):
            sent.append(msg)

    monkeypatch.setattr(email_service, "SMTP_HOST", "smtp.example.net")
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@example.org")
    monkeypatch.setattr(email_service, "_smtp_session", lambda: _FakeSMTP())
    monkeypatch.setattr(email_service, "_last_refusal_logged", None)

    prefix = "/scheduler"
    scanned: list[tuple[str, str]] = []

    with TestClient(main.create_app(), base_url="https://testserver") as c:
        # ---- 1. Anon poll creation. Mails the manage link.
        r = c.post(f"{prefix}/new", data={
            "title": "CapPoll", "creator_email": "ada@example.org",
            "mode": "full_day", "timezone": "Europe/Zurich",
            "dates": ["2026-12-01", "2026-12-02"],
            "csrf": make_csrf(capability.ANON_FORM_UID),
        }, follow_redirects=False)
        assert r.status_code == 200, r.text  # success renders a page here
        scanned.append(("POST /new (accountless)", r.text))
        assert sent, "capability-mode create must have mailed a manage link"
        # Grab the admin token from the DB — it is NOT in any HTTP response.
        poll = next(p for p in db.list_polls() if p["title"] == "CapPoll")
        pid, tok_pub = poll["id"], poll["public_token"]
        admin_token = poll["admin_token"]

        # ---- 2. GET interstitial, POST exchange, GET console.
        r = c.get(f"{prefix}/manage/{admin_token}")
        assert r.status_code == 200, r.text
        scanned.append(("GET /manage/<token>", r.text))

        r = c.post(f"{prefix}/manage/{admin_token}", data={},
                   follow_redirects=False)
        assert r.status_code == 302, r.text
        assert r.headers["location"] == f"{prefix}/manage"

        # The exchange rotated the admin token; use the new one.
        admin_token = db.get_poll(pid)["admin_token"]

        r = c.get(f"{prefix}/manage")
        assert r.status_code == 200, r.text
        scanned.append(("GET /manage (console)", r.text))

        # ---- 3. Re-link: "email me a new manage link" — second manage email.
        r = c.post(f"{prefix}/manage/link", data={
            "email": "ada@example.org",
            "csrf": make_csrf(capability.LINK_FORM_UID),
        }, follow_redirects=False)
        assert r.status_code == 200, r.text

        # ---- 4. Decide + email-decision from the console — poll_url comes
        #         from capability.py:1361.
        slot_id = db.get_poll(pid)["slots"][0]["id"]
        csrf_pid = make_csrf(pid)
        r = c.post(f"{prefix}/manage/{pid}/decide",
                   data={"slot_id": slot_id, "csrf": csrf_pid},
                   follow_redirects=False)
        assert r.status_code == 302, r.text

        # add a responder so email-decision has someone to mail
        db.add_response(pid, "Bea", "bea@example.org", {}, invite_id=None)

        r = c.post(f"{prefix}/manage/{pid}/email-decision",
                   data={"note": "fin", "csrf": csrf_pid},
                   follow_redirects=False)
        assert r.status_code == 302, r.text

    # ---- 5. Audit every captured HTTP body + email body. Email leaves are
    #          decoded (text/plain and text/html default to base64, which
    #          would otherwise hide the URL from a raw `as_string()` scan).
    for i, msg in enumerate(sent):
        subj = msg["Subject"] or "(no subject)"
        for k, part in enumerate(_decoded_parts(msg)):
            scanned.append((f"SMTP #{i} part #{k}: {subj!r}",
                            _unfold_ics(part)))

    # A public-token link must only appear as `{P}/p/<token>`; the admin token
    # may ONLY appear as `{P}/manage/<token>` and never as a bare root URL
    # — that is what the proxy bypass policy for `/manage` relies on.
    for token, leaders in [(tok_pub, ("p",)), (admin_token, ("manage",))]:
        for label, body in scanned:
            _forbid_bare_token_form(_unfold_ics(body), label,
                                    token=token, prefix=prefix,
                                    good_leaders=leaders)

    # Positive: at least one manage link under /manage/ appeared, and at least
    # one share link under /p/ appeared.
    joined = "\n".join(_unfold_ics(b) for _, b in scanned)
    assert f"{prefix}/manage/{admin_token}" in joined, \
        "the rotated manage link was never observed"
    assert f"{prefix}/p/{tok_pub}" in joined, \
        "the capability poll's share link was never observed"


def test_link_generators_through_real_code_paths_empty_prefix(tmp_path):
    """Same audit, but with `KAIROS_PREFIX=''`. A subprocess is the cheapest
    way to re-import every `P = settings.PREFIX` consumer against an empty
    prefix — reloading the modules in-process would strand references held by
    other test modules and break conftest's autouse fixture, which caches
    `kairos.capability` and `kairos.ratelimit` on first load.

    The subprocess runs a minimal re-do of the HTTP audit (poll via API, invite
    via API, nudge, agent.json) and asserts that no body carries a bare
    `/<token>` (which at prefix='' is the root form)."""
    import os
    import subprocess
    import sys
    from pathlib import Path

    script = Path(tmp_path) / "probe_empty_prefix.py"
    script.write_text(_EMPTY_PREFIX_PROBE)

    env = {**os.environ,
           "KAIROS_PREFIX": "",
           "KAIROS_AUTH": "header",
           "KAIROS_LOGIN_URL": "/login",
           "SESSION_SECRET": "dummy",
           "KAIROS_DB_URL": f"sqlite:///{tmp_path}/k.db",
           "KAIROS_FEED": "on",
           "KAIROS_IMIP": "on",
           "KAIROS_IMIP_ORGANIZER": "replies@kairos.example",
           "KAIROS_API_KEY": "k"}

    r = subprocess.run([sys.executable, str(script)], env=env,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, (
        f"empty-prefix probe failed (exit {r.returncode}):\n"
        f"STDOUT:\n{r.stdout}\n\nSTDERR:\n{r.stderr}"
    )


_EMPTY_PREFIX_PROBE = r'''"""Empty-prefix probe — runs in a subprocess under KAIROS_PREFIX=''.

Hits a subset of the routes the in-process audit hits (the ones whose URL
generators sit at a `P = settings.PREFIX` line, where `P == ""` here), and
asserts no captured body carries a bare `/{token}` that is NOT a legitimate
`/p/{token}` or `/p/i/{token}` form.
"""
import sys

from fastapi.testclient import TestClient

from kairos import api, db, email_service, main, settings, web  # noqa: F401
from kairos.csrf import make_csrf


assert settings.PREFIX == "", f"expected empty prefix, got {settings.PREFIX!r}"


sent = []


class _FakeSMTP:
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        return False
    def send_message(self, msg):
        sent.append(msg)


email_service.SMTP_HOST = "smtp.example.net"
email_service.SMTP_FROM = "kairos@example.org"
email_service._smtp_session = lambda: _FakeSMTP()
email_service._last_refusal_logged = None


def unfold(s):
    return s.replace("\r\n ", "").replace("\r\n\t", "")


def forbid(blob, label, token, leaders, host_anchor="testserver"):
    # Anchor on the hostname: without it, `/<token>` at an empty prefix is a
    # substring of `/p/<token>` (position 2 of `/p/<token>` is `/` followed
    # by the token) and would false-positive.
    bad = f"{host_anchor}/{token}"
    goods = tuple(f"{host_anchor}/{leader}/{token}" for leader in leaders)
    idx = 0
    while True:
        j = blob.find(bad, idx)
        if j < 0:
            break
        matched = next((g for g in goods if blob[j:j + len(g)] == g), None)
        if matched:
            idx = j + len(matched)
            continue
        raise AssertionError(
            f"{label}: bare `{bad}` found where only {goods} allowed "
            f"(context: ...{blob[max(0, j - 40):j + len(bad) + 40]!r}...)"
        )


hdr = {"X-User": "owner", "X-Email": "owner@x.ch", "X-Name": "Owner"}
api_hdr = {"Authorization": "Bearer k"}
csrf_owner = make_csrf("owner")

scanned = []


with TestClient(main.create_app(), base_url="https://testserver", headers=hdr) as c:
    # Create via API (returns share_url under empty prefix).
    r = c.post("/api/polls", headers=api_hdr, json={
        "title": "ApiPoll", "mode": "time_slot", "creator": "owner",
        "slots": [{"date": "2026-07-06", "start_time": "09:00",
                   "end_time": "09:30"}],
    })
    assert r.status_code == 200, r.text
    poll_a = r.json()
    pid_a = poll_a["id"]
    tok_a = poll_a["public_token"]
    scanned.append(("POST /api/polls", r.text))

    scanned.append(("GET /api/polls", c.get("/api/polls", headers=api_hdr).text))
    scanned.append(("GET /api/polls/{id}",
                    c.get(f"/api/polls/{pid_a}", headers=api_hdr).text))

    # Invite via API (sends mail; response carries invite_url).
    r = c.post(f"/api/polls/{pid_a}/invite", headers=api_hdr,
               json={"emails": ["bob@x.ch"], "required": True})
    assert r.status_code == 200, r.text
    scanned.append(("POST /api/polls/{id}/invite", r.text))
    inv_a = next(i for i in db.get_invites(pid_a) if i["email"] == "bob@x.ch")
    tok_ia = inv_a["token"]

    # Nudge via API (reminder email).
    r = c.post(f"/api/polls/{pid_a}/nudge", headers=api_hdr,
               json={"force": False, "emails": None})
    assert r.status_code == 200, r.text

    # Agent.json — public.py vote URLs.
    scanned.append(("GET /p/i/<tok>/agent.json",
                    c.get(f"/p/i/{tok_ia}/agent.json").text))

    # Public poll page + event.ics (feed, open).
    scanned.append(("GET /p/<tok>", c.get(f"/p/{tok_a}").text))
    scanned.append(("GET /p/<tok>/event.ics (feed)",
                    c.get(f"/p/{tok_a}/event.ics").text))
    scanned.append(("GET /p/i/<tok>/feed.ics",
                    c.get(f"/p/i/{tok_ia}/feed.ics").text))
    scanned.append(("GET /llms.txt", c.get("/llms.txt").text))

# Email bodies. text/plain and text/html parts default to base64
# Content-Transfer-Encoding, which hides the URL substrings from a raw
# `as_string()` scan; walk and decode each leaf instead.
def decoded_parts(msg):
    parts = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            parts.append(payload.decode(charset, errors="replace"))
        except (LookupError, UnicodeDecodeError):
            parts.append(payload.decode("utf-8", errors="replace"))
    return parts


assert sent, "expected the fake SMTP to have captured some messages"
for i, msg in enumerate(sent):
    subj = msg["Subject"] or "(no subject)"
    for k, part in enumerate(decoded_parts(msg)):
        scanned.append((f"SMTP #{i} part #{k}: {subj!r}", unfold(part)))

# Audit.
for token, leaders in [(tok_a, ("p",)), (tok_ia, ("p/i",))]:
    for label, body in scanned:
        forbid(unfold(body), label, token, leaders)

# Positive: the share link and the invite link appeared somewhere.
joined = "\n".join(unfold(b) for _, b in scanned)
assert f"testserver/p/{tok_a}" in joined, "share link under /p/ never observed"
assert f"testserver/p/i/{tok_ia}" in joined, "invite link under /p/i/ never observed"

print("empty-prefix audit OK")
sys.exit(0)
'''
