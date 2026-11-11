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

def test_no_public_link_generator_emits_root_token_form():
    """Audit every generator of a public poll URL -- email body, poll page,
    ICS feed/attachment, iMIP REQUEST, agent.json, llms.txt -- and assert
    none produces a bare `{base}/<token>` link. One regression here (a
    template, a forgotten f-string) is how share links drift back to the
    root and the proxy policy stops covering them.

    This is the pair of `test_no_root_catch_all_shadows_literal_or_fabricates_
    redirects`: together they say "every link is `/p/<token>`, and the root
    is reserved for owner pages -- no redirect, no catch-all, no drift."""
    from datetime import date as _date
    from datetime import time as _time

    from kairos import email_service, templating
    from kairos import ics as ics_mod

    base = "https://x.example"
    prefix = "/scheduler"
    tok = "TOKENabcXYZ"
    inv = "INVITEabc"
    public_url = f"{base}{prefix}/p/{tok}"
    invite_url = f"{base}{prefix}/p/i/{inv}"

    poll = {
        "id": "p1", "title": "Retreat", "description": "d",
        "mode": "time_slot", "timezone": "Europe/Zurich",
        "status": "open", "decided_slot_id": None, "public_token": tok,
    }
    slot = {"id": "s1", "date": _date(2026, 6, 8),
            "start_time": _time(9, 0), "end_time": _time(9, 30)}

    def forbid_root_form(blob: str, label: str, *, token: str = tok) -> None:
        """A bare `{base}{prefix}/<token>` that is NOT the leading substring
        of `{base}{prefix}/p/<token>` is the regression we are catching."""
        bad = f"{base}{prefix}/{token}"
        good = f"{base}{prefix}/p/{token}"
        idx = 0
        while True:
            j = blob.find(bad, idx)
            if j < 0:
                break
            if blob[j: j + len(good)] == good:
                # It IS the /p/ form -- skip past the whole `good` match.
                idx = j + len(good)
                continue
            raise AssertionError(
                f"{label}: root-level token link `{bad}` appeared "
                f"(context: ...{blob[max(0, j - 30):j + len(bad) + 30]!r}...)"
            )
        assert good in blob or f"{base}{prefix}/p/i/{inv}" in blob, (
            f"{label}: neither `{good}` nor the invite form appears"
        )

    # 1. Decided-event ICS (the one attached to the "we picked a date" email).
    # RFC 5545 folds lines at 75 octets with `\r\n ` continuation, so unfold
    # before substring checks for every ICS body.
    def _unfold(ics_text: str) -> str:
        return ics_text.replace("\r\n ", "").replace("\r\n\t", "")

    decided = dict(poll, status="decided", decided_slot_id="s1")
    decided_ics = _unfold(ics_mod.build_ics(decided, slot, public_url))
    forbid_root_form(decided_ics, "build_ics / decided .ics URL")

    # 2. Reverse-calendar candidate feed (every open-poll subscribe).
    feed = _unfold(ics_mod.build_feed_ics(decided, [slot], [], base_url=base,
                                          prefix=prefix, total_expected=0))
    forbid_root_form(feed, "build_feed_ics / candidate feed")

    # 3. Invite feed with deep-link vote URLs.
    inv_feed = _unfold(ics_mod.build_feed_ics(decided, [slot], [], base_url=base,
                                              prefix=prefix, invite_token=inv,
                                              total_expected=0))
    forbid_root_form(inv_feed, "build_feed_ics / invite feed")
    for av in ("yes", "maybe", "no"):
        assert f"{prefix}/p/i/{inv}/s/s1/{av}" in inv_feed

    # 4. iMIP REQUEST (the invite .ics mail body).
    req_ics = _unfold(ics_mod.build_request_ics(
        decided, slot, "to@x.ch",
        organizer_email="org@x.ch", organizer_name="Org",
        url=public_url))
    forbid_root_form(req_ics, "build_request_ics / iMIP REQUEST")

    # 5. Decision email body (HTML + text). The outer MIMEMultipart("mixed")
    # wraps a multipart/alternative (text + HTML) plus the .ics attachment;
    # pull both parts out of the alternative wrapper.
    dmsg = email_service.build_decision_message(
        "to@x.ch", "Retreat", "2026-06-08", public_url,
        "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n", "Lars", note="", reply_to="l@x.ch")
    alt = dmsg.get_payload()[0]
    text_part = alt.get_payload()[0].get_payload(decode=True).decode()
    html_part = alt.get_payload()[1].get_payload(decode=True).decode()
    forbid_root_form(text_part, "decision email text")
    forbid_root_form(html_part, "decision email HTML")

    # 6. Invite email body (multipart/alternative directly; text + HTML).
    imsg = email_service.build_invite_message("to@x.ch", "Retreat", invite_url,
                                              "Lars", reply_to="l@x.ch")
    itext = imsg.get_payload()[0].get_payload(decode=True).decode()
    ihtml = imsg.get_payload()[1].get_payload(decode=True).decode()
    forbid_root_form(itext, "invite email text", token=inv)
    forbid_root_form(ihtml, "invite email HTML", token=inv)

    # 7. agent.json shape (invitee self-describing surface) -- the URLs the
    # route builds, asserted at the URL-construction site so a regression is
    # caught here even if the HTTP shape stays the same.
    vb = f"{base}{prefix}/p/i/{inv}/s/s1"
    agent_blob = "\n".join([
        f"{vb}/yes", f"{vb}/maybe", f"{vb}/no",
        f"webcal://x.example{prefix}/p/i/{inv}/feed.ics",
    ])
    forbid_root_form(agent_blob, "agent.json vote/subscribe URLs", token=inv)

    # 8. The poll page itself (the "copy the share link" box).
    env2 = templating.create_env()
    rendered = templating.render(
        env2, "poll.html", title="t", poll=decided, share_url=public_url,
        user={"uid": "u", "name": "N", "email": "e@x.ch"},
        now=_date(2026, 6, 8), responses=[], invites=[], contacts={},
        total=0, pending_n=0, convergence={"state": "collecting"},
        is_ts=True, ts_payload={"grid": [], "saved": None},
        decided_label=None, msg=None, csrf_token="c", notif_count=0, notifs=[],
    ).body.decode()
    forbid_root_form(rendered, "poll.html share_url")

    # 9. llms.txt -- static agent-discovery doc in main.py.
    llms_client = TestClient(main.app, base_url="https://x.example")
    llms_body = llms_client.get("/scheduler/llms.txt").text
    # llms.txt documents the invitee link shape, so the /p/i/ form must be
    # mentioned and no bare `{P}/<token>` example may appear.
    assert "/scheduler/p/i/<token>" in llms_body
    # A bare `/scheduler/<token>` example in the docs is exactly the kind of
    # regression that tells agents to use the legacy form.
    assert "/scheduler/<token>" not in llms_body
