"""Bearer-API tests — full-parity agent control surface, stubbed DB."""

import datetime as _dt
import tracemalloc
from datetime import date, time

import pytest
from fastapi.testclient import TestClient

from kairos import api, capability, main

KEY = "test-api-key"

POLL = {
    "id": "p1", "creator_id": "lars", "title": "API poll", "description": None,
    "mode": "time_slot", "timezone": "Europe/Zurich", "status": "open",
    "decided_slot_id": None, "public_token": "tokA",
    "slots": [
        {"id": "t1", "date": date(2026, 6, 8), "start_time": time(9, 0), "end_time": time(9, 30)},
        {"id": "t2", "date": date(2026, 6, 8), "start_time": time(9, 30), "end_time": time(10, 0)},
    ],
}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    monkeypatch.setattr(api, "get_poll", lambda pid: dict(POLL) if pid == "p1" else None)
    monkeypatch.setattr(api, "get_responses", lambda pid: [])
    monkeypatch.setattr(api, "get_invites", lambda pid: [])
    c = TestClient(main.app, base_url="https://testserver")
    c.headers["Authorization"] = f"Bearer {KEY}"
    return c


def test_requires_bearer(client):
    assert client.get("/scheduler/api/polls/p1", headers={"Authorization": ""}).status_code == 401
    assert client.get("/scheduler/api/polls/p1",
                      headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_poll_detail_includes_convergence_and_share_url(client):
    r = client.get("/scheduler/api/polls/p1")
    assert r.status_code == 200
    data = r.json()
    assert data["convergence"]["state"] == "collecting"
    assert data["share_url"].endswith("/scheduler/p/tokA")
    assert "responses" in data and "invites" in data


def test_create_validates_creator_and_timezone(client, monkeypatch):
    r = client.post("/scheduler/api/polls", json={
        "title": "x", "mode": "full_day", "timezone": "Mars/Olympus",
        "slots": [{"date": "2026-06-08"}]})
    assert r.status_code == 400 and "timezone" in r.text.lower()


def test_create_attributes_to_real_user(client, monkeypatch):
    captured = {}
    monkeypatch.setattr(api, "create_poll",
                        lambda creator, *a: captured.update(creator=creator) or dict(POLL))
    r = client.post("/scheduler/api/polls", json={
        "title": "Agent poll", "mode": "full_day",
        "slots": [{"date": "2026-06-08"}], "creator": "lars"})
    assert r.status_code == 200
    assert captured["creator"] == "lars"
    assert r.json()["share_url"].endswith("/scheduler/p/tokA")


def test_decide_and_reopen(client, monkeypatch):
    updates = {}
    monkeypatch.setattr(api, "update_poll", lambda pid, **f: updates.update(f) or True)
    r = client.post("/scheduler/api/polls/p1/decide", json={"slot_id": "t1"})
    assert r.status_code == 200
    assert updates == {"status": "decided", "decided_slot_id": "t1"}

    assert client.post("/scheduler/api/polls/p1/decide",
                       json={"slot_id": "nope"}).status_code == 400

    updates.clear()
    r = client.patch("/scheduler/api/polls/p1", json={"status": "open"})
    assert r.status_code == 200
    assert updates == {"status": "open", "decided_slot_id": None}  # reopen clears decision

    assert client.patch("/scheduler/api/polls/p1",
                        json={"status": "decided"}).status_code == 400


def test_respond_upserts_by_email(client, monkeypatch):
    calls = {}
    monkeypatch.setattr(api, "find_response_by_email",
                        lambda pid, email: {"id": "r1"} if email == "known@x.ch" else None)
    monkeypatch.setattr(api, "update_response",
                        lambda rid, name, av, email=None: calls.update(updated=rid) or {"id": rid})
    monkeypatch.setattr(api, "add_response",
                        lambda *a, **k: calls.update(added=True) or {"id": "r2"})
    monkeypatch.setattr(api, "notify_new_response", lambda *a: None)

    r = client.post("/scheduler/api/polls/p1/respond", json={
        "name": "A", "email": "known@x.ch", "availabilities": {"t1": "yes"}})
    assert r.status_code == 200 and calls.get("updated") == "r1" and "added" not in calls

    r = client.post("/scheduler/api/polls/p1/respond", json={
        "name": "B", "email": "new@x.ch", "availabilities": {"t1": "maybe"}})
    assert r.status_code == 200 and calls.get("added")


def test_add_slots_with_notify_nudges(client, monkeypatch):
    monkeypatch.setattr(api, "add_slots", lambda pid, slots: slots)
    monkeypatch.setattr(api, "nudge_participants",
                        lambda req, poll, actor: {"invited": 0, "updated": 2, "skipped": 1})
    r = client.post("/scheduler/api/polls/p1/slots", json={
        "dates": ["2026-06-22"], "notify": True})
    assert r.status_code == 200
    data = r.json()
    assert len(data["added"]) == 2  # expanded over the 2-slot time grid
    assert data["nudged"]["updated"] == 2

    assert client.post("/scheduler/api/polls/p1/slots",
                       json={"dates": ["junk"]}).status_code == 400


def test_invite_with_required_flag(client, monkeypatch):
    created = []
    monkeypatch.setattr(api, "create_invite",
                        lambda pid, email, required=True, name=None:
                        created.append((email, required)) or
                        {"id": "i1", "token": "tk", "email": email})
    monkeypatch.setattr(api, "send_invite_email", lambda *a, **k: True)
    monkeypatch.setattr(api, "log_contact", lambda *a, **k: None)
    r = client.post("/scheduler/api/polls/p1/invite", json={
        "emails": ["a@x.ch"], "required": False})
    assert r.status_code == 200
    assert created == [("a@x.ch", False)]
    assert r.json()["invites"][0]["required"] is False


def test_ics_endpoint(client, monkeypatch):
    decided = dict(POLL, status="decided", decided_slot_id="t1")
    monkeypatch.setattr(api, "get_poll", lambda pid: decided)
    r = client.get("/scheduler/api/polls/p1/event.ics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/calendar")
    assert "DTSTART:20260608T070000Z" in r.text


def test_agent_discovery_surface(client):
    """OpenAPI + llms.txt + robots pointer — how agents find the API."""
    r = client.get("/scheduler/api/openapi.json")
    assert r.status_code == 200
    schema = r.json()
    assert "/scheduler/api/polls/{poll_id}/decide" in schema["paths"]
    assert "/scheduler/polls/{poll_id}" not in schema["paths"]  # HTML pages excluded
    assert schema["components"]["securitySchemes"]["bearerAuth"]["scheme"] == "bearer"

    r = client.get("/scheduler/llms.txt")
    assert r.status_code == 200
    assert "/scheduler/api/openapi.json" in r.text
    assert "Bearer" in r.text

    r = client.get("/scheduler/api/docs")
    assert r.status_code == 200 and "swagger" in r.text.lower()

    r = client.get("/scheduler/robots.txt")
    assert "llms.txt" in r.text


def test_contacts_endpoint(client, monkeypatch):
    monkeypatch.setattr(api, "get_contact_log", lambda pid: [
        {"email": "a@x.ch", "kind": "invite", "sent_at": "2026-06-04 18:00:00"}])
    r = client.get("/scheduler/api/polls/p1/contacts")
    assert r.status_code == 200
    assert r.json()[0]["kind"] == "invite"


# -- Issue #70: the REST slot-cap, matching the web/console cap ------------
#
# Every surface that writes slots to the database shares one ceiling,
# `capability.MAX_SLOTS_PER_ACCOUNTLESS_POLL`. On the console path #68 pinned
# that the bound runs **before** any expansion: a check after the loop produces
# the right 400 but half a gigabyte late. #70 brings the same discipline to
# the REST API's two slot-writing surfaces — `POST /api/polls` and
# `POST /api/polls/{id}/slots`. The tests here assert what the fix is *for*:
# the refusal arrives cheaply, before any allocation and before any DB write,
# and MCP inherits it by calling the REST endpoint directly.


def _grid_poll(n_pairs: int, mode: str = "time_slot") -> dict:
    """A poll carrying `n_pairs` distinct time pairs on one date.

    Mirrors `tests/test_capability.py::_grid_poll`'s shape (hand-built so the
    multiplier under test is the poll's grid, not a creator's input) so the
    REST test uses the same rig the console tests rely on.
    """
    if mode == "full_day":
        slots = [{"id": f"s{i}", "date": "2025-06-01",
                  "start_time": None, "end_time": None}
                 for i in range(n_pairs)]
    else:
        slots = [{"id": f"s{i}", "date": "2025-06-01",
                  "start_time": f"{9 + i // 60:02d}:{i % 60:02d}",
                  "end_time": f"{9 + (i + 1) // 60:02d}:{(i + 1) % 60:02d}"}
                 for i in range(n_pairs)]
    return {"id": "p1", "creator_id": "lars", "owner_id": "lars",
            "title": "grid", "description": None, "mode": mode,
            "timezone": "Europe/Zurich", "status": "open",
            "decided_slot_id": None, "public_token": "tokA",
            "manage_verified_at": None, "slots": slots}


def test_create_poll_refuses_a_slot_list_over_the_cap_at_validation(client, monkeypatch):
    """A `slots` list longer than the ceiling is a 422 from Pydantic, before any
    row is written — pinned so a creator cannot sneak a million slots past the
    model and have them parsed into Python objects before the endpoint runs.
    """
    wrote = []
    monkeypatch.setattr(api, "create_poll",
                        lambda *a, **k: wrote.append(a) or dict(POLL))
    cap = capability.MAX_SLOTS_PER_ACCOUNTLESS_POLL
    r = client.post("/scheduler/api/polls", json={
        "title": "huge", "mode": "full_day", "timezone": "Europe/Zurich",
        "slots": [{"date": "2026-06-08"} for _ in range(cap + 1)],
    })
    assert r.status_code == 422, r.text
    assert wrote == [], "a refused creation must not have called create_poll"


def test_create_poll_accepts_exactly_at_the_cap(client, monkeypatch):
    """The boundary: `cap` slots accepted, one more refused. Same number in both
    directions, which is what makes the ceiling testable at all.
    """
    monkeypatch.setattr(api, "create_poll", lambda *a, **k: dict(POLL))
    cap = capability.MAX_SLOTS_PER_ACCOUNTLESS_POLL
    # Distinct dates so the body validates in time_slot shape too; full_day keeps
    # the dates irrelevant to the cap — this is one slot per list entry.
    r = client.post("/scheduler/api/polls", json={
        "title": "at-cap", "mode": "full_day", "timezone": "Europe/Zurich",
        "slots": [{"date": f"2026-{1 + i // 300:02d}-{1 + i % 28:02d}"} for i in range(cap)],
    })
    assert r.status_code == 200, r.text


def test_add_slots_refuses_a_dates_list_over_the_cap_at_validation(client, monkeypatch):
    """`dates` over the cap is a 422 at the Pydantic layer — before
    `expand_new_dates` is called and before any row is written. The spies on
    `api.expand_new_dates` and `api.add_slots` would catch a refusal placed
    *after* either (same refusal, half a gigabyte more work).
    """
    called = {"expand": 0, "add": 0}
    monkeypatch.setattr(api, "expand_new_dates",
                        lambda *a, **k: called.update(expand=called["expand"] + 1) or [])
    monkeypatch.setattr(api, "add_slots",
                        lambda *a, **k: called.update(add=called["add"] + 1) or [])
    cap = capability.MAX_SLOTS_PER_ACCOUNTLESS_POLL
    r = client.post("/scheduler/api/polls/p1/slots",
                    json={"dates": ["2026-06-22"] * (cap + 1)})
    assert r.status_code == 422, r.text
    assert called["expand"] == 0, "expand_new_dates must not run when the input is refused"
    assert called["add"] == 0, "add_slots must not run when the input is refused"


def test_add_slots_refuses_the_product_before_expansion(monkeypatch):
    """A poll with 125 time pairs and 20 fresh dates: `20 × 125 = 2,500 > 1,000`.
    The refusal must arrive before `expand_new_dates` builds the grid — this is
    the same `tracemalloc` placement test #68 used on the console, applied to
    the REST route. The allocation ceiling rules out a 400 that the fix in #70
    could have landed *after* the comprehension (same status, same message,
    half a gigabyte more memory).
    """
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    poll = _grid_poll(125)
    monkeypatch.setattr(api, "get_poll", lambda pid: dict(poll) if pid == "p1" else None)
    monkeypatch.setattr(api, "get_responses", lambda pid: [])
    monkeypatch.setattr(api, "get_invites", lambda pid: [])
    called = {"add": 0}
    monkeypatch.setattr(api, "add_slots",
                        lambda *a, **k: called.update(add=called["add"] + 1) or [])
    c = TestClient(main.app, base_url="https://testserver")
    c.headers["Authorization"] = f"Bearer {KEY}"

    dates = [f"2026-07-{d:02d}" for d in range(1, 21)]  # 20 fresh dates × 125 pairs = 2,500

    tracemalloc.start()
    try:
        r = c.post("/scheduler/api/polls/p1/slots", json={"dates": dates})
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert r.status_code == 400, r.text
    assert called["add"] == 0, "add_slots must not run for a refused edit"
    # The allocation ceiling is the point: a check placed *after* the grid is
    # built produces the same 400 and allocates half a gigabyte doing it, and
    # this fails at 10 MB. The exact placement — the arithmetic bound in the
    # endpoint, or the `cap=` parameter on `expand_new_dates` — is incidental,
    # as long as nothing materialises the grid first.
    assert peak < 10 * 1024 * 1024, (
        f"the refusal allocated {peak / 1024 / 1024:.0f} MB — the cap is being "
        f"applied after the comprehension, not before it"
    )


def test_add_slots_refuses_when_existing_plus_new_exceeds_the_cap(monkeypatch):
    """A poll with 500 slots (full_day) + 600 new dates would land at 1,100
    > 1,000. The *existing* count has to be part of the bound, because this
    endpoint grows a poll across many sessions with the same key — the console
    gate does not have to compute this because every edit is one request, but
    the REST surface can bring a small poll to over-cap one request at a time
    if the bound only looks at the new work.
    """
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    poll = _grid_poll(500, mode="full_day")
    monkeypatch.setattr(api, "get_poll", lambda pid: dict(poll) if pid == "p1" else None)
    monkeypatch.setattr(api, "get_responses", lambda pid: [])
    monkeypatch.setattr(api, "get_invites", lambda pid: [])
    called = {"add": 0}
    monkeypatch.setattr(api, "add_slots",
                        lambda *a, **k: called.update(add=called["add"] + 1) or [])
    c = TestClient(main.app, base_url="https://testserver")
    c.headers["Authorization"] = f"Bearer {KEY}"

    # 600 distinct dates spread over ~20 months.
    start = _dt.date(2027, 1, 1)
    dates = [(start + _dt.timedelta(days=i)).isoformat() for i in range(600)]

    r = c.post("/scheduler/api/polls/p1/slots", json={"dates": dates})
    assert r.status_code == 400, r.text
    assert "1,100" in r.text, r.text  # The total this would create
    assert "500" in r.text, "the refusal should say how many the poll already has"
    assert called["add"] == 0, "add_slots must not run for a refused edit"


def test_add_slots_accepts_exactly_at_the_cap(monkeypatch):
    """1,000 total (0 existing + 1,000 new) accepted on a full_day poll, pinning
    the boundary — one more would be refused, same policy.
    """
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    # A fresh poll with zero slots (nothing to collide with).
    empty = {"id": "p1", "creator_id": "lars", "owner_id": "lars",
             "title": "empty", "description": None, "mode": "full_day",
             "timezone": "Europe/Zurich", "status": "open",
             "decided_slot_id": None, "public_token": "tokA",
             "manage_verified_at": None, "slots": []}
    monkeypatch.setattr(api, "get_poll", lambda pid: dict(empty) if pid == "p1" else None)
    monkeypatch.setattr(api, "get_responses", lambda pid: [])
    monkeypatch.setattr(api, "get_invites", lambda pid: [])
    monkeypatch.setattr(api, "add_slots", lambda pid, slots: slots)
    c = TestClient(main.app, base_url="https://testserver")
    c.headers["Authorization"] = f"Bearer {KEY}"

    cap = capability.MAX_SLOTS_PER_ACCOUNTLESS_POLL
    start = _dt.date(2027, 1, 1)
    at_cap = [(start + _dt.timedelta(days=i)).isoformat() for i in range(cap)]
    r = c.post("/scheduler/api/polls/p1/slots", json={"dates": at_cap})
    assert r.status_code == 200, r.text
    assert len(r.json()["added"]) == cap
