"""Bearer-API tests — full-parity agent control surface, stubbed DB."""

import datetime as _dt
import tracemalloc
from datetime import date, time

import pytest
from fastapi import HTTPException as _HTTPException
from fastapi.testclient import TestClient

from kairos import api, capability, main
from kairos import web as _web

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
    monkeypatch.setattr(api, "add_slots_capped", lambda pid, slots, cap: slots)
    monkeypatch.setattr(api, "nudge_participants",
                        lambda req, poll, actor: {"invited": 0, "updated": 2, "skipped": 1})
    r = client.post("/scheduler/api/polls/p1/slots", json={
        "dates": ["2026-06-22"], "notify": True})
    assert r.status_code == 200
    data = r.json()
    assert len(data["added"]) == 2  # expanded over the 2-slot time grid
    assert data["nudged"]["updated"] == 2

    # Since PR #92 the `dates` field validates at the Pydantic layer, so a
    # malformed date is a 422 at the model rather than a 400 from the route.
    assert client.post("/scheduler/api/polls/p1/slots",
                       json={"dates": ["junk"]}).status_code == 422


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


def test_create_poll_refuses_a_slot_list_over_the_per_request_guard(client, monkeypatch):
    """A `slots` list longer than `MAX_SLOTS_PER_REQUEST` is a 422 from Pydantic,
    before any row is written — pinned so a creator cannot sneak a million slots
    past the model and have them parsed into Python objects before the endpoint
    runs.
    """
    from kairos import settings as _settings
    wrote = []
    monkeypatch.setattr(api, "create_poll",
                        lambda *a, **k: wrote.append(a) or dict(POLL))
    cap = _settings.MAX_SLOTS_PER_REQUEST
    r = client.post("/scheduler/api/polls", json={
        "title": "huge", "mode": "full_day", "timezone": "Europe/Zurich",
        "slots": [{"date": "2026-06-08"} for _ in range(cap + 1)],
    })
    assert r.status_code == 422, r.text
    assert wrote == [], "a refused creation must not have called create_poll"


def test_create_poll_refuses_slot_list_over_the_per_poll_cap(client, monkeypatch):
    """Even when `slots` sits under the per-request guard, a list that would
    exceed the per-poll cap is a 400 from the route -- `slot_cap_refusal`'s
    single sentence, since PR #92.
    """
    monkeypatch.setenv("KAIROS_MAX_SLOTS_PER_POLL", "100")
    wrote = []
    monkeypatch.setattr(api, "create_poll",
                        lambda *a, **k: wrote.append(a) or dict(POLL))
    r = client.post("/scheduler/api/polls", json={
        "title": "huge", "mode": "full_day", "timezone": "Europe/Zurich",
        "slots": [{"date": f"2026-{1 + i // 300:02d}-{1 + i % 28:02d}"} for i in range(150)],
    })
    assert r.status_code == 400, r.text
    assert "too large" in r.text
    assert "100" in r.text
    assert wrote == [], "a refused creation must not have called create_poll"


def test_create_poll_accepts_exactly_at_the_cap(client, monkeypatch):
    """The boundary: `cap` slots accepted, one more refused. Same number in both
    directions, which is what makes the ceiling testable at all.
    """
    monkeypatch.setenv("KAIROS_MAX_SLOTS_PER_POLL", "1000")
    monkeypatch.setattr(api, "create_poll", lambda *a, **k: dict(POLL))
    cap = capability.MAX_SLOTS_PER_ACCOUNTLESS_POLL
    assert cap == 1000
    # Distinct dates so the body validates in time_slot shape too; full_day keeps
    # the dates irrelevant to the cap — this is one slot per list entry.
    r = client.post("/scheduler/api/polls", json={
        "title": "at-cap", "mode": "full_day", "timezone": "Europe/Zurich",
        "slots": [{"date": f"2026-{1 + i // 300:02d}-{1 + i % 28:02d}"} for i in range(cap)],
    })
    assert r.status_code == 200, r.text


def test_add_slots_refuses_a_dates_list_over_the_cap_at_validation(client, monkeypatch):
    """`dates` over `MAX_SLOTS_PER_REQUEST` is a 422 at the Pydantic layer —
    before `expand_new_dates` is called and before any row is written. The
    spies on `api.expand_new_dates` and `api.add_slots_capped` would catch a
    refusal placed *after* either (same refusal, half a gigabyte more work).
    """
    from kairos import settings as _settings
    called = {"expand": 0, "add": 0}
    monkeypatch.setattr(api, "expand_new_dates",
                        lambda *a, **k: called.update(expand=called["expand"] + 1) or [])
    monkeypatch.setattr(api, "add_slots_capped",
                        lambda *a, **k: called.update(add=called["add"] + 1) or [])
    cap = _settings.MAX_SLOTS_PER_REQUEST
    r = client.post("/scheduler/api/polls/p1/slots",
                    json={"dates": ["2026-06-22"] * (cap + 1)})
    assert r.status_code == 422, r.text
    assert called["expand"] == 0, "expand_new_dates must not run when the input is refused"
    assert called["add"] == 0, "add_slots_capped must not run when the input is refused"


def test_add_slots_refuses_the_product_before_expansion(monkeypatch):
    """A poll with 125 time pairs and 20 fresh dates: `20 × 125 = 2,500 >
    1,000`. The refusal must arrive before `expand_new_dates` builds the grid
    — this is the same `tracemalloc` placement test #68 used on the console,
    applied to the REST route. The allocation ceiling rules out a 400 that
    the fix in #70 could have landed *after* the comprehension (same status,
    same message, half a gigabyte more memory).
    """
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    monkeypatch.setenv("KAIROS_MAX_SLOTS_PER_POLL", "1000")
    poll = _grid_poll(125)
    monkeypatch.setattr(api, "get_poll", lambda pid: dict(poll) if pid == "p1" else None)
    monkeypatch.setattr(api, "get_responses", lambda pid: [])
    monkeypatch.setattr(api, "get_invites", lambda pid: [])
    called = {"add": 0}
    monkeypatch.setattr(api, "add_slots_capped",
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
    assert called["add"] == 0, "add_slots_capped must not run for a refused edit"
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
    monkeypatch.setenv("KAIROS_MAX_SLOTS_PER_POLL", "1000")
    poll = _grid_poll(500, mode="full_day")
    monkeypatch.setattr(api, "get_poll", lambda pid: dict(poll) if pid == "p1" else None)
    monkeypatch.setattr(api, "get_responses", lambda pid: [])
    monkeypatch.setattr(api, "get_invites", lambda pid: [])
    called = {"add": 0}
    monkeypatch.setattr(api, "add_slots_capped",
                        lambda *a, **k: called.update(add=called["add"] + 1) or [])
    c = TestClient(main.app, base_url="https://testserver")
    c.headers["Authorization"] = f"Bearer {KEY}"

    # 600 distinct dates spread over ~20 months.
    start = _dt.date(2027, 1, 1)
    dates = [(start + _dt.timedelta(days=i)).isoformat() for i in range(600)]

    r = c.post("/scheduler/api/polls/p1/slots", json={"dates": dates})
    assert r.status_code == 400, r.text
    assert "1,100" in r.text, r.text  # The total this would create
    assert called["add"] == 0, "add_slots_capped must not run for a refused edit"


def test_add_slots_accepts_exactly_at_the_cap(monkeypatch):
    """1,000 total (0 existing + 1,000 new) accepted on a full_day poll, pinning
    the boundary — one more would be refused, same policy.
    """
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    monkeypatch.setenv("KAIROS_MAX_SLOTS_PER_POLL", "1000")
    # A fresh poll with zero slots (nothing to collide with).
    empty = {"id": "p1", "creator_id": "lars", "owner_id": "lars",
             "title": "empty", "description": None, "mode": "full_day",
             "timezone": "Europe/Zurich", "status": "open",
             "decided_slot_id": None, "public_token": "tokA",
             "manage_verified_at": None, "slots": []}
    monkeypatch.setattr(api, "get_poll", lambda pid: dict(empty) if pid == "p1" else None)
    monkeypatch.setattr(api, "get_responses", lambda pid: [])
    monkeypatch.setattr(api, "get_invites", lambda pid: [])
    monkeypatch.setattr(api, "add_slots_capped", lambda pid, slots, cap: slots)
    c = TestClient(main.app, base_url="https://testserver")
    c.headers["Authorization"] = f"Bearer {KEY}"

    cap = capability.MAX_SLOTS_PER_ACCOUNTLESS_POLL
    assert cap == 1000
    start = _dt.date(2027, 1, 1)
    at_cap = [(start + _dt.timedelta(days=i)).isoformat() for i in range(cap)]
    r = c.post("/scheduler/api/polls/p1/slots", json={"dates": at_cap})
    assert r.status_code == 200, r.text
    assert len(r.json()["added"]) == cap

# -- PR #92 adversarial-review pass regressions ----------------------------
#
# One test per finding, each failing on d9029b3 (the PR's head before this
# round) and passing after. Numbers below pin the policy the review recorded:
# per-request memory guard applies to every slot-writing surface; per-poll
# cap is atomic at the data layer; body-size and 422-input scrubbing apply
# app-wide.


def test_finding_1_add_slots_is_atomic_under_concurrent_writers(tmp_path, monkeypatch):
    """**Finding 1 (MEDIUM race).** 64 concurrent adds against a 1,000-cap
    SQLite poll took it to 36,100 slots on d9029b3, because the count →
    check → insert in `add_slots_endpoint` had three statements between the
    read and the write and any concurrent writer could land its insert in
    the window. `add_slots_capped` closes it per dialect: SQLite under
    `BEGIN IMMEDIATE`, MySQL under `SELECT ... FOR UPDATE`.

    This test uses the real DB (SQLite) and a thread pool, so the race
    actually runs. Final slot count must be `<= cap` and the refused
    requests must have come back as 400.
    """
    from concurrent.futures import ThreadPoolExecutor

    monkeypatch.setenv("KAIROS_API_KEY", "race-key")
    monkeypatch.setenv("KAIROS_MAX_SLOTS_PER_POLL", "100")
    path = tmp_path / "race.db"
    monkeypatch.setattr("kairos.settings.DB_URL", f"sqlite:///{path}")
    monkeypatch.setattr("kairos.dbconn.IS_SQLITE", True)

    from kairos import db
    db.init_schema()
    poll = db.create_poll(
        creator_id="race-owner", title="race", description=None,
        mode="full_day", timezone="UTC",
        slots=[{"date": f"2026-{1 + i // 28:02d}-{1 + i % 28:02d}"} for i in range(50)],
        owner_id="race-owner",
    )
    poll_id = poll["id"]

    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": "Bearer race-key"})

    def worker(i: int):
        dates = [f"2030-{1 + i:02d}-{1 + d:02d}" for d in range(10)]
        return c.post(f"/scheduler/api/polls/{poll_id}/slots", json={"dates": dates})

    N = 32
    with ThreadPoolExecutor(max_workers=N) as pool:
        responses = list(pool.map(worker, range(N)))

    cap = capability.MAX_SLOTS_PER_ACCOUNTLESS_POLL
    assert cap == 100
    final = db.get_poll(poll_id)
    assert len(final["slots"]) <= cap, (
        f"the poll holds {len(final['slots'])} slots, over the cap of {cap} - "
        f"the count/check/insert race in add_slots_endpoint reopened"
    )
    oks = [r for r in responses if r.status_code == 200]
    refused = [r for r in responses if r.status_code == 400]
    assert oks and refused, (
        f"expected at least one accepted and one refused request, got "
        f"{len(oks)} 200s and {len(refused)} 400s"
    )
    for r in refused:
        assert "too large" in r.text or "per-poll" in r.text, r.text


def test_finding_2_header_mode_can_edit_a_demo_header_1280_slot_poll(monkeypatch):
    """**Finding 2 (MEDIUM regression).** A demo/header deployment that had
    grown a 1,280-slot poll before PR #92 landed must remain editable via
    API/MCP. The policy change (one cap for every surface) would be a
    data-loss regression if it refused edits to polls that already fit
    under the old header-mode behaviour.

    The policy records the number as 5,000 for self-host/ETH (looser) and
    1,000 only when capability or hosted mode is on, so a demo/header
    1,280-slot poll sits comfortably under the cap.
    """
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    monkeypatch.delenv("KAIROS_MAX_SLOTS_PER_POLL", raising=False)
    monkeypatch.setattr("kairos.settings.AUTH_MODE", "header")
    monkeypatch.setattr("kairos.settings.HOSTED", False)

    existing = [{"id": f"s{i}", "date": "2026-06-01",
                 "start_time": f"{9 + i // 60:02d}:{i % 60:02d}",
                 "end_time": f"{9 + (i + 1) // 60:02d}:{(i + 1) % 60:02d}"}
                for i in range(1280)]
    poll = {"id": "p1", "creator_id": "lars", "owner_id": "lars",
            "title": "demo", "description": None, "mode": "time_slot",
            "timezone": "Europe/Zurich", "status": "open",
            "decided_slot_id": None, "public_token": "tokA",
            "manage_verified_at": None, "slots": existing}
    monkeypatch.setattr(api, "get_poll", lambda pid: dict(poll) if pid == "p1" else None)
    monkeypatch.setattr(api, "get_responses", lambda pid: [])
    monkeypatch.setattr(api, "get_invites", lambda pid: [])
    monkeypatch.setattr(api, "add_slots_capped", lambda pid, slots, cap: slots)

    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": f"Bearer {KEY}"})

    r = c.post("/scheduler/api/polls/p1/slots", json={"dates": ["2026-07-01"]})
    assert r.status_code == 200, r.text
    assert len(r.json()["added"]) == 1280


def test_finding_2_rest_and_web_refuse_the_same_inputs(client, monkeypatch):
    """**Finding 2 parity.** The capability console, REST and MCP must
    refuse the same inputs. `expand_new_dates` is the shared function, but
    a parity test at the call-site level pins that neither surface drifts.
    """
    monkeypatch.setenv("KAIROS_MAX_SLOTS_PER_POLL", "100")
    many = [f"2027-{1 + i // 28:02d}-{1 + i % 28:02d}" for i in range(200)]
    monkeypatch.setattr(api, "create_poll", lambda *a, **k: dict(POLL))
    r = client.post("/scheduler/api/polls", json={
        "title": "huge", "mode": "full_day", "timezone": "Europe/Zurich",
        "slots": [{"date": d} for d in many],
    })
    assert r.status_code == 400
    assert "too large" in r.text
    empty_poll = {"id": "p", "mode": "full_day", "slots": []}
    try:
        _web.expand_new_dates(empty_poll, many)
    except _HTTPException as exc:
        assert exc.status_code == 400
        assert "too large" in exc.detail
    else:
        raise AssertionError("expand_new_dates must refuse the parallel input")


def test_finding_3_body_over_cap_is_413_before_fastapi_parses(monkeypatch):
    """**Finding 3 (MEDIUM body-size).** A 1.5 MiB JSON body must be
    refused with a JSON 413 before FastAPI parses it; the cap is an ASGI
    middleware, not a route-level check, so a body that never reaches a
    route is bounded too.
    """
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    oversized = (b'{"title":"x","mode":"full_day","slots":[{"date":"2026-06-08"}],'
                 b'"filler":"' + b"a" * (int(1.5 * 1024 * 1024)) + b'"}')
    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": f"Bearer {KEY}"})
    r = c.post("/scheduler/api/polls", content=oversized, headers={
        "Content-Type": "application/json",
        "Content-Length": str(len(oversized)),
    })
    assert r.status_code == 413, r.text
    assert "exceeds" in r.text


def test_finding_3_422_response_does_not_echo_the_submitted_input(client):
    """**Finding 3 (MEDIUM, second half).** Pydantic's default 422 body
    carries the whole `input` the client sent, so a 2 MB JSON with one
    bad field sent 2 MB back. The handler strips `input` and `ctx` from
    every error entry; `loc`, `msg` and `type` stay so an agent can find
    the offending field.
    """
    long_title = "huge-title-value-" + "x" * 1000
    r = client.post("/scheduler/api/polls", json={
        "title": long_title, "mode": "full_day", "timezone": "Europe/Zurich",
        "slots": [{"date": "2026-06-08"}],
    })
    assert r.status_code == 422, r.text
    body = r.json()
    for err in body["detail"]:
        assert "input" not in err, err
        assert "ctx" not in err, err
        assert "loc" in err and "msg" in err and "type" in err, err
    assert long_title[:200] not in r.text


def test_finding_4_slot_date_and_time_are_validated_at_the_model(client, monkeypatch):
    """**Finding 4 (LOW-MED validation).** A bad `date` / `start_time` /
    `end_time` is refused at the Pydantic layer, not left to raise 500
    on the next `DATE` / `TIME` column read.
    """
    monkeypatch.setattr(api, "create_poll", lambda *a, **k: dict(POLL))

    r = client.post("/scheduler/api/polls", json={
        "title": "x", "mode": "full_day", "timezone": "Europe/Zurich",
        "slots": [{"date": "06/08/2026"}],
    })
    assert r.status_code == 422, r.text
    r = client.post("/scheduler/api/polls", json={
        "title": "x", "mode": "time_slot", "timezone": "Europe/Zurich",
        "slots": [{"date": "2026-06-08", "start_time": "25:00", "end_time": "26:00"}],
    })
    assert r.status_code == 422, r.text
    r = client.post("/scheduler/api/polls", json={
        "title": "x", "mode": "time_slot", "timezone": "Europe/Zurich",
        "slots": [{"date": "2026-06-08", "start_time": "10:00", "end_time": "09:00"}],
    })
    assert r.status_code == 422, r.text


def test_finding_4_poll_title_has_a_max_length(client, monkeypatch):
    """**Finding 4.** Oversized free-text fields must refuse at validation,
    not as a DB VARCHAR(255) truncation or a 500. Title's cap is 255, which
    matches the column.
    """
    monkeypatch.setattr(api, "create_poll", lambda *a, **k: dict(POLL))
    long_title = "a" * 1000
    r = client.post("/scheduler/api/polls", json={
        "title": long_title, "mode": "full_day", "timezone": "Europe/Zurich",
        "slots": [{"date": "2026-06-08"}],
    })
    assert r.status_code == 422, r.text


def test_finding_5_slot_cap_refusal_sentence_fires_on_rest(client, monkeypatch):
    """**Finding 5 (LOW).** The shared `slot_cap_refusal` sentence must
    reach a client as 400 detail text. Pins that the sentence is the one
    that fires.
    """
    monkeypatch.setenv("KAIROS_MAX_SLOTS_PER_POLL", "50")
    monkeypatch.setattr(api, "create_poll", lambda *a, **k: dict(POLL))
    r = client.post("/scheduler/api/polls", json={
        "title": "x", "mode": "full_day", "timezone": "Europe/Zurich",
        "slots": [{"date": f"2026-{1 + i // 28:02d}-{1 + i % 28:02d}"} for i in range(60)],
    })
    assert r.status_code == 400, r.text
    assert "too large" in r.text
    assert "50" in r.text


# -- PR #92 round-2 regression pass ----------------------------------------
#
# One test per finding, each failing on 888ed5c and passing after.


def test_round2_finding_1_bare_add_slots_is_gone():
    """**Round-2 finding 1 (HIGH).** The bare `add_slots` must no longer
    be importable from `kairos.db`, so a future caller cannot bypass the
    atomic guard by naming the private helper. The one entry point is
    `add_slots_capped`.
    """
    from kairos import db
    assert not hasattr(db, "add_slots"), (
        "kairos.db.add_slots must be removed — every slot write goes "
        "through add_slots_capped so the per-poll cap is atomic."
    )
    assert hasattr(db, "add_slots_capped")


def test_round2_finding_1_manage_edit_is_atomic_under_concurrent_writers(tmp_path, monkeypatch):
    """**Round-2 finding 1 (HIGH race).** `capability._edit` called the
    bare `add_slots` on /manage/{id}/edit, skipping the atomic
    count+check+insert the REST path got in round-1. 128 concurrent workers
    against a 1,000-cap poll took it to 3,610 slots on the pre-fix tree.
    The fix removes the bare helper and routes every slot-insertion
    through `add_slots_capped`, so the console cannot drift from REST.

    Pinned against real SQLite via a thread pool so the race actually
    runs; final slot count must be `<= cap`. The manage auth/CSRF step
    is one-shot (the token is rotated on exchange), so this test stubs
    `require_manage` and `require_csrf` to let N concurrent POSTs reach
    `_edit` -- the REST-level atomicity test
    (`test_finding_1_add_slots_is_atomic_under_concurrent_writers`) pins
    the same invariant from the other direction.
    """
    from concurrent.futures import ThreadPoolExecutor

    monkeypatch.setenv("KAIROS_AUTH", "capability")
    monkeypatch.setenv("KAIROS_MAX_SLOTS_PER_POLL", "100")
    monkeypatch.setattr("kairos.settings.AUTH_MODE", "capability")
    monkeypatch.setattr("kairos.capability.is_configured", lambda: True)
    monkeypatch.setattr("kairos.capability.require_manage",
                        lambda poll, request, **kw: poll)
    monkeypatch.setattr("kairos.capability.require_csrf", lambda d, form: None)
    # The session check sits before `require_manage`; stub to a valid session
    # for the poll under test. Each worker's TestClient has no cookies, so
    # `read_session` returns None otherwise.
    def _fake_session(request):
        return {"pid": poll_id, "at": "stub-token"}
    monkeypatch.setattr("kairos.capability.read_session", _fake_session)
    path = tmp_path / "manage_race.db"
    monkeypatch.setattr("kairos.settings.DB_URL", f"sqlite:///{path}")
    monkeypatch.setattr("kairos.dbconn.IS_SQLITE", True)

    from kairos import db
    db.init_schema()
    poll = db.create_poll(
        creator_id="race-owner", title="race", description=None,
        mode="full_day", timezone="UTC",
        slots=[{"date": f"2026-{1 + i // 28:02d}-{1 + i % 28:02d}"} for i in range(50)],
        owner_id=None, creator_email="r@x.ch",
    )
    poll_id = poll["id"]

    # One session cookie per worker so cookie-jar access does not serialise
    # the race. Each client runs its own POST through the real app, which
    # calls the real `_edit`, which calls the real `add_slots_capped`.
    def worker(i: int):
        c = TestClient(main.app, base_url="https://testserver")
        # The route reads the session; with `require_manage` stubbed above,
        # a bare POST is enough.
        dates = [f"2030-{1 + i:02d}-{1 + d:02d}" for d in range(10)]
        return c.post(
            f"/scheduler/manage/{poll_id}/edit",
            data={"csrf": "x", "title": "race", "timezone": "UTC",
                  "dates": ",".join(dates)},
            follow_redirects=False,
        )

    N = 24
    with ThreadPoolExecutor(max_workers=N) as pool:
        responses = list(pool.map(worker, range(N)))

    final = db.get_poll(poll_id)
    assert len(final["slots"]) <= 100, (
        f"the poll holds {len(final['slots'])} slots, over the cap of 100 — "
        "the capability /manage/{id}/edit race reopened."
    )
    # At least one must have been accepted and at least one refused for the
    # race window to have run; otherwise the test is vacuous.
    accepted = sum(1 for r in responses if r.status_code in (200, 302, 303))
    refused = sum(1 for r in responses if r.status_code == 400)
    assert accepted >= 1 and refused >= 1, (
        f"test did not exercise the race: accepted={accepted} refused={refused} "
        f"statuses={[r.status_code for r in responses]}"
    )


def test_round2_finding_2_middleware_stops_reading_a_chunked_over_cap_body(monkeypatch):
    """**Round-2 finding 2 (HIGH body-size on chunked).** A chunked body
    over cap used to arrive in full (100 MB → 431 MB RSS; 300 MB → 1.2 GB
    RSS) before the middleware answered 413. The fix buffers up to the
    cap and refuses the moment a chunk would exceed it, NEVER forwarding
    further bytes to the app.

    Driven at the ASGI layer (not through `TestClient`) because httpx's
    ASGI transport pre-reads a generator into one buffer before handing
    it to ASGI's `receive` — a limitation of the TEST layer, not of the
    middleware. At the ASGI layer we can measure what we actually care
    about:

      * the app is never called (no body parser got partial bytes),
      * `receive` is NOT drained past the chunk that trips the cap
        (so RSS stays flat even for a 300 MiB body).
    """
    monkeypatch.setattr("kairos.settings.MAX_BODY_BYTES", 1 * 1024 * 1024)
    # Reinstall the middleware against a minimal ASGI app, so we drive
    # `_install_body_size_cap`'s exact function with a hand-crafted
    # `receive()` whose yields we can count and whose rate we control.
    from fastapi import FastAPI

    from kairos import main as _main
    inner = FastAPI()
    call_count = {"app": 0}

    @inner.post("/scheduler/api/polls")
    async def _spy():  # pragma: no cover — must not run
        call_count["app"] += 1
        return {"ok": True}

    _main._install_body_size_cap(inner)

    # Build the ASGI scope of a chunked POST (no Content-Length).
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "server": ("testserver", 443),
        "path": "/scheduler/api/polls",
        "raw_path": b"/scheduler/api/polls",
        "query_string": b"",
        "headers": [
            (b"host", b"testserver"),
            (b"content-type", b"application/json"),
            (b"transfer-encoding", b"chunked"),
        ],
        "client": ("127.0.0.1", 12345),
    }
    body_size = 300 * 1024 * 1024  # 300 MiB — the shape the finding measured
    chunk_size = 256 * 1024
    chunks_yielded = {"n": 0}

    async def receive():
        # Yield 256 KiB chunks until exhausted; count them so we can assert the
        # middleware stopped reading early.
        if chunks_yielded["n"] * chunk_size >= body_size:
            return {"type": "http.request", "body": b"", "more_body": False}
        chunks_yielded["n"] += 1
        return {"type": "http.request",
                "body": b"\x00" * chunk_size,
                "more_body": True}

    sent = []

    async def send(msg):
        sent.append(msg)

    import asyncio
    asyncio.run(inner(scope, receive, send))

    # The response must be 413.
    starts = [m for m in sent if m.get("type") == "http.response.start"]
    assert starts and starts[0]["status"] == 413, starts
    # The app must NEVER have been called for an over-cap body.
    assert call_count["app"] == 0, (
        "the route handler must not have run for an over-cap body — "
        "a route that has started parsing a partial body has already "
        "allocated its parse cost"
    )
    # And the middleware must have stopped reading early, not drained the
    # whole 300 MiB. 1 MiB cap / 256 KiB chunk = 4 chunks to reach the
    # cap; the 5th trips it. A pre-fix read-everything middleware would
    # yield ~1200 chunks.
    assert chunks_yielded["n"] <= 16, (
        f"middleware pulled {chunks_yielded['n']} chunks of {chunk_size} "
        f"for a 300 MiB over-cap body — it must stop at the cap, not "
        "continue draining the stream."
    )


def test_round2_finding_2_body_over_cap_with_content_length_is_413(monkeypatch):
    """**Round-2 finding 2 (header-shortcut).** When the client sends a
    Content-Length over cap, the middleware refuses before reading a
    byte of the body. This is the easy case and the test client handles
    it faithfully.
    """
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    monkeypatch.setattr("kairos.settings.MAX_BODY_BYTES", 1 * 1024 * 1024)
    oversized = b"x" * (int(1.5 * 1024 * 1024))
    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": f"Bearer {KEY}"})
    r = c.post(
        "/scheduler/api/polls",
        content=oversized,
        headers={"Content-Type": "application/json",
                 "Content-Length": str(len(oversized))},
    )
    assert r.status_code == 413, r.text


def test_round2_finding_2_under_cap_body_is_replayed_intact(monkeypatch):
    """The buffer-and-replay design hands the app the WHOLE body as one
    `http.request` message. Pins that a normal under-cap request still
    reaches the route and the route reads every byte.
    """
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    monkeypatch.setattr("kairos.settings.MAX_BODY_BYTES", 1 * 1024 * 1024)
    monkeypatch.setattr(api, "create_poll", lambda *a, **k: dict(POLL))
    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": f"Bearer {KEY}"})
    r = c.post("/scheduler/api/polls", json={
        "title": "x", "mode": "full_day", "timezone": "Europe/Zurich",
        "slots": [{"date": "2026-06-08"}],
    })
    assert r.status_code == 200, r.text


def test_round2_finding_3_web_new_header_mode_refuses_the_per_request_cap(monkeypatch):
    """**Round-2 finding 3 (MEDIUM per-request cap on /new).** Header-mode
    /new had no per-request cap: 5,000 dates created 5,000 slot dicts
    without challenge. The shared `web.request_cap_refusal` enforces the
    arithmetic bound on every write surface.
    """
    monkeypatch.setenv("KAIROS_MAX_SLOTS_PER_REQUEST", "500")
    monkeypatch.setattr("kairos.settings.MAX_SLOTS_PER_REQUEST", 500)
    monkeypatch.setattr("kairos.settings.AUTH_MODE", "header")
    monkeypatch.setattr("kairos.settings.HOSTED", False)
    monkeypatch.setattr("kairos.web.get_user",
                        lambda req: {"uid": "lars", "name": "L", "email": "l@x.ch"})
    monkeypatch.setattr("kairos.web.require_csrf", lambda user, form: None)
    monkeypatch.setattr("kairos.web.create_poll", lambda *a, **k: dict(POLL))
    # `_error_page` renders the nav, which reads notifications; stub so the
    # test is about the refusal shape, not the DB fixture.
    monkeypatch.setattr("kairos.web.get_notifications", lambda uid, unread_only=True: [])
    c = TestClient(main.app, base_url="https://testserver")
    from datetime import date as _d
    from datetime import timedelta as _td
    start = _d(2027, 1, 1)
    many = [(start + _td(days=i)).isoformat() for i in range(600)]
    r = c.post("/scheduler/new", data={
        "title": "huge", "mode": "full_day", "timezone": "Europe/Zurich",
        "csrf": "x", "dates": many,
    })
    assert r.status_code == 400, r.text
    assert "500" in r.text
    assert "too large" in r.text or "per-request" in r.text


def test_round2_finding_3_request_cap_helper_is_shared(monkeypatch):
    """The per-request refusal is one function used everywhere."""
    from kairos import web
    monkeypatch.setattr("kairos.settings.MAX_SLOTS_PER_REQUEST", 50)
    assert web.request_cap_refusal(49) is None
    assert web.request_cap_refusal(50) is None
    msg = web.request_cap_refusal(51)
    assert msg and "50" in msg and "too large" in msg
    monkeypatch.setattr("kairos.settings.MAX_SLOTS_PER_REQUEST", 0)
    assert web.request_cap_refusal(10_000_000) is None, "0 disables the cap"


def test_round2_finding_4_shared_validators_live_in_one_module():
    """**Round-2 finding 4 (MEDIUM validation).** One `validate_date` /
    `validate_time` used by every surface. Shape + arithmetic + bounded
    input length. `HH:MM:SS` is accepted and normalised to `HH:MM` so a
    MySQL TIME round-trip is not refused by its own input layer (fixes
    the round-1 regression).
    """
    from kairos.validation import (
        InvalidDate,
        InvalidTime,
        validate_date,
        validate_time,
    )
    assert validate_date("2026-01-05") == "2026-01-05"
    for bad in ("2026-1-5", "not-a-date", "2026-13-01", "2026-02-30",
                "2026/01/05", "x" * 500, 20260105):
        with pytest.raises(InvalidDate):
            validate_date(bad)
    assert validate_time("09:00") == "09:00"
    assert validate_time("09:00:00") == "09:00", "HH:MM:SS must normalise to HH:MM"
    assert validate_time("23:59:59") == "23:59"
    for bad in ("25:00", "9:5", "nope", "x" * 500, None, 900):
        with pytest.raises(InvalidTime):
            validate_time(bad)


def test_round2_finding_4_rest_slot_accepts_hhmmss_and_normalises(client, monkeypatch):
    """`SlotIn` must accept `HH:MM:SS` on start/end and normalise -- the
    column round-trip on MySQL carries seconds, so refusing them would
    make the data its own validator refused (round-1 regression).
    """
    captured = {}
    def capture_create_poll(*a, **k):
        slots = k.get("slots")
        if slots is None:
            slots = a[5]  # positional
        captured["slots"] = slots
        return dict(POLL)
    monkeypatch.setattr(api, "create_poll", capture_create_poll)
    r = client.post("/scheduler/api/polls", json={
        "title": "x", "mode": "time_slot", "timezone": "Europe/Zurich",
        "slots": [{"date": "2026-06-08",
                   "start_time": "09:00:00", "end_time": "10:00:00"}],
    })
    assert r.status_code == 200, r.text
    assert captured["slots"][0]["start_time"] == "09:00"
    assert captured["slots"][0]["end_time"] == "10:00"


def test_round2_finding_4_rest_slot_refuses_short_date_and_missing_zeros(client, monkeypatch):
    """A tight regex up front refuses shapes that `date.fromisoformat`
    might accept on a lax Python; the column converter raises on them
    either way.
    """
    monkeypatch.setattr(api, "create_poll", lambda *a, **k: dict(POLL))
    for bad in ("2026-1-5", "20260105"):
        r = client.post("/scheduler/api/polls", json={
            "title": "x", "mode": "full_day", "timezone": "Europe/Zurich",
            "slots": [{"date": bad}],
        })
        assert r.status_code == 422, (bad, r.text)


def test_round2_finding_4_read_path_tolerates_a_bad_stored_date(caplog):
    """A poll already on disk with a malformed `date` row must not 500
    the page. `validation.slot_is_readable` says False for such rows and
    the operator is told once.
    """
    import logging

    from kairos.validation import slot_is_readable
    good = {"id": "s1", "poll_id": "p1", "date": date(2026, 6, 8)}
    bad = {"id": "sbad", "poll_id": "p1", "date": "not-a-date"}
    bad_time = {"id": "stime", "poll_id": "p1", "date": date(2026, 6, 8),
                "start_time": "nope"}
    assert slot_is_readable(good) is True
    with caplog.at_level(logging.WARNING, logger="kairos.validation"):
        assert slot_is_readable(bad) is False
        assert slot_is_readable(bad_time) is False
    assert any("skipping unreadable slot" in r.message for r in caplog.records)


def test_round2_finding_5_validators_do_not_echo_the_full_submitted_value():
    """**Round-2 finding 5 (LOW).** A bad input of 1 MB must not produce
    a 1 MB refusal. The validator excerpts at 40 chars with an ellipsis.
    """
    from kairos.validation import (
        InvalidDate,
        InvalidTime,
        validate_date,
        validate_time,
    )
    huge = "x" * (1 * 1024 * 1024)
    try:
        validate_date(huge)
    except InvalidDate as exc:
        msg = str(exc)
        assert len(msg) < 200, f"refusal message is {len(msg)} chars long"
        assert huge[:100] not in msg
    else:
        raise AssertionError("expected InvalidDate")
    try:
        validate_time(huge)
    except InvalidTime as exc:
        msg = str(exc)
        assert len(msg) < 200
        assert huge[:100] not in msg
    else:
        raise AssertionError("expected InvalidTime")


def test_round2_finding_5_slot_add_rejection_is_bounded(client, monkeypatch):
    """REST `SlotsAdd._check_dates` must not echo the full submitted
    value into the 422 body. A 500 KiB bad date produces a short response.
    """
    monkeypatch.setattr(api, "get_poll", lambda pid: dict(POLL))
    monkeypatch.setattr(api, "add_slots_capped", lambda pid, slots, cap: slots)
    huge_bad = "x" * (int(0.5 * 1024 * 1024))
    r = client.post("/scheduler/api/polls/p1/slots", json={"dates": [huge_bad]})
    assert r.status_code == 422, r.text
    assert len(r.text) < 10_000, (
        f"a 500 KiB bad date produced a {len(r.text)}-char response — "
        "the validator echoed the submitted value in full."
    )
    assert huge_bad[:100] not in r.text
