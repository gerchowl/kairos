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
