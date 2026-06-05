"""Bearer-API tests — full-parity agent control surface, stubbed DB."""

from datetime import date, time

from kairos import api
from kairos import main
import pytest
from fastapi.testclient import TestClient

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
                        lambda pid, email, required=True:
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
