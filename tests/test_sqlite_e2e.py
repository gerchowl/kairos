"""True end-to-end against a real SQLite file — exercises the dialect layer
(schema DDL, migrations, upserts, datetime converters) with NO stubs."""

import pytest
from fastapi.testclient import TestClient

KEY = "e2e-key"


@pytest.fixture
def client(tmp_path, monkeypatch):
    from kairos import settings
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/kairos.db")
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    from kairos.main import create_app
    with TestClient(create_app(), base_url="https://testserver") as c:  # lifespan runs init_schema
        c.headers["Authorization"] = f"Bearer {KEY}"
        yield c


def test_full_lifecycle_on_sqlite(client):
    # create
    r = client.post("/scheduler/api/polls", json={
        "title": "SQLite e2e", "mode": "time_slot",
        "slots": [{"date": "2026-07-06", "start_time": "09:00", "end_time": "09:30"},
                  {"date": "2026-07-06", "start_time": "09:30", "end_time": "10:00"}]})
    assert r.status_code == 200, r.text
    poll = r.json()
    s1, s2 = poll["slots"][0]["id"], poll["slots"][1]["id"]

    # respond + upsert (exercises ON CONFLICT)
    r = client.post(f"/scheduler/api/polls/{poll['id']}/respond", json={
        "name": "Ann", "email": "ann@x.ch", "availabilities": {s1: "yes", s2: "no"}})
    assert r.status_code == 200, r.text
    r = client.post(f"/scheduler/api/polls/{poll['id']}/respond", json={
        "name": "Ann", "email": "ann@x.ch", "availabilities": {s1: "yes", s2: "yes"}})
    assert r.status_code == 200

    detail = client.get(f"/scheduler/api/polls/{poll['id']}").json()
    assert len(detail["responses"]) == 1  # upserted, not duplicated
    assert detail["convergence"]["state"] == "ready"
    assert detail["responses"][0]["slot_availabilities"][s2] == "yes"

    # additive dates (created_at column written by migration-compatible path)
    r = client.post(f"/scheduler/api/polls/{poll['id']}/slots", json={"dates": ["2026-07-08"]})
    assert r.status_code == 200 and len(r.json()["added"]) == 2

    detail = client.get(f"/scheduler/api/polls/{poll['id']}").json()
    assert detail["convergence"]["state"] == "collecting" or len(detail["slots"]) == 4

    # decide + ics
    r = client.post(f"/scheduler/api/polls/{poll['id']}/decide", json={"slot_id": s1})
    assert r.json()["status"] == "decided"
    ics = client.get(f"/scheduler/api/polls/{poll['id']}/event.ics")
    assert "DTSTART:20260706T070000Z" in ics.text  # 09:00 CEST -> UTC

    # contact log table exists & empty (no SMTP configured)
    assert client.get(f"/scheduler/api/polls/{poll['id']}/contacts").json() == []

    # public page renders from sqlite data
    page = client.get(f"/scheduler/p/{poll['public_token']}")
    assert page.status_code == 200 and "SQLite e2e" in page.text

    # init_schema is idempotent (migrations re-run safely)
    from kairos.db import init_schema
    init_schema()
