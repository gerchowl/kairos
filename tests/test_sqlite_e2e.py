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


def test_legal_pages_render_when_operator_set(tmp_path, monkeypatch):
    from kairos import settings
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/k.db")
    monkeypatch.setattr(settings, "OPERATOR", "Example Lab, ETH Zurich")
    monkeypatch.setattr(settings, "OPERATOR_ADDRESS", "Musterstrasse 1, 8092 Zurich, Switzerland")
    monkeypatch.setattr(settings, "OPERATOR_EMAIL", "lab@example.org")
    from kairos.main import create_app
    with TestClient(create_app(), base_url="https://testserver") as c:
        imp = c.get("/scheduler/imprint")
        assert imp.status_code == 200 and "Example Lab" in imp.text and "Musterstrasse" in imp.text
        prv = c.get("/scheduler/privacy")
        assert prv.status_code == 200 and "strictly-necessary cookies" in prv.text
        # footer links appear on regular pages
        pub = c.get("/scheduler/llms.txt")
        assert pub.status_code == 200


def test_no_legal_routes_without_operator(tmp_path, monkeypatch):
    from kairos import settings
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/k.db")
    monkeypatch.setattr(settings, "OPERATOR", "")
    from kairos.main import create_app
    with TestClient(create_app(), base_url="https://testserver") as c:
        assert c.get("/scheduler/imprint").status_code == 404


def test_participant_removal_lifecycle(tmp_path, monkeypatch):
    """Add-only invite -> appears in table -> delete invite (and its response)."""
    from kairos import settings
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/k.db")
    from kairos.main import create_app
    headers = {"X-User": "alice", "X-Email": "alice@example.org", "X-Name": "Alice"}
    api = {"Authorization": "Bearer dummy-key"}
    monkeypatch.setattr(settings, "API_KEY", "dummy-key")
    with TestClient(create_app(), base_url="https://testserver", headers=headers) as c:
        r = c.post("/scheduler/api/polls", headers=api, json={
            "title": "Cleanup", "mode": "full_day", "creator": "alice",
            "slots": [{"date": "2026-07-01"}]})
        poll = r.json()
        # web add-only invite: no mail sent, just created
        page = c.get(f"/scheduler/polls/{poll['id']}")
        import re
        m = re.search(r'name="csrf" value="([^"]*)"', page.text)
        csrf = m.group(1) if m else ""
        r = c.post(f"/scheduler/polls/{poll['id']}/invite",
                   data={"email": "bob@example.org", "optional": "on", "csrf": csrf},
                   follow_redirects=False)
        assert r.status_code == 302
        invites = c.get(f"/scheduler/api/polls/{poll['id']}", headers=api).json()["invites"]
        assert invites[0]["email"] == "bob@example.org" and invites[0]["required"] in (0, False)
        # duplicate guarded (friendly redirect)
        r = c.post(f"/scheduler/polls/{poll['id']}/invite",
                   data={"email": "bob@example.org", "csrf": csrf}, follow_redirects=False)
        assert r.status_code == 302 and "msg=duplicate" in r.headers["location"]
        # web removal of the invite
        r = c.post(f"/scheduler/polls/{poll['id']}/participants/remove",
                   data={"kind": "invite", "ref": invites[0]["id"], "csrf": csrf},
                   follow_redirects=False)
        assert r.status_code == 302
        assert c.get(f"/scheduler/api/polls/{poll['id']}", headers=api).json()["invites"] == []
        # API response deletion
        slot = poll["slots"][0]["id"]
        rid = c.post(f"/scheduler/api/polls/{poll['id']}/respond", headers=api,
                     json={"name": "Carol", "availabilities": {slot: "yes"}}).json()["id"]
        assert c.delete(f"/scheduler/api/polls/{poll['id']}/responses/{rid}",
                        headers=api).json() == {"deleted": True}
        assert c.delete(f"/scheduler/api/polls/{poll['id']}/responses/{rid}",
                        headers=api).status_code == 404


def test_named_invites_and_inline_edit(tmp_path, monkeypatch):
    """Names on invites: web add, API 'Name <addr>' form, PATCH, web update."""
    from kairos import settings
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/k.db")
    monkeypatch.setattr(settings, "API_KEY", "k")
    from kairos.main import create_app
    api = {"Authorization": "Bearer k"}
    headers = {"X-User": "alice", "X-Email": "a@e.org", "X-Name": "Alice"}
    with TestClient(create_app(), base_url="https://testserver", headers=headers) as c:
        poll = c.post("/scheduler/api/polls", headers=api, json={
            "title": "Named", "mode": "full_day", "creator": "alice",
            "slots": [{"date": "2026-07-01"}]}).json()
        pid = poll["id"]
        # API: RFC-5322 named entry
        c.post(f"/scheduler/api/polls/{pid}/invite", headers=api,
               json={"emails": ["Ada Lovelace <ada@example.org>"]})
        inv = c.get(f"/scheduler/api/polls/{pid}/invites", headers=api).json()[0]
        assert inv["name"] == "Ada Lovelace"
        # PATCH name + required
        r = c.patch(f"/scheduler/api/polls/{pid}/invites/{inv['id']}", headers=api,
                    json={"name": "Ada L.", "required": False})
        assert r.json() == {"updated": True}
        inv = c.get(f"/scheduler/api/polls/{pid}/invites", headers=api).json()[0]
        assert inv["name"] == "Ada L." and not inv["required"]
        # web: add with name + duplicate redirects friendly
        import re
        page = c.get(f"/scheduler/polls/{pid}")
        csrf = re.search(r'name="csrf" value="([^"]*)"', page.text).group(1)
        r = c.post(f"/scheduler/polls/{pid}/invite",
                   data={"email": "bob@example.org", "name": "Bob", "csrf": csrf},
                   follow_redirects=False)
        assert r.status_code == 302
        r = c.post(f"/scheduler/polls/{pid}/invite",
                   data={"email": "bob@example.org", "csrf": csrf}, follow_redirects=False)
        assert r.status_code == 302 and "msg=duplicate" in r.headers["location"]
        # web inline update route
        bob = [i for i in c.get(f"/scheduler/api/polls/{pid}/invites", headers=api).json()
               if i["email"] == "bob@example.org"][0]
        r = c.post(f"/scheduler/polls/{pid}/participants/update",
                   data={"kind": "invite", "ref": bob["id"], "name": "Robert",
                         "email": "robert@example.org", "optional": "on", "csrf": csrf},
                   follow_redirects=False)
        assert r.status_code == 302
        bob = [i for i in c.get(f"/scheduler/api/polls/{pid}/invites", headers=api).json()
               if i["id"] == bob["id"]][0]
        assert (bob["name"], bob["email"], bool(bob["required"])) == ("Robert", "robert@example.org", False)
        # payload feeds the table
        page = c.get(f"/scheduler/polls/{pid}")
        assert 'id="part-data"' in page.text and "Robert" in page.text


def test_via_link_respondent_optional_toggle(tmp_path, monkeypatch):
    """Via-link people count as required for convergence until marked optional."""
    from kairos import settings
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/k.db")
    monkeypatch.setattr(settings, "API_KEY", "k")
    from kairos.main import create_app
    api = {"Authorization": "Bearer k"}
    with TestClient(create_app(), base_url="https://testserver",
                    headers={"X-User": "alice", "X-Email": "a@e.org", "X-Name": "Alice"}) as c:
        poll = c.post("/scheduler/api/polls", headers=api, json={
            "title": "Conv", "mode": "full_day", "creator": "alice",
            "slots": [{"date": "2026-07-01"}, {"date": "2026-07-02"}]}).json()
        pid, s1, s2 = poll["id"], poll["slots"][0]["id"], poll["slots"][1]["id"]
        # two via-link respondents with disjoint availability -> blocked
        c.post(f"/scheduler/api/polls/{pid}/respond", headers=api,
               json={"name": "A", "email": "x@example.org",
                     "availabilities": {s1: "yes", s2: "no"}})
        rid = c.post(f"/scheduler/api/polls/{pid}/respond", headers=api,
                     json={"name": "B", "email": "y@example.org",
                           "availabilities": {s1: "no", s2: "yes"}}).json()["id"]
        from kairos.db import get_responses
        from kairos.helpers import convergence
        conv = convergence(poll, get_responses(pid), [])
        assert conv["state"] == "blocked"
        # mark B optional via the API -> a slot now works for the required set
        r = c.patch(f"/scheduler/api/polls/{pid}/responses/{rid}", headers=api,
                    json={"required": False})
        assert r.json() == {"updated": True}
        conv = convergence(poll, get_responses(pid), [])
        assert conv["state"] == "partial"


def test_reverse_calendar_feed_and_deeplink_vote(tmp_path, monkeypatch):
    """KAIROS_FEED on: subscribe-able candidate feed + deep-link Accept/Decline
    that upserts one slot at a time on the invitee's response."""
    from kairos import settings
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/k.db")
    monkeypatch.setattr(settings, "API_KEY", "k")
    monkeypatch.setattr(settings, "FEED_ENABLED", True)
    from kairos.main import create_app
    api = {"Authorization": "Bearer k"}
    with TestClient(create_app(), base_url="https://testserver") as c:
        poll = c.post("/scheduler/api/polls", headers=api, json={
            "title": "Reverse cal", "mode": "full_day", "creator": "alice",
            "slots": [{"date": "2026-07-06"}, {"date": "2026-07-07"}]}).json()
        pid, token = poll["id"], poll["public_token"]
        s1, s2 = poll["slots"][0]["id"], poll["slots"][1]["id"]

        # public candidate feed while open: TENTATIVE events, subscribe-able
        feed = c.get(f"/scheduler/p/{token}/event.ics")
        assert feed.status_code == 200
        assert feed.headers["content-type"].startswith("text/calendar")
        assert feed.text.count("BEGIN:VEVENT") == 2 and "STATUS:TENTATIVE" in feed.text

        # an invite -> per-invite feed carries deep-link vote URLs
        from kairos.db import create_invite, get_responses
        itok = create_invite(pid, "bob@x.ch", required=True, name="Bob")["token"]
        ifeed = c.get(f"/scheduler/p/i/{itok}/feed.ics")
        assert ifeed.status_code == 200
        unfolded = ifeed.text.replace("\r\n ", "")  # RFC 5545 unfold
        assert f"/scheduler/p/i/{itok}/s/{s1}/yes" in unfolded

        # tap a deep link -> records the vote, lands on the poll page
        r = c.get(f"/scheduler/p/i/{itok}/s/{s1}/yes")
        assert r.status_code == 200 and "Accepted" in r.text
        resp = get_responses(pid)
        assert len(resp) == 1 and resp[0]["slot_availabilities"][s1] == "yes"
        assert resp[0]["respondent_email"] == "bob@x.ch"

        # a second tap on the other slot upserts WITHOUT clobbering the first
        c.get(f"/scheduler/p/i/{itok}/s/{s2}/no")
        resp = get_responses(pid)
        assert resp[0]["slot_availabilities"] == {s1: "yes", s2: "no"}

        # invalid availability is rejected
        assert c.get(f"/scheduler/p/i/{itok}/s/{s1}/perhaps").status_code == 404


def test_feed_disabled_by_default(tmp_path, monkeypatch):
    """With KAIROS_FEED off, open-poll feeds + deep links don't exist (404)."""
    from kairos import settings
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/k.db")
    monkeypatch.setattr(settings, "API_KEY", "k")
    monkeypatch.setattr(settings, "FEED_ENABLED", False)
    from kairos.main import create_app
    api = {"Authorization": "Bearer k"}
    with TestClient(create_app(), base_url="https://testserver") as c:
        poll = c.post("/scheduler/api/polls", headers=api, json={
            "title": "No feed", "mode": "full_day", "creator": "alice",
            "slots": [{"date": "2026-07-06"}]}).json()
        # open poll + feed off -> falls through to the decided-event path (none yet)
        assert c.get(f"/scheduler/p/{poll['public_token']}/event.ics").status_code == 404
        from kairos.db import create_invite
        itok = create_invite(poll["id"], "b@x.ch")["token"]
        assert c.get(f"/scheduler/p/i/{itok}/feed.ics").status_code == 404
        assert c.get(f"/scheduler/p/i/{itok}/s/{poll['slots'][0]['id']}/yes").status_code == 404
