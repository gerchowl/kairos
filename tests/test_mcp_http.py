"""Issue #83: server-hosted MCP transport — streamable HTTP ``POST /mcp``.

What has to hold on this surface, and why each assertion earns its place:

1. **Protocol shape.** JSON-RPC 2.0 over streamable HTTP, spec 2025-06-18:
   ``initialize`` advertises that version, ``tools/list`` returns the
   surface's tools with JSON Schemas, ``tools/call`` dispatches them,
   ``notifications/initialized`` 202-no-bodies, malformed inputs come back as
   the spec's standard error codes, batches are refused (removed in
   2025-06-18), ``GET``/``DELETE`` are 405, the ``MCP-Protocol-Version``
   header lands on every response.

2. **One bearer, three states.** The same ``resolve`` function ``/api`` uses,
   so the three owner-token outcomes (revoked / expired / unknown) answer
   identically here; env keys come through the same keyring. A missing or
   malformed Bearer is 401 with ``WWW-Authenticate: Bearer`` set.

3. **Tool set parity with the stdio adapter.** Every tool
   ``mcp/kairos_mcp.py`` exposes is here, and with the same name; drift
   between the two is the one thing an operator cannot see at the call site
   and is the shape issue #83 names as "same tool set".

4. **Scope / reach / budgets flow through the same code paths.** A read-only
   key cannot reach a mail-sending tool; an owner-token cannot read another
   owner's poll under ``scoped``; the per-key rate limit fires as a
   ``-32099`` JSON-RPC error carrying ``retry_after``; a creator spoof is
   refused by the owner-token guard in ``api.create_poll_endpoint``.

5. **Byte-identical parity with REST results for the same operation**, so a
   test that runs on one surface would run on the other — the property that
   lets ``_call_rest`` be a safe DRY seam rather than a parallel path
   waiting to drift.
"""

import json
from datetime import date, time

import pytest
from fastapi.testclient import TestClient

from kairos import api, apitokens, db, main, mcp_http, ratelimit, settings

KEY = "test-api-key"
MCP = "/scheduler/mcp"

POLL = {
    "id": "p1",
    "creator_id": "u1",
    "owner_id": "u1",
    "title": "MCP poll",
    "description": None,
    "mode": "time_slot",
    "timezone": "Europe/Zurich",
    "status": "open",
    "decided_slot_id": None,
    "public_token": "tokA",
    "manage_verified_at": None,
    "slots": [
        {"id": "t1", "date": date(2026, 6, 8), "start_time": time(9, 0), "end_time": time(9, 30)},
        {"id": "t2", "date": date(2026, 6, 8), "start_time": time(9, 30), "end_time": time(10, 0)},
    ],
}

READER = "read-only-key"
SENDER = "mail-sender-key"
VOTER = "respond-only-key"
WRITER = "writer-key"
KEYRING = ";".join([
    f"{READER}:polls:read",
    f"{SENDER}:mail:send,polls:read",
    f"{VOTER}:respond,polls:read",
    f"{WRITER}:polls:write",
])


# -- Fixtures ---------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_limiter():
    """Rate-limit buckets are a module singleton. Reset between tests so a
    budget charged in one run does not refuse the first call of the next."""
    ratelimit.limiter.reset()
    yield
    ratelimit.limiter.reset()


@pytest.fixture
def stubbed(monkeypatch):
    """DB + SMTP stubs — these tests are about the MCP surface, not the backend."""
    sent: list[str] = []
    monkeypatch.setattr(api, "get_poll", lambda pid: dict(POLL) if pid == "p1" else None)
    monkeypatch.setattr(api, "get_responses", lambda pid: [])
    monkeypatch.setattr(api, "get_invites", lambda pid: [])
    monkeypatch.setattr(api, "create_poll", lambda creator, *a, **k: dict(POLL))
    monkeypatch.setattr(api, "update_poll", lambda pid, **k: dict(POLL))
    monkeypatch.setattr(api, "add_slots", lambda pid, slots: slots)
    monkeypatch.setattr(api, "add_response", lambda *a, **k: {"id": "r1"})
    monkeypatch.setattr(api, "find_response_by_email", lambda *a, **k: None)
    monkeypatch.setattr(api, "notify_new_response", lambda *a, **k: None)
    monkeypatch.setattr(api, "create_invite",
                        lambda pid, email, required=True, name=None: {
                            "id": "i1", "token": "tk", "email": email,
                        })
    monkeypatch.setattr(api, "send_invite_email",
                        lambda to, *a, **k: sent.append(to) or True)
    monkeypatch.setattr(api, "send_decision_email",
                        lambda recips, *a, **k: list(recips))
    monkeypatch.setattr(api, "log_contact", lambda *a, **k: None)
    monkeypatch.setattr(api, "get_contact_log", lambda pid: [])
    monkeypatch.setattr(api, "recipient_emails", lambda pid: ["a@x.ch", "b@x.ch"])
    monkeypatch.setattr(api, "decided_slot_of", lambda poll: poll["slots"][0])
    monkeypatch.setattr(api, "list_polls", lambda: [dict(POLL)])
    # web.nudge_participants requires a bunch of stubs, keep it simple
    monkeypatch.setattr(api, "nudge_participants",
                        lambda req, poll, user, **k: {"invited": 0, "updated": 0, "skipped": 0})
    return sent


@pytest.fixture
def client(monkeypatch, stubbed):
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    c = TestClient(main.app, base_url="https://testserver")
    c.headers["Authorization"] = f"Bearer {KEY}"
    return c


# -- Helpers ----------------------------------------------------------------


def rpc(client, method, params=None, *, id=1, key=None):
    """Issue one JSON-RPC request; return the parsed envelope."""
    headers = {}
    if key is not None:
        headers["Authorization"] = f"Bearer {key}"
    body = {"jsonrpc": "2.0", "id": id, "method": method}
    if params is not None:
        body["params"] = params
    r = client.post(MCP, json=body, headers=headers or None)
    return r, (r.json() if r.content else None)


def call_tool(client, name, arguments=None, *, id=1, key=None):
    return rpc(client, "tools/call",
               {"name": name, "arguments": arguments or {}}, id=id, key=key)


# -- 1. Protocol shape ------------------------------------------------------


def test_initialize_advertises_the_current_protocol_version_and_tools_capability(client):
    r, env = rpc(client, "initialize", {})
    assert r.status_code == 200
    assert env["jsonrpc"] == "2.0"
    assert env["id"] == 1
    assert env["result"]["protocolVersion"] == mcp_http.PROTOCOL_VERSION
    assert env["result"]["capabilities"]["tools"] == {"listChanged": False}
    assert env["result"]["serverInfo"]["name"] == "kairos"
    # Protocol version header on every response, per the spec.
    assert r.headers["MCP-Protocol-Version"] == mcp_http.PROTOCOL_VERSION


def test_notifications_initialized_answers_202_with_empty_body(client):
    r = client.post(MCP, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert r.status_code == 202
    assert r.content == b""
    assert r.headers["MCP-Protocol-Version"] == mcp_http.PROTOCOL_VERSION


def test_ping_is_a_zero_arg_health_check(client):
    r, env = rpc(client, "ping")
    assert r.status_code == 200 and env["result"] == {}


def test_tools_list_returns_the_kairos_surface_with_input_schemas(client):
    r, env = rpc(client, "tools/list")
    assert r.status_code == 200
    names = [t["name"] for t in env["result"]["tools"]]
    assert set(names) == set(mcp_http.tool_names())
    for tool in env["result"]["tools"]:
        assert "description" in tool and tool["description"]
        schema = tool["inputSchema"]
        assert schema["type"] == "object"
        # A poll-id tool must declare poll_id in its required fields — the
        # exact shape the tool-call dispatcher reads.
        meta = mcp_http._TOOL_INDEX[tool["name"]]
        if meta["reach"]:
            assert "poll_id" in schema["required"]


def test_unknown_method_is_method_not_found(client):
    r, env = rpc(client, "no/such/method")
    assert r.status_code == 200
    assert env["error"]["code"] == mcp_http.METHOD_NOT_FOUND


def test_a_body_that_is_not_valid_json_is_a_parse_error(client):
    r = client.post(MCP, content="{not json", headers={"Content-Type": "application/json"})
    assert r.status_code == 200
    env = r.json()
    assert env["error"]["code"] == mcp_http.PARSE_ERROR


def test_missing_jsonrpc_field_is_invalid_request(client):
    r = client.post(MCP, json={"id": 1, "method": "ping"})
    env = r.json()
    assert env["error"]["code"] == mcp_http.INVALID_REQUEST


def test_a_batch_is_refused_as_an_invalid_request(client):
    """Spec 2025-06-18 removed batching. A JSON array body is invalid."""
    r = client.post(MCP, json=[{"jsonrpc": "2.0", "id": 1, "method": "ping"}])
    env = r.json()
    assert env["error"]["code"] == mcp_http.INVALID_REQUEST


def test_tools_call_without_name_is_invalid_params(client):
    r, env = rpc(client, "tools/call", {})
    assert env["error"]["code"] == mcp_http.INVALID_PARAMS


def test_tools_call_arguments_must_be_an_object(client):
    r, env = rpc(client, "tools/call", {"name": "whoami", "arguments": "oops"})
    assert env["error"]["code"] == mcp_http.INVALID_PARAMS


def test_get_and_delete_answer_405(client):
    for method in ("GET", "DELETE"):
        r = client.request(method, MCP)
        assert r.status_code == 405
        assert r.headers.get("Allow") == "POST"


# -- 2. Auth ---------------------------------------------------------------


def test_no_bearer_is_401_with_www_authenticate(monkeypatch, stubbed):
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    c = TestClient(main.app, base_url="https://testserver")
    r = c.post(MCP, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert r.status_code == 401
    assert r.headers.get("WWW-Authenticate") == "Bearer"


def test_wrong_bearer_is_401(monkeypatch, stubbed):
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": "Bearer wrong"})
    r = c.post(MCP, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert r.status_code == 401


def test_an_env_key_can_call_tools_list_the_same_way(client):
    r, env = rpc(client, "tools/list")
    assert r.status_code == 200
    assert "tools" in env["result"]


def test_an_owner_token_authenticates_just_like_an_env_key(monkeypatch, stubbed):
    """The seam #82 added is what both surfaces call — same `resolve_token`,
    so the hosted MCP endpoint picks up every live token the REST does."""
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    token_plain = "kai_" + "x" * 43
    row = {
        "id": "t1", "owner_uid": "u1", "name": "n",
        "token_hash": apitokens._hash(token_plain),
        "prefix": token_plain[:12], "scopes": "polls:read",
        "created_at": apitokens._now(),
        "expires_at": apitokens._now().replace(year=apitokens._now().year + 1),
        "last_used_at": None, "revoked_at": None,
    }
    monkeypatch.setattr(db, "get_api_token_by_hash", lambda h: row)
    monkeypatch.setattr(apitokens, "_should_touch", lambda _tid: False)
    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": f"Bearer {token_plain}"})
    r, env = rpc(c, "tools/call", {"name": "whoami", "arguments": {}})
    assert r.status_code == 200, r.text
    assert "isError" not in env["result"]
    payload = json.loads(env["result"]["content"][0]["text"])
    assert payload["kind"] == "owner_token"
    assert payload["owner"] == "u1"


def test_a_revoked_token_is_401_identical_to_a_wrong_one(monkeypatch, stubbed):
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    token_plain = "kai_" + "x" * 43
    monkeypatch.setattr(db, "get_api_token_by_hash", lambda h: {
        "id": "t1", "owner_uid": "u1", "name": "n",
        "token_hash": apitokens._hash(token_plain),
        "prefix": token_plain[:12], "scopes": "polls:read",
        "created_at": apitokens._now(),
        "expires_at": apitokens._now().replace(year=apitokens._now().year + 1),
        "last_used_at": None, "revoked_at": apitokens._now(),
    })
    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": f"Bearer {token_plain}"})
    r, _env = rpc(c, "ping")
    assert r.status_code == 401


# -- 3. Tool-set parity with the stdio adapter -----------------------------


def test_the_hosted_tool_set_matches_the_stdio_adapter():
    """Issue #83's required test: an agent that works today with
    ``mcp/kairos_mcp.py`` must find the same tools on ``/mcp``. We parse the
    adapter file rather than importing it — the adapter has an inline-PEP-723
    dep on the ``mcp`` package which is not in the project env.
    """
    import re
    from pathlib import Path

    stdio = Path(__file__).resolve().parents[1] / "mcp" / "kairos_mcp.py"
    text = stdio.read_text()
    pattern = re.compile(r"@mcp\.tool\(\)\s+def\s+(\w+)\s*\(", re.MULTILINE)
    stdio_tools = set(pattern.findall(text))
    assert stdio_tools, "stdio adapter changed shape — update the parser"
    hosted_tools = set(mcp_http.tool_names())
    assert stdio_tools == hosted_tools, (
        f"stdio-only: {sorted(stdio_tools - hosted_tools)}; "
        f"hosted-only: {sorted(hosted_tools - stdio_tools)}"
    )


# -- 4. Scope / reach / budgets --------------------------------------------


def _as(c: TestClient, key: str) -> TestClient:
    c.headers["Authorization"] = f"Bearer {key}"
    return c


def test_a_read_only_key_cannot_call_a_mail_sending_tool(monkeypatch, stubbed):
    monkeypatch.setattr(settings, "API_KEYS", KEYRING)
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    c = _as(TestClient(main.app, base_url="https://testserver"), READER)
    r, env = call_tool(c, "invite", {"poll_id": "p1", "emails": ["a@x.ch"]})
    assert r.status_code == 200
    result = env["result"]
    assert result.get("isError") is True
    text = result["content"][0]["text"]
    assert "403" in text
    assert "mail:send" in text  # the missing scope the refusal must name
    assert stubbed == [], "a refused call must not send"


def test_a_read_only_key_can_read(monkeypatch, stubbed):
    monkeypatch.setattr(settings, "API_KEYS", KEYRING)
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    c = _as(TestClient(main.app, base_url="https://testserver"), READER)
    r, env = call_tool(c, "list_polls")
    assert r.status_code == 200
    assert "isError" not in env["result"]


def test_two_owner_tokens_cannot_read_each_others_polls(monkeypatch, stubbed):
    """Issue #82's promise on the MCP surface: an owner-minted token reaches
    only polls its owner holds management authority over. The REST path
    enforces this via `reach.guard_reach`; here we enforce it via
    `reach.guard_reach_id` — the same `_is_owner_token_for` branch."""
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    monkeypatch.setenv("KAIROS_POLL_REACH", "scoped")
    other_poll = dict(POLL, id="p2", creator_id="u2", owner_id="u2")

    def get(pid):
        if pid == "p1":
            return dict(POLL)
        if pid == "p2":
            return dict(other_poll)
        return None
    monkeypatch.setattr(api, "get_poll", get)
    monkeypatch.setattr(db, "get_poll", get)

    tok_u1 = "kai_" + "a" * 43
    tok_u2 = "kai_" + "b" * 43
    rows = {
        apitokens._hash(tok_u1): {
            "id": "t1", "owner_uid": "u1", "name": "u1-tok",
            "token_hash": apitokens._hash(tok_u1),
            "prefix": tok_u1[:12], "scopes": "polls:read",
            "created_at": apitokens._now(),
            "expires_at": apitokens._now().replace(year=apitokens._now().year + 1),
            "last_used_at": None, "revoked_at": None,
        },
        apitokens._hash(tok_u2): {
            "id": "t2", "owner_uid": "u2", "name": "u2-tok",
            "token_hash": apitokens._hash(tok_u2),
            "prefix": tok_u2[:12], "scopes": "polls:read",
            "created_at": apitokens._now(),
            "expires_at": apitokens._now().replace(year=apitokens._now().year + 1),
            "last_used_at": None, "revoked_at": None,
        },
    }
    monkeypatch.setattr(db, "get_api_token_by_hash", lambda h: rows.get(h))
    monkeypatch.setattr(apitokens, "_should_touch", lambda _tid: False)

    c = TestClient(main.app, base_url="https://testserver")

    # u1 reaches their own poll p1
    c.headers["Authorization"] = f"Bearer {tok_u1}"
    r, env = call_tool(c, "get_poll", {"poll_id": "p1"})
    assert r.status_code == 200
    assert "isError" not in env["result"], env["result"]

    # u1 is refused u2's poll p2 — and the refusal names the owner, not the key
    r, env = call_tool(c, "get_poll", {"poll_id": "p2"})
    assert r.status_code == 200
    assert env["result"].get("isError") is True
    text = env["result"]["content"][0]["text"]
    assert "403" in text
    assert "u1" in text, "the 403 should say which owner this token acts for"


def test_a_rate_limit_fires_as_a_json_rpc_error_with_retry_after(monkeypatch, stubbed):
    """Issue #51 budgets on `/mcp`. When `KAIROS_RATE_LIMIT=on` fires the
    `api` rule, a JSON-RPC error (not an isError result) carries the
    rule name and retry_after so an agent's loop can back off."""
    monkeypatch.setattr(settings, "API_KEYS", KEYRING)
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "RATE_LIMITS",
                        {**settings.DEFAULT_RATE_LIMITS, "api": (1, 60)})
    c = _as(TestClient(main.app, base_url="https://testserver"), READER)
    # First call spends the budget.
    r1, _ = call_tool(c, "whoami", id=1)
    assert r1.status_code == 200
    # Second call is refused as a JSON-RPC error.
    r2, env = call_tool(c, "whoami", id=2)
    assert r2.status_code == 200
    assert env.get("result") is None
    assert env["error"]["code"] == mcp_http.RATE_LIMITED_CODE
    assert env["error"]["data"]["rule"] == "api"
    assert env["error"]["data"]["retry_after"] >= 1


def test_an_owner_token_cannot_spoof_the_creator_on_create(monkeypatch, stubbed):
    """`api.create_poll_endpoint`'s owner-token guard is reached from `/mcp`
    identically: a token bound to u1 may not attribute a poll to u2."""
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    tok = "kai_" + "c" * 43
    row = {
        "id": "tt", "owner_uid": "u1", "name": "n",
        "token_hash": apitokens._hash(tok),
        "prefix": tok[:12], "scopes": "polls:write,polls:read",
        "created_at": apitokens._now(),
        "expires_at": apitokens._now().replace(year=apitokens._now().year + 1),
        "last_used_at": None, "revoked_at": None,
    }
    monkeypatch.setattr(db, "get_api_token_by_hash", lambda h: row)
    monkeypatch.setattr(apitokens, "_should_touch", lambda _tid: False)
    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": f"Bearer {tok}"})
    r, env = call_tool(c, "create_poll", {
        "title": "t", "mode": "full_day",
        "slots": [{"date": "2026-06-08"}], "creator": "u2",
    })
    assert r.status_code == 200
    assert env["result"].get("isError") is True
    assert "403" in env["result"]["content"][0]["text"]


# -- 5. REST/MCP byte-identical parity -------------------------------------


def test_the_mcp_tool_and_the_rest_route_answer_the_same_poll_detail(client):
    """The same operation on both surfaces must yield the same payload: the
    hosted MCP transport is explicitly a wrapper, not a parallel path, and
    this is the shape of that property."""
    rest = client.get("/scheduler/api/polls/p1").json()
    r, env = call_tool(client, "get_poll", {"poll_id": "p1"})
    assert r.status_code == 200
    mcp_result = json.loads(env["result"]["content"][0]["text"])
    assert mcp_result == rest


def test_create_via_mcp_returns_the_same_shape_as_rest(client, monkeypatch):
    captured = []
    def fake_create(creator, *a, **k):
        captured.append(creator)
        return dict(POLL)
    monkeypatch.setattr(api, "create_poll", fake_create)
    r, env = call_tool(client, "create_poll", {
        "title": "t", "mode": "full_day",
        "slots": [{"date": "2026-06-08"}], "creator": "lars",
    })
    assert r.status_code == 200
    assert "isError" not in env["result"]
    result = json.loads(env["result"]["content"][0]["text"])
    assert captured == ["lars"]
    assert result["share_url"].endswith("/scheduler/p/tokA")


def test_get_ics_returns_the_calendar_body_as_text_content(client, monkeypatch):
    decided = dict(POLL, status="decided", decided_slot_id="t1")
    monkeypatch.setattr(api, "get_poll", lambda pid: decided)
    r, env = call_tool(client, "get_ics", {"poll_id": "p1"})
    assert r.status_code == 200
    text = env["result"]["content"][0]["text"]
    assert "BEGIN:VCALENDAR" in text
    assert "DTSTART:20260608T070000Z" in text  # same assertion as the REST test


# -- 6. Origin validation (spec requirement) --------------------------------


def test_origin_is_checked_when_the_allowlist_is_configured(monkeypatch, stubbed):
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    monkeypatch.setenv("KAIROS_MCP_ALLOWED_ORIGINS",
                       "https://claude.ai,https://cursor.so")
    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": f"Bearer {KEY}"})
    # No Origin header — allowed (allowlist is not a membership requirement,
    # it is a refusal list for browsers that send Origin).
    r1 = c.post(MCP, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert r1.status_code == 200
    # Allowed Origin — ok.
    r2 = c.post(MCP, json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
                headers={"Origin": "https://claude.ai"})
    assert r2.status_code == 200
    # Wrong Origin — refused.
    r3 = c.post(MCP, json={"jsonrpc": "2.0", "id": 3, "method": "ping"},
                headers={"Origin": "https://evil.example"})
    assert r3.status_code == 403


def test_without_an_allowlist_origin_is_not_consulted(client):
    r = client.post(MCP, json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 200  # same as `/api` — Origin is only checked when configured
