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
import tracemalloc
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
    monkeypatch.setattr(api, "add_slots_capped", lambda pid, slots, cap: slots)
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


def test_without_an_allowlist_a_request_with_no_origin_header_still_passes(client):
    """Spec: streamable-HTTP servers MUST validate Origin. The resulting
    policy is: a request with NO Origin header passes (curl, `claude mcp`,
    every non-browser agent), and a request WITH an Origin header passes
    only if it is listed in `KAIROS_MCP_ALLOWED_ORIGINS`. The default empty
    allowlist is the safe default — see
    `test_origin_bearing_request_is_403_when_no_allowlist_is_configured`."""
    # No Origin header — request passes regardless of allowlist.
    r = client.post(MCP, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert r.status_code == 200


# -- 7. Regression tests for PR #89 adversarial-review findings ------------
#
# Every test in this section was observed FAILING on head a7371f7 — the shape
# of the finding first, and only then the fix. The grouping below mirrors the
# finding order on the PR review.


# -- 7a. Finding 1: rate-limit bypass via validation-first ordering --------


def test_invalid_mcp_create_poll_still_charges_the_api_write_budget(monkeypatch, stubbed):
    """MEDIUM: before the fix, `_dispatch` built the Pydantic body FIRST and
    called `_authorize` after, so an invalid tool call (missing title, giant
    slot list, nested-bracket body) returned a 400 isError without ever
    charging the rate budget. REST does the opposite — `api_scope` charges
    before body validation — and the two surfaces must answer identically.
    Under 2/hour, three calls with no title must see the third one 429."""
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "RATE_LIMITS",
                        {**settings.DEFAULT_RATE_LIMITS, "api_write": (2, 3600)})
    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": f"Bearer {KEY}"})
    # Two malformed calls — charged, returned as tool errors.
    for i in (1, 2):
        _, env = call_tool(c, "create_poll", {}, id=i)
        assert env.get("result", {}).get("isError") is True, env
    # The third malformed call — budget exhausted. JSON-RPC rate-limit error.
    _, env = call_tool(c, "create_poll", {}, id=3)
    assert env.get("error", {}).get("code") == mcp_http.RATE_LIMITED_CODE, env
    assert env["error"]["data"]["rule"] == "api_write"


def test_rest_and_mcp_charge_the_same_budget_for_the_same_invalid_call(monkeypatch, stubbed):
    """Parity: REST and MCP must charge the same rule for the same tool, and
    at the same point in the chain. Interleave three REST calls and three
    MCP calls against a 3/hour budget; the fourth attempt on the combined
    stream must 429 regardless of which surface it lands on."""
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "RATE_LIMITS",
                        {**settings.DEFAULT_RATE_LIMITS, "api_write": (3, 3600)})
    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": f"Bearer {KEY}"})
    # Two REST calls (422) and one MCP call (isError) consume the budget.
    r1 = c.post("/scheduler/api/polls", json={})
    assert r1.status_code == 422, r1.text
    r2 = c.post("/scheduler/api/polls", json={})
    assert r2.status_code == 422
    _, env = call_tool(c, "create_poll", {}, id=1)
    assert env["result"]["isError"] is True
    # Fourth attempt — refused on whichever surface.
    _, env = call_tool(c, "create_poll", {}, id=2)
    assert env.get("error", {}).get("code") == mcp_http.RATE_LIMITED_CODE
    r4 = c.post("/scheduler/api/polls", json={})
    assert r4.status_code == 429, r4.text


# -- 7b. Finding 2: argument coercion and REST/MCP parity ------------------


def test_mcp_invite_required_false_string_coerces_to_false_like_rest(client, monkeypatch):
    """`bool("false")` is True in Python. The old code wrote
    `required=bool(params.get("required", True))`, so `required:"false"` on
    the wire stored True — the opposite of what the caller asked for. The
    fix uses `InviteCreate.model_validate(...)`, which coerces the string
    exactly as REST's body parser does."""
    captured: dict = {}

    def fake(poll_id, body, request, user):
        captured["body"] = body
        return {"invites": []}

    monkeypatch.setattr(api, "invite_endpoint", fake)
    _, env = call_tool(client, "invite", {
        "poll_id": "p1", "emails": ["a@x.ch"], "required": "false",
    })
    assert "result" in env, env
    assert captured["body"].required is False, captured["body"]


def test_mcp_nudge_force_false_string_does_not_charge_mail_force(client, monkeypatch):
    """`bool("false")` is True, so the old `force=bool(params.get("force"))`
    turned `force:"false"` into True and bypassed the 24h cooldown — a path
    that also demanded `mail:force` scope and spent the tight `mail_force`
    budget. Pydantic coerces the string to False correctly."""
    captured: dict = {}

    def fake(poll_id, body, request, user):
        captured["body"] = body
        return {"invited": 0}

    monkeypatch.setattr(api, "nudge_endpoint", fake)
    _, env = call_tool(client, "nudge", {
        "poll_id": "p1", "force": "false",
    })
    assert "result" in env, env
    assert captured["body"].force is False


def test_mcp_add_dates_notify_false_string_does_not_require_mail_scope(monkeypatch, stubbed):
    """`add_dates notify:"false"` used to coerce to True (bool of non-empty
    string), which in turn demanded `mail:send` on top of `polls:write` —
    a reader with a polls:write-only key got a 403 for a request they never
    asked to mail. Pydantic coerces "false" to False so no mail:send check
    is triggered."""
    monkeypatch.setattr(settings, "API_KEYS", KEYRING)
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    captured: dict = {}

    def fake(poll_id, body, request, user):
        captured["body"] = body
        return {"added": body.dates, "nudged": None}

    monkeypatch.setattr(api, "add_slots_endpoint", fake)
    c = _as(TestClient(main.app, base_url="https://testserver"), WRITER)
    _, env = call_tool(c, "add_dates", {
        "poll_id": "p1", "dates": ["2026-06-09"], "notify": "false",
    })
    assert "result" in env and "isError" not in env["result"], env
    assert captured["body"].notify is False


def test_mcp_invite_emails_dict_is_a_validation_error_not_a_key_list(client, monkeypatch):
    """`list({"a": 1})` returns `["a"]`, so the old code happily sent an
    invite to the KEY of the dict — not the intent. Pydantic refuses a dict
    where a `list[str]` is required, so this reads as a 400 tool error."""
    monkeypatch.setattr(api, "invite_endpoint",
                        lambda *a, **k: pytest.fail("endpoint reached with invalid body"))
    _, env = call_tool(client, "invite", {
        "poll_id": "p1", "emails": {"evil@x.ch": 1},
    })
    assert env["result"].get("isError") is True, env
    assert "400" in env["result"]["content"][0]["text"]
    assert "emails" in env["result"]["content"][0]["text"]


def test_rest_and_mcp_refuse_the_same_bad_args_for_invite(client, monkeypatch):
    """Parity on argument validation: the REST route and the MCP tool must
    refuse the same inputs and accept the same ones, because the dispatcher
    now validates against the same Pydantic model."""
    # Bad emails type — dict — refused on both.
    r = client.post("/scheduler/api/polls/p1/invite", json={"emails": {"a": 1}})
    assert r.status_code == 422, r.text
    _, env = call_tool(client, "invite", {"poll_id": "p1", "emails": {"a": 1}})
    assert env["result"]["isError"] is True


# -- 7c. Finding 3: event-loop blocking ------------------------------------


def test_mcp_tool_dispatch_runs_in_a_worker_thread_not_the_event_loop(client, monkeypatch):
    """Finding 3: the endpoint used to be `async def` and called the whole
    sync chain (SQLite, SMTP, slot expansion) on the event loop, starving
    every concurrent request. The fix wraps auth + dispatch in
    `run_in_threadpool` — which Starlette runs on a DIFFERENT thread from
    the one the event loop is currently executing on. We detect that by
    asking for the running loop from inside the tool: on the fixed version
    the dispatch runs off-loop (so `asyncio.get_running_loop()` raises
    `RuntimeError`); on the pre-fix async handler the dispatch runs ON the
    loop and the call succeeds."""
    import asyncio

    seen: dict = {}

    def spy(user):
        try:
            asyncio.get_running_loop()
            seen["on_loop"] = True
        except RuntimeError:
            seen["on_loop"] = False
        return {"scopes": [], "key_id": "k", "tier": None, "polls": [], "reach_policy": "open"}

    monkeypatch.setattr(api, "whoami", spy)
    r, _env = call_tool(client, "whoami")
    assert r.status_code == 200
    assert seen.get("on_loop") is False, (
        "tool dispatch must run OFF the event loop (otherwise one slow call "
        "stalls every concurrent request on the same instance)"
    )


# -- 7d. Finding 4: malformed args → plain-text 500 ------------------------


def test_body_parser_handles_recursionerror_and_valueerror_as_parse_errors():
    """A nested-brackets body used to drive `json.loads` into a
    RecursionError that bubbled out as a plain-text 500 — breaking the MCP
    wire format a client reads. `_parse_body` now catches RecursionError,
    ValueError and JSONDecodeError so every parse pathology lands as a
    JSON-RPC parse-error envelope, not a wire-format violation.

    Tested against `_parse_body` directly rather than against a payload at
    some depth, because CPython and PyPy have different stack behaviours
    and a depth that trips RecursionError under one interpreter sails
    through another. The three branches we care about — malformed JSON,
    ValueError, RecursionError — are exercised by three calls here."""
    import json as _jsonlib

    # (1) Malformed JSON → PARSE_ERROR (JSONDecodeError path).
    msg, err = mcp_http._parse_body(b"{not json")
    assert msg is None and err is not None
    assert err["error"]["code"] == mcp_http.PARSE_ERROR

    # (2) Plain ValueError from the parser → PARSE_ERROR.
    def ve(*_a, **_k):
        raise ValueError("deliberate ValueError")

    old = _jsonlib.loads
    _jsonlib.loads = ve
    try:
        msg, err = mcp_http._parse_body(b'{"x":1}')
    finally:
        _jsonlib.loads = old
    assert msg is None and err is not None
    assert err["error"]["code"] == mcp_http.PARSE_ERROR

    # (3) RecursionError from the parser → PARSE_ERROR (not a plain 500).
    def re(*_a, **_k):
        raise RecursionError("deliberate RecursionError")

    _jsonlib.loads = re
    try:
        msg, err = mcp_http._parse_body(b'{"x":1}')
    finally:
        _jsonlib.loads = old
    assert msg is None and err is not None
    assert err["error"]["code"] == mcp_http.PARSE_ERROR


def test_a_body_over_the_cap_is_413_with_a_parse_error_envelope(client):
    """Oversized bodies were read into memory in full before parsing. The
    cap refuses them at 413 with a JSON-RPC parse error envelope so an MCP
    client's error handler still sees the protocol-level refusal."""
    oversized = b'{"jsonrpc":"2.0","id":1,"method":"ping","x":"' + b"a" * (2 * 1024 * 1024) + b'"}'
    r = client.post(MCP, content=oversized, headers={
        "Content-Type": "application/json",
        "Content-Length": str(len(oversized)),
    })
    assert r.status_code == 413
    env = r.json()
    assert env["error"]["code"] == mcp_http.PARSE_ERROR


def test_a_tool_exception_becomes_an_isError_result_not_a_plain_500(client, monkeypatch):
    """Finding 4 generic guard: if a tool raises an unexpected Exception
    (not an HTTPException, not a ValidationError), the response must still
    be a well-formed MCP envelope — not a plain-text 500 — so a client's
    `result.isError` path keeps working."""
    def boom(**kwargs):
        raise RuntimeError("something went wrong")

    monkeypatch.setattr(api, "whoami", boom)
    r, env = call_tool(client, "whoami")
    assert r.status_code == 200, r.text
    assert env["result"]["isError"] is True
    # The message must be generic — no traceback leak.
    text = env["result"]["content"][0]["text"]
    assert "500" in text
    assert "something went wrong" not in text


# -- 7e. Finding 5: protocol knobs -----------------------------------------


def test_unsupported_mcp_protocol_version_header_is_400(client):
    """Spec §4: a client that supplies MCP-Protocol-Version with an
    unsupported value must be refused with 400."""
    r = client.post(MCP, json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                    headers={"MCP-Protocol-Version": "1999-01-01"})
    assert r.status_code == 400
    assert "Unsupported MCP-Protocol-Version" in r.text


def test_supported_mcp_protocol_version_header_is_accepted(client):
    """The current spec version and the previous widely-used revision are
    both honoured — clients built against either must not be refused."""
    for version in ("2025-06-18", "2025-03-26"):
        r = client.post(MCP, json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                        headers={"MCP-Protocol-Version": version})
        assert r.status_code == 200, f"{version}: {r.text}"


def test_a_jsonrpc_id_that_is_not_string_number_or_null_is_invalid(client):
    """JSON-RPC 2.0 §4.1: id must be String, Number, or Null. A bool or an
    object is an Invalid Request (not an Internal Error), because an id
    that cannot be echoed back as the client sent it cannot correlate."""
    for bad in (True, False, {"x": 1}, ["a"]):
        r = client.post(MCP, json={"jsonrpc": "2.0", "id": bad, "method": "ping"})
        assert r.status_code == 200
        env = r.json()
        assert env["error"]["code"] == mcp_http.INVALID_REQUEST, (bad, env)


def test_origin_match_is_case_insensitive_and_trailing_slash_tolerant(monkeypatch, stubbed):
    """Finding 5: before the fix, a bare-string compare refused
    `https://CLAUDE.AI` or `https://claude.ai/` even when the operator had
    listed `https://claude.ai`. The normaliser lowercases scheme/host and
    strips a trailing slash, so all three forms match one allowlist entry."""
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    monkeypatch.setenv("KAIROS_MCP_ALLOWED_ORIGINS", "https://claude.ai")
    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": f"Bearer {KEY}"})
    for origin in ("https://claude.ai", "https://CLAUDE.AI",
                   "https://claude.ai/", "HTTPS://claude.ai"):
        r = c.post(MCP, json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                   headers={"Origin": origin})
        assert r.status_code == 200, f"{origin}: {r.text}"
    # And one that should still be refused.
    r = c.post(MCP, json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
               headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


# -- 7f. PR #89 final round — adversarial-review findings ------------------
#
# Every test in this section was observed FAILING on head 20547bd — the shape
# of the finding first, and only then the fix. The grouping mirrors the
# fix list in the final review round.


# -- 7f.1 MEDIUM: ids NaN/Infinity, lone-surrogate strings, … → plain 500 -

def test_mcp_endpoint_never_returns_a_non_json_response_for_any_fuzz_input(client):
    """MEDIUM: a request id of NaN / ±Infinity, a lone-surrogate string, or
    otherwise malformed JSON used to drive the fallback error path through
    code that cannot encode the id (Starlette's `allow_nan=False` renderer,
    or UTF-8 encoding of a lone surrogate), so the response fell out as a
    plain-text HTTP 500 — breaking the MCP wire format. Every body in this
    fuzz list must now come back as a VALID JSON response, never a 500 and
    never a non-JSON body.
    """
    import pytest as _pt

    fuzz_bodies = [
        b"",                                                      # empty body
        b"null",                                                  # JSON null
        b"true",                                                  # JSON true
        b"[]",                                                    # empty array (batch refused)
        b'"str"',                                                 # scalar string
        b"123",                                                   # scalar number
        b'{"jsonrpc":"2.0","id":NaN,"method":"ping"}',            # NaN id
        b'{"jsonrpc":"2.0","id":Infinity,"method":"ping"}',       # Infinity id
        b'{"jsonrpc":"2.0","id":-Infinity,"method":"ping"}',      # -Infinity id
        b'{"jsonrpc":"2.0","id":"\xed\xa0\x80","method":"ping"}',  # lone surrogate (invalid UTF-8)
        b'{"jsonrpc":"2.0","id":"\\ud800","method":"ping"}',      # lone surrogate as JSON escape
        b'{"jsonrpc":"2.0","id":99999999999999999999999999999,"method":"ping"}',  # huge int
        b'{"jsonrpc":"2.0","id":1,"method":"ping","extra":NaN}',  # NaN in body param
        b"\xef\xbb\xbf" + b'{"jsonrpc":"2.0","id":1,"method":"ping"}',  # BOM-prefixed
        b"\xff\xfe\xfd",                                          # invalid UTF-8 bytes
        b"[" * 500 + b"]" * 500,                                  # deep nesting under cap
        b'{"jsonrpc":"2.0","id":true,"method":"ping"}',           # bool id (not JSON-RPC)
        b'{"jsonrpc":"2.0","id":{"nested":1},"method":"ping"}',   # object id
        b"{not json",                                             # outright malformed
    ]
    for body in fuzz_bodies:
        r = client.post(MCP, content=body, headers={"Content-Type": "application/json"})
        assert r.status_code != 500, (
            f"body {body!r} drove a plain 500: {r.text[:200]!r}"
        )
        # The response body must be valid JSON — an MCP client reads
        # `result.isError` / `error.code`, not an HTML 500 page.
        try:
            env = r.json()
        except Exception as e:  # pragma: no cover — asserting below
            _pt.fail(f"body {body!r} → non-JSON response (status {r.status_code}): "
                     f"{r.text[:200]!r} ({e})")
        # Every failure response names a JSON-RPC envelope (either an error
        # or a WWW-Authenticate 401 detail).
        assert isinstance(env, dict), f"body {body!r} → {env!r}"


def test_nan_and_infinity_ids_are_parse_errors_not_server_errors(client):
    """JSON `NaN` / ±Infinity are not valid JSON (ECMA-404); Python's
    `json.loads` accepts them by default but Starlette's JSONResponse
    renderer cannot emit them. `parse_constant=` raises them at parse time,
    so they come back as a JSON-RPC parse error, not a 500."""
    for body in (
        b'{"jsonrpc":"2.0","id":NaN,"method":"ping"}',
        b'{"jsonrpc":"2.0","id":Infinity,"method":"ping"}',
        b'{"jsonrpc":"2.0","id":-Infinity,"method":"ping"}',
    ):
        r = client.post(MCP, content=body, headers={"Content-Type": "application/json"})
        assert r.status_code == 200
        env = r.json()
        assert env["error"]["code"] == mcp_http.PARSE_ERROR, (body, env)


def test_lone_surrogate_id_is_an_invalid_request_with_null_id_echo(client):
    """A `"id": "\\ud800"` body parses to a Python string whose UTF-8
    encoding fails. `_valid_jsonrpc_id` refuses it, and the envelope error
    path echoes `id: null` back — the alternative would 500 on the
    JSONResponse renderer."""
    body = b'{"jsonrpc":"2.0","id":"\\ud800","method":"ping"}'
    r = client.post(MCP, content=body, headers={"Content-Type": "application/json"})
    assert r.status_code == 200, r.text
    env = r.json()
    assert env["error"]["code"] == mcp_http.INVALID_REQUEST
    assert env["id"] is None


def test_valid_jsonrpc_id_rejects_non_finite_floats_and_bad_strings():
    """Unit guard for the id validator: non-finite floats and
    non-UTF-8-encodable strings are not safe to echo back, so they are
    excluded from the acceptance set, regardless of how they got past the
    parser."""
    assert mcp_http._valid_jsonrpc_id(float("nan")) is False
    assert mcp_http._valid_jsonrpc_id(float("inf")) is False
    assert mcp_http._valid_jsonrpc_id(float("-inf")) is False
    assert mcp_http._valid_jsonrpc_id("\udc00") is False
    assert mcp_http._valid_jsonrpc_id("\ud800") is False
    # And the valid shapes still pass.
    assert mcp_http._valid_jsonrpc_id(1) is True
    assert mcp_http._valid_jsonrpc_id("ok") is True
    assert mcp_http._valid_jsonrpc_id(None) is True
    assert mcp_http._valid_jsonrpc_id(3.14) is True


# -- 7f.2 LOW: tools/call with id null → invalid request, not 202 ---------

def test_tools_call_with_id_null_is_invalid_request_not_a_notification(client):
    """MCP spec 2025-06-18 §4: a request id MUST NOT be null. A `tools/call`
    with `"id": null` used to be read as a notification (202 empty body)
    — the comment even said "refuse rather than silently drop it" but the
    code dropped it. It must now be an INVALID_REQUEST JSON-RPC error."""
    r = client.post(MCP, json={
        "jsonrpc": "2.0", "id": None, "method": "tools/call",
        "params": {"name": "whoami", "arguments": {}},
    })
    assert r.status_code == 200, r.text
    env = r.json()
    assert env["error"]["code"] == mcp_http.INVALID_REQUEST
    # A null-id envelope is uncorrelatable, so the error echoes null back.
    assert env["id"] is None


def test_other_methods_with_id_null_are_also_invalid_request(client):
    """Not just `tools/call`: any method with `"id": null` (not omitted) is
    an INVALID_REQUEST per MCP 2025-06-18. Notifications remain OK — they
    omit the field entirely."""
    for method in ("initialize", "tools/list", "ping"):
        r = client.post(MCP, json={"jsonrpc": "2.0", "id": None, "method": method})
        assert r.status_code == 200, (method, r.text)
        env = r.json()
        assert env["error"]["code"] == mcp_http.INVALID_REQUEST, (method, env)


# -- 7f.3 LOW: tools/call arguments non-object → invalid_params -----------

def test_tools_call_arguments_non_object_is_invalid_params_not_silently_coerced(client):
    """`arguments: []` / `0` / `""` / `false` was silently coerced to `{}` by
    `.get("arguments") or {}`; a bug in the caller rather than a shape the
    server should assume on their behalf. Pydantic refuses non-object bodies
    on REST; this surface now matches."""
    for bad in ([], 0, "", False, 3.14):
        r = client.post(MCP, json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "whoami", "arguments": bad},
        })
        assert r.status_code == 200
        env = r.json()
        assert env.get("error", {}).get("code") == mcp_http.INVALID_PARAMS, (bad, env)
        assert "arguments" in env["error"]["message"], (bad, env)


def test_tools_call_arguments_missing_defaults_to_empty_object(client):
    """A caller that omits `arguments` entirely still gets `{}` — the common
    shape for a zero-arg tool (whoami, list_polls). Only an explicit
    non-object value is refused."""
    r = client.post(MCP, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "whoami"},  # no `arguments`
    })
    assert r.status_code == 200, r.text
    env = r.json()
    assert "result" in env, env
    assert "isError" not in env["result"]


# -- 7f.4 LOW: wrong-type poll_id → type-named error, not "missing" --------

def test_wrong_type_poll_id_names_the_type_problem_not_missing(client):
    """A `poll_id` that is a number, list, bool, or object is not a missing
    argument — it is a wrong-type argument, and the refusal must say so so
    the agent fixes the call rather than adding an argument that is already
    there."""
    for bad in (42, 3.14, ["p1"], {"a": 1}, True):
        r, env = call_tool(client, "get_poll", {"poll_id": bad})
        assert r.status_code == 200, (bad, r.text)
        assert env["result"].get("isError") is True, (bad, env)
        text = env["result"]["content"][0]["text"]
        assert "poll_id" in text, (bad, text)
        assert "invalid" in text.lower(), (bad, text)
        assert "must be a non-empty string" in text, (bad, text)
        assert "missing" not in text.lower(), (
            f"a wrong-type poll_id ({bad!r}) was reported as missing: {text!r}"
        )


def test_missing_poll_id_still_reads_as_missing(client):
    """The missing-argument path stays unchanged — only the wrong-type path
    gets its own message."""
    r, env = call_tool(client, "get_poll", {})
    assert r.status_code == 200
    assert env["result"].get("isError") is True
    text = env["result"]["content"][0]["text"]
    assert "missing argument: poll_id" in text, text


# -- 7f.5 LOW: initialize/tools/list/unknown-tool charge the api budget ---

def test_initialize_charges_the_api_budget_so_it_is_not_a_free_ping(monkeypatch, stubbed):
    """`initialize` used to be free — an authenticated key could call it
    forever without charging any rule. Set `api: 2/hour` and watch the
    third call refuse."""
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "RATE_LIMITS",
                        {**settings.DEFAULT_RATE_LIMITS, "api": (2, 3600)})
    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": f"Bearer {KEY}"})
    for i in (1, 2):
        r, env = rpc(c, "initialize", {}, id=i)
        assert r.status_code == 200 and "result" in env, env
    r, env = rpc(c, "initialize", {}, id=3)
    assert env.get("error", {}).get("code") == mcp_http.RATE_LIMITED_CODE, env
    assert env["error"]["data"]["rule"] == "api"


def test_tools_list_charges_the_api_budget(monkeypatch, stubbed):
    """`tools/list` used to be free too, same reason as `initialize`."""
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "RATE_LIMITS",
                        {**settings.DEFAULT_RATE_LIMITS, "api": (2, 3600)})
    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": f"Bearer {KEY}"})
    for i in (1, 2):
        r, env = rpc(c, "tools/list", id=i)
        assert r.status_code == 200 and "result" in env, env
    r, env = rpc(c, "tools/list", id=3)
    assert env.get("error", {}).get("code") == mcp_http.RATE_LIMITED_CODE
    assert env["error"]["data"]["rule"] == "api"


def test_unknown_tool_name_charges_the_api_budget(monkeypatch, stubbed):
    """An unknown tool name (`tools/call name='nope'`) used to short-circuit
    out of `_run_tool` with a tool-error result, never touching any budget
    — so an authenticated key could bang on `nope` as an unmetered probe.
    Now it charges the cheap `api` rule just like a read."""
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "RATE_LIMITS",
                        {**settings.DEFAULT_RATE_LIMITS, "api": (2, 3600)})
    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": f"Bearer {KEY}"})
    for i in (1, 2):
        r, env = call_tool(c, "nope_not_a_tool", id=i)
        assert r.status_code == 200
        assert env["result"].get("isError") is True, env
    r, env = call_tool(c, "nope_not_a_tool", id=3)
    assert env.get("error", {}).get("code") == mcp_http.RATE_LIMITED_CODE, env
    assert env["error"]["data"]["rule"] == "api"


def test_unauthenticated_initialize_is_401_before_any_charge(monkeypatch, stubbed):
    """Charging must happen only for authenticated principals. An
    unauthenticated hammer on `initialize` stays 401 on every attempt — the
    budget is never consumed, so the first *authenticated* caller still
    has their full quota."""
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "RATE_LIMITS",
                        {**settings.DEFAULT_RATE_LIMITS, "api": (1, 3600)})
    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": "Bearer wrong"})
    for _ in range(5):
        r = c.post(MCP, json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert r.status_code == 401, r.text
    # And the valid key still has its first call:
    c.headers["Authorization"] = f"Bearer {KEY}"
    r, env = rpc(c, "initialize", {})
    assert r.status_code == 200 and "result" in env, env


# -- 7f.6 LOW/spec: Origin validation ON by default ------------------------

def test_origin_bearing_request_is_403_when_no_allowlist_is_configured(monkeypatch, stubbed):
    """Spec 2025-06-18: streamable-HTTP servers MUST validate Origin. The
    safe default is: empty allowlist → every Origin-bearing request is 403.
    A CLI agent that sends no Origin header still passes."""
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    monkeypatch.delenv("KAIROS_MCP_ALLOWED_ORIGINS", raising=False)
    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": f"Bearer {KEY}"})
    # No Origin — passes (CLI agents).
    r1 = c.post(MCP, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert r1.status_code == 200, r1.text
    # With Origin and empty allowlist — refused.
    for origin in ("https://evil.example", "https://claude.ai",
                   "https://something.local"):
        r = c.post(MCP, json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
                   headers={"Origin": origin})
        assert r.status_code == 403, (origin, r.text)


# -- 8. Issue #70: slot cap on every MCP slot-writing tool -----------------
#
# `create_poll` and `add_dates` are the MCP tools that can write slots to the
# database. Each dispatches to the REST route function directly (see
# `_dispatch_sync`'s "call the REST function, don't reimplement" property), so
# the #70 ceiling on REST is the same ceiling on MCP by construction. These
# tests pin that property by exercising the surface — not the REST function —
# so a future refactor that broke the sharing would fail here loudly.


def _grid_poll_mcp(n_pairs: int, mode: str = "time_slot") -> dict:
    if mode == "full_day":
        slots = [{"id": f"s{i}", "date": date(2025, 6, 1),
                  "start_time": None, "end_time": None}
                 for i in range(n_pairs)]
    else:
        slots = [{"id": f"s{i}", "date": date(2025, 6, 1),
                  "start_time": time(9 + i // 60, i % 60),
                  "end_time": time(9 + (i + 1) // 60, (i + 1) % 60)}
                 for i in range(n_pairs)]
    return {**POLL, "slots": slots, "mode": mode}


def test_mcp_create_poll_refuses_a_slot_list_over_the_cap(client, monkeypatch):
    """MCP inherits the REST `max_length` on `slots`: a Pydantic validation
    error comes back as an `isError=true` tool result with a 400 message —
    the same refusal shape REST returns as a 422, mapped through
    `ValidationError` in `_run_tool`.
    """
    from kairos import settings as _settings
    wrote = []
    monkeypatch.setattr(api, "create_poll",
                        lambda *a, **k: wrote.append(a) or dict(POLL))
    cap = _settings.MAX_SLOTS_PER_REQUEST
    _, env = call_tool(client, "create_poll", {
        "title": "huge", "mode": "full_day",
        "slots": [{"date": "2026-06-08"} for _ in range(cap + 1)],
    })
    assert env["result"]["isError"] is True, env
    assert "400" in env["result"]["content"][0]["text"]
    assert "slots" in env["result"]["content"][0]["text"]
    assert wrote == [], "a refused creation must not have called create_poll"


def test_mcp_add_dates_refuses_a_dates_list_over_the_cap(client, monkeypatch):
    """The MCP tool for `/api/polls/{id}/slots`, same bound, same shape."""
    from kairos import settings as _settings
    added = []
    monkeypatch.setattr(api, "add_slots_capped",
                        lambda pid, slots, cap: added.append(slots) or [])
    cap = _settings.MAX_SLOTS_PER_REQUEST
    _, env = call_tool(client, "add_dates", {
        "poll_id": "p1", "dates": ["2026-06-22"] * (cap + 1),
    })
    assert env["result"]["isError"] is True, env
    assert "400" in env["result"]["content"][0]["text"]
    assert added == [], "add_slots_capped must not run for a refused edit"


def test_mcp_add_dates_refuses_the_product_cheaply(monkeypatch, stubbed):
    """The `tracemalloc` placement test, through `/mcp`. On a 125-pair poll,
    20 fresh dates give a product of 2,500 — well over the cap — and the
    refusal must come back without having built the grid.
    """
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    monkeypatch.setenv("KAIROS_MAX_SLOTS_PER_POLL", "1000")
    poll = _grid_poll_mcp(125)
    monkeypatch.setattr(api, "get_poll", lambda pid: dict(poll) if pid == "p1" else None)
    added = []
    monkeypatch.setattr(api, "add_slots_capped",
                        lambda pid, slots, cap: added.append(slots) or [])
    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": f"Bearer {KEY}"})
    dates = [f"2026-07-{d:02d}" for d in range(1, 21)]

    tracemalloc.start()
    try:
        _, env = call_tool(c, "add_dates", {"poll_id": "p1", "dates": dates})
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert env["result"]["isError"] is True, env
    assert added == [], "no slots may be written for a refused edit"
    assert peak < 10 * 1024 * 1024, (
        f"the MCP refusal allocated {peak / 1024 / 1024:.0f} MB — the cap is "
        f"being applied after the grid is built, not before it"
    )


def test_rest_and_mcp_refuse_the_same_over_cap_input_for_add_dates(client, monkeypatch):
    """Parity: the two surfaces must refuse the same oversized call. The REST
    route returns 422 for a Pydantic max_length refusal; the MCP tool returns
    an `isError=true` result. Each is the surface's own idiom for the same
    policy — and both are the same number in the same constant.
    """
    from kairos import settings as _settings
    added = []
    monkeypatch.setattr(api, "add_slots_capped",
                        lambda pid, slots, cap: added.append(slots) or [])
    cap = _settings.MAX_SLOTS_PER_REQUEST
    r = client.post("/scheduler/api/polls/p1/slots",
                    json={"dates": ["2026-06-22"] * (cap + 1)})
    assert r.status_code == 422, r.text
    _, env = call_tool(client, "add_dates", {
        "poll_id": "p1", "dates": ["2026-06-22"] * (cap + 1),
    })
    assert env["result"]["isError"] is True, env
    assert added == [], "neither surface may write slots for a refused edit"


def test_invalid_mcp_add_dates_still_charges_the_api_write_budget(monkeypatch, stubbed):
    """Charge-first discipline (#89) must hold on the #70 refusal too: an
    over-cap `add_dates` is still an attempt, and the rate budget must punish
    the loop that produces it, not just the well-formed calls. Identical to
    the `create_poll` test above — different tool, same property.
    """
    from kairos import settings as _settings
    monkeypatch.setenv("KAIROS_API_KEY", KEY)
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "RATE_LIMITS",
                        {**settings.DEFAULT_RATE_LIMITS, "api_write": (2, 3600)})
    c = TestClient(main.app, base_url="https://testserver",
                   headers={"Authorization": f"Bearer {KEY}"})
    cap = _settings.MAX_SLOTS_PER_REQUEST
    body = {"poll_id": "p1", "dates": ["2026-06-22"] * (cap + 1)}
    for i in (1, 2):
        _, env = call_tool(c, "add_dates", body, id=i)
        assert env["result"]["isError"] is True, env
    # Third call — budget exhausted, JSON-RPC rate-limit error.
    _, env = call_tool(c, "add_dates", body, id=3)
    assert env["error"]["code"] == mcp_http.RATE_LIMITED_CODE, env
    assert env["error"]["data"]["rule"] == "api_write"
