"""Server-hosted MCP transport — streamable HTTP ``POST {PREFIX}/mcp``.

Issue #83. ``mcp/kairos_mcp.py`` is the stdio adapter every agent used to have
to run locally; this module is the same tool set served by Kairos itself, so
an agent configures one URL and a bearer and gets the whole surface.

**Streamable HTTP, stateless, 2025-06-18.** One endpoint, JSON-RPC 2.0 request
in, JSON-RPC response out, no SSE (`GET /mcp` and `DELETE /mcp` answer 405).
Batching was removed in 2025-06-18, so a JSON array body is `-32600`.
`MCP-Protocol-Version` and `Mcp-Session-Id` round-trip but this server holds
no session state — "stateless" here means the hosted instance's defining
property on Cloudflare (every request a fresh Durable Object invocation) is
also its property on the ETH/duplet deployment, which is what keeps the two
surfaces interchangeable.

**No new auth path.** Every request to ``/mcp`` goes through
`scoping.resolve`, the same function the ``/api`` surface calls — one spelling
of "is this bearer live?" across both surfaces, including the three
owner-token states (`revoked`, `expired`, `unknown`) that `resolve_token`
answers identically. A tool call is rate-limited (the four `api` / `api_write`
/ `mail` / `mail_force` rules, keyed on `key:<digest>`), scope-checked
(`polls:read`, `polls:write`, `respond`, `mail:send`, `mail:force`), and
reach-checked (per issues #63/#64) exactly as its REST counterpart is — and
by *calling the same route function*, so there is one implementation of each
business rule and the two surfaces cannot drift.

**Tool call → REST route function.** `_call_rest` resolves rate / scope /
reach itself (because the FastAPI `Depends` is not reachable from a Python
call), then calls the REST endpoint with `user=` already bound. A route's
default `Depends(api_scope(...))` is only evaluated when FastAPI routes; a
plain Python call with `user=principal` bypasses it, so the shared code path
stays as it was and no REST test loses a byte.

**Error mapping.** A scope refusal (`HTTPException(403)`), a reach refusal
(the same), a 400 validation error and a 404 come back as MCP tool *results*
with `isError=True` and a text content naming what went wrong — an agent
reading the result sees the missing scope or the refused poll id in plain
text, as it does when it talks to the stdio adapter. A rate-limit refusal
(`RateLimited`) and a parse/invalid-request/method-not-found come back as
JSON-RPC *errors* (`-32099` carrying `retry_after` for rate limit, the
standard codes for the others) because those are protocol-level — the tool
never ran. The split is the one the MCP spec names: tool-execution failures
use `isError`, transport failures use error codes.

**Origin validation.** The spec requires it to prevent DNS-rebinding attacks
on local-bound servers. `KAIROS_MCP_ALLOWED_ORIGINS` lists allowed origins;
unset means "no Origin header required and none rejected", which is the
`/api` surface's existing behaviour (Kairos has no CORS today and nothing
cross-origin reads this surface). A hosted deployment sets it.

**Rate-limiting layer 2 belongs elsewhere.** The hosted Cloudflare deployment
also gets a Workers Rate Limiting binding in its entry Worker (`deploy/
cloudflare/entry.py`) keyed on the bearer hash, so a flood is rejected at
the edge before a Durable Object wakes. That lives in the Cloudflare branch
(#79) — this module owns the in-Kairos, authoritative layer: same limits as
``/api``, same `retry_after` the agent sees from the stdio adapter today.
"""

import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError

from kairos import api, reach, settings
from kairos.ratelimit import RateLimited
from kairos.scoping import DEFAULT_RULE_FOR_SCOPE, charge_request, enforce, resolve

log = logging.getLogger("kairos.mcp_http")

# Spec version this server advertises. 2025-06-18 is the stable, widely-
# implemented revision; it removed batching (a JSON array body is a protocol
# error here, by that spec's own rule) and locked the Accept / MCP-Protocol-
# Version semantics this module enforces. Older clients are still answered
# because the valid-shape superset is unchanged on the request side; the
# server names the version in the initialize response and in the
# `MCP-Protocol-Version` header of every response, as the spec requires.
PROTOCOL_VERSION = "2025-06-18"

SERVER_INFO = {"name": "kairos", "version": "1.0"}

# JSON-RPC 2.0 error codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
# Server-defined. Rate-limit refusals: lets a client distinguish "transport
# refused" from "internal error" and carries `retry_after` in `error.data`.
RATE_LIMITED_CODE = -32099


# -- Allowed-origins policy -------------------------------------------------


def _allowed_origins() -> set[str]:
    """`KAIROS_MCP_ALLOWED_ORIGINS` parsed. Empty = no origin check runs.

    Read at call time rather than captured at import, for the same reason
    every other knob in this app is: an operator who sets the variable, or a
    test using `monkeypatch.setenv`, must see it through the same door.
    """
    import os

    raw = os.environ.get("KAIROS_MCP_ALLOWED_ORIGINS", "")
    return {o.strip() for o in raw.split(",") if o.strip()}


def _validate_origin(request: Request) -> None:
    """Raise `HTTPException(403)` when the Origin header is set and not allowed.

    Spec requirement for streamable HTTP, to prevent a local-bound Kairos
    from being driven by a page a browser just loaded (DNS-rebinding). When
    no allowlist is configured, this is a no-op — Kairos has no cross-origin
    web surface today, and refusing every Origin-bearing request would break
    the same curl / `claude mcp` bearer flows the ``/api`` surface accepts.
    """
    allowed = _allowed_origins()
    if not allowed:
        return
    origin = request.headers.get("origin")
    if origin is None:
        return
    if origin not in allowed:
        log.warning("refused Origin %r (allowed: %s)", origin, ",".join(sorted(allowed)))
        raise HTTPException(403, "Origin not allowed")


# -- Tool registry ----------------------------------------------------------


# One entry per tool. The implementation calls the REST endpoint function, so
# business logic lives in exactly one place. `scope`/`rule`/`reach` describe
# what the dispatcher must enforce *before* the call; the REST function still
# performs any route-internal checks (e.g. `add_slots_endpoint` enforces
# `mail:send` on top when `notify=True`), so there is no duplication of rule
# in this file either.
#
# Tool names and semantics match ``mcp/kairos_mcp.py`` — a test asserts the
# parity so the two surfaces cannot drift (one hosted, one stdio).
TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "whoami",
        "description": (
            "What this bearer may do: its scopes (polls:read, polls:write, "
            "respond, mail:send, mail:force, imip:poll), a non-reversible id, "
            "and either the env-key reach fields (polls, reach_policy) or an "
            "owner-token shape (kind, owner, reach, expires_at). Call first "
            "when a tool returns a scope/reach refusal — the refusal names the "
            "missing scope."
        ),
        "scope": None,
        "rule": "api",
        "reach": False,
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "list_polls",
        "description": "List all scheduling polls this bearer reaches (id, title, status, share_url).",
        "scope": "polls:read",
        "rule": "api",
        "reach": False,
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "get_poll",
        "description": (
            "Full poll state: slots, responses, invites, convergence "
            "(collecting|ready|partial|blocked — ready means a date works for everyone)."
        ),
        "scope": "polls:read",
        "rule": "api",
        "reach": True,
        "input_schema": {
            "type": "object",
            "properties": {"poll_id": {"type": "string"}},
            "required": ["poll_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "create_poll",
        "description": (
            "Create a poll. mode: 'full_day' (slots: [{date}]) or 'time_slot' "
            "(slots: [{date, start_time, end_time}], HH:MM). Pass creator "
            "(account uid) so the poll appears on that user's dashboard; an "
            "owner-minted token may not spoof another user's creator — omit it "
            "or set it to the token owner's uid. Returns share_url."
        ),
        "scope": "polls:write",
        "rule": "api_write",
        "reach": False,
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "mode": {"type": "string", "enum": ["full_day", "time_slot"]},
                "slots": {"type": "array", "items": {"type": "object"}},
                "description": {"type": "string"},
                "timezone": {"type": "string"},
                "creator": {"type": ["string", "null"]},
            },
            "required": ["title", "mode", "slots"],
        },
    },
    {
        "name": "update_poll",
        "description": (
            "Edit title/description/timezone, or status 'closed' / 'open' "
            "(reopen clears a previous decision)."
        ),
        "scope": "polls:write",
        "rule": "api_write",
        "reach": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "poll_id": {"type": "string"},
                "title": {"type": ["string", "null"]},
                "description": {"type": ["string", "null"]},
                "timezone": {"type": ["string", "null"]},
                "status": {"type": ["string", "null"], "enum": ["open", "closed", None]},
            },
            "required": ["poll_id"],
        },
    },
    {
        "name": "add_dates",
        "description": (
            "Add dates (YYYY-MM-DD) to a poll additively — existing responses "
            "are kept; time_slot polls expand over the poll's time grid. "
            "notify=True runs the idempotent reminder engine so participants "
            "hear about the new dates — which is mail, so it needs mail:send "
            "on top of polls:write."
        ),
        "scope": "polls:write",
        "rule": "api_write",
        "reach": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "poll_id": {"type": "string"},
                "dates": {"type": "array", "items": {"type": "string"}},
                "notify": {"type": "boolean"},
            },
            "required": ["poll_id", "dates"],
        },
    },
    {
        "name": "respond",
        "description": (
            "Submit availability ({slot_id: yes|maybe|no}). With an email it "
            "upserts: re-submitting edits the same response."
        ),
        "scope": "respond",
        "rule": "api_write",
        "reach": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "poll_id": {"type": "string"},
                "name": {"type": "string"},
                "availabilities": {"type": "object"},
                "email": {"type": ["string", "null"]},
            },
            "required": ["poll_id", "name", "availabilities"],
        },
    },
    {
        "name": "invite",
        "description": (
            "Email personal invite links. required=False marks optional "
            "invitees — only required ones gate the convergence light. Needs "
            "mail:send, and one call may not name more addresses than the "
            "deployment's per-request ceiling: split a long list rather than "
            "retrying it."
        ),
        "scope": "mail:send",
        "rule": "mail",
        "reach": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "poll_id": {"type": "string"},
                "emails": {"type": "array", "items": {"type": "string"}},
                "required": {"type": "boolean"},
            },
            "required": ["poll_id", "emails"],
        },
    },
    {
        "name": "nudge",
        "description": (
            "Smart reminders, idempotent and safe to repeat: pending invitees "
            "(max once/day) and people who haven't seen newly added dates. "
            "Restrict with emails=[...]. force=True bypasses that 24h cooldown "
            "(scope mail:force, separately rate-limited) — leave False unless "
            "a human asked for an immediate reminder."
        ),
        "scope": "mail:send",
        "rule": "mail",
        "reach": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "poll_id": {"type": "string"},
                "emails": {"type": ["array", "null"], "items": {"type": "string"}},
                "force": {"type": "boolean"},
            },
            "required": ["poll_id"],
        },
    },
    {
        "name": "decide",
        "description": (
            "Fix the final date/slot. Call get_poll first; convergence 'ready' "
            "means a slot works for everyone."
        ),
        "scope": "polls:write",
        "rule": "api_write",
        "reach": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "poll_id": {"type": "string"},
                "slot_id": {"type": "string"},
            },
            "required": ["poll_id", "slot_id"],
        },
    },
    {
        "name": "email_decision",
        "description": (
            "Mail the decided date to every respondent + invitee with the "
            ".ics calendar file attached. Optional note goes into the email "
            "body. Needs mail:send, and the whole poll draws on one send "
            "budget — mail once, not once per attempt."
        ),
        "scope": "mail:send",
        "rule": "mail",
        "reach": True,
        "input_schema": {
            "type": "object",
            "properties": {
                "poll_id": {"type": "string"},
                "note": {"type": "string"},
            },
            "required": ["poll_id"],
        },
    },
    {
        "name": "get_ics",
        "description": "The decided slot as an iCalendar (.ics) document (404 until decided).",
        "scope": "polls:read",
        "rule": "api",
        "reach": True,
        "input_schema": {
            "type": "object",
            "properties": {"poll_id": {"type": "string"}},
            "required": ["poll_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_contacts",
        "description": "Outbound-mail audit trail for a poll (who was contacted, what kind, when), newest first.",
        "scope": "polls:read",
        "rule": "api",
        "reach": True,
        "input_schema": {
            "type": "object",
            "properties": {"poll_id": {"type": "string"}},
            "required": ["poll_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "delete_poll",
        "description": "Permanently delete a poll and all its responses/invites.",
        "scope": "polls:write",
        "rule": "api_write",
        "reach": True,
        "input_schema": {
            "type": "object",
            "properties": {"poll_id": {"type": "string"}},
            "required": ["poll_id"],
            "additionalProperties": False,
        },
    },
)

_TOOL_INDEX: dict[str, dict[str, Any]] = {t["name"]: t for t in TOOLS}


def tool_names() -> tuple[str, ...]:
    """The hosted MCP tool set, used by the stdio-parity test."""
    return tuple(t["name"] for t in TOOLS)


# -- Dispatch ---------------------------------------------------------------


def _text_content(text: str) -> list[dict[str, str]]:
    """The MCP spec's `content` array with one text block."""
    return [{"type": "text", "text": text}]


def _json_text(value: Any) -> str:
    """Serialize a result for text content. `jsonable_encoder` is what FastAPI
    uses for the REST surface, so an MCP result carries the exact same bytes
    a REST response would — dates round-trip as ISO-8601, Pydantic models as
    their dict forms. One serializer, one shape, no drift."""
    return json.dumps(jsonable_encoder(value), ensure_ascii=False)


def _tool_error(message: str) -> dict[str, Any]:
    """An `isError: true` tool result. For scope / reach / validation refusals
    that the caller can act on (rename, mint, fix the args)."""
    return {"content": _text_content(message), "isError": True}


def _authorize(principal: dict, scope: str | None, rule: str | None, *,
               poll_id: str | None = None) -> None:
    """The four checks `api_scope` does, replayed here because the FastAPI
    `Depends` is not reachable from a tool dispatcher. Same order: charge
    first (so a 403 cannot be used as a free probe), then scope, then reach.
    """
    effective_rule = rule or DEFAULT_RULE_FOR_SCOPE.get(scope or "", "api")
    charge_request(principal, effective_rule)
    if scope:
        enforce(principal, scope)
    if poll_id is not None:
        reach.guard_reach_id(principal, poll_id)


def _call_rest(fn, principal: dict, *args, **kwargs) -> Any:
    """Call a REST endpoint function with `user=principal` bound.

    The endpoint's parameter default is `Depends(api_scope(...))`; FastAPI
    evaluates it during routing, but a plain Python call with `user=` passes
    through the Depends sentinel and runs the body against the bound
    principal. Nothing in the endpoint body consults the Depends object
    itself, so the behaviour is identical to the REST path.
    """
    return fn(*args, user=principal, **kwargs)


def _run_tool(name: str, params: dict, principal: dict, request: Request) -> dict[str, Any]:
    """Resolve, authorize, and call the REST function for one tool.

    Returns the tool-result dict (`content` + optional `isError`). Raises
    `RateLimited` on a budget refusal (the caller turns that into a JSON-RPC
    error) — every other HTTP failure comes back as an `isError=true` result.
    """
    tool = _TOOL_INDEX.get(name)
    if tool is None:
        return _tool_error(
            f"Unknown tool {name!r}. Call tools/list to see what this bearer may use."
        )
    # Validate the input against the tool's pydantic model (where one exists)
    # or just check required keys. Validation errors are `isError=true` tool
    # results, not JSON-RPC errors: the request *reached* a tool, so the
    # failure is tool-execution, not transport.
    try:
        return _dispatch(tool, params, principal, request)
    except HTTPException as exc:
        # Scope/reach/validation refusals from `enforce`, `guard_reach_id`,
        # the REST endpoint's own validation (`timezone`, `mode`, slot id,
        # recipient list cap), the `require_sendable` gate, `_get_or_404`.
        # All of these are *actionable* by the caller, so they become tool
        # results naming the detail, not JSON-RPC errors.
        detail = exc.detail if isinstance(exc.detail, str) else json.dumps(exc.detail)
        return _tool_error(f"{exc.status_code}: {detail}")
    except ValidationError as exc:
        # Pydantic model construction failed — wrong types / missing fields.
        # Same reasoning as HTTPException(400) above.
        return _tool_error(f"400: {exc.errors()}")


def _dispatch(tool: dict, params: dict, principal: dict, request: Request) -> dict[str, Any]:
    """Call the REST function the tool wraps. Separate so `_run_tool` can
    catch and translate without the authorize/call shape getting lost."""
    name = tool["name"]
    scope, rule = tool["scope"], tool["rule"]

    if name == "whoami":
        _authorize(principal, scope, rule)
        return {"content": _text_content(_json_text(api.whoami(user=principal)))}

    if name == "list_polls":
        _authorize(principal, scope, rule)
        return {"content": _text_content(_json_text(
            api.list_polls_endpoint(request=request, user=principal)
        ))}

    if name == "get_poll":
        poll_id = _required(params, "poll_id")
        _authorize(principal, scope, rule, poll_id=poll_id)
        return {"content": _text_content(_json_text(
            api.get_poll_endpoint(poll_id, request=request, user=principal)
        ))}

    if name == "create_poll":
        body = api.PollCreate(
            title=params.get("title"),
            description=params.get("description"),
            mode=params.get("mode"),
            timezone=params.get("timezone", "Europe/Zurich"),
            slots=[api.SlotIn(**s) for s in params.get("slots", [])],
            creator=params.get("creator"),
            creator_email=params.get("creator_email"),
        )
        _authorize(principal, scope, rule)
        result = api.create_poll_endpoint(body, request=request, user=principal)
        return {"content": _text_content(_json_text(result))}

    if name == "update_poll":
        poll_id = _required(params, "poll_id")
        body = api.PollUpdate(
            title=params.get("title"),
            description=params.get("description"),
            timezone=params.get("timezone"),
            status=params.get("status"),
        )
        _authorize(principal, scope, rule, poll_id=poll_id)
        return {"content": _text_content(_json_text(
            api.update_poll_endpoint(poll_id, body, request=request, user=principal)
        ))}

    if name == "add_dates":
        poll_id = _required(params, "poll_id")
        body = api.SlotsAdd(
            dates=params.get("dates", []),
            notify=bool(params.get("notify", False)),
        )
        _authorize(principal, scope, rule, poll_id=poll_id)
        return {"content": _text_content(_json_text(
            api.add_slots_endpoint(poll_id, body, request=request, user=principal)
        ))}

    if name == "respond":
        poll_id = _required(params, "poll_id")
        body = api.ResponseCreate(
            name=params.get("name", ""),
            email=params.get("email"),
            availabilities=params.get("availabilities") or {},
        )
        _authorize(principal, scope, rule, poll_id=poll_id)
        return {"content": _text_content(_json_text(
            api.respond_endpoint(poll_id, body, user=principal)
        ))}

    if name == "invite":
        poll_id = _required(params, "poll_id")
        body = api.InviteCreate(
            emails=list(params.get("emails") or []),
            required=bool(params.get("required", True)),
        )
        _authorize(principal, scope, rule, poll_id=poll_id)
        return {"content": _text_content(_json_text(
            api.invite_endpoint(poll_id, body, request=request, user=principal)
        ))}

    if name == "nudge":
        poll_id = _required(params, "poll_id")
        emails_arg = params.get("emails")
        body = api.NudgeIn(
            emails=list(emails_arg) if emails_arg is not None else None,
            force=bool(params.get("force", False)),
        )
        _authorize(principal, scope, rule, poll_id=poll_id)
        return {"content": _text_content(_json_text(
            api.nudge_endpoint(poll_id, body, request=request, user=principal)
        ))}

    if name == "decide":
        poll_id = _required(params, "poll_id")
        slot_id = _required(params, "slot_id")
        body = api.DecideIn(slot_id=slot_id)
        _authorize(principal, scope, rule, poll_id=poll_id)
        return {"content": _text_content(_json_text(
            api.decide_endpoint(poll_id, body, request=request, user=principal)
        ))}

    if name == "email_decision":
        poll_id = _required(params, "poll_id")
        body = api.MailIn(note=params.get("note", "") or "")
        _authorize(principal, scope, rule, poll_id=poll_id)
        return {"content": _text_content(_json_text(
            api.email_decision_endpoint(poll_id, body, request=request, user=principal)
        ))}

    if name == "get_ics":
        poll_id = _required(params, "poll_id")
        _authorize(principal, scope, rule, poll_id=poll_id)
        resp = api.event_ics_endpoint(poll_id, request=request, user=principal)
        # ics_response returns a Response whose body is the text/calendar
        # string; the stdio adapter returns the string directly, so do the
        # same here — one tool, one shape across transports.
        if isinstance(resp, Response):
            text = resp.body.decode("utf-8") if isinstance(resp.body, bytes) else str(resp.body)
            return {"content": _text_content(text)}
        return {"content": _text_content(_json_text(resp))}

    if name == "get_contacts":
        poll_id = _required(params, "poll_id")
        _authorize(principal, scope, rule, poll_id=poll_id)
        return {"content": _text_content(_json_text(
            api.contacts_endpoint(poll_id, user=principal)
        ))}

    if name == "delete_poll":
        poll_id = _required(params, "poll_id")
        _authorize(principal, scope, rule, poll_id=poll_id)
        return {"content": _text_content(_json_text(
            api.delete_poll_endpoint(poll_id, user=principal)
        ))}

    # Unreachable: every tool in TOOLS has a branch above. Leaving a loud
    # failure rather than falling back silently, in case a tool is added
    # without being wired here.
    raise HTTPException(500, f"Tool {name!r} wired into the registry but not into the dispatcher")


def _required(params: dict, key: str) -> Any:
    """`params[key]` or a 400 — the invalid_params path the dispatcher turns
    into a tool-error result. The REST surface answers 422 for a missing
    field; this surface answers one 400 in a text content, because an MCP
    client reads `content[0].text`, not a Pydantic validation structure.
    """
    value = params.get(key)
    if value is None or value == "":
        raise HTTPException(400, f"missing argument: {key}")
    return value


# -- JSON-RPC layer ---------------------------------------------------------


def _jsonrpc_error(code: int, message: str, request_id: Any = None, data: Any = None) -> dict:
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _jsonrpc_result(request_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _handle_method(method: str, params: Any, request_id: Any, principal: dict | None,  # noqa: C901 — one JSON-RPC method dispatcher, clearer flat than split per method
                   request: Request) -> dict | None:
    """Return one JSON-RPC response (dict), or None for a notification."""
    is_notification = request_id is None
    if method == "initialize":
        if is_notification:
            return None
        return _jsonrpc_result(request_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": SERVER_INFO,
        })
    if method == "notifications/initialized":
        # Spec: notifications answer 202 with empty body. From the dispatcher's
        # perspective that's "produce no response object".
        return None
    if method.startswith("notifications/"):
        return None  # tolerate and ignore other notifications
    if method == "ping":
        if is_notification:
            return None
        return _jsonrpc_result(request_id, {})
    if method == "tools/list":
        if is_notification:
            return None
        tools_list = [
            {
                "name": t["name"],
                "description": t["description"],
                "inputSchema": t["input_schema"],
            }
            for t in TOOLS
        ]
        return _jsonrpc_result(request_id, {"tools": tools_list})
    if method == "tools/call":
        if is_notification:
            # tools/call as a notification would be fire-and-forget — the spec
            # requires a result, so refuse rather than silently drop it.
            return None
        if principal is None:
            # Should never reach here because authentication happened before
            # dispatch; keep a loud failure rather than a silent pass.
            return _jsonrpc_error(INTERNAL_ERROR, "principal missing", request_id)
        if not isinstance(params, dict):
            return _jsonrpc_error(INVALID_PARAMS, "params must be an object", request_id)
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str):
            return _jsonrpc_error(INVALID_PARAMS, "tools/call requires `name`", request_id)
        if not isinstance(arguments, dict):
            return _jsonrpc_error(INVALID_PARAMS, "tools/call `arguments` must be an object", request_id)
        try:
            tool_result = _run_tool(name, arguments, principal, request)
        except RateLimited as exc:
            # Protocol-level: transport refused. The agent's loop needs
            # retry_after in `error.data`, which the stdio adapter surfaces
            # the same way (via the HTTP Retry-After header).
            return _jsonrpc_error(
                RATE_LIMITED_CODE,
                f"Rate limit {exc.rule!r} exceeded",
                request_id,
                data={"rule": exc.rule, "retry_after": exc.retry_after},
            )
        return _jsonrpc_result(request_id, tool_result)
    if is_notification:
        return None
    return _jsonrpc_error(METHOD_NOT_FOUND, f"Unknown method: {method}", request_id)


def _validate_envelope(message: Any, allow_notification: bool = True) -> tuple[bool, dict | None]:
    """Is this a well-formed JSON-RPC 2.0 request/notification?

    Returns (ok, error_response). The error response is a complete JSON-RPC
    envelope so the caller can send it unchanged.
    """
    if not isinstance(message, dict):
        return False, _jsonrpc_error(INVALID_REQUEST, "request must be a JSON object")
    if message.get("jsonrpc") != "2.0":
        return False, _jsonrpc_error(INVALID_REQUEST, "jsonrpc must be '2.0'", message.get("id"))
    method = message.get("method")
    if not isinstance(method, str) or not method:
        return False, _jsonrpc_error(INVALID_REQUEST, "method is required", message.get("id"))
    return True, None


# -- Endpoint ---------------------------------------------------------------


router = APIRouter(prefix=settings.PREFIX)


def _response_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    """`MCP-Protocol-Version` on every response, per spec."""
    headers = {"MCP-Protocol-Version": PROTOCOL_VERSION}
    if extra:
        headers.update(extra)
    return headers


@router.post("/mcp", include_in_schema=False)
async def mcp_post(request: Request) -> Response:
    """Streamable HTTP endpoint. One JSON-RPC message in, one out (or 202 for
    a notification). See the module docstring for the authentication,
    rate-limiting and scope/reach model this applies.
    """
    try:
        _validate_origin(request)
    except HTTPException as exc:
        return JSONResponse(
            {"detail": exc.detail}, status_code=exc.status_code, headers=_response_headers(),
        )

    # Auth — same bearer, same `resolve` function as `/api`, same 401 wording
    # as `require_api_key`. One implementation of "is this bearer live?"; no
    # second path that could forget that revoked means revoked.
    try:
        principal = resolve(request)
    except HTTPException as exc:
        headers = _response_headers({"WWW-Authenticate": "Bearer"})
        return JSONResponse(
            {"detail": exc.detail}, status_code=exc.status_code, headers=headers,
        )

    # Parse JSON. A malformed body is parse_error at 200 (the JSON-RPC wire
    # spec puts the status in the envelope, not the HTTP status) because a
    # 400 here would hide the JSON-RPC error code an MCP client reads first.
    try:
        raw = await request.body()
        message = json.loads(raw) if raw else None
    except json.JSONDecodeError as exc:
        return _rpc_response(_jsonrpc_error(PARSE_ERROR, f"Parse error: {exc.msg}"))

    # Batching removed in spec 2025-06-18. A JSON array body is invalid.
    if isinstance(message, list):
        return _rpc_response(_jsonrpc_error(
            INVALID_REQUEST,
            "Batch requests are not supported in MCP spec 2025-06-18; send one message",
        ))

    ok, error = _validate_envelope(message)
    if not ok:
        return _rpc_response(error)

    response = _handle_method(
        message["method"], message.get("params") or {}, message.get("id"),
        principal, request,
    )
    if response is None:
        # Notification: spec says 202 Accepted with empty body.
        return Response(status_code=202, headers=_response_headers())
    return _rpc_response(response)


@router.get("/mcp", include_in_schema=False)
@router.delete("/mcp", include_in_schema=False)
async def mcp_other() -> Response:
    """Spec: GET is for the optional server-initiated SSE stream; without
    one, 405. DELETE is session termination; we hold no sessions, so same."""
    return Response(status_code=405, headers=_response_headers({"Allow": "POST"}))


def _rpc_response(envelope: dict) -> Response:
    return JSONResponse(envelope, status_code=200, headers=_response_headers())
