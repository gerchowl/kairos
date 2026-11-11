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

**One dispatcher skeleton, charge-first.** The per-tool branches below used to
build the Pydantic body FIRST and call `_authorize` afterwards, so an invalid
call (a missing title, a slot list that expanded to a million rows) returned
a 400 without ever incrementing the rate budget. REST does the opposite — the
`api_scope` dependency charges its rule before the body parameter is
validated — and the two surfaces have to answer identically on every budget
question, or a rotated key can be spent on malformed requests. `_dispatch`
now runs the four REST checks (charge, scope, reach, body) in that order, in
one place, so every branch below is just "call the REST endpoint with the
validated body" and no branch can forget any of them.

**Tool call → REST route function.** The dispatcher resolves rate / scope /
reach itself (because the FastAPI `Depends` is not reachable from a Python
call), validates the arguments against the **same Pydantic model REST uses**
(`PollCreate`, `InviteCreate`, `NudgeIn`, …) — so string "false" coerces to
False exactly as it does on REST, a dict given where a list[str] is required
is a validation error exactly as it is on REST, and no boolean / email /
date type ever enters a tool body with a shape the REST endpoint would have
refused. Then it calls the REST endpoint with `user=` already bound. A
route's default `Depends(api_scope(...))` is only evaluated when FastAPI
routes; a plain Python call with `user=principal` bypasses it, so the shared
code path stays as it was and no REST test loses a byte.

**Threadpool for the sync body.** `scoping.resolve` → `apitokens.resolve_token`
opens the SQLite connection; `api.*_endpoint` performs the real DB write,
the SMTP send, the slot expansion — all synchronous. An `async def` handler
on the Starlette event loop would hold the loop for the duration of that
work, starving every other concurrent request on the same instance. The
endpoint is therefore the usual FastAPI sync-handler shape (`def`, which
Starlette runs in its threadpool) so an arbitrary number of concurrent MCP
calls do not serialise on one CPU; auth + dispatch run off the loop, exactly
like every `/api` route already does.

**Error mapping.** A scope refusal (`HTTPException(403)`), a reach refusal
(the same), a 400 validation error and a 404 come back as MCP tool *results*
with `isError=True` and a text content naming what went wrong — an agent
reading the result sees the missing scope or the refused poll id in plain
text, as it does when it talks to the stdio adapter. A rate-limit refusal
(`RateLimited`) and a parse/invalid-request/method-not-found come back as
JSON-RPC *errors* (`-32099` carrying `retry_after` for rate limit, the
standard codes for the others) because those are protocol-level — the tool
never ran. **Any unexpected server-side exception** becomes a JSON-RPC
`INTERNAL_ERROR` without details, logged server-side with a traceback, so no
tool bug can produce a plain-text 500 (which breaks the MCP wire format).

**Request size cap.** `Content-Length` over `MAX_BODY_BYTES` (default 1 MiB)
is answered with a JSON-RPC parse error at HTTP 413 — a recursion-bomb body
(200 KiB of `[[[[…]]]]`) cannot drive a RecursionError inside the JSON
parser, because the parser never gets handed the bytes.

**Origin validation.** The spec requires it to prevent DNS-rebinding attacks
on local-bound servers. `KAIROS_MCP_ALLOWED_ORIGINS` lists allowed origins;
unset means "no Origin header required and none rejected", which is the
`/api` surface's existing behaviour (Kairos has no CORS today and nothing
cross-origin reads this surface). A hosted deployment sets it. The caller's
`Origin` header is normalised (lowercase scheme/host, trailing slash
stripped) before comparison, so an allowlist entry `https://claude.ai` and
an incoming header `https://CLAUDE.AI/` match.

**MCP-Protocol-Version.** If the client sent a `MCP-Protocol-Version` header,
it must be one this server supports (2025-06-18 and the three widely-used
earlier revisions). An unsupported version is a 400, per spec, so a client
built against a version this server does not understand fails loudly rather
than falling back silently.

**Rate-limiting layer 2 belongs elsewhere.** The hosted Cloudflare deployment
also gets a Workers Rate Limiting binding in its entry Worker (`deploy/
cloudflare/entry.py`) keyed on the bearer hash, so a flood is rejected at
the edge before a Durable Object wakes. That lives in the Cloudflare branch
(#79) — this module owns the in-Kairos, authoritative layer: same limits as
``/api``, same `retry_after` the agent sees from the stdio adapter today.

**Issue #70 (unbounded dates × grid) is a REST-side bug that this surface
inherits for free.** Each MCP tool runs the REST endpoint body directly, so
the size-cap fix #70 lands on `api.add_slots_endpoint` / `create_poll_endpoint`
automatically covers this surface too — no second cap, no second review, no
second place to drift from the one truth. The property that makes that
true is `_dispatch`'s "call the REST function, don't reimplement": fix a
ceiling once and both surfaces see it.
"""

import json
import logging
from typing import Any, Callable

from fastapi import APIRouter, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ValidationError
from starlette.concurrency import run_in_threadpool

from kairos import api, reach, settings
from kairos.ratelimit import RateLimited
from kairos.scoping import DEFAULT_RULE_FOR_SCOPE, charge_request, enforce

log = logging.getLogger("kairos.mcp_http")

# Spec version this server advertises. 2025-06-18 is the stable, widely-
# implemented revision; it removed batching (a JSON array body is a protocol
# error here, by that spec's own rule) and locked the Accept / MCP-Protocol-
# Version semantics this module enforces. Older clients are still answered
# because the valid-shape superset is unchanged on the request side; the
# server names the version in the initialize response and in the
# `MCP-Protocol-Version` header of every response, as the spec requires.
PROTOCOL_VERSION = "2025-06-18"

# Revisions this server will honour on an incoming `MCP-Protocol-Version`
# request header. The spec (2025-06-18 §4) says a client that supplies the
# header with an unsupported value must be refused with 400. Older clients
# that omit the header still work; this list is the union of revisions whose
# request *shape* this module accepts without translation.
SUPPORTED_PROTOCOL_VERSIONS = frozenset({
    "2025-06-18", "2025-03-26", "2024-11-05", "2024-10-07",
})

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

# Hard cap on request body size. 1 MiB is far past any legitimate tool call —
# `create_poll` with a full week's worth of time slots is well under 50 KiB —
# so refusing over this is free. The cap exists because a 200 KiB of nested
# JSON brackets drives `json.loads` into a RecursionError without any of the
# handlers below getting to run; capping `Content-Length` before the body is
# read keeps that payload from ever reaching the parser.
MAX_BODY_BYTES = 1 * 1024 * 1024


# -- Allowed-origins policy -------------------------------------------------


def _normalise_origin(value: str) -> str:
    """Normalise an Origin for comparison.

    An `Origin` header carries scheme + host + optional port, as defined by
    RFC 6454. The spec's own examples (`https://claude.ai`) are all-lowercase
    and trailing-slash free, but a browser's `Origin` header is case-
    insensitive on scheme and host and some agents send a trailing `/` by
    habit — a string equality check would then refuse a legitimate request
    for the shape of its casing, which is the kind of fragile allowlist
    #51's module docstring complained about on rate-limit rules. One
    normaliser, one place, read on both sides of the check.
    """
    value = value.strip()
    if value.endswith("/"):
        value = value[:-1]
    scheme, sep, rest = value.partition("://")
    if not sep:
        return value.lower()
    return f"{scheme.lower()}://{rest.lower()}"


def _allowed_origins() -> set[str]:
    """`KAIROS_MCP_ALLOWED_ORIGINS` parsed. Empty = no origin check runs.

    Read at call time rather than captured at import, for the same reason
    every other knob in this app is: an operator who sets the variable, or a
    test using `monkeypatch.setenv`, must see it through the same door.
    Each entry is normalised with `_normalise_origin` so the allowlist and
    the incoming header are compared in the same shape.
    """
    import os

    raw = os.environ.get("KAIROS_MCP_ALLOWED_ORIGINS", "")
    return {_normalise_origin(o) for o in raw.split(",") if o.strip()}


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
    if _normalise_origin(origin) not in allowed:
        log.warning("refused Origin %r (allowed: %s)", origin, ",".join(sorted(allowed)))
        raise HTTPException(403, "Origin not allowed")


def _validate_protocol_version(request: Request) -> None:
    """Raise `HTTPException(400)` on an unsupported `MCP-Protocol-Version`.

    Spec 2025-06-18 §4: a client that carries the header must use a version
    the server supports, else it is a protocol-level refusal (not a tool
    error). Clients that omit the header are still answered — the valid-
    shape superset is unchanged on the request side, so older clients that
    predate this header interoperate.
    """
    advertised = request.headers.get("mcp-protocol-version")
    if advertised is None:
        return
    if advertised not in SUPPORTED_PROTOCOL_VERSIONS:
        log.warning("refused MCP-Protocol-Version %r", advertised)
        raise HTTPException(
            400,
            f"Unsupported MCP-Protocol-Version {advertised!r}; this server speaks "
            f"{', '.join(sorted(SUPPORTED_PROTOCOL_VERSIONS))}",
        )


# -- Tool registry ----------------------------------------------------------


# One entry per tool. Each tool declares:
#
#   `scope` / `rule` / `reach`   — what the dispatcher must enforce *before*
#                                  the call, in the REST order (charge first,
#                                  scope second, reach third).
#   `model`                      — the Pydantic request model REST uses for
#                                  this tool's body. `None` means the tool
#                                  takes no body (whoami, list_polls, the
#                                  single-poll-id reads/deletes). Using the
#                                  REST model is how finding 2's coercion
#                                  bugs stay fixed: pydantic coerces "false"
#                                  to False, refuses a dict where a list[str]
#                                  is required, and does so with the exact
#                                  same rules the REST surface already pins
#                                  down.
#   `handler`                    — the small callable that runs the already-
#                                  validated body against the REST endpoint.
#                                  Because the handler sees only the
#                                  validated poll_id and body, no branch can
#                                  forget to authenticate or charge.
#
# Tool names and semantics match ``mcp/kairos_mcp.py`` — a test asserts the
# parity so the two surfaces cannot drift (one hosted, one stdio).


def _whoami(poll_id, body, principal, request):
    return _ok(api.whoami(user=principal))


def _list_polls(poll_id, body, principal, request):
    return _ok(api.list_polls_endpoint(request=request, user=principal))


def _get_poll(poll_id, body, principal, request):
    return _ok(api.get_poll_endpoint(poll_id, request=request, user=principal))


def _create_poll(poll_id, body, principal, request):
    return _ok(api.create_poll_endpoint(body, request=request, user=principal))


def _update_poll(poll_id, body, principal, request):
    return _ok(api.update_poll_endpoint(poll_id, body, request=request, user=principal))


def _add_dates(poll_id, body, principal, request):
    return _ok(api.add_slots_endpoint(poll_id, body, request=request, user=principal))


def _respond(poll_id, body, principal, request):
    return _ok(api.respond_endpoint(poll_id, body, user=principal))


def _invite(poll_id, body, principal, request):
    return _ok(api.invite_endpoint(poll_id, body, request=request, user=principal))


def _nudge(poll_id, body, principal, request):
    return _ok(api.nudge_endpoint(poll_id, body, request=request, user=principal))


def _decide(poll_id, body, principal, request):
    return _ok(api.decide_endpoint(poll_id, body, request=request, user=principal))


def _email_decision(poll_id, body, principal, request):
    return _ok(api.email_decision_endpoint(poll_id, body, request=request, user=principal))


def _get_ics(poll_id, body, principal, request):
    # ics_response returns a Response whose body is the text/calendar string;
    # the stdio adapter returns the string directly, so do the same here —
    # one tool, one shape across transports.
    resp = api.event_ics_endpoint(poll_id, request=request, user=principal)
    if isinstance(resp, Response):
        text = resp.body.decode("utf-8") if isinstance(resp.body, bytes) else str(resp.body)
        return {"content": _text_content(text)}
    return _ok(resp)


def _get_contacts(poll_id, body, principal, request):
    return _ok(api.contacts_endpoint(poll_id, user=principal))


def _delete_poll(poll_id, body, principal, request):
    return _ok(api.delete_poll_endpoint(poll_id, user=principal))


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
        "model": None,
        "handler": _whoami,
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "list_polls",
        "description": "List all scheduling polls this bearer reaches (id, title, status, share_url).",
        "scope": "polls:read",
        "rule": "api",
        "reach": False,
        "model": None,
        "handler": _list_polls,
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
        "model": None,
        "handler": _get_poll,
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
        "model": api.PollCreate,
        "handler": _create_poll,
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
        "model": api.PollUpdate,
        "handler": _update_poll,
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
        "model": api.SlotsAdd,
        "handler": _add_dates,
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
        "model": api.ResponseCreate,
        "handler": _respond,
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
        "model": api.InviteCreate,
        "handler": _invite,
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
        "model": api.NudgeIn,
        "handler": _nudge,
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
        "model": api.DecideIn,
        "handler": _decide,
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
        "model": api.MailIn,
        "handler": _email_decision,
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
        "model": None,
        "handler": _get_ics,
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
        "model": None,
        "handler": _get_contacts,
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
        "model": None,
        "handler": _delete_poll,
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


def _ok(value: Any) -> dict[str, Any]:
    """The success shape: a single text content with the JSON-encoded result."""
    return {"content": _text_content(_json_text(value))}


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


def _validate_body(tool: dict, params: dict) -> BaseModel | None:
    """Validate `params` (minus `poll_id`, which is a path parameter on REST)
    against the tool's request model. Returns the parsed model, or None when
    the tool has no body. Any `ValidationError` from the Pydantic model
    propagates — `_run_tool` turns it into an `isError` tool result.
    """
    model = tool.get("model")
    if model is None:
        return None
    body = {k: v for k, v in params.items() if k != "poll_id"}
    return model.model_validate(body)


def _run_tool(name: str, params: dict, principal: dict, request: Request) -> dict[str, Any]:
    """Resolve, authorize, and call the REST function for one tool.

    Returns the tool-result dict (`content` + optional `isError`). Raises
    `RateLimited` on a budget refusal (the caller turns that into a JSON-RPC
    error) — every other HTTP failure comes back as an `isError=true` result.

    Order is load-bearing: charge first (so invalid calls still spend the
    budget, matching REST exactly), then scope, then reach, then body —
    which is the same order the REST dependency chain runs in.
    """
    tool = _TOOL_INDEX.get(name)
    if tool is None:
        return _tool_error(
            f"Unknown tool {name!r}. Call tools/list to see what this bearer may use."
        )
    if not isinstance(params, dict):
        return _tool_error("400: arguments must be an object")
    try:
        # (1) charge + scope: cheap checks that must run before any arg
        # parsing, or a malformed call would silently skip the rate budget.
        # (2) reach: needs the poll_id, which must be present and a string.
        #     A missing poll_id is a 400 isError result (post-charge), same
        #     as on REST where it would be a 422 from the path parameter.
        poll_id = None
        if tool["reach"]:
            poll_id = params.get("poll_id")
            if not isinstance(poll_id, str) or not poll_id:
                # Charge still happens — the budget punishes the loop that
                # builds malformed calls, not just well-formed ones.
                _authorize(principal, tool["scope"], tool["rule"])
                return _tool_error("400: missing argument: poll_id")
        _authorize(principal, tool["scope"], tool["rule"], poll_id=poll_id)
        # (3) body: same Pydantic model REST uses, so coercion matches.
        body = _validate_body(tool, params)
        # (4) call the REST function.
        return tool["handler"](poll_id, body, principal, request)
    except RateLimited:
        # Protocol-level: let the JSON-RPC layer turn this into -32099.
        raise
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, str) else json.dumps(exc.detail)
        return _tool_error(f"{exc.status_code}: {detail}")
    except ValidationError as exc:
        # Pydantic model construction failed — wrong types / missing fields.
        # Concise message (first error only) so a tool result stays readable
        # for an agent; the full list goes to the server log.
        errors = exc.errors()
        log.info("mcp %s: argument validation failed: %s", name, errors)
        first = errors[0] if errors else {}
        loc = ".".join(str(p) for p in first.get("loc", ())) or "body"
        return _tool_error(f"400: invalid argument {loc}: {first.get('msg', 'validation error')}")
    except Exception:
        # Any other exception is an internal bug, not something the caller
        # can act on. Log the traceback server-side and return a tool-level
        # internal error without leaking details.
        log.exception("mcp tool %r raised", name)
        return _tool_error("500: internal error")


def _required(params: dict, key: str) -> Any:
    """`params[key]` or a 400 — the invalid_params path the dispatcher turns
    into a tool-error result. The REST surface answers 422 for a missing
    field; this surface answers one 400 in a text content, because an MCP
    client reads `content[0].text`, not a Pydantic validation structure.

    Kept for callers outside `_run_tool` (none remain in-tree today); the
    dispatcher's own poll_id extraction is in `_run_tool`.
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


def _valid_jsonrpc_id(value: Any) -> bool:
    """True when `value` is one of the three JSON-RPC 2.0 id types.

    The spec §4.1 requires an id that is a String, Number, or Null; anything
    else is an Invalid Request. A bool is a Number subclass in Python, so it
    is excluded explicitly — `True` is not a legitimate correlation id even
    though `isinstance(True, int)` holds.
    """
    if value is None:
        return True
    if isinstance(value, bool):
        return False
    return isinstance(value, (str, int, float))


def _validate_envelope(message: Any) -> tuple[bool, dict | None]:
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
    # id (when present) must be string, number or null — bool excluded.
    # Spec: §4.1. A list/dict id would silently correlate as whatever Python
    # serialises it to, so refuse at the envelope rather than deeper.
    if "id" in message and not _valid_jsonrpc_id(message["id"]):
        return False, _jsonrpc_error(INVALID_REQUEST, "id must be string, number, or null")
    return True, None


# -- Endpoint ---------------------------------------------------------------


router = APIRouter(prefix=settings.PREFIX)


def _response_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    """`MCP-Protocol-Version` on every response, per spec."""
    headers = {"MCP-Protocol-Version": PROTOCOL_VERSION}
    if extra:
        headers.update(extra)
    return headers


async def _read_body_capped(request: Request) -> bytes:
    """Read the request body, refusing anything over `MAX_BODY_BYTES`.

    Reads Content-Length first when present; otherwise streams into a buffer
    with the same cap. Raises `HTTPException(413)` so the caller returns a
    parse error envelope at HTTP 413 without ever handing the bytes to
    `json.loads` — a nested-brackets recursion bomb cannot reach the parser.
    """
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > MAX_BODY_BYTES:
                raise HTTPException(413, f"request body exceeds {MAX_BODY_BYTES} bytes")
        except ValueError:
            # A malformed Content-Length is a client bug; let the stream
            # read decide, with the same cap.
            pass
    buf = bytearray()
    async for chunk in request.stream():
        buf.extend(chunk)
        if len(buf) > MAX_BODY_BYTES:
            raise HTTPException(413, f"request body exceeds {MAX_BODY_BYTES} bytes")
    return bytes(buf)


def _parse_body(raw: bytes) -> tuple[Any, dict | None]:
    """Parse the JSON body. Returns (message, error) — exactly one is set.

    `error` is a full JSON-RPC envelope. `RecursionError` is explicitly
    handled because a deeply-nested brackets payload drives `json.loads`
    into one; the body-size cap makes this rare, but a hostile client can
    still send 999 nested `{...}` inside the cap. `ValueError` catches every
    other parse pathology.
    """
    try:
        return json.loads(raw) if raw else None, None
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        return None, _jsonrpc_error(PARSE_ERROR, f"Parse error: {exc}")


def _authenticate(request: Request) -> tuple[dict | None, Response | None]:
    """Resolve the bearer, or return the 401 response.

    Factored out so it can run inside the threadpool wrapper — the SQLite
    read inside `resolve_token` is synchronous.
    """
    # `scoping.resolve` is imported inside the function to let a test (or a
    # future refactor) monkeypatch the symbol on `kairos.scoping`; module-
    # level `from … import resolve` would capture the import-time binding.
    from kairos.scoping import resolve

    try:
        principal = resolve(request)
    except HTTPException as exc:
        headers = _response_headers({"WWW-Authenticate": "Bearer"})
        return None, JSONResponse(
            {"detail": exc.detail}, status_code=exc.status_code, headers=headers,
        )
    return principal, None


def _dispatch_sync(message: Any, principal: dict, request: Request) -> Response:
    """The rest of the handler, after body read and parse.

    Runs in the Starlette threadpool so the event loop is not held for the
    duration of the DB/SMTP work inside `_handle_method`. Any exception
    here (other than the ones `_run_tool` already turns into tool errors) is
    an internal error: logged, and answered with a JSON-RPC internal error
    envelope rather than a plain-text 500 (which would break the MCP wire
    format a client reads).
    """
    try:
        if isinstance(message, list):
            # Batching removed in spec 2025-06-18. A JSON array body is invalid.
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
            return Response(status_code=202, headers=_response_headers())
        return _rpc_response(response)
    except Exception:
        log.exception("mcp dispatch raised")
        request_id = message.get("id") if isinstance(message, dict) else None
        return _rpc_response(_jsonrpc_error(INTERNAL_ERROR, "internal error", request_id))


@router.post("/mcp", include_in_schema=False)
async def mcp_post(request: Request) -> Response:
    """Streamable HTTP endpoint. One JSON-RPC message in, one out (or 202 for
    a notification). See the module docstring for the authentication,
    rate-limiting and scope/reach model this applies.

    This endpoint is `async def` only so it can `await` the body read; the
    real work (auth, dispatch, DB, SMTP, the Pydantic validation) happens
    inside `run_in_threadpool` so one slow tool call cannot starve every
    concurrent request on the same instance.
    """
    try:
        _validate_origin(request)
        _validate_protocol_version(request)
    except HTTPException as exc:
        return JSONResponse(
            {"detail": exc.detail}, status_code=exc.status_code, headers=_response_headers(),
        )

    # Body first, with a hard cap: a recursion-bomb payload must not reach
    # the JSON parser. 413 carries a JSON-RPC parse error envelope so an
    # agent reading `error.code` sees a protocol-level refusal, not an HTML
    # body (which it would misparse).
    try:
        raw = await _read_body_capped(request)
    except HTTPException as exc:
        return JSONResponse(
            _jsonrpc_error(PARSE_ERROR, exc.detail),
            status_code=exc.status_code, headers=_response_headers(),
        )

    message, parse_error = _parse_body(raw)
    if parse_error is not None:
        return _rpc_response(parse_error)

    # Auth + dispatch run off the event loop. Both are synchronous (SQLite
    # for auth, SQLite/SMTP/slot-expansion for dispatch), so running them
    # on the loop would serialise every concurrent MCP request through one
    # worker. `run_in_threadpool` is the same mechanism FastAPI uses for a
    # sync `def` route, so the behaviour matches `/api` exactly.
    principal, failure = await run_in_threadpool(_authenticate, request)
    if failure is not None:
        return failure

    return await run_in_threadpool(_dispatch_sync, message, principal, request)


@router.get("/mcp", include_in_schema=False)
@router.delete("/mcp", include_in_schema=False)
async def mcp_other() -> Response:
    """Spec: GET is for the optional server-initiated SSE stream; without
    one, 405. DELETE is session termination; we hold no sessions, so same."""
    return Response(status_code=405, headers=_response_headers({"Allow": "POST"}))


def _rpc_response(envelope: dict) -> Response:
    return JSONResponse(envelope, status_code=200, headers=_response_headers())


# -- Type hint for the handler signature ------------------------------------
# One handler shape: (poll_id, body, principal, request) -> tool-result dict.
# Kept at the bottom so the handlers themselves read top-to-bottom like the
# tool registry does; this is only here for a static type checker and for a
# code reader looking at a single handler to know what it is called with.
_Handler = Callable[[str | None, BaseModel | None, dict, Request], dict[str, Any]]
