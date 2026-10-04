"""Kairos app factory + ASGI entrypoint (kairos.main:app)."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from kairos import settings
from kairos.db import get_connection, init_schema

P = settings.PREFIX
log = logging.getLogger("kairos.proxy")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_schema()
    yield


def create_app() -> FastAPI:
    from kairos import scoping
    from kairos.api import router as api_router
    from kairos.auth import peer_address, peer_is_trusted
    from kairos.oidc import boot_warnings, identity_report
    from kairos.oidc import router as oidc_router
    from kairos.public import router as public_router
    from kairos.ratelimit import install as install_ratelimit
    from kairos.web import router as web_router

    app = FastAPI(
        lifespan=lifespan,
        title=f"{settings.BRAND} API",
        version="1.0",
        description=(
            "Scheduling-poll API. Create polls, submit responses, invite "
            "participants (required/optional), send idempotent reminders, "
            "decide a final date and distribute it with an .ics file.\n\n"
            "Auth: `Authorization: Bearer <KAIROS_API_KEY>`. Keys may be scoped "
            "(`polls:read`, `polls:write`, `respond`, `mail:send`, `mail:force`, "
            "`imip:poll`); `GET /whoami` reports what the presenting key may do, "
            "and a route answers 403 for a capability the key lacks. "
            f"Agent quickstart: {P}/llms.txt"
        ),
        openapi_url=f"{P}/api/openapi.json",
        docs_url=f"{P}/api/docs",
        redoc_url=None,
    )

    # Obligation S1 (#47): if an allowlist is configured, only requests from a
    # trusted peer may reach the app at all. Enforced at the edge rather than
    # inside each route, so a new route cannot forget the check. Unconfigured =>
    # middleware is a no-op and behaviour is byte-for-byte what it always was.
    # /health is exempt: container HEALTHCHECKs, k8s liveness/readiness probes and
    # load-balancer health checks all originate from loopback or pod-internal
    # addresses, so gating it turns a probe into a crashloop. It runs SELECT 1 and
    # returns {"status","app"}.
    #
    # Matched exactly, not by substring. `endswith("/health")" would also exempt
    # /api/polls/health and /static/health; nothing reachable does today, but that
    # safety came from Starlette routing rather than from this check, so it is not
    # a property worth leaving to chance.
    health_path = f"{P}/health"

    if settings.TRUSTED_PROXY_NETWORKS:
        # The allowlist reads the ASGI scope's peer. If a server rewrote that from
        # X-Forwarded-For first, the allowlist would be checked against a value the
        # caller supplied. The app cannot detect this from inside -- uvicorn's
        # ProxyHeadersMiddleware mutates the scope with no marker -- so say so loudly
        # rather than fail silently and look like the control is working.
        log.warning(
            "KAIROS_TRUSTED_PROXY_CIDRS is set, so peer identity matters: the ASGI "
            "server MUST NOT rewrite the client address from X-Forwarded-For. The "
            "`kairos` entrypoint passes proxy_headers=False; if you launch uvicorn "
            "yourself, do the same (uvicorn --no-proxy-headers)."
        )

    # Obligation M1 (#48): say at every boot which identity outbound mail will be
    # sent as, and whether the gate is in force. SPF/DKIM/DMARC are DNS records the
    # app cannot read, so this line is the only place the deployment's mail identity
    # is stated — a misconfiguration that silently sends is far more expensive than
    # a log line. Logged here rather than in cli.main because the ETH/duplet adapter
    # calls create_app() itself and never goes through the console script.
    from kairos.email_service import mail_identity_report

    logging.getLogger("kairos.mail").info("%s", mail_identity_report())

    # Issue #53: the same statement for the *inbound* identity boundary. Which
    # control decided "who is the owner" is the one fact an operator cannot
    # infer from a working page, so say it at every boot — and say it
    # unconditionally, so "owner auth: header" is what a self-hoster reads on a
    # deployment that never asked for OIDC.
    oidc_log = logging.getLogger("kairos.oidc")
    oidc_log.info("%s", identity_report())
    for warning in boot_warnings():
        oidc_log.warning("%s", warning)
    # Issue #51: the API surface's authorisation and budgets, stated once at boot
    # the same way — a scoped keyring an operator believes is in force but is not
    # is the failure this line exists to make visible. Also *validates* it, so a
    # typo'd keyring or scope name refuses the boot here instead of silently
    # leaving every key at full capability.
    scoping_log = logging.getLogger("kairos.scoping")
    scoping_log.info("%s", scoping.boot_report())
    # Issues #63/#64: the same convention as `oidc.boot_warnings` above, at the
    # level a warning deserves — reach decides who may read which poll, so the
    # states where it is not the rule the operator believes (an unrecognised
    # KAIROS_HOSTED, `open` with scoped keys configured, `scoped` in header mode
    # with no trusted-proxy CIDRs) are warnings, not a line of prose in a green log.
    for warning in scoping.boot_warnings():
        scoping_log.warning("%s", warning)

    @app.middleware("http")
    async def trusted_proxy_only(request, call_next):
        if request.url.path != health_path and not peer_is_trusted(request):
            peer = peer_address(request)
            log.warning(
                "rejected untrusted peer %s (allowed: %s)",
                peer or "<unknown>",
                # Log the value enforcement actually reads, not the raw string:
                # they can disagree if the var was set without a re-parse.
                ",".join(str(n) for n in settings.TRUSTED_PROXY_NETWORKS) or "<unset: trusting every peer>",
            )
            return JSONResponse(
                content={"detail": "Forbidden: request did not arrive from a trusted proxy"},
                status_code=403,
            )
        return await call_next(request)

    app.include_router(api_router)
    app.include_router(web_router, include_in_schema=False)
    app.include_router(public_router, include_in_schema=False)
    # Registered in every mode and self-404ing when KAIROS_AUTH != oidc, so the
    # route table — which tests/test_ratelimit.py's route audit reads — does not
    # change shape with the auth mode.
    app.include_router(oidc_router, include_in_schema=False)

    # Obligation A3 (#37): register the rejection handler for exhausted budgets.
    # Registered unconditionally and inert while KAIROS_RATE_LIMIT is unset, so
    # an unconfigured deployment behaves exactly as before.
    install_ratelimit(app)

    app.mount(f"{P}/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

    def _openapi_with_bearer():
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title, version=app.version, description=app.description, routes=app.routes
        )
        schema.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = {
            "type": "http",
            "scheme": "bearer",
            "description": "KAIROS_API_KEY",
        }
        schema["security"] = [{"bearerAuth": []}]
        app.openapi_schema = schema
        return schema

    app.openapi = _openapi_with_bearer

    llms = f"""\
# {settings.BRAND} — scheduling polls

> when2meet-style scheduler. Everything the web UI does is also available
> through a JSON API, designed to be driven by agents.

## API

- [OpenAPI schema]({P}/api/openapi.json)
- [Interactive docs]({P}/api/docs)
- Auth: `Authorization: Bearer <KAIROS_API_KEY>` (ask the operator for the key)

## What am I allowed to do?

`GET {P}/api/whoami` returns the scopes your key holds
(`polls:read`, `polls:write`, `respond`, `mail:send`, `mail:force`, `imip:poll`).
A route you lack a scope for answers **403** with the missing scope in the
message — that is a permission boundary, not a bug, and not worth retrying.
`mail:force` (bypass the 24h reminder cooldown) is an operator capability on
purpose: do not reach for it on your own. Outbound mail is rate-limited per key
and budgeted per poll, so a retry loop will get a 429 rather than more mail.

## Typical agent flow

1. `POST {P}/api/polls` — create (mode: full_day | time_slot)
2. `POST {P}/api/polls/{{id}}/invite` — email invites (`required`: true|false)
3. `POST {P}/api/polls/{{id}}/respond` — submit/edit availability (upserts by email)
4. `GET  {P}/api/polls/{{id}}` — state incl. convergence (collecting|ready|partial|blocked)
5. `POST {P}/api/polls/{{id}}/nudge` — idempotent reminders
6. `POST {P}/api/polls/{{id}}/decide` — fix the final slot
7. `POST {P}/api/polls/{{id}}/email-decision` — mail everyone, .ics attached
8. `GET  {P}/api/polls/{{id}}/event.ics` — calendar file

## Invitee flow — no API key (the invite link IS the identity)

Given an invite link `{P}/p/i/<token>` (personal — treat it as a secret; whoever
holds it can vote as that person), an agent can RSVP with NO key:

- `GET {P}/p/i/<token>/agent.json` — poll, options, your current vote, one-click vote URLs
- `GET {P}/p/i/<token>/feed.ics`   — same options as a subscribe-able calendar
- `GET {P}/p/i/<token>/s/<slot>/<yes|maybe|no>` — cast/replace your vote (idempotent)

Hand your assistant the invite link; it self-describes via `agent.json`. Kairos
never reads your calendar — you (or your agent) tell it what works.
"""

    @app.get(f"{P}/llms.txt", include_in_schema=False)
    def llms_txt():
        return PlainTextResponse(llms, media_type="text/markdown; charset=utf-8")

    @app.get(f"{P}/robots.txt", include_in_schema=False)
    def robots_txt():
        return PlainTextResponse(
            f"# Agent/API discovery: {P}/llms.txt and {P}/api/openapi.json\n"
            f"User-agent: *\nDisallow: {P}/p/\nDisallow: {P}/api/\n"
        )

    if settings.OPERATOR:
        from kairos.templating import create_env, render

        legal_env = create_env()
        legal_ctx = {
            "operator": settings.OPERATOR,
            "address": [a.strip() for a in settings.OPERATOR_ADDRESS.split(",") if a.strip()],
            "email": settings.OPERATOR_EMAIL,
            "extra": settings.LEGAL_EXTRA,
        }

        @app.get(f"{P}/imprint", include_in_schema=False)
        def imprint():
            return render(legal_env, "legal_imprint.html", title="Imprint", **legal_ctx)

        @app.get(f"{P}/privacy", include_in_schema=False)
        def privacy():
            return render(legal_env, "legal_privacy.html", title="Privacy", **legal_ctx)

    @app.get(f"{P}/health", include_in_schema=False)
    def health():
        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()
            conn.close()
            return {"status": "ok", "app": "kairos"}
        except Exception as e:
            # Log the detail; do not return it. str(e) on a sqlite failure carries
            # absolute paths and driver text, and this endpoint is deliberately
            # reachable without passing the trusted-proxy allowlist.
            log.error("health check failed: %s", e, exc_info=True)
            return JSONResponse(content={"status": "degraded"}, status_code=503)

    return app


app = create_app()
