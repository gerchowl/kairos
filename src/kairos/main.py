"""Kairos app factory + ASGI entrypoint (kairos.main:app)."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from kairos import settings
from kairos.db import get_connection, init_schema

P = settings.PREFIX


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_schema()
    yield


def create_app() -> FastAPI:
    from kairos.api import router as api_router
    from kairos.public import router as public_router
    from kairos.web import router as web_router

    app = FastAPI(
        lifespan=lifespan,
        title=f"{settings.BRAND} API",
        version="1.0",
        description=(
            "Scheduling-poll API. Create polls, submit responses, invite "
            "participants (required/optional), send idempotent reminders, "
            "decide a final date and distribute it with an .ics file.\n\n"
            "Auth: `Authorization: Bearer <KAIROS_API_KEY>`. "
            f"Agent quickstart: {P}/llms.txt"
        ),
        openapi_url=f"{P}/api/openapi.json",
        docs_url=f"{P}/api/docs",
        redoc_url=None,
    )

    app.include_router(api_router)
    app.include_router(web_router, include_in_schema=False)
    app.include_router(public_router, include_in_schema=False)
    app.mount(f"{P}/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

    def _openapi_with_bearer():
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(title=app.title, version=app.version,
                             description=app.description, routes=app.routes)
        schema.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = {
            "type": "http", "scheme": "bearer", "description": "KAIROS_API_KEY"}
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

## Typical agent flow

1. `POST {P}/api/polls` — create (mode: full_day | time_slot)
2. `POST {P}/api/polls/{{id}}/invite` — email invites (`required`: true|false)
3. `POST {P}/api/polls/{{id}}/respond` — submit/edit availability (upserts by email)
4. `GET  {P}/api/polls/{{id}}` — state incl. convergence (collecting|ready|partial|blocked)
5. `POST {P}/api/polls/{{id}}/nudge` — idempotent reminders
6. `POST {P}/api/polls/{{id}}/decide` — fix the final slot
7. `POST {P}/api/polls/{{id}}/email-decision` — mail everyone, .ics attached
8. `GET  {P}/api/polls/{{id}}/event.ics` — calendar file
"""

    @app.get(f"{P}/llms.txt", include_in_schema=False)
    def llms_txt():
        return PlainTextResponse(llms, media_type="text/markdown; charset=utf-8")

    @app.get(f"{P}/robots.txt", include_in_schema=False)
    def robots_txt():
        return PlainTextResponse(
            f"# Agent/API discovery: {P}/llms.txt and {P}/api/openapi.json\n"
            f"User-agent: *\nDisallow: {P}/p/\nDisallow: {P}/api/\n")

    if settings.OPERATOR:
        from kairos.templating import create_env, render
        legal_env = create_env()
        legal_ctx = {"operator": settings.OPERATOR,
                     "address": [a.strip() for a in settings.OPERATOR_ADDRESS.split(",") if a.strip()],
                     "email": settings.OPERATOR_EMAIL, "extra": settings.LEGAL_EXTRA}

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
            return JSONResponse(content={"status": "degraded", "error": str(e)}, status_code=503)

    return app


app = create_app()
