"""Request helpers."""

from fastapi import Request


def get_base_url(request: Request) -> str:
    """Public base URL from reverse-proxy headers, falling back to request.base_url."""
    proto = request.headers.get("X-Forwarded-Proto", request.url.scheme)
    host = request.headers.get("X-Forwarded-Host", request.headers.get("Host", ""))
    if host:
        return f"{proto}://{host}"
    return str(request.base_url).rstrip("/")


async def form_data(request: Request):
    """FastAPI dependency: parsed form for SYNC handlers.

    Route handlers should be plain `def` (FastAPI runs them in a threadpool,
    so blocking DB calls don't stall the event loop). `await request.form()`
    needs async — this dependency does the awaiting so handlers can stay sync:

        def submit(form=Depends(form_data)): ...
    """
    return await request.form()
