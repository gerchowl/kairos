"""Kairos on Cloudflare Workers — Python Worker + Durable Object (SQLite).

Shape (#54 spike, ADR-0001/0002 "additive and nullable"):

  1. `Default.fetch` (the Worker entrypoint) forwards every HTTP request to a
     single named Durable Object instance. One writer, which matches the SQLite
     decision (#36) — the hosted product converges on the same shape ETH runs.
  2. `KairosDO.fetch` sets `dbconn.set_do_sql(self.sql)` for the request's
     lifetime, then runs Kairos' FastAPI ASGI app against a scope built from
     the Workers `Request`. Every SQL call from kairos.db flows through the
     DO's `ctx.storage.sql` without touching any of the existing query code.

The FastAPI app and the schema init both happen once per DO instance (there's
only one), so a cold start pays the FastAPI import + CREATE TABLE IF NOT EXISTS
cost once per DO wake.
"""

import os

# WASM has no OS threads. workers-py ships two top-level modules that patch
# packages like `anyio.to_thread` to inline their work; the .pth loader is
# supposed to pull them in at site init, but the auto-load is not reliable
# across every compat-date / python_process_pth_files combination, so import
# them explicitly BEFORE anything that pulls anyio in (starlette, fastapi,
# kairos.main). Patches register `register_exec_patch("anyio.to_thread")`,
# which only fires if the patch manager is installed and anyio.to_thread is
# not yet in `sys.modules` — hence the order.
try:  # pragma: no cover — only meaningful inside the workers runtime
    import importlib.util as _ilu
    if _ilu.find_spec("_cloudflare") is not None:
        import _workers_sdk_entropy_import_context  # noqa: F401
        import _workers_sdk_package_patches  # noqa: F401
except Exception:
    pass

# Kairos itself is imported lazily inside KairosDO.__init__: `kairos.main`
# calls `app = create_app()` at module level and `kairos.settings` refuses to
# boot without SESSION_SECRET — both must run AFTER the DO has `env` in hand,
# since secrets are only in `os.environ` once the worker starts, not at
# deploy-time module validation.

from workers import DurableObject, Response, WorkerEntrypoint  # noqa: E402


def _apply_env_from_bindings(env):
    """Copy bindings (vars + secrets) into os.environ so kairos.settings reads them.

    Workers plumbs env vars and secrets onto `env`; pyodide-workers also mirrors
    them into `os.environ`, but doing the copy explicitly makes it work for
    both. idempotent.
    """
    # The bindings we care about for kairos. Secrets (SESSION_SECRET) must come
    # through this path; vars could rely on the implicit mirroring, but naming
    # them keeps the invariant obvious.
    wanted = (
        "SESSION_SECRET",
        "KAIROS_AUTH",
        "KAIROS_BRAND",
        "KAIROS_DB_URL",
        "KAIROS_POLL_REACH",
        "KAIROS_RATE_LIMIT",
        "KAIROS_IMIP",
        "KAIROS_FEED",
        "KAIROS_HOSTED",
        "KAIROS_PUBLIC_URL",
    )
    for name in wanted:
        try:
            value = getattr(env, name, None)
        except Exception:
            value = None
        if value is not None:
            os.environ[name] = str(value)
    # Defaults that stay fixed in this deployment shape.
    os.environ.setdefault("KAIROS_AUTH", "capability")
    os.environ.setdefault("KAIROS_BRAND", "Kairos (spike)")
    os.environ.setdefault("KAIROS_DB_URL", "do-sqlite:///kairos")


class KairosDO(DurableObject):
    def __init__(self, ctx, env):
        super().__init__(ctx, env)
        self.sql = ctx.storage.sql
        _apply_env_from_bindings(env)

        # Import kairos AFTER env is in place. The order matters:
        #   1. dbconn reads KAIROS_DB_URL to pick the DO-SQLite backend
        #   2. set_do_sql lets kairos.db queries find this DO's sql
        #   3. init_schema CREATEs IF NOT EXISTS — idempotent per DO wake
        #   4. create_app wires routers; settings.session_secret() is read
        #      at request time, not at import time, but `capability` guards
        #      SESSION_SECRET at import so it must be set first.
        # Belt-and-suspenders: the workers-py register_exec_patch for
        # `anyio.to_thread` is a no-op if anyio was already loaded before the
        # patch manager ran. Forcibly override the two spellings that FastAPI
        # and starlette reach for — `anyio.to_thread.run_sync` (patched by
        # workers-py) and the asyncio backend's `run_sync_in_worker_thread`
        # (which starlette.concurrency routes to directly). This mirrors the
        # playground's Pyodide shim.
        import anyio.to_thread as _ato
        from anyio._backends import _asyncio as _aio_backend

        async def _inline_run_sync(func, *args, **kwargs):
            return func(*args)

        _ato.run_sync = _inline_run_sync

        async def _inline_backend_run_sync(func, args, abandon_on_cancel=False, limiter=None):
            return func(*args)

        _aio_backend.AsyncIOBackend.run_sync_in_worker_thread = staticmethod(
            _inline_backend_run_sync
        )

        from kairos import dbconn
        from kairos.db import init_schema
        from kairos.main import create_app

        dbconn.set_do_sql(self.sql)
        init_schema()
        self.dbconn = dbconn
        self.app = create_app()

    async def fetch(self, request):  # noqa: C901 — one linear ASGI shim, splitting hurts more than it helps for a spike
        # Rebind the DO sql for THIS request (DO instances persist across
        # requests, but a defensive re-set is cheap and keeps the invariant
        # obvious at the top of the hot path).
        self.dbconn.set_do_sql(self.sql)

        from js import URL as _URL

        url = _URL.new(request.url)
        # request.method is an HTTPMethod enum in workers-py Python Request;
        # ASGI wants the plain uppercase string.
        method = request.method.value if hasattr(request.method, "value") else str(request.method)
        path = url.pathname
        query = url.search.lstrip("?") if url.search else ""

        # ASGI headers: list of (name_bytes, value_bytes), lowercased.
        # workers-py returns headers as an http.client.Message-like object with
        # `.items()`; iterate that and lower-case for ASGI.
        headers = []
        try:
            for name, value in request.headers.items():
                headers.append((str(name).lower().encode("latin-1"),
                                str(value).encode("latin-1")))
        except Exception:
            # Fallback: a few common headers via .get()
            for h in ("content-type", "content-length", "cookie", "host",
                      "accept", "x-forwarded-for", "user-agent"):
                v = request.headers.get(h)
                if v:
                    headers.append((h.encode(), str(v).encode("latin-1")))

        body = b""
        if method not in ("GET", "HEAD", "OPTIONS"):
            # workers.Request exposes `.bytes()` which awaits arrayBuffer.
            try:
                body = await request.bytes()
            except Exception:
                body = b""

        # Client address: workers Request exposes it on `.cf` (an IncomingRequestCfProperties).
        peer = "0.0.0.0"
        try:
            cf = request.cf
            if cf is not None:
                ip = getattr(cf, "ip", None)
                if ip is not None:
                    peer = str(ip)
        except Exception:
            pass

        scheme = "https"
        try:
            scheme = url.protocol.rstrip(":") or "https"
        except Exception:
            pass

        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method,
            "scheme": scheme,
            "path": path,
            "raw_path": path.encode(),
            "query_string": query.encode(),
            "root_path": "",
            "headers": headers,
            "client": (peer, 0),
            "server": ("workers", 443),
        }

        out = {"status": 500, "headers": [], "chunks": []}
        done = {"v": False}

        async def receive():
            if done["v"]:
                return {"type": "http.disconnect"}
            done["v"] = True
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(msg):
            t = msg["type"]
            if t == "http.response.start":
                out["status"] = msg["status"]
                out["headers"] = list(msg.get("headers") or [])
            elif t == "http.response.body":
                chunk = msg.get("body") or b""
                if chunk:
                    out["chunks"].append(bytes(chunk))

        await self.app(scope, receive, send)

        # Convert ASGI headers → JS init object. Workers Response accepts
        # a plain dict or a JS Headers; a list of 2-tuples lets the runtime
        # preserve duplicate Set-Cookie headers.
        resp_headers = {}
        set_cookies = []
        for k, v in out["headers"]:
            name = k.decode("latin-1") if isinstance(k, (bytes, bytearray)) else str(k)
            value = v.decode("latin-1") if isinstance(v, (bytes, bytearray)) else str(v)
            if name.lower() == "set-cookie":
                set_cookies.append(value)
            else:
                resp_headers[name] = value

        body_bytes = b"".join(out["chunks"])
        resp = Response(body_bytes, status=out["status"], headers=resp_headers)
        # Append Set-Cookie headers (duplicates matter — resp_headers can't hold
        # two of the same key).
        for cookie in set_cookies:
            try:
                resp.headers.append("Set-Cookie", cookie)
            except Exception:
                resp.headers.set("Set-Cookie", cookie)
        return resp


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        # Serve `/static/*` from the Workers Static Assets binding first —
        # free of CPU budget and skips the DO round-trip entirely. Kairos
        # mounts /static inside the app too, so this is purely an optimisation.
        from js import URL as _URL
        url = _URL.new(request.url)
        if url.pathname.startswith("/static/"):
            asset_resp = await self.env.ASSETS.fetch(request)
            if asset_resp.status != 404:
                return asset_resp
        # Otherwise: forward to the single Kairos DO instance.
        ns = self.env.KAIROS_DO
        stub = ns.get(ns.idFromName("singleton"))
        return await stub.fetch(request)


# Kept for tooling that imports the module-level handler. Workers calls
# `Default.fetch` as declared above.
__all__ = ["Default", "KairosDO"]
