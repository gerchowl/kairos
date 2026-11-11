# Kairos on Cloudflare — Python Worker + Durable Object (SQLite)

This directory is the time-boxed spike for #54 — Kairos running as a
Cloudflare Python Worker whose Durable Object owns the SQLite storage.

> **Status:** proof-of-concept, deployed live at
> https://kairos.pet4pets.workers.dev. Not production. See the PR body for the
> verdict and the gaps.

## Shape

```
HTTPS request
    ↓
Default.fetch (Python Worker entrypoint)
    ├─ /static/*  →  env.ASSETS.fetch (Workers Static Assets)
    └─ anything else  →  env.KAIROS_DO.get(idFromName("singleton")).fetch(req)
                              ↓
                          KairosDO.fetch
                              ├─ dbconn.set_do_sql(ctx.storage.sql)
                              ├─ build ASGI scope from the Workers Request
                              └─ run kairos.main.app(scope, receive, send)
```

One named Durable Object, one writer — matches ADR-0001 / #36. The DO's
SQLite is reached through a third backend in `kairos.dbconn` (see
`IS_DO_SQLITE`); every other deployment keeps its existing backend.

## Prerequisites

- Node (for `npx wrangler`)
- A Cloudflare account with Workers + Durable Objects access. The account
  used for this spike is `3306f41c1d726772439628e21d375304`.
- Host Python 3.12+ to run `scripts/vendor.sh` (just copies files around).
- `wrangler` is used via `npx wrangler@4` so no global install is needed.

## One-time setup

1. `cd deploy/cloudflare`
2. `npx wrangler@4 login` (OAuth in the browser)
3. `bash scripts/vendor.sh` — downloads Pyodide-platform wheels for pydantic/
   markupsafe/tzdata, pure-Python wheels for fastapi/starlette/jinja2/
   itsdangerous/python-multipart/email-validator, copies the `workers-py`
   SDK out of a host venv, and vendors the `kairos/` package. Produces
   `./python_modules/` (~13 MB after trimming — see "Bundle trims" below).
4. Generate a session secret and upload it as a Worker secret:
   ```sh
   openssl rand -hex 32 | npx wrangler@4 secret put SESSION_SECRET
   ```

## Deploy

```sh
npx wrangler@4 deploy
```

Expected output names the live URL (a workers.dev subdomain under your
account). The Worker's default route is the only one; no custom domain for
the spike.

## Config

See `wrangler.jsonc`. Important bits:

- `compatibility_date = "2026-09-07"` — pre-`python_workers_314` on purpose;
  see `scripts/vendor.sh` header for the pydantic-core compatibility story.
- `[[durable_objects.bindings]] class_name = "KairosDO"` — single named DO.
- `[[migrations]] new_sqlite_classes = ["KairosDO"]` — SQLite-backed DO.
  Required for this spike; the KV backend is no longer offered for new
  accounts anyway.
- `[assets] directory = "./public", binding = "ASSETS", run_worker_first = true` — 
  static files under `public/static/` bypass the DO entirely. `vendor.sh`
  copies kairos' CSS/JS into `public/static/` so this works.
- `vars` sets `KAIROS_AUTH=demo` (see note below on capability mode).

## Spike-only shortcuts to be aware of

- **`KAIROS_AUTH=demo`, not `capability`.** Capability mode refuses to
  create a poll if outbound mail is not configured (the `admin_token` is
  delivered by mail). This spike has mail off. The DO-SQLite backend and
  the full ASGI pipeline are exercised just as hard under `demo`.
- **`fastapi==0.115.6`, `starlette==0.41.3`.** The current pins avoid two
  Workers-runtime incompatibilities documented in `scripts/vendor.sh`.
- **`python_modules/` is not committed.** Rebuild with `vendor.sh` on each
  deploy. A production path would build it in CI.

## Bundle trims (keeping under the Workers 3 MB gzip cap)

The Workers Free plan refuses any upload above **3072 KiB gzipped**. Our
baseline vendored bundle was `12122.27 KiB raw / 3031.72 KiB gzip` — a
41 KiB headroom, enough for a single new wheel version to tip the deploy
over. `scripts/vendor.sh` therefore prunes files that are never imported
or read in the Worker runtime; each exclusion carries an inline comment
explaining why it is safe.

After trimming: **`9501.02 KiB raw / 2475.50 KiB gzip`** (1088 modules),
~556 KiB of headroom under the limit.

Current exclusions (see `scripts/vendor.sh`):

| Excluded path | Why safe |
|---|---|
| `python_modules/**/__pycache__/` | Host-CPython .pyc files; the wasm Pyodide runtime recompiles on import. |
| `python_modules/kairos/static/*` | Same bytes live under `public/static/`, served by the ASSETS binding (`run_worker_first`). The empty dir + a 0-byte `.keep` keep `StaticFiles(check_dir=True)` happy. |
| `python_modules/dns` + dnspython dist-info | Only imported by `email_validator.deliverability`, which is lazy and gated on `check_deliverability=True`. kairos always passes `False`. |
| `python_modules/pydantic/v1` | pre-v2 shim; kairos/fastapi 0.115/starlette 0.41 never import `pydantic.v1` at runtime. |
| `python_modules/pydantic/experimental` | opt-in beta (pipeline); not referenced anywhere. |
| `python_modules/anyio/_backends/_trio.py` | asyncio is the only backend used; trio is lazy-loaded by `import_module`. |
| `python_modules/anyio/pytest_plugin.py` | anyio's own test plugin; no runtime import. |
| `python_modules/starlette/testclient.py`, `python_modules/fastapi/testclient.py` | Not imported by the app. |
| `*.pyi` type stubs | Python ignores `.pyi` on import; the two top-level stubs describe modules the Workers runtime injects natively. |
| `python_modules/tzdata/zoneinfo/{zone.tab,zone1970.tab,zonenow.tab,iso3166.tab,tzdata.zi,leapseconds}` | Used by the `tz` CLI / `tzselect`, not by Python's `zoneinfo` (which walks the tree directly). |

Revert-if-it-breaks: undo the matching line in `scripts/vendor.sh`, then
re-measure with `npx wrangler@4 deploy --dry-run --outdir /tmp/cfbuild`.

## What this spike proves and doesn't prove

Proven live:
- `from workers import DurableObject` works on a Python Worker
- FastAPI's ASGI app runs end-to-end — module load, request dispatch,
  cookies, CSRF, redirects, templated HTML responses, .ics generation
- `ctx.storage.sql.exec(sql, *params)` is enough SQL surface area for
  every kairos route tested: create poll, vote, decide, fetch event.ics
- Data persists across worker redeploys (the DO survives)
- Static assets via the Workers Static Assets binding
- The anyio-to-thread shim (patched both at `anyio.to_thread.run_sync` and
  at `AsyncIOBackend.run_sync_in_worker_thread`) covers starlette's sync
  dependency dispatch under Workers' single-threaded runtime

Not addressed (gaps for productionization, filed in the PR body):
- Outbound mail (needs an HTTP API, SPF/DKIM/DMARC → #34, #48)
- Inbound iMIP (needs Cloudflare Email Routing → #34)
- Cron reminders (needs Workers Cron Triggers)
- Rate-limit state across requests (currently in-memory per isolate)
- Turnstile integration (library is present but not wired)
- CPU per request vs. Workers Free's 10 ms cap (see PR numbers)
