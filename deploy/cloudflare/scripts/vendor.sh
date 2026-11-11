#!/usr/bin/env bash
# Rebuild python_modules/ for the Cloudflare Python Worker deploy.
#
# Why this exists: pywrangler's own `sync` command creates a pyodide-platform
# uv venv to resolve Emscripten wheels, and on NixOS the Pyodide interpreter
# can't satisfy uv's sysconfig probe. This script does the same shape by hand:
# download the specific wheels we need from the Pyodide index + PyPI, copy the
# workers-py SDK out of the host venv, and unpack everything into
# python_modules/ (the layout wrangler auto-discovers).
#
# Pinned versions explained:
#   * pydantic-core<2.35 — the Workers runtime patches `pydantic_core.
#     validate_core_schema`, a symbol pydantic-core dropped at 2.35. The
#     pyodide 0.28.3 index still ships 2.27.2 which exports it.
#   * fastapi==0.115.6 — 0.136+ imports opentelemetry at module level, which
#     calls uuid4() during Worker startup and trips the Workers "no randomness
#     during startup" refusal.
#   * starlette==0.41.3 — fastapi 0.115.6 passes `on_startup=` to the
#     Starlette router, which 1.x removed. 0.41 is the last pre-1.0 line.
#
# Keep `wrangler.jsonc`'s `compatibility_date = "2026-09-07"` aligned: the
# python_workers_314 default (2026-09-08) picks a different runtime whose
# pydantic patch expects wheels from the pyodide-314 index — none of which
# re-export `validate_core_schema`.
#
# Usage:
#   cd deploy/cloudflare && bash scripts/vendor.sh
set -euo pipefail

cd "$(dirname "$0")/.."

PYODIDE_INDEX="https://index.pyodide.org/0.28.3"
PYTHON_VERSION=313
HOST_PYTHON="${HOST_PYTHON:-python3}"

rm -rf python_modules
mkdir -p python_modules
touch python_modules/pyvenv.cfg

# -- Host-side venv just for workers-py (pure Python; version doesn't matter) --
"$HOST_PYTHON" -m venv .venv
.venv/bin/pip install --quiet --upgrade pip workers-py

# Workers SDK files. These are what makes `from workers import ...` work and
# what the `_workers_sdk_patch_loader.pth` references.
cp -r .venv/lib/python*/site-packages/workers python_modules/
cp -r .venv/lib/python*/site-packages/pyodide python_modules/
cp -r .venv/lib/python*/site-packages/_pyodide python_modules/
cp .venv/lib/python*/site-packages/asgi.py python_modules/
cp .venv/lib/python*/site-packages/_workers_sdk_entropy_import_context.py python_modules/
cp .venv/lib/python*/site-packages/_workers_sdk_package_patches.py python_modules/
cp .venv/lib/python*/site-packages/_workers_sdk_patch_loader.pth python_modules/
cp .venv/lib/python*/site-packages/_workers_sdk_patch_loader.py python_modules/
cp .venv/lib/python*/site-packages/_cloudflare_compat_flags.pyi python_modules/
cp .venv/lib/python*/site-packages/_pyodide_entrypoint_helper.pyi python_modules/

# -- Vendor the kairos package itself --
cp -r ../../src/kairos python_modules/

# -- Download Emscripten + pure-Python wheels into a stash directory --
export WHEELS="$(mktemp -d)"
.venv/bin/pip download --dest "$WHEELS" --no-deps --only-binary :all: \
    --platform pyodide_2025_0_wasm32 --platform any \
    --python-version "$PYTHON_VERSION" --implementation cp \
    --index-url "$PYODIDE_INDEX" --extra-index-url https://pypi.org/simple \
    "jinja2>=3.1,<3.2" "itsdangerous>=2.1" "python-multipart>=0.0.9" \
    "email-validator>=2.2" annotated-types "annotated-doc>=0.0.4" \
    dnspython idna typing-extensions typing-inspection anyio sniffio \
    markupsafe pydantic==2.10.6 pydantic-core==2.27.2 tzdata

# Specific pins for fastapi/starlette (their interface compatibility is
# narrower than the pyodide index's chosen pair):
.venv/bin/pip download --dest "$WHEELS" --no-deps --only-binary :all: \
    --platform any --python-version "$PYTHON_VERSION" --implementation cp \
    -i https://pypi.org/simple fastapi==0.115.6 starlette==0.41.3

# -- Unpack every wheel into python_modules/ --
"$HOST_PYTHON" - <<'PY'
import glob, os, zipfile
root = "python_modules"
for whl in sorted(glob.glob(os.environ["WHEELS"] + "/*.whl")):
    zipfile.ZipFile(whl).extractall(root)
    print("unpacked", os.path.basename(whl))
PY

# -- Static assets: copy kairos' CSS/JS under public/static/ so the Workers
#    Static Assets binding can serve them directly (bypassing FastAPI).
rm -rf public/static
mkdir -p public
cp -r ../../src/kairos/static public/static

# ---- Trim python_modules/ to fit the 3-MB-gzip Worker upload cap ---------
#
# The untrimmed bundle gzips to just over the 3072 KiB free-plan limit, so
# every deploy would be refused. Each cut below is checked against runtime
# imports (see the comment); if any smoke test fails, revert the matching
# line and re-measure with `wrangler deploy --dry-run`.

# __pycache__: compiled by the HOST CPython while unpacking wheels into
# python_modules/. The Workers pyodide runtime is a different interpreter
# (wasm32-emscripten, python 3.13) and recompiles on import, so these
# .pyc blobs are never executed.
find python_modules -type d -name "__pycache__" -exec rm -rf {} +

# kairos/static/: byte-identical to public/static/, which Workers' Static
# Assets binding serves via run_worker_first (see wrangler.jsonc and the
# `/static/` branch in entry.py — ASSETS answers before the DO is ever
# invoked). kairos.main.create_app() still mounts StaticFiles(check_dir=
# True) pointing at this path, so the directory must exist at runtime.
# Workers' wrangler packer skips empty directories, so we leave a 0-byte
# placeholder — enough for os.path.isdir() in starlette.StaticFiles.
rm -f python_modules/kairos/static/*
mkdir -p python_modules/kairos/static
: > python_modules/kairos/static/.keep

# dns/ (dnspython): only reached by email_validator.deliverability, which
# is lazy-imported inside validate_email() when check_deliverability=True
# (and separately by caching_resolver() if the caller asks for one).
# kairos always calls validate_email(check_deliverability=False) — see
# src/kairos/http.py:_norm_email — and nothing else in kairos, fastapi or
# starlette imports `dns`. The dist-info goes too since the wheel
# installer only lists it for dnspython.
rm -rf python_modules/dns python_modules/dnspython-*.dist-info

# pydantic/v1: the pre-v2 compatibility shim. kairos uses pydantic v2
# only; fastapi 0.115 and starlette 0.41 route v1 fields through a
# `hasattr(field, "serialize")` duck-type check, not an actual import
# of pydantic.v1.
rm -rf python_modules/pydantic/v1

# pydantic/experimental: opt-in beta features (pipeline). Not referenced
# by pydantic's own __init__, by fastapi, or by kairos.
rm -rf python_modules/pydantic/experimental

# anyio/_backends/_trio.py: anyio.run defaults to the asyncio backend and
# loads trio only via `import_module("anyio._backends._trio")` when a
# caller passes backend="trio". The Worker ASGI shim and kairos both
# stay on asyncio, so the trio module is dead code.
# anyio/pytest_plugin.py: anyio's own pytest helper; no runtime import.
rm -f python_modules/anyio/_backends/_trio.py \
      python_modules/anyio/pytest_plugin.py

# starlette/testclient.py + fastapi/testclient.py: only used by tests.
# Nothing in kairos imports them at runtime.
rm -f python_modules/starlette/testclient.py \
      python_modules/fastapi/testclient.py

# .pyi type stubs: Python's import machinery looks for .py/.pyc, not
# .pyi. These exist for type checkers and IDEs only. The two top-level
# stubs (_cloudflare_compat_flags, _pyodide_entrypoint_helper) describe
# modules the Workers runtime INJECTS as built-ins — the real objects
# come from the runtime, not from these files.
find python_modules -name "*.pyi" -delete

# tzdata non-data files: Python's zoneinfo walks the tzdata/zoneinfo/
# tree directly (via importlib.resources) when loading a timezone; the
# .tab files, tzdata.zi source and leapseconds metadata are used by the
# `tz`/`tzselect` CLIs, not by ZoneInfo. The binary tz files (and the
# tzdata/zones manifest zoneinfo.available_timezones uses) stay.
rm -f python_modules/tzdata/zoneinfo/zone.tab \
      python_modules/tzdata/zoneinfo/zone1970.tab \
      python_modules/tzdata/zoneinfo/zonenow.tab \
      python_modules/tzdata/zoneinfo/iso3166.tab \
      python_modules/tzdata/zoneinfo/tzdata.zi \
      python_modules/tzdata/zoneinfo/leapseconds

echo
echo "Done. python_modules/ ready for \`wrangler deploy\`."
du -sh python_modules/
