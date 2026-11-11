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

echo
echo "Done. python_modules/ ready for \`wrangler deploy\`."
du -sh python_modules/
