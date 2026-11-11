#!/usr/bin/env bash
# Build, size-check and deploy the Worker; refuse to upload a broken bundle.
#
# Why this exists: a hand-typed `vendor.sh; wrangler deploy` chain once shipped a
# 452 KiB partial bundle after vendor.sh had failed, and the live site was down
# until a rollback. Every step here must succeed before the next one runs, and
# the dry-run size must fall inside a sane window before anything is uploaded.
#
# Usage: bash scripts/deploy.sh            (from deploy/cloudflare)
# Env:   MIN_KIB / MAX_KIB  gzip size window (default 2000..3000; the Workers
#        Free cap is 3072 KiB gzip)
set -euo pipefail

cd "$(dirname "$0")/.."
MIN_KIB="${MIN_KIB:-2000}"
MAX_KIB="${MAX_KIB:-3000}"
export TMPDIR="${TMPDIR:-$HOME/.cache/kairos/tmp}"
mkdir -p "$TMPDIR"

if grep -rqE '^(<<<<<<<|>>>>>>>)' ../../src/kairos; then
    echo "refusing to deploy: unresolved merge conflict markers in src/kairos" >&2
    exit 1
fi

bash scripts/vendor.sh

out="$(npx -y wrangler@4 deploy --dry-run --outdir "$TMPDIR/cfbuild" 2>&1)"
kib="$(printf '%s\n' "$out" | sed -n 's/.*gzip: \([0-9.]*\) KiB.*/\1/p' | tail -1)"
if [ -z "$kib" ]; then
    printf '%s\n' "$out" >&2
    echo "refusing to deploy: could not read the bundle size from the dry run" >&2
    exit 1
fi
kib_int="${kib%.*}"
if [ "$kib_int" -lt "$MIN_KIB" ] || [ "$kib_int" -gt "$MAX_KIB" ]; then
    echo "refusing to deploy: bundle is ${kib} KiB gzip, outside ${MIN_KIB}..${MAX_KIB} KiB" >&2
    exit 1
fi
echo "bundle ${kib} KiB gzip — deploying"

npx -y wrangler@4 deploy
