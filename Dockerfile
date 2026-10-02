# Kairos — OCI image (issue #35; obligation D3, "wraps the same uvicorn app").
#
# Design rules this file encodes, in the order they matter:
#
#   1. SQLite is the deployment database (#36) and the default
#      `KAIROS_DB_URL=sqlite:///kairos.db` is *relative to the working
#      directory*. So the working directory IS the volume mount point (/data):
#      `podman compose up` needs no database configuration, and kairos.db lands
#      on the volume instead of in the container's throwaway layer.
#   2. Config comes from the environment only (ADR-0003). No secret, no operator
#      name, no ETH/duplet-specific value is baked in — one core, thin adapters
#      (D1). Anything hardcoded here becomes a per-deploy fork.
#   3. The CMD runs the `kairos` console script, which passes
#      `proxy_headers=False` to uvicorn. That is a SECURITY property, not a
#      preference: with uvicorn's default on, scope["client"] is rewritten from
#      X-Forwarded-For before Kairos sees it, so the KAIROS_TRUSTED_PROXY_CIDRS
#      allowlist (S1) would be checked against a caller-supplied address.
#      If you override the CMD and invoke uvicorn directly, you must add
#      --no-proxy-headers yourself.
#   4. The runtime layer carries no build toolchain: no compiler (gcc/cc/make are
#      all absent), no `curl`/`wget`, no `git`, and no `pip` anywhere — uv does
#      not install one into the venv and the Debian base's `/usr/local/bin/pip*`
#      is deleted. `apt`/`apt-get` DO remain: they are part of the Debian base
#      rather than something this file added, and they are how you would patch
#      an OS CVE in a derived image. Removing them too is a trade-off, not a free
#      win — see docs/design/self-host-hardening.md §9.
#      Python + the venv, running as uid 10001.

# Base-image family is an operator-level choice (slim vs alpine vs distroless).
# The default here is Debian slim, for the reasons that are actually about this
# project: it is the same CPython/glibc/`uvx kairos` semantics, and it keeps a
# shell for `podman run --rm -it <img> sh` debugging. It is NOT a security claim:
# the CI `audit` job runs `pip-audit` over `uv.lock` only, so Debian's own OS
# CVEs are unaudited here either way. Track those with Trivy/Grype against the
# image, or take the distroless option and accept no shell.
# See docs/design/self-host-hardening.md — flagged, not decided.
ARG PYTHON_VERSION=3.12

FROM docker.io/library/python:${PYTHON_VERSION}-slim-bookworm AS build

# uv, so the image installs the exact closure in uv.lock — which is what the CI
# `audit` job scans with pip-audit. Re-resolving at image-build time would ship
# a tree CI has never audited.
COPY --from=ghcr.io/astral-sh/uv:0.9.11 /uv /uvx /usr/local/bin/

ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /build

# README.md is a build input: pyproject declares it as the wheel readme.
COPY pyproject.toml uv.lock README.md ./
COPY src ./src

# --all-extras pulls in pymysql (pure Python, ~1 MB) so ONE image serves both
# the SQLite default and the MariaDB path — compose.mysql.yaml then needs no
# second build and no separate tag. Build a SQLite-only, pymysql-free image
# with `--build-arg UV_EXTRAS=`.
ARG UV_EXTRAS=--all-extras

# --locked: fail the build if pyproject.toml and uv.lock have drifted, rather
# than silently installing something the lockfile does not describe.
# --no-editable: install the built wheel, not a path pointing back at /build.
# --no-dev: the dev group (pytest, httpx) is a build-time toolchain, not runtime.
RUN uv sync --locked --no-dev --no-editable ${UV_EXTRAS} \
 && /opt/venv/bin/python -c "import kairos.main"   # fail the build on a broken import


FROM docker.io/library/python:${PYTHON_VERSION}-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="Kairos" \
      org.opencontainers.image.description="when2meet-style scheduling polls — self-hostable, reverse-proxy-auth friendly, agent-first API" \
      org.opencontainers.image.source="https://github.com/gerchowl/kairos" \
      org.opencontainers.image.licenses="MIT"

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

# Non-root. uid/gid 10001 matches the distroless `nonroot` convention, so an
# operator who later switches base image does not have to re-map volume
# ownership. nologin shell: nothing here should ever be exec'd into a login.
# /data is created and chowned HERE, which is what makes a fresh *named* volume
# work with no chown step: both podman and docker seed an empty named volume
# from the image directory, ownership included. A bind mount is the operator's
# to chown — see the hardening doc.
RUN groupadd --system --gid 10001 kairos \
 && useradd --uid 10001 --gid kairos --no-log-init --home-dir /data --shell /usr/sbin/nologin kairos \
 && mkdir -p /data \
 && chown kairos:kairos /data \
 # No pip anywhere in the runtime image: uv does not install one into the venv,
 # and the Debian base's /usr/local/bin/pip* is removed here. Nothing in the
 # image needs it, and pip is a convenient way to turn a read-only container
 # into a writable one. `apt` stays on purpose — see the header, rule 4.
 && rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12

COPY --from=build /opt/venv /opt/venv

# The SQLite default is relative to CWD, so this one line is the whole
# persistence story: `kairos.db`, its journal and any -wal/-shm siblings all
# appear next to it, i.e. on the volume.
WORKDIR /data

# Deliberately NO `VOLUME ["/data"]`. An anonymous volume per `podman run --rm`
# is a leak, and it would silently mask a missing mount instead of failing
# loudly. Compose mounts the named volume; the documented `podman run` command
# passes `-v kairos-data:/data`.

EXPOSE 8003

# /health is exempt from the trusted-proxy allowlist precisely so container and
# k8s probes do not crashloop — this probe depends on that, do not change it.
# urllib is stdlib: no curl/wget in the image, nothing extra to audit.
# Changing the in-container port means overriding CMD *and* this line.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8003/health', timeout=4).status == 200 else 1)"]

USER 10001:10001

# Through the `kairos` entrypoint on purpose — see rule 3 above. Override with
# extra flags via compose `command:`, e.g. ["kairos", "--port", "9000"].
CMD ["kairos", "--host", "0.0.0.0", "--port", "8003"]
