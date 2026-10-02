"""Obligation D3 (#35): the OCI image must wrap the *same* app, safely.

There is no way to unit-test a Dockerfile, but there are invariants in it that
only fail in production and that no linter knows about. Each one below is a
property a reviewer would otherwise have to remember:

  * the container must start the `kairos` console script, not `uvicorn` — see
    `test_container_starts_the_kairos_entrypoint`. Replacing the CMD with a bare
    `uvicorn` invocation silently re-enables uvicorn's X-Forwarded-For rewrite,
    and with it the entire S1 allowlist bypass, with no error and no log line.
  * the SQLite file must land on the mounted volume, and the volume must be
    mounted at the working directory the relative DB path resolves against —
    see the `test_sqlite_*` group.
  * no secret, and no deployment-specific value, may be baked into the image
    (ADR-0003 env-only config, D1 one-core-no-forks, S4 no committed secrets).
  * `/health` must stay reachable for container probes. It is exempted from the
    trusted-proxy allowlist in `main.create_app` precisely so a probe does not
    crashloop; an image whose healthcheck hits anything else reintroduces that.
  * the container must not run as root.

These parse the files as text. That is deliberate: it keeps the check
dependency-free (no PyYAML) and it asserts on the *shipped source*, which is
what an operator edits.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = (ROOT / "Dockerfile").read_text()
COMPOSE = (ROOT / "compose.yaml").read_text()
PROXY_COMPOSE = (ROOT / "compose.proxy.yaml").read_text()
MYSQL_COMPOSE = (ROOT / "compose.mysql.yaml").read_text()
DOCKERIGNORE = (ROOT / ".dockerignore").read_text().split()
# Everything from the final stage on — the builder stage is not shipped, so
# its WORKDIR, its venv and its imports are not what an operator runs.
RUNTIME_STAGE = DOCKERFILE.split("AS runtime", 1)[-1]

# Directives, so a multi-line RUN/CMD/ENV is handled as one value.
_DIRECTIVE = re.compile(r"^(?P<name>[A-Z]+)(?P<rest>[^\n]*(?:\n[ \t]+[^\n]*)*)", re.MULTILINE)


def _instructions(text: str, name: str) -> list[str]:
    """Every value of a Dockerfile instruction, joined across line continuations."""
    out = []
    for match in _DIRECTIVE.finditer(text):
        if match.group("name") == name:
            out.append(" ".join(match.group("rest").split()))
    return out


def _service(text: str, name: str) -> str:
    """One service's body from a compose file (services are indented by two)."""
    lines = _commented_out(text).splitlines()
    start = next(
        i
        for i, line in enumerate(lines)
        if line == f"  {name}:" or line.startswith(f"  {name}: ")
    )
    body = [lines[start]]
    for follow in lines[start + 1:]:
        if re.match(r"^ {0,2}\S", follow):
            break
        body.append(follow)
    return "\n".join(body)


def _healthcheck_block(text: str, key: str = "healthcheck:") -> str:
    """A `healthcheck:` block (compose) or `HEALTHCHECK` instruction (Dockerfile).

    Matched by indentation so it works in both YAML list style and exec form.
    """
    lines = _commented_out(text).splitlines()
    for i, line in enumerate(lines):
        if not line.strip().startswith(key):
            continue
        indent = len(line) - len(line.lstrip())
        body = [line]
        for follow in lines[i + 1:]:
            if follow.strip() and (len(follow) - len(follow.lstrip())) <= indent:
                break
            body.append(follow)
        return "\n".join(body)
    return ""


def _commented_out(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


# -- the load-bearing one: the entrypoint, not uvicorn -----------------------


def test_container_starts_the_kairos_entrypoint():
    """`kairos` on the CMD line, because it passes proxy_headers=False.

    uvicorn's own default rewrites scope["client"] from X-Forwarded-For before
    the app sees it, so `kairos.auth.peer_address()` would return the caller's
    claimed address and KAIROS_TRUSTED_PROXY_CIDRS would be validated against
    attacker input. `kairos.cli` documents the same thing; the point here is
    that the *image* cannot drift away from it silently.
    """
    cmds = _instructions(_commented_out(RUNTIME_STAGE), "CMD")
    assert cmds, "Dockerfile must have a CMD"
    for cmd in cmds:
        assert "kairos" in cmd, f"CMD must invoke the kairos entrypoint: {cmd}"
        assert "uvicorn" not in cmd, (
            "CMD must not invoke uvicorn directly — it would drop "
            "proxy_headers=False and re-enable the X-Forwarded-For rewrite that "
            "the trusted-proxy allowlist (S1) depends on. Pass --no-proxy-headers."
        )


def test_dockerfile_warns_about_uvicorn_override():
    """The hazard is documented at the place someone would trip over it."""
    assert "proxy_headers" in DOCKERFILE
    assert "no-proxy-headers" in DOCKERFILE


def test_no_compose_command_bypasses_the_entrypoint():
    """No compose file may pass a bare uvicorn as the container command."""
    for name, text in (
        ("compose.yaml", COMPOSE),
        ("compose.proxy.yaml", PROXY_COMPOSE),
        ("compose.mysql.yaml", MYSQL_COMPOSE),
    ):
        live = _commented_out(text)
        assert not re.search(r"^\s*command:.*\buvicorn\b", live, re.M), name
        assert not re.search(r"^\s*entrypoint:.*\buvicorn\b", live, re.M), name


# -- persistence: SQLite on the volume --------------------------------------


def test_workdir_is_the_data_directory():
    """The relative default `sqlite:///kairos.db` resolves against CWD.

    This is the whole persistence mechanism: WORKDIR is /data and /data is the
    volume mount point, so the default configuration already writes onto the
    volume. Changing WORKDIR without changing that reasoning loses every poll.
    """
    assert _instructions(_commented_out(RUNTIME_STAGE), "WORKDIR") == ["/data"]
    assert re.search(r"^\s*-\s*[\w.-]+:/data\s*$", COMPOSE, re.M), "compose.yaml must mount a volume at /data"


def test_compose_db_url_is_inside_the_volume():
    db_urls = re.findall(r"KAIROS_DB_URL:\s*(\S+)", _commented_out(COMPOSE))
    assert db_urls == ["sqlite:////data/kairos.db"], db_urls
    # Four slashes, not three: three is a *relative* path, which would resolve
    # against CWD and happen to work today purely by accident of WORKDIR.
    assert db_urls[0].startswith("sqlite:////")


def test_data_directory_is_owned_by_the_runtime_user():
    """A fresh named volume inherits ownership from the image directory."""
    assert re.search(r"chown\s+kairos:kairos\s+/data", _commented_out(DOCKERFILE))


# -- non-root ---------------------------------------------------------------


def test_container_does_not_run_as_root():
    users = _instructions(_commented_out(RUNTIME_STAGE), "USER")
    assert users, "Dockerfile must set USER"
    uid = users[-1].split(":")[0]
    assert uid.isdigit() and int(uid) != 0, f"USER must be a non-root uid: {users}"
    assert "USER root" not in _commented_out(DOCKERFILE)


def test_compose_drops_capabilities_and_refuses_privilege_escalation():
    for name, text in (("compose.yaml", COMPOSE), ("compose.proxy.yaml", PROXY_COMPOSE)):
        live = _commented_out(text)
        assert "no-new-privileges:true" in live, name
        assert "cap_drop" in live and "ALL" in live, name


# -- /health stays probeable ------------------------------------------------


def test_healthcheck_probes_slash_health():
    """/health is exempt from the allowlist precisely so probes work."""
    healthchecks = _instructions(_commented_out(RUNTIME_STAGE), "HEALTHCHECK")
    assert healthchecks, "Dockerfile must declare a HEALTHCHECK"
    assert any("/health" in hc for hc in healthchecks)
    # Repeat it in compose: podman's default image format is OCI, which cannot
    # carry a HEALTHCHECK at all, so an image-only probe silently does not exist.
    assert "/health" in _commented_out(COMPOSE)
    assert "/health" in _commented_out(PROXY_COMPOSE)


def test_kairos_healthcheck_needs_no_package_manager():
    """urllib (stdlib) rather than curl/wget — nothing extra to install or audit.

    Scoped to the Kairos probe on purpose: the Caddy healthcheck legitimately
    uses wget, because the caddy image is alpine-based and already has it.
    """
    for name, text in (("Dockerfile", RUNTIME_STAGE), ("compose.yaml", COMPOSE),
                       ("compose.proxy.yaml", _service(PROXY_COMPOSE, "kairos"))):
        key = "HEALTHCHECK" if name == "Dockerfile" else "healthcheck:"
        probe = _healthcheck_block(text, key)
        assert probe, f"{name}: no healthcheck found"
        assert "urlopen" in probe, f"{name}: probe must use urllib"
        assert not re.search(r"\b(curl|wget)\b", probe), (
            f"{name}: the Kairos probe must not depend on a packaged client"
        )


# -- no baked secrets, no per-deploy forks (D1, ADR-0003, S4) ---------------


def test_no_secret_or_deployment_value_is_baked_into_the_image():
    """No literal secrets, and nothing ETH/duplet-shaped either.

    The second half is D1: a `KAIROS_BRAND` or `KAIROS_OPERATOR` default here
    would be a per-deploy fork that no amount of env-var overriding cleanly
    undoes, and every deployment would silently inherit it.
    """
    runtime_stage = DOCKERFILE.split("AS runtime", 1)[-1]
    for env in _instructions(runtime_stage, "ENV"):
        for assignment in env.split():
            name, _, value = assignment.partition("=")
            assert not re.fullmatch(r"[0-9a-fA-F]{32,}", value), f"{name} looks like a literal secret"
            for forbidden in (
                "SESSION_SECRET",
                "KAIROS_API_KEY",
                "KAIROS_BRAND",
                "KAIROS_OPERATOR",
                "KAIROS_TRUSTED_PROXY_CIDRS",
                "KAIROS_AUTH",
            ):
                assert name != forbidden, f"{forbidden} must come from the environment, not the image"


# Operator-supplied values that must never have a default. Anything security
# relevant is `${NAME:?...}` so compose refuses to start rather than booting
# with an empty secret.
REQUIRED_VARS = {
    "compose.proxy.yaml": (
        "KAIROS_SITE",
        "ACME_EMAIL",
        "OIDC_ISSUER_URL",
        "OIDC_CLIENT_ID",
        "OIDC_CLIENT_SECRET",
        "OIDC_REDIRECT_URL",
        "OIDC_ALLOWED_DOMAINS",
        "OAUTH2_PROXY_COOKIE_SECRET",
        "SESSION_SECRET",
    ),
    "compose.mysql.yaml": ("KAIROS_DB_PASSWORD", "KAIROS_DB_ROOT_PASSWORD"),
}


@pytest.mark.parametrize("name", sorted(REQUIRED_VARS))
def test_operator_secrets_are_required_interpolations(name):
    """Every secret is `${NAME:?...}`, so compose fails closed on a missing .env.

    A defaulted secret (`${NAME:-}`) is worse than no secret: it boots, and
    either signs with a known-empty key or, for the MariaDB root password,
    initialises a database with a guessable one.
    """
    live = _commented_out({"compose.proxy.yaml": PROXY_COMPOSE, "compose.mysql.yaml": MYSQL_COMPOSE}[name])
    for var in REQUIRED_VARS[name]:
        suffixes = re.findall(r"\$\{" + var + r"([^}]*)\}", live)
        assert suffixes, f"{name}: {var} is never read from the environment"
        for suffix in suffixes:
            assert suffix.startswith(":?"), (
                f"{name}: {var} must be required (`${{{var}:?message}}`), got "
                f"`${{{var}{suffix}}}`"
            )


def test_dotenv_stays_out_of_git_and_out_of_the_build_context():
    """.env is read by compose and must reach neither a commit nor a layer (S4)."""
    assert ".env" in DOCKERIGNORE
    gitignore = (ROOT / ".gitignore").read_text()
    assert re.search(r"^/?\.env$", gitignore, re.M), ".env must be gitignored"
    # ...and .env.example must NOT be, or there would be no template to copy.
    assert re.search(r"^!/?\.env\.example$", gitignore, re.M)
    assert (ROOT / ".env.example").exists()


# -- the proxy topology's one structural claim ------------------------------


def test_proxy_topology_never_publishes_the_app_port():
    """Only Caddy may be reachable from off-box.

    compose overrides merge list-valued keys rather than subtracting them, so
    this is asserted on the standalone proxy file — the reason it is standalone.
    A published app port is the one thing that reliably defeats the allowlist:
    the engine's port forwarder is seen by the app as an in-subnet peer.
    """
    kairos = _service(PROXY_COMPOSE, "kairos")
    assert "ports:" not in kairos, "the app port must not be published"
    assert "expose:" in kairos


def test_proxy_topology_sets_the_allowlist_to_the_pinned_subnet_only():
    """Loopback and the container's own address must stay OUT of the allowlist."""
    subnets = re.findall(r"- subnet: (\S+)", _commented_out(PROXY_COMPOSE))
    assert len(subnets) == 1, subnets
    cidr = re.search(r'KAIROS_TRUSTED_PROXY_CIDRS:\s*"?([0-9./,\s]+)"?', _commented_out(PROXY_COMPOSE))
    assert cidr, "the proxy topology must set KAIROS_TRUSTED_PROXY_CIDRS"
    allowed = [part.strip() for part in cidr.group(1).split(",") if part.strip()]
    assert allowed == subnets, f"allowlist {allowed} must equal pinned subnet {subnets}"
    assert not any("127.0.0.1" in entry or "::1" in entry for entry in allowed)


def test_kairos_service_is_on_the_network_the_allowlist_names():
    """Without this the app is unreachable by name and every page 502s.

    Naming `networks:` on a service replaces the implicit `default` network
    rather than adding to it, so it is easy to omit — and the failure mode is a
    container that boots healthy and serves nothing.
    """
    networks = re.search(
        r"^  kairos:\n(?:(?!^\w)[\s\S])*?^    networks:\n      - (\S+)",
        _commented_out(PROXY_COMPOSE),
        re.M,
    )
    assert networks, "the kairos service must declare the proxy-facing network"
    assert networks.group(1) in _commented_out(PROXY_COMPOSE)


@pytest.mark.parametrize(
    "name,text",
    [("compose.yaml", COMPOSE), ("compose.proxy.yaml", PROXY_COMPOSE)],
)
def test_healthcheck_survives_the_proxy_allowlist(name, text):
    """A 403'd healthcheck is a crashloop; /health must be probed on loopback."""
    assert "127.0.0.1:8003/health" in _commented_out(text), name
