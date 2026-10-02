"""Obligation S1 (#47): header-mode identity must come only from our proxy.

In `KAIROS_AUTH=header` the owner identity is read straight off request headers,
so anyone who can reach the port can assert any identity. `KAIROS_TRUSTED_PROXY_CIDRS`
closes that by rejecting untrusted peers at the edge.

The subtle part — and the reason this file spends so much effort on
X-Forwarded-For — is *which* address gets checked. An allowlist validated against
a caller-supplied header is not an allowlist at all.
"""

import ipaddress
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from kairos import auth, main, settings

ALLOW = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("127.0.0.1"))


@pytest.fixture
def allowlist(monkeypatch):
    """Configure a trusted-proxy allowlist for the duration of a test."""
    monkeypatch.setattr(settings, "TRUSTED_PROXY_CIDRS", "10.0.0.0/8,127.0.0.1")
    monkeypatch.setattr(settings, "TRUSTED_PROXY_NETWORKS", ALLOW)
    return ALLOW


def client_from(peer: str) -> TestClient:
    """A TestClient whose ASGI scope reports `peer` as the transport address."""
    return TestClient(main.app, base_url="https://testserver", client=(peer, 51000))


# -- unset must change nothing (the ETH / self-host deployments) ------------


def test_unconfigured_allowlist_admits_every_peer():
    """With no allowlist configured, behaviour is exactly what it always was."""
    assert settings.TRUSTED_PROXY_NETWORKS == (), "test env must not set an allowlist"
    for peer in ("203.0.113.7", "198.51.100.9", "testclient"):
        assert auth.peer_is_trusted(_request_from(peer)) is True


def test_unconfigured_allowlist_leaves_requests_working(monkeypatch):
    monkeypatch.setenv("KAIROS_API_KEY", "k")
    c = client_from("203.0.113.7")  # an arbitrary public peer
    assert c.get("/scheduler/health").status_code == 200


# -- the allowlist does its job ---------------------------------------------


def test_peer_inside_allowlist_is_admitted(allowlist):
    assert auth.peer_is_trusted(_request_from("10.1.2.3")) is True
    assert auth.peer_is_trusted(_request_from("127.0.0.1")) is True


def test_peer_outside_allowlist_is_rejected(allowlist):
    assert auth.peer_is_trusted(_request_from("203.0.113.7")) is False


def test_ipv6_cidr_is_matched(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_NETWORKS", settings._parse_networks("2001:db8::/32", "T"))
    assert auth.peer_is_trusted(_request_from("2001:db8::1")) is True
    assert auth.peer_is_trusted(_request_from("2001:db9::1")) is False


def test_unmatchable_peer_is_untrusted_when_allowlist_set(allowlist):
    """A unix-socket path cannot match a CIDR list, so it must not be waved through."""
    assert auth.peer_is_trusted(_request_from("/tmp/kairos.sock")) is False


def test_missing_client_in_scope_is_untrusted_when_allowlist_set(allowlist):
    assert auth.peer_is_trusted(_request_from(None)) is False


def test_missing_client_in_scope_is_trusted_when_unset():
    assert auth.peer_is_trusted(_request_from(None)) is True


# -- the whole point: X-Forwarded-For must not be the checked address -------


def test_spoofed_xff_does_not_grant_trust(allowlist):
    """The decisive test.

    An attacker outside the allowlist sends an allowlisted address in
    X-Forwarded-For. If the check consulted that header it would pass; it must
    not, because the header is the very thing being claimed.
    """
    req = _request_from("203.0.113.7", headers={"x-forwarded-for": "10.0.0.1"})
    assert auth.peer_address(req) == "203.0.113.7"
    assert auth.peer_is_trusted(req) is False


def test_middleware_rejects_untrusted_peer_claiming_to_be_the_proxy(allowlist, monkeypatch):
    monkeypatch.setenv("KAIROS_API_KEY", "k")
    c = client_from("203.0.113.7")
    c.headers["Authorization"] = "Bearer k"
    c.headers["X-Forwarded-For"] = "10.0.0.1"
    c.headers["X-User"] = "victim"
    r = c.get("/scheduler/api/polls")
    assert r.status_code == 403
    assert "trusted proxy" in r.json()["detail"]


def test_middleware_admits_trusted_peer(allowlist, monkeypatch):
    monkeypatch.setenv("KAIROS_API_KEY", "k")
    monkeypatch.setattr("kairos.api.list_polls", lambda: [])
    c = client_from("10.1.2.3")
    c.headers["Authorization"] = "Bearer k"
    assert c.get("/scheduler/api/polls").status_code == 200


def test_middleware_rejects_untrusted_peer_on_public_routes_too(allowlist):
    """Respondent-facing pages are not an exemption.

    Public/token routes do not read identity headers, but the allowlist's job is
    to keep untrusted peers off the app entirely — otherwise this only half
    closes S1.
    """
    c = client_from("203.0.113.7")
    assert c.get("/scheduler/llms.txt").status_code == 403


def test_health_stays_reachable_from_an_untrusted_peer(allowlist):
    """/health is deliberately exempt.

    Container HEALTHCHECKs, k8s probes and LB health checks come from
    loopback/pod-internal addresses. Gating /health turns a probe into a
    crashloop, and the endpoint only runs SELECT 1.
    """
    c = client_from("203.0.113.7")
    assert c.get("/scheduler/health").status_code == 200


def test_trusted_peer_asserting_identity_is_honoured(allowlist):
    """The positive security property S1 exists to protect.

    A genuinely trusted proxy's identity header must still work -- otherwise the
    control has broken header mode rather than securing it.
    """
    req = _request_from("10.1.2.3", headers={"x-user": "alice", "x-email": "alice@example.org"})
    assert auth.peer_is_trusted(req) is True
    assert auth.get_user(req)["uid"] == "alice"


def test_unconfigured_allowlist_still_honours_header_identity():
    """The ETH/duplet invariant, pinned explicitly (PLAN.md): unset allowlist +
    header mode + X-User owner => unchanged behaviour, from a peer that would
    be untrusted if an allowlist existed."""
    req = _request_from("203.0.113.7", headers={"x-user": "alice"})
    assert auth.peer_is_trusted(req) is True
    assert auth.get_user(req)["uid"] == "alice"


def test_trusted_proxy_header_identity_works_end_to_end(allowlist, monkeypatch):
    """The same property through a real request: the owner UI renders."""
    from kairos import db, web

    monkeypatch.setattr(web, "list_polls", lambda uid: [])
    monkeypatch.setattr(web, "get_notifications", lambda uid, unread_only=False: [])
    monkeypatch.setattr(db, "get_notifications", lambda uid, unread_only=False: [])
    c = client_from("10.1.2.3")
    c.headers["X-User"] = "alice"
    assert c.get("/scheduler/", follow_redirects=True).status_code == 200


def test_ipv4_mapped_ipv6_peer_matches_an_ipv4_allowlist(monkeypatch):
    """A dual-stack listener ("--host ::", the container default) reports IPv4
    clients as ::ffff:a.b.c.d. Without normalisation an operator following the
    README example gets a silently dead app."""
    monkeypatch.setattr(settings, "TRUSTED_PROXY_NETWORKS", settings._parse_networks("127.0.0.1", "T"))
    assert auth.peer_is_trusted(_request_from("::ffff:127.0.0.1")) is True
    assert auth.peer_is_trusted(_request_from("::ffff:203.0.113.7")) is False


def test_log_names_the_enforced_allowlist_not_the_raw_var(allowlist, monkeypatch, caplog):
    """Regression: the log used to print TRUSTED_PROXY_CIDRS while enforcement
    read TRUSTED_PROXY_NETWORKS, so a disagreement was invisible."""
    monkeypatch.setattr(settings, "TRUSTED_PROXY_CIDRS", "10.0.0.0/8,127.0.0.1")
    monkeypatch.setattr(settings, "TRUSTED_PROXY_NETWORKS", (ipaddress.ip_network("192.0.2.0/24"),))
    c = client_from("198.51.100.9")
    with caplog.at_level("WARNING", logger="kairos.proxy"):
        c.get("/scheduler/llms.txt")
    assert "192.0.2.0/24" in caplog.text
    assert "10.0.0.0/8" not in caplog.text


# -- configuration parsing must not fail quietly ----------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", ()),
        ("10.0.0.0/8", (ipaddress.ip_network("10.0.0.0/8"),)),
        ("10.0.0.5", (ipaddress.ip_network("10.0.0.5"),)),  # bare IP -> /32
        (" 10.0.0.0/8 , 127.0.0.1 ", (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("127.0.0.1"))),
        ("10.0.0.0/8,,", (ipaddress.ip_network("10.0.0.0/8"),)),  # trailing commas
    ],
)
def test_parse_networks_accepts(raw, expected):
    assert settings._parse_networks(raw, "T") == expected


@pytest.mark.parametrize("raw", ["10.0.0.1/24", "192.168.1.7/16", "2001:db8::5/24"])
def test_parse_networks_rejects_host_bits_set(raw):
    """strict=True: "10.0.0.5/24" would silently trust 256 addresses and
    "192.168.1.7/16" would trust 65 536. Refuse rather than widen an allowlist."""
    with pytest.raises(RuntimeError, match="T"):
        settings._parse_networks(raw, "T")


@pytest.mark.parametrize("raw", ["not-an-ip", "10.0.0.0/99", "10.0.0.0/8,oops", "example.com"])
def test_parse_networks_rejects_garbage(raw):
    """A typo must be a startup error, not a silently skipped line — a skipped
    entry could void an allowlist the operator believes is in force."""
    with pytest.raises(RuntimeError, match="T"):
        settings._parse_networks(raw, "T")


def test_env_to_settings_wiring_rejects_a_typo_at_startup():
    """Every other test monkeypatches the parsed value, so pin the real
    env -> settings path in a subprocess: a typo must fail the boot."""
    result = subprocess.run(
        [sys.executable, "-c", "import sys; sys.path.insert(0, 'src'); import kairos.settings"],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "KAIROS_TRUSTED_PROXY_CIDRS": "10.0.0.0/8,typo"},
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "KAIROS_TRUSTED_PROXY_CIDRS" in result.stderr


def test_env_to_settings_wiring_accepts_a_good_value():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0, 'src');"
            " from kairos.settings import TRUSTED_PROXY_NETWORKS as n; print(len(n))",
        ],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "KAIROS_TRUSTED_PROXY_CIDRS": "10.0.0.0/8, 127.0.0.1"},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "2"


# -- the load-bearing uvicorn setting ---------------------------------------


def test_cli_disables_uvicorn_proxy_headers(monkeypatch):
    """`proxy_headers=False` is what makes peer_address() trustworthy.

    Uvicorn defaults proxy_headers on and rewrites scope["client"] from
    X-Forwarded-For before the app sees it. Left on, peer_address() returns the
    caller's claimed address and the allowlist is checked against attacker input.
    """
    import uvicorn

    from kairos import cli

    captured = {}
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: captured.update(kw))
    monkeypatch.setattr("sys.argv", ["kairos", "--port", "9999"])
    cli.main()

    assert captured.get("proxy_headers") is False


# -- end-to-end over a real socket -----------------------------------------


@pytest.mark.parametrize("proxy_headers", [True, False])
def test_real_server_xff_spoof_end_to_end(allowlist, monkeypatch, proxy_headers):
    """Drive a real uvicorn socket, with and without its XFF rewrite.

    Starlette's TestClient never rewrites scope["client"], so it structurally
    cannot catch this. Over a real socket, uvicorn's default
    `proxy_headers=True` replaces the peer with the caller's X-Forwarded-For
    *before* the app runs, so with the rewrite on, spoofing an allowlisted
    address gets through (200) — the allowlist is checking attacker input.

    With the rewrite off, which is what `kairos.cli` now sets, the same request
    is judged on its real peer and refused (403).
    """
    import uvicorn

    port = _free_port()
    config = uvicorn.Config(
        main.app, host="127.0.0.1", port=port, log_level="error", proxy_headers=proxy_headers
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    _wait_for_port(port)
    try:
        # Allowlist deliberately excludes the real peer (127.0.0.1) and contains
        # only the address the caller is about to claim.
        monkeypatch.setattr(settings, "TRUSTED_PROXY_NETWORKS", (ipaddress.ip_network("10.99.0.0/16"),))
        status = _get(port, "/scheduler/llms.txt", xff="10.99.0.1").status
        if proxy_headers:
            assert status == 200, "documents the hazard: uvicorn's rewrite defeats the allowlist"
        else:
            assert status == 403, "the fix: the allowlist must not honour a claimed address"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_real_server_admits_genuinely_allowlisted_peer(allowlist, monkeypatch):
    """And the positive case over a real socket: a real trusted proxy works."""
    import uvicorn

    port = _free_port()
    config = uvicorn.Config(main.app, host="127.0.0.1", port=port, log_level="error", proxy_headers=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    _wait_for_port(port)
    try:
        assert _get(port, "/scheduler/llms.txt", xff="203.0.113.99").status == 200
    finally:
        server.should_exit = True
        thread.join(timeout=5)


# -- helpers ----------------------------------------------------------------


def _request_from(peer: str | None, headers: dict | None = None):
    """A minimal Request carrying a chosen ASGI scope.

    Uses Starlette's real Headers so lookups are case-insensitive as they are on
    an actual request — a plain dict would silently miss "X-User" when the test
    wrote "x-user", which is how the header-identity tests first failed.
    """
    from starlette.datastructures import Headers

    raw = [(k.encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": raw,
        "client": (peer, 51000) if peer else None,
    }
    return type("R", (), {"scope": scope, "headers": Headers(raw=raw)})()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_for_port(port: int) -> None:
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("server never came up")


def _get(port: int, path: str, xff: str | None):
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"X-Forwarded-For": xff} if xff else {}
    conn.request("GET", path, headers=headers)
    resp = conn.getresponse()
    resp.read()
    conn.close()
    return resp
