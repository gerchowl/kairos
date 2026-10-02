"""The MCP client must build URLs that match how the server actually mounts /api.

The bug this guards: the client hardcoded ``/scheduler/api``, which is correct
only for the ETH/duplet deployment. Against a default instance — including the
README quickstart — every tool call 404s.
"""

import importlib.util
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

MCP_PATH = Path(__file__).resolve().parents[1] / "mcp" / "kairos_mcp.py"


def load_client(monkeypatch, **env):
    """Import mcp/kairos_mcp.py with a stubbed fastmcp, under the given env.

    The real `mcp` package is a PEP 723 inline-dependency script dependency and
    is not installed in the project env, so stub the one symbol the module
    touches at import time. Everything under test is pure URL construction.
    """
    for key in ("KAIROS_URL", "KAIROS_PREFIX"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    fastmcp = types.ModuleType("mcp.server.fastmcp")
    fastmcp.FastMCP = lambda *_a, **_kw: types.SimpleNamespace(tool=lambda *_a, **_kw: lambda f: f)
    server = types.ModuleType("mcp.server")
    server.fastmcp = fastmcp
    package = types.ModuleType("mcp")
    package.server = server
    for name, module in (("mcp", package), ("mcp.server", server), ("mcp.server.fastmcp", fastmcp)):
        monkeypatch.setitem(sys.modules, name, module)

    spec = importlib.util.spec_from_file_location("kairos_mcp_under_test", MCP_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        # Unprefixed default — the README quickstart case that used to 404.
        ({}, "http://127.0.0.1:8003/api/polls"),
        # The ETH/duplet deployment this was originally written for.
        ({"KAIROS_PREFIX": "/scheduler"}, "http://127.0.0.1:8003/scheduler/api/polls"),
        # Trailing slash must not double up.
        ({"KAIROS_PREFIX": "/scheduler/"}, "http://127.0.0.1:8003/scheduler/api/polls"),
        # A bare "/" prefix means "unprefixed", not "root of a doubled slash".
        ({"KAIROS_PREFIX": "/"}, "http://127.0.0.1:8003/api/polls"),
        ({"KAIROS_PREFIX": ""}, "http://127.0.0.1:8003/api/polls"),
        # Custom host and a nested prefix both compose.
        (
            {"KAIROS_URL": "https://kairos.example/", "KAIROS_PREFIX": "/s"},
            "https://kairos.example/s/api/polls",
        ),
        ({"KAIROS_URL": "https://kairos.nerdmachines.com"}, "https://kairos.nerdmachines.com/api/polls"),
    ],
)
def test_api_url_matches_server_mounting(monkeypatch, env, expected):
    assert load_client(monkeypatch, **env).api_url("/polls") == expected


def test_api_url_does_not_double_slash_between_prefix_and_api(monkeypatch):
    for prefix in ("", "/", "/scheduler", "/scheduler/", "//scheduler//"):
        client = load_client(monkeypatch, KAIROS_PREFIX=prefix)
        url = client.api_url("/polls")
        assert "//api" not in url.removeprefix("http://")
        assert url == f"http://127.0.0.1:8003{client.PREFIX}/api/polls"


def test_default_mounting_matches_settings_prefix(monkeypatch):
    """The client and the server must agree on the default, or every tool 404s.

    settings.PREFIX is the server's own normalization; the client has to land on
    the same string. Read it out of the settings module rather than restating it.
    """
    """The client and the server must agree on the default, or every tool 404s.

    Read the server's own PREFIX out of a clean-env subprocess rather than
    importing it here: settings.py binds the env at import time, so importing
    it in-process would compare against this machine's deployment (direnv
    exports KAIROS_PREFIX=/scheduler) and would also reload a module other
    tests have already cached.
    """
    repo_root = Path(__file__).resolve().parents[1]
    clean_env = {k: v for k, v in os.environ.items() if k != "KAIROS_PREFIX"}
    server_prefix = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0, 'src');"
            " from kairos.settings import PREFIX; sys.stdout.write(PREFIX)",
        ],
        cwd=repo_root,
        env=clean_env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    client = load_client(monkeypatch)
    assert server_prefix == "", f"shipped default should be unprefixed, got {server_prefix!r}"
    assert client.PREFIX == server_prefix
    assert client.api_url("/polls").endswith("/api/polls")
