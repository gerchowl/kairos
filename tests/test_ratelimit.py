"""Obligation A3 (#37): abuse limits on the public / email-sending surface.

Two things are being tested here, and they pull in opposite directions:

1. **The limits work.** An unauthenticated stranger hammering a token URL, a
   calendar deep link, or the create form runs out of budget and gets a 429
   with a `Retry-After`. The address charged is the *real transport peer* — the
   decisive property, because a budget keyed on `X-Forwarded-For` is a budget
   the caller sets for themselves.

2. **Nothing happens at all unless asked.** ADR-0001/0002 and PLAN.md's guiding
   constraint: with no `KAIROS_RATE_LIMIT` in the environment, header-mode and
   self-host deployments must behave exactly as they did before this file
   existed. That is the invariant the coordinator checks, so it is pinned
   explicitly rather than left to the rest of the suite happening to pass.

The route-audit test in the middle is the one that keeps paying: it walks the
live route table, so a *new* public route added without a budget fails here.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from kairos import main, ratelimit, settings
from kairos.ratelimit import MAX_BUCKETS, RateLimiter, caller_key, rate_limit

REPO = Path(__file__).resolve().parents[1]


# -- fixtures ---------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_limiter(monkeypatch):
    """Every test starts with an empty counter table and the warning latch down."""
    ratelimit.limiter.reset()
    monkeypatch.setattr(ratelimit, "_warned_no_peer", False)
    yield
    ratelimit.limiter.reset()


@pytest.fixture
def on(monkeypatch):
    """Limits enabled with small, test-sized budgets.

    Deliberately not "one rule, tiny count": the shipped defaults must be
    exercised too, or a test that passes at 3/minute says nothing about 120.
    """
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(
        settings,
        "RATE_LIMITS",
        {
            "read": (3, 60),
            "respond": (2, 60),
            "deeplink_vote": (2, 60),
            "create": (2, 60),
            "invite": (2, 60),
            "send": (2, 3600),
        },
    )
    return settings.RATE_LIMITS


@pytest.fixture
def no_db(monkeypatch):
    """Make the token routes 404 without touching the database.

    These tests are about the limiter, not about poll rendering, and a 404 is
    the cheapest way to observe "the request got through the budget".
    """
    from kairos import public

    monkeypatch.setattr(public, "get_poll_by_token", lambda token: None)
    monkeypatch.setattr(public, "get_invite_by_token", lambda token: None)
    monkeypatch.setattr(public, "_render_poll_page",
                        lambda *a, **k: HTMLResponse("PAGE"))
    monkeypatch.setattr(public, "_not_found",
                        lambda *a, **k: HTMLResponse("MISSING", status_code=404))


def client_from(peer: str | None) -> TestClient:
    """A TestClient whose ASGI scope reports `peer` as the transport address."""
    return TestClient(main.app, base_url="https://testserver", client=(peer, 51000) if peer else None)


def request_from(peer: str | None, headers: dict | None = None):
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


# -- 1. THE ETH / SELF-HOST INVARIANT ---------------------------------------
# No configuration change, no behavioural change. Every existing test in the
# suite already relies on this implicitly; these make it explicit.


def test_limits_are_off_by_default():
    """The test environment must not silently enable them.

    If this ever needs relaxing, the suite's other 160 tests stop meaning
    "unchanged", so it is worth failing loudly and early.
    """
    assert settings.RATE_LIMIT_ENABLED is False
    assert settings.RATE_LIMITS == settings.DEFAULT_RATE_LIMITS


def test_an_unconfigured_deployment_admits_far_more_than_any_budget(no_db):
    """Hammer a limited route well past its budget with limits unset: no 429.

    `read` ships at 120/minute, so 400 requests from one peer is >3x the
    budget. If the limiter ran anyway, this fails.
    """
    c = client_from("203.0.113.7")
    statuses = {
        c.get("/scheduler/p/whatever", headers={"Accept": "text/html"}).status_code for _ in range(400)
    }
    assert 429 not in statuses


def test_unset_limits_change_nothing_with_limits_enabled_but_unreachable(on, monkeypatch, no_db):
    """Enabling the switch must not be what does the work — a request still has
    to carry a budget. With the whole table set to 'unlimited', every protected
    route answers exactly as it does unconfigured."""
    monkeypatch.setattr(settings, "RATE_LIMITS",
                        dict.fromkeys(settings.DEFAULT_RATE_LIMITS, (0, 60)))
    c = client_from("203.0.113.7")
    assert {c.get("/scheduler/p/t", headers={"Accept": "text/html"}).status_code for _ in range(300)} == {404}


# -- 2. THE LIMITS ACTUALLY LIMIT -------------------------------------------


def test_budget_is_exhausted_and_answers_429_with_retry_after(on, no_db):
    c = client_from("203.0.113.7")
    for _ in range(3):
        assert c.get("/scheduler/p/tok", headers={"Accept": "text/html"}).status_code == 404
    r = c.get("/scheduler/p/tok", headers={"Accept": "text/html"})
    assert r.status_code == 429
    assert r.headers["retry-after"] == "60"


def test_browser_gets_a_readable_page_not_a_json_blob(on, no_db):
    """A token page can be opened from a tap on a calendar event, so the person
    standing there must get an HTML explanation."""
    c = client_from("203.0.113.7")
    for _ in range(4):
        r = c.get("/scheduler/p/tok", headers={"Accept": "text/html"})
    assert r.status_code == 429
    assert r.headers["content-type"].startswith("text/html")
    assert "Too many requests" in r.text
    assert "60 seconds" in r.text


def test_json_client_gets_a_json_429(on, no_db):
    """The API and MCP surfaces (#51) must not have to parse a web page."""
    c = client_from("203.0.113.7")
    for _ in range(4):
        r = c.get("/scheduler/p/tok", headers={"Accept": "application/json"})
    assert r.status_code == 429
    assert r.headers["content-type"].startswith("application/json")
    assert r.json()["detail"].startswith("Rate limit exceeded for 'read'")
    assert r.headers["retry-after"] == "60"


def test_budget_is_charged_to_the_transport_peer_not_the_caller(on, no_db):
    c = client_from("203.0.113.7")
    other = client_from("198.51.100.4")
    assert [c.get("/scheduler/p/tok").status_code for _ in range(4)] == [404, 404, 404, 429]
    assert other.get("/scheduler/p/tok").status_code == 404


def test_spoofed_xff_cannot_reset_or_reach_the_budget(on, no_db):
    """The decisive test, and the reason `peer_address()` is used at all.

    An attacker sends a fresh `X-Forwarded-For` on every request. If the budget
    were keyed on that header, every request would look like a brand-new caller
    and none would ever be limited.
    """
    c = client_from("203.0.113.7")
    statuses = [
        c.get("/scheduler/p/tok", headers={"X-Forwarded-For": f"10.0.0.{n}"}).status_code for n in range(6)
    ]
    assert statuses[:3] == [404, 404, 404]
    assert statuses[3:] == [429, 429, 429]


def test_caller_key_is_the_peer_and_never_a_header(on):
    req = request_from(
        "203.0.113.7", {"x-forwarded-for": "10.0.0.1", "forwarded": "for=10.0.0.1", "x-real-ip": "10.0.0.1"}
    )
    assert caller_key(req) == "203.0.113.7"


def test_rules_have_independent_budgets(on, no_db):
    """Exhausting the read budget must not lock the same caller out of voting."""
    c = client_from("203.0.113.7")
    for _ in range(5):
        c.get("/scheduler/p/tok")
    assert c.get("/scheduler/p/tok", headers={"Accept": "application/json"}).status_code == 429
    # A different rule, untouched counter — still admitted (and then 404s on the
    # missing invite, which is the handler's business, not the limiter's).
    assert c.get("/scheduler/p/i/nope/s/t1/yes").status_code == 404


def test_the_rejection_is_logged_with_the_rule_and_the_peer(on, no_db, caplog):
    """An operator has to be able to see *who* is being limited and on what."""
    c = client_from("203.0.113.7")
    with caplog.at_level("WARNING", logger="kairos.ratelimit"):
        for _ in range(5):
            c.get("/scheduler/p/tok")
    assert "read" in caplog.text
    assert "203.0.113.7" in caplog.text


def test_the_rejection_never_logs_a_capability_token(on, no_db, caplog):
    """S3: tokens are bearer capabilities and must never reach a log."""
    c = client_from("203.0.113.7")
    with caplog.at_level("DEBUG", logger="kairos.ratelimit"):
        for _ in range(5):
            c.get("/scheduler/p/super-secret-token")
    assert "super-secret-token" not in caplog.text


# -- 3. THE ROUTE AUDIT — a new public route cannot ship unprotected --------


def _walk(router):
    """Yield every leaf route, descending into included routers.

    This FastAPI version keeps `include_router` as an `_IncludedRouter` wrapper
    instead of flattening, so a flat `app.routes` walk sees *no* endpoint at all.
    A guard built on that walk would pass forever while checking nothing.
    """
    for route in getattr(router, "routes", []):
        inner = getattr(route, "original_router", None)
        if inner is not None:
            yield from _walk(inner)
        elif getattr(route, "routes", None):
            yield from _walk(route)
        else:
            yield route


def _budgets_of(route):
    return {d.call.rule: d.call for d in route.dependant.dependencies if isinstance(d.call, rate_limit)}


# (method, path) -> rule, for everything A3 is about. Anything else that lives
# under the public or web router has to appear in the allowlist below with a
# reason, so "we forgot" is not an available outcome.
PROTECTED = {
    ("GET", "/scheduler/p/{token}/event.ics"): "read",
    ("GET", "/scheduler/p/{token}"): "read",
    ("POST", "/scheduler/p/{token}"): "respond",
    ("GET", "/scheduler/p/i/{invite_token}"): "read",
    ("POST", "/scheduler/p/i/{invite_token}"): "respond",
    ("GET", "/scheduler/p/i/{invite_token}/feed.ics"): "read",
    ("GET", "/scheduler/p/i/{invite_token}/agent.json"): "read",
    ("GET", "/scheduler/p/i/{invite_token}/s/{slot_id}/{availability}"): "deeplink_vote",
    ("POST", "/scheduler/new"): "create",
    ("POST", "/scheduler/polls/{poll_id}/invite"): "invite",
    ("POST", "/scheduler/polls/{poll_id}/remind-selected"): "send",
    ("POST", "/scheduler/polls/{poll_id}/remind"): "send",
    ("POST", "/scheduler/polls/{poll_id}/email-decision"): "send",
}

# Deliberately unlimited, with the reason. Owner-authenticated pages and
# one-row edits are behind `require_manage`/proxy auth, and an IP budget would
# punish a whole office sharing one NAT address for no abuse benefit — the
# hosted answer for those is capability auth (#30) plus A1/A2, not IP limiting.
# `/v/<code>` is a single indexed SELECT. The `/api/*` surface is #51's.
UNLIMITED = {
    ("GET", "/scheduler/p/"): "prefix of the token routes above",
    ("GET", "/scheduler/health"): "SELECT 1, exempt from the proxy allowlist too",
    ("GET", "/scheduler/llms.txt"): "static text",
    ("GET", "/scheduler/robots.txt"): "static text",
    ("GET", "/scheduler/v/{code}"): "one indexed SELECT, no render",
    ("GET", "/scheduler/"): "owner dashboard, auth-gated",
    ("GET", "/scheduler/new"): "owner page, auth-gated",
    ("GET", "/scheduler/polls/{poll_id}"): "owner page, auth-gated",
    ("GET", "/scheduler/polls/{poll_id}/edit"): "owner page, auth-gated",
    ("POST", "/scheduler/polls/{poll_id}/edit"): "edits existing rows, auth-gated",
    ("POST", "/scheduler/polls/{poll_id}/close"): "auth-gated",
    ("POST", "/scheduler/polls/{poll_id}/reopen"): "auth-gated",
    ("POST", "/scheduler/polls/{poll_id}/decide"): "auth-gated",
    ("POST", "/scheduler/polls/{poll_id}/participants/update"): "edits existing rows, auth-gated",
    ("POST", "/scheduler/polls/{poll_id}/participants/remove"): "auth-gated",
    ("POST", "/scheduler/notifications/read-all"): "own notifications, auth-gated",
    ("GET", "/scheduler/polls/{poll_id}/event.ics"): "owner page, auth-gated",
}


def test_public_and_web_routes_are_each_either_limited_or_explicitly_excluded():
    """The guard against a new public route shipping with no budget.

    Fail here means one of three things, all worth knowing: a genuinely new
    route needs a rule, a rule was renamed, or PREFIX moved.
    """
    seen = set()
    for route in _walk(main.app):
        path = getattr(route, "path", None)
        if not path or not hasattr(route, "dependant"):
            continue
        # The public router and the web router. /api/* is #51's surface and the
        # static mount is not an endpoint; both are deliberately out of scope.
        if not path.startswith("/scheduler/p/") and not path.startswith("/scheduler/"):
            continue
        if "/api/" in path or path.startswith("/scheduler/static"):
            continue
        for method in getattr(route, "methods", set()) - {"HEAD"}:
            seen.add((method, path))

    unexpected = {(m, p) for m, p in seen if (m, p) not in PROTECTED and (m, p) not in UNLIMITED}
    assert not unexpected, f"route(s) with no rate-limit decision recorded: {sorted(unexpected)}"

    missing = {(m, p) for m, p in PROTECTED if (m, p) not in seen}
    assert not missing, f"protected route(s) no longer exist: {sorted(missing)}"


def test_each_protected_route_actually_carries_its_rule():
    """Read off the live route table rather than trusting the table above."""
    actual = {}
    for route in _walk(main.app):
        if not hasattr(route, "dependant"):
            continue
        for rule in _budgets_of(route):
            for method in getattr(route, "methods", set()) - {"HEAD"}:
                actual[(method, route.path)] = rule
    assert actual == PROTECTED


def test_rate_limit_rejects_an_unknown_rule_name():
    """A typo in `rate_limit("repond")` must not be a rule that never fires."""
    with pytest.raises(RuntimeError, match="repond"):
        rate_limit("repond")


# -- 4. THE ALGORITHM -------------------------------------------------------


def test_fixed_window_admits_exactly_the_budget_then_refuses():
    lim = RateLimiter()
    assert lim.check("r", 2, 60, "k", now=0.0) == (True, 0)
    assert lim.check("r", 2, 60, "k", now=0.0) == (True, 0)
    allowed, retry = lim.check("r", 2, 60, "k", now=0.0)
    assert allowed is False and retry == 60
    # A refusal does not extend the window: the caller still gets served at the
    # original boundary, not later for having been throttled.
    assert lim.check("r", 2, 60, "k", now=59.0)[0] is False
    assert lim.check("r", 2, 60, "k", now=60.0)[0] is True


def test_retry_after_counts_down():
    lim = RateLimiter()
    lim.check("r", 1, 60, "k", now=0.0)
    assert lim.check("r", 1, 60, "k", now=25.0)[1] == 35
    assert lim.check("r", 1, 60, "k", now=25.0)[1] == 35
    assert lim.check("r", 1, 60, "k", now=59.9)[1] == 1  # never zero


def test_keys_and_rules_do_not_share_a_bucket():
    lim = RateLimiter()
    assert lim.check("r", 1, 60, "a", now=0.0)[0] is True
    assert lim.check("r", 1, 60, "b", now=0.0)[0] is True
    assert lim.check("other", 1, 60, "a", now=0.0)[0] is True


def test_a_zero_count_disables_that_rule():
    """The escape hatch: an operator who wants spam limits but not a budget on,
    say, agent sweeps sets 0 and gets unlimited for that rule only."""
    lim = RateLimiter()
    assert all(lim.check("r", 0, 60, f"k{i}")[0] for i in range(1000))


def test_the_bucket_table_stays_bounded_under_key_rotation():
    """Source addresses are caller-chosen, so the table is a memory-growth target.

    Without a trim, a rotation of source addresses grows a dict until the
    process dies — which is the limiter becoming the outage.
    """
    lim = RateLimiter(max_buckets=100)
    for i in range(5000):
        lim.check("read", 10, 60, f"10.0.{i // 256}.{i % 256}", now=float(i))
    assert len(lim._buckets) <= 100


def test_trimming_prefers_the_windows_that_are_about_to_reset():
    """Evicting a live, nearly-expired window costs the caller one extra request;
    evicting a fresh one costs a whole budget. Cheapest first."""
    lim = RateLimiter(max_buckets=3)
    lim.check("r", 5, 60, "old", now=0.0)   # nearly expired (60s window)
    lim.check("r", 5, 60, "mid", now=40.0)
    lim.check("r", 5, 60, "fresh", now=58.0)
    lim.check("r", 5, 60, "newest", now=58.0)  # table is now over cap -> trims
    assert "old" not in lim._buckets
    assert {"mid", "fresh"} <= {key for _, key in lim._buckets}


def test_trimming_clears_expired_windows_before_live_ones():
    """A table full of stale entries costs nothing to clear."""
    lim = RateLimiter(max_buckets=3)
    for i in range(3):
        lim.check("r", 5, 60, f"stale{i}", now=float(i))
    lim.check("r", 5, 60, "live", now=1000.0)   # every earlier window has expired
    lim.check("r", 5, 60, "live2", now=1000.0)  # now over cap -> sweeps the stale three
    assert {key for _, key in lim._buckets} == {"live", "live2"}


# -- 5. FAIL-OPEN / FAIL-CLOSED, STATED HONESTLY ---------------------------


def test_misconfiguration_fails_closed_at_boot():
    """A typo'd limit must be a process that refuses to start, not a control
    the operator believes is in force and is not (#47's lesson)."""
    with pytest.raises(RuntimeError, match="KAIROS_RATE_LIMIT_RESPOND"):
        settings._parse_rate_limits({"KAIROS_RATE_LIMIT_RESPOND": "twenty/minute"})


def test_an_unknown_rule_name_is_a_boot_error_too():
    """`KAIROS_RATE_LIMIT_REPOND=` is exactly the failure this must not have."""
    with pytest.raises(RuntimeError, match="KAIROS_RATE_LIMIT_REPOND"):
        settings._parse_rate_limits({"KAIROS_RATE_LIMIT_REPOND": "20/minute"})


def test_an_internal_fault_fails_open_and_says_so(on, monkeypatch, caplog, no_db):
    """The one judgement call, pinned so it cannot change silently.

    Fail-*closed* here would lock every respondent out of every poll because a
    dict increment raised. There is no untrusted input on this path and the
    keyspace is bounded, so an attacker cannot reach this branch; it is only a
    bug. When the counters move to a shared store this test must be inverted
    and the docstring with it.
    """

    def boom(*_a, **_k):
        raise RuntimeError("simulated limiter fault")

    monkeypatch.setattr(ratelimit.limiter, "check", boom)
    c = client_from("203.0.113.7")
    with caplog.at_level("ERROR", logger="kairos.ratelimit"):
        assert {c.get("/scheduler/p/tok").status_code for _ in range(50)} == {404}
    assert "rate limiter failed" in caplog.text


def test_an_unattributable_caller_is_admitted_and_warns_once(on, monkeypatch, caplog):
    """A scope with no client address (unix-socket listener) cannot be attributed.

    Folding every local request into one shared bucket would break the
    operator's own deployment — the exact regression ADR-0001/0002 forbid — so
    such a caller is unlimited, and says so once rather than on every request.
    """
    monkeypatch.setattr(ratelimit.limiter, "check", lambda *_a, **_k: (False, 42))
    assert caller_key(request_from(None)) is None
    with caplog.at_level("WARNING", logger="kairos.ratelimit"):
        for _ in range(3):
            assert rate_limit("read")(request_from(None)) is None
    assert caplog.text.count("no transport peer") == 1


def test_an_empty_budget_never_rejects(on, monkeypatch):
    """The early return when the switch is off must not consult the limiter at
    all — not merely not raise."""
    monkeypatch.setattr(
        ratelimit.limiter, "check", lambda *_a, **_k: pytest.fail("limiter consulted with limits off")
    )
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", False)
    assert rate_limit("read")(request_from("203.0.113.7")) is None


# -- 6. CONFIGURATION -------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("20/minute", (20, 60)),
        ("1/second", (1, 1)),
        ("10/hour", (10, 3600)),
        ("7/day", (7, 86400)),
        (" 30 / HOUR ", (30, 3600)),  # tolerant of the shell quoting deploy docs use
        ("0/minute", (0, 60)),  # 0 == this rule is off
    ],
)
def test_limits_parse(raw, expected):
    assert settings._parse_rate_limit(raw, "T") == expected


@pytest.mark.parametrize(
    "raw",
    [
        "20",  # missing window: a hidden default is a surprise
        "20/parsec",  # unknown window
        "twenty/minute",
        "-1/minute",
        "/minute",
        "",
    ],
)
def test_limits_refuse_garbage(raw):
    with pytest.raises(RuntimeError, match="T"):
        settings._parse_rate_limit(raw, "T")


def test_a_good_env_reaches_settings():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0, 'src');"
            " from kairos.settings import RATE_LIMITS as n; print(n['send'])",
        ],
        cwd=REPO,
        env={**os.environ, "KAIROS_RATE_LIMIT": "on", "KAIROS_RATE_LIMIT_SEND": "3/minute"},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "(3, 60)"


def test_a_typo_in_the_env_stops_the_boot():
    result = subprocess.run(
        [sys.executable, "-c", "import sys; sys.path.insert(0, 'src'); import kairos.settings"],
        cwd=REPO,
        env={**os.environ, "KAIROS_RATE_LIMIT_SEND": "10/minutes"},
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "KAIROS_RATE_LIMIT_SEND" in result.stderr


# -- 7. THE REAL ROUTES, END TO END ----------------------------------------


@pytest.fixture
def live(tmp_path, monkeypatch):
    """A real SQLite deployment with a poll, an invite and an owner session."""
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/k.db")
    monkeypatch.setattr(settings, "API_KEY", "k")
    monkeypatch.setattr(settings, "FEED_ENABLED", True)
    from kairos.main import create_app

    with TestClient(create_app(), base_url="https://testserver") as c:
        c.headers["Authorization"] = "Bearer k"
        poll = c.post(
            "/scheduler/api/polls",
            json={
                "title": "Abuse",
                "mode": "full_day",
                "creator": "alice",
                "slots": [{"date": "2026-07-06"}, {"date": "2026-07-07"}],
            },
        ).json()
        from kairos.db import create_invite

        invite = create_invite(poll["id"], "bob@x.ch", required=True, name="Bob")
        yield SimplePoll(c, poll, invite)


class SimplePoll:
    def __init__(self, client, poll, invite):
        self.c = client
        self.poll = poll
        self.invite = invite

    @property
    def token(self):
        return self.poll["public_token"]

    @property
    def itok(self):
        return self.invite["token"]

    @property
    def slot(self):
        return self.poll["slots"][0]["id"]


def test_deep_link_vote_is_budgeted(live, on):
    """The cheapest unbounded write on the public surface: an unauthenticated
    GET that creates a response row and a notification, with no CSRF token."""
    c = client_from("203.0.113.7")
    url = f"/scheduler/p/i/{live.itok}/s/{live.slot}/yes"
    assert [c.get(url).status_code for _ in range(2)] == [200, 200]
    r = c.get(url)
    assert r.status_code == 429
    assert r.headers["retry-after"] == "60"


def test_public_response_submission_is_budgeted(live, on):
    c = client_from("203.0.113.7")
    form = {"name": "Mallory", "email": "mallory@x.ch"}
    assert [c.post(f"/scheduler/p/{live.token}", data=form).status_code for _ in range(2)] == [200, 200]
    assert c.post(f"/scheduler/p/{live.token}", data=form).status_code == 429


def test_the_owner_send_budget_covers_the_actual_smtp_paths(live, on, monkeypatch):
    """`remind-selected` fans out to every address on the participants table and
    deliberately bypasses the 24h reminder cooldown — the strongest single lever
    from inside the web UI, so it is the one that most needs a ceiling."""
    sent = []
    from kairos import web

    monkeypatch.setattr(web, "send_invite_email", lambda email, *a, **k: sent.append(email) or True)
    monkeypatch.setattr(web, "send_update_emails", lambda *a, **k: sent.append(a) or True)
    monkeypatch.setattr(web, "log_contact", lambda *a, **k: None)
    monkeypatch.setattr(web, "mark_invite_notified", lambda *a, **k: None)

    from kairos.csrf import make_csrf

    form = {"csrf": make_csrf("alice"), "emails": "bob@x.ch"}
    c = client_from("203.0.113.7")
    c.headers["X-User"] = "alice"
    codes = [
        c.post(f"/scheduler/polls/{live.poll['id']}/remind-selected", data=form,
               follow_redirects=False).status_code
        for _ in range(3)
    ]
    assert codes[:2] == [302, 302]
    assert codes[2] == 429
    assert len(sent) == 2  # the third attempt never reached the transport


def test_an_enabled_limiter_does_not_disturb_the_normal_respondent_journey(live, on):
    """Not just "nothing 429s": with limits on, the whole flow still works,
    including the one user who is legitimately under the ceiling."""
    c = client_from("203.0.113.7")
    assert c.get(f"/scheduler/p/{live.token}").status_code == 200
    assert c.get(f"/scheduler/p/i/{live.itok}/agent.json").status_code == 200
    assert c.get(f"/scheduler/p/i/{live.itok}/s/{live.slot}/maybe").status_code == 200
    assert "Accepted" in c.get(f"/scheduler/p/i/{live.itok}/s/{live.slot}/yes").text


def test_the_dependency_raises_a_transport_agnostic_signal(on):
    """#51 needs to translate this into whatever its own surface answers with,
    so the dependency raises a domain exception and never an HTTP response."""
    with pytest.raises(ratelimit.RateLimited) as caught:
        for _ in range(4):
            rate_limit("read")(request_from("203.0.113.7"))
    assert caught.value.rule == "read"
    assert caught.value.retry_after == 60


def test_the_default_bucket_cap_is_finite_and_sane():
    """An unbounded keyspace is a memory-exhaustion vector: source addresses are
    caller-chosen, so every request can arrive under a new one."""
    assert RateLimiter()._max_buckets == MAX_BUCKETS
    assert 0 < MAX_BUCKETS <= 100_000


# -- the load-bearing uvicorn setting, measured over a real socket ----------


@pytest.mark.parametrize("proxy_headers", [True, False])
def test_real_server_xff_rotation_cannot_evade_the_budget(proxy_headers, no_db, monkeypatch):
    """Drive a real uvicorn socket, with and without its XFF rewrite.

    Starlette's TestClient never rewrites `scope["client"]`, so it structurally
    cannot catch this. Over a real socket, uvicorn's default `proxy_headers=True`
    replaces the peer with the caller's `X-Forwarded-For` *before* the app runs —
    so with the rewrite on, rotating that header evades the budget completely and
    the limiter silently does nothing.

    With the rewrite off, which is what `kairos.cli` sets, the same requests are
    charged to the real peer and are limited.
    """
    import http.client
    import socket
    import threading

    import uvicorn

    from kairos import settings as st

    # monkeypatch, never a direct assignment: settings is module state shared by
    # the whole suite, and leaking `enabled` from here breaks every later test.
    monkeypatch.setattr(st, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(st, "RATE_LIMITS", dict.fromkeys(st.DEFAULT_RATE_LIMITS, (2, 60)))


    def free_port() -> int:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def wait(port: int) -> None:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise AssertionError("server never came up")

    port = free_port()
    server = uvicorn.Server(
        uvicorn.Config(main.app, host="127.0.0.1", port=port, log_level="error",
                       proxy_headers=proxy_headers)
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    wait(port)
    try:
        statuses = []
        for i in range(5):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/scheduler/p/tok", headers={"X-Forwarded-For": f"10.0.0.{i}"})
            resp = conn.getresponse()
            resp.read()
            conn.close()
            statuses.append(resp.status)
        if proxy_headers:
            assert set(statuses) == {404}, "documents the hazard: XFF rotation evades the budget"
        else:
            assert statuses == [404, 404, 429, 429, 429], "the fix: the real peer carries the budget"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_enabling_limits_warns_about_the_proxy_headers_dependency(on, caplog):
    """The operator has to hear about the setting the control depends on."""
    from kairos.main import create_app

    with caplog.at_level("WARNING", logger="kairos.ratelimit"):
        create_app()
    assert "proxy_headers=False" in caplog.text
