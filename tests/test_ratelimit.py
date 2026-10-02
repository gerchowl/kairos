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

from kairos import main, ratelimit, settings, templating
from kairos.ratelimit import MAX_BUCKETS, RateLimiter, caller_key, rate_limit

REPO = Path(__file__).resolve().parents[1]


# -- fixtures ---------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_limiter(monkeypatch):
    """Every test starts with an empty counter table and a fresh unattributed count."""
    ratelimit.limiter.reset()
    monkeypatch.setattr(ratelimit, "_no_peer_events", 0)
    monkeypatch.setattr(ratelimit.limiter, "sweeps", 0)
    yield
    ratelimit.limiter.reset()


@pytest.fixture
def on(monkeypatch):
    """Limits enabled with budgets small enough to exhaust inside a test.

    These are NOT the shipped numbers, and a test that passes at 3/minute says
    nothing about whether 300/minute is right. The shipped values are checked
    separately, against the thing they are sized for: `shipped` below, and
    `test_a_full_week_agent_sweep_fits_in_one_budget`.
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


@pytest.fixture
def shipped(monkeypatch):
    """Limits enabled at the SHIPPED numbers, untouched.

    The `on` fixture shrinks every budget so a test can exhaust one in a few
    requests. That makes those tests blind to whether the shipped numbers are
    right, so anything that is *about* a shipped number uses this instead.
    """
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    assert settings.RATE_LIMITS == settings.DEFAULT_RATE_LIMITS


def client_from(peer: str | None) -> TestClient:
    """A TestClient whose ASGI scope reports `peer` as the transport address."""
    return TestClient(main.app, base_url="https://testserver", client=(peer, 51000) if peer else None)


def request_from(peer: str | None, headers: dict | None = None):
    """A minimal Request carrying a chosen ASGI scope and headers.

    Keys are lower-cased on the way in: Starlette's `Headers(raw=...)` compares
    the *raw* bytes against `key.lower()`, so a mixed-case key silently never
    matches. Without this, a header written "X-Forwarded-For" looks absent here
    while being present on a real request -- which is how the first version of
    the two-proxy chain test "passed" against a header the code never saw.
    """
    from starlette.datastructures import Headers

    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
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
    ("GET", "/scheduler/health"): "SELECT 1; exempt from the proxy allowlist too",
    ("GET", "/scheduler/llms.txt"): "static text",
    ("GET", "/scheduler/robots.txt"): "static text",
    ("GET", "/scheduler/v/{code}"): "one indexed SELECT and a redirect; no render, no send",

    # Everything below is an *owner* route. Deliberately not limited, and the
    # defensible reason is NOT "it is auth-gated" -- `AUTH_MODE` defaults to
    # `demo`, where get_user() returns DEMO_USER for everyone and the CSRF token
    # is worthless, so in the shipped default these are exactly as open as the
    # public ones. The real argument:
    #
    #   * The owner surface does not touch a third party. `create`, `invite` and
    #     `send` are limited because they grow the participants table and open an
    #     SMTP connection; these only read rows or rewrite rows an owner already
    #     owns, so the abuse ceiling they add is the DB, not anyone's inbox.
    #   * They are keyed by owner identity, not by address. An IP budget on them
    #     would spend one shared bucket on everyone behind a NAT -- an office, a
    #     campus, ETH -- and lock out a legitimate organizer mid-poll. That is a
    #     self-inflicted outage bought against no attacker.
    #   * The hosted answer for owner routes is capability auth (#30) and A1/A2,
    #     not IP limiting. #51 adds the per-key tiering for the API surface.
    ("GET", "/scheduler/"): "owner dashboard; reads rows",
    ("GET", "/scheduler/new"): "owner form; renders the picker",
    ("GET", "/scheduler/polls/{poll_id}"): "owner view; reads rows",
    ("GET", "/scheduler/polls/{poll_id}/edit"): "owner form; reads rows",
    ("POST", "/scheduler/polls/{poll_id}/edit"): "edits slots on a poll the caller owns",
    ("POST", "/scheduler/polls/{poll_id}/close"): "state change on a poll the caller owns",
    ("POST", "/scheduler/polls/{poll_id}/reopen"): "state change on a poll the caller owns",
    ("POST", "/scheduler/polls/{poll_id}/decide"): "state change on a poll the caller owns",
    ("POST", "/scheduler/polls/{poll_id}/participants/update"): "edits rows the caller owns",
    ("POST", "/scheduler/polls/{poll_id}/participants/remove"): "deletes rows the caller owns",
    ("POST", "/scheduler/notifications/read-all"): "the caller's own notifications",
    ("GET", "/scheduler/polls/{poll_id}/event.ics"): "owner download of a poll's own .ics",
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


def test_the_bucket_table_stays_bounded_when_every_bucket_is_live():
    """Source addresses are caller-chosen, so the table is a memory-growth target.

    `now` is held CONSTANT, which is the realistic burst: a rotation of source
    addresses arriving inside a single window. An earlier version of this test
    advanced `now` by 1.0 per request against a 60s window, so every bucket was
    already stale by the time the cap was reached and only the cheap stale-sweep
    branch ever ran — it passed without ever exercising the live-window path.
    """
    lim = RateLimiter(max_buckets=100)
    for i in range(5000):
        lim.check("read", 10, 60, f"10.0.{i // 256}.{i % 256}", now=0.0)
    assert len(lim._buckets) <= 100


def test_the_table_stays_bounded_when_no_window_ever_expires():
    """The adversarial shape: a full table of live buckets that never age out."""
    lim = RateLimiter(max_buckets=50)
    for i in range(2000):
        lim.check("read", 10, 3600, f"10.0.{i // 256}.{i % 256}", now=0.0)
    assert len(lim._buckets) <= 50


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


def test_trimming_evicts_the_least_recently_charged_without_sorting():
    """Eviction must not order the whole table.

    The sweep dropped a 50k-element `sorted` on the request path: an attacker
    triggers it once by filling the table, and then every user behind them pays
    for it forever. Eviction is now `islice` over least-recently-charged order —
    O(overflow), no sort.
    """
    lim = RateLimiter(max_buckets=4)
    for i in range(8):
        lim.check("r", 5, 3600, f"k{i}", now=0.0)
    assert "k0" not in lim._buckets  # least recently charged, evicted first
    assert {"k6", "k7"} <= {key for _, key in lim._buckets}


def test_trimming_is_amortized_not_paid_per_request():
    """Once the table is full, sweeping on every request is a CPU amplifier:
    measured at ~4ms per request at 50k buckets, paid by every user behind
    whoever filled it. It must run at most once per `sweep_every` charges.
    """
    lim = RateLimiter(max_buckets=1000)  # sweep_every == 125
    for i in range(1000):
        lim.check("read", 10, 3600, f"seed{i}", now=0.0)
    before = lim.sweeps
    for i in range(5000):
        lim.check("read", 10, 3600, f"k{i % 900}", now=0.0)
    # 5000 charges at one sweep per 125 is ~40 sweeps, not 5000.
    assert lim.sweeps - before <= 5000 // lim._sweep_every + 1
    assert lim._sweep_every == 125


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


def test_an_unattributable_caller_is_admitted_and_says_so(on, monkeypatch, caplog):
    """A scope with no client address (unix-socket listener) cannot be attributed.

    Folding every local request into one shared bucket would break the
    operator's own deployment — the exact regression ADR-0001/0002 forbid — so
    such a caller is unlimited.
    """
    monkeypatch.setattr(ratelimit.limiter, "check", lambda *_a, **_k: (False, 42))
    assert caller_key(request_from(None)) is None
    with caplog.at_level("WARNING", logger="kairos.ratelimit"):
        for _ in range(3):
            assert rate_limit("read")(request_from(None)) is None
    assert caplog.text.count("no transport peer") == 3


def test_the_unattributable_warning_does_not_go_silent_forever(on, caplog):
    """Warn-once was the wrong shape: the cause is a deployment mistake nobody
    notices for weeks, and a control that is silently inert is worse than one
    that is switched off. A long-lived process must keep saying something."""
    with caplog.at_level("WARNING", logger="kairos.ratelimit"):
        for _ in range(ratelimit._NO_PEER_REWARN_EVERY + 5):
            caller_key(request_from(None))
    # The first few, then the periodic re-warn — not 1000 identical lines.
    assert caplog.text.count("no transport peer") == 3 + 1
    assert "#1000" in caplog.text


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


def test_the_default_bucket_cap_is_a_real_ceiling_not_a_slack_estimate():
    """The shipped limiter must hold its own table to MAX_BUCKETS, on the live
    path, with `now` pinned so nothing expires. (An earlier version asserted
    `0 < MAX_BUCKETS <= 100_000` — a range the test itself chose, which can only
    ever fail if someone edits the test.)
    """
    lim = RateLimiter()
    for i in range(MAX_BUCKETS + 500):
        lim.check("read", 10, 3600, f"10.0.{i // 256}.{i % 256}", now=0.0)
    assert len(lim._buckets) <= MAX_BUCKETS


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


# -- behind a reverse proxy: one shared bucket is NOT a rate limit ------------


@pytest.fixture
def proxying(monkeypatch):
    """A deployment behind a trusted reverse proxy (the README's own topology).

    TLS termination in front is universal, so this is the normal hosted shape,
    not an edge case: `scope["client"]` is the *proxy's* address on every request.
    """
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "RATE_LIMITS", dict.fromkeys(settings.DEFAULT_RATE_LIMITS, (3, 60)))
    monkeypatch.setattr(settings, "TRUSTED_PROXY_CIDRS", "127.0.0.0/8")
    monkeypatch.setattr(settings, "TRUSTED_PROXY_NETWORKS", settings._parse_networks("127.0.0.0/8", "T"))


def test_a_trusted_proxy_does_not_collapse_every_user_into_one_budget(proxying, no_db):
    """The bug this fixes, stated as a test.

    Eight genuinely distinct client addresses, all forwarded by one trusted
    proxy. Keyed on the peer, clients 4..8 would all be refused -- different
    humans sharing one budget, and at shipped defaults `create` 10/min and `send`
    10/hour would be the whole instance's allowance.
    """
    c = client_from("127.0.0.1")  # the proxy's socket, identical every request
    statuses = []
    for host in ("203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"):
        statuses.append(c.get("/scheduler/p/tok", headers={"X-Forwarded-For": host}).status_code)
    assert statuses == [404, 404, 404, 404], "each distinct client gets its own budget"


def test_a_repeated_client_behind_a_trusted_proxy_is_still_limited(proxying, no_db):
    """Separating users must not make each one unlimited."""
    c = client_from("127.0.0.1")
    headers = {"X-Forwarded-For": "203.0.113.7"}
    assert [c.get("/scheduler/p/tok", headers=headers).status_code for _ in range(5)] == [
        404, 404, 404, 429, 429,
    ]


def test_the_chain_is_walked_right_to_left_so_a_prepended_claim_is_ignored(proxying, no_db):
    """THE property. This is why the implementation is not rotation-attackable.

    XFF is built by appending, so anything a caller sends sits at the LEFT end
    and our own proxy's observation of the real socket is appended to its right.
    Walking from the right and skipping allowlisted hops therefore always lands
    on what our nearest proxy actually saw, and never on the caller's claim.

    Walking from the left -- the intuitive direction -- would return the caller's
    claim and hand back exactly the rotation this control exists to stop.
    """
    c = client_from("127.0.0.1")
    statuses = [
        c.get("/scheduler/p/tok",
              headers={"X-Forwarded-For": f"10.9.9.{i}, 203.0.113.7"}).status_code
        for i in range(5)
    ]
    # The rotating left-hand values are ignored; all five are the same client.
    assert statuses == [404, 404, 404, 429, 429]


def test_a_chain_through_two_of_our_proxies_resolves_to_the_real_caller(proxying, no_db):
    """`claim, ip-proxy-a-saw, ip-proxy-b-saw`.

    Right-to-left: 127.0.0.5 is inside the allowlist so it is one of ours and is
    skipped; 198.51.100.4 is the address proxy-b actually saw proxy-a's socket as,
    and it is not ours, so that is the caller. The left-hand `10.9.9.9` claim is
    never consulted.
    """
    headers = {"X-Forwarded-For": "10.9.9.9, 198.51.100.4, 127.0.0.5"}
    assert caller_key(request_from("127.0.0.1", headers)) == "198.51.100.4"

    # And it is one budget, not three: four requests on the same chain exhaust it.
    c = client_from("127.0.0.1")
    assert [c.get("/scheduler/p/tok", headers=headers).status_code for _ in range(4)] == [
        404, 404, 404, 429,
    ]


def test_an_untrusted_peer_cannot_choose_its_own_key_via_the_chain(proxying):
    """A caller who reaches the app directly supplies the whole header.

    The chain is only consulted when the transport peer is trusted, so an
    untrusted caller is keyed on its real peer and rotating the header buys it
    nothing -- the property the previous implementation had, preserved.
    """
    for i in range(5):
        req = request_from("203.0.113.7", {"x-forwarded-for": f"198.51.100.{i}"})
        assert caller_key(req) == "203.0.113.7"


def test_an_untrusted_peer_is_refused_outright_before_the_limiter_runs(proxying, no_db):
    """And in a configured deployment such a request never reaches the limiter
    at all -- S1's middleware 403s it at the edge (#47). So the keying rule
    above is defence in depth, not the only thing standing there."""
    c = client_from("203.0.113.7")
    assert c.get("/scheduler/p/tok", headers={"X-Forwarded-For": "198.51.100.1"}).status_code == 403


def test_no_allowlist_means_the_header_is_ignored_entirely(monkeypatch, no_db):
    """With nothing configured there is no way to know which hop to believe, so
    the header stays caller-supplied and is not used. This is the ETH/unconfigured
    invariant: key on the peer, exactly as before."""
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "RATE_LIMITS", dict.fromkeys(settings.DEFAULT_RATE_LIMITS, (3, 60)))
    monkeypatch.setattr(settings, "TRUSTED_PROXY_NETWORKS", ())
    c = client_from("203.0.113.7")
    statuses = [
        c.get("/scheduler/p/tok", headers={"X-Forwarded-For": f"198.51.100.{i}"}).status_code
        for i in range(5)
    ]
    assert statuses == [404, 404, 404, 429, 429]


def test_a_wholly_trusted_chain_falls_back_to_the_peer(proxying):
    """Every hop is one of ours, so there is no untrusted hop to name."""
    req = request_from("127.0.0.1", {"x-forwarded-for": "127.0.0.1, 127.0.0.2"})
    assert caller_key(req) == "127.0.0.1"


def test_an_empty_or_absent_chain_falls_back_to_the_peer(proxying):
    for headers in ({}, {"x-forwarded-for": ""}, {"x-forwarded-for": " , "}):
        assert caller_key(request_from("127.0.0.1", headers)) == "127.0.0.1"


def test_one_host_cannot_hold_two_budgets_by_spelling_its_address_two_ways(proxying):
    """`::ffff:203.0.113.7` and `203.0.113.7` are the same host.

    A dual-stack listener reports IPv4 clients in the mapped form, so without the
    fold a single caller would hold two budgets purely by which spelling the
    socket happened to produce -- the same reason auth.py folds it for the
    allowlist.
    """
    assert caller_key(request_from("::ffff:203.0.113.7")) == "203.0.113.7"
    assert caller_key(request_from("203.0.113.7")) == caller_key(request_from("::ffff:203.0.113.7"))


def test_a_unix_socket_path_is_kept_verbatim_as_a_key(monkeypatch):
    """Not an IP, so there is nothing to fold -- but it must still be a usable
    key rather than None (which would mean unlimited)."""
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "TRUSTED_PROXY_NETWORKS", ())
    assert caller_key(request_from("/tmp/kairos.sock")) == "/tmp/kairos.sock"


# -- the shipped deeplink_vote number, against what it is sized for ----------


def test_the_smallest_offered_increment_is_15_minutes():
    """Guards the input to the arithmetic below. If someone adds a 5-minute
    option, SLOTS_PER_DAY_AT_FINEST_OFFERED_INCREMENT is wrong and the sweep
    test below would be checking the wrong number."""
    import re

    source = (Path(templating.TEMPLATES) / "new_poll.html").read_text()
    increments = [int(v) for v in re.findall(r'<option value="(\d+)">', source)]
    assert increments, "could not read the increment options out of new_poll.html"
    assert min(increments) == 15
    # 09:00 -> 17:00 in 15-minute steps.
    assert settings.SLOTS_PER_DAY_AT_FINEST_OFFERED_INCREMENT == (17 - 9) * 60 // 15
    assert settings.FULL_WEEK_SWEEP_VOTES == 224


@pytest.fixture
def big_poll(tmp_path, monkeypatch):
    """A real full-week poll at the finest offered granularity: 32 x 7 = 224 slots.

    This is the thing `deeplink_vote` is sized for, so the sweep has to be run
    against an actual poll of that size, not a 2-slot fixture.
    """
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/big.db")
    monkeypatch.setattr(settings, "API_KEY", "k")
    monkeypatch.setattr(settings, "FEED_ENABLED", True)

    minute = 9 * 60
    slots = []
    for day in range(7):  # a week
        for _ in range((17 - 9) * 60 // 15):  # 32 slots of 15 minutes
            slots.append({"date": f"2026-07-{6 + day:02d}",
                          "start_time": f"{minute // 60:02d}:{minute % 60:02d}",
                          "end_time": f"{(minute + 15) // 60:02d}:{(minute + 15) % 60:02d}"})
            minute += 15
        minute = 9 * 60

    from kairos.main import create_app
    with TestClient(create_app(), base_url="https://testserver") as c:
        c.headers["Authorization"] = "Bearer k"
        poll = c.post("/scheduler/api/polls", json={
            "title": "Big week", "mode": "time_slot", "creator": "alice", "slots": slots}).json()
        assert len(poll["slots"]) == settings.FULL_WEEK_SWEEP_VOTES, len(poll["slots"])
        from kairos.db import create_invite
        itok = create_invite(poll["id"], "bob@x.ch", required=True, name="Bob")["token"]
        yield SimplePoll(c, poll, {"token": itok})


def test_a_full_week_agent_sweep_fits_in_one_budget_window(big_poll, shipped):
    """The behavioural version of the arithmetic, and the test that matters.

    `agent.json` hands an agent one vote URL per slot, so sweeping a poll costs
    one request per slot. A week of 15-minute slots across the default 09:00-17:00
    window is 32 x 7 = 224 slots. At the previously shipped 120/min that sweep was
    impossible inside any single window -- and the old justification cited ADR-0010
    for "~100 votes", a number ADR-0010 does not contain.

    If this fails, either `deeplink_vote` was lowered below a realistic poll, or
    the poll got bigger and the limit needs to follow.
    """
    limit, _window = settings.RATE_LIMITS["deeplink_vote"]
    assert limit >= settings.FULL_WEEK_SWEEP_VOTES

    c = client_from("203.0.113.7")
    slots = big_poll.poll["slots"]
    statuses = [c.get(f"/scheduler/p/i/{big_poll.itok}/s/{s['id']}/yes").status_code
                for s in slots]
    assert 429 not in statuses, f"sweep refused at request {statuses.index(429)}"
    assert statuses == [200] * len(slots)
    assert limit > len(slots), "the limit should still leave headroom over a full week"


def test_the_budget_is_still_finite_after_a_full_sweep(big_poll, shipped):
    """A sweep that fits must not mean an unlimited rule."""
    c = client_from("203.0.113.7")
    slot = big_poll.poll["slots"][0]["id"]
    limit, _ = settings.RATE_LIMITS["deeplink_vote"]
    for _ in range(limit + 5):
        c.get(f"/scheduler/p/i/{big_poll.itok}/s/{slot}/yes")
    assert c.get(f"/scheduler/p/i/{big_poll.itok}/s/{slot}/yes").status_code == 429
