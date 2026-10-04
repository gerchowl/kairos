"""Test env: prefix + header auth mirror the original duplet deployment so the
ported tests keep their URLs/redirect expectations. SQLite is never touched —
db functions are stubbed per test."""

import os

import pytest

os.environ.setdefault("KAIROS_PREFIX", "/scheduler")
os.environ.setdefault("KAIROS_AUTH", "header")
os.environ.setdefault("KAIROS_LOGIN_URL", "/login")
os.environ.setdefault("SESSION_SECRET", "dummy")
os.environ.setdefault("KAIROS_DB_URL", "sqlite:///:memory:")


@pytest.fixture(autouse=True)
def _reset_process_local_abuse_state():
    """Clear the module-level abuse state `KAIROS_RATE_LIMIT=off` relies on.

    `capability._link_cooldowns` (#31's per-address re-link cooldown) and
    `ratelimit`'s counters are deliberately in-process — that is the tradeoff
    documented in both files — which means they survive between tests in one pytest
    process exactly as they survive between requests in production. Without this,
    any test that posts `/manage/link` for the same address twice would be answered by
    whichever earlier test ran first, and the suite would pass or fail by ordering.

    Here rather than in each test module, so no test can forget it: a module-local
    reset would be one more place for the next `/manage/link` test to miss.
    """
    from kairos import capability, ratelimit

    capability._link_cooldowns.clear()
    ratelimit.limiter._buckets.clear()
    yield
    capability._link_cooldowns.clear()
    ratelimit.limiter._buckets.clear()
