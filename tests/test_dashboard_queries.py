"""The dashboard's SQL cost is a hard constraint on Cloudflare's free tier.

Workers Free allows 50 D1 subrequests per invocation (1000 on paid). The dashboard
renders every poll an owner has, so its cost is linear in poll count: measured
against real SQLite it is `3N + 2` statements — 1 initial poll SELECT, plus one
`COUNT(*)` per poll inside `list_polls`, plus `get_responses` and `get_invites`
per poll, plus one notification query.

These tests count **real** `cursor.execute` calls against a real SQLite schema.
An earlier version counted calls to stubbed `web.py` functions and modelled the
cost as `2 + 2N`; that model cannot see the N+1 *inside* `list_polls`, so it
reported 50 statements at 24 polls when the true figure is 74 — a false green on
the exact property the test claimed to protect.

The honest conclusion these tests record: with a trusted-proxy allowlist and a
50-statement budget, the dashboard fits ~16 polls with no responses and only ~8
once polls have responses. That is a real limit of the current design, not a
regression, and fixing it needs convergence denormalised onto `sched_polls` (one
query) or the grid loaded per poll as a JS island. Tracked in `PLAN.md`.
"""

import sqlite3

import pytest
from fastapi.testclient import TestClient

from kairos import settings

FREE_SUBREQUESTS = 50
PAID_SUBREQUESTS = 1000

# Per-poll statement overhead beyond the initial SELECT, as measured below.
EXPECTED_BASE = 2
EXPECTED_PER_POLL = 3


@pytest.fixture
def counted(tmp_path, monkeypatch):
    """Point kairos at a fresh on-disk SQLite DB and count real statements.

    `get_connection()` reads `settings.DB_URL` at call time, so pointing it at a
    temp file needs no module reloading -- which matters, because reloading the
    `kairos` package leaks module references into every other test module.
    """
    count = {"n": 0}

    class CountingCursor:
        def __init__(self, cursor):
            self._cursor = cursor

        def execute(self, *a, **k):
            count["n"] += 1
            return self._cursor.execute(*a, **k)

        def executemany(self, *a, **k):
            count["n"] += 1
            return self._cursor.executemany(*a, **k)

        def __getattr__(self, name):
            return getattr(self._cursor, name)

        def __iter__(self):
            return iter(self._cursor)

    class CountingConnection(sqlite3.Connection):
        def cursor(self, *a, **k):
            return CountingCursor(super().cursor(*a, **k))

    real_connect = sqlite3.connect
    sqlite3.connect = lambda *a, **k: real_connect(*a, **{**k, "factory": CountingConnection})
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/t.db")

    from kairos import db, main
    db.init_schema()
    client = TestClient(main.app, base_url="https://testserver")
    client.headers["X-User"] = "alice"
    try:
        yield count, db, client
    finally:
        sqlite3.connect = real_connect


def seed(db, n_polls: int, n_responses: int = 0) -> None:
    for i in range(n_polls):
        poll = db.create_poll(
            creator_id="alice",
            title=f"P{i}",
            description=None,
            mode="full_day",
            timezone="UTC",
            slots=[{"date": f"2026-11-{d:02d}"} for d in range(1, 6)],
        )
        for r in range(n_responses):
            db.add_response(
                poll["id"],
                name=f"R{r}",
                email=f"r{r}@x.org",
                slot_availabilities={s["id"]: "yes" for s in poll["slots"]},
            )


def dashboard_statements(counted, n_polls: int, n_responses: int = 0) -> int:
    count, db, client = counted
    seed(db, n_polls, n_responses)
    count["n"] = 0
    response = client.get("/scheduler/", follow_redirects=True)
    assert response.status_code == 200
    return count["n"]


@pytest.mark.parametrize("n_polls", [1, 5, 10])
def test_dashboard_costs_three_statements_per_poll(counted, n_polls):
    """Measured, not modelled. This is the number that matters for the budget."""
    assert dashboard_statements(counted, n_polls) == EXPECTED_BASE + EXPECTED_PER_POLL * n_polls


def test_dashboard_fits_the_free_budget_up_to_sixteen_empty_polls(counted):
    """The last poll count that fits Workers Free's 50-subrequest budget."""
    assert dashboard_statements(counted, 16) == FREE_SUBREQUESTS
    assert dashboard_statements(counted, 17) > FREE_SUBREQUESTS


def test_dashboard_exceeds_free_budget_once_polls_have_responses(counted):
    """The limit that actually matters, and the reason the N+1 must be fixed.

    A poll with responses is the normal case, and there the dashboard only fits
    ~8 polls on the free tier. Recorded here deliberately: the assertion is that
    the budget IS exceeded, so that when someone fixes the N+1 this test fails and
    forces the documented numbers to be updated.
    """
    assert dashboard_statements(counted, 10, n_responses=3) > FREE_SUBREQUESTS


def test_paid_budget_is_not_the_binding_constraint(counted):
    assert dashboard_statements(counted, 24) <= PAID_SUBREQUESTS


def test_invites_are_fetched_once_per_poll(counted):
    """The regression this suite came from: get_invites() ran twice per poll."""
    count, db, client = counted
    seed(db, 3)
    calls = {"n": 0}
    from kairos import web

    original = web.get_invites

    def counting(*a, **k):
        calls["n"] += 1
        return original(*a, **k)

    web.get_invites = counting
    try:
        client.get("/scheduler/", follow_redirects=True)
    finally:
        web.get_invites = original
    assert calls["n"] == 3
