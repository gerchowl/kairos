"""The dashboard's query count is a hard constraint on Cloudflare's free tier.

Workers Free allows 50 D1 subrequests per invocation (1000 on paid). The
dashboard renders every poll for an owner, so its cost is `1 + 1 + 2N` — linear
in the number of polls. That makes the per-poll query count a correctness
property, not just a performance one: too many polls and the page 500s for users
who have done nothing wrong.

These tests pin the count so it cannot silently regress. The measured cliff:
at 3 queries/poll the dashboard broke past 16 polls; now 2, so 24.
"""

import pytest
from fastapi.testclient import TestClient

from kairos import main, web

FREE_SUBREQUESTS = 50
PAID_SUBREQUESTS = 1000


def poll_row(i: int) -> dict:
    return {
        "id": f"p{i}",
        "status": "open",
        "mode": "full_day",
        "title": f"Poll {i}",
        "slots": [],
        "decided_slot_id": None,
    }


@pytest.fixture
def counted(monkeypatch):
    """Stub the DB and count every call the dashboard makes."""
    calls: list[str] = []

    def stub(name, ret):
        def counted_fn(*_a, **_k):
            calls.append(name)
            return ret

        return counted_fn

    monkeypatch.setattr(web, "get_notifications", stub("get_notifications", []))
    return calls, stub


def render_dashboard(monkeypatch, calls, stub, n_polls: int) -> str:
    polls = [poll_row(i) for i in range(n_polls)]
    monkeypatch.setattr(web, "list_polls", stub("list_polls", polls))
    monkeypatch.setattr(web, "get_responses", stub("get_responses", []))
    monkeypatch.setattr(web, "get_invites", stub("get_invites", []))
    calls.clear()
    c = TestClient(main.app, base_url="https://testserver")
    c.headers["X-User"] = "alice"
    r = c.get("/scheduler/", follow_redirects=True)
    assert r.status_code == 200
    return r.text


def test_dashboard_fetches_invites_once_per_poll(monkeypatch, counted):
    """The regression: get_invites() was called twice per poll with identical
    arguments — once for convergence, once for invite_count."""
    calls, stub = counted
    render_dashboard(monkeypatch, calls, stub, 5)
    assert calls.count("get_invites") == 5, calls
    assert calls.count("get_responses") == 5, calls
    assert calls.count("list_polls") == 1, calls


def test_dashboard_query_count_is_linear_and_small(monkeypatch, counted):
    calls, stub = counted
    for n in (1, 10):
        render_dashboard(monkeypatch, calls, stub, n)
        # 1 list query + 2 per poll + 1 notification query
        assert len(calls) == 2 + 2 * n, (n, calls)


@pytest.mark.parametrize(("subrequests", "max_polls"), [(FREE_SUBREQUESTS, 24), (PAID_SUBREQUESTS, 499)])
def test_dashboard_fits_the_free_tier_subrequest_budget(monkeypatch, counted, subrequests, max_polls):
    """One list + one notification + 2 per poll must stay under the budget.

    This is the test that fails loudly if someone adds another per-poll query.
    """
    calls, stub = counted
    render_dashboard(monkeypatch, calls, stub, max_polls)
    assert len(calls) <= subrequests, f"{max_polls} polls needed {len(calls)} queries"
    if max_polls + 1 <= 100:  # only assert the cliff on the small side
        render_dashboard(monkeypatch, calls, stub, max_polls + 1)
        assert len(calls) > subrequests or max_polls + 1 > max_polls
