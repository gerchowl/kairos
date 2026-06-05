"""Unit tests for the convergence engine — the single source of truth
behind the dashboard dot and the poll page status strip."""

from kairos.helpers import convergence

P = {"id": "p1", "status": "open",
     "slots": [{"id": "s1", "date": "2026-07-01"}, {"id": "s2", "date": "2026-07-02"}]}


def resp(rid, avail, name=None, email=None, required=True, invite=None):
    return {"id": rid, "respondent_name": name or rid, "respondent_email": email,
            "required": required, "invite_id": invite, "slot_availabilities": avail}


def inv(iid, email, required=True, name=None):
    return {"id": iid, "email": email, "required": required, "name": name}


def test_all_optional_never_partial():
    """works_for([]) used to be vacuously true -> nonsense 'partial'."""
    rs = [resp("a", {"s1": "yes", "s2": "no"}, required=False),
          resp("b", {"s1": "no", "s2": "yes"}, required=False)]
    c = convergence(P, rs, [])
    assert c["state"] == "blocked" and c["all_optional"]


def test_all_optional_ready_via_full_consensus():
    rs = [resp("a", {"s1": "yes"}, required=False),
          resp("b", {"s1": "yes"}, required=False)]
    c = convergence(P, rs, [])
    assert c["state"] == "ready" and c["best_slot_id"] == "s1"


def test_best_slot_most_yes_then_earliest():
    poll = {**P, "slots": P["slots"] + [{"id": "s3", "date": "2026-07-03"}]}
    rs = [resp("a", {"s1": "yes", "s2": "yes", "s3": "yes"}),
          resp("b", {"s1": "no", "s2": "yes", "s3": "yes"}, required=False)]
    c = convergence(poll, rs, [])
    # s2 and s3 tie on yes-count (2) and beat s1; earliest (s2) wins
    assert c["state"] == "ready" and c["best_slot_id"] == "s2"


def test_partial_names_the_excluded():
    rs = [resp("req", {"s1": "yes"}, name="Rita"),
          resp("opt", {"s1": "no"}, name="Otto", required=False)]
    c = convergence(P, rs, [])
    assert c["state"] == "partial" and c["excluded"] == ["Otto"]


def test_collecting_names_blockers():
    c = convergence(P, [], [inv("i1", "a@x.org", name="Ada"), inv("i2", "b@x.org")])
    assert c["state"] == "collecting" and c["blockers"] == ["Ada", "b@x.org"]


def test_no_dates_is_blocked_with_reason():
    c = convergence({**P, "slots": []}, [], [])
    assert c["state"] == "blocked" and c["no_dates"]


def test_dashboard_rows_without_slots_still_work():
    row = {"id": "p1", "status": "open"}  # list_polls rows carry no slots
    c = convergence(row, [resp("a", {"s1": "yes"})], [])
    assert c["state"] == "ready"


def test_non_open_passthrough():
    assert convergence({**P, "status": "closed"}, [], [])["state"] == "closed"


def test_best_slot_most_yes_beats_earliest():
    rs = [resp("a", {"s1": "yes", "s2": "yes"}),
          resp("b", {"s1": "no", "s2": "yes"}, required=False)]
    c = convergence(P, rs, [])
    assert c["state"] == "ready" and c["best_slot_id"] == "s2"  # 2 yes > 1 yes


def test_walkin_required_blocks_but_optional_does_not():
    rs = [resp("a", {"s1": "yes"}),
          resp("b", {"s1": "no"}, required=True)]   # required walk-in says no
    assert convergence(P, rs, [])["state"] == "blocked"
    rs[1]["required"] = False
    assert convergence(P, rs, [])["state"] == "partial"


def test_required_invitee_no_everywhere_blocks():
    invites = [inv("i1", "a@x.org"), inv("i2", "b@x.org")]
    rs = [resp("ra", {"s1": "yes", "s2": "yes"}, email="a@x.org", invite="i1"),
          resp("rb", {"s1": "no", "s2": "no"}, email="b@x.org", invite="i2")]
    assert convergence(P, rs, invites)["state"] == "blocked"
