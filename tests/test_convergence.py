"""Convergence engine unit tests — the poll-list status light."""

from kairos.helpers import convergence

OPEN = {"status": "open"}


def _resp(rid, avails, email=None, invite_id=None):
    return {"id": rid, "invite_id": invite_id, "respondent_email": email,
            "respondent_name": rid, "slot_availabilities": avails}


def test_non_open_passthrough():
    assert convergence({"status": "decided"}, [], [])["state"] == "decided"
    assert convergence({"status": "closed"}, [], [])["state"] == "closed"


def test_no_responses_is_collecting():
    assert convergence(OPEN, [], [])["state"] == "collecting"


def test_pending_required_invitee_is_collecting():
    invites = [{"id": "i1", "email": "a@x", "required": True}]
    resp = [_resp("r1", {"s1": "yes"}, email="other@x")]
    assert convergence(OPEN, resp, invites)["state"] == "collecting"


def test_open_link_poll_common_slot_is_ready():
    resps = [_resp("r1", {"s1": "yes", "s2": "no"}),
             _resp("r2", {"s1": "yes", "s2": "yes"})]
    c = convergence(OPEN, resps, [])
    assert c["state"] == "ready" and c["slots"] == 1


def test_open_link_poll_no_common_slot_is_blocked():
    resps = [_resp("r1", {"s1": "yes", "s2": "no"}),
             _resp("r2", {"s1": "no", "s2": "yes"})]
    assert convergence(OPEN, resps, [])["state"] == "blocked"


def test_required_fit_optional_missing_is_partial():
    invites = [{"id": "i1", "email": "req@x", "required": True},
               {"id": "i2", "email": "opt@x", "required": False}]
    resps = [_resp("r1", {"s1": "yes", "s2": "yes"}, invite_id="i1"),
             _resp("r2", {"s1": "no", "s2": "no"}, invite_id="i2")]
    c = convergence(OPEN, resps, invites)
    assert c["state"] == "partial" and c["slots"] == 2


def test_everyone_fits_is_ready_with_walkin():
    invites = [{"id": "i1", "email": "req@x", "required": True}]
    resps = [_resp("r1", {"s1": "yes"}, invite_id="i1"),
             _resp("r2", {"s1": "yes"}, email="walkin@y")]
    assert convergence(OPEN, resps, invites)["state"] == "ready"


def test_required_blocked_is_blocked():
    invites = [{"id": "i1", "email": "a@x", "required": True},
               {"id": "i2", "email": "b@x", "required": True}]
    resps = [_resp("r1", {"s1": "yes", "s2": "no"}, invite_id="i1"),
             _resp("r2", {"s1": "no", "s2": "yes"}, invite_id="i2")]
    assert convergence(OPEN, resps, invites)["state"] == "blocked"


def test_maybe_does_not_count_as_yes():
    resps = [_resp("r1", {"s1": "maybe"}), _resp("r2", {"s1": "yes"})]
    assert convergence(OPEN, resps, [])["state"] == "blocked"
