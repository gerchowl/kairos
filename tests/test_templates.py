"""Render smoke tests — every template with realistic contexts, no DB needed.

Run from repo root:
    PYTHONPATH=libs:apps/scheduler/src uv run --project apps/scheduler --with pytest pytest apps/scheduler/tests/
"""

from datetime import date, time

import pytest

from kairos.helpers import (
    env,
    expected_counts,
    fullday_grid_data,
    fullday_weeks,
    slot_counts,
    timeslot_payload,
)

USER = {"uid": "testuser", "name": "Test User", "email": "test@ethz.ch"}

FULLDAY_SLOTS = [
    {"id": "s1", "date": date(2026, 6, 8), "start_time": None, "end_time": None},
    {"id": "s2", "date": date(2026, 6, 9), "start_time": None, "end_time": None},
    {"id": "s3", "date": date(2026, 6, 15), "start_time": None, "end_time": None},
]

TS_SLOTS = [
    {"id": "t1", "date": date(2026, 6, 8), "start_time": time(9, 0), "end_time": time(9, 30)},
    {"id": "t2", "date": date(2026, 6, 8), "start_time": time(9, 30), "end_time": time(10, 0)},
    {"id": "t3", "date": date(2026, 6, 10), "start_time": time(9, 0), "end_time": time(9, 30)},
]

RESPONSES = [
    {"id": "r1", "respondent_name": "Alice <script>", "slot_availabilities": {"s1": "yes", "s2": "maybe", "t1": "yes"}},
    {"id": "r2", "respondent_name": "Bob", "slot_availabilities": {"s1": "no", "s3": "yes", "t2": "maybe"}},
]

INVITES = [
    {"id": "i1", "email": "alice@example.com", "responded": True},
    {"id": "i2", "email": "bob@example.com", "responded": False},
]


def _poll(mode, slots, status="open", description="A <b>test</b> poll"):
    return {
        "id": "p1", "creator_id": "testuser", "title": "Team retreat <script>",
        "description": description, "mode": mode, "timezone": "Europe/Zurich",
        "status": status, "decided_slot_id": slots[0]["id"] if status == "decided" else None,
        "public_token": "tok123", "slots": slots,
    }


def test_dashboard():
    html = env.get_template("dashboard.html").render(
        user=USER, title="Kairos", notif_count=2, csrf_token="tok",
        notifs=[{"id": "n1", "poll_id": "p1", "message": "New response from <b>Eve</b>"}],
        polls=[{"id": "p1", "title": "Retreat <script>", "status": "open",
                "mode": "full_day", "response_count": 3, "invite_count": 2,
                "created_at": "2026-06-01 10:00:00", "public_token": "tok123",
                "conv": {"state": "ready"}}])
    assert "Retreat" in html
    assert "Retreat <script>" not in html  # user data escaped
    assert "Retreat &lt;script&gt;" in html
    assert "text-success" in html                       # convergence dot
    assert 'data-link="/scheduler/p/tok123"' in html    # copy share link
    assert "Mark all read" in html                      # notif dropdown
    assert 'id="poll-search"' in html                   # search box
    assert "New poll" in html                           # dimmed + card
    assert "hero" not in html                           # hero removed


def test_dashboard_empty():
    html = env.get_template("dashboard.html").render(
        user=USER, title="Kairos", notif_count=0, notifs=[], csrf_token="tok", polls=[])
    assert "No polls yet" in html


def test_new_poll():
    html = env.get_template("new_poll.html").render(
        user=USER, title="New Poll", notif_count=0, notifs=[], csrf_token="tok",
        timezones=["Europe/Zurich", "America/New_York"])
    assert 'id="cal-grid"' in html
    assert 'name="csrf"' in html
    assert "cal-select.js" in html
    assert "Slot length" in html
    assert '<option value="America/New_York">' in html


def test_poll_fullday_owner():
    poll = _poll("full_day", FULLDAY_SLOTS)
    total, pending_n = expected_counts(INVITES, RESPONSES)
    html = env.get_template("poll.html").render(
        user=USER, title=poll["title"], poll=poll, responses=RESPONSES,
        invites=INVITES, total=total, pending_n=pending_n,
        share_url="https://x/scheduler/p/tok123", decided_label=None,
        notif_count=0, notifs=[], is_owner=True, msg_text="Poll closed.",
        csrf_token="tok", is_ts=False, gaps=[1],
        conv={"state": "partial", "slots": 1, "best_slot_id": "s3",
              "excluded": ["Bob"], "blockers": [], "responses": 2,
              "pending_required": 0, "all_optional": False, "stale_n": 1},
        counts=slot_counts(FULLDAY_SLOTS, RESPONSES),
        participants=[
            {"email": "alice@example.com", "invite_id": "i1", "required": True,
             "invited": True, "name": "Alice", "state": "current",
             "responded_at": None, "last_contact": {"kind": "invite", "sent_at": "2026-06-04 18:00:00"},
             "contacts": [{"kind": "invite", "sent_at": "2026-06-04 18:00:00"}]},
            {"email": "bob@example.com", "invite_id": "i2", "required": False,
             "invited": True, "name": None, "state": "pending",
             "responded_at": None, "last_contact": None, "contacts": []},
        ],
        part_payload={"open": True, "csrf": "tok", "update_url": "/u", "remove_url": "/r",
                      "rows": [{"kind": "invite", "ref": "i1", "name": "Alice",
                                "email": "alice@example.com", "optional": False,
                                "state": "current", "joined": "✉ 04 Jun 2026", "via_link": False,
                                "last_contact": "invite · 2026-06-04 18:00",
                                "contacts_n": 1, "trail": ""}]})
    assert "sched-bar" in html
    assert "Close" in html              # ghost close in the strip
    assert "alice@example.com" in html   # row lands in the part-data payload
    assert 'id="part-data"' in html and "tabulator.min.js" in html
    assert "&lt;script&gt;" in html  # respondent name escaped
    assert "invite \\u00b7 2026-06-04 18:00" in html  # contact trail in JSON payload
    assert "part-smart" in html  # smart reminders button (fetch-wired)
    assert "Email selected" in html
    assert 'id="part-send"' in html   # email-selected button (fetch-wired)


def test_poll_timeslot_decided():
    poll = _poll("time_slot", TS_SLOTS, status="decided")
    html = env.get_template("poll.html").render(
        user=USER, title=poll["title"], poll=poll, responses=RESPONSES,
        invites=[], total=2, pending_n=0, share_url="https://x/p/t",
        decided_label="2026-06-08 09:00–09:30", notif_count=0, notifs=[], is_owner=True,
        recipients_n=2, msg_text=None, csrf_token="tok", is_ts=True,
        ts_payload=timeslot_payload(TS_SLOTS, RESPONSES, 2))
    assert "ts-grid-data" in html
    assert "Final Date" in html
    assert "/event.ics" in html
    assert "Email everyone (2)" in html
    assert "Close Poll" not in html  # not open


def test_public_fullday_open():
    poll = _poll("full_day", FULLDAY_SLOTS)
    weeks = fullday_weeks(FULLDAY_SLOTS)
    html = env.get_template("public_poll.html").render(
        title=poll["title"], poll=poll, responses=RESPONSES, total=2,
        pending_n=0, is_open=True, action="/scheduler/p/tok123",
        prefill_email="invited@example.com", prefill_name="Invited Person",
        msg="", decided_label=None, gaps=[1],
        is_ts=False, counts=slot_counts(FULLDAY_SLOTS, RESPONSES),
        weeks=weeks, fullday_payload={"grid": fullday_grid_data(weeks), "saved": {"s1": "yes"}})
    assert "noindex" in html
    assert "fullday-cal-data" in html
    assert 'data-slot="s1"' in html
    assert 'value="invited@example.com"' in html
    assert 'value="Invited Person"' in html
    assert 'id="save-btn"' in html
    assert "Logout" not in html  # no user -> no account menu


def test_public_timeslot_closed():
    poll = _poll("time_slot", TS_SLOTS, status="closed")
    html = env.get_template("public_poll.html").render(
        title=poll["title"], poll=poll, responses=RESPONSES, total=2,
        pending_n=0, is_open=False, action="/x", prefill_email="",
        prefill_name="", msg="", decided_label=None, is_ts=True,
        ts_payload=timeslot_payload(TS_SLOTS, RESPONSES, 2, interactive=False))
    assert "ts-grid-data" in html
    assert "Save Response" not in html  # closed -> no form
    assert "badge-error" in html  # closed badge


def test_message():
    html = env.get_template("message.html").render(
        title="Not Found", heading="Poll not found", detail="Invalid link.",
        error=True, noindex=True, back="/scheduler/", user=None)
    assert "Poll not found" in html
    assert "noindex" in html


def test_email_invite():
    html = env.get_template("email/invite.html").render(
        sender_name="Mallory <script>", poll_title="Poll & co",
        invite_url="https://x/scheduler/p/i/tok")
    assert "&lt;script&gt;" in html  # autoescape on
    assert "Open the poll" in html
    assert "Subscribe in my calendar" not in html  # no subscribe section without a URL


def test_email_invite_subscribe_section():
    html = env.get_template("email/invite.html").render(
        sender_name="Al", poll_title="P",
        invite_url="https://x/scheduler/p/i/tok",
        subscribe_url="webcal://x/scheduler/p/i/tok/feed.ics")
    assert "Subscribe in my calendar" in html
    assert "webcal://x/scheduler/p/i/tok/feed.ics" in html
    assert "catches up later" in html  # honest refresh-delay caveat


def test_timeslot_payload_shape():
    payload = timeslot_payload(TS_SLOTS, RESPONSES, 2, interactive=True)
    assert payload["interactive"] is True
    assert len(payload["dates"]) == 2
    assert payload["times"] == ["09:00", "09:30"]
    assert {g["id"] for g in payload["grid"]} == {"t1", "t2", "t3"}
    assert payload["gaps"] == [0]  # Jun 8 -> Jun 10 gap
    hm = payload["heatmap"]
    assert hm["t1"]["count"] == "1"
    assert hm["t2"]["count"] == "?1"
    assert "Alice" in hm["t1"]["tip"]
    # theme-aware: Python sends intensity, grid.js derives colors from CSS vars
    assert hm["t1"]["alpha"] == 0.5  # 1 yes / 2 expected
    assert hm["t2"]["alpha"] == pytest.approx(0.15)  # 1 maybe * 0.3 / 2
    assert hm["t3"]["alpha"] == 0.0


def test_fullday_weeks_alignment():
    weeks = fullday_weeks(FULLDAY_SLOTS)
    assert len(weeks) == 2  # Jun 8-14 and Jun 15-21
    assert all(len(w["days"]) == 7 for w in weeks)
    grid = fullday_grid_data(weeks)
    assert {g["id"] for g in grid} == {"s1", "s2", "s3"}


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))



@pytest.mark.parametrize("conv,frags", [
    ({"state": "collecting", "responses": 0, "blockers": [], "stale_n": 0},
     ["Collecting replies", "share the link"]),
    ({"state": "collecting", "responses": 2, "blockers": ["alice", "bob"], "stale_n": 0},
     ["waiting on alice, bob"]),
    ({"state": "ready", "slots": 1, "best_slot_id": "s1", "responses": 2,
      "blockers": [], "stale_n": 0},
     ["works for everyone", "Mon 08 Jun 2026", "Decide", "alert-success"]),
    ({"state": "partial", "slots": 1, "best_slot_id": "s3", "excluded": ["Bob"],
      "responses": 2, "blockers": [], "stale_n": 2},
     ["works for all required", "excludes Bob", "2 responses outdated", "alert-warning"]),
    ({"state": "blocked", "responses": 2, "blockers": [], "stale_n": 0},
     ["No date fits", "Close poll", "Edit dates", "alert-error"]),
    ({"state": "blocked", "no_dates": True, "responses": 0, "blockers": [], "stale_n": 0},
     ["No dates in this poll yet", "Add dates"]),
    ({"state": "closed"}, ["Closed without a final date", "Reopen"]),
    ({"state": "decided"}, ["decided date was removed", "Reopen"]),
])
def test_convergence_strip_states(conv, frags):
    tpl = env.from_string(
        '{% from "_macros.html" import convergence_strip %}'
        '{{ convergence_strip(poll, conv, "tok") }}')
    poll = {"id": "p1", "status": "open", "mode": "full_day", "slots": FULLDAY_SLOTS}
    html = tpl.render(poll=poll, conv=conv)
    for frag in frags:
        assert frag in html, f"{conv['state']}: missing {frag!r}"


def test_convergence_strip_decided_with_label_is_empty():
    tpl = env.from_string(
        '{% from "_macros.html" import convergence_strip %}'
        '{{ convergence_strip(poll, conv, "tok", decided_label="Mon 08") }}')
    html = tpl.render(poll={"id": "p1", "slots": [], "mode": "full_day"},
                      conv={"state": "decided"})
    assert html.strip() == ""  # the Final Date card owns this state
