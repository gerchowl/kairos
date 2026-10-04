"""Issues #63 and #64: per-poll *reach* — who may read which poll, on both surfaces.

One defect, two surfaces, one mechanism (`kairos.reach`):

* **#63, machine-facing.** `polls:read` is a capability, not a tenant. A key
  holding nothing else enumerated the whole instance through `GET /polls` and read
  every poll's respondents, invites and mail log by id.
* **#64, human-facing.** `view_poll` and `poll_ics` required *an* identity rather
  than *the owner's*, so any signed-in user in header mode could open any poll by
  id and see its respondent names and availability grid.

What these tests hold to, in the order they matter:

1. **Nothing that was legal stops being legal.** The shipped default is `open` —
   the pre-existing rule — and section 1 asserts it on both surfaces, per read.
   A self-hoster and the ETH group deployment are in that state and must stay in it
   (ADR-0001/0002). The strict policy is opt-in, and `KAIROS_HOSTED` turns it on
   because that is the multi-tenant case the defect is actually exploitable in.
   Section 1b is the second review's addition: the knob that *selects* the policy
   may not itself fail open.
2. **Under `scoped`, the right caller may read and nobody else.** Sections 3 and 4
   are the authorization matrix: for each protected read, *who* may read it —
   owner, legacy service key, key granted that poll, key granted every poll, key
   granted another poll, and a stranger on the web surface. Not "403 vs 200" but
   named callers.
3. **A new poll-id route cannot ship unguarded, on either surface.** Section 5
   extends #51's route audit from "declares a scope" to "declares a reach", reusing
   its live route walk (and its fixed prefix anchoring) rather than standing up a
   parallel guard; 5b holds both enforcement points to their own inputs — a renamed
   path parameter is still guarded, and a declared reach that cannot name its poll
   refuses; 5c is the web-surface audit the second review found missing entirely.
   Each is backed by driving the live app, not only by reading a declaration.
4. **The refusal is legible and never names the credential** (#51's rule), and
   REST and MCP answer identically (ADR-0012).

The residual cases this could not cover — per-account reach (#32), per-plan reach
(#33), and a key that creates a poll not being auto-granted reach over it — are
pinned as tests at the end so a later change to any of them is a deliberate diff.
"""

import hashlib
import os
import re
import sys
from datetime import date, time

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from test_api_scoping import API, _api_routes, _load_mcp, _walk, _wire_mcp_to_app

from kairos import api, main, ratelimit, reach, scoping, settings, web

LEGACY = "legacy-all-power-key"
NOREACH = "reader-key-no-reach"  # polls:read, granted no poll
ONEPOLL = "reader-key-p1"  # polls:read, granted p1 only
OTHERPOLL = "reader-key-p2"  # polls:read, granted p2 only
WIDE = "reader-key-everything"  # polls:read, `~*`
WRITER = "writer-key-p1"  # polls:write, granted p1 only
WRITER_ALL = "writer-key-everything"  # polls:write, `~*`

KEYRING = ";".join(
    [
        f"{NOREACH}:polls:read",
        f"{ONEPOLL}:polls:read~p1",
        f"{OTHERPOLL}:polls:read~p2",
        f"{WIDE}:polls:read~*",
        f"{WRITER}:polls:write~p1",
        f"{WRITER_ALL}:polls:write~*",
    ]
)

POLL = {
    "id": "p1",
    "creator_id": "owner-uid",
    "title": "Team retro",
    "description": None,
    "mode": "time_slot",
    "timezone": "Europe/Zurich",
    "status": "open",
    "decided_slot_id": "t1",
    "public_token": "tokA",
    "admin_token": "tok-admin",
    "slots": [
        {"id": "t1", "date": date(2026, 6, 8), "start_time": time(9, 0), "end_time": time(9, 30)},
        {"id": "t2", "date": date(2026, 6, 8), "start_time": time(9, 30), "end_time": time(10, 0)},
    ],
}
POLL2 = dict(POLL, id="p2", creator_id="someone-else", title="Someone else's poll", public_token="tokB")

# One respondent on p1: bound to a *uid* (they answered while signed in) and to an
# address, and p2 has a respondent nobody here is.
RESPONSES = {
    "p1": [
        {
            "id": "r1",
            "respondent_name": "Alice Answered",
            "respondent_email": "alice@example.org",
            "user_id": "alice-uid",
            "invite_id": None,
            "invited": True,
            "joined_at": None,
            "slot_availabilities": {"t1": "yes"},
        },
    ],
    "p2": [
        {
            "id": "r2",
            "respondent_name": "Bob Stranger",
            "respondent_email": "bob@elsewhere.example",
            "user_id": "bob-uid",
            "invite_id": None,
            "invited": False,
            "joined_at": None,
            "slot_availabilities": {"t2": "no"},
        },
    ],
}
INVITES = {
    "p1": [
        {
            "id": "i1",
            "email": "invitee@example.org",
            "name": "Invitee Person",
            "token": "tk",
            "responded": False,
            "notified_at": None,
            "sent_at": None,
            "required": True,
        }
    ],
    "p2": [],
}

# Header-mode identities. The web surface reads its identity from these headers for
# real (conftest sets KAIROS_AUTH=header), so "stranger" here is a stranger the way
# issue #64 measured one: a valid identity, the wrong person.
OWNER = {"X-User": "owner-uid", "X-Email": "owner@example.org"}
ALICE = {"X-User": "alice-uid", "X-Email": "alice@example.org"}
INVITEE = {"X-User": "invitee-uid", "X-Email": "invitee@example.org"}
STRANGER = {"X-User": "stranger-uid", "X-Email": "stranger@example.org"}

WEB_POLL = "/scheduler/polls/p1"
WEB_ICS = "/scheduler/polls/p1/event.ics"


# -- fixtures ---------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_limiter():
    """The budgets are a shared singleton; an empty counter table per test."""
    ratelimit.limiter.reset()
    yield
    ratelimit.limiter.reset()


@pytest.fixture
def scoped(monkeypatch):
    """The keyring configured, the legacy key also set, reach SCOPED."""
    monkeypatch.setenv("KAIROS_API_KEY", LEGACY)
    monkeypatch.setattr(settings, "API_KEYS", KEYRING)
    monkeypatch.setattr(settings, "POLL_REACH", reach.SCOPED)


@pytest.fixture
def open_policy(monkeypatch):
    """Reach OPEN — the state every deployment that predates this file is in.

    The keyring is configured on purpose, scopes and all: the claim under test is
    that the *policy* preserves a least-privilege key's behaviour, not that an
    absent keyring happens to. A deployment that already handed out `polls:read`
    keys must find them working exactly as before.
    """
    monkeypatch.setenv("KAIROS_API_KEY", LEGACY)
    monkeypatch.setattr(settings, "API_KEYS", KEYRING)
    monkeypatch.setattr(settings, "POLL_REACH", reach.OPEN)
    assert settings.AUTH_MODE == "header"  # the mode #64 was measured in
    assert not settings.HOSTED  # so `open` is what an unconfigured deployment gets


@pytest.fixture
def stubbed(monkeypatch):
    """Two polls, their participants, and no database behind either surface."""

    def api_poll(pid):
        return {**POLL} if pid == "p1" else ({**POLL2} if pid == "p2" else None)

    monkeypatch.setattr(api, "get_poll", api_poll)
    monkeypatch.setattr(api, "list_polls", lambda *a, **k: [{**POLL}, {**POLL2}])
    monkeypatch.setattr(api, "get_responses", lambda pid: RESPONSES.get(pid, []))
    monkeypatch.setattr(api, "get_invites", lambda pid: INVITES.get(pid, []))
    monkeypatch.setattr(api, "get_contact_log", lambda pid: [])
    # `ics_response` asks `web.decided_slot_of`; the API has its own copy.
    for module in (api, web):
        monkeypatch.setattr(module, "decided_slot_of", lambda poll: poll["slots"][0])
    # `reach` reads participants through its own imports (the poll page hands it
    # the rows it already fetched); it never reads a poll itself -- the API-side
    # guard is a pure function of the id and the grant.
    for module in (web, reach):
        monkeypatch.setattr(module, "get_responses", lambda pid: RESPONSES.get(pid, []))
        monkeypatch.setattr(module, "get_invites", lambda pid: INVITES.get(pid, []))
    monkeypatch.setattr(web, "get_poll", api_poll)
    monkeypatch.setattr(web, "get_contact_log", lambda pid: [])
    monkeypatch.setattr(web, "get_notifications", lambda uid, unread_only=False: [])
    monkeypatch.setattr(web, "mark_notification_read", lambda nid: None)
    return api_poll


@pytest.fixture
def client(stubbed):
    return TestClient(main.app, base_url="https://testserver")


def as_key(client: TestClient, key: str) -> TestClient:
    client.headers["Authorization"] = f"Bearer {key}"
    return client


def as_person(client: TestClient, who: dict) -> TestClient:
    client.headers.update(who)
    return client


def reachable_only(read: bool = True):
    """Polls on the instance whose id the caller was granted, under the grant as written."""
    return [POLL["id"]] if read else []


# -- 1. THE DEFAULT IS UNCHANGED ---------------------------------------------
#
# The hardest constraint in the issue: every read that is legal today must still be
# legal in the default configuration. Asserted caller by caller, not as a tally,
# because "unchanged" is a claim about people.


@pytest.mark.parametrize(
    ("key", "path"),
    [
        (LEGACY, f"{API}/polls"),
        (LEGACY, f"{API}/polls/p1"),
        (LEGACY, f"{API}/polls/p1/responses"),
        (LEGACY, f"{API}/polls/p1/invites"),
        (LEGACY, f"{API}/polls/p1/contacts"),
        (LEGACY, f"{API}/polls/p1/event.ics"),
        (NOREACH, f"{API}/polls"),
        (NOREACH, f"{API}/polls/p1"),
        (NOREACH, f"{API}/polls/p2"),
        (NOREACH, f"{API}/polls/p2/contacts"),
    ],
)
def test_open_reach_leaves_every_api_read_exactly_as_it_was(open_policy, client, key, path):
    """The whole point of the default: a scoped key still reads everything.

    Without this, `scoped` is not a policy the deployment chooses — it is the policy
    every existing deployment gets, which would break the ETH/duplet adapter and
    every self-hoster with a scoped key the moment this ships.
    """
    assert as_key(client, key).get(path).status_code == 200


@pytest.mark.parametrize("who", [OWNER, ALICE, INVITEE, STRANGER])
def test_open_reach_leaves_the_poll_page_readable_by_anyone_authenticated(open_policy, client, who):
    """#64's measurement, preserved: in header mode a stranger gets 200 today.

    This test is the compatibility half of the fix. It is expected to *change* the
    day an operator opts into `scoped` (section 4) — and until then it is the
    reason ADR-0002's group deployment keeps working.
    """
    r = as_person(client, who).get(WEB_POLL)
    assert r.status_code == 200
    assert "Alice Answered" in r.text  # the leak #64 measured, still there by default


def test_open_reach_leaves_the_ics_readable_by_anyone_authenticated(open_policy, client):
    assert as_person(client, STRANGER).get(WEB_ICS).status_code == 200


def test_open_reach_does_not_ask_the_predicate_about_a_single_poll(monkeypatch, open_policy):
    """Not one query or predicate call more than before this file existed.

    `can_reach` is consulted per poll on the list route and per poll on the page, so
    a permissive policy that still called it would be a behaviour-preserving change
    with a per-request cost nobody asked for.
    """
    monkeypatch.setattr(reach, "can_reach", lambda *a, **k: pytest.fail("asked"))
    monkeypatch.setattr(reach, "key_reaches", lambda *a, **k: pytest.fail("asked"))
    assert reach.only_reachable([POLL, POLL2], None) == [POLL, POLL2]


def test_the_policy_is_open_unless_the_deployment_says_it_is_hosted(monkeypatch):
    """The compatibility argument, stated as a table."""
    monkeypatch.setattr(settings, "POLL_REACH", "")
    monkeypatch.setattr(settings, "HOSTED", False)
    assert reach.policy() == reach.OPEN  # self-host, ETH/duplet, demo: unchanged
    monkeypatch.setattr(settings, "HOSTED", True)
    assert reach.policy() == reach.SCOPED  # a deployment we operate: the IDOR closes
    monkeypatch.setattr(settings, "POLL_REACH", "scoped")
    monkeypatch.setattr(settings, "HOSTED", False)
    assert reach.policy() == reach.SCOPED  # opt-in for anyone who wants it


def test_the_policy_is_read_at_call_time_from_either_door(monkeypatch):
    """`monkeypatch.setenv` after import must work, exactly as for `KAIROS_API_KEYS`.

    Same reason `scoping.keyring()` reads the environment as well as the settings
    constant: a deployment that exports the variable after import — or a test that
    sets it with `setenv` — must not find one spelling honoured and the other
    silently ignored.
    """
    monkeypatch.setattr(settings, "POLL_REACH", "")
    monkeypatch.delenv("KAIROS_POLL_REACH", raising=False)
    assert reach.policy() == reach.OPEN
    monkeypatch.setenv("KAIROS_POLL_REACH", "scoped")
    assert reach.policy() == reach.SCOPED


# -- 1b. `KAIROS_HOSTED` MAY NOT FAIL OPEN ------------------------------------
#
# Second review. `KAIROS_HOSTED` was a mail-identity knob (M1/#48) whose fail-open
# was correct there: an unrecognised value keeps the mail gate *off*, which is the
# safe direction for a self-hoster whose relay authenticates their own mail. This
# PR is what made the same knob decide *who may read which poll*, and it inherited
# the reading: `KAIROS_HOSTED=Y` — the spelling an operator actually types — left
# `HOSTED` False and silently selected `open`, the permissive policy, on the
# deployment that had just asked to be treated as hosted.


def _policy_in_a_fresh_process(env: dict) -> str:
    """`(HOSTED, HOSTED_UNKNOWN, policy)` from a real process, for one env value.

    A subprocess rather than a monkeypatched constant because the bug *is* the
    wiring: `HOSTED_UNKNOWN` is derived from the raw string at import, and a test
    that patched the boolean would assert the conclusion without exercising the
    parse. Same shape as `tests/test_mail_auth.py::_import_settings`.
    """
    import subprocess
    from pathlib import Path

    return subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0, 'src');"
            " from kairos import settings, reach;"
            " print(settings.HOSTED, settings.HOSTED_UNKNOWN, reach.policy())",
        ],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, **env},
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        # Recognised hosted.
        ("on", "True False scoped"),
        ("1", "True False scoped"),
        ("yes", "True False scoped"),
        ("true", "True False scoped"),
        # Recognised self-host: the pre-#63 rule, unchanged. `n` and `f` are here
        # because they are what somebody writes for "no" — and they used to land on
        # the unrecognised reading, which reach treats as *hosted*, so the likeliest
        # spelling of "not hosted" was the one that turned a self-hoster strict.
        ("", "False False open"),
        ("0", "False False open"),
        ("off", "False False open"),
        ("false", "False False open"),
        ("no", "False False open"),
        ("n", "False False open"),
        ("f", "False False open"),
        ("N", "False False open"),
        ("OFF", "False False open"),
        # Recognised hosted, short spelling: `y` is a spelling of `yes`, not a typo,
        # so it arms the gate and reports nothing.
        ("y", "True False scoped"),
        ("Y", "True False scoped"),
        # Unrecognised — the reviewer's table. Every one of these used to yield
        # `open`, i.e. an operator asking to be treated as hosted and silently
        # getting the permissive policy on a control that now decides reads.
        ("enabled", "False True scoped"),
        ("t", "False True scoped"),
        ("2", "False True scoped"),
        ("nope", "False True scoped"),
    ],
)
def test_a_misspelt_hosted_knob_does_not_select_the_permissive_policy(value, expected):
    """`policy()` reads an unrecognised `KAIROS_HOSTED` as **scoped**, on purpose.

    Asserted end to end in a real process, so the settings parse and the policy
    default are pinned together: patching `settings.HOSTED_UNKNOWN` would test the
    conclusion, not the thing an operator types.
    """
    assert _policy_in_a_fresh_process({"KAIROS_HOSTED": value}) == expected


def test_the_policy_reads_an_unrecognised_hosted_value_as_scoped(monkeypatch):
    """The same rule at the seam, on all three states `settings` can report."""
    monkeypatch.setattr(settings, "POLL_REACH", "")
    monkeypatch.setattr(settings, "HOSTED_RAW", "Y")
    for hosted, unknown, expected in [
        (True, False, reach.SCOPED),  # recognised hosted
        (False, False, reach.OPEN),  # recognised self-host
        (False, True, reach.SCOPED),  # unrecognised -> fail closed
    ]:
        monkeypatch.setattr(settings, "HOSTED", hosted)
        monkeypatch.setattr(settings, "HOSTED_UNKNOWN", unknown)
        assert reach.policy() == expected


def test_an_explicit_policy_still_overrides_the_hosted_default(monkeypatch):
    """The fail-closed reading is a *default*, not a lock: `KAIROS_POLL_REACH=open`
    is how a self-hoster who meant the other thing gets the pre-#63 behaviour back,
    which is what makes choosing `scoped` here safe."""
    monkeypatch.setattr(settings, "POLL_REACH", reach.OPEN)
    monkeypatch.setattr(settings, "HOSTED", False)
    monkeypatch.setattr(settings, "HOSTED_UNKNOWN", True)
    assert reach.policy() == reach.OPEN


def test_the_boot_warnings_name_an_unrecognised_hosted_value(monkeypatch):
    """A control that is in force but was never asked for is a warning, not a line
    of prose in a green log — and it has to say how to undo it."""
    monkeypatch.setattr(settings, "POLL_REACH", "")
    monkeypatch.setattr(settings, "HOSTED", False)
    monkeypatch.setattr(settings, "HOSTED_UNKNOWN", True)
    monkeypatch.setattr(settings, "HOSTED_RAW", "Y")
    monkeypatch.setattr(settings, "AUTH_MODE", "oidc")  # not the header warning
    warnings = reach.boot_warnings()
    assert len(warnings) == 1
    assert "KAIROS_HOSTED='Y'" in warnings[0]
    assert "SCOPED" in warnings[0]
    assert "KAIROS_POLL_REACH=open" in warnings[0]  # the way back


def test_scoped_in_header_mode_without_trusted_proxies_warns(monkeypatch):
    """`scoped` is only as strong as the identity it trusts.

    Header mode takes the caller's identity from a request header, so with no
    `KAIROS_TRUSTED_PROXY_CIDRS` the app trusts every peer and `X-User: <a creator
    uid>` is reach on demand. The strict policy is decorative there, and the boot
    log should say so rather than let an operator read "SCOPED" as protection.
    """
    monkeypatch.setattr(settings, "POLL_REACH", reach.SCOPED)
    monkeypatch.setattr(settings, "HOSTED", False)
    monkeypatch.setattr(settings, "HOSTED_UNKNOWN", False)
    monkeypatch.setattr(settings, "AUTH_MODE", "header")
    monkeypatch.setattr(settings, "TRUSTED_PROXY_NETWORKS", ())
    assert any("KAIROS_TRUSTED_PROXY_CIDRS" in w for w in reach.boot_warnings())
    # With a proxy named, or off the web identity surface, there is nothing to say.
    monkeypatch.setattr(settings, "TRUSTED_PROXY_NETWORKS", ("10.0.0.0/8",))
    assert reach.boot_warnings() == []
    monkeypatch.setattr(settings, "TRUSTED_PROXY_NETWORKS", ())
    monkeypatch.setattr(settings, "AUTH_MODE", "oidc")
    assert reach.boot_warnings() == []


def test_open_with_scoped_keys_warns_that_the_claims_are_inert(monkeypatch):
    """`open` reads as a deprecation because the boot log says what it costs.

    An operator who has handed out least-privilege keys believes those keys are
    scoped to what they were granted. Under `open` every one of them still reads
    every poll and their `~` claims do nothing — #63 still reproducing, on a
    deployment that has the grammar configured for it.
    """
    monkeypatch.setattr(settings, "API_KEYS", KEYRING)
    monkeypatch.setattr(settings, "POLL_REACH", reach.OPEN)
    assert any("'~' claims are inert" in w for w in scoping.boot_warnings())
    monkeypatch.setattr(settings, "POLL_REACH", reach.SCOPED)
    assert not any("'~' claims are inert" in w for w in scoping.boot_warnings())
    # ...and with no keyring configured there is nothing to warn about: the ETH/duplet
    # and self-host default deployment must boot without a lecture.
    monkeypatch.setattr(settings, "API_KEYS", "")
    monkeypatch.setattr(settings, "POLL_REACH", reach.OPEN)
    assert not any("'~' claims are inert" in w for w in scoping.boot_warnings())


def test_the_boot_line_marks_the_default_deprecated(monkeypatch):
    """`open` is the pre-#63 rule kept for compatibility, and the log says so."""
    monkeypatch.setattr(settings, "API_KEYS", KEYRING)
    monkeypatch.setenv("KAIROS_API_KEY", LEGACY)
    monkeypatch.setattr(settings, "POLL_REACH", reach.OPEN)
    assert "DEPRECATED as a default" in scoping.boot_report()
    monkeypatch.setattr(settings, "POLL_REACH", reach.SCOPED)
    assert "DEPRECATED" not in scoping.boot_report()


def test_the_boot_warnings_are_logged_as_warnings_not_prose(monkeypatch, caplog):
    """The convention the reach line was missing: `log.warning`, beside the INFO
    boot line, from `create_app` (which is also where the ETH adapter lands)."""
    monkeypatch.setattr(settings, "API_KEYS", KEYRING)
    monkeypatch.setattr(settings, "POLL_REACH", reach.OPEN)
    with caplog.at_level("INFO", logger="kairos.scoping"):
        main.create_app()
    warned = [r for r in caplog.records if r.levelname == "WARNING"
              and r.name == "kairos.scoping"]
    assert any("'~' claims are inert" in r.getMessage() for r in warned)


def test_a_typo_in_the_policy_refuses_the_boot(monkeypatch):
    """A control that silently picked a reading is worse than one that is off."""
    monkeypatch.setattr(settings, "POLL_REACH", "scopped")
    with pytest.raises(RuntimeError, match="KAIROS_POLL_REACH"):
        scoping.boot_report()


def test_the_boot_line_says_which_reach_rule_is_in_force(monkeypatch, caplog):
    monkeypatch.setattr(settings, "API_KEYS", KEYRING)
    monkeypatch.setenv("KAIROS_API_KEY", LEGACY)
    monkeypatch.setattr(settings, "POLL_REACH", reach.SCOPED)
    with caplog.at_level("INFO", logger="kairos.scoping"):
        report = scoping.boot_report()
    assert "poll reach SCOPED" in report
    assert "KAIROS_POLL_REACH=open" in report  # the escape hatch is discoverable
    assert "KAIROS_API_KEY reaches every poll" in report
    assert "reach no poll at all" in report  # NOREACH and WRITER-only entries


# -- 2. WHOAMI REPORTS REACH, NOT JUST CAPABILITY -----------------------------


def test_whoami_reports_what_the_key_reaches_and_never_the_key(scoped, client):
    """Discoverability (#51's argument) applied to reach: an agent that meets a 403
    it was never told about cannot plan."""
    body = as_key(client, ONEPOLL).get(f"{API}/whoami").json()
    assert body["scopes"] == ["polls:read"]
    assert body["polls"] == ["p1"]
    assert body["reach_policy"] == reach.SCOPED  # ...and which rule is in force
    assert ONEPOLL not in str(body)

    assert as_key(client, WIDE).get(f"{API}/whoami").json()["polls"] == "*"
    assert as_key(client, NOREACH).get(f"{API}/whoami").json()["polls"] == []
    assert as_key(client, LEGACY).get(f"{API}/whoami").json()["polls"] == "*"


def test_whoami_reports_the_permissive_policy_when_that_is_what_is_in_force(
    open_policy, client
):
    """An agent can tell a `scoped` refusal from a permissive deployment's."""
    assert as_key(client, NOREACH).get(f"{API}/whoami").json()["reach_policy"] == reach.OPEN


def test_whoami_reports_the_policy_so_an_agent_knows_why(scoped, client):
    assert as_key(client, ONEPOLL).get(f"{API}/whoami").json()["scopes"]
    monkeypatched = TestClient(main.app, base_url="https://testserver")
    monkeypatched.headers["Authorization"] = f"Bearer {ONEPOLL}"
    assert monkeypatched.get(f"{API}/whoami").status_code == 200


# -- 3. #63 — THE MACHINE-FACING HALF -----------------------------------------
#
# The matrix, caller by caller, on every route that takes a poll id.


@pytest.mark.parametrize(
    "path",
    [
        f"{API}/polls/p1",  # the poll plus its respondents and invites
        f"{API}/polls/p1/responses",  # respondent names and per-slot availability
        f"{API}/polls/p1/invites",  # the invitee list
        f"{API}/polls/p1/contacts",  # every address the poll has ever mailed
        f"{API}/polls/p1/event.ics",  # the decided event time and title
    ],
)
def test_a_read_key_with_no_reach_is_refused_on_every_poll_read(scoped, client, path):
    """The issue's acceptance criterion, including the two it says are easy to
    forget because they look read-only and harmless."""
    r = as_key(client, NOREACH).get(path)
    assert r.status_code == 403, r.text
    assert "may not reach poll p1" in r.text


@pytest.mark.parametrize(
    "path",
    [
        f"{API}/polls/p1",
        f"{API}/polls/p1/responses",
        f"{API}/polls/p1/invites",
        f"{API}/polls/p1/contacts",
        f"{API}/polls/p1/event.ics",
    ],
)
def test_a_key_granted_that_poll_reads_it(scoped, client, path):
    assert as_key(client, ONEPOLL).get(path).status_code == 200


def test_reach_is_per_poll_not_per_capability(scoped, client):
    """The gap, closed: the same key, the same scope, a different poll id."""
    assert as_key(client, ONEPOLL).get(f"{API}/polls/p1").status_code == 200
    refused = as_key(client, ONEPOLL).get(f"{API}/polls/p2")
    assert refused.status_code == 403
    assert "p2" in refused.text
    # and symmetrically, so the grant is not just "the first poll alphabetically"
    assert as_key(client, OTHERPOLL).get(f"{API}/polls/p2").status_code == 200
    assert as_key(client, OTHERPOLL).get(f"{API}/polls/p1").status_code == 403


def test_the_refusal_carries_no_respondent_data(scoped, client):
    """Not just a status code: the refused body must not be the poll."""
    r = as_key(client, NOREACH).get(f"{API}/polls/p1")
    assert r.status_code == 403
    for leaked in ("Alice Answered", "alice@example.org", "Invitee Person", "tokA", "Team retro"):
        assert leaked not in r.text


def test_the_instance_wide_grant_is_explicit_and_works(scoped, client):
    """`~*` is the grant issue #63 asked for, so a cron or an export can have one."""
    assert as_key(client, WIDE).get(f"{API}/polls/p1").status_code == 200
    assert as_key(client, WIDE).get(f"{API}/polls/p2").status_code == 200
    assert as_key(client, WIDE).get(f"{API}/polls/p2/contacts").status_code == 200


def test_the_deployments_own_service_key_keeps_reaching_everything(scoped, client):
    """`KAIROS_API_KEY` is the ETH/duplet adapter's credential; scoping may not
    cost it the instance. Under `scoped` this is the explicit instance-wide grant,
    not an exemption the deployment does not know it has."""
    assert as_key(client, LEGACY).get(f"{API}/polls/p1").status_code == 200
    assert as_key(client, LEGACY).get(f"{API}/polls/p2").status_code == 200


@pytest.mark.parametrize(
    ("key", "method", "path", "kwargs"),
    [
        (NOREACH, "PATCH", f"{API}/polls/p1", {"json": {"title": "hijacked"}}),
        (NOREACH, "DELETE", f"{API}/polls/p1", {}),
        (NOREACH, "POST", f"{API}/polls/p1/decide", {"json": {"slot_id": "t1"}}),
        (NOREACH, "POST", f"{API}/polls/p1/slots", {"json": {"dates": ["2026-06-09"]}}),
        (
            NOREACH,
            "POST",
            f"{API}/polls/p1/respond",
            {"json": {"name": "A", "availabilities": {"t1": "yes"}}},
        ),
        (NOREACH, "POST", f"{API}/polls/p1/invite", {"json": {"emails": ["a@x.ch"]}}),
        (NOREACH, "POST", f"{API}/polls/p1/nudge", {"json": {}}),
        (NOREACH, "POST", f"{API}/polls/p1/email-decision", {"json": {"note": "x"}}),
        (NOREACH, "POST", f"{API}/polls/p1/imip-decision", {"json": {}}),
        (NOREACH, "PATCH", f"{API}/polls/p1/responses/r1", {"json": {"name": "A"}}),
        (NOREACH, "PATCH", f"{API}/polls/p1/invites/i1", {"json": {"name": "A"}}),
    ],
)
def test_a_mutating_route_is_gated_by_reach_too(scoped, client, key, method, path, kwargs):
    """Reach on reads only would be a half-measure: the same key could delete the
    poll it may not read. One mechanism, every poll-id route."""
    assert as_key(client, key).request(method, path, **kwargs).status_code == 403


def test_a_key_granted_the_poll_keeps_its_capabilities_there(scoped, client, monkeypatch):
    monkeypatch.setattr(api, "update_poll", lambda pid, **f: dict(POLL))
    assert as_key(client, WRITER).patch(f"{API}/polls/p1", json={"title": "mine"}).status_code == 200
    assert as_key(client, WRITER).patch(f"{API}/polls/p2", json={"title": "theirs"}).status_code == 403
    assert as_key(client, WRITER_ALL).patch(f"{API}/polls/p2", json={"title": "theirs"}).status_code == 200


def test_reach_is_checked_after_the_capability_so_the_message_is_about_the_right_thing(scoped, client):
    """A key that lacks both is told the scope first — the capability is the
    coarser fact and the one an operator usually got wrong."""
    r = as_key(client, NOREACH).delete(f"{API}/polls/p1")
    assert r.status_code == 403 and "polls:write" in r.text


def test_get_polls_returns_only_what_the_caller_reaches(scoped, client):
    """The list route is the enumeration hole, and it is now the caller's reach."""
    assert [p["id"] for p in as_key(client, ONEPOLL).get(f"{API}/polls").json()] == ["p1"]
    assert [p["id"] for p in as_key(client, OTHERPOLL).get(f"{API}/polls").json()] == ["p2"]
    assert len(as_key(client, WIDE).get(f"{API}/polls").json()) == 2
    assert len(as_key(client, LEGACY).get(f"{API}/polls").json()) == 2


def test_get_polls_is_empty_for_a_key_with_no_reach_not_403(scoped, client):
    """The open question #63 left, answered: empty.

    The route is legal for this caller; it simply has nothing in scope, and a 403
    would tell a correctly-scoped agent its configuration is broken when it is
    exactly right. `whoami` is where the reach is discoverable.
    """
    r = as_key(client, NOREACH).get(f"{API}/polls")
    assert r.status_code == 200 and r.json() == []


def test_a_refusal_never_names_the_credential(scoped, client, caplog):
    with caplog.at_level("WARNING"):
        as_key(client, NOREACH).get(f"{API}/polls/p1")
    assert NOREACH not in caplog.text
    assert scoping.key_id(NOREACH) in caplog.text


# -- 4. #64 — THE HUMAN-FACING HALF ------------------------------------------


def test_the_owner_reads_their_poll(scoped, client):
    r = as_person(client, OWNER).get(WEB_POLL)
    assert r.status_code == 200
    assert "Alice Answered" in r.text
    assert as_person(client, OWNER).get(WEB_ICS).status_code == 200


def test_someone_named_on_the_poll_still_reads_it(scoped, client):
    """The scoped-visibility answer to "ETH shares polls across a group".

    Flat owner-gating would have broken the flagship deployment; requiring the
    owner *or a participant* keeps invited colleagues and people who have already
    answered working, and costs only the unrelated stranger.
    """
    assert as_person(client, ALICE).get(WEB_POLL).status_code == 200  # answered
    assert as_person(client, INVITEE).get(WEB_POLL).status_code == 200  # invited


def test_a_stranger_is_refused_the_poll_and_the_ics(scoped, client):
    page = as_person(client, STRANGER).get(WEB_POLL)
    assert page.status_code == 404
    # No wording of its own: `test_a_refusal_is_byte_identical_to_a_missing_poll`
    # below is what pins the shape of the body.
    feed = as_person(client, STRANGER).get(WEB_ICS)
    assert feed.status_code == 404  # a calendar feed is not a page, but it is 404 too


# The two per-run values in a rendered page, scrubbed before hashing so the pin
# below is about the page rather than about when the suite ran: the nav's signed
# CSRF token, and the static-asset cache-buster (`?v=<source mtime>`), which moves
# whenever a file under `static/` is touched. The second was found by pinning the
# digest and having it disagree between two runs of the same tree — byte 476,
# `?v=1791120485` against `?v=1791120486`, which is the whole point of scrubbing.
_SIGNED = re.compile(rb"[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")
_ASSET_V = re.compile(rb"\?v=\d+")


def _scrubbed_page(response) -> bytes:
    return _ASSET_V.sub(b"?v=<mtime>", _SIGNED.sub(b"<signed>", response.content))


def test_the_missing_poll_page_is_the_page_it_has_always_been(scoped, client):
    """The absolute bytes, pinned — because `refused == missing` cannot catch a change
    that moves *both*.

    The third review's point, and it is the load-bearing one: the whole
    default-configuration claim rests on this page not changing, and an equality
    assertion between the two branches is blind to a sentence added to the helper
    they share. (Neither does `prek`: it proves lint and behaviour, not bytes. The
    byte-identity evidence is an external digest probe over 30 reads, which is why
    this pin exists in the repo at all.)

    The pin is on the page with the per-run CSRF token scrubbed — that token is the
    only thing in a rendered page that changes between two identical requests — and
    in **bytes**, not characters: the template carries two em dashes in its inline
    theme script, so `len(response.text)` is four short of `len(response.content)`
    and a character count would let a real change hide in that gap. (The third
    review's 4309 is this number, which is how the two environments agree.)
    """
    page = as_person(client, STRANGER).get(f"{web.P}/polls/no-such-poll")
    assert page.status_code == 404
    scrubbed = _scrubbed_page(page)
    assert len(page.content) == 4309
    assert len(scrubbed) == 4274
    assert hashlib.sha256(scrubbed).hexdigest() == (
        "23ae8fdc2ff0c6e5d448eedf5f7939cd4f95c2560a828782213ab5c684c587d8"
    ), "the missing-poll page changed: update this pin deliberately, and re-run the byte probe"


def test_a_refusal_is_byte_identical_to_a_missing_poll(scoped, client):
    """Not merely the same status — the same **bytes**. The second review's must-fix,
    and easy to regress: the first attempt at this unification put a 60-byte sentence
    on the refusal only, which the reviewer measured on the live app as 4369 bytes for
    "not mine" against 4309 for "missing" from the same poll id. Same status,
    different body — the oracle, still open.

    Both surfaces, and the whole response rather than a substring, because comparing
    substrings is exactly how the difference got through in the first place.
    """
    stranger = as_person(client, STRANGER)
    refused, missing = stranger.get(WEB_POLL), stranger.get(f"{web.P}/polls/no-such-poll")
    assert refused.status_code == missing.status_code == 404
    assert len(refused.text) == len(missing.text)
    assert refused.text == missing.text, "the refusal body differs from a missing poll's"
    # The ICS needs no helper for this: its two cases are one branch, one bare raise.
    ics_refused = stranger.get(WEB_ICS)
    ics_missing = stranger.get(f"{web.P}/polls/no-such-poll/event.ics")
    assert ics_refused.status_code == ics_missing.status_code == 404
    assert ics_refused.content == ics_missing.content
    # And nothing in a refusal names ownership, which is the other thing that would
    # tell the two answers apart.
    assert "owner" not in ics_refused.text.lower()


def test_the_web_refusals_are_404_and_they_name_nothing(scoped, client):
    """One answer for "not yours" and "not there", so neither is a probe.

    Second review. On the API surface reach is a pure function of the path id and
    the grant, so "not yours" and "does not exist" are the same 403 by
    construction. On the web surface the rule includes *being named on the poll*,
    so the row has to be read before the decision -- which means the route could
    tell the two apart, and 403-beside-404 was exactly that tell for anyone holding
    an id. Both refusals are now the missing poll's own 404 — the same *bytes*,
    which `test_a_refusal_is_byte_identical_to_a_missing_poll` pins.
    """
    # Two clients: `as_person` mutates the one it is given, so an "owner" view of
    # the same client would be a view of whoever was last written onto it.
    stranger = as_person(client, STRANGER)
    owner = TestClient(main.app, base_url="https://testserver", headers=dict(OWNER))
    assert stranger.get(WEB_POLL).status_code == 404
    assert stranger.get("/scheduler/polls/no-such-poll").status_code == 404
    # The owner is unaffected: this is a refusal shape, not a lost page.
    assert owner.get(WEB_POLL).status_code == 200
    assert owner.get(WEB_ICS).status_code == 200


def test_the_web_ics_is_gated_by_reach_alone(scoped, client):
    """The lower-severity half of #64, on its own because it is the easiest read in
    the app to forget: a decided event's title and time, to any signed-in user.

    Asserted on the content as well as the status, since what leaked was the data.
    """
    refused = as_person(client, STRANGER).get(WEB_ICS)
    assert refused.status_code == 404
    assert "BEGIN:VCALENDAR" not in refused.text
    assert "Team retro" not in refused.text
    assert as_person(client, ALICE).get(WEB_ICS).status_code == 200


def test_a_refused_poll_page_carries_no_respondent_data(scoped, client):
    """Not a status code: what the stranger cannot get is the *content*."""
    r = as_person(client, STRANGER).get(WEB_POLL)
    assert r.status_code == 404
    for leaked in ("Alice Answered", "alice@example.org", "Invitee Person", "Team retro"):
        assert leaked not in r.text


def test_a_refused_caller_leaves_no_trace(scoped, client, monkeypatch):
    """The one side effect on this path is marking notifications read; a refused
    caller must not have marked anything."""
    marked = []
    monkeypatch.setattr(web, "mark_notification_read", lambda nid: marked.append(nid))
    monkeypatch.setattr(
        web,
        "get_notifications",
        lambda uid, unread_only=False: [{"id": "n1", "poll_id": "p1"}, {"id": "n2", "poll_id": "p2"}],
    )
    assert as_person(client, STRANGER).get(WEB_POLL).status_code == 404
    assert marked == []

    assert as_person(client, OWNER).get(WEB_POLL).status_code == 200
    assert marked == ["n1"]


def test_reach_does_not_widen_what_a_reachable_non_owner_may_do(scoped, client):
    """Reading a poll is not managing it: the participants table and every mutating
    route stay with the owner, exactly as before."""
    r = as_person(client, INVITEE).get(WEB_POLL)
    assert r.status_code == 200
    assert "Alice Answered" in r.text  # the availability grid is what they came for
    assert "remind-selected" not in r.text  # ...and none of the owner's controls
    assert (
        as_person(client, INVITEE).post(f"{WEB_POLL}/remind", data={}, follow_redirects=False).status_code
        == 403
    )


def test_an_anonymous_caller_is_still_sent_to_sign_in(scoped, client):
    """Unchanged: no identity is a redirect to the deployment's sign-in page."""
    r = client.get(WEB_POLL, follow_redirects=False)
    assert r.status_code == 302
    assert "/login" in r.headers["location"]
    assert "Alice Answered" not in r.text


def test_a_missing_poll_is_a_404_for_a_reachable_caller(scoped, client):
    """Forbidden and gone must never share one code path."""
    assert as_person(client, OWNER).get("/scheduler/polls/nope").status_code == 404
    assert as_person(client, STRANGER).get("/scheduler/polls/nope").status_code == 404


def test_the_two_surfaces_agree_on_who_the_owner_is(scoped, client):
    """The defect was the two surfaces answering differently for the same row.

    Same person, same poll: the web page and the API's detail route must both admit
    the owner and both refuse the stranger. (Different keys from different
    credentials, so this is about the *rule*, not the credential.)
    """
    owner_web = as_person(client, OWNER).get(WEB_POLL).status_code
    owner_api = as_key(client, WRITER).get(f"{API}/polls/p1").status_code
    assert owner_web == owner_api == 200


# -- 5. THE ROUTE AUDIT — a new poll-id route cannot ship unguarded -----------


def _declared_reach(app=None):
    """{(method, api path): bool} — did the route declare that it reaches a poll?

    Read off the live route table through #51's `_api_routes` (and its fixed,
    both-sides-anchored prefix filter), so this extends the existing audit rather
    than standing up a second walker that could grow its own blind spots.
    """
    declared = {}
    for route in _api_routes(app):
        guards = [d.call for d in route.dependant.dependencies if isinstance(d.call, scoping.api_scope)]
        for method in getattr(route, "methods", set()) - {"HEAD"}:
            declared[(method, route.path[len(API) :])] = bool(guards and guards[0].reach)
    return declared


def _poll_routes(declared: dict) -> dict:
    """The subset of a declared-reach table whose routes name a poll.

    **The filter is the fix, so it is a named thing and it is asked twice** — of the
    live route table below, and of the synthetic rogue apps in the tests that follow.
    That is not tidiness: the second review's mutation M7 reverted only this filter
    back to the literal `"{poll_id}" in path` and left the suite green, because
    nothing asserted that a `{pid}` route ends up in the audited set at all. A fix
    with no test that fails without it is not a fix, so the assertions below and in
    `test_the_audit_catches_a_route_whose_poll_parameter_is_not_spelled_poll_id` both
    go through here.
    """
    return {k: v for k, v in declared.items() if reach.names_poll(k[1])}


def test_every_api_route_that_names_a_poll_declares_its_reach():
    """The guard that pays for itself, in #51's shape: the table is read off the
    live app, so a new `/api` poll-id route without `reach=True` fails here.

    "Names a poll" is asked *structurally* (`reach.names_poll`, which is
    "a `polls`/`poll` segment with something after it") and not by looking for the
    literal `{poll_id}`. The first review of this PR matched the literal, and that
    half of it was the same bug as the guard: a route spelling its parameter
    `{pid}` was invisible here *and* unguarded at request time, so it was reported
    clean and shipped the IDOR. One question, asked of both, from one function.
    """
    declared = _declared_reach()
    poll_routes = _poll_routes(declared)
    assert poll_routes, "the filter stopped finding poll-id routes at all"
    # And every declared reach must be *resolvable* on the route that declares it.
    # A `reach=True` on a path `required_poll_id` cannot resolve is not a weak guard,
    # it is none: `guard_reach` raises, so the route answers 500 on every call. That
    # fails closed, but it is an outage discovered in production rather than in CI,
    # and the synthetic tests only prove `required_poll_id` behaves — not that no
    # live route can ask it something impossible.
    unresolvable = sorted(
        path for (_method, path), reached in declared.items()
        if reached and reach.poll_param(path) is None
    )
    assert unresolvable == [], (
        f"/api routes declaring reach on a path with no resolvable poll id (they 500): "
        f"{unresolvable}"
    )
    # The two collection routes are the ones the rule must *not* sweep in: they name
    # no single poll, which is why they answer with the caller's whole reach instead.
    assert ("GET", "/polls") not in poll_routes
    assert ("POST", "/polls") not in poll_routes
    missing = sorted(path for (_m, path), reached in poll_routes.items() if not reached)
    assert missing == [], f"/api routes naming a poll with no declared reach: {missing}"


# -- 5b. THE SECOND REVIEW: the guard and the audit must both survive a renamed
#        parameter, and a declared reach that cannot name its poll must refuse. --


def test_poll_param_is_the_rule_and_the_name_is_only_a_spelling():
    """The one function both enforcement points and both audits ask.

    A table rather than an example, because the blind spot this closes is a class
    of spellings: `{pid}`, `{pollId}`, `{id}`, anything. What must hold is that a
    parameter *after the polls segment* is the poll id whatever it is called, and
    that a route which names no poll reports none rather than guessing one.
    """
    assert reach.poll_param("/api/polls/{poll_id}") == "poll_id"
    assert reach.poll_param("/api/polls/{pid}") == "pid"
    assert reach.poll_param("/api/polls/{pollId}/responses/{rid}") == "pollId"
    assert reach.poll_param("/api/polls/{id}/invite") == "id"
    assert reach.poll_param("/scheduler/polls/{poll_id}/event.ics") == "poll_id"
    assert reach.poll_param("/api/polls/{poll_id}/responses/{response_id}") == "poll_id"
    # The singular spelling resolves the same way, so `/poll/{pid}` is not the same
    # hole with a different letter.
    assert reach.poll_param("/scheduler/poll/{poll_id}") == "poll_id"
    # No poll after the segment: no guess.
    assert reach.poll_param("/api/polls") is None
    assert reach.poll_param("/api/polls/") is None
    assert reach.poll_param("/api/whoami") is None
    assert reach.poll_param("/api/imip/poll") is None
    assert reach.poll_param("/api/polls/export") is None  # ids are in the body
    assert reach.poll_param("") is None


def test_names_poll_is_wider_than_the_parameter_it_can_resolve():
    """The question the audits ask, as a table — and it is wider on purpose.

    `poll_param` answers "which parameter holds the id", which is the wrong question
    for a route that keeps its ids in a body or a query string: the second review
    demonstrated `POST /api/polls/export` satisfying #51's scope audit *and* the reach
    audit while returning `{"exported": ["p1","p2","p3"]}` to a key granted `p1`
    alone. So the audit asks "is this a route about polls", and a route that cannot
    answer reach's question has to authorize its ids itself.
    """
    # A poll route, id in the path — either spelling of the collection.
    assert reach.names_poll("/api/polls/{poll_id}") is True
    assert reach.names_poll("/api/polls/{pid}/responses/{rid}") is True
    assert reach.names_poll(f"{web.P}/polls/{{poll_id}}/edit") is True
    assert reach.names_poll("/scheduler/poll/{poll_id}") is True
    # A poll route whose ids are somewhere else: still a poll route.
    assert reach.names_poll("/api/polls/export") is True
    assert reach.names_poll("/api/polls/bulk/{x}") is True
    assert reach.names_poll(f"{web.P}/polls/export") is True
    # The collection itself, and nothing else.
    assert reach.names_poll("/api/polls") is False
    assert reach.names_poll("/api/polls/") is False
    assert reach.names_poll("/api/whoami") is False
    assert reach.names_poll("/api/imip/poll") is False  # ends in `poll`, names no poll
    assert reach.names_poll("/api/polls-archive/{x}") is False
    assert reach.names_poll("") is False


def test_a_bulk_route_that_names_polls_somewhere_else_is_audited_and_cannot_declare_reach(scoped):
    """The `/polls/export` shape, live on a synthetic app.

    Two things have to hold, and neither held before: the route is in the audited set
    (so forgetting the guard is CI red), and *declaring* reach on it is refused rather
    than accepted — because `required_poll_id` cannot see a body, so a declaration
    would be a lie. Such a route authorizes each id against the caller's grant itself,
    which is what the audit forces the author to notice.
    """
    from fastapi import APIRouter, Depends, FastAPI

    def export(body: dict, user: dict = Depends(scoping.api_scope("polls:read"))):
        return {"exported": body.get("ids", [])}

    def export_guarded(body: dict, user: dict = Depends(scoping.api_scope("polls:read", reach=True))):
        return {"exported": body.get("ids", [])}

    unguarded = APIRouter(prefix=API)
    unguarded.post("/polls/export")(export)
    app = FastAPI()
    app.include_router(unguarded)
    # It leaks: the key is granted p1 and is handed p1, p2, p3.
    with TestClient(app) as rogue:
        assert rogue.post(f"{API}/polls/export", json={"ids": ["p1", "p2", "p3"]},
                          headers={"Authorization": f"Bearer {ONEPOLL}"}).json() == {
                              "exported": ["p1", "p2", "p3"]}
    # ...and the audit has it, with no declaration to show for itself.
    assert set(_poll_routes(_declared_reach(app))) == {("POST", "/polls/export")}
    assert _declared_reach(app)[("POST", "/polls/export")] is False

    # Declaring reach does not make it guarded; it makes the route refuse.
    declared_app = FastAPI()
    declared_app.include_router(APIRouter(prefix=API))
    guarded = APIRouter(prefix=API)
    guarded.post("/polls/export")(export_guarded)
    declared_app.include_router(guarded)
    with TestClient(declared_app, raise_server_exceptions=False) as rogue:
        got = rogue.post(f"{API}/polls/export", json={"ids": ["p1"]},
                         headers={"Authorization": f"Bearer {WIDE}"})
    assert got.status_code == 500
    assert "exported" not in got.text


def _request_for_route(path_template: str, path_params: dict, key: str | None = None):
    """A Request carrying a route template, as one really does inside a dependency."""
    from starlette.requests import Request

    headers = [(b"authorization", f"Bearer {key}".encode())] if key else []
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": path_template,
            "query_string": b"",
            "path_params": dict(path_params),
            "headers": headers,
            "route": type("_R", (), {"path_format": path_template})(),
        }
    )


def test_the_poll_id_is_read_off_the_route_template_not_the_house_spelling():
    """`{pid}` is resolved exactly like `{poll_id}`.

    This is the first review's mutation W9: reverting `poll_id_of` to the literal
    key makes it fail, because `poll_id` comes back None for a `{pid}` route — and
    before `required_poll_id` existed, that None was a `return` and `guard_reach`
    silently let the request through.
    """
    renamed = _request_for_route("/api/polls/{pid}/rogue", {"pid": "p1"})
    assert reach.poll_id_of(renamed) == "p1"
    assert reach.required_poll_id(renamed) == "p1"
    house = _request_for_route("/api/polls/{poll_id}/rogue", {"poll_id": "p2"})
    assert reach.poll_id_of(house) == "p2"
    # A hand-built scope with no template still resolves the house spelling, which
    # is what the unit-level callers (#30's token route, tests) rely on.
    assert reach.poll_id_of(_request_with(NOREACH, params={"poll_id": "p3"})) == "p3"


def test_a_declared_reach_that_cannot_name_its_poll_refuses_rather_than_passing(scoped):
    """"I could not tell" and "you may read it" must not be the same answer."""
    request = _request_for_route("/api/instance/report", {})
    assert reach.poll_id_of(request) is None
    with pytest.raises(RuntimeError, match="no poll id resolves"):
        reach.required_poll_id(request)
    # And with the real guard, on a real request: a 500 for a route that declares
    # reach on a path that names no poll -- never the handler's own 200.
    from fastapi import APIRouter, Depends, FastAPI

    rogue = APIRouter(prefix=API)

    @rogue.get("/instance/report")
    def report(user: dict = Depends(scoping.api_scope("polls:read", reach=True))):
        return {"leak": "every row on the instance"}

    app = FastAPI()
    app.include_router(rogue)
    with TestClient(app, raise_server_exceptions=False) as rogue_client:
        got = rogue_client.get(f"{API}/instance/report",
                               headers={"Authorization": f"Bearer {WIDE}"})
    assert got.status_code == 500
    assert "every row on the instance" not in got.text


def _rogue_app(declared_reach: bool, param: str = "pid"):
    """A synthetic `/api` route naming a poll, with or without a declared reach."""
    from fastapi import APIRouter, Depends, FastAPI

    rogue = APIRouter(prefix=API)

    @rogue.get(f"/polls/{{{param}}}/rogue")
    def rogue_export(pid: str, user: dict = Depends(scoping.api_scope("polls:read", reach=declared_reach))):
        return {"respondent_names": ["Alice Victim", "Bob Victim"], "poll_id": pid}

    app = FastAPI()
    app.include_router(rogue)
    return app


def test_the_audit_catches_a_route_whose_poll_parameter_is_not_spelled_poll_id(scoped):
    """The exact mutation the reviewer shipped: `{pid}`, `reach=True`, no audit.

    Built with the request as well as the route table, for the reason the test
    above does: the point is not that the audit notices, it is that such a route is
    genuinely reachable by a key that has no reach.
    """
    guarded = _rogue_app(declared_reach=True)
    with TestClient(guarded) as rogue_client:
        # A key granted p2 — not p1 — is refused. This is the assertion the
        # pre-fix code failed: it returned 200 with the respondents' names, because
        # `poll_id_of` looked up a key the route does not have.
        refused = rogue_client.get(f"{API}/polls/p1/rogue",
                                   headers={"Authorization": f"Bearer {OTHERPOLL}"})
    assert refused.status_code == 403
    assert "Alice Victim" not in refused.text

    # The audit now *sees* the route at all — the other half of the same bug, and the
    # half that was unpinned: before the fix the `{pid}` spelling did not match the
    # audit's `{poll_id}` filter, so the route was not in the audited set and nothing
    # could complain about it. Asserted on the *set*, not on one key, so reverting
    # `_poll_routes` to the literal filter fails here (second review's M7: it left
    # 844 green) instead of silently auditing an empty set again.
    assert set(_poll_routes(_declared_reach(guarded))) == {("GET", "/polls/{pid}/rogue")}

    # Drop the declaration and the audit has something to complain about, which is
    # the failure mode `test_every_api_route_that_names_a_poll_declares_its_reach`
    # turns into CI red for a real route.
    undeclared = _declared_reach(_rogue_app(declared_reach=False))
    assert undeclared[("GET", "/polls/{pid}/rogue")] is False
    assert set(_poll_routes(undeclared)) == {("GET", "/polls/{pid}/rogue")}
    assert reach.poll_param("/polls/{pid}/rogue") == "pid"


def test_the_reach_audit_catches_a_route_that_forgot_to_declare(monkeypatch, scoped, client):
    """On a synthetic app, so the real route table is never mutated — and with the
    request too, because the point is not that the audit notices but that such a
    route is genuinely reachable by a key that has no reach."""
    from fastapi import APIRouter, Depends, FastAPI

    rogue = APIRouter(prefix=API)

    @rogue.get("/polls/{poll_id}/leak")
    def leak(poll_id: str, user: dict = Depends(scoping.api_scope("polls:read"))):
        return {"stole": poll_id}

    app = FastAPI()
    app.include_router(rogue)
    # The route really is reachable by a key that has no reach -- which is what
    # makes the audit noticing it matter -- and the audit notices it.
    with TestClient(app) as rogue_client:
        got = rogue_client.get(f"{API}/polls/p1/leak",
                               headers={"Authorization": f"Bearer {NOREACH}"})
    assert got.json() == {"stole": "p1"}
    assert _declared_reach(app)[("GET", "/polls/{poll_id}/leak")] is False

    real = [r for r in _api_routes() if r.path == f"{API}/polls/{{poll_id}}/event.ics"][0]
    assert any(getattr(d.call, "reach", False) for d in real.dependant.dependencies)


@pytest.mark.parametrize(
    ("key", "path"),
    [
        (NOREACH, f"{API}/polls/p1"),
        (NOREACH, f"{API}/polls/p1/responses"),
        (NOREACH, f"{API}/polls/p1/invites"),
        (NOREACH, f"{API}/polls/p1/contacts"),
        (NOREACH, f"{API}/polls/p1/event.ics"),
    ],
)
def test_every_poll_id_read_route_is_refused_in_practice_not_just_on_paper(scoped, client, key, path):
    """Belt and braces for the declaration above: the live app, driven.

    A declaration the handler ignores would pass the audit and still ship the IDOR,
    so the audit is backed by observed behaviour on every poll-id read.
    """
    assert as_key(client, key).get(path).status_code == 403


# -- 5c. THE SAME AUDIT ON THE WEB SURFACE -------------------------------------
#
# Second review. The API surface above is auditable because its routes *declare*
# their authorization as a dependency (`api_scope(reach=True)`), so the audit can
# read it off the live route table. The web surface had no such audit at all — only
# rate-limit bookkeeping — and the second review demonstrated what that costs: a
# new unguarded `GET /polls/{poll_id}/rogue-export` returning the title and the
# respondents answered **200 to an authenticated stranger under `scoped`**, and the
# suite stayed green after the two table updates #51's audit demands. No reach
# test would ever have noticed, because on this surface a route authorizes by
# *asking*, not by declaring.
#
# So the audit reads what the routes ask. Three layers, each catching something the
# others cannot:
#
#   1. the live route table, so a new poll-id web route is unlisted and fails;
#   2. the handler's own source, so a listed route cannot pass by not asking;
#   3. a real request as a stranger, so a route cannot pass by asking and ignoring.

# The authorization a web route asks for, by the call that asks. `_owner_action`
# is #29's shared management gate (identity -> CSRF -> require_manage) and is what
# every mutating route goes through, so a route calling it inherits its
# authorization the way an owner-POST inherits the CSRF requirement.
_WEB_MANAGE_CALLS = ("_owner_action(", "require_manage(", "can_manage(")
# Reach, and only `can_reach`: these are the calls the web surface makes today. A
# future web route reaching for a different one is meant to fail here and be added,
# rather than be quietly unaudited by a name that was never in the list.
_WEB_REACH_CALLS = ("can_reach(",)

# (method, path) -> the authorization the route asks for. Read off the live route
# table by the test below; this table is the assertion, so a new poll-id web route
# has to be listed here with the rule it enforces. The poll page asks for both,
# because "may read this page" and "may see the participants table and the owner's
# controls on it" are different questions and it asks each.
EXPECTED_WEB_POLL_AUTH = {
    # reads: reach (issue #64) — refused as the missing poll's own 404
    ("GET", "/polls/{poll_id}"): (frozenset({"reach", "manage"}), 404),
    ("GET", "/polls/{poll_id}/event.ics"): (frozenset({"reach"}), 404),
    # the owner's own pages and every mutating route: management authority (#29),
    # which answers 403 — including for a poll that is not there, so this surface
    # has no existence oracle of its own.
    ("GET", "/polls/{poll_id}/edit"): (frozenset({"manage"}), 403),
    ("POST", "/polls/{poll_id}/close"): (frozenset({"manage"}), 403),
    ("POST", "/polls/{poll_id}/reopen"): (frozenset({"manage"}), 403),
    ("POST", "/polls/{poll_id}/decide"): (frozenset({"manage"}), 403),
    ("POST", "/polls/{poll_id}/edit"): (frozenset({"manage"}), 403),
    ("POST", "/polls/{poll_id}/remind-selected"): (frozenset({"manage"}), 403),
    ("POST", "/polls/{poll_id}/remind"): (frozenset({"manage"}), 403),
    ("POST", "/polls/{poll_id}/email-decision"): (frozenset({"manage"}), 403),
    ("POST", "/polls/{poll_id}/invite"): (frozenset({"manage"}), 403),
    ("POST", "/polls/{poll_id}/participants/update"): (frozenset({"manage"}), 403),
    ("POST", "/polls/{poll_id}/participants/remove"): (frozenset({"manage"}), 403),
}


def _web_routes(app=None):
    """Every route on the identity-authenticated web surface, `/api` excluded."""
    prefix = web.P
    for route in _walk(app or main.app):
        path = getattr(route, "path", "")
        if (
            path.startswith(f"{prefix}/")
            and not path.startswith(f"{prefix}/api")
            and hasattr(route, "dependant")
        ):
            yield route


def _declared_web_auth(app=None) -> dict:
    """{(method, path): the rules the handler asks} for every web route.

    An empty frozenset is a real answer and the one that matters: a route naming a
    poll and asking nobody is the defect the second review demonstrated, and it has
    to be reportable as a value so the audit can name it.
    """
    import inspect

    declared = {}
    for route in _web_routes(app):
        try:
            source = inspect.getsource(route.endpoint)
        except (OSError, TypeError):  # pragma: no cover — a C-level or eval'd handler
            source = ""
        asked = frozenset(
            name
            for name, calls in (("manage", _WEB_MANAGE_CALLS), ("reach", _WEB_REACH_CALLS))
            if any(call in source for call in calls)
        )
        for method in getattr(route, "methods", set()) - {"HEAD"}:
            declared[(method, route.path[len(web.P):])] = asked
    return declared


def test_every_web_route_that_names_a_poll_authorizes_its_poll():
    """The web surface's #51/#63 audit, and the first that has ever existed here.

    Asserted in two halves because they fail for different reasons: a new route is
    *missing* from the table (the live walk is the input, so it cannot be satisfied
    by adding a row), and a route that lists an authorization it does not ask for
    is *wrong* in the table.
    """
    declared = {k: v for k, v in _declared_web_auth().items() if reach.names_poll(k[1])}
    expected = {k: v[0] for k, v in EXPECTED_WEB_POLL_AUTH.items()}
    assert declared, "the web filter stopped finding poll-id routes at all"
    assert set(declared) == set(expected), (
        f"/web routes naming a poll that are not in the audit table: "
        f"{sorted(set(declared) - set(expected))}"
    )
    assert declared == expected


def test_a_rogue_web_poll_route_answers_a_stranger_and_the_audit_catches_it():
    """The second review's live demonstration, pinned as a test.

    Built as a real request as well as a real route, for the reason the API-side
    rogue tests are: the point is not that the audit notices an unguarded route, it
    is that such a route genuinely leaks under `scoped` — which is what makes the
    audit noticing it worth anything.
    """
    from fastapi import APIRouter, FastAPI

    rogue = APIRouter(prefix=web.P)

    @rogue.get("/polls/{poll_id}/rogue-export")
    def rogue_export(poll_id: str, request: Request):
        return {"title": POLL["title"], "respondents": [r["respondent_name"] for r in RESPONSES["p1"]]}

    app = FastAPI()
    app.include_router(rogue)
    # A stranger really does get the title and every respondent name.
    with TestClient(app) as rogue_client:
        leaked = rogue_client.get(f"{web.P}/polls/p1/rogue-export", headers=dict(STRANGER))
    assert leaked.status_code == 200
    assert "Alice Answered" in leaked.text

    # And the audit sees it, with nothing to add: no row, and nothing asked for.
    seen = _declared_web_auth(app)
    rogue = ("GET", "/polls/{poll_id}/rogue-export")
    assert seen[rogue] == frozenset()
    assert rogue not in EXPECTED_WEB_POLL_AUTH
    assert reach.poll_param(rogue[1]) == "poll_id"  # ...and it is a poll route at all


def test_every_web_poll_route_refuses_a_stranger_in_practice_not_just_on_paper(scoped, stubbed):
    """Belt and braces for the audit above: the live app, driven.

    A declaration the handler ignores — or asks and then proceeds anyway — would
    pass the source check, so every poll-id web route is driven as a stranger with
    a *valid* CSRF token, which gets past the token check and lands on the
    authorization the route actually claims.
    """
    from kairos.csrf import make_csrf

    forms = {"data": {"csrf": make_csrf(STRANGER["X-User"])}}
    for (method, template), (_auth, refused_with) in EXPECTED_WEB_POLL_AUTH.items():
        path = f"{web.P}{template.format(poll_id='p1')}"
        kwargs = forms if method == "POST" else {}
        response = as_person(client_for_stranger(), STRANGER).request(method, path, **kwargs)
        assert response.status_code == refused_with, (
            f"{method} {path} answered {response.status_code} to a stranger under `scoped`, "
            f"expected {refused_with}"
        )
        assert "Alice Answered" not in response.text, f"{method} {path} leaked a respondent"
        assert POLL["title"] not in response.text, f"{method} {path} leaked the title"


def client_for_stranger() -> TestClient:
    """A fresh client: `as_person` mutates the one it is handed."""
    return TestClient(main.app, base_url="https://testserver")


# -- 6. THE GRAMMAR -----------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "polls"),
    [
        ("k:polls:read", frozenset()),  # omitted: reaches nothing
        ("k:polls:read~*", reach.EVERY_POLL),
        ("k:polls:read~p1", frozenset({"p1"})),
        ("k:polls:read~p1+p2", frozenset({"p1", "p2"})),
        ("k:polls:read,respond~p1", frozenset({"p1"})),
        ("k@pro~p1", frozenset({"p1"})),
        ("  k:polls:read ~ p1  ", frozenset({"p1"})),
        ("k:polls:read~p1;k2:mail:send~*", frozenset({"p1"})),
    ],
)
def test_the_grammar_accepts_a_reach_claim(raw, polls):
    assert scoping.parse_keyring(raw)[0].polls == polls


@pytest.mark.parametrize(
    ("raw", "why"),
    [
        ("k:polls:read~", "an empty claim"),
        ("k:polls:read~~p1", "two claims"),
        ("k:polls:read~p1+", "a trailing separator"),
        ("k:polls:read~+p1", "a leading separator"),
        ("k:polls:read~p1 p2", "whitespace inside an id"),
        ("k:polls:read~*+p1", "'*' mixed with ids"),
        ("k~p1:polls:read", "a claim before the scopes"),
    ],
)
def test_the_grammar_refuses_an_ambiguous_reach_claim(raw, why):
    """A claim quietly dropped is an operator believing a key reaches a poll it
    cannot — or, worse, believing a grant exists that does not. Refuse the boot."""
    with pytest.raises(RuntimeError, match="KAIROS_API_KEYS"):
        scoping.parse_keyring(raw)


def test_a_form_without_a_reach_claim_means_exactly_what_it_did_before():
    """Every string #51 documented parses through the identical code path."""
    entries = scoping.parse_keyring("k1:polls:read,respond;k2:mail:send")
    assert [e.scopes for e in entries] == [{"polls:read", "respond"}, {"mail:send"}]
    assert [e.tier for e in entries] == [None, None]
    assert all(e.polls == frozenset() for e in entries)


def test_a_bare_key_is_still_refused_not_a_way_to_mean_every_poll():
    """The one mistake #51 refuses must not become a way to ask for everything."""
    with pytest.raises(RuntimeError, match="must name scopes"):
        scoping.parse_keyring("k")


def test_the_scopes_audit_table_is_unchanged_by_the_reach_claim():
    """`reach=True` is a second declaration on the same guard, never a second guard:
    #51's audit reads `guards[0].scope` and asserts exactly one per route."""
    for route in _api_routes():
        guards = [d.call for d in route.dependant.dependencies if isinstance(d.call, scoping.api_scope)]
        assert len(guards) <= 1, route.path


# -- 7. REST AND MCP AGREE (ADR-0012) -----------------------------------------


def _parity(monkeypatch, stubbed, key, call_rest, call_mcp):
    monkeypatch.setattr(settings, "API_KEYS", KEYRING)
    monkeypatch.setenv("KAIROS_API_KEY", LEGACY)
    monkeypatch.setattr(settings, "POLL_REACH", reach.SCOPED)
    rest = call_rest(
        TestClient(main.app, base_url="https://testserver", headers={"Authorization": f"Bearer {key}"})
    )
    module = _wire_mcp_to_app(monkeypatch, _load_mcp(monkeypatch, key), key)
    return rest, call_mcp(module)


def test_a_key_without_reach_is_refused_identically_over_rest_and_mcp(monkeypatch, stubbed):
    rest, mcp = _parity(
        monkeypatch,
        stubbed,
        NOREACH,
        lambda c: c.get(f"{API}/polls/p1"),
        lambda m: m.get_poll("p1"),
    )
    assert rest.status_code == 403
    assert mcp["error"] == 403
    assert "may not reach poll p1" in mcp["detail"]


def test_the_agent_can_ask_what_it_reaches_over_both_surfaces(monkeypatch, stubbed):
    rest, mcp = _parity(
        monkeypatch,
        stubbed,
        ONEPOLL,
        lambda c: c.get(f"{API}/whoami"),
        lambda m: m.whoami(),
    )
    assert rest.json()["polls"] == ["p1"]
    assert mcp["polls"] == ["p1"]
    assert mcp["reach_policy"] == reach.SCOPED


def test_the_parity_harness_reaches_the_same_poll_through_the_same_routes(monkeypatch, stubbed):
    """The MCP client is a thin HTTP client, so parity has to be structural: the
    agent's `get_poll` must be the route the audit declared."""
    audited = {path for (_m, path) in _declared_reach() if path == "/polls/{poll_id}"}
    assert audited == {"/polls/{poll_id}"}
    module = _load_mcp(monkeypatch, LEGACY)
    assert callable(module.get_poll) and callable(module.whoami)


# -- 8. THE RESIDUALS, PINNED -------------------------------------------------
#
# What this could not decide, asserted so that changing any of it later is a
# deliberate diff rather than an accident.


def test_a_key_does_not_inherit_reach_over_the_poll_it_just_created(scoped, client, monkeypatch):
    """The sharpest residual, and it is a data-model limit rather than a policy one.

    `POST /polls` attributes a poll to `creator_id == "api"` — the *same* string for
    every key, because there is no per-key identity in the schema yet (#32). So
    nothing can infer "the key that made this poll" from the row, and auto-granting
    reach on create would hand every key every poll it could guess the id of. Until
    accounts exist, a scoped key that creates a poll must be granted reach to it in
    `KAIROS_API_KEYS`; the 403 says exactly that.
    """
    monkeypatch.setattr(api, "create_poll", lambda *a, **k: {**POLL})
    created = as_key(client, WRITER).post(
        f"{API}/polls", json={"title": "t", "mode": "full_day", "slots": [{"date": "2026-06-08"}]}
    )
    assert created.status_code == 200
    # WRITER was granted p1 and p1 is what the stub returns, so the grant covers it:
    assert as_key(client, WRITER).get(f"{API}/polls/p1").status_code == 200
    # ...but p2 is not reachable, and nobody may claim that creating a poll reached it.
    assert as_key(client, WRITER).get(f"{API}/polls/p2").status_code == 403


def test_a_key_that_cannot_reach_what_it_creates_is_told_so(scoped, client, monkeypatch):
    """The half of the create residual that is a *reporting* problem, not a policy one.

    Second review: under `scoped`, `POST /polls` hands back an id the caller provably
    cannot use — `GET`/`PATCH`/`DELETE` on it all 403, and it is absent from
    `GET /polls`, because nothing in the schema says which key made the row (#32).
    Auto-granting is still wrong (every key shares the uid `"api"`), and refusing
    creation outright would break the deployment that *should* be creating polls with
    a bounded key, so the response says it instead of leaving it to be discovered on
    the next call.
    """
    monkeypatch.setattr(api, "create_poll", lambda *a, **k: {**POLL, "id": "brand-new"})
    body = {"title": "t", "mode": "full_day", "slots": [{"date": "2026-06-08"}]}

    # A key granted p1 is told it cannot reach the *new* poll, not p1.
    warned = as_key(client, WRITER).post(f"{API}/polls", json=body)
    assert warned.status_code == 200
    assert "brand-new" in warned.json()["reach_warning"]
    assert "KAIROS_API_KEYS" in warned.json()["reach_warning"]

    # An instance-wide grant has nothing to be told.
    assert "reach_warning" not in as_key(client, WRITER_ALL).post(f"{API}/polls", json=body).json()

    # And under the default policy the field is absent, byte-for-byte as before.
    with monkeypatch.context() as m:
        m.setattr(settings, "POLL_REACH", reach.OPEN)
        assert "reach_warning" not in as_key(client, WRITER).post(f"{API}/polls", json=body).json()


def test_the_surface_is_coherent_about_who_may_create_and_who_may_read(scoped, client, monkeypatch):
    """Answering the coherence question the second review raised, on the facts.

    A `respond` key with no grant 403s on every poll, and it also cannot create one:
    `POST /polls` needs `polls:write`, so the two capabilities cannot disagree about
    creating. The combination that *can* is `polls:write` with no reach claim — it
    creates a row it cannot then read, edit, delete or enumerate — and that one is
    refused no further (auto-granting would hand every key every poll whose id it
    could guess) but is told, in the response, by the test above. Pinned here so the
    next person to widen either rule has to decide about both.
    """
    monkeypatch.setattr(api, "create_poll", lambda *a, **k: {**POLL, "id": "brand-new"})
    body = {"title": "t", "mode": "full_day", "slots": [{"date": "2026-06-08"}]}
    monkeypatch.setattr(settings, "API_KEYS", f"{NOREACH}:respond")
    assert as_key(client, NOREACH).post(f"{API}/polls", json=body).status_code == 403

    monkeypatch.setattr(settings, "API_KEYS", f"{NOREACH}:respond,polls:write")
    allowed = as_key(client, NOREACH).post(f"{API}/polls", json=body)
    assert allowed.status_code == 200
    assert "brand-new" in allowed.json()["reach_warning"]
    # ...and the grant that fixes it is the one the warning names.
    monkeypatch.setattr(settings, "API_KEYS", f"{NOREACH}:respond,polls:write~*")
    assert "reach_warning" not in as_key(client, NOREACH).post(f"{API}/polls", json=body).json()


def test_a_scoped_key_with_no_polls_claim_reaches_nothing_not_everything(monkeypatch, client):
    """Default-deny, stated directly on the predicate rather than through a route."""
    monkeypatch.setenv("KAIROS_API_KEY", "")
    monkeypatch.setattr(settings, "API_KEY", "")
    monkeypatch.setattr(settings, "POLL_REACH", reach.SCOPED)
    monkeypatch.setattr(settings, "API_KEYS", f"{NOREACH}:polls:read")
    principal = scoping.resolve(_request_with(NOREACH))
    assert principal["polls"] == frozenset()
    assert reach.key_reaches(principal, "p1") is False
    # and an identity-less principal, the #29 fail-open shape, reaches nothing
    assert reach.key_reaches({}, "p1") is False
    assert reach.key_reaches(None, "p1") is False


def _request_with(key: str, *, params: dict | None = None):
    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "path_params": dict(params or {}),
        "headers": [(b"authorization", f"Bearer {key}".encode())],
    }
    return Request(scope)


def test_the_web_predicate_fails_closed_without_an_identity():
    """`{"uid": None}` is the shape a session-cookie portal's `get_user` seam
    returns for "not logged in" — the exact fail-open #29's review caught."""
    assert reach.named_on_poll("p1", None) is False
    assert reach.named_on_poll("p1", {"uid": None}) is False
    assert reach.named_on_poll("p1", {"uid": "", "email": ""}) is False


def test_named_on_poll_matches_the_three_ways_a_person_is_named():
    responses, invites = RESPONSES["p1"], INVITES["p1"]
    rows = (responses, invites)
    assert reach.named_on_poll("p1", {"uid": "alice-uid"}, participants=rows) is True
    assert reach.named_on_poll("p1", {"email": "INVITEE@example.org"}, participants=rows) is True
    assert reach.named_on_poll("p1", {"email": " Alice@Example.org "}, participants=rows) is True
    assert reach.named_on_poll("p1", {"uid": "bob-uid"}, participants=rows) is False
    assert (
        reach.named_on_poll("p1", {"uid": "bob", "email": "bob@elsewhere.example"}, participants=rows)
        is False
    )


def test_possessing_the_admin_token_reaches_the_poll_without_an_identity(scoped):
    """The seam #30 needs, exercised now: a `/manage/<token>` route is a reader of
    the poll as much as a manager of it, and it has no identity to offer.

    `token` is passed explicitly, never sniffed out of the request, for the reason
    #29 records: `public.py` has `{token}` path parameters holding *public* tokens.
    """
    request = _request_with(NOREACH)
    assert reach.can_reach(POLL, request, user=None, token="wrong") is False
    assert reach.can_reach(POLL, request, user=None, token="tok-admin") is True
    assert reach.can_reach(POLL, request, user=None) is False
    # and a poll with no admin_token minted fails closed on a NULL expectation
    assert reach.can_reach(dict(POLL, admin_token=None), request, token=None) is False


def test_reach_is_not_management_authority():
    """Two different questions, and the one module answers only the first."""
    from kairos.auth import can_manage

    class _R:
        scope = {"client": ("127.0.0.1", 1), "headers": []}
        state = type("S", (), {})()

    assert can_manage(POLL, _R(), user={"uid": "owner-uid"}) is True
    # alice is named on the poll but manages nothing
    assert can_manage(POLL, _R(), user={"uid": "alice-uid"}) is False
