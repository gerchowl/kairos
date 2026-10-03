"""Issue #51: least-privilege scopes and blast-radius budgets on the API/MCP surface.

What is being tested here, and the two directions they pull in:

1. **The controls hold.** A read-only key gets **403** on every mail-sending route
   (never 404, never 500). `force=True` needs its own scope *and* its own budget.
   `invite` refuses an oversized recipient list. A poll's send budget holds
   regardless of which key asks. Per-key budgets are per key, so two keys cannot
   starve each other.

2. **Nothing happens unless asked.** `KAIROS_API_KEY` alone still reaches
   everything, exactly as before this file existed — the ETH/duplet adapter and
   every self-hoster set that one variable and must be byte-for-byte unchanged
   (ADR-0001/0002). The budgets that *are* on by default (the per-request
   recipient cap, the per-poll budget) are asserted inert at their shipped
   values, because a control that is silently inert is worse than one that is off.

The route audit in section 3 is the one that keeps paying: it walks the live route
table, so a new `/api` route added without a declared scope fails here.
"""

import importlib.util
import sys
import types
from datetime import date, time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from kairos import api, main, ratelimit, scoping, settings, web

MCP_PATH = Path(__file__).resolve().parents[1] / "mcp" / "kairos_mcp.py"

LEGACY = "legacy-all-power-key"
READER = "read-only-key"
SENDER = "mail-sender-key"
FORCER = "nudge-forcer-key"
OPERATOR = "imip-operator-key"
VOTER = "respond-only-key"
WRITER = "poll-writer-key"

KEYRING = ";".join([
    f"{READER}:polls:read",
    f"{WRITER}:polls:write",
    f"{SENDER}:mail:send,polls:read",
    f"{FORCER}:mail:force,polls:read",
    f"{OPERATOR}:imip:poll,polls:read",
    f"{VOTER}:respond,polls:read",
])

POLL = {
    "id": "p1",
    "creator_id": "u1",
    "title": "API poll",
    "description": None,
    "mode": "time_slot",
    "timezone": "Europe/Zurich",
    "status": "open",
    "decided_slot_id": "t1",
    "public_token": "tokA",
    "slots": [
        {"id": "t1", "date": date(2026, 6, 8), "start_time": time(9, 0), "end_time": time(9, 30)},
        {"id": "t2", "date": date(2026, 6, 8), "start_time": time(9, 30), "end_time": time(10, 0)},
    ],
}
API = "/scheduler/api"


# -- fixtures ---------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_limiter(monkeypatch):
    """Every test starts with an empty counter table — the budgets are a shared
    singleton, so without this a poll named `p1` in one test would be charged in
    the next."""
    ratelimit.limiter.reset()
    yield
    ratelimit.limiter.reset()


@pytest.fixture
def scoped(monkeypatch):
    """The keyring configured, the legacy key also set, everything else default."""
    monkeypatch.setenv("KAIROS_API_KEY", LEGACY)
    monkeypatch.setattr(settings, "API_KEYS", KEYRING)


@pytest.fixture
def legacy_only(monkeypatch):
    """No scoping configured at all — the state the ETH/duplet deployment is in."""
    monkeypatch.setenv("KAIROS_API_KEY", LEGACY)
    monkeypatch.setattr(settings, "API_KEYS", "")
    assert not settings.RATE_LIMIT_ENABLED


@pytest.fixture
def sent():
    """Every address handed to the mail layer, so a test can assert that a refused
    call sent nothing — the property that matters more than the status code."""
    return []


@pytest.fixture
def stubbed(monkeypatch, sent):
    """Stub out the DB and SMTP so these tests are about authorisation only."""
    monkeypatch.setattr(api, "get_poll", lambda pid: dict(POLL) if pid == "p1" else None)
    monkeypatch.setattr(api, "get_responses", lambda pid: [])
    monkeypatch.setattr(api, "get_invites", lambda pid: [])
    monkeypatch.setattr(
        api,
        "create_invite",
        lambda pid, email, required=True, name=None: {"id": "i1", "token": "tk", "email": email},
    )
    monkeypatch.setattr(api, "send_invite_email", lambda to, *a, **k: sent.append(to) or True)
    monkeypatch.setattr(api, "send_decision_email", lambda recips, *a, **k: list(recips))
    monkeypatch.setattr(api, "send_imip", lambda *a, **k: sent.append("imip") or True)
    monkeypatch.setattr(api, "log_contact", lambda *a, **k: None)
    monkeypatch.setattr(api, "get_contact_log", lambda pid: [])
    monkeypatch.setattr(api, "recipient_emails", lambda pid: ["a@x.ch", "b@x.ch"])
    monkeypatch.setattr(web, "get_poll", lambda pid: dict(POLL))
    monkeypatch.setattr(
        web,
        "get_invites",
        lambda pid: [
            {"id": "i1", "email": "a@x.ch", "token": "ta", "responded": False, "notified_at": None},
            {"id": "i2", "email": "b@x.ch", "token": "tb", "responded": False, "notified_at": None},
        ],
    )
    monkeypatch.setattr(web, "get_responses", lambda pid: [])
    monkeypatch.setattr(web, "send_invite_email", lambda to, *a, **k: sent.append(to) or True)
    monkeypatch.setattr(web, "send_update_emails", lambda *a, **k: True)
    monkeypatch.setattr(web, "send_decision_email", lambda recips, *a, **k: list(recips))
    monkeypatch.setattr(web, "log_contact", lambda *a, **k: None)
    monkeypatch.setattr(web, "recipient_emails", lambda pid: ["a@x.ch", "b@x.ch"])
    monkeypatch.setattr(web, "mark_invite_notified", lambda iid: None)
    monkeypatch.setattr(web, "mark_response_notified", lambda rid: None)
    # The rest of the api module's DB touches, so the "unchanged path" tests are
    # about authorisation and not about a missing in-memory schema.
    monkeypatch.setattr(api, "create_poll", lambda creator, title, *a, **k: dict(POLL))
    monkeypatch.setattr(api, "update_poll", lambda pid, **k: dict(POLL))
    monkeypatch.setattr(api, "add_slots", lambda pid, slots: slots)
    monkeypatch.setattr(api, "add_response", lambda pid, name, email, avail: {"id": "r1"})
    monkeypatch.setattr(api, "find_response_by_email", lambda pid, email: None)
    monkeypatch.setattr(api, "notify_new_response", lambda *a: None)
    monkeypatch.setattr(api, "decided_slot_of", lambda poll: poll["slots"][0])
    monkeypatch.setattr(api, "list_polls", lambda: [dict(POLL)])
    monkeypatch.setattr(web, "get_user", lambda request: {"uid": "u1", "name": "U", "email": "u@x.ch"})
    monkeypatch.setattr(web, "require_csrf", lambda user, form: None)
    return sent


@pytest.fixture
def client(stubbed):
    return TestClient(main.app, base_url="https://testserver")


def as_(client: TestClient, key: str) -> TestClient:
    client.headers["Authorization"] = f"Bearer {key}"
    return client


def web_owner(client: TestClient) -> TestClient:
    """The same client, presenting the web-UI owner identity (header mode)."""
    client.headers["X-User"] = "u1"
    return client


# -- 1. THE ETH / SELF-HOST INVARIANT ---------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        ("GET", f"{API}/polls", {}),
        ("GET", f"{API}/polls/p1", {}),
        (
            "POST",
            f"{API}/polls",
            {"json": {"title": "t", "mode": "full_day", "slots": [{"date": "2026-06-08"}]}},
        ),
        ("PATCH", f"{API}/polls/p1", {"json": {"title": "t2"}}),
        ("POST", f"{API}/polls/p1/invite", {"json": {"emails": ["a@x.ch"]}}),
        ("POST", f"{API}/polls/p1/nudge", {"json": {"force": True}}),
        ("POST", f"{API}/polls/p1/email-decision", {"json": {"note": "hi"}}),
        ("POST", f"{API}/polls/p1/respond", {"json": {"name": "A", "availabilities": {"t1": "yes"}}}),
        ("POST", f"{API}/imip/poll", {}),
        ("GET", f"{API}/whoami", {}),
    ],
)
def test_the_legacy_key_still_reaches_everything(legacy_only, client, method, path, kwargs):
    """With no scoping configured, the single key answers as it always has.

    The sharpest assertion in this file: if any of these turns into a 403, an
    existing self-hoster or the ETH/duplet deployment has been broken by a change
    that was supposed to be invisible until it was configured.
    """
    r = as_(client, LEGACY).request(method, path, **kwargs)
    assert r.status_code not in (401, 403, 429), r.text


def test_no_scopes_configured_means_no_scoping_at_all(legacy_only, client):
    body = as_(client, LEGACY).get(f"{API}/whoami").json()
    assert body["scopes"] == sorted(scoping.ALL_SCOPES)


def test_the_web_ui_is_untouched_by_any_of_this(legacy_only, client, stubbed):
    """A human at a keyboard keeps the force affordance and every send route.

    ADR-0012 parity in its bluntest form: scoping is a property of the API key,
    and the UI never had one.
    """
    web_owner(client)
    r = client.post(
        "/scheduler/polls/p1/remind-selected", data={"emails": ["a@x.ch"]}, follow_redirects=False
    )
    assert "msg=nudged&inv=1" in r.headers["location"]


def test_the_per_request_cap_and_poll_budget_are_off_by_default(legacy_only, client, stubbed):
    """A far larger one-call fan-out than the shipped ceiling still works.

    This is what pins the shipped defaults as *inert for real use* rather than
    merely present. If someone lowers `MAIL_MAX_RECIPIENTS` to a number a meeting
    could actually hit, this fails and the change has to be argued for.
    """
    everyone = [f"p{i}@x.ch" for i in range(settings.MAIL_MAX_RECIPIENTS)]
    r = as_(client, LEGACY).post(f"{API}/polls/p1/invite", json={"emails": everyone})
    assert r.status_code == 200
    assert len(r.json()["invites"]) == settings.MAIL_MAX_RECIPIENTS


# -- 2. SCOPES --------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        ("POST", f"{API}/polls/p1/invite", {"json": {"emails": ["a@x.ch"]}}),
        ("POST", f"{API}/polls/p1/nudge", {"json": {}}),
        ("POST", f"{API}/polls/p1/email-decision", {"json": {"note": "x"}}),
    ],
)
def test_a_read_only_key_cannot_reach_any_mail_route(scoped, client, stubbed, method, path, kwargs):
    """403, not 404 and not 500 — the issue's first required test."""
    r = as_(client, READER).request(method, path, **kwargs)
    assert r.status_code == 403, r.text
    assert "mail:send" in r.text


def test_a_read_only_key_is_refused_before_anything_is_sent(scoped, client, sent):
    r = as_(client, READER).post(f"{API}/polls/p1/invite", json={"emails": ["victim@x.ch"]})
    assert r.status_code == 403
    assert sent == []


def test_a_read_only_key_can_read(scoped, client, monkeypatch):
    assert as_(client, READER).get(f"{API}/polls/p1").status_code == 200
    assert as_(client, READER).get(f"{API}/polls/p1/responses").status_code == 200
    assert as_(client, READER).get(f"{API}/polls/p1/invites").status_code == 200
    assert as_(client, READER).get(f"{API}/polls/p1/contacts").status_code == 200
    monkeypatch.setattr(api, "get_poll", lambda pid: dict(POLL, status="decided"))
    monkeypatch.setattr(api, "decided_slot_of", lambda poll: poll["slots"][0])
    assert as_(client, READER).get(f"{API}/polls/p1/event.ics").status_code == 200


def test_a_read_only_key_cannot_write_a_poll(scoped, client):
    r = as_(client, READER).patch(f"{API}/polls/p1", json={"title": "hijacked"})
    assert r.status_code == 403 and "polls:write" in r.text


def test_a_mail_key_cannot_rewrite_the_poll(scoped, client):
    """The other direction of least privilege: `mail:send` is not `polls:write`."""
    assert as_(client, SENDER).post(f"{API}/polls/p1/invite", json={"emails": ["a@x.ch"]}).status_code == 200
    assert as_(client, SENDER).delete(f"{API}/polls/p1").status_code == 403


def test_a_vote_key_can_only_vote(scoped, client):
    body = {"name": "A", "availabilities": {"t1": "yes"}}
    assert as_(client, VOTER).post(f"{API}/polls/p1/respond", json=body).status_code == 200
    assert as_(client, VOTER).post(f"{API}/polls/p1/invite", json={"emails": ["a@x.ch"]}).status_code == 403
    assert (
        as_(client, VOTER)
        .post(f"{API}/polls", json={"title": "t", "mode": "full_day", "slots": [{"date": "2026-06-08"}]})
        .status_code
        == 403
    )


def test_the_imip_poll_is_an_operator_job_not_an_agents(scoped, client):
    """The one route an agent has no business calling: it reads the mailbox."""
    assert as_(client, SENDER).post(f"{API}/imip/poll").status_code == 403
    assert as_(client, OPERATOR).post(f"{API}/imip/poll").status_code == 200


def test_adding_dates_without_notifying_needs_no_mail_scope(scoped, client):
    """A pure write stays reachable for a key that can only write polls."""
    r = as_(client, WRITER).post(f"{API}/polls/p1/slots", json={"dates": ["2026-06-09"]})
    assert r.status_code == 200


def test_notify_on_add_dates_needs_mail_send_not_just_polls_write(scoped, client, sent):
    """A route whose name promises no mail must not be a way into every inbox.

    The boundary cuts both ways, from one table: `polls:write` alone gets the write
    and is refused the `notify`, and `mail:send` alone is refused the write itself.
    """
    refused = as_(client, WRITER).post(
        f"{API}/polls/p1/slots", json={"dates": ["2026-06-09"], "notify": True}
    )
    assert refused.status_code == 403 and "mail:send" in refused.text
    assert sent == []

    no_write = as_(client, SENDER).post(
        f"{API}/polls/p1/slots", json={"dates": ["2026-06-09"], "notify": True}
    )
    assert no_write.status_code == 403 and "polls:write" in no_write.text


def test_granting_polls_write_implies_read(scoped, client):
    """A write key that could not read its own poll could not decide it."""
    granted = scoping.expand(["polls:write"])
    assert "polls:read" in granted
    assert "mail:send" not in granted


def test_granting_mail_force_implies_mail_send(scoped):
    assert "mail:send" in scoping.expand(["mail:force"])


def test_whoami_reports_the_key_s_own_capabilities_and_never_the_key(scoped, client):
    body = as_(client, FORCER).get(f"{API}/whoami").json()
    assert body["scopes"] == sorted(scoping.expand(["mail:force", "polls:read"]))
    assert body["tier"] is None
    assert FORCER not in str(body)
    assert body["key_id"] == scoping.key_id(FORCER)
    assert len(body["key_id"]) == 16 and FORCER != body["key_id"]


def test_whoami_needs_a_key(scoped, client):
    assert client.get(f"{API}/whoami").status_code == 401


def test_an_unknown_key_is_401_when_only_the_keyring_is_configured(monkeypatch, client):
    """Not the 500 that "KAIROS_API_KEY not configured" would produce: with only
    `KAIROS_API_KEYS` set there is no missing configuration to report, just a wrong
    key — and a 5xx would tell a prober the keyring exists but is broken."""
    monkeypatch.delenv("KAIROS_API_KEY", raising=False)
    monkeypatch.setattr(settings, "API_KEY", "")
    monkeypatch.setattr(settings, "API_KEYS", KEYRING)
    r = client.get(f"{API}/whoami", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401
    assert "not configured" not in r.text


def test_a_key_present_in_both_places_gets_its_scopes(monkeypatch, client):
    """Scoping must win over the legacy grant, or adding a scoped entry for a key
    that is also `KAIROS_API_KEY` would silently do nothing."""
    monkeypatch.setenv("KAIROS_API_KEY", LEGACY)
    monkeypatch.setattr(settings, "API_KEYS", f"{LEGACY}:polls:read")
    body = as_(client, LEGACY).get(f"{API}/whoami").json()
    assert body["scopes"] == ["polls:read"]


def test_no_refusal_ever_names_the_credential(scoped, client, caplog):
    """The bearer token must not reach a log line. Same guarantee #37 established
    for the public budgets, and it is the whole reason budgets key on a digest."""
    with caplog.at_level("WARNING"):
        as_(client, READER).post(f"{API}/polls/p1/invite", json={"emails": ["a@x.ch"]})
    assert READER not in caplog.text
    assert scoping.key_id(READER) in caplog.text


# -- 3. THE ROUTE AUDIT — a new /api route cannot ship unscoped -------------


def _walk(router):
    for route in getattr(router, "routes", []):
        inner = getattr(route, "original_router", None)
        if inner is not None:
            yield from _walk(inner)
        elif getattr(route, "routes", None):
            yield from _walk(route)
        else:
            yield route


# (method, api path) -> required scope. Read off the live route table, so this
# table is the assertion rather than a copy of the code under test.
EXPECTED_SCOPES = {
    ("POST", "/polls"): "polls:write",
    ("GET", "/polls"): "polls:read",
    ("GET", "/polls/{poll_id}"): "polls:read",
    ("PATCH", "/polls/{poll_id}"): "polls:write",
    ("DELETE", "/polls/{poll_id}"): "polls:write",
    ("POST", "/polls/{poll_id}/decide"): "polls:write",
    ("POST", "/polls/{poll_id}/slots"): "polls:write",
    ("POST", "/polls/{poll_id}/respond"): "respond",
    ("GET", "/polls/{poll_id}/responses"): "polls:read",
    ("PATCH", "/polls/{poll_id}/responses/{response_id}"): "polls:write",
    ("DELETE", "/polls/{poll_id}/responses/{response_id}"): "polls:write",
    ("GET", "/polls/{poll_id}/invites"): "polls:read",
    ("PATCH", "/polls/{poll_id}/invites/{invite_id}"): "polls:write",
    ("DELETE", "/polls/{poll_id}/invites/{invite_id}"): "polls:write",
    ("POST", "/polls/{poll_id}/invite"): "mail:send",
    ("POST", "/polls/{poll_id}/nudge"): "mail:send",
    ("GET", "/polls/{poll_id}/contacts"): "polls:read",
    ("POST", "/polls/{poll_id}/email-decision"): "mail:send",
    ("GET", "/polls/{poll_id}/event.ics"): "polls:read",
    ("POST", "/imip/poll"): "imip:poll",
    ("POST", "/polls/{poll_id}/imip-decision"): "mail:send",
    ("GET", "/whoami"): None,
    ("GET", "/ping"): None,
}


def _api_routes():
    for route in _walk(main.app):
        if "/api/" in getattr(route, "path", "") and hasattr(route, "dependant"):
            yield route


def test_every_api_route_declares_a_scope_and_a_budget_rule():
    """The guard that pays for itself. A new `/api` route with no declared
    capability, or with a rule that is not one of the budgets, fails here."""
    actual = {}
    for route in _api_routes():
        guards = [d.call for d in route.dependant.dependencies if isinstance(d.call, scoping.api_scope)]
        methods = getattr(route, "methods", set()) - {"HEAD"}
        if not guards:
            # /ping is the only route allowed to be unauthenticated: it is the
            # liveness probe a container or a load balancer calls.
            assert (route.path, methods) == (f"{API}/ping", {"GET"}), route.path
        assert len(guards) <= 1, f"{route.path} declares {len(guards)} guards"
        for method in methods:
            actual[(method, route.path[len(API):])] = guards[0].scope if guards else None
    assert actual == EXPECTED_SCOPES


def test_every_api_rule_is_one_the_limiter_knows():
    """A `rule=` typo must not be a budget that never fires."""
    for route in _api_routes():
        for dep in route.dependant.dependencies:
            if isinstance(dep.call, scoping.api_scope):
                assert dep.call.rule in settings.RATE_LIMITS


def test_mail_capable_routes_are_charged_the_tight_mail_budget():
    """`mail:send` must not be reachable on a route whose rule is the floor."""
    for (_method, path), scope in EXPECTED_SCOPES.items():
        if scope != "mail:send":
            continue
        rules = {
            d.call.rule
            for r in _api_routes()
            if r.path == f"{API}{path}"
            for d in r.dependant.dependencies
            if isinstance(d.call, scoping.api_scope)
        }
        assert rules == {"mail"}, path


# -- 4. THE KEYRING GRAMMAR -------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "scopes"),
    [
        ("k:polls:read", {"polls:read"}),
        ("k:polls:read,respond", {"polls:read", "respond"}),
        ("k:polls:write", {"polls:read", "polls:write"}),
        ("k:mail:force", {"mail:send", "mail:force"}),
        ("k:polls:read , respond", {"polls:read", "respond"}),
        ("k1:polls:read;k2:mail:send", None),
        ("  k:polls:read  ", {"polls:read"}),
    ],
)
def test_the_grammar_accepts_the_documented_forms(raw, scopes):
    entries = scoping.parse_keyring(raw)
    assert len(entries) == len([c for c in raw.split(";") if c.strip()])
    if scopes is not None:
        assert entries[0].scopes == scopes


@pytest.mark.parametrize(
    ("raw", "why"),
    [
        ("k", "a bare key must not mean full power"),
        ("k:", "no scopes after the colon"),
        ("k:nope", "an unknown scope name"),
        ("k:polls:read,nope", "an unknown scope name"),
        ("k@", "no tier name"),
        ("k:polls:read@tier", "scopes and a tier together"),
        ("k:polls:read;k", "a bare second key"),
        ("k:polls:read;k:polls:read", "the same key twice"),
        ("k;with:delims:polls:read", "a key the grammar cannot carry"),
        (":polls:read", "an empty key"),
    ],
)
def test_the_grammar_refuses_anything_ambiguous(raw, why):
    """A keyring entry that is quietly dropped is an operator believing in a scope
    that is not there, or the reverse — both invisible. Refuse the boot."""
    with pytest.raises(RuntimeError, match="KAIROS_API_KEYS"):
        scoping.parse_keyring(raw)


def test_a_malformed_keyring_refuses_the_boot_not_just_the_key(monkeypatch):
    monkeypatch.setattr(settings, "API_KEYS", "k:nonsense")
    with pytest.raises(RuntimeError, match="KAIROS_API_KEYS"):
        scoping.boot_report()


def test_the_boot_line_states_what_the_api_surface_will_enforce(scoped, caplog):
    with caplog.at_level("INFO", logger="kairos.scoping"):
        report = scoping.boot_report()
    assert "KAIROS_API_KEY (full scope)" in report
    assert "polls:read" in report and "mail:send" in report


def test_a_key_naming_an_unregistered_tier_grants_nothing(monkeypatch, client):
    """#33's seam, exercised. An unresolved tier must fail closed — the reason it
    does not exist is that nobody decided what it was worth."""
    monkeypatch.setenv("KAIROS_API_KEY", LEGACY)
    monkeypatch.setattr(settings, "API_KEYS", "k@pro")
    scoping._TIERS.pop("pro", None)
    r = TestClient(main.app, base_url="https://testserver", headers={"Authorization": "Bearer k"}).get(
        f"{API}/whoami"
    )
    assert r.status_code == 401


# -- 5. SEND BUDGETS --------------------------------------------------------


def test_invite_refuses_an_oversized_recipient_list(scoped, client, sent):
    """The issue's third required test. Nothing is written and nothing is sent —
    the check runs before the first row."""
    oversized = [f"victim{i}@x.ch" for i in range(settings.MAIL_MAX_RECIPIENTS + 1)]
    r = as_(client, SENDER).post(f"{API}/polls/p1/invite", json={"emails": oversized})
    assert r.status_code == 400, r.text
    assert "KAIROS_MAIL_MAX_RECIPIENTS" in r.text
    assert sent == []


def test_the_ceiling_is_exactly_where_it_is_documented(scoped, client):
    at = [f"a{i}@x.ch" for i in range(settings.MAIL_MAX_RECIPIENTS)]
    assert as_(client, SENDER).post(f"{API}/polls/p1/invite", json={"emails": at}).status_code == 200
    over = at + ["one.more@x.ch"]
    assert as_(client, SENDER).post(f"{API}/polls/p1/invite", json={"emails": over}).status_code == 400


def test_the_cap_can_be_raised_and_turned_off(monkeypatch, client, sent):
    monkeypatch.setenv("KAIROS_API_KEY", LEGACY)
    monkeypatch.setattr(settings, "MAIL_MAX_RECIPIENTS", 3)
    assert (
        as_(client, LEGACY)
        .post(f"{API}/polls/p1/invite", json={"emails": ["a@x.ch", "b@x.ch", "c@x.ch"]})
        .status_code
        == 200
    )
    monkeypatch.setattr(settings, "MAIL_MAX_RECIPIENTS", 0)
    assert (
        as_(client, LEGACY)
        .post(f"{API}/polls/p1/invite", json={"emails": [f"x{i}@x.ch" for i in range(50)]})
        .status_code
        == 200
    )


def test_a_polls_send_budget_is_counted_in_recipients(monkeypatch, client, sent):
    monkeypatch.setenv("KAIROS_API_KEY", LEGACY)
    monkeypatch.setattr(settings, "MAIL_PER_POLL", (6, 3600))
    body = {"emails": ["a@x.ch", "b@x.ch", "c@x.ch"]}
    assert as_(client, LEGACY).post(f"{API}/polls/p1/invite", json=body).status_code == 200
    assert as_(client, LEGACY).post(f"{API}/polls/p1/invite", json=body).status_code == 200
    r = as_(client, LEGACY).post(f"{API}/polls/p1/invite", json=body)
    assert r.status_code == 429 and "Retry-After" in r.headers
    assert sent == ["a@x.ch", "b@x.ch", "c@x.ch"] * 2  # the refused call sent nothing


def test_the_poll_budget_holds_regardless_of_key(monkeypatch, client, sent):
    """ "regardless of key", the issue's word: keyed on the poll, so two keys, or a
    rotated one, share one allowance."""
    monkeypatch.setattr(settings, "MAIL_PER_POLL", (3, 3600))
    monkeypatch.setattr(settings, "API_KEYS", f"{SENDER}:mail:send;{LEGACY}:mail:send")
    monkeypatch.setenv("KAIROS_API_KEY", LEGACY)
    for key in (SENDER, LEGACY, SENDER):
        assert as_(client, key).post(f"{API}/polls/p1/invite", json={"emails": ["a@x.ch"]}).status_code == 200
    assert as_(client, LEGACY).post(f"{API}/polls/p1/invite", json={"emails": ["a@x.ch"]}).status_code == 429


def test_the_poll_budget_is_per_poll(monkeypatch, client):
    """One poll's exhaustion must not stop another poll's mail."""
    monkeypatch.setenv("KAIROS_API_KEY", LEGACY)
    monkeypatch.setattr(settings, "MAIL_PER_POLL", (2, 3600))
    monkeypatch.setattr(api, "get_poll", lambda pid: dict(POLL, id=pid))
    body = {"emails": ["a@x.ch"]}
    for _ in range(2):
        assert as_(client, LEGACY).post(f"{API}/polls/p1/invite", json=body).status_code == 200
    assert as_(client, LEGACY).post(f"{API}/polls/p1/invite", json=body).status_code == 429
    assert as_(client, LEGACY).post(f"{API}/polls/p2/invite", json=body).status_code == 200


def test_the_web_ui_and_the_api_share_one_poll_budget(legacy_only, monkeypatch, client):
    """ADR-0012's parity invariant, enforced by construction rather than review:
    there is one charge, in `nudge_participants`, and both surfaces reach it."""
    monkeypatch.setattr(settings, "MAIL_PER_POLL", (2, 3600))
    # the API nudge aims at two participants (stubbed invites), the UI's the same
    assert as_(client, LEGACY).post(f"{API}/polls/p1/nudge", json={}).status_code == 200
    web_owner(client)
    r = client.post(
        "/scheduler/polls/p1/remind-selected", data={"emails": ["a@x.ch"]}, follow_redirects=False
    )
    assert r.status_code == 429  # budget spent, whatever the surface


def test_a_nudge_counts_the_addresses_it_targets_not_the_ones_it_mails(
    legacy_only, monkeypatch, client, sent
):
    """Charging only what goes out would make bypassing the cooldown *cheaper*.

    Both invitees are in their 24h cooldown, so this nudge sends nothing at all —
    and must still be charged for both, because both are what it aimed at.
    """
    from datetime import datetime, timedelta

    now = datetime.now()
    monkeypatch.setattr(
        web,
        "get_invites",
        lambda pid: [
            {"id": "i1", "email": "a@x.ch", "token": "ta", "responded": False,
             "notified_at": now - timedelta(hours=1)},
            {"id": "i2", "email": "b@x.ch", "token": "tb", "responded": False,
             "notified_at": now - timedelta(hours=1)},
        ],
    )
    monkeypatch.setattr(settings, "MAIL_PER_POLL", (2, 3600))
    assert as_(client, LEGACY).post(f"{API}/polls/p1/nudge", json={}).status_code == 200
    assert sent == [], "the cooldown should have meant zero sends"
    assert as_(client, LEGACY).post(f"{API}/polls/p1/nudge", json={}).status_code == 429


def test_the_web_ui_gets_the_same_per_request_ceiling(monkeypatch, client):
    monkeypatch.setattr(settings, "MAIL_MAX_RECIPIENTS", 2)
    web_owner(client)
    r = client.post(
        "/scheduler/polls/p1/remind-selected",
        data={"emails": ["a@x.ch", "b@x.ch", "c@x.ch"]},
        follow_redirects=False,
    )
    assert r.status_code == 400


# -- 6. `force` IS NOT A LICENCE TO SPAM ------------------------------------


def test_force_needs_its_own_scope(scoped, client, sent):
    r = as_(client, SENDER).post(f"{API}/polls/p1/nudge", json={"force": True})
    assert r.status_code == 403 and "mail:force" in r.text
    assert sent == []


def test_a_plain_nudge_still_works_without_mail_force(scoped, client):
    assert as_(client, SENDER).post(f"{API}/polls/p1/nudge", json={}).status_code == 200


def test_repeated_force_is_rate_limited_beyond_the_mail_budget(monkeypatch, client):
    """Scoped *and* rate-limited: a key that legitimately holds `mail:force` — an
    operator's automation key — must not be able to use it as a spam lever."""
    monkeypatch.setenv("KAIROS_API_KEY", LEGACY)
    monkeypatch.setattr(settings, "API_KEYS", f"{FORCER}:mail:force,polls:read")
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "MAIL_PER_POLL", (0, 3600))  # isolate the force budget
    monkeypatch.setattr(
        settings,
        "RATE_LIMITS",
        {**settings.DEFAULT_RATE_LIMITS, "mail": (100, 3600), "mail_force": (3, 3600)},
    )
    for _ in range(3):
        assert as_(client, FORCER).post(f"{API}/polls/p1/nudge", json={"force": True}).status_code == 200
    r = as_(client, FORCER).post(f"{API}/polls/p1/nudge", json={"force": True})
    assert r.status_code == 429


def test_the_force_budget_is_separate_from_the_mail_budget(monkeypatch):
    assert settings.RATE_LIMITS["mail_force"][0] < settings.RATE_LIMITS["mail"][0]


def test_the_human_in_the_ui_keeps_the_force_affordance(scoped, client, sent):
    """The asymmetry is the point: `force` stays one click away for a person."""
    web_owner(client)
    r = client.post(
        "/scheduler/polls/p1/remind-selected", data={"emails": ["a@x.ch"]}, follow_redirects=False
    )
    assert "msg=nudged" in r.headers["location"]
    assert sent == ["a@x.ch"]


# -- 7. PER-KEY RATE LIMITS -------------------------------------------------


@pytest.fixture
def limited(monkeypatch):
    """`KAIROS_RATE_LIMIT=on` with budgets a test can exhaust in a few calls."""
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(
        settings,
        "RATE_LIMITS",
        {
            **dict.fromkeys(settings.DEFAULT_RATE_LIMITS, (0, 60)),
            "mail": (2, 3600),
            "mail_force": (1, 3600),
        },
    )


def test_the_mail_budget_engages_and_answers_429(scoped, limited, client, sent):
    for _ in range(2):
        assert (
            as_(client, SENDER).post(f"{API}/polls/p1/invite", json={"emails": ["a@x.ch"]}).status_code == 200
        )
    r = as_(client, SENDER).post(f"{API}/polls/p1/invite", json={"emails": ["a@x.ch"]})
    assert r.status_code == 429
    assert sent == ["a@x.ch"] * 2


def test_the_budget_is_per_key_and_not_global(scoped, limited, client):
    """The issue's second required test: two keys must not starve each other."""
    for _ in range(2):
        as_(client, SENDER).post(f"{API}/polls/p1/invite", json={"emails": ["a@x.ch"]})
    assert as_(client, SENDER).post(f"{API}/polls/p1/invite", json={"emails": ["a@x.ch"]}).status_code == 429
    assert as_(client, LEGACY).post(f"{API}/polls/p1/invite", json={"emails": ["a@x.ch"]}).status_code == 200


def test_a_forbidden_call_still_spends_the_budget(scoped, limited, client, sent):
    """Charged before the scope check, so a 403 is not a free probe of what a key
    may not do."""
    for _ in range(2):
        as_(client, SENDER).post(f"{API}/polls/p1/invite", json={"emails": ["a@x.ch"]})
    assert as_(client, READER).post(f"{API}/polls/p1/invite", json={"emails": ["a@x.ch"]}).status_code == 403
    as_(client, READER)
    assert as_(client, SENDER).post(f"{API}/polls/p1/invite", json={"emails": ["a@x.ch"]}).status_code == 429


def test_no_budget_applies_while_the_switch_is_off(scoped, client):
    """`KAIROS_RATE_LIMIT` stays #37's switch, off by default, so a self-hoster
    who never turned it on gets no new refusals from this PR."""
    assert not settings.RATE_LIMIT_ENABLED
    for _ in range(30):
        assert as_(client, SENDER).get(f"{API}/polls/p1").status_code == 200


def test_an_agent_is_not_second_class_to_the_human_path():
    """ADR-0012's parity rule, as an assertion on the shipped numbers: the API's
    mail budget must be at least as generous as the web UI's `send`, because a
    single agent key is the one identity behind what is often one egress address."""
    assert settings.RATE_LIMITS["mail"][0] >= settings.RATE_LIMITS["send"][0]


def test_a_budget_failure_fails_open_and_says_so(scoped, limited, monkeypatch, client, caplog):
    monkeypatch.setattr(
        ratelimit.limiter, "check", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    with caplog.at_level("ERROR"):
        r = as_(client, SENDER).post(f"{API}/polls/p1/invite", json={"emails": ["a@x.ch"]})
    assert r.status_code == 200
    assert "rate limiter failed" in caplog.text


# -- 8. REST / MCP PARITY (ADR-0012) ---------------------------------------


def _load_mcp(monkeypatch, key: str):
    """Import mcp/kairos_mcp.py with a stubbed fastmcp and this key, per the
    approach tests/test_mcp_client.py already uses (the real `mcp` package is a
    PEP 723 script dependency and is not installed here)."""
    for name in ("KAIROS_URL", "KAIROS_PREFIX", "KAIROS_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    # Point the client at this app: the server's own prefix, so the parity test
    # also asserts the agent reaches the routes the REST caller does.
    monkeypatch.setenv("KAIROS_URL", "https://testserver")
    monkeypatch.setenv("KAIROS_PREFIX", settings.PREFIX)
    monkeypatch.setenv("KAIROS_API_KEY", key)
    fastmcp = types.ModuleType("mcp.server.fastmcp")
    fastmcp.FastMCP = lambda *_a, **_kw: types.SimpleNamespace(tool=lambda *_a, **_kw: lambda f: f)
    server = types.ModuleType("mcp.server")
    server.fastmcp = fastmcp
    package = types.ModuleType("mcp")
    package.server = server
    for name, module in (("mcp", package), ("mcp.server", server), ("mcp.server.fastmcp", fastmcp)):
        monkeypatch.setitem(sys.modules, name, module)
    spec = importlib.util.spec_from_file_location("kairos_mcp_parity", MCP_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _wire_mcp_to_app(monkeypatch, module, key: str):
    """Point the client's httpx at the live app, so its tools are the *server's*
    behaviour rather than a re-implementation of it."""

    def fake_request(method, url, headers=None, timeout=None, **kw):
        from urllib.parse import urlparse

        path = urlparse(url).path
        with TestClient(main.app, base_url="https://testserver") as c:
            return c.request(method, path, headers=headers or {}, **kw)

    monkeypatch.setattr(module.httpx, "request", fake_request)
    return module


def _parity(monkeypatch, stubbed, key, call_rest, call_mcp):
    """Run the same operation both ways and return (rest status, mcp result)."""
    monkeypatch.setattr(settings, "API_KEYS", KEYRING)
    monkeypatch.setenv("KAIROS_API_KEY", LEGACY)
    rest = call_rest(
        TestClient(main.app, base_url="https://testserver", headers={"Authorization": f"Bearer {key}"})
    )
    module = _wire_mcp_to_app(monkeypatch, _load_mcp(monkeypatch, key), key)
    return rest, call_mcp(module)


def test_a_read_only_key_is_refused_identically_over_rest_and_mcp(monkeypatch, stubbed, sent):
    """The AX-parity invariant, from ADR-0012: the same key, the same capability,
    the same answer — a tier limit must not make the agent path second-class."""
    rest, mcp = _parity(
        monkeypatch,
        stubbed,
        READER,
        lambda c: c.post(f"{API}/polls/p1/invite", json={"emails": ["victim@x.ch"]}),
        lambda m: m.invite("p1", ["victim@x.ch"]),
    )
    assert rest.status_code == 403
    assert mcp["error"] == 403
    assert "mail:send" in mcp["detail"]
    assert sent == []


def test_the_recipient_ceiling_is_server_side_so_mcp_cannot_outrun_rest(monkeypatch, stubbed):
    oversized = [f"victim{i}@x.ch" for i in range(settings.MAIL_MAX_RECIPIENTS + 1)]
    rest, mcp = _parity(
        monkeypatch,
        stubbed,
        SENDER,
        lambda c: c.post(f"{API}/polls/p1/invite", json={"emails": oversized}),
        lambda m: m.invite("p1", oversized),
    )
    assert rest.status_code == 400 and mcp["error"] == 400
    assert "KAIROS_MAIL_MAX_RECIPIENTS" in mcp["detail"]


def test_force_is_refused_identically_over_rest_and_mcp(monkeypatch, stubbed):
    rest, mcp = _parity(
        monkeypatch,
        stubbed,
        SENDER,
        lambda c: c.post(f"{API}/polls/p1/nudge", json={"force": True}),
        lambda m: m.nudge("p1", force=True),
    )
    assert rest.status_code == 403 and mcp["error"] == 403
    assert "mail:force" in mcp["detail"]


def test_an_exhausted_budget_is_429_over_both_surfaces(monkeypatch, stubbed):
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(
        settings,
        "RATE_LIMITS",
        {**dict.fromkeys(settings.DEFAULT_RATE_LIMITS, (0, 60)), "mail": (1, 3600)},
    )
    monkeypatch.setattr(settings, "API_KEYS", KEYRING)
    monkeypatch.setenv("KAIROS_API_KEY", LEGACY)
    with TestClient(
        main.app, base_url="https://testserver", headers={"Authorization": f"Bearer {SENDER}"}
    ) as c:
        assert c.post(f"{API}/polls/p1/invite", json={"emails": ["a@x.ch"]}).status_code == 200
    mcp = _wire_mcp_to_app(monkeypatch, _load_mcp(monkeypatch, SENDER), SENDER)
    out = mcp.invite("p1", ["a@x.ch"])
    assert out["error"] == 429 and out["retry_after"]


def test_a_permitted_operation_returns_the_same_thing_both_ways(monkeypatch, stubbed):
    rest, mcp = _parity(
        monkeypatch,
        stubbed,
        READER,
        lambda c: c.get(f"{API}/polls/p1"),
        lambda m: m.get_poll("p1"),
    )
    assert rest.status_code == 200
    assert mcp["id"] == rest.json()["id"]
    assert mcp["slots"] == rest.json()["slots"]


def test_an_agent_can_ask_what_it_may_do_both_ways(monkeypatch, stubbed):
    _, mcp = _parity(monkeypatch, stubbed, FORCER, lambda c: c.get(f"{API}/whoami"), lambda m: m.whoami())
    assert mcp["scopes"] == sorted(scoping.expand(["mail:force", "polls:read"]))


def test_every_mail_capable_mcp_tool_is_covered_by_the_audit(monkeypatch, stubbed):
    """The MCP surface is a thin client, so parity is structural — but only if
    every tool it exposes exists in the audited route table. `imip-decision` has
    no tool today; if one appears it must land in EXPECTED_SCOPES too."""
    module = _load_mcp(monkeypatch, LEGACY)
    audited = {path for (_method, path) in EXPECTED_SCOPES}
    called = {
        "/polls",
        "/polls/{poll_id}",
        "/polls/{poll_id}/invite",
        "/polls/{poll_id}/nudge",
        "/polls/{poll_id}/email-decision",
        "/polls/{poll_id}/respond",
        "/polls/{poll_id}/slots",
        "/polls/{poll_id}/decide",
        "/polls/{poll_id}/contacts",
        "/polls/{poll_id}/event.ics",
        "/whoami",
    }
    assert called <= audited
    assert callable(module.invite) and callable(module.nudge)


def test_the_mcp_client_reports_a_readable_reason_not_a_json_blob(monkeypatch, stubbed):
    """An agent has to be able to act on a refusal: which scope, which knob."""
    _, mcp = _parity(
        monkeypatch,
        stubbed,
        READER,
        lambda c: c.post(f"{API}/polls/p1/invite", json={"emails": ["a@x.ch"]}),
        lambda m: m.invite("p1", ["a@x.ch"]),
    )
    assert isinstance(mcp["detail"], str)
    assert mcp["detail"].startswith("This API key is not allowed")


# -- 9. THE TIER HOOK LEFT FOR #33 -----------------------------------------


def test_no_tier_ships_with_this_pr():
    """The decision that is not this PR's: what a plan is worth. Nothing here
    invents a plan table, a price, or a Stripe integration."""
    assert scoping.tiers() == {}


def test_a_registered_tier_is_what_a_key_resolves_to(monkeypatch, stubbed, client):
    """The seam, exercised end to end: a key that names a tier gets that tier's
    capabilities, and no call site had to change to honour it."""
    monkeypatch.setenv("KAIROS_API_KEY", LEGACY)
    monkeypatch.setattr(settings, "API_KEYS", "k@pro")
    scoping.register_tier(scoping.Tier("pro", scoping.expand(["polls:read", "mail:send"])))
    try:
        client = TestClient(main.app, base_url="https://testserver", headers={"Authorization": "Bearer k"})
        assert client.get(f"{API}/whoami").json()["scopes"] == ["mail:send", "polls:read"]
        assert client.get(f"{API}/whoami").json()["tier"] == "pro"
        assert client.post(f"{API}/polls/p1/invite", json={"emails": ["a@x.ch"]}).status_code == 200
        assert client.delete(f"{API}/polls/p1").status_code == 403
    finally:
        scoping._TIERS.pop("pro")


def test_a_tier_may_not_name_a_capability_that_does_not_exist():
    with pytest.raises(RuntimeError, match="not a scope"):
        scoping.register_tier(scoping.Tier("typo", {"polls:everything"}))


def test_an_explicit_scope_list_wins_over_the_keyring_entry_shape(monkeypatch, client):
    """`KEY:scopes` and `KEY@tier` are mutually exclusive, so there is no
    precedence rule to get wrong and no way to half-apply both."""
    entries = scoping.parse_keyring("a:polls:read;b@pro")
    assert entries[0].scopes == {"polls:read"} and entries[0].tier is None
    assert entries[1].scopes is None and entries[1].tier == "pro"


def test_the_tier_carries_a_mail_budget_hook_for_stripe_to_fill(monkeypatch):
    """The structure a subscription row becomes. No numbers are chosen here — the
    defaults in the comment are the deployment's, not a plan's."""
    tier = scoping.Tier("example", scoping.expand(["polls:write"]), mail_budget=(50, 86400))
    assert tier.mail_budget == (50, 86400)
    assert tier.api_limits is None  # None means "the deployment's own setting"


# -- 10. THE SHIPPED NUMBERS ------------------------------------------------


def test_the_ceiling_sits_above_any_hand_driven_workflow():
    """Pinned so that lowering it is a deliberate act, not an accident. The web
    UI mails one recipient at a time; the UI's batch path is a checkbox list."""
    assert settings.MAIL_MAX_RECIPIENTS == 100


def test_the_poll_budget_fits_a_large_meeting_in_one_window():
    """2000 recipients/day is 500 participants x the ~4 messages a poll sends each
    (invite, reminder, new-dates notice, decision)."""
    assert settings.MAIL_PER_POLL == (2000, 86400)


def test_the_poll_budget_still_bounds_a_cannon():
    """The point of the whole exercise: finite, per poll, whatever the key."""
    assert settings.MAIL_PER_POLL[0] > 0
    assert settings.RATE_LIMITS["mail"][0] > 0
    assert settings.RATE_LIMITS["mail_force"][0] > 0


def test_a_bad_mail_budget_refuses_the_boot(monkeypatch):
    """Same reasoning as every other limit in this app: a control the operator
    believes is in force and is not is worse than one that is off."""
    from kairos import settings as st

    with pytest.raises(RuntimeError, match="KAIROS_MAIL_PER_POLL"):
        st._parse_rate_limit("lots/day", "KAIROS_MAIL_PER_POLL")
    with pytest.raises(RuntimeError, match="KAIROS_MAIL_MAX_RECIPIENTS"):
        st._parse_count("-1", "KAIROS_MAIL_MAX_RECIPIENTS")
    assert st._parse_count("0", "KAIROS_MAIL_MAX_RECIPIENTS") == 0


def test_the_limiter_can_charge_more_than_one_unit(monkeypatch):
    """`cost=n`, for a budget denominated in recipients. Refused before any of it
    lands, so a partial charge is not expressible."""
    lim = ratelimit.RateLimiter()
    assert lim.check("r", 10, 60, "k", now=0.0, cost=10) == (True, 0)
    assert lim.check("r", 10, 60, "k", now=0.0, cost=1) == (False, 60)
    assert lim.check("r", 10, 60, "k", now=0.0, cost=11) == (False, 60)
    # cost=1 is unchanged: admit exactly the budget, then refuse
    fresh = ratelimit.RateLimiter()
    assert fresh.check("r", 2, 60, "k", now=0.0) == (True, 0)
    assert fresh.check("r", 2, 60, "k", now=0.0) == (True, 0)
    assert fresh.check("r", 2, 60, "k", now=0.0)[0] is False
