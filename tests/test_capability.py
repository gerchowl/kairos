"""Obligation A2's precondition, done: `KAIROS_AUTH=capability` + `/manage/<token>`.

Issue #30, step 2 of the hosted chain (#29 → this → #31). What is pinned here,
because #31 and #32 both build on it and neither can afford to discover it is
false:

1. **The mode is inert unless asked for** (ADR-0001/0002). Every `/manage` route
   is 404 in demo/header/oidc/none, a stray `KAIROS_CAPABILITY_*` cannot take down
   a deployment that never opted in, and an unrecognised `KAIROS_AUTH` refuses to
   boot rather than silently disabling owner auth. `SESSION_SECRET` is the one
   variable that refuses to boot *in this mode*, because the mode cannot work
   without it.
2. **The emailed link is a secret with a stated lifetime**: no clock, single use,
   consumed by an exchange that rotates the capability and mints a signed cookie.
   The two-step (GET interstitial, POST exchange) is asserted because link
   prefetching is a real consumer of single-use links.
3. **One predicate authorizes everything** (#29's `require_manage`, called with a
   token and no identity). The action tests spy on it and stop inside, so they
   assert *where* authorization happens, the way #29's own guard does.
4. **The placeholder creator** — the schema decision #29 left here — cannot be
   presented as an identity and cannot make `list_polls` return another poll.
5. **The anonymous POSTs are bounded and bound-bound.** `POST /new` refuses an
   `increment` that cannot terminate the slot loop or that is not a number, before
   the loop runs; `POST /manage/link` refuses a post no page of this app rendered.
   Both were found by review rather than by this suite, and both are the kind of
   thing that only shows up when someone reads the route instead of the tests.

NOT in this file: #31's Turnstile check and the `manage_verified_at` **send-gate**.
The column is written here, because #29 handed that write to this issue and the
route is what performs it; nothing in this file refuses a send because of it.
"""

import inspect
import logging
import re
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from itsdangerous import URLSafeTimedSerializer
from starlette.requests import Request
from starlette.responses import Response

from kairos import auth, capability, db, email_service, main, settings, web
from kairos.auth import can_manage
from kairos.csrf import make_csrf

SRC = Path(__file__).resolve().parent.parent / "src" / "kairos"

# The test env mirrors the ETH deployment: prefix /scheduler, header auth
# (tests/conftest.py). Every "unchanged" claim below is measured against that.


class _Reached(Exception):
    """Thrown from inside the `require_manage` spy, so the test stops at the gate."""


class _FakeRelay:
    def __init__(self):
        self.sent: list = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def send_message(self, msg):
        self.sent.append(msg)


class Live:
    """The real app on a real SQLite file, in capability mode, with working mail."""

    def __init__(self, client, conn, relay):
        self.client, self.conn, self.relay = client, conn, relay

    @property
    def polls(self):
        conn = sqlite3.connect(self.conn)
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute("SELECT * FROM sched_polls").fetchall()]
        conn.close()
        return rows

    def poll(self):
        assert len(self.polls) == 1, f"expected exactly one poll, found {len(self.polls)}"
        return self.polls[0]

    def row(self, poll_id):
        for poll in self.polls:
            if poll["id"] == poll_id:
                return poll
        raise AssertionError(f"no such poll: {poll_id}")

    def bodies(self):
        return [m.as_string() for m in self.relay.sent]

    def reset_mail(self):
        self.relay.sent.clear()


@pytest.fixture
def relay(monkeypatch):
    """A working relay.

    In capability mode outbound mail is not a feature of the poll, it is how the
    credential is delivered, so most of these tests need it on and the ones that
    need it off patch it off deliberately.
    """
    fake = _FakeRelay()
    monkeypatch.setattr(email_service, "SMTP_HOST", "smtp.example.net")
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@example.org")
    monkeypatch.setattr(email_service, "_smtp_session", lambda: fake)
    monkeypatch.setattr(email_service, "_last_refusal_logged", None)
    return fake


@pytest.fixture
def cap_mode(monkeypatch):
    """This process's *view* of the mode, switched to capability.

    `AUTH_MODE` is a plain module constant that `capability.enabled()` reads at
    call time, so setting it is enough for every route. The one thing fixed at
    import is the Jinja global, which is why it is patched too — otherwise a
    template assertion would inspect the header-mode form while the route under
    test is the capability one.
    """
    monkeypatch.setattr(settings, "AUTH_MODE", "capability")
    monkeypatch.setitem(web.env.globals, "CAPABILITY", True)
    return settings


@pytest.fixture
def live(tmp_path, monkeypatch, cap_mode, relay):
    path = tmp_path / "cap.db"
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{path}")
    db.init_schema()
    # follow_redirects=False, the convention the rest of the suite applies per
    # request: every assertion here is about the status a route actually returns,
    # and a followed 302 would silently become the console's 200.
    with TestClient(
        main.create_app(), base_url="https://testserver", follow_redirects=False
    ) as client:
        yield Live(client, path, relay)


@pytest.fixture
def console(live):
    """A client with a live exchange already done, and the poll's CSRF token."""
    live.create()
    poll = live.poll()
    live.open(poll["admin_token"])
    live.csrf = make_csrf(poll["id"])
    return live


def _create(live, email="ada@example.org", title="Retreat", dates=("2026-12-01",)):
    return live.client.post(
        "/scheduler/new",
        data={
            "title": title,
            "creator_email": email,
            "dates": list(dates),
            "mode": "full_day",
            "timezone": "Europe/Zurich",
            "csrf": make_csrf(capability.ANON_FORM_UID),
        },
    )


def _open(live, token):
    """Run the whole exchange: interstitial, POST, redirect."""
    live.client.get(f"/scheduler/manage/{token}")
    return live.client.post(f"/scheduler/manage/{token}", data={})


def _link(live, email, **extra):
    """POST the re-link form the way the page does — with the form's CSRF token.

    Every caller goes through here rather than posting `email` alone, so a test
    cannot quietly stop exercising the route: without the token it gets a 403,
    which passes an assertion about "no mail was sent" while checking nothing.
    """
    return live.client.post(
        "/scheduler/manage/link",
        data={"email": email, "csrf": make_csrf(capability.LINK_FORM_UID), **extra},
    )


Live.create = lambda self, **kw: _create(self, **kw)
Live.open = lambda self, token: _open(self, token)
Live.link = lambda self, email, **extra: _link(self, email, **extra)


def _request_uid(uid):
    """A bare ASGI request carrying a header identity (the ETH shape)."""
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "headers": [(b"x-user", uid.encode())],
            "scheme": "https",
            "server": ("t", 443),
            "client": ("t", 1),
            "root_path": "",
        }
    )


def _https_request():
    class _Url:
        scheme = "https"

    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/manage",
            "query_string": b"",
            "headers": [],
            "scheme": "https",
            "server": ("t", 443),
            "client": ("t", 1),
            "root_path": "",
        }
    )


def _reimport(path_name, module_name, **env):
    """Execute a module again under a different name, with `env` applied.

    Deliberately not a reload: nothing is removed from `sys.modules`, so this
    cannot leak into another test module (which is how deleting `kairos.*` entries
    once broke seven unrelated tests). The point is to exercise module-level code
    — the `os.environ` reads — which patching an already-parsed constant hides.
    """
    import importlib.util
    import os

    saved_env = {name: os.environ.get(name) for name in env}
    saved_mode = settings.AUTH_MODE
    for name, value in env.items():
        os.environ[name] = value
    if "KAIROS_AUTH" in env:
        settings.AUTH_MODE = env["KAIROS_AUTH"]
    try:
        spec = importlib.util.spec_from_file_location(module_name, SRC / path_name)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        settings.AUTH_MODE = saved_mode
        for name, value in saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


# -- 1. the mode is inert unless asked for (ADR-0001/0002) -------------------


@pytest.mark.parametrize("mode", ["demo", "header", "oidc", "none"])
def test_no_manage_route_exists_outside_capability_mode(mode, monkeypatch):
    """Every route in the new module 404s in every other mode.

    Not "returns nothing useful" — 404, so an operator who mistypes
    KAIROS_AUTH=capabilty gets a deployment visibly missing its management surface
    rather than one that looks like it has one.
    """
    monkeypatch.setattr(settings, "AUTH_MODE", mode)
    client = TestClient(main.app, base_url="https://testserver", follow_redirects=False)
    for method, path in [
        ("get", "/scheduler/manage"),
        ("get", "/scheduler/manage/sometoken"),
        ("post", "/scheduler/manage/sometoken"),
        ("post", "/scheduler/manage/link"),
        ("post", "/scheduler/manage/p1/close"),
    ]:
        response = client.get(path) if method == "get" else client.post(path, data={})
        assert response.status_code == 404, f"{method.upper()} {path} in {mode} mode"


def test_a_stray_capability_variable_cannot_take_down_a_deployment_not_using_it():
    """The regression oidc.py's allowlist gate exists to prevent, for this knob.

    `KAIROS_CAPABILITY_SESSION_HOURS` is *unused* in every other mode, so a value
    that would be refused cannot be allowed to raise at import: one variable
    pasted into the wrong shell would otherwise break the boot of a self-hoster
    that never asked for capability mode. Hence a warning, not an exception — and
    hence re-importing the module, because patching the parsed constant hides the
    very thing being asserted.
    """
    module = _reimport(
        "capability.py",
        "kairos_capability_probe",
        KAIROS_AUTH="header",
        KAIROS_CAPABILITY_SESSION_HOURS="not-a-number",
    )
    assert module.SESSION_HOURS == module.DEFAULT_SESSION_HOURS
    assert module.enabled() is False
    assert module.identity_report().startswith("owner auth: header")


def test_the_mode_gate_covers_the_parse_not_just_the_routes():
    """A *valid* value must still be ignored outside the mode.

    The half the previous test could fake: without the gate, a deployment
    exporting KAIROS_CAPABILITY_SESSION_HOURS=1 would silently give its capability
    sessions an hour instead of the default — a control the operator set in one
    mode quietly changing another.
    """
    module = _reimport(
        "capability.py", "kairos_capability_probe2", KAIROS_AUTH="header", KAIROS_CAPABILITY_SESSION_HOURS="1"
    )
    assert module.SESSION_HOURS == module.DEFAULT_SESSION_HOURS


def test_an_unrecognised_auth_mode_refuses_to_boot():
    """A typo in KAIROS_AUTH must not silently disable owner auth.

    Every mode is a string dispatch in `auth.get_user`, so `capabilty` resolves
    nobody: every owner page 401s and the deployment looks exactly like one where
    everybody is logged out. That is a control the operator believes is in force
    and is not — the failure this repo answers by refusing to boot (#47, #37, #51,
    #53). A recognised-value set rather than `in (...)`, so the typo cannot
    disarm anything quietly either.
    """
    with pytest.raises(RuntimeError) as exc:
        _reimport("settings.py", "kairos_settings_probe", KAIROS_AUTH="capabilty")
    assert "KAIROS_AUTH" in str(exc.value)
    assert "capability" in str(exc.value)


@pytest.mark.parametrize("value", ["", " demo", "demo ", "DEMO", "Demo", "Header"])
def test_an_unrecognised_auth_mode_is_a_refusal_not_a_demo_fallback(value):
    """`KAIROS_AUTH=` — or a stray space, or a capital letter — must not mean "demo".

    Falling back to `demo` would make every visitor the same owner, which is the
    one direction that fails open; quietly resolving nobody is merely useless. The
    refusal is the honest answer to "we cannot tell what identity you meant", and
    it is why the value is compared without stripping it: stripping would turn one
    stray space in a compose file into the fail-open.
    """
    with pytest.raises(RuntimeError, match="KAIROS_AUTH"):
        _reimport("settings.py", f"kairos_settings_probe_{abs(hash(value))}", KAIROS_AUTH=value)


def test_every_mode_that_existed_before_still_boots():
    """The other side of that check: the refusal must not have narrowed the set."""
    for mode in ("demo", "header", "oidc", "none", "capability"):
        assert _reimport("settings.py", f"kairos_settings_ok_{mode}", KAIROS_AUTH=mode).AUTH_MODE == mode


def test_the_boot_line_states_which_boundary_is_in_force(monkeypatch):
    """A green boot must not be the only evidence about who may manage a poll."""
    monkeypatch.setattr(settings, "AUTH_MODE", "capability")
    line = capability.identity_report()
    assert line.startswith("owner auth: capability")
    assert "rotates admin_token" in line
    monkeypatch.setattr(settings, "AUTH_MODE", "header")
    assert capability.identity_report().startswith("owner auth: header")


def test_a_capability_deployment_without_working_mail_is_told_so_at_boot(monkeypatch):
    """The mode cannot run without outbound mail, so boot says so rather than
    letting the first creator find out by creating an unusable poll."""
    monkeypatch.setattr(settings, "AUTH_MODE", "capability")
    monkeypatch.setattr(email_service, "SMTP_HOST", "")
    assert "capability is on but outbound mail is unusable" in " ".join(capability.boot_warnings())
    monkeypatch.setattr(settings, "AUTH_MODE", "header")
    assert capability.boot_warnings() == []


# -- 2. the placeholder creator: the schema decision --------------------------


def test_the_placeholder_is_per_poll_unguessable_and_fits_the_column():
    """`creator_id` is VARCHAR(36), so the placeholder has to fit it — and it has
    to be per poll, because `db.list_polls` is the dashboard's only query."""
    values = {capability.anonymous_creator_id() for _ in range(500)}
    assert len(values) == 500, "two accountless polls shared a creator_id"
    for value in values:
        assert value.startswith(capability.ANON_CREATOR_PREFIX)
        # 14 bytes of CSPRNG output, hex: 112 bits, not a guessable counter.
        assert re.fullmatch(r"anon:[0-9a-f]{28}", value)
        assert len(value) <= 36


def test_the_placeholder_cannot_be_presented_as_an_identity():
    """The fail-open a *constant* sentinel would have been.

    #29's predicate compares `uid == poll["creator_id"]`, so a sentinel anyone can
    name is a sentinel that owns every accountless poll the moment any identity
    source can return it — a header-mode deployment flipped back, or a supported
    `kairos.auth.get_user` seam. This is the test that makes the unguessable part
    load-bearing: guess the prefix, and nothing.
    """
    poll = {
        "id": "p1",
        "creator_id": capability.ANON_CREATOR_PREFIX + "0" * 28,
        "owner_id": None,
        "admin_token": "s3cret",
        "slots": [],
    }
    # `poll` above is a row written by hand with the "obvious" constant
    # placeholder — exactly what a fixed sentinel would have put in every
    # accountless row. Guessing it must not work.
    for guessed in ("anon", "anon:", "accountless", "anon:0", "ANON", "api", "demo", ""):
        assert can_manage(poll, _request_uid(guessed), token=None) is False, \
            f"a guessable uid ({guessed!r}) took over an accountless poll"


def test_a_shared_sentinel_would_have_been_a_dashboard_over_fetch(tmp_path, monkeypatch):
    """Why uniqueness is not decoration.

    `db.list_polls(creator_id)` is `WHERE creator_id = ?`. With one shared
    placeholder for every accountless poll, any code path that ever passed it
    would return every accountless poll in the deployment — the cross-tenant
    over-fetch ADR-0009 exists to prevent. Per-poll uniqueness makes the worst
    case one row: the same poll.
    """
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/sentinel.db")
    db.init_schema()
    a = db.create_poll(
        capability.anonymous_creator_id(), "A", None, "full_day", "UTC", [{"date": "2026-12-01"}]
    )
    b = db.create_poll(
        capability.anonymous_creator_id(), "B", None, "full_day", "UTC", [{"date": "2026-12-02"}]
    )

    assert a["creator_id"] != b["creator_id"]
    assert [p["id"] for p in db.list_polls(a["creator_id"])] == [a["id"]], (
        "listing by one accountless creator returned another creator's poll"
    )


def test_an_accountless_poll_has_a_null_owner_and_a_minted_capability(live):
    """The tenancy shape #29 designed for: `owner_id` NULL is the accountless
    marker, `creator_email` says where the link went, and the capability carries
    the same entropy as every other token (ADR-0001)."""
    live.create()
    poll = live.poll()
    assert poll["owner_id"] is None
    assert poll["creator_email"] == "ada@example.org"
    assert poll["creator_id"].startswith(capability.ANON_CREATOR_PREFIX)
    assert poll["manage_verified_at"] is None, "the exchange stamps it, not creation"
    assert len(poll["admin_token"]) == 43 == len(poll["public_token"])
    assert poll["admin_token"] != poll["public_token"]


# -- 3. creation: the link is mailed, and only the link ----------------------


def test_creating_a_poll_mails_its_manage_link(live):
    response = live.create(title="Retreat")
    assert response.status_code == 200
    assert "Check your inbox" in response.text

    poll = live.poll()
    assert len(live.relay.sent) == 1
    message = live.relay.sent[0]
    assert message["To"] == "ada@example.org"
    assert poll["title"] in message["Subject"]
    # "works once" is a claim the creator acts on, so it has to be in the message.
    body = message.as_string()
    assert f"/scheduler/manage/{poll['admin_token']}" in body
    assert "once" in body


def test_creating_a_poll_never_reveals_the_capability_on_the_page(live):
    """The response is the one an anonymous stranger gets, so it must not carry a
    credential — including in a redirect target."""
    response = live.create()
    token = live.poll()["admin_token"]
    assert token not in response.text
    assert token not in response.headers.get("location", "")


def test_creation_refuses_when_outbound_mail_cannot_send(live, monkeypatch):
    """No poll, not an unreachable one.

    A row whose management link exists in no inbox and cannot be retrieved is the
    exact failure this route exists to prevent, so the mode refuses to create it
    and says why.
    """
    monkeypatch.setattr(email_service, "SMTP_HOST", "")
    response = live.create()
    assert response.status_code == 503
    assert "Email is not available" in response.text
    assert live.polls == [], "a poll was created whose credential can never be delivered"


def test_creation_requires_a_creator_address(live):
    response = live.client.post(
        "/scheduler/new",
        data={
            "title": "No address",
            "dates": ["2026-12-01"],
            "mode": "full_day",
            "timezone": "Europe/Zurich",
            "csrf": make_csrf(capability.ANON_FORM_UID),
        },
    )
    assert response.status_code == 400
    assert "Email address required" in response.text
    assert live.polls == []


def test_an_anonymous_creation_post_without_our_csrf_token_is_refused(live):
    """No account means the CSRF token binds to a constant, not to nobody: the
    form is still ours, and the POST has to prove it came from it."""
    response = live.client.post(
        "/scheduler/new",
        data={
            "title": "Forged",
            "creator_email": "attacker@example.org",
            "dates": ["2026-12-01"],
            "mode": "full_day",
            "timezone": "Europe/Zurich",
            "csrf": make_csrf("someone-else"),
        },
    )
    assert response.status_code == 403
    assert live.polls == []


def test_an_invalid_creator_address_creates_nothing(live):
    response = live.create(email="not-an-address")
    assert response.status_code == 400
    assert live.polls == []


def test_the_creation_form_asks_for_an_address_only_in_capability_mode(live, monkeypatch):
    assert "Your email address" in live.client.get("/scheduler/new").text

    monkeypatch.setattr(settings, "AUTH_MODE", "header")
    monkeypatch.setitem(web.env.globals, "CAPABILITY", False)
    page = live.client.get("/scheduler/new", headers={"X-User": "alice"})
    assert page.status_code == 200
    assert "Your email address" not in page.text


def test_the_re_link_route_is_not_shadowed_by_the_token_route():
    """`POST /manage/link` has to be registered before `POST /manage/{token>`.

    Otherwise Starlette matches the literal path as a *token*, every re-link
    request answers "not a valid link", and the recovery path for a spent
    single-use link silently does not exist — the kind of absence nobody notices
    until a creator is locked out. Asserted on the live route table rather than
    left to a comment.
    """
    order = [r.path for r in capability.router.routes]
    assert order.index("/scheduler/manage/link") < order.index("/scheduler/manage/{token}"), \
        "the re-link route must be declared before the token route"


def test_a_bad_link_is_a_page_that_says_nothing_about_other_polls(live):
    """One answer for "no such link", "not yours" and "already spent" — so the
    route is not an oracle for which polls exist."""
    live.create(title="Retreat")
    body = live.client.get("/scheduler/manage/never-existed").text
    assert "not valid" in body
    assert "Retreat" not in body


# -- 4. the exchange: single use, no clock, a stated session lifetime ---------


def test_the_emailed_link_get_is_an_interstitial_that_does_not_spend_the_token(live):
    """Link prefetching (Outlook Safe Links, Proofpoint, every corporate scanner)
    follows links in inbound mail with a GET. A GET that consumed the capability
    would spend the creator's only credential before they clicked anything."""
    live.create(title="Retreat")
    before = live.poll()

    page = live.client.get(f"/scheduler/manage/{before['admin_token']}")
    assert page.status_code == 200
    assert "Retreat" in page.text
    assert f'action="/scheduler/manage/{before["admin_token"]}"' in page.text
    assert capability.SESSION_COOKIE not in live.client.cookies
    assert live.poll()["admin_token"] == before["admin_token"], "a GET spent the link"


def test_the_exchange_rotates_the_capability_and_mints_a_session(live):
    live.create()
    emailed = live.poll()["admin_token"]

    response = live.open(emailed)
    assert response.status_code == 302
    assert response.headers["location"] == "/scheduler/manage"
    assert capability.SESSION_COOKIE in live.client.cookies
    assert live.poll()["admin_token"] != emailed
    # The redirect carries no token: the credential moved out of the URL.
    assert "manage/" not in response.headers["location"]


def test_the_emailed_link_works_exactly_once(live):
    """The property the whole exchange exists for: a link copied out of an inbox,
    a proxy log or a forwarded mail is worthless once opened."""
    live.create()
    emailed = live.poll()["admin_token"]
    assert live.open(emailed).status_code == 302
    replay = live.client.post(f"/scheduler/manage/{emailed}", data={})
    assert replay.status_code == 404
    assert "not valid" in replay.text


def test_the_exchange_stamps_manage_verified_at_and_keeps_the_first_time(live):
    """#29 handed this write to #30. It is the precondition #31's send-gate reads,
    and it is deliberately idempotent: the column holds the *first* open."""
    live.create()
    poll_id = live.poll()["id"]
    assert db.mark_manage_verified(poll_id) is True
    first = live.row(poll_id)["manage_verified_at"]
    assert first is not None
    assert db.mark_manage_verified(poll_id) is False
    assert live.row(poll_id)["manage_verified_at"] == first


def test_the_exchange_writes_the_verification_stamp(live):
    live.create()
    assert live.poll()["manage_verified_at"] is None
    live.open(live.poll()["admin_token"])
    assert live.poll()["manage_verified_at"] is not None


def _null_out_capability(poll_id):
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE sched_polls SET admin_token = NULL WHERE id = %s", (poll_id,))
    conn.commit()
    cursor.close()
    conn.close()


def test_rotating_a_poll_with_no_capability_mints_nothing(tmp_path, monkeypatch):
    """`NULL` means "no management capability was ever minted for this poll", and
    rotation must not quietly hand such a row one."""
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/nocap.db")
    db.init_schema()
    poll = db.create_poll("alice", "No cap", None, "full_day", "UTC", [{"date": "2026-12-01"}])
    _null_out_capability(poll["id"])
    assert db.rotate_admin_token(poll["id"], poll["admin_token"]) is None
    assert db.rotate_admin_token(poll["id"], None) is None


def test_rotation_is_a_compare_and_swap_on_the_presented_token(live):
    """Two exchanges racing on one link must produce one winner and one refusal.

    With an unconditional `WHERE admin_token IS NOT NULL` the loser would also be
    told it had rotated, and would mint a session around a capability that has
    already been replaced — a guard that reads as if it works while being
    unreachable. Asserted directly on the data-layer function, because that is
    where the guarantee lives.
    """
    live.create()
    poll = live.poll()
    first = db.rotate_admin_token(poll["id"], poll["admin_token"])
    assert first and first != poll["admin_token"]
    # The loser's swap: it presents the token it read, which is no longer the row's.
    assert db.rotate_admin_token(poll["id"], poll["admin_token"]) is None
    assert live.poll()["admin_token"] == first, "a refused swap still changed the row"


def test_the_loser_of_a_race_cannot_mint_a_session(live):
    """The same thing at the route: a stale token gets no cookie."""
    live.create()
    poll = live.poll()
    live.open(poll["admin_token"])  # rotates; the creator now has a session
    live.client.cookies.clear()
    assert live.client.post(f"/scheduler/manage/{poll['admin_token']}", data={}).status_code == 404
    assert capability.SESSION_COOKIE not in live.client.cookies


def test_the_session_cookie_is_signed_bounded_and_scoped_to_the_console():
    """Cookie hygiene: HttpOnly (a capability must not be reachable from script),
    Lax (the console is a top-level GET), scoped to {P}/manage (a capability has no
    business travelling to /p/<token>), Secure under https, and Max-Aged."""
    response = Response()
    capability.mint_session(response, _https_request(), {"id": "p1"}, "tok")
    cookie = response.headers["set-cookie"]
    assert capability.SESSION_COOKIE in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie.replace("samesite", "SameSite")
    assert "Secure" in cookie
    assert "Path=/scheduler/manage" in cookie
    assert f"Max-Age={capability.SESSION_MAX_AGE}" in cookie


def test_the_session_is_bounded_at_twelve_hours_by_default():
    """#53's owner-session lifetime, for the same reason: a working day, and a
    scheduling poll is a short-lived artefact. Stated rather than implied."""
    module = _reimport("capability.py", "kairos_cap_probe_default", KAIROS_AUTH="capability")
    assert module.SESSION_HOURS == 12
    assert module.SESSION_MAX_AGE == 12 * 3600


def test_the_session_lifetime_is_configurable_and_a_typo_warns():
    good = _reimport(
        "capability.py", "kairos_cap_probe_ok", KAIROS_AUTH="capability", KAIROS_CAPABILITY_SESSION_HOURS="2"
    )
    assert good.SESSION_HOURS == 2 and good.SESSION_MAX_AGE == 7200

    for bad in ("0", "-3", "soon", "12h"):
        warnings: list = []
        assert good.parse_session_hours(bad, warnings.append) == good.DEFAULT_SESSION_HOURS
        assert "KAIROS_CAPABILITY_SESSION_HOURS" in warnings[0]


# -- 5. the session authorizes the console, and only it ----------------------


def test_the_console_is_unreachable_without_a_capability_cookie(live):
    live.create(title="Retreat")
    page = live.client.get("/scheduler/manage")
    assert page.status_code == 200
    assert "Open your manage link" in page.text
    assert "Retreat" not in page.text


def test_the_console_renders_the_poll_after_the_exchange(live):
    live.create(title="Retreat")
    poll = live.poll()
    live.open(poll["admin_token"])
    page = live.client.get("/scheduler/manage")
    assert page.status_code == 200
    assert "Retreat" in page.text
    assert f"/scheduler/p/{poll['public_token']}" in page.text


def _signed_cookie(poll_id, token):
    return capability._serializer(salt="cap-session").dumps({"pid": poll_id, "at": token})


def test_a_cookie_minted_before_a_rotation_stops_working(live):
    """A capability cookie *is* a capability, so rotating the token retires the
    old cookies too — instead of leaving them as credentials nobody remembers to
    revoke."""
    live.create(title="Retreat")
    poll = live.poll()
    live.open(poll["admin_token"])
    rotated = live.poll()["admin_token"]

    live.client.cookies.set(capability.SESSION_COOKIE, _signed_cookie(poll["id"], poll["admin_token"]))
    assert "Open your manage link" in live.client.get("/scheduler/manage").text

    live.client.cookies.set(capability.SESSION_COOKIE, _signed_cookie(poll["id"], rotated))
    assert "Retreat" in live.client.get("/scheduler/manage").text


def test_a_forged_or_tampered_cookie_is_refused_rather_than_crashing(live):
    """A bad cookie is a wrong credential, and the predicate is what says so."""
    live.create()
    for junk in ("garbage", "x" * 400, "a.b.c"):
        live.client.cookies.set(capability.SESSION_COOKIE, junk)
        assert live.client.get("/scheduler/manage").status_code == 200
    # A correctly *signed* cookie naming a token that is not this poll's.
    poll_id = live.poll()["id"]
    live.client.cookies.set(capability.SESSION_COOKIE, _signed_cookie(poll_id, "not-the-token"))
    assert "Open your manage link" in live.client.get("/scheduler/manage").text


def test_no_capability_ever_appears_in_a_response_body_or_a_log(live, caplog):
    """S3. A capability in a log line or a page is a credential in the wrong
    place, and the console's own credential must never be rendered — the cookie is
    HttpOnly precisely so it cannot be."""
    # Scoped to Kairos's own loggers. httpx logs every request line at DEBUG in the
    # test client, and an access log *does* contain the manage URL — as it does for
    # every public_token and invite token this app has always handed out. That is
    # inherent to a capability in a URL, and it is part of why the link is single
    # use: the token is rotated the moment it is exchanged. What is asserted here
    # is the part Kairos controls — it never *writes* the capability down.
    caplog.set_level(logging.DEBUG, logger="kairos")
    live.create(title="Retreat")
    poll = live.poll()
    emailed = poll["admin_token"]

    interstitial = live.client.get(f"/scheduler/manage/{emailed}")
    exchange = live.client.post(f"/scheduler/manage/{emailed}", data={})
    console_page = live.client.get("/scheduler/manage")
    live.link("ada@example.org")
    rotated = live.poll()["admin_token"]

    # The interstitial legitimately echoes the token: it is the URL the creator
    # just clicked, and its form posts back to it.
    assert emailed in interstitial.text
    for response in (exchange, console_page):
        assert emailed not in response.text
        assert rotated not in response.text
    # Both capabilities reach the two places they are *meant* to — the mail the
    # creator was sent, and the interstitial they asked for — and no log line.
    assert any(emailed in body for body in live.bodies())
    assert emailed not in caplog.text
    assert rotated not in caplog.text


# -- 6. every action authorizes through #29's predicate ------------------------

ACTIONS = ["close", "reopen", "decide", "invite", "remind", "email-decision", "edit", "delete"]


@pytest.mark.parametrize("action", ACTIONS)
def test_every_action_authorizes_through_the_predicate(console, monkeypatch, action):
    """Obligation S6, as CI enforces it for the owner surface: the gate is
    *called*. Execution stops inside the spy, so this asserts where authorization
    happens and nothing about what the route does next."""
    live = console
    seen = []

    def spy(target, request, **kwargs):
        seen.append((target["id"], kwargs.get("token"), kwargs.get("user")))
        raise _Reached

    monkeypatch.setattr(capability, "require_manage", spy)
    with pytest.raises(_Reached):
        live.client.post(
            f"/scheduler/manage/{live.poll()['id']}/{action}",
            data={
                "csrf": live.csrf,
                "title": "T",
                "timezone": "UTC",
                "slot_id": "x",
                "email": "a@example.org",
            },
        )
    assert len(seen) == 1
    # A token, and deliberately no identity: this is the anonymous capability
    # shape #29's predicate was documented for.
    assert seen[0][1] == live.poll()["admin_token"]
    assert seen[0][2] is None


def test_an_unknown_action_is_a_404(console):
    """The vocabulary is closed, so a typo is visible instead of silently doing
    nothing.

    Not a leak that the check runs before the session check: the action names are
    in `capability.py`, which is public, and answering 404 to a garbage name costs
    no session lookup and no query.
    """
    live = console
    assert (
        live.client.post(
            f"/scheduler/manage/{live.poll()['id']}/drop-tables", data={"csrf": live.csrf}
        ).status_code
        == 404
    )


def test_an_action_without_a_session_is_401(console):
    live = console
    csrf = live.csrf
    live.client.cookies.clear()
    assert (
        live.client.post(f"/scheduler/manage/{live.poll()['id']}/close", data={"csrf": csrf}).status_code
        == 401
    )


def test_an_action_without_a_csrf_token_is_403(console):
    live = console
    poll_id = live.poll()["id"]
    assert live.client.post(f"/scheduler/manage/{poll_id}/close", data={}).status_code == 403
    assert db.get_poll(poll_id)["status"] == "open", "a refused action still wrote"


def test_an_action_naming_another_poll_is_404_and_changes_nothing(console):
    """The session speaks for exactly one poll. A path naming another one is not
    a "not the owner" case, and must not leak whether that poll exists."""
    live = console
    mine = live.poll()["id"]
    live.create(title="Other", dates=("2026-12-09",))
    other = [p for p in live.polls if p["id"] != mine][0]

    assert (
        live.client.post(f"/scheduler/manage/{other['id']}/close", data={"csrf": live.csrf}).status_code
        == 404
    )
    assert db.get_poll(other["id"])["status"] == "open"


def test_a_session_whose_poll_was_deleted_falls_back_to_the_link_page(console):
    live = console
    db.delete_poll(live.poll()["id"])
    assert "Open your manage link" in live.client.get("/scheduler/manage").text


def test_close_and_reopen_move_the_poll(console):
    live = console
    poll_id = live.poll()["id"]
    assert live.client.post(f"/scheduler/manage/{poll_id}/close", data={"csrf": live.csrf}).status_code == 302
    assert db.get_poll(poll_id)["status"] == "closed"
    assert (
        live.client.post(f"/scheduler/manage/{poll_id}/reopen", data={"csrf": live.csrf}).status_code == 302
    )
    assert db.get_poll(poll_id)["status"] == "open"


def test_decide_refuses_a_slot_belonging_to_another_poll(console):
    """web.decide_poll's check, for web.decide_poll's reason."""
    live = console
    mine = live.poll()["id"]
    live.create(title="Other", dates=("2026-12-09",))
    other = db.get_poll([p for p in live.polls if p["id"] != mine][0]["id"])

    response = live.client.post(
        f"/scheduler/manage/{mine}/decide", data={"csrf": live.csrf, "slot_id": other["slots"][0]["id"]}
    )
    assert response.status_code == 400
    assert db.get_poll(mine)["status"] == "open"


def test_decide_records_the_chosen_slot(console):
    live = console
    slot_id = db.get_poll(live.poll()["id"])["slots"][0]["id"]
    live.client.post(
        f"/scheduler/manage/{live.poll()['id']}/decide", data={"csrf": live.csrf, "slot_id": slot_id}
    )
    decided = db.get_poll(live.poll()["id"])
    assert decided["status"] == "decided" and decided["decided_slot_id"] == slot_id


def test_invite_refuses_an_invalid_address_and_deduplicates(console):
    live = console
    poll_id = live.poll()["id"]
    assert (
        live.client.post(
            f"/scheduler/manage/{poll_id}/invite", data={"csrf": live.csrf, "email": "nope"}
        ).status_code
        == 400
    )
    assert (
        live.client.post(
            f"/scheduler/manage/{poll_id}/invite", data={"csrf": live.csrf, "email": "bob@example.org"}
        ).status_code
        == 302
    )
    assert [i["email"] for i in db.get_invites(poll_id)] == ["bob@example.org"]
    live.client.post(
        f"/scheduler/manage/{poll_id}/invite", data={"csrf": live.csrf, "email": "BOB@example.org"}
    )
    assert len(db.get_invites(poll_id)) == 1


def test_remind_goes_through_the_shared_engine(console, monkeypatch):
    """DRY is the point.

    `web.nudge_participants` carries the per-participant cooldown and #51's
    per-poll budget; this console reusing it is what makes those hold across
    surfaces rather than per surface (ADR-0012's parity invariant). A copy would
    be a second, unreviewed set of numbers — and the creator's own address is the
    Reply-To, which is how a participant can reach an accountless organizer.
    """
    live = console
    seen = {}
    monkeypatch.setattr(
        web,
        "nudge_participants",
        lambda request, poll, user, **kw: (
            seen.update(poll=poll["id"], email=user["email"]) or {"invited": 2, "updated": 0}
        ),
    )
    assert (
        live.client.post(
            f"/scheduler/manage/{live.poll()['id']}/remind", data={"csrf": live.csrf}
        ).status_code
        == 302
    )
    assert seen == {"poll": live.poll()["id"], "email": "ada@example.org"}


def test_remind_is_refused_on_a_closed_poll(console):
    live = console
    poll_id = live.poll()["id"]
    live.client.post(f"/scheduler/manage/{poll_id}/close", data={"csrf": live.csrf})
    assert (
        live.client.post(f"/scheduler/manage/{poll_id}/remind", data={"csrf": live.csrf}).status_code == 400
    )


def test_email_decision_charges_the_same_per_poll_budget_the_other_surfaces_do(console, monkeypatch):
    """#51's per-poll budget is counted in recipients across every send path. If
    this route did not charge it, the accountless console would be the one way to
    mail a poll without a ceiling."""
    live = console
    poll_id = live.poll()["id"]
    slot = db.get_poll(poll_id)["slots"][0]
    db.create_invite(poll_id, "bob@example.org")
    db.update_poll(poll_id, status="decided", decided_slot_id=slot["id"])

    charged = []
    monkeypatch.setattr(capability, "charge_poll_recipients", lambda pid, count: charged.append((pid, count)))
    monkeypatch.setattr(capability, "send_decision_email", lambda *a, **k: ["bob@example.org"])
    assert (
        live.client.post(f"/scheduler/manage/{poll_id}/email-decision", data={"csrf": live.csrf}).status_code
        == 302
    )
    assert charged == [(poll_id, 1)]
    assert db.get_contact_log(poll_id)[0]["kind"] == "decision"


def test_email_decision_is_refused_before_a_date_is_chosen(console):
    live = console
    assert (
        live.client.post(
            f"/scheduler/manage/{live.poll()['id']}/email-decision", data={"csrf": live.csrf}
        ).status_code
        == 400
    )


def test_edit_appends_dates_and_keeps_existing_ones(console):
    """web.edit_poll_submit's semantics: additive, so a response to an existing
    date survives a later edit."""
    live = console
    poll_id = live.poll()["id"]
    before = {s["id"] for s in db.get_poll(poll_id)["slots"]}
    response = live.client.post(
        f"/scheduler/manage/{poll_id}/edit",
        data={
            "csrf": live.csrf,
            "title": "Retreat (moved)",
            "timezone": "UTC",
            "dates": "2026-12-01, 2026-12-08",
        },
    )
    assert response.status_code == 302
    updated = db.get_poll(poll_id)
    assert updated["title"] == "Retreat (moved)" and updated["timezone"] == "UTC"
    assert before <= {s["id"] for s in updated["slots"]}
    assert len(updated["slots"]) == 2


def test_edit_refuses_a_date_it_could_not_store(console):
    """The console's date field is free text, so it validates.

    An unvalidated value lands in a `DATE` column that `dbconn` reads back through
    a strict converter: storing it succeeds and the *next* read of the poll raises.
    A 400 at the form beats a 500 on an ordinary page view afterwards.
    """
    live = console
    response = live.client.post(
        f"/scheduler/manage/{live.poll()['id']}/edit",
        data={"csrf": live.csrf, "title": "T", "timezone": "UTC", "dates": "not-a-date"},
    )
    assert response.status_code == 400
    assert db.get_poll(live.poll()["id"])["title"] == "Retreat"


def test_edit_refuses_an_unknown_timezone(console):
    live = console
    assert (
        live.client.post(
            f"/scheduler/manage/{live.poll()['id']}/edit",
            data={"csrf": live.csrf, "title": "T", "timezone": "Mars/Olympus"},
        ).status_code
        == 400
    )


def test_delete_removes_the_poll(console):
    live = console
    poll_id = live.poll()["id"]
    assert (
        live.client.post(f"/scheduler/manage/{poll_id}/delete", data={"csrf": live.csrf}).status_code == 302
    )
    assert db.get_poll(poll_id) is None
    assert "Open your manage link" in live.client.get("/scheduler/manage").text


# -- 7. getting a spent link back -------------------------------------------


def test_requesting_a_link_mails_the_current_capability_to_the_owner(console):
    """A single-use link needs a way back, and the link that comes back must be
    the *current* capability — re-sending the spent one would be re-sending a dead
    link."""
    live = console
    live.client.cookies.clear()
    live.reset_mail()
    response = live.link("ada@example.org")
    assert response.status_code == 200
    assert "Check your inbox" in response.text
    assert len(live.relay.sent) == 1
    assert f"/scheduler/manage/{live.poll()['admin_token']}" in live.relay.sent[0].as_string()


def _without_csrf_tokens(html: str) -> str:
    """The page with its per-render CSRF bindings masked.

    A signed CSRF token embeds the second it was minted, so two renders a second
    apart differ in it — and it is a function of the clock, not of the address. The
    honest form of "the answer is identical" therefore masks those and compares
    everything else, rather than comparing two whole strings that happened to be
    minted inside the same second. (It only became visible when the re-link form got
    a CSRF field: until then the page had no per-render value at all, so the
    comparison passed for a reason that had nothing to do with the property.)
    """
    return re.sub(r'name="csrf" value="[^"]+"', 'name="csrf" value="TOKEN"', html)


def test_the_re_link_answer_is_identical_whether_or_not_anything_matched(console):
    """Not an address oracle: no count, no title, no difference in the page.

    Masked, not raw — see `_without_csrf_tokens`. What is left after masking is the
    whole sentence a reader sees, and it does not move.
    """
    live = console
    live.client.cookies.clear()
    live.reset_mail()
    matched = live.link("ada@example.org")
    live.reset_mail()
    unmatched = live.link("nobody@example.org")

    assert matched.status_code == unmatched.status_code == 200
    assert _without_csrf_tokens(matched.text) == _without_csrf_tokens(unmatched.text)
    assert live.relay.sent == [], "a stranger's address was mailed somebody else's link"


def test_the_re_link_request_is_capped_per_post(console):
    """A bound on how many SMTP messages one form post can open, so a deployment
    with a thousand polls on one address does not turn one click into a thousand
    messages. The rate limit is the anti-spam control; this is the blast radius."""
    live = console
    live.client.cookies.clear()
    for i in range(capability.MAX_LINKS_PER_REQUEST + 3):
        db.create_poll(
            capability.anonymous_creator_id(),
            f"P{i}",
            None,
            "full_day",
            "UTC",
            [{"date": "2026-12-01"}],
            creator_email="bulk@example.org",
        )
    live.reset_mail()
    live.link("bulk@example.org")
    assert len(live.relay.sent) == capability.MAX_LINKS_PER_REQUEST


def test_the_re_link_request_is_rate_limited(console, monkeypatch):
    """It opens SMTP connections for an address the caller supplies, so it draws
    `send` — the same budget as every other send route."""
    live = console
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setitem(settings.RATE_LIMITS, "send", (1, 3600))
    live.client.cookies.clear()
    assert live.link("a@example.org").status_code == 200
    assert live.link("a@example.org").status_code == 429


def test_a_link_request_that_fans_out_is_charged_in_links_not_requests(console, monkeypatch):
    """One post can open several SMTP connections, so it is charged what it sends.

    With a budget of 3 and a request that matches 3 polls, charging the *request*
    (1) would allow it and 30 requests an hour would put 90 messages in one
    person's inbox. Charging the fan-out refuses it, which is the point: the
    operator's `send` number has to mean what it says on this route.
    """
    live = console
    live.client.cookies.clear()
    for i in range(3):
        db.create_poll(
            capability.anonymous_creator_id(), f"Bulk{i}", None, "full_day", "UTC",
            [{"date": "2026-12-01"}], creator_email="bulk@example.org",
        )
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setitem(settings.RATE_LIMITS, "send", (3, 3600))
    live.reset_mail()

    assert live.link("bulk@example.org").status_code == 429
    assert live.relay.sent == [], "a refused fan-out still sent mail"


def test_the_re_link_route_says_so_when_mail_is_unusable(console, monkeypatch):
    live = console
    live.client.cookies.clear()
    monkeypatch.setattr(email_service, "SMTP_HOST", "")
    response = live.link("ada@example.org")
    assert response.status_code == 503
    assert "Email is not available" in response.text


# -- 8. the review fixes, pinned --------------------------------------------


@pytest.mark.parametrize(
    "data",
    [
        {"title": "", "dates": ["2026-12-01"]},
        {"title": "T", "dates": ["2026-12-01"], "timezone": "Mars/Olympus"},
        {"title": "T", "dates": []},
        {"title": "T", "dates": ["2026-12-01"], "mode": "time_slot",
         "start_time_all": "", "end_time_all": "17:00"},
    ],
    ids=["empty-title", "bad-timezone", "no-dates", "no-times"],
)
def test_a_refused_creation_is_a_page_and_not_a_server_error(live, monkeypatch, data):
    """The shared validation path, in all four modes.

    This one exists because it *was* a 500: the accountless refusal renderer was
    declared with two arguments and called with one, so four ordinary inputs on the
    path ETH, demo and OIDC all share raised a TypeError. Capability mode's own
    refusals come from a different function, which is exactly why the new suite
    missed it and only a probe of the shared path found it.
    """
    payload = {"mode": "full_day", "timezone": "UTC", **data,
               "csrf": make_csrf(capability.ANON_FORM_UID)}
    assert live.client.post("/scheduler/new", data=payload).status_code == 400

    monkeypatch.setattr(settings, "AUTH_MODE", "header")
    payload["csrf"] = make_csrf("alice")
    assert live.client.post("/scheduler/new", data=payload,
                            headers={"X-User": "alice"}).status_code == 400
    assert live.polls == []


def test_the_flash_survives_the_state_that_follows_it(live):
    """`delete` redirects back to a poll that no longer exists.

    The console therefore falls back to the "no usable capability" page, and the
    flash has to be rendered *there* — otherwise the creator destroys their poll and
    is told they have no link, which reads as "Kairos lost it" rather than "you
    deleted it".
    """
    live.create()
    poll_id = live.poll()["id"]
    live.open(live.poll()["admin_token"])
    csrf = make_csrf(poll_id)
    assert live.client.post(f"/scheduler/manage/{poll_id}/delete", data={"csrf": csrf}).status_code == 302
    body = live.client.get("/scheduler/manage?msg=deleted").text
    assert "Poll deleted." in body


def test_a_refused_sender_is_not_reported_as_unconfigured_mail(live, monkeypatch):
    """#48's distinction survives into this surface.

    `web._mail_failure_msg()` exists so an operator chasing "no mail went out" is
    sent to the right knob. Conflating the two cases in the console would undo that
    for exactly the audience that cannot see the log.
    """
    live = live
    live.create()
    poll_id = live.poll()["id"]
    slot = db.get_poll(poll_id)["slots"][0]
    db.update_poll(poll_id, status="decided", decided_slot_id=slot["id"])
    db.create_invite(poll_id, "bob@example.org")

    monkeypatch.setattr(capability, "send_decision_email", lambda *a, **k: [])
    live.open(live.poll()["admin_token"])
    csrf = make_csrf(poll_id)
    response = live.client.post(f"/scheduler/manage/{poll_id}/email-decision", data={"csrf": csrf})
    assert response.status_code == 302
    assert response.headers["location"].endswith("msg=mailfail")

    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", "example.com")
    monkeypatch.setattr(email_service, "SMTP_FROM", "personal@gmail.com")
    monkeypatch.setattr(email_service, "_last_refusal_logged", None)
    response = live.client.post(f"/scheduler/manage/{poll_id}/email-decision", data={"csrf": csrf})
    assert response.headers["location"].endswith("msg=mailblocked")


def test_the_console_charges_the_budgets_the_owner_ui_charges(console, monkeypatch):
    """`invite` and `send` are charged here too, not only the per-poll budget.

    The per-peer budgets are what stop one source fanning out; ADR-0012's parity
    rule is about the *limits*, and a surface that honours only the per-poll one is
    not in parity. Charged in the handler because the rule follows the action, which
    a route-level dependency cannot see.
    """
    live = console
    charged = []
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(capability, "charge",
                        lambda request, rule, cost=1: charged.append((rule, cost)))
    poll_id = live.poll()["id"]
    live.client.post(f"/scheduler/manage/{poll_id}/invite",
                     data={"csrf": live.csrf, "email": "bob@example.org"})
    live.client.post(f"/scheduler/manage/{poll_id}/remind", data={"csrf": live.csrf})
    live.client.post(f"/scheduler/manage/{poll_id}/edit",
                     data={"csrf": live.csrf, "title": "T", "timezone": "UTC"})
    assert charged == [("invite", 1), ("send", 1)], "edit should cost nothing; sends must"


def test_an_anonymous_creation_refuses_a_poll_larger_than_the_slot_cap(live):
    """The cap on the *result*, and only that.

    In `time_slot` mode each date expands into `(end - start) / increment` rows, so
    a handful of form fields is enough to ask for thousands of writes -- and this
    request is anonymous. (python-multipart's own 1000-field ceiling bounds the
    field count, not the slot count, which is the one that matters here.) Turnstile
    (#31) is the real answer for the public surface; this is the structural bound in
    the meantime.

    Named for what it asserts. It used to claim the *expansion* was bounded, which
    was false and load-bearing: the cap runs after the slot list has been built, so
    it cannot bound what building it costs, and `increment=0` proved it — an
    unbounded loop in front of a cap that never got a chance to run. What bounds the
    expansion is the increment, before the loop; see
    `test_the_slot_step_bounds_are_what_make_the_loop_terminate`. This test covers
    the second line of defence and nothing more.
    """
    payload = {"title": "Wide", "creator_email": "ada@example.org", "mode": "time_slot",
               "start_time_all": "00:00", "end_time_all": "12:00", "increment": "1",
               "timezone": "UTC", "csrf": make_csrf(capability.ANON_FORM_UID),
               "dates": ["2026-01-05"] * 3}  # 3 x 720 = 2160 slots
    response = live.client.post("/scheduler/new", data=payload)
    assert response.status_code == 400
    assert "too large" in response.text
    assert live.polls == [], "an over-sized poll was created anyway"

    payload["dates"] = ["2026-01-05"]
    assert live.client.post("/scheduler/new", data=payload).status_code == 200
    assert len(db.get_poll(live.poll()["id"])["slots"]) == 720


def test_the_interstitial_does_not_leak_the_capability_through_the_referer(live):
    """The one page whose URL carries a credential must not pass it on.

    Same-origin assets would otherwise put the manage URL in their Referer header,
    which lands in access logs and in any analytics a deployment later adds.
    """
    live.create()
    response = live.client.get(f"/scheduler/manage/{live.poll()['admin_token']}")
    assert response.headers.get("Referrer-Policy") == "no-referrer"


def test_the_interstitial_states_the_real_session_lifetime(monkeypatch):
    """Not `default(12)` in a template.

    The page tells the creator how long their session lasts, so a deployment that
    sets KAIROS_CAPABILITY_SESSION_HOURS=2 and is told "12 hours" is a page making
    a security claim it does not honour. Driven through a re-imported module so the
    constant under test is the parsed one rather than a patched attribute.
    """
    probe = _reimport("capability.py", "kairos_cap_probe_interstitial", KAIROS_AUTH="capability",
                      KAIROS_CAPABILITY_SESSION_HOURS="2")
    assert probe.SESSION_HOURS == 2
    # `_reimport` restores AUTH_MODE on the way out; the route reads it at call time,
    # so it has to be put back for the request under test.
    monkeypatch.setattr(settings, "AUTH_MODE", "capability")
    monkeypatch.setattr(probe, "get_poll_by_admin_token",
                        lambda token: {"id": "p1", "title": "Retreat", "admin_token": token})
    monkeypatch.setattr(probe, "can_manage", lambda *a, **k: True)
    request = Request({"type": "http", "method": "GET", "path": "/manage/x", "query_string": b"",
                       "headers": [], "scheme": "https", "server": ("t", 443),
                       "client": ("t", 1), "root_path": ""})
    rendered = probe.manage_link("tok", request).body.decode()
    assert "2 hours" in rendered and "12 hours" not in rendered


def test_a_capability_boot_without_a_session_secret_refuses_to_boot(monkeypatch):
    """SESSION_SECRET is a hard requirement of this mode, not a warning.

    It signs the capability cookie, which is the only credential the console has,
    and `settings.session_secret()` raises at first use. As a warning this was a
    green boot, a 200 from `GET /manage` (the "no session" branch never touches the
    secret) and then a 500 on the two routes that actually mint or verify a cookie —
    so the failure looked like a bug and the log looked healthy. #53 refuses to boot
    on a missing allowlist for the same reason, and the gate costs the other modes
    nothing because they never reach this line. Driven through a re-import, because
    the thing being asserted is module-level code.
    """
    monkeypatch.setattr(settings, "AUTH_MODE", "capability")
    monkeypatch.delenv("SESSION_SECRET", raising=False)
    with pytest.raises(RuntimeError) as exc:
        _reimport("capability.py", "kairos_cap_probe_nosecret", KAIROS_AUTH="capability")
    assert "SESSION_SECRET" in str(exc.value)
    assert "openssl rand -hex 32" in str(exc.value), "the refusal has to say what to do"
    # And the rest of the mode's mail surface is unreachable rather than half-working.
    assert "SESSION_SECRET is unset" not in " ".join(capability.boot_warnings())


def test_a_missing_session_secret_does_not_affect_any_other_mode(monkeypatch):
    """The other half of the gate: this may not become a new way to break a
    self-hoster who never asked for capability mode (ADR-0001/0002).

    `KAIROS_AUTH=header` with no SESSION_SECRET in the environment must still
    import cleanly, which is the whole reason the refusal sits under `enabled()`.
    """
    monkeypatch.delenv("SESSION_SECRET", raising=False)
    for mode in ("header", "demo", "oidc", "none"):
        module = _reimport("capability.py", f"kairos_cap_probe_nosecret_{mode}", KAIROS_AUTH=mode)
        assert module.enabled() is False


def test_a_capability_boot_without_rate_limits_says_so(monkeypatch):
    """With the shipped defaults this mode is an open mail relay from its own
    domain: `create` and the re-link request are both anonymous, and #37's budgets
    are opt-in (ADR-0001/0002). Saying so at boot is the difference between an
    operator who read it and one who found out.
    """
    monkeypatch.setattr(settings, "AUTH_MODE", "capability")
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", False)
    warnings = " ".join(capability.boot_warnings())
    assert "unbounded per source" in warnings and "KAIROS_RATE_LIMIT=on" in warnings
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    assert "unbounded per source" not in " ".join(capability.boot_warnings())


# -- 8. what this did NOT touch ----------------------------------------------


def test_header_mode_creation_is_unchanged(tmp_path, monkeypatch):
    """The ETH invariant, on the one route #30 edited.

    Header mode still creates the poll it always did: creator_id and owner_id both
    the proxy uid, creator_email NULL (only the accountless flow mails a link),
    and a 302 to the poll page.
    """
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/header.db")
    db.init_schema()
    client = TestClient(
        main.create_app(), base_url="https://testserver", headers={"X-User": "alice"},
        follow_redirects=False,
    )
    response = client.post(
        "/scheduler/new",
        data={
            "title": "Retreat",
            "dates": ["2026-12-01"],
            "mode": "full_day",
            "timezone": "Europe/Zurich",
            "csrf": make_csrf("alice"),
        },
    )
    assert response.status_code == 302
    assert response.headers["location"].startswith("/scheduler/polls/")

    poll = db.list_polls("alice")[0]
    assert poll["creator_id"] == "alice"
    assert poll["owner_id"] == "alice"
    assert poll["creator_email"] is None


def test_get_user_stays_the_seam_and_resolves_nothing_in_this_mode(live):
    """`auth.get_user` keeps its shape: in capability mode there is no account, so
    it resolves nothing — it does not become a capability resolver.

    That is deliberate. An identity here would have to equal `creator_id` for the
    existing owner pages to work, which would make the placeholder creator
    load-bearing for authorization; and leaving the seam alone is what keeps
    #63/#64 (per-poll authorization) unaware that this mode exists.
    """
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/manage",
            "query_string": b"",
            "headers": [],
            "scheme": "https",
            "server": ("t", 443),
            "client": ("t", 1),
            "root_path": "",
        }
    )
    assert settings.AUTH_MODE == "capability"
    assert auth.get_user(request) is None
    assert callable(auth.get_user), "the seam must stay replaceable at runtime"


def test_no_route_in_this_feature_compares_a_token_or_an_owner_by_hand():
    """A tripwire, in the spirit of #29's: every authorization decision in the
    capability surface goes through `require_manage`, so an inline comparison
    creeping back is visible here."""
    source = (SRC / "capability.py").read_text()
    assert "compare_digest" not in source, "token comparison belongs to auth._token_manages"
    assert not re.search(r"""\["creator_id"\]\s*[!=]=\s*(session|token)""", source)
    assert "require_manage(" in source
    assert "can_manage(" in source


# -- 9. the second review round, pinned ---------------------------------------
#
# Everything below was found by a fresh-context review of this branch rather than by
# this branch's own tests, and each item says what it was, because a test whose
# comment only says "still true" teaches the next reader nothing.


def _backdate(poll_id, when="2000-01-01 00:00:00"):
    """Move one poll to the far end of the newest-first ordering.

    `created_at` is `CURRENT_TIMESTAMP` — one-second resolution — so "newest first"
    is a tie among rows created in the same test, and a test that relied on the tie
    would be asserting on SQLite's row order rather than on this route.
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE sched_polls SET created_at = %s WHERE id = %s", (when, poll_id))
    conn.commit()
    cursor.close()
    conn.close()


def _creation_post(live, data, header_uid=None):
    """POST the creation form in whichever mode is currently in force."""
    payload = {"title": "Wide", "mode": "time_slot", "timezone": "UTC",
               "start_time_all": "09:00", "end_time_all": "17:00",
               "csrf": make_csrf(capability.ANON_FORM_UID if header_uid is None else header_uid),
               **data}
    headers = {"X-User": header_uid} if header_uid else {}
    return live.client.post("/scheduler/new", data=payload, headers=headers)


@pytest.mark.parametrize(
    "increment", ["0", "-5", "-1440", "x", "", "1.5", "1441", "100000", "0x10", "30min", "1e3"],
    ids=["zero", "negative", "negative-day", "text", "empty", "float", "over-a-day", "absurd",
         "hex", "suffixed", "exponent"],
)
def test_an_anonymous_creation_refuses_an_increment_that_cannot_terminate_the_loop(
    live, monkeypatch, increment
):
    """**This was an unauthenticated OOM.** Measured against a real uvicorn in this
    mode with shipped defaults and no credential at all (the anon CSRF token is
    scraped off the public `/new` form): `increment=0` took the process from 59 MB
    to 2.1 GB without answering, and anyio's 40-thread default meant ~40 requests
    were enough to take the deployment down. `/health` kept answering, so it read
    as a hang rather than a crash.

    `while t + timedelta(minutes=increment) <= t_end` never advances `t` when
    `increment <= 0`, so it appends a slot forever. The bound this branch advertises
    (`MAX_SLOTS_PER_ACCOUNTLESS_POLL`) was checked *after* the loop, which cannot
    bound what building the list costs — so the PR claimed a bound the loop did not
    have. These are refusals now, before the loop, and both halves of the old line
    are here: a value that cannot terminate it, and a value that is not an int
    (`increment=x` was a `ValueError` → 500 on an anonymous route).

    Run in both modes, because #30 made an owner-only form anonymous and the field
    is on the shared path: a 500 in header mode is an authenticated 500, and a 400
    is what every other field on this form already does.
    """
    response = _creation_post(live, {"increment": increment, "dates": ["2026-01-05"]})
    assert response.status_code == 400, "an unbounded increment must be refused, not served"
    assert live.polls == [], "a refused creation still wrote a row"

    monkeypatch.setattr(settings, "AUTH_MODE", "header")
    owner = _creation_post(live, {"increment": increment, "dates": ["2026-01-05"]}, header_uid="alice")
    assert owner.status_code == 400
    assert live.polls == [], "a refused creation still wrote a row"


@pytest.mark.parametrize(
    ("field", "value"),
    [("start_time_all", "25:00"), ("start_time_all", "noon"), ("end_time_all", "99:99"),
     ("end_time_all", "5pm"), ("start_time_all", "09:00:00")],
)
def test_an_anonymous_creation_refuses_a_clock_it_could_not_parse(live, field, value):
    """**The same bug on the two fields above it, found while fixing that one.**
    `datetime.strptime` raises `ValueError` on all five of those, out of the route,
    on an anonymous POST — a sixth 500 on this path, in the same three lines. The
    empty-string case was already refused (and pinned); every other unparseable
    clock was not, which is why the existing test gave a false sense of coverage.
    """
    response = _creation_post(live, {field: value, "dates": ["2026-01-05"]})
    assert response.status_code == 400
    assert live.polls == []


def test_the_slot_step_bounds_are_what_make_the_loop_terminate():
    """The numbers, and where they live.

    Two properties, both load-bearing. The *values*: `increment >= 1` is the only
    reason the `while` advances at all, and 1440 is one day, so the worst case is
    1440 iterations and 1440 slots for one date. The *location*: the validation and
    the loop are in one function, asserted with `inspect` rather than by reading,
    because "the bound is over there, in the caller" is precisely how an unbounded
    anonymous loop ships with a slot cap three frames away from it.
    """
    assert web.MIN_INCREMENT_MINUTES >= 1, "increment <= 0 makes the loop immortal"
    assert web.MAX_INCREMENT_MINUTES <= 1440, "the window is bounded by the day"

    source = inspect.getsource(web._expand_time_slots)
    assert "_bounded_int(" in source and "while " in source, \
        "the increment bound and the loop it bounds must be one function"

    slots, error = web._expand_time_slots(
        {"start_time_all": "00:00", "end_time_all": "23:59", "increment": "1"}, ["2026-01-05"]
    )
    assert error is None
    assert len(slots) == 1439, "one slot per minute of the widest possible window"
    assert slots[0]["start_time"] == "00:00" and slots[-1]["end_time"] == "23:59"

    for bad in ("0", "-1", "x", "", "1441"):
        slots, error = web._expand_time_slots(
            {"start_time_all": "09:00", "end_time_all": "17:00", "increment": bad}, ["2026-01-05"]
        )
        assert error is not None and slots == [], f"increment={bad!r} was accepted"

    # Deliberately *not* refusals, stated so nobody "tightens" them later: " 30 " and
    # "٣٠" are both the number 30 to `int`, and a form field is typed by a human who
    # pasted it. Refusing a padded number would be pedantry, not a bound.
    for padded in (" 30 ", "30\t", "٣٠", "+30"):
        slots, error = web._expand_time_slots(
            {"start_time_all": "09:00", "end_time_all": "17:00", "increment": padded}, ["2026-01-05"]
        )
        assert error is None and len(slots) == 16, f"{padded!r} should read as 30 minutes"


def test_the_re_link_request_refuses_a_post_no_page_of_this_app_rendered(console):
    """**This was a drive-by mail primitive.** The creation form has been
    CSRF-bound since it was written; this one was not, and it is the anonymous POST
    that sends mail. Measured: 26 cross-origin form posts with no cookie and no
    token, and 26 manage-link mails sent to an address the attacker chose — from
    this deployment's own sender, domain and branding. The mail only goes to an
    address that already created a poll here, so the attacker learns nothing they
    could not read; what they get is the ability to make somebody else's
    deployment send mail, on demand, for free.

    The check is CSRF, not authorization: the uid is a constant, so a direct
    attacker scrapes the token off `/manage` in one request. What it removes is the
    *drive-by*, which is what a cross-site form post is.
    """
    live = console
    live.client.cookies.clear()
    live.reset_mail()
    # No token at all.
    assert live.client.post("/scheduler/manage/link", data={"email": "ada@example.org"}).status_code == 403
    # The creation form's token is not this form's token — one page's token is not
    # replayable at the other form on the same origin.
    assert live.client.post(
        "/scheduler/manage/link",
        data={"email": "ada@example.org", "csrf": make_csrf(capability.ANON_FORM_UID)},
    ).status_code == 403
    assert live.relay.sent == [], "a refused cross-origin post still sent mail"
    # And the real form still works, which is the half a CSRF change usually breaks.
    assert live.link("ada@example.org").status_code == 200
    assert len(live.relay.sent) == 1


@pytest.mark.parametrize("stage", ["signed-out", "console"])
def test_both_link_forms_render_the_token_the_route_checks(live, stage):
    """The template half of the check above.

    A CSRF requirement with no matching hidden field is a 403 on every legitimate
    click, and it is the failure mode that gets "fixed" by removing the check. Both
    forms — the one on the signed-out page and the one in the console footer — must
    carry the binding `request_link` verifies.
    """
    if stage == "console":
        live.create()
        live.open(live.poll()["admin_token"])
    page = live.client.get("/scheduler/manage").text
    match = re.search(
        r'action="[^"]*/manage/link".*?name="csrf" value="([^"]+)"', page, re.DOTALL
    )
    assert match, f"the {stage} page has no CSRF token on its link-request form"
    assert match.group(1) == make_csrf(capability.LINK_FORM_UID)


def test_the_re_link_answer_holds_a_time_floor_so_the_fan_out_is_not_a_timing_oracle(console):
    """**The body was byte-identical and the response time was not.** Measured
    against a real relay: 0.254s for an address with polls, 0.003s for one without —
    87x, from the SMTP connection a match opens and a miss does not. Same oracle, in
    a channel nobody reads, and not a harmless one: it confirms which addresses have
    created a poll here, and the Subject line of the mail a real hit triggers
    ("Your manage link: Quarterly planning") then leaks the titles.

    The floor is a mitigation, not a proof, and the constant says so: a relay slower
    than the floor still shows through, and the real fix is queueing the mail and
    answering before SMTP. What is asserted here is the part that is in this
    branch's hands — a match cannot be *faster* than the floor, so the direction
    that carries the bit is gone.
    """
    live = console
    live.client.cookies.clear()
    assert capability.LINK_REQUEST_FLOOR_SECONDS >= 0.25, \
        "the floor has to cover the fan-out it is hiding, or it hides nothing"

    started = time.monotonic()
    matched = live.link("ada@example.org")
    hit = time.monotonic() - started
    started = time.monotonic()
    unmatched = live.link("nobody@example.org")
    miss = time.monotonic() - started

    assert matched.status_code == unmatched.status_code == 200
    assert _without_csrf_tokens(matched.text) == _without_csrf_tokens(unmatched.text)
    assert miss >= capability.LINK_REQUEST_FLOOR_SECONDS
    assert hit >= capability.LINK_REQUEST_FLOOR_SECONDS
    assert abs(hit - miss) < capability.LINK_REQUEST_FLOOR_SECONDS / 2, \
        f"the hit and the miss still differ in time by {abs(hit - miss):.3f}s"


def test_a_capability_cookie_is_verified_by_its_signature_and_by_nothing_else(live):
    """**The signature was untested.** Replacing the signed `loads` in
    `read_session` with an unsigned base64 decode left 809/809 green: every
    refusal test in the file is refused by a second gate as well — a junk string is
    not JSON, a rotated token fails `require_manage`'s row comparison — so the one
    thing enforcing `max_age` and unforgeability was never the thing doing the
    rejecting, and nothing noticed.

    So this test is a pair that differ in exactly one byte of input: the same
    payload, naming the same poll and carrying that poll's *real* capability, signed
    with a different secret. `require_manage` would accept it — the row matches — so
    if it is refused, the signature is the reason.
    """
    live.create(title="Retreat")
    poll = live.poll()
    payload = {"pid": poll["id"], "at": poll["admin_token"]}

    # Control: this deployment's own signature. The console opens.
    live.client.cookies.set(capability.SESSION_COOKIE, _signed_cookie(poll["id"], poll["admin_token"]))
    assert "Retreat" in live.client.get("/scheduler/manage").text

    forged = URLSafeTimedSerializer("a-different-secret", salt="cap-session").dumps(payload)
    assert forged != _signed_cookie(poll["id"], poll["admin_token"])
    live.client.cookies.set(capability.SESSION_COOKIE, forged)
    assert "Open your manage link" in live.client.get("/scheduler/manage").text


def test_a_capability_cookie_past_its_lifetime_is_refused_despite_a_valid_signature(live, monkeypatch):
    """The other half of what the signature is for.

    A correctly signed cookie older than `SESSION_MAX_AGE` is the one thing a
    weakened verifier would let through, and `read_session` is the only place that
    knows the age — `require_manage` compares a token and cannot. `time.time` is
    patched rather than the parsed constant, because expiry is computed by
    itsdangerous at verification time.
    """
    live.create(title="Retreat")
    poll = live.poll()
    cookie = _signed_cookie(poll["id"], poll["admin_token"])
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + capability.SESSION_MAX_AGE + 60)
    live.client.cookies.set(capability.SESSION_COOKIE, cookie)
    assert "Open your manage link" in live.client.get("/scheduler/manage").text


def test_a_creator_with_more_polls_than_the_cap_still_gets_their_link(console):
    """**Filter, then cap — the order was the bug.** The route did
    `list_polls_by_creator_email(email)[:MAX_LINKS_PER_REQUEST]` and filtered
    afterwards, on a newest-first list. Every poll minted since #29 carries a
    capability, so a creator with ten recent polls and one *older* poll that still
    does (a pre-#29 row, or one created through the API) matched nothing, was sent
    nothing, and was told to check an inbox that would stay empty — on the one route
    that exists to get a spent-link creator back in.

    The NULL rows here stand in for both of those cases; they are what the filter
    exists for.
    """
    live = console
    live.client.cookies.clear()
    original = live.poll()  # the one poll that still has a capability is the oldest
    _backdate(original["id"])
    for i in range(capability.MAX_LINKS_PER_REQUEST + 2):
        unlinkable = db.create_poll(
            capability.anonymous_creator_id(), f"NoCap{i}", None, "full_day", "UTC",
            [{"date": "2026-12-01"}], creator_email="ada@example.org",
        )
        _null_out_capability(unlinkable["id"])
    live.reset_mail()

    response = live.link("ada@example.org")
    assert response.status_code == 200 and "Check your inbox" in response.text
    assert len(live.relay.sent) == 1
    assert f"/scheduler/manage/{original['admin_token']}" in live.relay.sent[0].as_string()


def test_the_bounds_on_this_mode_are_pinned_by_this_suite():
    """`MAX_LINKS_PER_REQUEST` was unpinned: raising 10 → 1000 left 809/809 green.

    It is the only bound on the re-link fan-out, and the rate limit is the operator's
    number rather than ours, so a bound nobody asserts is a number that gets widened
    by accident and reviewed by nobody. The slot cap is here for the same reason,
    and the increment bounds because they are what terminate the loop above.
    """
    assert capability.MAX_LINKS_PER_REQUEST == 10
    assert capability.MAX_SLOTS_PER_ACCOUNTLESS_POLL == 1000
    assert (web.MIN_INCREMENT_MINUTES, web.MAX_INCREMENT_MINUTES) == (1, 1440)
    # And the fan-out is charged in links, so the bound above is the blast radius a
    # single form post can open against a relay.
    assert capability.MAX_LINKS_PER_REQUEST <= settings.RATE_LIMITS["send"][0] or \
        not settings.RATE_LIMIT_ENABLED


def test_the_loser_of_a_rotation_does_not_stamp_the_verification_column(live):
    """**Wrong order for the consumer.** `mark_manage_verified` ran *before* the
    compare-and-swap, so the loser of a race — the stale link, replayed a moment
    after the creator used it, which is exactly what a mail prefetcher or a stale
    tab does — stamped `manage_verified_at`. That column is dead today, but #31
    gates sends on it, and the flag it is meant to carry ("this creator proved they
    read the mail we sent") would be set by a request that never won the capability.

    Simulated by rotating first, which is what the racing winner does.
    """
    live.create()
    poll = live.poll()
    assert db.rotate_admin_token(poll["id"], poll["admin_token"])  # the other device wins
    assert live.open(poll["admin_token"]).status_code == 404
    assert live.poll()["manage_verified_at"] is None, \
        "a refused exchange stamped the column #31 will gate sends on"


def test_the_creator_address_is_not_written_to_the_log(live, caplog):
    """A stranger's address at INFO, in a log an operator ships to a collector, for a
    poll the operator cannot see. The poll id is enough to find the row; whoever
    wants the address has it in the database.
    """
    caplog.set_level(logging.DEBUG, logger="kairos")
    live.create(email="ada@example.org")
    live.open(live.poll()["admin_token"])
    live.link("ada@example.org")
    assert "ada@example.org" not in caplog.text
    # The poll id is still there, so this is a redaction and not a silence.
    assert live.poll()["id"] in caplog.text
