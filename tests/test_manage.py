"""Obligation S6 (#29): one management predicate, over four nullable columns.

Three things are pinned here, because each is a promise the next two steps in the
chain (#30 `/manage/<token>`, #31 the `manage_verified_at` send-gate) will build
on and cannot afford to discover is false:

1. **The migration is additive.** A pre-existing `sched_polls` gains four
   nullable columns and a unique index; every existing row reads NULL in all
   four, and `init_schema()` stays idempotent. That is the whole of the ETH /
   self-host guarantee: byte-for-byte the same behaviour when the columns are
   null.
2. **One predicate, consulted by every mutating owner route.** The route tests
   below spy on `require_manage` and stop execution there, so they assert
   *where authorization happens* rather than what each route does next.
3. **The management capability is a secret.** `admin_token` is minted with the
   entropy ADR-0001 fixes for every other capability, is unique per poll, is
   compared in constant time, and never reaches an API response or a log line.

NOT in this file, by design: the `/manage/<token>` route, the magic-link mail,
`KAIROS_AUTH=capability`, and the send-gate. Those are #30 and #31; what they
need from here is `require_manage`, `manage_verified_at` (readable, never
written), and a token they can resolve.
"""

import json
import logging
import re
import secrets
import sqlite3
import string
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from kairos import main, settings, web
from kairos.auth import can_manage, get_user, require_manage
from kairos.csrf import make_csrf

SRC = Path(__file__).resolve().parent.parent / "src" / "kairos"

# The pre-#29 shape of sched_polls, spelled out rather than imported: the point
# of a migration test is the *old* table, and a future edit to SCHEMA must not
# silently change what "old" means to it.
LEGACY_POLL_DDL = """CREATE TABLE sched_polls (
    id VARCHAR(36) PRIMARY KEY,
    creator_id VARCHAR(36) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    mode ENUM('full_day', 'time_slot') NOT NULL,
    timezone VARCHAR(64) DEFAULT 'Europe/Zurich',
    public_token VARCHAR(64) UNIQUE NOT NULL,
    status ENUM('open', 'closed', 'decided') DEFAULT 'open',
    decided_slot_id VARCHAR(36),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)"""

NEW_COLUMNS = ("admin_token", "owner_id", "creator_email", "manage_verified_at")


def sqlite_ify(ddl: str) -> str:
    """The two rewrites db.py applies to SCHEMA for SQLite: no ENUM, no ON UPDATE."""
    return re.sub(r"ENUM\([^)]*\)", "TEXT", ddl).replace(" ON UPDATE CURRENT_TIMESTAMP", "")


def request_from(uid: str | None = None) -> Request:
    """A bare ASGI request; the test env runs `KAIROS_AUTH=header` (conftest)."""
    headers = [(b"x-user", uid.encode())] if uid else []
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "headers": headers,
            "scheme": "https",
            "server": ("test", 443),
            "client": ("testclient", 51000),
            "root_path": "",
        }
    )


@pytest.fixture
def live_db(tmp_path, monkeypatch):
    """A real on-disk SQLite DB. `get_connection()` reads settings.DB_URL at call
    time, so repointing it needs no module reload (see test_dashboard_queries)."""
    path = tmp_path / "kairos.db"
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{path}")

    from kairos import db

    db.init_schema()
    return db, sqlite3.connect(path)


@pytest.fixture
def live_client(tmp_path, monkeypatch):
    """The real app on a real SQLite file, in header mode (the ETH shape)."""
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{tmp_path}/live.db")

    from kairos.main import create_app

    with TestClient(create_app(), base_url="https://testserver") as client:
        yield client


# -- 1. the migration ------------------------------------------------------


def test_a_fresh_install_gets_the_columns_from_the_migration_not_the_ddl(live_db):
    """The four columns are deliberately absent from SCHEMA, added only by
    `_ensure_column`. That is fine only because init_schema() always runs, on a
    fresh database as much as on an old one -- this is the test that says so.
    """
    db, conn = live_db
    columns = {row[1] for row in conn.execute("PRAGMA table_info(sched_polls)")}
    assert set(NEW_COLUMNS) <= columns
    assert "CREATE TABLE IF NOT EXISTS sched_polls" in "\n".join(db.SCHEMA)
    assert not any("admin_token" in stmt for stmt in db.SCHEMA)


def test_a_pre_existing_table_migrates_and_every_existing_row_stays_null(live_db):
    db, conn = live_db
    conn.execute("DROP TABLE sched_polls")
    conn.execute(sqlite_ify(LEGACY_POLL_DDL))
    conn.execute(
        "INSERT INTO sched_polls (id, creator_id, title, mode, public_token)"
        " VALUES ('legacy1', 'alice', 'Old poll', 'full_day', 'pub-legacy')"
    )
    conn.commit()

    assert "admin_token" not in {row[1] for row in conn.execute("PRAGMA table_info(sched_polls)")}
    db.init_schema()  # the migration, over a table that predates it

    row = db.get_poll("legacy1")
    assert {col: row[col] for col in NEW_COLUMNS} == dict.fromkeys(NEW_COLUMNS)
    assert (row["creator_id"], row["title"], row["public_token"], row["status"]) == (
        "alice",
        "Old poll",
        "pub-legacy",
        "open",
    )
    db.init_schema()  # idempotent: boot happens on every start


def test_the_migration_is_safe_to_run_on_a_table_that_already_has_them(live_db):
    db, _ = live_db
    poll = db.create_poll("alice", "Twice", None, "full_day", "UTC", [{"date": "2026-01-01"}])
    db.init_schema()
    assert db.get_poll(poll["id"])["admin_token"] == poll["admin_token"]


def test_a_management_capability_can_name_only_one_poll(live_db):
    db, conn = live_db
    db.create_poll("alice", "One", None, "full_day", "UTC", [{"date": "2026-01-01"}])
    db.create_poll("alice", "Two", None, "full_day", "UTC", [{"date": "2026-01-01"}])
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE sched_polls SET admin_token = 'shared' WHERE title = 'Two'")
        conn.execute("UPDATE sched_polls SET admin_token = 'shared' WHERE title = 'One'")
        conn.commit()


def test_the_migration_adds_the_unique_index_only_once(live_db):
    db, conn = live_db
    db.init_schema()
    names = {row[1] for row in conn.execute("PRAGMA index_list(sched_polls)")}
    assert "idx_sched_polls_admin_token" in names


def test_create_poll_mints_a_capability_of_the_advertised_entropy(live_db):
    """ADR-0001: capability tokens are `secrets.token_urlsafe(32)` and never
    logged. `admin_token` uses the one generator in the codebase (db.new_token),
    so it cannot drift from `public_token` or an invite token."""
    db, _ = live_db
    minted = []
    for i in range(20):
        poll = db.create_poll("alice", f"P{i}", None, "full_day", "UTC", [{"date": "2026-01-01"}])
        token = poll["admin_token"]
        assert len(token) == len(secrets.token_urlsafe(32)) == 43
        assert set(token) <= set(string.ascii_letters + string.digits + "-_")
        assert token != poll["public_token"]
        assert poll["owner_id"] is None and poll["creator_email"] is None
        # #31's send-gate is closed until someone verifies the creator, so a new
        # poll must never be born verified.
        assert poll["manage_verified_at"] is None
        minted.append(token)
    assert len(set(minted)) == len(minted)


def test_create_poll_records_the_owner_it_is_given(live_db):
    db, _ = live_db
    poll = db.create_poll(
        "alice",
        "Owned",
        None,
        "full_day",
        "UTC",
        [{"date": "2026-01-01"}],
        owner_id="acct-1",
        creator_email="alice@example.org",
    )
    stored = db.get_poll(poll["id"])
    assert (stored["owner_id"], stored["creator_email"]) == ("acct-1", "alice@example.org")


# -- 2. the predicate ------------------------------------------------------


POLL = {"id": "p1", "creator_id": "alice", "owner_id": None, "admin_token": None}


def test_the_creator_may_manage_their_poll_without_any_token():
    assert can_manage(POLL, request_from("alice")) is True
    assert can_manage(POLL, request_from()) is False


def test_the_named_owner_may_manage_a_poll_they_did_not_create():
    poll = dict(POLL, owner_id="acct-1")
    assert can_manage(poll, request_from("acct-1")) is True
    assert can_manage(poll, request_from("mallory")) is False


def test_nobody_else_may_manage():
    assert can_manage(POLL, request_from("mallory")) is False


def test_a_capability_manages_an_accountless_poll_with_no_owner_at_all():
    """What #30 will rely on: owner_id NULL, creator_id a placeholder, and the
    token in the URL is the whole of the authority."""
    poll = dict(POLL, creator_id="anon", admin_token="s3cret")
    anonymous = request_from()
    assert can_manage(poll, anonymous) is False
    assert can_manage(poll, anonymous, token="s3cret") is True
    assert can_manage(poll, anonymous, token="s3cre") is False
    assert can_manage(poll, anonymous, token="s3crets") is False


def test_a_capability_is_scoped_to_its_own_poll():
    mine, theirs = dict(POLL, admin_token="mine"), dict(POLL, id="p2", admin_token="theirs")
    assert can_manage(mine, request_from(), token="theirs") is False
    assert can_manage(theirs, request_from(), token="mine") is False


def test_a_poll_without_a_token_fails_closed():
    """The legacy-row case, and the one that must not silently pass: NULL means
    no capability was ever minted, so presenting one must match nothing."""
    for poll in (dict(POLL), dict(POLL, admin_token=None), {"id": "p1", "creator_id": "alice"}):
        assert can_manage(poll, request_from(), token="anything") is False


def test_an_absent_uid_cannot_authorize_through_the_identity_path():
    """Regression: the identity test used to be `uid in (creator_id, owner_id)`,
    and `None in (None, None)` is True. `owner_id` IS NULL on every pre-#29 row
    and on every accountless poll, so a seam returning `{"uid": None}` for "not
    logged in" -- the natural shape for the session-cookie portal `get_user` is
    documented to serve -- granted management of every such poll.

    Not reachable through the stock `get_user` (demo returns "demo", header
    rejects an empty uid, none returns None), which is why it survived review of
    the first cut: the bug needed the seam, not a request.
    """
    legacy = {"creator_id": "alice", "owner_id": None}
    accountless = {"creator_id": "anon", "owner_id": None}
    for user in ({"uid": None}, {"uid": ""}, {"uid": False}, {}):
        for poll in (legacy, accountless, {}):
            assert can_manage(poll, request_from(), user=user) is False, (poll, user)
            with pytest.raises(HTTPException) as exc:
                require_manage(poll, request_from(), user=user)
            assert exc.value.status_code == 403

    # Not over-corrected: a real uid, and a correct token, still authorize.
    assert can_manage(legacy, request_from(), user={"uid": "alice"}) is True
    with_token = dict(accountless, admin_token="s3cret")
    assert can_manage(with_token, request_from(), user={"uid": None}, token="s3cret") is True
    with pytest.raises(HTTPException):
        require_manage(with_token, request_from(), user={"uid": None}, token="wrong")


def test_a_capability_is_only_presented_on_request_never_inferred():
    """`public.py` has routes whose `{token}` path parameter is a public_token.
    The predicate must not go looking in the request for one."""
    request = request_from()
    request.scope["path_params"] = {"token": "mine"}
    assert can_manage(dict(POLL, admin_token="mine"), request) is False


def test_a_non_ascii_capability_is_refused_rather_than_crashing():
    """hmac.compare_digest raises TypeError on a non-ASCII str, and a capability
    arrives from a URL -- so this must be a 403, not a 500."""
    poll = dict(POLL, admin_token="s3cret")
    assert can_manage(poll, request_from(), token="süß") is False
    with pytest.raises(HTTPException) as exc:
        require_manage(poll, request_from(), token="süß")
    assert exc.value.status_code == 403


def test_a_capability_of_an_unexpected_type_is_refused_rather_than_crashing():
    """Neither side of the comparison is type-checked by the caller, and both
    failure modes are exceptions rather than refusals: a non-ASCII str is a
    TypeError from compare_digest, a bytes value is an AttributeError from
    `.encode()`. A row from a hand-rolled `get_poll` seam could be either."""
    for stored, presented in ((b"bytes-token", "bytes-token"), ("bytes-token", b"bytes-token")):
        poll = dict(POLL, admin_token=stored)
        assert can_manage(poll, request_from(), token=presented) is False
        with pytest.raises(HTTPException) as exc:
            require_manage(poll, request_from(), token=presented)
        assert exc.value.status_code == 403


def test_the_capability_comparison_is_constant_time(monkeypatch):
    """Not the arithmetic (untestable from outside), but that the comparison
    goes through hmac: a plain `==` would leak the token a byte at a time."""
    import hmac

    seen = []
    real = hmac.compare_digest
    monkeypatch.setattr(hmac, "compare_digest", lambda a, b: (seen.append((a, b)), real(a, b))[1])

    assert can_manage(dict(POLL, admin_token="s3cret"), request_from(), token="s3cret")
    assert seen == [(b"s3cret", b"s3cret")]


def test_require_manage_returns_the_poll_it_authorised():
    poll = dict(POLL, creator_id="alice")
    assert require_manage(poll, request_from("alice")) is poll


def test_require_manage_is_403_for_anonymous_and_for_a_stranger_alike():
    """Neither is entitled to learn more than "not the owner"."""
    for request in (request_from(), request_from("mallory")):
        with pytest.raises(HTTPException) as exc:
            require_manage(POLL, request)
        assert exc.value.status_code == 403
        assert exc.value.detail == "Not the poll owner"


def test_require_manage_does_not_need_an_authenticated_user():
    """An anonymous capability route (#30) calls it with no identity at all --
    which is why it does not wrap require_auth."""
    poll = dict(POLL, creator_id="anon", admin_token="s3cret")
    assert require_manage(poll, request_from(), token="s3cret") is poll


def test_require_manage_honours_a_pre_resolved_identity_without_asking_again(monkeypatch):
    """`auth.get_user` is a documented runtime seam whose replacement need not be
    idempotent, so a route that already authenticated passes the user it holds."""
    import kairos.auth as auth

    def boom(_request):
        raise AssertionError("get_user must not be consulted twice")

    monkeypatch.setattr(auth, "get_user", boom)
    assert require_manage(POLL, request_from("alice"), user={"uid": "alice"}) is POLL

    # Omitting `user` is the anonymous-capability case (#30): resolve it here.
    monkeypatch.setattr(auth, "get_user", lambda request: {"uid": "alice"})
    assert require_manage(POLL, request_from("alice")) is POLL


def test_the_predicate_reads_the_poll_with_get_not_subscript():
    """A row/row-dict from before these columns must authorize exactly as it
    always did -- the property that keeps every existing test, and every existing
    deployment, byte-for-byte unchanged."""
    legacy = {"id": "p1", "creator_id": "alice"}
    assert can_manage(legacy, request_from("alice")) is True
    assert can_manage(legacy, request_from("mallory")) is False


# -- 3. the routes authorize through it ------------------------------------


class _Reached(Exception):
    """Raised by the spy to stop the request at the gate."""


POLL_STUB = {
    "id": "p1",
    "creator_id": "testuser",
    "title": "Retreat",
    "description": None,
    "mode": "full_day",
    "timezone": "Europe/Zurich",
    "status": "open",
    "decided_slot_id": None,
    "public_token": "tok123",
    "manage_verified_at": None,
    "slots": [{"id": "s1", "date": "2026-06-08", "start_time": None, "end_time": None}],
}

MUTATING_ROUTES = [
    ("/scheduler/polls/p1/close", {}),
    ("/scheduler/polls/p1/reopen", {}),
    ("/scheduler/polls/p1/decide", {"slot_id": "s1"}),
    ("/scheduler/polls/p1/edit", {"title": "New", "timezone": "UTC"}),
    ("/scheduler/polls/p1/remind", {}),
    ("/scheduler/polls/p1/remind-selected", {"emails": "a@b.ch"}),
    ("/scheduler/polls/p1/email-decision", {}),
    ("/scheduler/polls/p1/invite", {"email": "a@b.ch"}),
    ("/scheduler/polls/p1/participants/update", {"kind": "invite", "ref": "i1"}),
    ("/scheduler/polls/p1/participants/remove", {"kind": "invite", "ref": "i1"}),
]


@pytest.fixture
def owner_routes(monkeypatch):
    """A signed-in owner with the DB stubbed, as tests/test_routes.py does."""
    monkeypatch.setattr(web, "get_user", lambda request: {"uid": "testuser", "name": "T"})
    monkeypatch.setattr(web, "require_csrf", lambda user, form: None)
    monkeypatch.setattr(web, "get_poll", lambda pid: dict(POLL_STUB))
    monkeypatch.setattr(web, "get_notifications", lambda uid, unread_only=False: [])
    return TestClient(main.app, base_url="https://testserver")


@pytest.mark.parametrize("path,data", MUTATING_ROUTES)
def test_every_mutating_owner_route_authorizes_through_the_predicate(owner_routes, monkeypatch, path, data):
    """Obligation S6, as CI enforces it: the gate is *called*. Execution stops
    inside the spy, so this asserts where authorization happens and nothing
    about what the route does afterwards (which the suite already covers)."""
    reached = []

    def spy(poll, request, **kwargs):
        reached.append(poll["id"])
        raise _Reached

    monkeypatch.setattr(web, "require_manage", spy)
    with pytest.raises(_Reached):
        owner_routes.post(path, data=data)
    assert reached == ["p1"], f"{path} does not authorize through require_manage"


@pytest.mark.parametrize("path", ["/scheduler/polls/p1", "/scheduler/polls/p1/edit"])
def test_the_owner_only_pages_ask_the_predicate_too(owner_routes, monkeypatch, path):
    """`can_manage` (not `require_manage`): these render a page or a 403 page
    rather than raising, so the predicate has to answer a question, not raise."""
    monkeypatch.setattr(web, "get_responses", lambda pid: [])
    monkeypatch.setattr(web, "get_invites", lambda pid: [])
    monkeypatch.setattr(web, "get_contact_log", lambda pid: [])

    def spy(poll, request, **kwargs):
        raise _Reached

    monkeypatch.setattr(web, "can_manage", spy)
    with pytest.raises(_Reached):
        owner_routes.get(path)


def test_the_owner_check_is_not_reimplemented_per_route():
    """A tripwire, not the guard, and deliberately modest about that.

    The real S6 enforcement is
    `test_every_mutating_owner_route_authorizes_through_the_predicate`, which
    asserts each route *calls* the predicate and cannot be defeated by rewriting
    the comparison. This one only catches the exact pre-#29 spelling coming
    back verbatim; whitespace in the subscript, `.get()` in place of `[]`,
    swapped operands, a hoisted local or `not in (...,)` all evade it. Kept
    because a verbatim revert is the likely mistake, not because it is proof.

    public.py is excluded deliberately, not by oversight: its mutating routes
    (`submit_public_response`, `submit_invite_response`, `deep_link_vote`) are
    respondent actions authorized by possession of the poll's public or invite
    token, which *is* the identity -- there is no owner to authorize against.
    """
    inlined = re.compile(r"""creator_id["']\]\s*[!=]=\s*user""")
    for module in ("web.py", "api.py"):
        assert not inlined.search((SRC / module).read_text()), (
            f"{module} compares creator_id to the user inline again -- call require_manage"
        )

    # ...and the exclusion stays justified: public.py never looks at ownership
    # at all. It calls get_user, but only to prefill a respondent's own name
    # (public.py:53) -- its routes are authorized by the poll or invite token in
    # the path, which is the respondent's identity.
    public = (SRC / "public.py").read_text()
    assert "creator_id" not in public and "owner_id" not in public


def test_a_validated_creator_email_always_fits_the_column():
    """`valid_email` caps an address at RFC 5321's 254 octets and
    creator_email is VARCHAR(255), so MySQL strict mode cannot overflow on a
    value that passed validation -- the assertion a future column change would
    break, and the reason create_poll's docstring can tell #30 to validate
    rather than merely presence-check."""
    from kairos.http import valid_email

    longest = valid_email("a" * 242 + "@example.org")
    assert longest is not None and len(longest) == 254
    assert valid_email("a" * 243 + "@example.org") is None


# -- 4. the capability never escapes ---------------------------------------


def test_the_capability_is_never_serialized_to_an_api_client(live_client, monkeypatch, caplog):
    """Obligation S3. A response carrying admin_token would hand every holder of
    the operator's single bearer key a permanent per-poll credential that works
    without the key -- more than the key already is, and it survives rotation.
    creator_email is the creator's own address, which no response carried before.
    """
    monkeypatch.setenv("KAIROS_API_KEY", "k")
    monkeypatch.setattr(settings, "API_KEY", "k")
    caplog.set_level(logging.DEBUG)
    live_client.headers["Authorization"] = "Bearer k"

    created = live_client.post(
        "/scheduler/api/polls",
        json={
            "title": "Secret poll",
            "mode": "full_day",
            "slots": [{"date": "2026-12-01"}],
            "creator": "alice",
            "creator_email": "alice@example.org",
        },
    ).json()
    token = _admin_token_of(created["id"])

    detail = live_client.get(f"/scheduler/api/polls/{created['id']}")
    listing = live_client.get("/scheduler/api/polls")
    for response in (created, detail.json(), listing.json()):
        body = json.dumps(response)
        assert "admin_token" not in body
        assert token not in body
        assert "alice@example.org" not in body

    # ...and it never reaches a log line either.
    assert token not in caplog.text


def test_the_scrub_copies_rather_than_pops_in_place():
    """`_without_secrets` used to pop in place, and `list_polls_endpoint`
    discarded its return value -- a leak that only a refactor away, and one that
    would have looked like a working change. Both call sites now use the return
    value; this pins the copy."""
    from kairos import api

    poll = {"id": "p1", "title": "T", "admin_token": "s3cret", "creator_email": "a@b.ch"}
    scrubbed = api._without_secrets(poll)
    assert scrubbed == {"id": "p1", "title": "T"}
    assert poll["admin_token"] == "s3cret", "the source dict must be untouched"


def _admin_token_of(poll_id: str) -> str:
    from kairos import db

    return db.get_poll(poll_id)["admin_token"]


def test_the_api_records_a_creator_email_but_never_answers_with_one(live_client, monkeypatch):
    monkeypatch.setenv("KAIROS_API_KEY", "k")
    monkeypatch.setattr(settings, "API_KEY", "k")
    live_client.headers["Authorization"] = "Bearer k"
    body = {
        "title": "Managed",
        "mode": "full_day",
        "slots": [{"date": "2026-12-01"}],
        "creator": "alice",
        "creator_email": "Alice@Example.org",
    }

    created = live_client.post("/scheduler/api/polls", json=body).json()
    stored = _stored_poll(created["id"])
    assert stored["creator_email"] == "Alice@example.org"  # normalized, as invitees are
    assert stored["owner_id"] == "alice"
    assert "creator_email" not in created


def test_the_api_rejects_an_unusable_creator_email(live_client, monkeypatch):
    monkeypatch.setenv("KAIROS_API_KEY", "k")
    monkeypatch.setattr(settings, "API_KEY", "k")
    live_client.headers["Authorization"] = "Bearer k"
    r = live_client.post(
        "/scheduler/api/polls",
        json={
            "title": "Managed",
            "mode": "full_day",
            "slots": [{"date": "2026-12-01"}],
            "creator_email": "not-an-address",
        },
    )
    assert r.status_code == 400 and "email" in r.text.lower()


def _stored_poll(poll_id: str) -> dict:
    from kairos import db

    return db.get_poll(poll_id)


# -- 5. header mode is byte-for-byte unchanged -----------------------------


def test_a_poll_created_before_the_migration_is_still_its_creator_s(live_client):
    """The ETH invariant, end to end: a row with all four columns NULL, mutated
    by its creator (works) and by a stranger (403) -- exactly as before #29."""
    from kairos import db

    poll = db.create_poll("alice", "Legacy", None, "full_day", "UTC", [{"date": "2026-12-01"}])

    # Null the four columns as the migration leaves them, so this is a pre-#29
    # row in every respect authorization can see.
    conn = db.get_connection()
    cursor = conn.cursor()
    for column in NEW_COLUMNS:
        cursor.execute(f"UPDATE sched_polls SET {column} = NULL")  # noqa: S608
    conn.commit()
    cursor.close()
    conn.close()
    assert all(_stored_poll(poll["id"])[column] is None for column in NEW_COLUMNS)

    form = {"csrf": make_csrf("alice")}
    closed = live_client.post(
        f"/scheduler/polls/{poll['id']}/close", data=form, headers={"X-User": "alice"}, follow_redirects=False
    )
    assert closed.status_code == 302
    assert _stored_poll(poll["id"])["status"] == "closed"

    refused = live_client.post(
        f"/scheduler/polls/{poll['id']}/reopen", data=form, headers={"X-User": "mallory"}
    )
    assert refused.status_code == 403
    assert _stored_poll(poll["id"])["status"] == "closed"  # unchanged by the attempt


def test_creating_a_poll_in_header_mode_records_the_header_uid_as_owner(live_client):
    created = live_client.post(
        "/scheduler/new",
        data={
            "title": "ETH poll",
            "mode": "full_day",
            "timezone": "Europe/Zurich",
            "dates": "2026-12-01",
            "csrf": make_csrf("alice"),
        },
        headers={"X-User": "alice"},
        follow_redirects=False,
    )
    assert created.status_code == 302
    poll = _stored_poll(created.headers["location"].rsplit("/", 1)[-1])
    assert poll["creator_id"] == poll["owner_id"] == "alice"
    assert poll["creator_email"] is None  # only the hosted flow mails a manage link
    assert poll["admin_token"] is not None  # minted, but shown to nobody in this mode


def test_an_anonymous_owner_action_is_still_401(live_client):
    r = live_client.post("/scheduler/polls/whatever/close", data={})
    assert r.status_code == 401  # unchanged: no identity, no CSRF check, no 403


def test_the_owner_only_page_shows_its_controls_to_the_owner(live_client):
    from kairos import db

    poll = db.create_poll("alice", "Controls", None, "full_day", "UTC", [{"date": "2026-12-01"}])
    owner_view = live_client.get(f"/scheduler/polls/{poll['id']}", headers={"X-User": "alice"})
    stranger_view = live_client.get(f"/scheduler/polls/{poll['id']}", headers={"X-User": "mallory"})
    assert "Edit Poll" in owner_view.text
    assert "Edit Poll" not in stranger_view.text

    stranger_edit = live_client.get(f"/scheduler/polls/{poll['id']}/edit", headers={"X-User": "mallory"})
    assert stranger_edit.status_code == 403 and "Not allowed" in stranger_edit.text


def test_get_user_is_consulted_once_per_owner_mutation(live_client, monkeypatch):
    """The `auth.get_user` runtime seam is documented as replaceable; a request
    that consults it twice is a request whose behaviour depends on a
    non-idempotent replacement."""
    import kairos.auth as auth

    calls = []
    real = get_user

    def counting(request):
        calls.append(1)
        return real(request)

    # Both names: web.py imports get_user into its own namespace, so counting
    # only the module it was imported from would leave this vacuous.
    monkeypatch.setattr(auth, "get_user", counting)
    monkeypatch.setattr(web, "get_user", counting)
    live_client.post("/scheduler/polls/whatever/close", data={}, headers={"X-User": "alice"})
    assert len(calls) == 1
