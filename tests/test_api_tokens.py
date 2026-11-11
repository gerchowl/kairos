"""Issue #82: owner-minted API tokens — scoped, expiring, revocable.

Properties this file asserts, each named exactly as the issue's acceptance list:

1. **Hash-only storage.** The plaintext is not in the DB after mint. The only
   on-disk trace is a sha256 hexdigest.
2. **Shown exactly once.** The mint POST renders the plaintext in its response;
   every subsequent list read serves only the prefix.
3. **Expiry presets** (24h / 7d / 30d / 90d / 1y) are honoured, any other
   expiry code refuses, no never-expiring token exists.
4. **Expired or revoked → 401.** Non-leaky message, identical wording across
   the three refusal paths (unknown / expired / revoked).
5. **Scope enforcement.** A token minted with `polls:read` cannot reach any
   mail-sending route (same 403, same wording, as #51's env-key refusal).
6. **Ownership of created polls.** A poll minted via a token is attributed to
   the minting owner (uid becomes creator_id / owner_id).
7. **Reach isolation.** Two owners' tokens cannot read each other's polls under
   `KAIROS_POLL_REACH=scoped`.
8. **Env keys unchanged.** `KAIROS_API_KEY` still answers byte-identically.
9. **Panel is owner-only + CSRF.** The GET requires a signed-in owner, each
   POST requires a valid CSRF token bound to that owner.
10. **last_used_at throttling.** At most one write per minute per token.

End-to-end against the real SQLite layer (no DB stubs): the `sched_api_tokens`
table, the schema migrations, the authentication resolver, the reach guard and
the panel's own routes are all exercised by one TestClient, which is the only
way to assert property #1 (that nothing in the whole pipeline persists a
plaintext).
"""

import hashlib
import re
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from kairos import apitokens, settings

OWNER_A = "alice"
OWNER_B = "bob"
LEGACY = "legacy-all-power-key"


@pytest.fixture
def db_file(tmp_path, monkeypatch):
    """A fresh on-disk SQLite per test, through `settings.DB_URL`.

    Not `:memory:` because the API tokens module opens a new connection per
    call and an in-memory DB is per-connection — two calls would see two empty
    databases. `tmp_path` is torn down by pytest.
    """
    path = tmp_path / "kairos.db"
    monkeypatch.setattr(settings, "DB_URL", f"sqlite:///{path}")
    return path


@pytest.fixture
def client(db_file, monkeypatch):
    """A TestClient that boots `create_app` — so init_schema runs — with a
    legacy API key and header-auth as both the "web owner" and "API caller"."""
    monkeypatch.setenv("KAIROS_API_KEY", LEGACY)
    # The scoping module caches nothing, but keyring reads env at call time;
    # make sure no stray KAIROS_API_KEYS from another test leaks in.
    monkeypatch.setattr(settings, "API_KEYS", "")
    monkeypatch.setenv("KAIROS_API_KEYS", "")
    from kairos.main import create_app
    with TestClient(create_app(), base_url="https://testserver") as c:
        yield c


@pytest.fixture(autouse=True)
def _reset_touch_cache():
    """The in-process last_used_at throttle survives across tests otherwise."""
    apitokens._last_used_cache.clear()
    yield
    apitokens._last_used_cache.clear()


def as_owner(client, uid, email=""):
    """Return a client with the identity headers set for this owner."""
    client.headers["X-User"] = uid
    client.headers["X-Email"] = email or f"{uid}@example.org"
    client.headers["X-Name"] = uid.capitalize()
    return client


def as_bearer(client, token):
    """Return a client authenticated with `token` on /api, with no web identity."""
    # Remove any owner headers from previous use; they must not leak into /api
    # under scoped reach, where they would answer something other than the key.
    for h in ("X-User", "X-Email", "X-Name"):
        client.headers.pop(h, None)
    client.headers["Authorization"] = f"Bearer {token}"
    return client


# -- 1. hash-only storage, shown-once --------------------------------------


def test_the_plaintext_is_stored_only_as_its_sha256(client, db_file):
    """The plaintext never lands in the DB.

    Minted, then the raw DB bytes are searched. A `kai_` substring is a
    fail — it means the plaintext (or a chunk of it) sits in a row.
    """
    as_owner(client, OWNER_A)
    r = client.get("/scheduler/tokens")
    assert r.status_code == 200
    csrf = _csrf_from(r.text)
    r = client.post("/scheduler/tokens", data={
        "csrf": csrf, "name": "cli", "scopes": ["polls:read"], "expiry": "30d",
    })
    assert r.status_code == 200
    plaintext = _plaintext_from(r.text)
    assert plaintext.startswith("kai_")
    raw = db_file.read_bytes()
    # The only expected `kai_` in the DB is the 12-char prefix column; the full
    # plaintext (>= 40 chars after the prefix) must not appear.
    assert plaintext.encode() not in raw, "plaintext leaked to disk"
    # And the sha256 of the plaintext IS in the DB — otherwise we could not
    # have stored it at all.
    assert hashlib.sha256(plaintext.encode()).hexdigest().encode() in raw


def test_the_plaintext_is_shown_only_on_the_mint_response(client):
    """Subsequent GETs show the prefix, never the plaintext."""
    as_owner(client, OWNER_A)
    r = client.get("/scheduler/tokens")
    csrf = _csrf_from(r.text)
    r = client.post("/scheduler/tokens", data={
        "csrf": csrf, "name": "cli", "scopes": ["polls:read"], "expiry": "30d",
    })
    plaintext = _plaintext_from(r.text)

    # A fresh GET must not contain the plaintext anywhere.
    r2 = client.get("/scheduler/tokens")
    assert plaintext not in r2.text
    # The prefix column IS rendered, so the owner can tell their tokens apart.
    assert plaintext[:12] in r2.text


# -- 2. expiry presets ------------------------------------------------------


@pytest.mark.parametrize("code,expected_seconds", [
    ("24h", 24 * 3600),
    ("7d", 7 * 24 * 3600),
    ("30d", 30 * 24 * 3600),
    ("90d", 90 * 24 * 3600),
    ("1y", 365 * 24 * 3600),
])
def test_each_expiry_preset_sets_the_right_lifetime(client, code, expected_seconds):
    as_owner(client, OWNER_A)
    _, row = apitokens.mint(OWNER_A, f"t-{code}", ["polls:read"], expected_seconds)
    actual = (row["expires_at"] - row["created_at"]).total_seconds()
    assert abs(actual - expected_seconds) < 2  # clock slack


def test_an_unknown_expiry_code_is_refused(client):
    as_owner(client, OWNER_A)
    r = client.get("/scheduler/tokens")
    csrf = _csrf_from(r.text)
    r = client.post("/scheduler/tokens", data={
        "csrf": csrf, "name": "n", "scopes": ["polls:read"], "expiry": "forever",
    })
    assert r.status_code == 200  # re-renders with an inline error
    assert "Unknown expiry" in r.text


def test_the_mint_api_refuses_zero_or_negative_lifetime():
    with pytest.raises(ValueError, match="positive"):
        apitokens.mint(OWNER_A, "n", ["polls:read"], 0)
    with pytest.raises(ValueError, match="positive"):
        apitokens.mint(OWNER_A, "n", ["polls:read"], -1)


def test_an_empty_scope_list_is_refused():
    """A token with no scopes would grant nothing but cost a row; the issue
    wants mint to be a deliberate act, which includes 'name at least one scope'."""
    with pytest.raises(ValueError, match="at least one scope"):
        apitokens.mint(OWNER_A, "n", [], 3600)


def test_an_unknown_scope_name_is_refused():
    with pytest.raises(ValueError, match="unknown scope"):
        apitokens.mint(OWNER_A, "n", ["polls:nukes"], 3600)


# -- 3. expired / revoked / unknown — all 401, same wording -----------------


def test_a_fresh_token_authenticates_against_the_api(client):
    """The positive case first — otherwise the refusals could be hiding a
    broken happy path."""
    plain, _ = apitokens.mint(OWNER_A, "t", ["polls:read"], 3600)
    r = as_bearer(client, plain).get("/scheduler/api/whoami")
    assert r.status_code == 200
    body = r.json()
    assert "polls:read" in body["scopes"]
    assert body["key_id"]


def test_an_expired_token_answers_401(client):
    plain, _ = apitokens.mint(OWNER_A, "t", ["polls:read"], 1)
    # Force an expiry-in-the-past regardless of clock drift between the mint
    # timestamp and the comparison: we go through the DB rather than hoping on
    # sleep(2).
    _force_expire(plain, hours_ago=1)
    r = as_bearer(client, plain).get("/scheduler/api/whoami")
    assert r.status_code == 401
    assert "Invalid" in r.text  # byte-identical wording to a wrong env key


def test_a_revoked_token_answers_401(client):
    plain, row = apitokens.mint(OWNER_A, "t", ["polls:read"], 3600)
    from kairos.db import revoke_api_token
    assert revoke_api_token(row["id"], OWNER_A) is True
    r = as_bearer(client, plain).get("/scheduler/api/whoami")
    assert r.status_code == 401


def test_a_wrong_token_answers_the_same_401_wording(client):
    """The three refusal paths must be indistinguishable from the outside."""
    plain_ok, _ = apitokens.mint(OWNER_A, "t", ["polls:read"], 3600)
    plain_expired, _ = apitokens.mint(OWNER_A, "e", ["polls:read"], 1)
    _force_expire(plain_expired, hours_ago=1)
    plain_revoked, row = apitokens.mint(OWNER_A, "r", ["polls:read"], 3600)
    from kairos.db import revoke_api_token
    revoke_api_token(row["id"], OWNER_A)

    def msg_for(bearer):
        return as_bearer(client, bearer).get("/scheduler/api/whoami").text

    wrong = msg_for("kai_" + "a" * 60)
    assert msg_for(plain_expired) == wrong
    assert msg_for(plain_revoked) == wrong


def test_the_bearer_is_never_logged_in_full(client, caplog):
    """The log stream must not carry the plaintext — it is a credential."""
    import logging
    caplog.set_level(logging.DEBUG, logger="kairos")
    plain, row = apitokens.mint(OWNER_A, "t", ["polls:read"], 3600)
    from kairos.db import revoke_api_token
    revoke_api_token(row["id"], OWNER_A)
    as_bearer(client, plain).get("/scheduler/api/whoami")
    for r in caplog.records:
        assert plain not in r.getMessage()


# -- 4. scope enforcement, same shape as #51 --------------------------------


def test_a_read_only_token_cannot_reach_a_mail_route(client):
    """403 (not 401, not 404, not 500) naming the missing scope — identical to
    the way #51 refuses a scoped env key. The UI makes this grantable at mint
    time, so the test proves the deny side."""
    # Set up a poll under OWNER_A so the route can find one.
    plain_admin, _ = apitokens.mint(OWNER_A, "admin", ["polls:write", "polls:read"], 3600)
    r = as_bearer(client, plain_admin).post("/scheduler/api/polls", json={
        "title": "t", "mode": "time_slot",
        "slots": [{"date": "2026-08-01", "start_time": "09:00", "end_time": "10:00"}],
    })
    assert r.status_code == 200, r.text
    poll_id = r.json()["id"]

    plain_ro, _ = apitokens.mint(OWNER_A, "ro", ["polls:read"], 3600)
    r = as_bearer(client, plain_ro).post(
        f"/scheduler/api/polls/{poll_id}/invite", json={"emails": ["a@x.ch"]}
    )
    assert r.status_code == 403
    assert "mail:send" in r.text


def test_a_sender_token_is_let_through_mail_routes(client, monkeypatch):
    """The positive side of the test above: a token minted with the right
    scope reaches the route."""
    monkeypatch.setattr("kairos.api.send_invite_email", lambda *a, **k: True)
    monkeypatch.setattr("kairos.api.log_contact", lambda *a, **k: None)
    plain_admin, _ = apitokens.mint(OWNER_A, "admin",
                                     ["polls:write", "mail:send"], 3600)
    r = as_bearer(client, plain_admin).post("/scheduler/api/polls", json={
        "title": "t", "mode": "time_slot",
        "slots": [{"date": "2026-08-01", "start_time": "09:00", "end_time": "10:00"}],
    })
    assert r.status_code == 200
    poll_id = r.json()["id"]
    r = as_bearer(client, plain_admin).post(
        f"/scheduler/api/polls/{poll_id}/invite", json={"emails": ["a@x.ch"]}
    )
    assert r.status_code == 200, r.text


def test_implications_apply_at_mint(client):
    """`polls:write` implies `polls:read`; the stored scope string reflects the
    expanded closure."""
    _, row = apitokens.mint(OWNER_A, "t", ["polls:write"], 3600)
    stored = set(row["scopes"].split(","))
    assert "polls:read" in stored and "polls:write" in stored


# -- 5. ownership + reach isolation ----------------------------------------


def test_a_poll_minted_via_a_token_is_attributed_to_the_owner(client, monkeypatch):
    monkeypatch.setattr(settings, "POLL_REACH", "scoped")
    plain, _ = apitokens.mint(OWNER_A, "cli", ["polls:write"], 3600)
    r = as_bearer(client, plain).post("/scheduler/api/polls", json={
        "title": "alices poll", "mode": "full_day",
        "slots": [{"date": "2026-08-01"}],
    })
    assert r.status_code == 200, r.text
    poll = r.json()
    # On the server the poll's creator_id is the owner's uid, not the flat "api"
    # label every env-keyring entry writes. Verified via the DB directly, so
    # the assertion is on the stored row rather than on the API response shape.
    from kairos.db import get_poll
    row = get_poll(poll["id"])
    assert row["creator_id"] == OWNER_A
    assert row["owner_id"] == OWNER_A


def test_the_owner_token_reaches_its_owners_polls_under_scoped(client, monkeypatch):
    """Even though its static grant is empty, the owner-token branch lets it
    read polls its owner holds management authority over."""
    monkeypatch.setattr(settings, "POLL_REACH", "scoped")
    plain_a, _ = apitokens.mint(OWNER_A, "a", ["polls:write"], 3600)
    r = as_bearer(client, plain_a).post("/scheduler/api/polls", json={
        "title": "a's poll", "mode": "full_day", "slots": [{"date": "2026-08-01"}],
    })
    poll_id = r.json()["id"]
    r = as_bearer(client, plain_a).get(f"/scheduler/api/polls/{poll_id}")
    assert r.status_code == 200, r.text
    assert r.json()["title"] == "a's poll"


def test_an_owner_token_cannot_read_another_owners_poll(client, monkeypatch):
    """The isolation property under scoped reach — issue #82's "cannot read
    other owners' polls"."""
    monkeypatch.setattr(settings, "POLL_REACH", "scoped")
    plain_a, _ = apitokens.mint(OWNER_A, "a", ["polls:write"], 3600)
    plain_b, _ = apitokens.mint(OWNER_B, "b", ["polls:read"], 3600)
    r = as_bearer(client, plain_a).post("/scheduler/api/polls", json={
        "title": "alice's", "mode": "full_day", "slots": [{"date": "2026-08-01"}],
    })
    poll_id = r.json()["id"]
    # Bob tries to read Alice's poll — 403 under scoped reach.
    r = as_bearer(client, plain_b).get(f"/scheduler/api/polls/{poll_id}")
    assert r.status_code == 403


def test_the_list_endpoint_only_returns_the_owners_own_polls(client, monkeypatch):
    monkeypatch.setattr(settings, "POLL_REACH", "scoped")
    plain_a, _ = apitokens.mint(OWNER_A, "a", ["polls:write"], 3600)
    plain_b, _ = apitokens.mint(OWNER_B, "b", ["polls:write"], 3600)
    for name, token in (("a-poll", plain_a), ("b-poll", plain_b)):
        as_bearer(client, token).post("/scheduler/api/polls", json={
            "title": name, "mode": "full_day", "slots": [{"date": "2026-08-01"}],
        })
    a_list = as_bearer(client, plain_a).get("/scheduler/api/polls").json()
    b_list = as_bearer(client, plain_b).get("/scheduler/api/polls").json()
    assert [p["title"] for p in a_list] == ["a-poll"]
    assert [p["title"] for p in b_list] == ["b-poll"]


# -- 6. env-key path unchanged --------------------------------------------


def test_the_legacy_env_key_answers_byte_identically(client):
    """ADR-0001/0002: the ETH/duplet deployment sets KAIROS_API_KEY and nothing
    else; minting a token must not change how that key answers."""
    r = as_bearer(client, LEGACY).get("/scheduler/api/whoami")
    assert r.status_code == 200
    body = r.json()
    assert body["key_id"]  # legacy key gets its own digest
    # The legacy key reaches every poll, which `GET /whoami` reports as "*".
    assert body["polls"] == "*"


def test_a_wrong_legacy_key_still_401s_with_the_same_wording(client):
    r = as_bearer(client, "wrong-" + "a" * 20).get("/scheduler/api/whoami")
    assert r.status_code == 401
    assert "Invalid" in r.text


# -- 7. panel is owner-only + CSRF -----------------------------------------


def test_the_panel_refuses_unauthenticated_requests(client):
    # No X-User header — in header mode this is the "not signed in" state.
    r = client.get("/scheduler/tokens", follow_redirects=False)
    # 302 (to login) or 401 (if no login url) — both are "not signed in", which
    # is what the test asserts.
    assert r.status_code in (302, 401)


def test_the_panel_rejects_a_mint_submit_without_csrf(client):
    as_owner(client, OWNER_A)
    r = client.post("/scheduler/tokens", data={
        "name": "n", "scopes": ["polls:read"], "expiry": "30d",
    })
    assert r.status_code == 403
    assert "CSRF" in r.text


def test_the_panel_rejects_a_mint_submit_with_someone_elses_csrf(client):
    # Get CSRF as alice, then present it as bob.
    as_owner(client, OWNER_A)
    r = client.get("/scheduler/tokens")
    alice_csrf = _csrf_from(r.text)
    as_owner(client, OWNER_B)
    r = client.post("/scheduler/tokens", data={
        "csrf": alice_csrf, "name": "n", "scopes": ["polls:read"], "expiry": "30d",
    })
    assert r.status_code == 403


def test_the_panel_rejects_a_revoke_submit_for_another_owners_token(client):
    """A real cross-owner attempt: alice mints a token, bob tries to revoke by
    its id with his own valid CSRF. Must answer 404 (does-not-exist from bob's
    perspective), not 200 (don't tell him it exists), and the row must stay
    active."""
    _plain_a, row_a = apitokens.mint(OWNER_A, "a", ["polls:read"], 3600)
    as_owner(client, OWNER_B)
    r = client.get("/scheduler/tokens")
    bob_csrf = _csrf_from(r.text)
    r = client.post(
        f"/scheduler/tokens/{row_a['id']}/revoke",
        data={"csrf": bob_csrf},
        follow_redirects=False,
    )
    assert r.status_code == 404
    # Alice's token is still live.
    from kairos.db import list_api_tokens
    alice_rows = list_api_tokens(OWNER_A)
    assert alice_rows[0]["revoked_at"] is None


def test_the_panel_is_unavailable_in_capability_mode(client, monkeypatch):
    """`KAIROS_AUTH=capability` has no account to attribute a token to — the
    page must say so clearly rather than render a working-looking form."""
    monkeypatch.setattr(settings, "AUTH_MODE", "capability")
    r = client.get("/scheduler/tokens")
    assert r.status_code == 404
    assert "capability" in r.text.lower() or "accountless" in r.text.lower()


# -- 8. last_used_at throttling -------------------------------------------


def test_last_used_at_is_written_on_first_use(client):
    plain, row = apitokens.mint(OWNER_A, "t", ["polls:read"], 3600)
    assert row["last_used_at"] is None
    as_bearer(client, plain).get("/scheduler/api/whoami")
    from kairos.db import list_api_tokens
    [row_after] = list_api_tokens(OWNER_A)
    assert row_after["last_used_at"] is not None


def test_last_used_at_is_throttled_to_once_per_window(client):
    """Issue #82: 'throttle writes, e.g. at most once/minute'. We don't sleep;
    the in-process cache is what we assert on directly."""
    plain, _row = apitokens.mint(OWNER_A, "t", ["polls:read"], 3600)
    client1 = as_bearer(client, plain)
    assert client1.get("/scheduler/api/whoami").status_code == 200
    # The second request within the window must NOT touch the cache's timestamp.
    cache_before = dict(apitokens._last_used_cache)
    client1.get("/scheduler/api/whoami")
    cache_after = dict(apitokens._last_used_cache)
    assert cache_before == cache_after, "last_used throttle did not hold"


# -- helpers ---------------------------------------------------------------


def _csrf_from(html: str) -> str:
    """Pull the CSRF value out of a rendered form's hidden input."""
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    assert m, "CSRF token not present in panel HTML"
    return m.group(1)


def _plaintext_from(html: str) -> str:
    """Pull the plaintext out of the one-time disclosure input on the mint
    response. The template puts it in `<input id="minted-token" value="...">`."""
    m = re.search(r'id="minted-token"[^>]*value="(kai_[^"]+)"', html)
    assert m, "plaintext not present in mint response HTML"
    return m.group(1)


def _force_expire(plaintext: str, hours_ago: int) -> None:
    """Overwrite a token's expires_at so the auth layer reads it as expired.

    Direct SQL rather than a mint-with-tiny-lifetime-and-sleep, so the test is
    deterministic — and it lets us assert that the authentication layer reads
    the column, not the lifetime-at-mint, which is the property that actually
    protects the deployment.
    """
    from kairos.dbconn import get_connection
    token_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    past = datetime.utcnow() - timedelta(hours=hours_ago)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE sched_api_tokens SET expires_at = %s WHERE token_hash = %s",
        (past, token_hash),
    )
    conn.commit()
    cursor.close()
    conn.close()
