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


# ===========================================================================
# Post-review regression tests (PR #85). Each of these FAILS on 64a8b0a and
# passes with the fix beneath it. Named for the finding in the review, so the
# intent and the shape of the defect are both legible in the test output.
# ===========================================================================


# -- Finding #1 (HIGH): owner tokens enforce ownership on every policy ------


def test_owner_token_cannot_read_another_owners_poll_under_default_policy(
    client, monkeypatch
):
    """The issue's isolation property has to hold on the *default* policy.

    64a8b0a's `can_reach` returned True unconditionally when `policy() == OPEN`,
    which is the default on ETH / self-host / header / oidc deployments. In
    that configuration an owner token reached every poll on the instance even
    though the panel told the owner it would act as them — bypassing exactly
    the control #82 was supposed to add.
    """
    # Make sure no explicit policy is set; this is the default configuration.
    monkeypatch.setattr(settings, "POLL_REACH", "")
    monkeypatch.setenv("KAIROS_POLL_REACH", "")
    # And HOSTED is not set, so `policy()` resolves to OPEN.
    monkeypatch.setattr(settings, "HOSTED", False)
    monkeypatch.setattr(settings, "HOSTED_UNKNOWN", False)
    from kairos import reach
    assert reach.policy() == reach.OPEN

    plain_a, _ = apitokens.mint(OWNER_A, "a", ["polls:write"], 3600)
    plain_b, _ = apitokens.mint(OWNER_B, "b", ["polls:read"], 3600)
    r = as_bearer(client, plain_a).post("/scheduler/api/polls", json={
        "title": "alice's", "mode": "full_day", "slots": [{"date": "2026-08-01"}],
    })
    assert r.status_code == 200
    poll_id = r.json()["id"]

    # Bob's token must not reach alice's poll — even though the default policy
    # is OPEN, which is what gives every env key the run of the instance.
    r = as_bearer(client, plain_b).get(f"/scheduler/api/polls/{poll_id}")
    assert r.status_code == 403, r.text


def test_owner_token_cannot_delete_another_owners_poll_under_default_policy(
    client, monkeypatch
):
    """DELETE follows the same reach guard as GET. A separate test because the
    review named GET and DELETE explicitly, and the same defect could skip one
    while catching the other if `guard_reach` ever diverged across methods."""
    monkeypatch.setattr(settings, "POLL_REACH", "")
    monkeypatch.setenv("KAIROS_POLL_REACH", "")
    monkeypatch.setattr(settings, "HOSTED", False)
    monkeypatch.setattr(settings, "HOSTED_UNKNOWN", False)
    from kairos import reach
    assert reach.policy() == reach.OPEN

    plain_a, _ = apitokens.mint(OWNER_A, "a", ["polls:write"], 3600)
    plain_b, _ = apitokens.mint(OWNER_B, "b", ["polls:write"], 3600)
    r = as_bearer(client, plain_a).post("/scheduler/api/polls", json={
        "title": "alice's", "mode": "full_day", "slots": [{"date": "2026-08-01"}],
    })
    poll_id = r.json()["id"]
    r = as_bearer(client, plain_b).delete(f"/scheduler/api/polls/{poll_id}")
    assert r.status_code == 403, r.text
    # Alice's poll is still there.
    from kairos.db import get_poll
    assert get_poll(poll_id) is not None


def test_owner_token_list_filters_to_own_polls_under_default_policy(
    client, monkeypatch
):
    """`GET /polls` listed every poll on 64a8b0a under the default policy —
    `only_reachable`'s OPEN fast-path returned the argument unchanged for
    every principal, so bob saw alice's titles. Must now filter."""
    monkeypatch.setattr(settings, "POLL_REACH", "")
    monkeypatch.setenv("KAIROS_POLL_REACH", "")
    monkeypatch.setattr(settings, "HOSTED", False)
    monkeypatch.setattr(settings, "HOSTED_UNKNOWN", False)
    from kairos import reach
    assert reach.policy() == reach.OPEN

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


def test_env_key_still_reaches_every_poll_under_open(client):
    """Byte-identical compatibility: the operator's `KAIROS_API_KEY` under the
    default (OPEN) policy still sees everything. The owner-token tightening
    must not touch env-key behaviour."""
    plain_a, _ = apitokens.mint(OWNER_A, "a", ["polls:write"], 3600)
    plain_b, _ = apitokens.mint(OWNER_B, "b", ["polls:write"], 3600)
    for name, token in (("a-poll", plain_a), ("b-poll", plain_b)):
        as_bearer(client, token).post("/scheduler/api/polls", json={
            "title": name, "mode": "full_day", "slots": [{"date": "2026-08-01"}],
        })
    # The legacy env key reaches every poll (reach.EVERY_POLL).
    legacy_list = as_bearer(client, LEGACY).get("/scheduler/api/polls").json()
    titles = sorted(p["title"] for p in legacy_list)
    assert titles == ["a-poll", "b-poll"]


def test_owner_token_cannot_read_another_owners_poll_under_scoped(
    client, monkeypatch
):
    """The same property, under the explicit `scoped` policy. 64a8b0a already
    held this one; keep it in the regression suite to prove the fix did not
    regress scoped reach either."""
    monkeypatch.setattr(settings, "POLL_REACH", "scoped")
    plain_a, _ = apitokens.mint(OWNER_A, "a", ["polls:write"], 3600)
    plain_b, _ = apitokens.mint(OWNER_B, "b", ["polls:read"], 3600)
    r = as_bearer(client, plain_a).post("/scheduler/api/polls", json={
        "title": "alice's", "mode": "full_day", "slots": [{"date": "2026-08-01"}],
    })
    poll_id = r.json()["id"]
    r = as_bearer(client, plain_b).get(f"/scheduler/api/polls/{poll_id}")
    assert r.status_code == 403


# -- Finding #2: owner token cannot forge creator on POST /polls ------------


def test_owner_token_refuses_to_create_a_poll_as_another_user(client):
    """`body.creator` was `or user["uid"]`'d in 64a8b0a, so an owner token
    minted by alice could post `{"creator": "bob"}` and have the poll
    attributed to bob — defeating "a token acts as its owner"."""
    plain, _ = apitokens.mint(OWNER_A, "a", ["polls:write"], 3600)
    r = as_bearer(client, plain).post("/scheduler/api/polls", json={
        "title": "forged", "mode": "full_day",
        "slots": [{"date": "2026-08-01"}],
        "creator": OWNER_B,
    })
    assert r.status_code == 403, r.text
    # Nothing was written.
    from kairos.db import list_polls
    assert list_polls() == []


def test_owner_token_may_name_its_own_uid_as_creator(client):
    """The permissive side: `creator == token owner's uid` is accepted — the
    refusal is per-mismatch, not per-presence-of-creator."""
    plain, _ = apitokens.mint(OWNER_A, "a", ["polls:write"], 3600)
    r = as_bearer(client, plain).post("/scheduler/api/polls", json={
        "title": "own", "mode": "full_day",
        "slots": [{"date": "2026-08-01"}],
        "creator": OWNER_A,
    })
    assert r.status_code == 200, r.text


def test_env_key_may_still_attribute_a_poll_to_a_named_user(client):
    """Env keys keep today's behaviour byte-identically: a service credential
    like `KAIROS_API_KEY` is allowed to name a creator on the body (ADR-0001).
    Only owner tokens have the restriction."""
    r = as_bearer(client, LEGACY).post("/scheduler/api/polls", json={
        "title": "service", "mode": "full_day",
        "slots": [{"date": "2026-08-01"}],
        "creator": OWNER_B,
    })
    assert r.status_code == 200, r.text
    from kairos.db import get_poll
    assert get_poll(r.json()["id"])["creator_id"] == OWNER_B


# -- Finding #3: operator-only scopes stay env-key-only ---------------------


def test_the_mint_api_refuses_an_operator_only_scope():
    """`mail:force` and `imip:poll` are operator affordances (bypassing a 24h
    cooldown, running the instance-wide inbox poll). The panel must not let an
    owner mint a token with either, even via a form-tampering POST."""
    with pytest.raises(ValueError, match="not owner-grantable"):
        apitokens.mint(OWNER_A, "n", ["mail:force"], 3600)
    with pytest.raises(ValueError, match="not owner-grantable"):
        apitokens.mint(OWNER_A, "n", ["imip:poll"], 3600)


def test_the_mint_route_rejects_a_form_tampered_operator_scope(client):
    """Belt-and-braces: even if a caller POSTs `scopes=mail:force` directly
    (the UI never offers it), the server refuses and re-renders with the
    error inline — no row is written."""
    as_owner(client, OWNER_A)
    r = client.get("/scheduler/tokens")
    csrf = _csrf_from(r.text)
    r = client.post("/scheduler/tokens", data={
        "csrf": csrf, "name": "forge",
        "scopes": ["mail:force"], "expiry": "30d",
    })
    assert r.status_code == 200
    assert "not owner-grantable" in r.text
    from kairos.db import list_api_tokens
    assert list_api_tokens(OWNER_A) == []


def test_the_panel_offers_only_owner_grantable_scopes(client):
    """The mint form's checkbox list is the OWNER_GRANTABLE set only — a
    clear UI, not relying on the server to catch tampering (the server does
    catch it, but the panel never offers the mistake in the first place)."""
    as_owner(client, OWNER_A)
    r = client.get("/scheduler/tokens")
    assert r.status_code == 200
    assert 'value="polls:read"' in r.text
    assert 'value="polls:write"' in r.text
    assert 'value="respond"' in r.text
    assert 'value="mail:send"' in r.text
    # Operator-only scopes are not offered.
    assert 'value="mail:force"' not in r.text
    assert 'value="imip:poll"' not in r.text


# -- Finding #4: one clock across all timestamp columns ---------------------


def test_expiry_lifetime_is_exact_under_a_local_non_utc_server(
    client, monkeypatch
):
    """MySQL/MariaDB writes CURRENT_TIMESTAMP in session-local time; 64a8b0a
    wrote created_at/expires_at with `datetime.utcnow()` while comparing them
    with `db_now()` (local time on MySQL), so the token's lifetime was off by
    the server UTC offset. The fix uses `db_now()` for both, so lifetime stays
    exact even when the server clock is local.
    """
    from datetime import datetime as _dt
    from datetime import timedelta as _td

    # Simulate a MySQL deployment in a local non-UTC timezone: `db_now()` on
    # MySQL returns `datetime.now()`. We monkeypatch it to a fixed local-time
    # instant, then another fixed local-time instant one hour later.
    calls = {"n": 0}
    # UTC "now" would be 2026-01-15 00:00, but the server's local clock is
    # +05:00, so `db_now()` reports 05:00. The difference used to turn into
    # an expiry shift.
    LOCAL_NOW = _dt(2026, 1, 15, 5, 0, 0)

    def fake_db_now():
        calls["n"] += 1
        return LOCAL_NOW

    monkeypatch.setattr("kairos.dbconn.db_now", fake_db_now)

    # Mint with a precise 3600s lifetime.
    plain, row = apitokens.mint(OWNER_A, "t", ["polls:read"], 3600)
    assert (row["expires_at"] - row["created_at"]).total_seconds() == 3600
    # created_at matches the local clock exactly.
    assert row["created_at"] == LOCAL_NOW
    assert row["expires_at"] == LOCAL_NOW + _td(seconds=3600)

    # And the token is still live when compared at the same local instant.
    r = as_bearer(client, plain).get("/scheduler/api/whoami")
    assert r.status_code == 200, r.text


# -- Finding #5: hosted demo makes the panel unavailable --------------------


def test_the_panel_is_unavailable_in_hosted_demo(client, monkeypatch):
    """Demo mode shares one dev identity across every visitor. On a HOSTED
    deployment that would mean every visitor sees and mints tokens under the
    shared uid, and one visitor's token would be revocable by the next. The
    panel must self-404 in that specific combination.
    """
    monkeypatch.setattr(settings, "AUTH_MODE", "demo")
    monkeypatch.setattr(settings, "HOSTED", True)
    r = client.get("/scheduler/tokens")
    assert r.status_code == 404
    # The copy explains why, so an operator sees something more useful than a
    # generic "not found".
    assert "demo" in r.text.lower() and "hosted" in r.text.lower()


def test_the_panel_is_still_available_in_plain_local_demo(client, monkeypatch):
    """Plain demo (not hosted) still has the panel — a developer poking at
    the feature on their laptop sees it. The gate is specifically the
    `demo AND hosted` combination.
    """
    monkeypatch.setattr(settings, "AUTH_MODE", "demo")
    monkeypatch.setattr(settings, "HOSTED", False)
    # Demo mode's `get_user` synthesises a user from a fixed uid; the panel
    # renders.
    r = client.get("/scheduler/tokens")
    assert r.status_code == 200
    assert "API tokens" in r.text


# -- Finding #6: Cache-Control: no-store on the panel -----------------------


def test_the_mint_response_disclosing_the_plaintext_is_not_cached(client):
    """The one response that has the plaintext in it must not land in a
    shared cache (a proxy) or the browser history-back store."""
    as_owner(client, OWNER_A)
    r = client.get("/scheduler/tokens")
    csrf = _csrf_from(r.text)
    r = client.post("/scheduler/tokens", data={
        "csrf": csrf, "name": "t", "scopes": ["polls:read"], "expiry": "30d",
    })
    assert r.status_code == 200
    cache_control = r.headers.get("cache-control", "").lower()
    assert "no-store" in cache_control
    assert "no-cache" in cache_control
    assert r.headers.get("pragma", "").lower() == "no-cache"


def test_the_panel_list_response_is_not_cached(client):
    """Every panel render carries the no-store headers, not just the one with
    the plaintext — the list carries token prefixes and the CSRF token and
    has no reason to be cached at all."""
    as_owner(client, OWNER_A)
    r = client.get("/scheduler/tokens")
    assert r.status_code == 200
    cache_control = r.headers.get("cache-control", "").lower()
    assert "no-store" in cache_control


# -- Finding #7: "All owner permissions" shortcut ---------------------------


def test_the_all_owner_permissions_shortcut_expands_at_mint_time(client):
    """A single-checkbox shortcut for the owner-grantable set — expanded to
    the explicit scope list on the stored row (not a wildcard). A grant minted
    today cannot silently widen when a new owner-grantable scope is added.
    """
    as_owner(client, OWNER_A)
    r = client.get("/scheduler/tokens")
    csrf = _csrf_from(r.text)
    # Just the `scopes_all` checkbox, no per-scope boxes. 64a8b0a had no such
    # shortcut at all — the test was impossible to write.
    r = client.post("/scheduler/tokens", data={
        "csrf": csrf, "name": "all", "expiry": "30d", "scopes_all": "1",
    })
    assert r.status_code == 200, r.text
    from kairos.db import list_api_tokens
    [row] = list_api_tokens(OWNER_A)
    stored = set(row["scopes"].split(","))
    # Expanded to exactly the OWNER_GRANTABLE set (polls:write implies
    # polls:read, so the stored form is the closure, same as `mint` always does).
    assert stored == apitokens.OWNER_GRANTABLE
    # Not a wildcard: operator-only scopes are not stored.
    assert "mail:force" not in stored
    assert "imip:poll" not in stored
    assert "*" not in stored
