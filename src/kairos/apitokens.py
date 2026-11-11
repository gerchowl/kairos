"""Owner-minted API tokens — issue #82, the DB-backed counterpart to KAIROS_API_KEYS.

A signed-in owner mints bearer credentials from the admin panel, in addition
to (not instead of) the static env grants that already exist: `KAIROS_API_KEY`
(ADR-0001, byte-identical behaviour) and `KAIROS_API_KEYS` (issue #51, least
privilege). The new credentials sit in the `sched_api_tokens` table and share
the same bearer-authentication surface as the env keys, so a route that
already declares `api_scope("polls:read")` is enforced identically against all
three.

**Hash-only storage.** The token is shown exactly once at mint time, after
which only `sha256(token).hexdigest()` is stored (`token_hash`, UNIQUE). An
attacker with read access to the database cannot reconstruct any working
credential; an operator who misplaces the one-time display has to revoke and
re-mint. The plaintext is never logged, never emailed, never returned by any
listing.

**Scope vocabulary = #51.** The scopes an owner may grant are the same six
capabilities `kairos.scoping` already defines (`polls:read`, `polls:write`,
`respond`, `mail:send`, `mail:force`, `imip:poll`), transitively expanded
(`polls:write` implies `polls:read`, `mail:force` implies `mail:send`). One
vocabulary, enforced in one place — a mail-sending route refuses a token
without `mail:send` by construction, exactly as it refuses a keyring entry.

**Reach = ownership.** A token "acts as its owner": polls it creates are
attributed to the minting owner (their uid becomes `creator_id` / `owner_id`),
and under `KAIROS_POLL_REACH=scoped` the token reaches only polls the owner
holds management authority over — a token cannot read other owners' polls.
That decision lives in `kairos.reach` (the `_is_owner_of` branch on the
reach guards); here we just set `source="owner_token"` on the principal and
carry the owner's real uid through, so every downstream check works against
the real identity rather than a flat `"api"` label.

**Expiry is required.** Every mint picks one of the five fixed presets
(24h / 7d / 30d (default) / 90d / 1y). There is deliberately no
never-expiring option: rotation is a deliberate act, and the expiry column is
`NOT NULL` in the schema so the "no expiry" state cannot be represented at all.
Expired or revoked tokens answer 401 with a non-leaky message that is byte-
identical to a wrong-token response, so a probing caller cannot distinguish
"revoked", "expired" and "unknown".

**The one function #83's /mcp endpoint will reuse.** `resolve_token(bearer)`
below is the whole token-check surface: it takes a presented bearer string
and returns a Principal (the scoping module's shape) or None. The future
server-hosted MCP endpoint reads its bearer, hands it to `resolve_token`, and
authorizes against the same principal shape — one check, one truth,
no second path that forgets that revoked means revoked.

**Last-used throttling.** Every authenticated API request touches
`last_used_at`, which would otherwise be the second SQLite write on every API
call for a column that is only read by the panel. The in-process cache below
keeps a per-token "written within the last N seconds" guard so the write
fires at most once per `_LAST_USED_WINDOW_SECONDS` per token — same tradeoff
as `kairos.ratelimit`'s in-process counters: per-process state, so N app
instances give N x the write rate, but #36's "one writer" ceiling is also the
deployment ceiling until that's revisited.
"""

import hashlib
import hmac
import logging
import secrets
import threading
import time
from datetime import datetime, timedelta

from kairos import db, settings
from kairos.scoping import Principal, expand, key_id

log = logging.getLogger("kairos.apitokens")

# Token format. `kai_` is a fixed, secret-scanner-friendly prefix: GitHub and
# every other scanner the industry uses keys on a short literal, and a human
# reading a leaked log can tell a Kairos bearer from a Stripe key at a glance.
# The random half is `secrets.token_urlsafe(32)` — 32 bytes of CSPRNG, 43 URL-
# safe chars — well past the 16-byte floor the keyring entries use.
TOKEN_PREFIX = "kai_"
RANDOM_BYTES = 32  # ≥32, as issue #82 requires
# Prefix stored on the row for the panel's display column: `kai_` + first 8
# random chars. Not sensitive — 8 base64url chars is 48 bits, which cannot
# narrow a search of the remaining 196 random bits to anything useful, and
# tests assert the plaintext never leaks anywhere else.
PREFIX_LEN = len(TOKEN_PREFIX) + 8

# Which of #51's capabilities an **owner** may mint from the panel. A strict
# subset of `scoping.SCOPES`: an owner grants what pertains to their own polls
# (read/write their polls, accept responses, send invites and reminders), and
# operator affordances stay operator-only.
#
# `mail:force` (bypass the 24h nudge cooldown) and `imip:poll` (run the
# instance-wide IMAP poll cycle) are deliberately out: they are operator
# affordances in the #51 vocabulary, and leaving them in let a poll owner
# re-run the inbox on every instance they've logged into and spam their
# invitees out of the cooldown. Those capabilities stay on `KAIROS_API_KEYS`
# (env-only), which the server operator controls.
#
# Server-side enforcement in `mint` is the belt; the panel's checkbox list
# (built from `OWNER_GRANTABLE` in `panel._render_panel`) is the braces — a
# form-tampering POST that names `mail:force` is a 400 even if the UI never
# offered it.
OWNER_GRANTABLE: frozenset[str] = frozenset({
    "polls:read", "polls:write", "respond", "mail:send",
})

# Expiry presets. Fixed menu, no free-form expiry: an operator who wants a 2-
# year token has to revoke and re-mint, which is the point. The default is the
# issue's "30d", and `PRESETS` is ordered so the panel renders them in the
# same order a reader would expect (shortest to longest).
PRESETS: tuple[tuple[str, str, int], ...] = (
    ("24h", "24 hours", 24 * 60 * 60),
    ("7d", "7 days", 7 * 24 * 60 * 60),
    ("30d", "30 days", 30 * 24 * 60 * 60),
    ("90d", "90 days", 90 * 24 * 60 * 60),
    ("1y", "1 year", 365 * 24 * 60 * 60),
)
DEFAULT_PRESET = "30d"
_PRESET_SECONDS = {code: seconds for code, _, seconds in PRESETS}


def tokens_enabled() -> bool:
    """True iff this deployment's auth mode can mint and resolve owner tokens.

    The three modes with no stable owner identity to attribute a token to --
    `capability` (no account), `none` (no owner auth), and `demo` on HOSTED
    (one dev identity shared across every visitor) -- cannot. Both the panel's
    self-404 and `resolve_token`'s refusal read off this one function so a
    mode switch that makes the panel unavailable also stops outstanding
    tokens from authenticating: tokens outlive the panel only when the two
    answers disagree. An operator wanting to invalidate an owner's live
    tokens by flipping modes used to have no effect on the tokens (the panel
    was gone but every bearer kept working); now the credential dies with
    the surface that minted it.

    Deliberately pure-settings and no DB read: called on every authenticated
    API request (the `resolve_token` gate), so it has to be free. A mode
    change made after a process started reads here the moment the next
    request runs, so no restart is required for the gate to take effect.

    `resolve_token` returning None for these modes means a bearer that was
    valid yesterday answers 401 today -- same wording as revoked/expired, so
    a probing caller cannot distinguish "credentials cannot be resolved right
    now" from "this token never existed". Flipping back restores
    authentication: tokens are *suspended* by an unavailable panel, not
    destroyed, so a bad mode toggle is recoverable without a re-mint.
    """
    if settings.AUTH_MODE in ("capability", "none"):
        return False
    if settings.AUTH_MODE == "demo" and settings.HOSTED:
        return False
    return True


def preset_seconds(code: str) -> int | None:
    """The lifetime a preset code resolves to, or None for an unknown one.

    None, not a fallback, deliberately: the panel chooses from a fixed `<select>`
    and anything else is form tampering, and we would rather refuse a mint than
    silently clamp it to a default the user did not pick.
    """
    return _PRESET_SECONDS.get(code)


# In-process throttle for the `last_used_at` write. Not shared across workers
# by design — the write it skips is also not shared, so a second process will
# simply write its own update independently.
_last_used_cache: dict[str, float] = {}
_last_used_cache_lock = threading.Lock()
_LAST_USED_WINDOW_SECONDS = 60  # issue asks for "at most once/minute"


def _should_touch(token_id: str) -> bool:
    """Should we write `last_used_at` for this token right now?

    True at most once per `_LAST_USED_WINDOW_SECONDS` per token within this
    process. Thread-safe. The window is coarse on purpose: the only reader is
    the panel's "last used" column, which is about recency, not telemetry.
    """
    now = time.monotonic()
    with _last_used_cache_lock:
        prev = _last_used_cache.get(token_id)
        if prev is not None and now - prev < _LAST_USED_WINDOW_SECONDS:
            return False
        _last_used_cache[token_id] = now
        return True


def _hash(token: str) -> str:
    """The sha256 hexdigest we store and look up by. Never logged in raw form."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def mint(owner_uid: str, name: str, scopes_list: list[str], expires_in_seconds: int,
         *, now: datetime | None = None) -> tuple[str, dict]:
    """Mint a new token for `owner_uid`. Returns `(plaintext, row)`.

    The plaintext is returned exactly once — the caller is the panel's POST
    handler, which puts it in the response to that specific submit and never
    stores it. Nothing in this module persists plaintext.

    `scopes_list` is validated against `kairos.scoping.SCOPES` (expanded for
    the implications table) before persisting; an unknown or empty scope list
    is a `ValueError` rather than a silent full-power mint. `expires_in_seconds`
    must be strictly positive — there is no never-expiring token.
    """
    from kairos.scoping import SCOPES  # local: avoid import cycle with scoping

    if not name.strip():
        raise ValueError("token name is required")
    unknown = sorted(set(scopes_list) - set(SCOPES))
    if unknown:
        raise ValueError(f"unknown scope(s): {', '.join(unknown)}")
    if not scopes_list:
        raise ValueError("a token must grant at least one scope")
    # Operator-only scopes stay env-key-only. See the OWNER_GRANTABLE docstring
    # above for why `mail:force` and `imip:poll` are out of this surface.
    not_grantable = sorted(set(scopes_list) - OWNER_GRANTABLE)
    if not_grantable:
        raise ValueError(
            f"owner-grantable scopes are {', '.join(sorted(OWNER_GRANTABLE))}; "
            f"not owner-grantable: {', '.join(not_grantable)} — configure "
            f"KAIROS_API_KEYS to grant operator capabilities."
        )
    if expires_in_seconds <= 0:
        raise ValueError("expires_in_seconds must be positive — no never-expiring tokens")
    expanded = expand(scopes_list)
    # Canonicalise the stored string: expand (so a reader of the row sees the
    # grant as the authenticator will see it) and sort (so the stored form is
    # deterministic across equal grants, which helps when debugging a surprising
    # 403).
    scopes_stored = ",".join(sorted(expanded))
    plaintext = TOKEN_PREFIX + secrets.token_urlsafe(RANDOM_BYTES)
    token_id = secrets.token_hex(16)  # not a UUID, but the same width and shape
    token_hash = _hash(plaintext)
    prefix = plaintext[:PREFIX_LEN]
    # One clock for every time column this module touches — `db_now()` — so the
    # dialect stays consistent with every comparison in `resolve_token`, every
    # DB-side `CURRENT_TIMESTAMP` (revoked_at, last_used_at) and every display
    # in the panel. The first cut used `datetime.utcnow()` for `created_at`
    # /`expires_at` while comparisons used `db_now()` (local-time on MySQL),
    # which shaved or stretched a token's lifetime by the server's UTC offset.
    created_at = now or _now()
    expires_at = created_at + timedelta(seconds=expires_in_seconds)
    db.insert_api_token(
        token_id=token_id,
        owner_uid=owner_uid,
        name=name.strip()[:255],
        token_hash=token_hash,
        prefix=prefix,
        scopes=scopes_stored,
        created_at=created_at,
        expires_at=expires_at,
    )
    row = {
        "id": token_id,
        "owner_uid": owner_uid,
        "name": name.strip()[:255],
        "prefix": prefix,
        "scopes": scopes_stored,
        "created_at": created_at,
        "expires_at": expires_at,
        "last_used_at": None,
        "revoked_at": None,
    }
    return plaintext, row


def _now() -> datetime:
    """`now()` in the dialect the DB writes. SQLite writes naive UTC via
    `CURRENT_TIMESTAMP`; MySQL/MariaDB writes session-local time. `dbconn.db_now`
    is the single source of truth for this comparison and we delegate to it so
    expired/not-expired here matches the way every other time column in this
    app is compared."""
    from kairos.dbconn import db_now

    return db_now()


def _parse_dt(value) -> datetime | None:
    """A DB column read back as `datetime` — tolerating both the naive UTC
    SQLite writes and the session-local MySQL/MariaDB string.

    Returns None rather than raising so a corrupted row answers "expired, 401"
    rather than "500, your API is down". A control that silently fails open is
    worse than one that fails closed.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        # Both dialects write naive datetimes; strip any tz so comparisons
        # against `_now()` are same-naivety.
        return value.replace(tzinfo=None) if value.tzinfo else value
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _principal_from_row(row: dict) -> Principal:
    """Build the API principal this token resolves to.

    Shape matches `kairos.scoping._principal` on every field the enforcement
    paths read — `uid`, `scopes`, `key_id`, `polls` — so a route that already
    declared `api_scope(...)` is authorized identically whether the caller
    presented an env key or an owner-minted token. The differences are two:

    * `uid` is the owner's real uid (not the flat string `"api"`), so a poll
      the token creates is attributed to the owner and shows on *their*
      dashboard — the issue's "a token acts as its owner".
    * `source="owner_token"` tells `kairos.reach` to additionally consult
      `can_manage(poll)` for the API surface, so the token reaches the polls
      its owner can manage — including polls created after mint time, with no
      per-poll grant to maintain.
    """
    scopes = frozenset(s for s in row["scopes"].split(",") if s)
    return Principal(
        uid=row["owner_uid"],
        email="",
        name=f"owner token: {row['name']}",
        source="owner_token",
        token_id=row["id"],
        scopes=scopes,
        key_id=key_id(row["token_hash"]),
        tier=None,
        # Reach (issue #63): a frozenset by default, meaning "no static grant".
        # The owner-token branch in `kairos.reach` additionally lets this
        # principal reach polls the owner holds management authority over, so
        # a static grant is neither necessary nor correct here — a per-poll
        # frozenset would go stale the moment the owner creates another poll.
        polls=frozenset(),
        # Carried for `/whoami`'s owner-token shape (PR #85 round-F): when an
        # agent asks what it holds, a wall-clock answer is the thing that
        # tells it "re-mint tomorrow". `_parse_dt` across both dialects so the
        # value is a comparable `datetime`; `resolve_token` has already proved
        # it is live, so this is always a future instant.
        expires_at=_parse_dt(row.get("expires_at")),
    )


def resolve_token(bearer: str) -> Principal | None:
    """Resolve a bearer string to an owner-token principal, or None.

    **The seam issue #82 asks for and #83 will reuse.** This is the entire
    token-check surface: scoping.resolve() calls it from `/api`, and the
    server-hosted MCP endpoint (#83) will call it from `/mcp`. Keeping the
    check behind one function means "revoked", "expired" and "unknown" answer
    401 identically everywhere, and a future route that forgets a state is
    impossible.

    Returns None for: an empty bearer, a bearer that is not a Kairos token
    (wrong prefix), a token whose hash does not match any row, a revoked
    token, an expired token. The caller renders None as a 401 — exactly as
    it does for a wrong env key — so the four refusal paths are
    indistinguishable from the outside.

    The hash lookup is deterministic (indexed equality), so two wrong bearers
    cost the same `SELECT`. We additionally run `hmac.compare_digest` over the
    row's stored hash against the computed one, which is redundant after an
    equality lookup but cheap and unmistakable in the next review.

    **Tied to the panel's lifecycle.** A mode switch that makes the panel
    unavailable (capability / none / hosted-demo) also makes `resolve_token`
    answer None -- same wording as revoked/expired, so a bearer that was live
    yesterday answers 401 today, and an operator can invalidate every
    outstanding owner token by flipping modes. See `tokens_enabled()`.
    """
    if not bearer or not bearer.startswith(TOKEN_PREFIX):
        return None
    if not tokens_enabled():
        return None
    presented_hash = _hash(bearer)
    row = db.get_api_token_by_hash(presented_hash)
    if row is None:
        return None
    # Belt-and-braces constant-time compare — the equality lookup already was
    # constant-time at byte level, but the explicit call is what a future
    # reader audits for, and it costs 64 bytes of comparison.
    if not hmac.compare_digest(row["token_hash"], presented_hash):
        return None
    if row.get("revoked_at") is not None:
        log.info("token %s revoked, refused", key_id(row["token_hash"]))
        return None
    expires_at = _parse_dt(row.get("expires_at"))
    if expires_at is None or expires_at <= _now():
        log.info("token %s expired, refused", key_id(row["token_hash"]))
        return None
    # Hot path: at most once per minute per token, write last_used_at. The
    # throttle is in-process; see module docstring for the tradeoff.
    if _should_touch(row["id"]):
        try:
            db.touch_api_token_last_used(row["id"])
        except Exception:
            # The write is advisory; a failed touch must not fail the request.
            log.exception("touch_api_token_last_used failed")
    return _principal_from_row(row)
