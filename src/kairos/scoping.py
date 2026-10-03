"""Least-privilege capabilities and blast-radius budgets for the API/MCP surface.

Issue #51. Before this module the whole `/api` surface behind
`Authorization: Bearer` was one shared secret with no scope, no per-key budget
and no ceiling on who could be mailed — and three routes
(`invite`, `nudge(force=True)`, `email-decision`) put bytes in a third party's
inbox from data the *caller* supplies. A key that leaked into an agent's
environment was therefore an unbounded mail cannon aimed at arbitrary
recipients, sending from whatever domain the deployment authenticates as.

Four separate ceilings, each for a different job:

1. **Scopes** (`api_scope(...)`) — what a key *may* do. Default deny: a route
   declares the capability it needs and a key that was not granted it gets 403.
   A read-only key cannot reach any mail-sending route, by construction rather
   than by remembering to check.
2. **Per-key budgets** (`api_scope` charges `limiter`) — how often one key may
   act. Reuses #37's `RateLimiter` singleton and its `RateLimited` signal; the
   only difference is what it charges to. #37 charges the transport peer, which
   an API client cannot vary, so its budgets are evaded by source rotation and
   are shared by every caller behind one NAT. An API caller *does* present
   something it cannot vary — the key — so that is what this charges to, which
   is the interaction #37's module docstring pointed at.
3. **Recipient-list cap** (`check_recipient_list`) — how many recipients one
   *request* may name. A hard structural bound: the point is that a single call
   cannot name an arbitrary list, so an oversized list is a 400 rather than mail.
4. **Per-poll send budget** (`charge_poll_recipients`) — how many recipients one
   *poll* may mail in a window, counted across every send path (API *and* web
   UI) and charged to the poll, so it holds **regardless of key** and cannot be
   ratcheted up by rotating keys or splitting calls.

**`force` is not a licence to spam.** Bypassing the 24h nudge cooldown is an
operator affordance for a human in the UI, so it takes its own scope
(`mail:force`) *and* its own, tighter budget (`mail_force`). The web UI's
`remind-selected` is unchanged: a human at a keyboard still has one click, and
`nudge_participants` still treats `force` as operator intent.

**Compatibility (ADR-0001/0002).** `KAIROS_API_KEY` — which the ETH/duplet
adapter sets from `SCHEDULER_API_KEY` — is still exactly as it was: one key,
all scopes, no per-key budget *unless* `KAIROS_RATE_LIMIT=on` (#37's switch,
which no existing deployment sets). An unconfigured deployment answers every
route the way it did before this file existed. Scoping is therefore invisible
until someone opts into it with `KAIROS_API_KEYS`.

**`force` is also the reason this file is not a tier system.** Which scopes and
which limits a *plan* gets is a product decision (#33, with Stripe), so `Tier`
and `register_tier` below are the seam and nothing more: no plan ships, and a
key may name a tier (`key@pro`) which resolves at request time, so #33 can
populate the registry from its subscription table without touching a call site.
"""

import hashlib
import hmac
import logging
from typing import NamedTuple

from fastapi import HTTPException, Request

from kairos import settings
from kairos.auth import bearer_credential, require_api_key

log = logging.getLogger("kairos.scoping")

# -- The capability vocabulary ---------------------------------------------
#
# Six capabilities, split so that each is a thing an operator would actually
# hand out on its own. The read/write split is the one that matters most: it is
# what makes "a read-only key cannot send mail" a structural property instead of
# a review convention.
SCOPES = (
    "polls:read",  # read poll state, responses, invites, contact log, .ics
    "polls:write",  # create/edit/delete polls, add dates, decide, edit invitees
    "respond",  # submit availability on a poll (upserts by email)
    "mail:send",  # anything that puts a message in a third party's inbox
    "mail:force",  # bypass the 24h nudge cooldown — the operator affordance
    "imip:poll",  # run the inbound IMAP poll cycle (an operator's cron job)
)

# Granting the wider capability implies the narrower one, so an operator does not
# have to write out both halves of a pair. `polls:write` cannot read back its own
# poll — which means it cannot get the slot ids it needs to add dates, decide, or
# vote — and a key with `mail:force` but not `mail:send` would be able to demand
# the cooldown bypass on a route it cannot call.
SCOPE_IMPLIES = {
    "polls:write": "polls:read",
    "mail:force": "mail:send",
}


def expand(scopes) -> frozenset[str]:
    """`scopes` closed over `SCOPE_IMPLIES`.

    Transitive, and cycle-safe: a cycle in the table cannot hang the boot, and
    an unknown name is passed through rather than dropped, so a typo surfaces at
    the check that matters (a key that does not hold it) instead of silently
    widening or silently narrowing the grant.
    """
    out = set()
    stack = list(scopes)
    while stack:
        scope = stack.pop()
        if scope in out:
            continue
        out.add(scope)
        implied = SCOPE_IMPLIES.get(scope)
        if implied and implied not in out:
            stack.append(implied)
    return frozenset(out)


ALL_SCOPES = expand(SCOPES)

# Which budget a capability draws from when the route does not override it. A
# route's rule follows from the capability it needs, so there is one declaration
# per route (`api_scope("mail:send")`) and no second table to forget to update.
DEFAULT_RULE_FOR_SCOPE = {
    "polls:read": "api",
    "polls:write": "api_write",
    "respond": "api_write",
    "mail:send": "mail",
    "mail:force": "mail",
    "imip:poll": "api_write",
}

# Rules that only exist on this surface. Added to `settings.DEFAULT_RATE_LIMITS`
# so they override with the same `KAIROS_RATE_LIMIT_<RULE>` syntax and answer to
# the same `KAIROS_RATE_LIMIT` switch as #37's public budgets — one switch, two
# families of budgets, no second mechanism. Documented in the README next to it.
API_RATE_RULES = ("api", "api_write", "mail", "mail_force")


# -- Principals -------------------------------------------------------------


class Principal(dict):
    """The authenticated caller.

    A `dict`, not a dataclass, because every existing call site already treats
    the result of `require_api_key` as `user["uid"]` / `user["email"]` and the
    point of this change is that none of them had to change.
    """

    @property
    def scopes(self) -> frozenset[str]:
        return self["scopes"]

    @property
    def key_id(self) -> str:
        return self["key_id"]


def key_id(key: str) -> str:
    """A stable, non-reversible name for a key, safe to log and to bucket by.

    A digest rather than the key itself: budgets are keyed on it and every log
    line and 403 names it, and a bearer credential must never appear in either
    (see the "never logs a capability token" guarantee #37 established for the
    public budgets). Truncated to 16 hex chars — 64 bits is far past the point
    where two live keys collide, and a shorter name is a shorter log line.
    """
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


# -- The keyring: KAIROS_API_KEYS -------------------------------------------


class KeyEntry(NamedTuple):
    key: str
    scopes: frozenset[str] | None  # None => resolve from `tier`
    tier: str | None


# `;` separates entries and `,` separates the scopes within one. Not an
# arbitrary split: with `,` doing both jobs, `k1:polls:read,respond` is genuinely
# ambiguous between "one key with two scopes" and "two keys", and a security
# control must not have a reading you have to guess at.
_DELIMITERS = ";:@"


def _reject(raw: str, why: str) -> RuntimeError:
    """A configuration error naming the variable and the offending fragment.

    Echoes only the fragment, never the whole value: `KAIROS_API_KEYS` holds
    credentials, and a boot log is the last place they should land.
    """
    return RuntimeError(f"KAIROS_API_KEYS: {why} ({raw!r})")


def parse_keyring(raw: str) -> tuple[KeyEntry, ...]:
    """Parse `KAIROS_API_KEYS` into entries. Raises on anything malformed.

    Grammar, `;`-separated entries:

        KEY                      rejected — a key with no scopes is the one
                                 mistake that silently means "full power", and
                                 the legacy var is the only way to ask for that
        KEY:scope[,scope...]     least privilege, explicit
        KEY@tier                 scopes come from a registered tier (see below)

    So: `KAIROS_API_KEYS="k1:polls:read,respond;k2:mail:send"`.

    `scope` and `tier` are mutually exclusive on purpose: one rule, two readings,
    no precedence to get wrong.

    Fails loudly rather than skipping an entry, for the reason `_parse_networks`
    does (#47): a keyring entry that is quietly dropped is an operator believing
    a key is scoped when it is not, or the reverse — and both are invisible.
    """
    entries = []
    seen = set()
    for chunk in (c.strip() for c in raw.split(";")):
        if not chunk:
            continue
        scope_part, at, tier_name = chunk.partition("@")
        if at and not tier_name:
            raise _reject(chunk, "a tier name is required after '@'")
        key, colon, scope_text = scope_part.partition(":")
        key = key.strip()
        if not key:
            raise _reject(chunk, "the key is empty")
        if any(d in key for d in _DELIMITERS):
            # token_urlsafe(32) — what .env.example tells operators to generate —
            # never produces one of these, so this only fires on a key the
            # grammar could not round-trip. Refusing is the safe direction.
            raise _reject(key, "the key contains a character the grammar cannot carry (';', ':', '@')")
        if colon and at:
            raise _reject(chunk, "a key takes scopes or a tier, not both")
        if not colon and not at:
            raise _reject(key, "a keyring entry must name scopes (KEY:scopes) or a tier (KEY@name)")
        scopes = None
        if colon:
            names = [s.strip() for s in scope_text.split(",") if s.strip()]
            if not names:
                raise _reject(chunk, "no scopes listed after ':'")
            unknown = sorted(set(names) - set(SCOPES))
            if unknown:
                raise _reject(",".join(unknown), "not a scope (known: " + ", ".join(SCOPES) + ")")
            scopes = expand(names)
        if key in seen:
            raise _reject(key_id(key), "duplicate key")
        seen.add(key)
        entries.append(KeyEntry(key, scopes, tier_name or None))
    return tuple(entries)


def keyring() -> tuple[KeyEntry, ...]:
    """The configured keyring, read at call time.

    Not cached: `require_api_key` has always read its key from the environment on
    every request, and a memo keyed on a string of secrets would keep them alive
    in a module global for the life of the process. The parse is a split over a
    short string on a surface that is measured in requests per minute.
    """
    return parse_keyring(settings.API_KEYS)


# -- Tiers: the seam #33 fills ---------------------------------------------


class Tier(NamedTuple):
    """A named bundle of capabilities and limits — the unit a plan resolves to.

    Deliberately *not* populated. Which scopes and which numbers a paying plan
    gets is a product decision, and it belongs to #33 alongside the Stripe table
    it has to agree with. What belongs here is only the shape: a tier names
    scopes, may override rate limits, and may cap a poll's send budget — so the
    moment a subscription row exists it can be turned into a `Tier` and every
    call site already respects it.

    `api_limits` and `mail_budget` default to None meaning "the deployment's own
    setting", so a tier can grant a capability without having to restate the
    numbers the operator chose.
    """

    name: str
    scopes: frozenset[str]
    api_limits: dict[str, tuple[int, int]] | None = None
    mail_budget: tuple[int, int] | None = None


_TIERS: dict[str, Tier] = {}


def register_tier(tier: Tier) -> Tier:
    """Add (or replace) a tier. The call #33 makes; nothing calls it here."""
    unknown = sorted(set(tier.scopes) - set(ALL_SCOPES))
    if unknown:
        raise RuntimeError(f"tier {tier.name!r}: not a scope ({', '.join(unknown)})")
    _TIERS[tier.name] = tier
    return tier


def tiers() -> dict[str, Tier]:
    """The registered tiers, for `GET /api/whoami` and for #33's admin tooling."""
    return dict(_TIERS)


def tier(name: str) -> Tier:
    """The registered tier called `name`, or a loud failure.

    Fail-closed on an unknown name rather than falling back to anything: a key
    that names a tier which does not exist must grant *nothing*, because the
    reason it does not exist is that nobody decided what it was worth.
    """
    try:
        return _TIERS[name]
    except KeyError:
        raise RuntimeError(
            f"tier {name!r} is not registered ({', '.join(sorted(_TIERS)) or 'no tiers are registered'})"
        ) from None


# -- Authentication + authorisation ----------------------------------------


def _legacy_key() -> str:
    """`KAIROS_API_KEY`, or "" — the same expression `require_api_key` uses.

    Restated rather than shared on purpose. `require_api_key` is the documented
    entry point an adapter may import and its env fallback is part of that
    contract (the suite sets `KAIROS_API_KEY` with `monkeypatch.setenv` after
    import, which a settings-level constant taken at import would miss), so this
    must read it the same way rather than from somewhere else — and it needs the
    value *before* deciding whether to delegate to it at all.
    """
    import os

    return settings.API_KEY or os.environ.get("KAIROS_API_KEY", "")


def _match(presented: str) -> KeyEntry | None:
    """The keyring entry for a presented credential, or None.

    Every entry is compared and the winner chosen afterwards, so a caller cannot
    learn its own position in the list from how long the check took. Compared as
    bytes so a key that is not URL-safe base64 (an operator's own passphrase) is
    checked rather than raising.
    """
    matched = None
    candidate = presented.encode("utf-8")
    for entry in keyring():
        if hmac.compare_digest(candidate, entry.key.encode("utf-8")):
            matched = entry
    return matched


def resolve(request: Request) -> Principal:
    """The principal for the bearer credential on this request, or a 401.

    Two accepted credentials, and the order is deliberate: the **keyring first**,
    so that scoping wins when a key appears in both places. The other order would
    let `KAIROS_API_KEY` silently override the least-privilege entry an operator
    just added for the same key — the exact mistake this module exists to make
    hard. A deployment that sets only `KAIROS_API_KEY` matches nothing in the ring
    and falls through, unchanged.

    The legacy check is delegated to `require_api_key` rather than reimplemented,
    so there is one implementation of "is this the legacy key" and its 401 and
    its "KAIROS_API_KEY not configured" 500 keep the exact wording an operator has
    already seen. The guard in front of it is what keeps that 500 honest: with
    only `KAIROS_API_KEYS` configured, a wrong key is a wrong key (401), not a
    missing configuration.
    """
    presented = bearer_credential(request)
    entry = _match(presented)
    if entry is not None:
        return _principal(entry)

    if not _legacy_key():
        raise HTTPException(401, "Invalid API key")
    require_api_key(request)
    return Principal(
        uid="api",
        email="",
        name="API",
        source="api_key",
        scopes=ALL_SCOPES,
        key_id=key_id(_legacy_key()),
        tier=None,
    )


def _principal(entry: KeyEntry) -> Principal:
    """The principal a keyring entry grants."""
    scopes, name = entry.scopes, entry.tier
    if scopes is None:
        try:
            resolved = tier(name)
        except RuntimeError as exc:
            # An operator error rather than a caller's, but still a 401: the key
            # demonstrably grants nothing, and a 5xx would tell a probing caller
            # that the key exists and its configuration is broken.
            log.error("%s (key %s)", exc, key_id(entry.key))
            raise HTTPException(401, "Invalid API key") from None
        scopes = expand(resolved.scopes)
        name = resolved.name
    return Principal(
        uid="api",
        email="",
        name="API",
        source="api_key",
        scopes=scopes,
        key_id=key_id(entry.key),
        tier=name,
    )


def enforce(principal: dict, scope: str) -> None:
    """403 unless `principal` holds `scope`.

    The status is 403, not 404 and never 500: the caller is authenticated and
    the route exists, it is simply not theirs to use. Naming the missing scope
    in the message is what makes a scoped key debuggable by an agent — the whole
    point of scoping is that the refusal is legible.
    """
    held = principal.get("scopes") or frozenset()
    if scope in held:
        return
    log.warning(
        "key %s lacks scope %r (granted: %s)",
        principal.get("key_id", "?"),
        scope,
        ",".join(sorted(held)) or "none",
    )
    raise HTTPException(
        403,
        f"This API key is not allowed to {scope}. It grants: "
        f"{', '.join(sorted(held)) or 'nothing'}. Ask the operator for the {scope} scope.",
    )


class api_scope:
    """Authenticate, charge this caller's budget, then require one capability.

        @router.post("/polls/{poll_id}/invite")
        def invite(poll, request, user=Depends(api_scope("mail:send"))): ...

    One dependency rather than an authenticator plus an authorizer so the two
    cannot come apart: there is no signature that authenticates without also
    declaring what it needs, and no route that can be checked by reading its
    parameters. A class rather than a closure so the capability it enforces is
    inspectable off the live route table — which is what the audit test reads,
    and what stops a new `/api` route from shipping with no scope declared.

    `rule=` overrides which budget a route draws from. No route overrides it
    today — the rule follows from the capability, which is why there is one
    declaration per route and no second table — but it is here so a tier or a
    future route can charge a different budget without a new dependency class.
    `scope=None` means "any authenticated key" and charges the floor rule: only
    `/whoami` uses it (`/ping` needs no key at all).
    """

    def __init__(self, scope: str | None = None, rule: str | None = None):
        if scope is not None and scope not in ALL_SCOPES:
            raise RuntimeError(f"{scope!r} is not a scope ({', '.join(SCOPES)})")
        self.scope = scope
        self.rule = rule or DEFAULT_RULE_FOR_SCOPE.get(scope or "", "api")

    def __call__(self, request: Request) -> dict:
        principal = resolve(request)
        # Charged before the scope check, on purpose: a key looping on a route it
        # may not use spends its budget doing so, so the 403 cannot be used as a
        # free probe of what a key is refused.
        charge_request(principal, self.rule)
        if self.scope:
            enforce(principal, self.scope)
        request.state.api_principal = principal
        return principal


def require_capability(principal: dict, scope: str) -> None:
    """Imperative form, for a capability a route needs only sometimes.

    Two routes reach `mail:send` through a scope that is nominally something
    else — `add_slots(notify=True)` and `nudge(force=True)` both mail. A
    dependency cannot see the body, so those call this once the body is parsed.
    """
    enforce(principal, scope)


# -- Budgets ----------------------------------------------------------------


def charge_request(principal: dict, rule: str) -> None:
    """Charge one authenticated API request against `rule`, for this key only.

    The only difference from #37's `rate_limit` dependency is the bucket key.
    #37 charges the transport peer, which an API caller cannot vary, so its
    budget survives nothing but a single source and is shared by everything
    behind one NAT. A key *is* something the caller cannot vary, which is what
    makes a per-key budget both evadable-proof and fair between two keys — and
    it is the interaction #37's module docstring left for this issue.

    Two keys must not starve each other, so the keyspace is the key, never the
    deployment. Fail-open on an internal fault, exactly as `rate_limit` does and
    for the same reason: an outage in a counter must not read as a broken API,
    and the remaining ceilings (the recipient cap and the per-poll budget) do
    not depend on this one.
    """
    from kairos import ratelimit

    if not settings.RATE_LIMIT_ENABLED:
        return
    limit, window = settings.RATE_LIMITS.get(rule, (0, 0))
    if limit <= 0:
        return
    key = f"key:{principal['key_id']}"
    try:
        allowed, retry_after = ratelimit.limiter.check(rule, limit, window, key)
    except Exception:
        log.exception("rate limiter failed; allowing the request")
        return
    if not allowed:
        log.warning("rate limit %s exceeded by API key %s", rule, principal["key_id"])
        raise ratelimit.RateLimited(rule, retry_after)


def charge_force(principal: dict) -> None:
    """The extra, tighter budget a `force=True` nudge spends.

    Scoped *and* rate-limited on purpose. The scope is what stops an agent that
    holds only `mail:send` from reaching the cooldown bypass at all; this is what
    stops a key that legitimately holds `mail:force` — an operator's automation
    key — from using it as a spam lever, which is the failure the issue is
    actually about. 5/hour against `mail`'s 20/hour.
    """
    charge_request(principal, "mail_force")


def check_recipient_list(count: int, *, what: str = "recipients") -> None:
    """400 when a request names more than `MAIL_MAX_RECIPIENTS` recipients.

    A hard cap on the *request*, not a rate: a per-call list is the one shape
    where refusing is free. The caller still has the addresses — split the call
    into two. That is why this refuses while the fan-out routes below budget
    instead: there the recipient list is the poll's, and a poll with more
    participants than the cap is a legitimate meeting, not an attack.

    Applied to caller-supplied lists only (`invite`, `nudge(emails=[...])`, the
    UI's `remind-selected`). It is a *ceiling on blast radius*, so it ships on by
    default at a value a hand-driven workflow never reaches, unlike the
    address-keyed budgets of #37 which punish a shared NAT and stay opt-in.
    """
    limit = settings.MAIL_MAX_RECIPIENTS
    if not limit or count <= limit:
        return
    log.warning("refused %d %s in one request (cap %d)", count, what, limit)
    raise HTTPException(
        400,
        f"{count} {what} in one request is over the {limit}-recipient ceiling. "
        f"Send them in batches, or raise KAIROS_MAIL_MAX_RECIPIENTS "
        f"(0 disables the cap).",
    )


def charge_poll_recipients(poll_id: str, count: int) -> None:
    """Charge `count` recipients against one poll's send budget. 429 when spent.

    Keyed on the poll, not the key, which is the property the issue asks for:
    the budget holds *regardless of key*, so it survives a rotated or stolen
    credential — the only per-call ceiling that does. Counted from every send
    path (the API's `invite` / `nudge` / `email-decision` / `imip-decision`, the
    web UI's `remind` / `remind-selected` / `email-decision`) so switching
    surfaces cannot buy a bigger allowance, and so ADR-0012's parity invariant
    holds by construction rather than by review.

    Charged against the *targeted* recipients, not the ones that end up sent:
    `force` narrows what actually goes out, and a budget that shrank when the
    cooldown was bypassed would make the bypass cheaper to abuse.
    """
    from kairos import ratelimit

    limit, window = settings.MAIL_PER_POLL
    if limit <= 0 or count <= 0:
        return
    try:
        allowed, retry_after = ratelimit.limiter.check(
            "mail_per_poll", limit, window, f"poll:{poll_id}", cost=count
        )
    except Exception:
        log.exception("poll mail budget failed; allowing the send")
        return
    if not allowed:
        log.warning("poll %s exhausted its mail budget (%d)", poll_id, limit)
        raise ratelimit.RateLimited("mail_per_poll", retry_after)


# -- Boot -------------------------------------------------------------------


def boot_report() -> str:
    """Validate the keyring and describe the API surface's authorisation, for the
    startup log. Raises (refusing the boot) on a malformed keyring — a control an
    operator believes is in force and is not is worse than one that is off.

    Registered from `create_app()` rather than from `settings` so the parsing
    lives next to the grammar and cannot drift from it, and so the ETH/duplet
    adapter — which calls `create_app()` directly and never imports `settings`
    first — gets the same check as the `kairos` entrypoint.
    """
    entries = keyring()
    for entry in entries:
        if entry.tier and entry.tier not in _TIERS:
            # Not fatal: tiers are registered at runtime by #33, which may not
            # have run yet. A key naming one grants nothing (see `resolve`).
            log.warning(
                "API key %s names tier %r, which is not registered; it grants nothing until the tier exists",
                key_id(entry.key),
                entry.tier,
            )
    scopes = sorted({s for e in entries for s in (e.scopes or frozenset())})
    legacy = "KAIROS_API_KEY (full scope)" if _legacy_key() else "unset"
    return (
        f"API surface: {legacy}; "
        f"{len(entries)} scoped key(s) in KAIROS_API_KEYS"
        + (f" granting {', '.join(scopes)}" if scopes else "")
        + f"; rate limits {'on' if settings.RATE_LIMIT_ENABLED else 'off'}"
        f" (api {', '.join(API_RATE_RULES)})"
        f"; mail ceiling {settings.MAIL_MAX_RECIPIENTS or 'off'}/request,"
        f" poll budget {settings.MAIL_PER_POLL[0] or 'off'}/"
        f"{settings.MAIL_PER_POLL[1]}s"
    )
