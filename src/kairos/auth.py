"""Owner authentication — pluggable, reverse-proxy friendly.

Modes (KAIROS_AUTH):
  demo    everyone is the same demo owner (playgrounds, local trials)
  header  trust identity headers injected by ANY SSO reverse proxy
          (Shibboleth/Apache, oauth2-proxy, Authelia, Cloudflare Access, ...);
          optionally gate with KAIROS_ALLOW (uids/emails) and with
          KAIROS_TRUSTED_PROXY_CIDRS (which peers may set those headers at all)
  none    no owner auth — the web management UI is disabled, API + public
          response pages only

Poll *management* authority is a separate question from who the caller is, and
lives in `require_manage` below (obligation S6, issue #29): an authenticated
owner, or possession of the poll's `admin_token` capability.

Respondent identity (signed per-poll cookies, invite tokens) is independent
of this and always available. Replace get_user at runtime for custom
integrations (e.g. a session-cookie portal): `kairos.auth.get_user = mine`.
"""

import hmac
import ipaddress
import os

from fastapi import HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from kairos import settings

DEMO_USER = {"uid": "demo", "name": "Demo User", "email": "demo@example.org"}


def peer_address(request: Request) -> str | None:
    """The real transport peer, or None if the ASGI scope carries no client.

    Deliberately *not* X-Forwarded-For: that header is attacker-controlled
    unless the peer is already known to be our proxy, which is the very thing
    being decided here. Requires uvicorn's `proxy_headers` to be off — otherwise
    uvicorn rewrites scope["client"] from XFF *before* the app sees it and this
    would return the spoofed value. See `kairos.cli`, which sets
    proxy_headers=False for exactly this reason.
    """
    client = request.scope.get("client")
    return client[0] if client else None


def parse_address(value: str):
    """`value` as an ip_address, with IPv4-mapped IPv6 folded down to IPv4.

    None when it is not an IP at all (a unix socket path, say).

    The fold matters because a dual-stack listener ("kairos --host ::", the
    container/K8s default) sees IPv4 clients as IPv4-mapped IPv6
    ("::ffff:127.0.0.1"). Without this, an operator following the README's own
    example allowlist gets a silently dead app: every peer fails to match an
    IPv4 network. It still fails closed, so there is no exposure — it just fails
    closed *everywhere*. Only IPv6Address has .ipv4_mapped, hence the getattr.

    Folding also gives one host exactly one spelling, which is what lets a rate
    limiter charge ::ffff:203.0.113.7 and 203.0.113.7 to a single budget.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return getattr(address, "ipv4_mapped", None) or address


def canonical_address(value: str) -> str:
    """`value` in the one spelling that identifies the host, or itself when it is
    not an IP. Used as a map key, so it must be total."""
    address = parse_address(value)
    return str(address) if address is not None else value


def address_is_trusted(address: str | None) -> bool:
    """Is this address inside `KAIROS_TRUSTED_PROXY_CIDRS`?

    Fails closed: with an allowlist configured, anything unparseable or outside
    it is untrusted. With none configured, everything is trusted — the
    pre-existing behaviour, safe only while the app port is not publicly
    reachable.

    Takes an address rather than a request so the rate limiter can ask the same
    question about every hop in a forwarded chain, instead of re-implementing
    the CIDR matching (and the IPv4-mapped fold) a second time.
    """
    networks = settings.TRUSTED_PROXY_NETWORKS
    if not networks:
        return True
    if not address:
        return False
    parsed = parse_address(address)
    # Not an IP (a unix socket path, say) — cannot be matched against a CIDR
    # list, so treat as untrusted rather than waving it through.
    return parsed is not None and any(parsed in net for net in networks)


def peer_is_trusted(request: Request) -> bool:
    """May this request's peer assert identity headers?"""
    return address_is_trusted(peer_address(request))


def _serializer(salt: str = "session") -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.session_secret(), salt=salt)


def _header_user(request: Request) -> dict | None:
    uid = request.headers.get(settings.AUTH_UID_HEADER)
    if not uid:
        return None
    email = request.headers.get(settings.AUTH_EMAIL_HEADER, "")
    if settings.ALLOW and not ({uid.lower(), email.lower()} & settings.ALLOW):
        return None
    name = request.headers.get(settings.AUTH_NAME_HEADER) or email or uid
    return {"uid": uid, "name": name, "email": email}


def get_user(request: Request) -> dict | None:
    """The poll-owner identity for this request, or None."""
    if settings.AUTH_MODE == "demo":
        return dict(DEMO_USER)
    if settings.AUTH_MODE == "header":
        return _header_user(request)
    return None


def require_auth(request: Request) -> dict:
    user = get_user(request)
    if not user:
        raise HTTPException(401, "Not authenticated")
    return user


# -- Poll management authority (obligation S6, issue #29) -------------------
#
# One predicate, so authorization stops being re-decided per route. Two
# independent ways to be a poll's manager (ADR-0001, ADR-0002, ADR-0009):
#
#   1. an authenticated identity equal to the poll's `creator_id` (the rule that
#      has always existed) or its `owner_id` (an account id, or the header uid,
#      on polls created since #29);
#   2. possession of the poll's `admin_token`, which the caller presents.
#
# In `KAIROS_AUTH=header` (ETH, every self-hoster) rule 1 fires exactly as it
# always did and rule 2 is never reachable in practice -- no such route exists
# and no token is ever shown to anyone -- so those deployments are unchanged.


def _token_manages(poll: dict, token: str | None) -> bool:
    """Does `token` equal this poll's management capability? Fails closed."""
    expected = poll.get("admin_token")
    if not expected or not token:
        return False
    # Both sides are str in practice -- a VARCHAR column and a URL path
    # parameter -- and both are coerced anyway, because neither input is
    # trustworthy enough to type-check: hmac.compare_digest raises TypeError on
    # a non-ASCII str (a URL can carry any byte) and AttributeError on bytes (a
    # hand-rolled `get_poll` seam need not), and a 500 provoked by someone
    # else's malformed input is a worse answer than a 403.
    return hmac.compare_digest(str(token).encode(), str(expected).encode())


def can_manage(poll: dict, request: Request, *, token: str | None = None,
               user: dict | None = None) -> bool:
    """Does the caller of `request` hold management authority over `poll`?

    `token` is the management capability the caller presented, if any. It is
    passed explicitly rather than read out of the request on purpose:
    `public.py` has routes whose path parameter is *also* called `token` and
    holds a `public_token`, so a route that forgot to pass one would otherwise
    hand this predicate a value it never meant to.

    `user` is the caller's already-resolved identity; omit it and it is resolved
    from `request` here. A route that has authenticated should pass the user it
    holds, so `auth.get_user` -- a documented runtime seam (`kairos.auth.get_user
    = mine`) whose replacement need not be cheap or idempotent -- runs at most
    once per request. Omitting it is what an anonymous capability route (#30's
    `/manage/<token>`) wants.

    The poll is read with `.get()` throughout, so a row that predates these
    columns -- or a stubbed dict in a test -- authorizes exactly as it always
    did.

    Deliberately *not* here: CSRF (request integrity, the route's business) and
    the `manage_verified_at` send-gate (obligation A2, #31 -- a property of the
    poll, not of who is asking). Keeping them out is what lets #31 add that gate
    without re-deciding who may manage a poll.
    """
    user = user if user is not None else get_user(request)
    # Truthiness-checked uid, compared with `==` rather than membership in a
    # tuple: `None in (None, None)` is True, and `owner_id` IS NULL on every
    # pre-#29 row and on every #30 accountless poll -- so a seam that returns
    # `{"uid": None}` for "not logged in" (the natural shape for a session
    # cookie portal, and `get_user` is a documented supported seam) would have
    # granted management of every such poll. Fail closed on an absent uid.
    uid = (user or {}).get("uid")
    if uid and (uid == poll.get("creator_id") or uid == poll.get("owner_id")):
        return True
    return _token_manages(poll, token)


def require_manage(poll: dict, request: Request, *, token: str | None = None,
                   user: dict | None = None) -> dict:
    """`poll` if the caller may manage it, else 403. Returns the poll so a
    route can write `poll = require_manage(poll, request, user=user)`.

    403 for an anonymous caller and for a wrong-but-authenticated one alike:
    "you are not the owner" is the only thing either is entitled to learn. A
    route that wants a different shape (an HTML error page, a login redirect)
    asks `can_manage` first -- see web.edit_poll_page.

    A missing poll is not handled here: that is a 404 and stays the route's
    business, so "forbidden" and "gone" never share one code path.
    """
    if not can_manage(poll, request, token=token, user=user):
        raise HTTPException(403, "Not the poll owner")
    return poll


def get_base_url(request: Request) -> str:
    """Public base URL for share links: explicit KAIROS_PUBLIC_URL (SSoT,
    e.g. the WASM playground or odd proxies), else forwarding headers."""
    if settings.PUBLIC_URL:
        return settings.PUBLIC_URL.rstrip("/")
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    return f"{proto}://{host}"


def bearer_credential(request: Request) -> str:
    """The credential from `Authorization: Bearer <key>`, or a 401.

    Split out of `require_api_key` because the scoped API (#51) must read the
    header before it knows *which* credential to compare it against: its keyring
    is checked before the legacy single key, not after.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")
    return auth[7:]


def require_api_key(request: Request) -> dict:
    """`Authorization: Bearer <KAIROS_API_KEY>` with constant-time comparison.

    The single unscoped credential — every poll, every capability, no budget.
    Deliberately unchanged: the ETH/duplet adapter (from `SCHEDULER_API_KEY`) and
    every self-hoster set `KAIROS_API_KEY` and must keep working exactly as they
    do (ADR-0001/0002). Least-privilege keys arrive via `KAIROS_API_KEYS`, and
    `kairos.scoping` delegates back here for any credential not in that ring, so
    there is one implementation of the legacy check and its 401/500 wording.
    """
    expected = settings.API_KEY or os.environ.get("KAIROS_API_KEY", "")
    if not expected:
        raise HTTPException(500, "KAIROS_API_KEY not configured")
    if not hmac.compare_digest(bearer_credential(request), expected):
        raise HTTPException(401, "Invalid API key")
    return {"uid": "api", "email": "", "name": "API", "source": "api_key"}


# -- Anonymous respondent identity (signed per-poll browser cookie) -----------

RESPONSE_REF_MAX_AGE = 60 * 60 * 24 * 180  # 180 days


def sign_response_ref(response_id: str) -> str:
    return _serializer(salt="sched-resp").dumps({"rid": response_id})


def load_response_ref(token: str | None) -> str | None:
    if not token:
        return None
    try:
        return _serializer(salt="sched-resp").loads(token, max_age=RESPONSE_REF_MAX_AGE).get("rid")
    except (BadSignature, SignatureExpired):
        return None
