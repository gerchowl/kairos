"""Owner authentication — pluggable, reverse-proxy friendly.

Modes (KAIROS_AUTH):
  demo    everyone is the same demo owner (playgrounds, local trials)
  header  trust identity headers injected by ANY SSO reverse proxy
          (Shibboleth/Apache, oauth2-proxy, Authelia, Cloudflare Access, ...);
          optionally gate with KAIROS_ALLOW (uids/emails) and with
          KAIROS_TRUSTED_PROXY_CIDRS (which peers may set those headers at all)
  oidc    Kairos terminates OIDC itself — no proxy to deploy. Identity comes
          from a signed session cookie minted by `kairos.oidc` after an
          authorization-code exchange, gated by a subject allowlist that denies
          by default. See docs/design/oidc-login.md.
  none    no owner auth — the web management UI is disabled, API + public
          response pages only

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
    """The poll-owner identity for this request, or None.

    This stays the one seam every caller goes through, and stays replaceable at
    runtime (`kairos.auth.get_user = mine`) — the ETH/duplet adapter depends on
    that, and so does any bespoke session-cookie portal.
    """
    if settings.AUTH_MODE == "demo":
        return dict(DEMO_USER)
    if settings.AUTH_MODE == "header":
        return _header_user(request)
    if settings.AUTH_MODE == "oidc":
        # Imported here, not at module scope: `kairos.oidc` needs `_serializer`
        # from this module, and a top-level import each way is a cycle.
        from kairos.oidc import session_user

        return session_user(request)
    return None


def require_auth(request: Request) -> dict:
    user = get_user(request)
    if not user:
        raise HTTPException(401, "Not authenticated")
    return user


def get_base_url(request: Request) -> str:
    """Public base URL for share links: explicit KAIROS_PUBLIC_URL (SSoT,
    e.g. the WASM playground or odd proxies), else forwarding headers."""
    if settings.PUBLIC_URL:
        return settings.PUBLIC_URL.rstrip("/")
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    return f"{proto}://{host}"


def require_api_key(request: Request) -> dict:
    """`Authorization: Bearer <KAIROS_API_KEY>` with constant-time comparison."""
    expected = settings.API_KEY or os.environ.get("KAIROS_API_KEY", "")
    if not expected:
        raise HTTPException(500, "KAIROS_API_KEY not configured")
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")
    if not hmac.compare_digest(auth[7:], expected):
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
