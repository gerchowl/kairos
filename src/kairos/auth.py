"""Owner authentication — pluggable, reverse-proxy friendly.

Modes (KAIROS_AUTH):
  demo    everyone is the same demo owner (playgrounds, local trials)
  header  trust identity headers injected by ANY SSO reverse proxy
          (Shibboleth/Apache, oauth2-proxy, Authelia, Cloudflare Access, ...);
          optionally gate with KAIROS_ALLOW (uids/emails) and with
          KAIROS_TRUSTED_PROXY_CIDRS (which peers may set those headers at all)
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


def peer_is_trusted(request: Request) -> bool:
    """May this request's peer assert identity headers?

    Fails closed: with an allowlist configured, anything outside it is
    untrusted. With none configured, everything is trusted — the pre-existing
    behaviour, safe only while the app port is not publicly reachable.
    """
    networks = settings.TRUSTED_PROXY_NETWORKS
    if not networks:
        return True
    peer = peer_address(request)
    if not peer:
        return False
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        # Not an IP (a unix socket path, say) — cannot be matched against a CIDR
        # list, so treat as untrusted rather than waving it through.
        return False
    return any(address in net for net in networks)


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
