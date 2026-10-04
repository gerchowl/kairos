"""First-party OIDC owner login — Kairos as the OAuth 2.0 / OpenID Connect client.

This is owner *identity only* (issue #53). Not accounts, not dashboards, not plan
limits: `KAIROS_AUTH=oidc` resolves `kairos.auth.get_user` from a signed session
cookie that is only ever minted here, after a full authorization-code exchange
and an allowlist check. Everything else in Kairos is unchanged.

Why this exists when `KAIROS_AUTH=header` already reaches every IdP (ADR-0002):
header mode needs an authenticating proxy in front, and nginx cannot terminate
OIDC — which is exactly why `oauth2-proxy` and Authelia exist as separate
boxes. Every self-hosted app people actually run (Grafana, Nextcloud, Vault,
Gitea, Immich) terminates OIDC itself, because that is what makes deployment
four environment variables instead of an infrastructure project. See
docs/design/oidc-login.md.

The flow, in the order the requests happen:

    GET  {prefix}/login          sign-in page (the default KAIROS_LOGIN_URL)
    GET  {prefix}/oidc/start     mints state + nonce + PKCE verifier into a
                                 signed short-lived *transaction* cookie and
                                 302s to the IdP
    GET  {prefix}/oidc/callback  state matches that cookie (CSRF), the code is
                                 exchanged with the verifier, the id_token is
                                 verified, the subject is allowlisted, and a
                                 signed *session* cookie is set
    POST {prefix}/oidc/logout    clears the session cookie (CSRF-protected)

Deliberately stdlib + the stack already here: no session library, no JWT
library, no OAuth library. `urllib.request` for HTTP, `itsdangerous` (already
how `auth.py` and `csrf.py` sign things) for both cookies, and the ~40 lines of
RSA PKCS#1 v1.5 verification in `_rsa_verify` for the id_token signature. That
is the trade ADR-0004 made for iCalendar: more code to own, zero license and CVE
surface added. Every byte of that crypto is exercised offline in
tests/test_oidc.py against a locally generated RSA key; the honest list of what
only a real IdP can prove is in docs/design/oidc-login.md.

Two design rules that are not negotiable, both stated in the issue:

1. **Allowlist by known subject, never "anyone the IdP vouched for".** The ETH
   deployment's Shibboleth adapter (`duplet-webserver/libs/duplet_common/auth.py`)
   requires the asserted identity to resolve to a *known row in the directory*
   with an explicit per-app grant, because the SP sits in the full SWITCHaai
   federation and so *any* university account produces headers — its own
   comment is "spoofed headers fail the DB check". Same shape here: a successful
   exchange is necessary and not sufficient. `KAIROS_OIDC_ALLOWED_SUBJECTS` /
   `_ALLOWED_EMAIL_DOMAINS` default to deny, and an empty allowlist refuses to
   boot rather than admitting the world.
2. **`kairos.auth.get_user` stays the seam.** The ETH adapter replaces it at
   runtime; this mode is one more branch inside it, not a restructuring.
"""

import base64
import binascii
import hashlib
import hmac
import json
import logging
import math
import os
import re
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPRedirectHandler, build_opener
from urllib.request import Request as UrlRequest

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, SignatureExpired

from kairos import settings
from kairos.auth import _serializer, get_base_url
from kairos.csrf import require_csrf
from kairos.helpers import env
from kairos.http import form_data
from kairos.ratelimit import rate_limit
from kairos.templating import render

log = logging.getLogger("kairos.oidc")

P = settings.PREFIX
CALLBACK_PATH = f"{P}/oidc/callback"

SESSION_COOKIE = "kairos_oidc_session"
TRANSACTION_COOKIE = "kairos_oidc_txn"

# 12h: an owner session is a working day, and a scheduling poll is a
# short-lived artefact — a day-long cookie is the honest ceiling, not a
# month-long one. The transaction cookie only has to survive one round trip
# through a human's IdP login, second factor and all.
SESSION_MAX_AGE = 12 * 60 * 60
TRANSACTION_MAX_AGE = 10 * 60

# Clock skew tolerated on exp/nbf/iat. Small on purpose: a login that fails at
# the boundary is a login the operator retries.
CLOCK_SKEW = 60

# No redirects, no unbounded reads. Every HTTP call Kairos makes is to a URL
# that came out of a document it just fetched, so a redirect off the IdP is
# either a misconfiguration or an attack and both should be loud; and a hostile
# endpoint must not be able to exhaust memory.
HTTP_TIMEOUT = 10
MAX_RESPONSE_BYTES = 1 << 20

# How long a fetched discovery document / JWKS is reused. Long enough that a
# busy deployment is not re-fetching per request, short enough that a rotated
# signing key is picked up without a restart.
METADATA_TTL = 3600

BOOT_WARNINGS: list[str] = []


class OidcError(Exception):
    """Any failure to obtain or accept an identity.

    The message is for the operator's log. Callers show an end user something
    generic: an IdP error string can carry a client id, a redirect URI and
    occasionally a subject, none of which belong in a page.
    """


# -- Configuration ----------------------------------------------------------
# Env-only (ADR-0003), parsed and validated here rather than in settings.py so
# the whole feature is one self-contained file. The rules, and the refusal to
# start on a bad value, are the ones settings._parse_networks set: a typo in a
# security allowlist is not a skipped line, it is a control the operator
# believes is in force and is not.


def _split(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def _parse_subjects(raw: str) -> frozenset[str]:
    subjects = set()
    for item in _split(raw):
        # `sub` is an opaque, case-sensitive string. Whitespace or a control
        # character in it is a paste accident — a truncated value, a line break
        # from a wrapped console — and admitting one would create an allowlist
        # entry that can never match.
        if re.search(r"\s", item) or any(ord(c) < 0x20 or ord(c) == 0x7F for c in item):
            raise RuntimeError(
                f"KAIROS_OIDC_ALLOWED_SUBJECTS: {item!r} contains whitespace or a control "
                "character — an OIDC subject is one opaque token"
            )
        subjects.add(item)
    return frozenset(subjects)


_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")


def _parse_domains(raw: str) -> frozenset[str]:
    domains = set()
    for item in _split(raw):
        domain = item.lower().lstrip("@").rstrip(".")
        if not _DOMAIN_RE.match(domain):
            # Matched against the *whole* domain, never with endswith, so
            # "notexample.org" cannot ride in on an "example.org" entry.
            raise RuntimeError(
                f"KAIROS_OIDC_ALLOWED_EMAIL_DOMAINS: {item!r} is not a bare domain "
                "(expected example.org, or example.org,subsidiary.example.org)"
            )
        domains.add(domain)
    return frozenset(domains)


def _is_loopback(host: str | None) -> bool:
    return bool(host) and (host == "localhost" or host.startswith("127.") or host == "::1")


def _check_url(value: str, var: str, error=RuntimeError) -> str:
    """An https URL, or http on loopback for a local Keycloak/Authentik dev run."""
    parsed = urlparse(value)
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise error(f"{var}: {value!r} must be an absolute https:// URL")
    if parsed.scheme == "http" and not _is_loopback(parsed.hostname):
        raise error(
            f"{var}: {value!r} is plain http to a non-loopback host. A login flow carries an "
            "authorization code and sets a session cookie; both must travel over TLS."
        )
    if parsed.query or parsed.fragment:
        raise error(f"{var}: {value!r} must have no query or fragment")
    return value.rstrip("/")


ISSUER = os.environ.get("KAIROS_OIDC_ISSUER", "").strip()
CLIENT_ID = os.environ.get("KAIROS_OIDC_CLIENT_ID", "").strip()
CLIENT_SECRET = os.environ.get("KAIROS_OIDC_CLIENT_SECRET", "").strip()
REDIRECT_URI = os.environ.get("KAIROS_OIDC_REDIRECT_URI", "").strip()
SCOPES = os.environ.get("KAIROS_OIDC_SCOPES", "openid email profile").strip() or "openid"
# `post` (client_id + client_secret in the form body) is the default because it
# is what the hosted providers document; `basic` (RFC 6749 §2.3.1 HTTP Basic)
# is what the self-hosted ones default to. Both spellings are in the wild, so
# this is a knob rather than a guess.
CLIENT_AUTH = os.environ.get("KAIROS_OIDC_CLIENT_AUTH", "post").strip().lower()
# Off by default, and named for what it weakens: an IdP that lets anyone claim
# any address at an allowed domain turns domain allowlisting into a claim about
# a string rather than about a verified mailbox.
TRUST_UNVERIFIED_EMAIL = os.environ.get("KAIROS_OIDC_TRUST_UNVERIFIED_EMAIL", "").strip().lower() in (
    "1",
    "on",
    "true",
    "yes",
)
# The allowlists are the only two values here that can *fail* to parse, so the
# gate on the auth mode has to sit here rather than further down: parsing before
# the gate would let a stray `KAIROS_OIDC_ALLOWED_SUBJECTS='alice bob'` — one
# pasted into the wrong shell, or exported for another app — take down a
# header-mode self-hoster that never asked for OIDC at all. That is precisely the
# regression ADR-0001/0002 forbid, and it is invisible to a test that patches the
# already-parsed values, so the gate is local to the parse and
# `tests/test_oidc.py` re-imports the module to hold it in place.
if settings.AUTH_MODE == "oidc":
    ALLOWED_SUBJECTS = _parse_subjects(os.environ.get("KAIROS_OIDC_ALLOWED_SUBJECTS", ""))
    ALLOWED_EMAIL_DOMAINS = _parse_domains(os.environ.get("KAIROS_OIDC_ALLOWED_EMAIL_DOMAINS", ""))
else:
    ALLOWED_SUBJECTS = frozenset()
    ALLOWED_EMAIL_DOMAINS = frozenset()


def _validate_config() -> None:
    """Refuse to boot on an OIDC deployment that is misconfigured.

    Gated on KAIROS_AUTH=oidc, and that gate is the point: with OIDC switched
    off, importing this module must be a no-op, so a self-hoster or the ETH
    deployment that happens to export a stray KAIROS_OIDC_* variable stays
    byte-for-byte unaffected (ADR-0001/0002). A deployment that *opted in* to
    this mode gets the loud boot instead — which is the failure #47 was filed
    about, where an allowlist entry is silently skipped.
    """
    if settings.AUTH_MODE != "oidc":
        return
    if not ISSUER:
        raise RuntimeError(
            "KAIROS_AUTH=oidc requires KAIROS_OIDC_ISSUER (the issuer identifier, e.g. "
            "https://id.example.org/realms/main). See docs/design/oidc-login.md."
        )
    _check_url(ISSUER, "KAIROS_OIDC_ISSUER")
    if not CLIENT_ID:
        raise RuntimeError("KAIROS_AUTH=oidc requires KAIROS_OIDC_CLIENT_ID")
    if CLIENT_AUTH not in ("basic", "post"):
        raise RuntimeError(
            f"KAIROS_OIDC_CLIENT_AUTH: {CLIENT_AUTH!r} is not a token-endpoint client "
            "authentication method (use 'basic' or 'post')"
        )
    if REDIRECT_URI:
        _check_url(REDIRECT_URI, "KAIROS_OIDC_REDIRECT_URI")
    if not ALLOWED_SUBJECTS and not ALLOWED_EMAIL_DOMAINS:
        # Not a typo check — a policy refusal. An OIDC deployment with an empty
        # allowlist admits *every account at the IdP*, which is precisely the
        # shape this design exists to refuse (see the module docstring).
        raise RuntimeError(
            "KAIROS_AUTH=oidc requires an owner allowlist: set KAIROS_OIDC_ALLOWED_SUBJECTS "
            "(exact `sub` values from your IdP) or KAIROS_OIDC_ALLOWED_EMAIL_DOMAINS. Kairos "
            "does not admit 'anyone the IdP vouched for' — see docs/design/oidc-login.md."
        )
    if not CLIENT_SECRET:
        BOOT_WARNINGS.append(
            "KAIROS_OIDC_CLIENT_SECRET is unset, so Kairos registers as a public client "
            "(PKCE only). That is right for a client registered as public and wrong for one "
            "registered as confidential — a confidential IdP will refuse the token exchange."
        )
    if not REDIRECT_URI and not settings.PUBLIC_URL:
        BOOT_WARNINGS.append(
            "neither KAIROS_OIDC_REDIRECT_URI nor KAIROS_PUBLIC_URL is set, so the redirect "
            "URI and the session cookie's Secure flag are derived from request headers. Set one "
            "of them behind a proxy."
        )
    if settings.ALLOW:
        BOOT_WARNINGS.append(
            "KAIROS_ALLOW is set but KAIROS_AUTH=oidc never reads identity headers, so it has "
            "no effect here. Use KAIROS_OIDC_ALLOWED_SUBJECTS."
        )


_validate_config()


def provider_label() -> str:
    """The IdP's host, for the sign-in button. Never the issuer's path."""
    return (urlparse(ISSUER).hostname if ISSUER else "") or "your identity provider"


def identity_report() -> str:
    """One boot line: which identity boundary is in force, and how narrow.

    Same reasoning as `mail_identity_report()` — a green boot must not be the
    only evidence an operator has about which control decided their identity.
    """
    if settings.AUTH_MODE != "oidc":
        return f"owner auth: {settings.AUTH_MODE} (OIDC not configured)"
    redirect = REDIRECT_URI or f"{settings.PUBLIC_URL or '<derived from request headers>'}{CALLBACK_PATH}"
    allowlist = []
    if ALLOWED_SUBJECTS:
        allowlist.append(f"{len(ALLOWED_SUBJECTS)} subject(s)")
    if ALLOWED_EMAIL_DOMAINS:
        allowlist.append(
            f"{len(ALLOWED_EMAIL_DOMAINS)} email domain(s), "
            f"{'unverified accepted' if TRUST_UNVERIFIED_EMAIL else 'email_verified required'}"
        )
    edge = (
        " + trusted-proxy CIDRs (edge only, not the identity boundary)"
        if settings.TRUSTED_PROXY_NETWORKS
        else ""
    )
    return (
        f"owner auth: oidc (issuer={ISSUER}, client={CLIENT_ID}, redirect={redirect}, "
        f"allowlist={' + '.join(allowlist) or 'none'}{edge}; session cookie {SESSION_COOKIE}, "
        f"{SESSION_MAX_AGE // 3600}h, allowlist re-checked on every request)"
    )


def boot_warnings() -> list[str]:
    return list(BOOT_WARNINGS)


# -- HTTP transport ---------------------------------------------------------
# One function, so the whole flow is exercisable without a network: every test
# in tests/test_oidc.py substitutes a fake and drives the real code paths.


class Response:
    __slots__ = ("status", "headers", "body")

    def __init__(self, status: int, headers: dict, body: bytes):
        self.status = status
        self.headers = headers
        self.body = body

    def json(self) -> dict:
        try:
            payload = json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise OidcError(f"response was not JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise OidcError("response JSON was not an object")
        return payload


class _NoRedirect(HTTPRedirectHandler):
    """A 3xx off the IdP is a misconfiguration, not something to follow."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise OidcError(f"refusing to follow a {code} redirect to {newurl}")


class UrllibTransport:
    def fetch(
        self, url: str, *, method: str = "GET", data: bytes | None = None,
        headers: dict | None = None, timeout: float | None = None
    ) -> Response:
        # `timeout` is the app's one outbound seam's one tunable, added for
        # `kairos.turnstile` (#31): a second caller with a different latency
        # budget than an IdP token exchange, and the alternative would have been a
        # second transport — or a runtime `httpx` import, since httpx is a *dev*
        # dependency here, not a shipped one. Defaults to this module's
        # `HTTP_TIMEOUT`, so every existing call site is unaffected.
        request = UrlRequest(url, data=data, method=method, headers=headers or {})
        opener = build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=HTTP_TIMEOUT if timeout is None else timeout) as raw:
                return self._wrap(raw)
        except HTTPError as exc:
            # A 400 from a token endpoint is information the operator needs, and
            # a 404 on the discovery document is the most common setup mistake.
            # Read the body instead of discarding it.
            with exc:
                return self._wrap(exc)
        except (URLError, OSError, ValueError) as exc:
            raise OidcError(f"{method} {url} failed: {exc}") from exc

    @staticmethod
    def _wrap(raw) -> Response:
        body = raw.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise OidcError(f"response from {raw.url} exceeded {MAX_RESPONSE_BYTES} bytes")
        headers = {k.lower(): v for k, v in raw.headers.items()}
        return Response(raw.status, headers, body)


# A module attribute on purpose: `monkeypatch.setattr` reaches it, and so does an
# operator who needs a proxy for the discovery call.
http = UrllibTransport()


def reset_caches() -> None:
    """Drop the discovery document and the JWKS. Tests, and nothing else."""
    with _cache_lock:
        _metadata_cache.clear()
        _jwks_cache.clear()


# -- Metadata + keys (cached) ----------------------------------------------

_cache_lock = threading.Lock()
_metadata_cache: dict[str, tuple[float, dict]] = {}
_jwks_cache: dict[str, tuple[float, list]] = {}


def _cached(cache: dict, key: str):
    with _cache_lock:
        hit = cache.get(key)
    return hit[1] if hit and (time.monotonic() - hit[0]) < METADATA_TTL else None


def _store(cache: dict, key: str, value) -> None:
    with _cache_lock:
        cache[key] = (time.monotonic(), value)


def _get_json(url: str, what: str) -> dict:
    response = http.fetch(url, headers={"Accept": "application/json"})
    if response.status != 200:
        raise OidcError(f"{what} at {url} returned HTTP {response.status}")
    return response.json()


def _fetch_metadata(issuer: str) -> dict:
    document = _get_json(f"{issuer}/.well-known/openid-configuration", "discovery document")
    # OIDC Discovery §4.3: the `issuer` inside the document MUST equal the
    # issuer identifier used to fetch it. Enforced, because a document that
    # disagrees is either a typo that silently points the login flow at another
    # provider or a redirect off this trust root.
    if str(document.get("issuer", "")).rstrip("/") != issuer.rstrip("/"):
        raise OidcError(
            f"discovery document issuer {document.get('issuer')!r} does not match "
            f"KAIROS_OIDC_ISSUER ({issuer!r})"
        )
    for required in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        _check_url(str(document.get(required, "")), f"discovery {required}", OidcError)
    return document


def metadata() -> dict:
    """The provider's discovery document, fetched once and cached."""
    document = _cached(_metadata_cache, ISSUER)
    if document is None:
        document = _fetch_metadata(ISSUER)
        _store(_metadata_cache, ISSUER, document)
    return document


def _jwks(jwks_uri: str) -> list:
    keys = _cached(_jwks_cache, jwks_uri)
    if keys is None:
        document = _get_json(jwks_uri, "JWKS")
        keys = document.get("keys")
        if not isinstance(keys, list) or not keys:
            raise OidcError(f"JWKS at {jwks_uri} contained no keys")
        _store(_jwks_cache, jwks_uri, keys)
    return keys


def _select_key(keys: list, header: dict, alg: str) -> dict:
    candidates = [k for k in keys if isinstance(k, dict) and k.get("kty") == "RSA"]
    kid = header.get("kid")
    if kid is not None:
        candidates = [k for k in candidates if k.get("kid") == kid]
    # RFC 7517: `use` is optional, but when present it must permit signing, and
    # an `alg` on the key must agree with the header's. An encryption key is
    # never a verification key.
    usable = [k for k in candidates if k.get("use") in (None, "sig") and k.get("alg") in (None, alg)]
    if not usable:
        raise OidcError(f"no usable RSA signing key in the JWKS for kid={kid!r} alg={alg}")
    if len(usable) > 1:
        raise OidcError(
            f"{len(usable)} JWKS keys match kid={kid!r} alg={alg}; refusing to guess which one "
            "signed the token"
        )
    return usable[0]


def _public_key(key: dict) -> tuple[int, int, int]:
    try:
        modulus = int.from_bytes(_b64url_decode(key["n"]), "big")
        exponent = int.from_bytes(_b64url_decode(key["e"]), "big")
    except (KeyError, ValueError) as exc:
        raise OidcError(f"JWKS key is not a usable RSA key: {exc}") from exc
    if modulus < 2 or exponent < 3 or exponent % 2 == 0:
        raise OidcError("JWKS RSA key has an implausible modulus or exponent")
    return modulus, exponent, (modulus.bit_length() + 7) // 8


def signing_key(header: dict, alg: str, jwks_uri: str) -> tuple[int, int, int]:
    """The RSA public key (n, e, modulus length) an id_token was signed with.

    Only ever taken from the provider's JWKS. A key carried in the token's own
    header (`jwk`/`x5c`) is the classic JWT forgery and is never consulted, so
    an attacker who can mint a token still has to sign it with the IdP's key.

    An unknown `kid` triggers exactly one JWKS re-fetch, so key rotation does
    not need a restart — and only once, so a provider whose kid never matches
    does not turn every login into two fetches.
    """
    keys = _jwks(jwks_uri)
    try:
        key = _select_key(keys, header, alg)
    except OidcError:
        if header.get("kid") is None:
            raise
        _jwks_cache.pop(jwks_uri, None)
        key = _select_key(_jwks(jwks_uri), header, alg)
    return _public_key(key)


# -- JOSE (JWS verification), stdlib only ----------------------------------

# DigestInfo prefixes from RFC 8017 §9.2 note 1 — the DER encoding of
# `SEQUENCE { AlgorithmIdentifier(sha256WithRSAEncryption), OCTET STRING }`.
# Written out rather than assembled, because a byte wrong here is exactly the
# kind of bug a round-trip test cannot see: it makes every real token fail,
# which is loud, rather than every forged token pass, which would not be.
_DIGEST_INFO = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def _b64url_decode(segment: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (ValueError, binascii.Error) as exc:
        raise OidcError(f"malformed base64url segment: {exc}") from exc


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def pkcs1_v15_encode(message: bytes, hash_name: str, k: int) -> bytes:
    """`EMSA-PKCS1-v1_5` of `message`, as the bytes a signature must decode to.

    `0x00 || 0x01 || PS || 0x00 || DigestInfo || H`, with PS = 0xFF… and at
    least eight octets (RFC 8017 §9.2). Plain PKCS#1 v1.5 padding is a fixed
    string format, so writing it out *is* the algorithm; the only arithmetic
    after this is the public-key operation.
    """
    tail = _DIGEST_INFO[hash_name] + hashlib.new(hash_name, message).digest()
    if k < len(tail) + 11:
        raise OidcError(f"an RSA modulus of {k} bytes is too small for {hash_name}")
    return b"\x00\x01" + b"\xff" * (k - len(tail) - 3) + b"\x00" + tail


def _rsa_verify(n: int, e: int, k: int, signature: bytes, message: bytes, hash_name: str) -> bool:
    if len(signature) != k or hash_name not in _DIGEST_INFO:
        return False
    value = int.from_bytes(signature, "big")
    if value >= n:
        return False
    # The public-key operation, then a comparison against the encoding we would
    # have produced ourselves. No padding oracle and no early return: either the
    # whole block matches or the signature is refused.
    return hmac.compare_digest(pow(value, e, n).to_bytes(k, "big"), pkcs1_v15_encode(message, hash_name, k))


def _hs_verify(secret: str, signature: bytes, message: bytes, hash_name: str) -> bool:
    if not secret:
        # An empty client secret must never be a usable HMAC key: it would make
        # every HS256 token forgeable by anyone who can guess the client id.
        return False
    return hmac.compare_digest(hmac.new(secret.encode("utf-8"), message, hash_name).digest(), signature)


# Symmetric signing is keyed by the client secret, which a provider only honours
# when this client is registered confidential. RSA is keyed from the JWKS and is
# what essentially every provider uses by default.
#
# KNOWN: this is an allowlist, not a pin, so an RS256 deployment would also
# accept an HS256/384/512 token keyed on its own client secret. That needs the
# secret, so it is not remote, but a *leaked* secret would then be enough to
# forge an owner identity without the private key. A KAIROS_OIDC_ALLOWED_ALGS
# knob closes it; deliberately not built here, because it adds configuration to
# every deployment to defend against a compromise that already yields the
# client secret.
_ALGORITHMS = {
    "RS256": ("rsa", "sha256"),
    "RS384": ("rsa", "sha384"),
    "RS512": ("rsa", "sha512"),
    "HS256": ("hs", "sha256"),
    "HS384": ("hs", "sha384"),
    "HS512": ("hs", "sha512"),
}


def _audiences(claim) -> list[str]:
    if isinstance(claim, str):
        return [claim]
    if isinstance(claim, list) and all(isinstance(a, str) for a in claim):
        return claim
    raise OidcError("id_token aud is neither a string nor a list of strings")


def _numeric(claim, name: str) -> float:
    """`claim` as a finite number, or an error.

    Three things are rejected here rather than downstream, because each of them
    turns a *check* into a no-op instead of a refusal:

      * a non-numeric value (`"soon"`, `{}`, `[]`) — `exp` was already refused on
        this, and `nbf`/`iat` have to be too, or a malformed not-before quietly
        skips the not-before check;
      * a **bool**, which is an `int` in Python and so would read as 0 or 1;
      * **`NaN` / `Infinity`**, which `json.loads` accepts by default and RFC 7519
        does not. Every comparison against them is false, so `"exp": NaN` is a
        token that never expires — and `exp` is what bounds replay.
    """
    if isinstance(claim, bool) or not isinstance(claim, (int, float)):
        raise OidcError(f"id_token {name} is not a number: {claim!r}")
    value = float(claim)
    if not math.isfinite(value):
        raise OidcError(f"id_token {name} is not a finite number: {claim!r}")
    return value


def _check_claims(payload: dict, *, nonce: str, moment: float) -> None:
    """Every claim check except the signature. Raises OidcError on the first failure.

    `iss` and `aud` pin the token to *this* deployment; `exp`/`nbf`/`iat` pin it
    to *now*; `nonce` and `sub` pin it to *this login of this browser*. All five
    are load-bearing — dropping `azp` in particular re-opens cross-client replay.

    `exp` is mandatory. `nbf` and `iat` are optional, so the rule for them is
    "absent, or a finite number that is not in the future" — never "absent, or
    whatever it happens to be", which is how a malformed claim turns into a check
    that never fires.
    """
    if str(payload.get("iss", "")).rstrip("/") != ISSUER.rstrip("/"):
        raise OidcError(f"id_token iss {payload.get('iss')!r} is not this deployment's issuer")

    audiences = _audiences(payload.get("aud"))
    if CLIENT_ID not in audiences:
        raise OidcError("id_token aud does not contain this client")
    if len(audiences) > 1 and payload.get("azp") != CLIENT_ID:
        # OIDC Core §3.1.3.7: a token with several audiences must name which
        # client it was issued to, or another client in that list could replay
        # it here.
        raise OidcError("id_token has several audiences and no azp naming this client")

    if _numeric(payload.get("exp"), "exp") < moment - CLOCK_SKEW:
        raise OidcError("id_token has expired")
    for claim in ("nbf", "iat"):
        if payload.get(claim) is None:
            continue
        if _numeric(payload[claim], claim) > moment + CLOCK_SKEW:
            raise OidcError(f"id_token {claim} is in the future")

    if not payload.get("nonce") or not hmac.compare_digest(str(payload["nonce"]), nonce):
        raise OidcError("id_token nonce does not match the login this browser started")
    if not isinstance(payload.get("sub"), str) or not payload["sub"]:
        raise OidcError("id_token has no sub")


def verify_id_token(id_token: str, *, nonce: str, now: float | None = None) -> dict:
    """Verify an id_token end to end and return its claims.

    Every one of these must pass: the JWS shape; the algorithm is one Kairos
    implements (`none` and anything unrecognised is refused — an `alg` the
    verifier does not know is an `alg` it must not guess, which is also what
    closes the RSA-public-key-as-HMAC-secret confusion attack); the signature
    against the provider's key or the client secret; then `_check_claims`.

    `now` is injectable so expiry is testable without sleeping.
    """
    if not isinstance(id_token, str) or id_token.count(".") != 2:
        raise OidcError("id_token is not a JWS compact serialization")
    header_b64, payload_b64, signature_b64 = id_token.split(".")
    try:
        header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise OidcError(f"id_token is not base64url-encoded JSON: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise OidcError("id_token header and payload must both be JSON objects")
    if header.get("crit"):
        # A `crit` header names extensions the verifier must understand. Kairos
        # understands none, so any of them is a token whose meaning it cannot
        # vouch for.
        raise OidcError(f"id_token requires unsupported critical headers {header['crit']!r}")

    alg = header.get("alg")
    if alg not in _ALGORITHMS:
        raise OidcError(f"id_token alg {alg!r} is not one Kairos verifies ({', '.join(_ALGORITHMS)})")
    family, hash_name = _ALGORITHMS[alg]
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = _b64url_decode(signature_b64)

    if family == "rsa":
        modulus, exponent, k = signing_key(header, alg, metadata()["jwks_uri"])
        if not _rsa_verify(modulus, exponent, k, signature, signing_input, hash_name):
            raise OidcError("id_token signature does not verify against the provider's key")
    elif not _hs_verify(CLIENT_SECRET, signature, signing_input, hash_name):
        raise OidcError("id_token signature does not verify against the client secret")

    _check_claims(payload, nonce=nonce, moment=time.time() if now is None else now)
    return payload


# -- Authorization request --------------------------------------------------


def _pkce_pair() -> tuple[str, str]:
    verifier = b64url_encode(os.urandom(48))
    challenge = b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def resolve_redirect_uri(request: Request) -> str:
    """The redirect URI to send; it must equal the one registered on the IdP.

    Preference order is deliberate: an explicit setting, then the public origin
    (the SSoT `auth.get_base_url` already uses for share links), and only then
    the request's own headers — caller-supplied unless a proxy sets them, which
    is why that last case warns at boot.

    KNOWN, and left as is: that last fallback does not go through `_check_url`,
    so a hostile `X-Forwarded-Host` yields a `redirect_uri` pointing somewhere
    else (including a `javascript://` one). The blast radius is one
    self-inflicted failed login — the provider rejects the unregistered URI, so
    nothing is exchanged and no cookie is issued — and it is exactly the
    pre-existing behaviour of `auth.get_base_url` for share links. Validating it
    here would mean trusting `Host` less than the rest of the app trusts it,
    which is a larger change than this issue should make silently; the fix is
    `KAIROS_PUBLIC_URL`, and the boot warning says so.
    """
    if REDIRECT_URI:
        return REDIRECT_URI
    base = settings.PUBLIC_URL.rstrip("/") if settings.PUBLIC_URL else get_base_url(request)
    return f"{base}{CALLBACK_PATH}"


def authorization_url(*, redirect_uri: str, state: str, nonce: str, code_challenge: str) -> str:
    endpoint = metadata()["authorization_endpoint"]
    query = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": SCOPES,
        "state": state,
        "nonce": nonce,
        # S256 only, never `plain`: the verifier is a secret the browser holds,
        # and the authorization request is a URL that ends up in history.
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{endpoint}?{urlencode(query)}"


def exchange_code(*, code: str, verifier: str, redirect_uri: str) -> dict:
    """Swap an authorization code for tokens. POST form-encoded, RFC 6749 §4.1.3."""
    endpoint = metadata()["token_endpoint"]
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
    }
    headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    if CLIENT_AUTH == "basic" and CLIENT_SECRET:
        credentials = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
        headers["Authorization"] = f"Basic {credentials}"
    else:
        form["client_id"] = CLIENT_ID
        if CLIENT_SECRET:
            form["client_secret"] = CLIENT_SECRET

    response = http.fetch(endpoint, method="POST", data=urlencode(form).encode(), headers=headers)
    payload = response.json()
    if response.status != 200:
        # `error_description` names the real cause (redirect_uri_mismatch,
        # invalid_client, invalid_grant) and belongs in the operator's log.
        raise OidcError(
            f"token endpoint returned HTTP {response.status}: "
            f"{payload.get('error')} {payload.get('error_description') or ''}".rstrip()
        )
    if not payload.get("id_token"):
        raise OidcError(
            "token response carried no id_token — this provider answered with a plain OAuth2 "
            "response (GitHub's user endpoints, for one). Kairos authenticates from a verified "
            "id_token only; see docs/design/oidc-login.md."
        )
    return payload


# -- The owner allowlist ----------------------------------------------------


def subject_allowed(claims: dict) -> bool:
    """Is this a *known* subject at *this* deployment, or one some IdP vouched for?

    Two ways in, both opt-in, both deny by default:

      * `KAIROS_OIDC_ALLOWED_SUBJECTS` — exact `sub` values. Opaque,
        case-sensitive, stable for the life of the account, and the same shape
        on every provider. This is the directory-row equivalent and the stronger
        form: use it.
      * `KAIROS_OIDC_ALLOWED_EMAIL_DOMAINS` — a whole domain, which is coarser:
        it trusts that anyone who can authenticate at the IdP with an address at
        that domain is one of your users. Convenient, and the reason
        `email_verified` is honoured — and required by default.

    The issuer is checked here rather than left to the caller. The allowlist
    belongs to one deployment, which has one issuer, so "is this a known subject"
    and "is this a subject of our IdP" are the same question — and answering it in
    one place means a future call site cannot get it wrong by forgetting.

    Mirrors `duplet_common.auth.get_user`, where an asserted header still has to
    resolve to a known user row carrying an explicit grant for this app.
    """
    if str(claims.get("iss", "")).rstrip("/") != ISSUER.rstrip("/"):
        return False
    subject = claims.get("sub") or ""
    if isinstance(subject, str) and subject in ALLOWED_SUBJECTS:
        return True
    if not ALLOWED_EMAIL_DOMAINS:
        return False
    address = str(claims.get("email") or "").strip().lower()
    if "@" not in address:
        return False
    if not TRUST_UNVERIFIED_EMAIL and not email_verified(claims):
        return False
    # Whole-domain equality, never endswith: `endswith("example.org")` would also
    # admit `notexample.org` and `evil-example.org`.
    return address.rsplit("@", 1)[1] in ALLOWED_EMAIL_DOMAINS


def email_verified(claims: dict) -> bool:
    """The `email_verified` claim, accepting the two spellings seen in the wild."""
    value = claims.get("email_verified")
    # OIDC Core says boolean. Some providers send the string "true", which is
    # not the same type but is not a weaker claim either, so both are accepted.
    # Anything else — absent, false, "yes", 1 — is not verified.
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def deny_reason(claims: dict) -> str:
    """Which knob to look at, for the log line and the refusal."""
    if ALLOWED_SUBJECTS or ALLOWED_EMAIL_DOMAINS:
        return (
            f"subject {claims.get('sub')!r} is not on this deployment's owner allowlist "
            "(KAIROS_OIDC_ALLOWED_SUBJECTS / KAIROS_OIDC_ALLOWED_EMAIL_DOMAINS)"
        )
    return "this deployment has no owner allowlist configured"


# -- Session + transaction cookies -----------------------------------------
# The same machinery as auth.py's response-ref cookie and csrf.py: a signed,
# time-limited itsdangerous token. No session store, no session table, and so
# no server-side session id that a login could be fixated onto.


def _serialize(salt: str, payload: dict) -> str:
    return _serializer(salt=salt).dumps(payload)


def _deserialize(salt: str, token: str | None, max_age: int) -> dict | None:
    if not token:
        return None
    try:
        data = _serializer(salt=salt).loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired, ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _is_https(request: Request) -> bool:
    # KAIROS_PUBLIC_URL is the trustworthy answer when there is a proxy. Failing
    # that, both the ASGI scheme (uvicorn's, with proxy_headers=False, is the
    # real one) and X-Forwarded-Proto are consulted; the last is
    # caller-supplied in a deployment with no proxy, where the worst it can do
    # is mark a cookie Secure that did not need to be.
    if settings.PUBLIC_URL:
        return settings.PUBLIC_URL.startswith("https://")
    forwarded = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return request.url.scheme == "https" or forwarded == "https"


def _cookie_kwargs(request: Request) -> dict:
    return {
        # Path-scoped to this app, so a second Kairos on the same host (or the
        # ETH deployment's sibling apps) cannot read the cookie.
        "path": P or "/",
        "httponly": True,
        # lax, not strict: the callback is a cross-site top-level GET back from
        # the IdP, and `strict` would withhold both cookies exactly there.
        "samesite": "lax",
        "secure": _is_https(request),
    }


def claims_to_user(claims: dict) -> dict:
    """OIDC claims into the owner dict every Kairos page already expects."""
    email = str(claims.get("email") or "").strip()
    return {
        "uid": claims["sub"],
        "name": claims.get("name") or claims.get("preferred_username") or email or claims["sub"],
        "email": email,
        "source": "oidc",
    }


def session_user(request: Request) -> dict | None:
    """The owner identity carried by a valid session cookie, or None.

    The allowlist is re-checked here, on every request, not only at login. That
    is the directory check `duplet_common.auth` performs: deleting a user row
    invalidates that user's sessions at once, and here removing a subject from
    `KAIROS_OIDC_ALLOWED_SUBJECTS` does the same without waiting for a cookie to
    expire. The issuer is pinned into the cookie too, so a session minted
    against a previous IdP stops being accepted once the deployment changes
    provider.
    """
    claims = _deserialize("oidc-session", request.cookies.get(SESSION_COOKIE), SESSION_MAX_AGE)
    if not claims or claims.get("iss") != ISSUER or not subject_allowed(claims):
        return None
    try:
        return claims_to_user(claims)
    except KeyError:
        return None


def set_session(response, request: Request, claims: dict) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        _serialize("oidc-session", {**claims, "iss": ISSUER}),
        max_age=SESSION_MAX_AGE,
        **_cookie_kwargs(request),
    )


def clear_session(response) -> None:
    response.delete_cookie(SESSION_COOKIE, path=P or "/")


def _transaction(request: Request) -> dict | None:
    return _deserialize("oidc-txn", request.cookies.get(TRANSACTION_COOKIE), TRANSACTION_MAX_AGE)


def _set_transaction(response, request: Request, data: dict) -> None:
    response.set_cookie(
        TRANSACTION_COOKIE,
        _serialize("oidc-txn", data),
        max_age=TRANSACTION_MAX_AGE,
        **_cookie_kwargs(request),
    )


def _clear_transaction(response) -> None:
    response.delete_cookie(TRANSACTION_COOKIE, path=P or "/")


# -- Redirect validation ----------------------------------------------------


def safe_next(candidate) -> str:
    r"""`candidate` if it is a local path inside this app, else the dashboard.

    A login flow takes a return address from the query string and later hands it
    to a `Location` header, which is the textbook open redirect — and the one
    place this repo would otherwise have had it already, because
    `web._login_or_401` interpolates a request path into `KAIROS_LOGIN_URL`. So
    the check lives where the redirect is *issued*, and it is total:

      * absolute (`https:`, `//host`, `/\host`) — refused, which is why a
        backslash is refused anywhere in the value: browsers fold `\` to `/`, so
        `/\evil.example` navigates off-origin;
      * not under this deployment's prefix — refused, so a `next` cannot reach
        another app mounted on the same host;
      * control characters — refused, so a value cannot split a response header.
    """
    home = f"{P}/"
    if not isinstance(candidate, str) or not candidate.startswith("/"):
        return home
    if candidate.startswith("//") or "\\" in candidate:
        return home
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in candidate):
        return home
    parsed = urlparse(candidate)
    if parsed.scheme or parsed.netloc:
        return home
    return candidate if candidate.startswith(home) else home


# -- HTTP surface -----------------------------------------------------------
# Registered unconditionally and 404s itself when KAIROS_AUTH is not `oidc`, so
# the route table is identical in every mode. tests/test_ratelimit.py's route
# audit reads that table, and a route that existed in only one mode would make
# it assert against a shape that depends on the environment.


def enabled() -> bool:
    return settings.AUTH_MODE == "oidc"


def _require_enabled() -> None:
    if not enabled():
        raise HTTPException(404)


def _page(heading: str, detail: str, status_code: int, title: str | None = None):
    """A refusal page: human-readable, no provider internals, never a traceback."""
    return render(
        env,
        "message.html",
        status_code=status_code,
        title=title or heading,
        noindex=True,
        heading=heading,
        error=True,
        user=None,
        detail=detail,
    )


router = APIRouter(prefix=P) if P else APIRouter()


@router.get("/login", include_in_schema=False)
def login_page(request: Request):
    _require_enabled()
    destination = safe_next(request.query_params.get("next"))
    if session_user(request):
        return RedirectResponse(destination, status_code=302)
    return render(
        env,
        "login.html",
        noindex=True,
        user=None,
        provider=provider_label(),
        destination=destination,
        start_url=f"{P}/oidc/start?{urlencode({'next': destination})}",
    )


@router.get("/oidc/start", include_in_schema=False, dependencies=[Depends(rate_limit("login"))])
def oidc_start(request: Request):
    """Begin the flow: bind state, nonce and the PKCE verifier to this browser."""
    _require_enabled()
    destination = safe_next(request.query_params.get("next"))
    verifier, challenge = _pkce_pair()
    state = b64url_encode(os.urandom(24))
    nonce = b64url_encode(os.urandom(24))
    try:
        target = authorization_url(
            redirect_uri=resolve_redirect_uri(request),
            state=state,
            nonce=nonce,
            code_challenge=challenge,
        )
    except OidcError as exc:
        # A discovery failure is an operator problem (wrong issuer, no route to
        # the IdP), not a visitor's mistake, so it says so without echoing the
        # provider's response.
        log.error("OIDC discovery failed: %s", exc)
        response = _page(
            "Cannot reach the identity provider",
            "Kairos could not read this deployment's OIDC discovery document. The operator "
            "needs to check KAIROS_OIDC_ISSUER and this host's access to it.",
            502,
        )
        _clear_transaction(response)
        return response
    response = RedirectResponse(target, status_code=302)
    _set_transaction(
        response,
        request,
        {
            "state": state,
            "nonce": nonce,
            "verifier": verifier,
            "next": destination,
        },
    )
    return response


@router.get("/oidc/callback", include_in_schema=False, dependencies=[Depends(rate_limit("login"))])
def oidc_callback(request: Request):
    """Complete the flow, then decide whether this subject may own polls."""
    _require_enabled()
    transaction = _transaction(request)
    # The transaction cookie is what makes this endpoint safe to *call*. Without
    # it there is no state to compare against, so nobody who can make a browser
    # follow a URL can borrow someone else's login — including replaying their
    # own code into a victim's session.
    if not transaction or not all(transaction.get(k) for k in ("state", "nonce", "verifier")):
        return _expired()
    if not hmac.compare_digest(request.query_params.get("state", ""), str(transaction["state"])):
        return _state_mismatch()
    if request.query_params.get("error"):
        return _idp_error(request.query_params.get("error", ""))
    code = request.query_params.get("code", "")
    if not code:
        return _expired()

    try:
        tokens = exchange_code(
            code=code, verifier=str(transaction["verifier"]), redirect_uri=resolve_redirect_uri(request)
        )
        claims = verify_id_token(tokens["id_token"], nonce=str(transaction["nonce"]))
    except OidcError as exc:
        log.error("OIDC exchange or verification failed: %s", exc)
        return _spent(
            _page(
                "Sign-in failed",
                "The identity provider's response could not be verified, so no session was "
                "created. The details are in the server log.",
                400,
            )
        )
    if not subject_allowed(claims):
        # Logged with the subject and never with the address: this check is what
        # makes the deployment safe, so an operator chasing "I cannot sign in"
        # needs to see which subject to allow.
        log.warning("rejected OIDC sign-in: %s", deny_reason(claims))
        return _spent(
            _page(
                "Not authorised",
                "Your account is not on this deployment's owner allowlist. Ask the operator to "
                "add your identity provider subject.",
                403,
            )
        )

    response = RedirectResponse(safe_next(transaction.get("next")), status_code=302)
    set_session(response, request, claims)
    _clear_transaction(response)
    return response


@router.post("/oidc/logout", include_in_schema=False)
def oidc_logout(request: Request, form=Depends(form_data)):
    """Drop the Kairos session.

    Local only: the IdP's own session survives, so the next sign-in is one
    click rather than a fresh login. Single logout (and revoking the refresh
    token) is `end_session_endpoint`, which is provider-specific and out of scope
    here. POST + CSRF rather than a GET, so a third-party page cannot sign
    somebody out.
    """
    _require_enabled()
    user = session_user(request)
    if not user:
        return RedirectResponse(f"{P}/login", status_code=302)
    require_csrf(user, form)
    response = RedirectResponse(f"{P}/login", status_code=302)
    clear_session(response)
    _clear_transaction(response)
    return response


def _spent(response):
    """End the transaction on a page that is not a success.

    Every terminal outcome of the callback retires the transaction cookie, so this
    is the *only* way to finish an attempt — two of these paths used to return
    their page directly and left the cookie standing. Not exploitable (the
    `state` inside it is unguessable and HttpOnly, and a real IdP consumes the
    code on the first exchange), but it contradicted the "single use" claim the
    operator guide makes, and a security claim in a document someone relies on
    should be true rather than nearly true.
    """
    _clear_transaction(response)
    return response


def _expired():
    response = _page(
        "Sign-in expired",
        "This sign-in took longer than the ten minutes it is valid for, or the browser dropped "
        "the cookie. Start again.",
        400,
    )
    return _spent(response)


def _state_mismatch():
    """`state` did not come back as this browser left it. Refuse, and say why.

    A mismatch is a stale tab, a back button, or someone trying to graft an
    authorization response onto a session that did not start it.
    """
    log.warning("OIDC callback state mismatch (the CSRF check failed)")
    response = _page(
        "Sign-in could not be verified",
        "The sign-in response did not match the request this browser started. Start again from "
        "the sign-in page.",
        400,
    )
    return _spent(response)


def _idp_error(code: str):
    """The IdP answered with `error=…` instead of a code (declined, cancelled)."""
    log.info("the identity provider returned error=%s", code)
    response = _page(
        "Sign-in cancelled",
        "The identity provider did not return an authorization code"
        + (f" ({code})." if code else "."),
        400,
    )
    return _spent(response)
