"""First-party OIDC owner login (#53), tested without an IdP.

Everything security-critical in `kairos.oidc` is exercised here with **no network
call at all**: `oidc.http` is a module attribute, so a fake provider serves
discovery, the JWKS and the token endpoint in-process while the real
authorization-URL builder, code exchange, id_token verifier, allowlist, cookie
handling and HTTP routes all run unchanged.

The RSA keypairs below are throwaway 2048-bit pairs generated once, offline,
purely so these tests have something to sign with. They guard nothing.

What these tests prove, and what they cannot:

  * **Proven offline** — state/nonce/PKCE binding, callback CSRF, one-time use
    of the transaction, id_token signature and claim verification (including
    `alg` confusion, `alg: none`, a `jwk` carried in the token header, `azp`,
    expiry and clock skew), the subject allowlist and its default deny, `next`
    open-redirect rejection, session tampering, revocation taking effect on a
    live session, and the whole flow including 404-in-every-other-mode.
  * **Not proven here** — only a real provider can show these: that a given
    vendor's discovery document and JWKS parse the way we assume, that its
    redirect-URI matching is as strict as its documentation claims, and what its
    logout actually does. See "What is NOT tested" in
    docs/design/oidc-login.md.
"""

import base64
import hashlib
import hmac
import json
import time
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient
from itsdangerous import URLSafeTimedSerializer
from starlette.requests import Request

from kairos import auth, main, oidc, settings
from kairos.csrf import make_csrf

P = settings.PREFIX
ISSUER = "https://id.example.org/realms/main"
CLIENT_ID = "kairos"
CLIENT_SECRET = "s3cret-from-the-idp-console"
KID = "signing-key-1"
CALLBACK = f"{P}/oidc/callback"


# Throwaway RSA keypairs, generated offline. The first is "the provider's"; the
# second exists so a test can sign something the provider did not. Encoded the
# way a JWKS encodes them, because that is how they arrive in real life.
def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


_PROVIDER_N = int.from_bytes(
    _unb64(
        "pIuezJ_3bUdsvW4u0mtuM5V1InZCoahLlfMAyCI9vk26se5qd-zIEl0G3cYmie3O"
        "LLCGskNssgD-trrjsi2C6w4y9tyfVFlZj3C2aWJXgL117uvvxSk5-3raPuYKOmwD"
        "BipyvBYkbbgScGYqVeKkWkRl-dipMLubPn5lLwIAXJlDv7XWzl1Z7DI6qZSaEsZB"
        "Mu1UuoPSRQbZEnLbtnXLHLcWEzvFWvXvPu2_41VnqTxt4ZXWBP7pfCmwaw6ryCS8"
        "DG-L9FsAwG-laIDGtk7quJBD9cJxsebs7P70PXcDSKJN4D5QhnKghdq832OyQK09"
        "0MIIaGeKdScj2X61xOaNlw"
    ),
    "big",
)
_PROVIDER_D = int.from_bytes(
    _unb64(
        "Zyz9KAXuWeF9d9KNHXgro8DFsBRDd6ZVrvKuvM9rs9Z9iHCc5hHc6lbWpV1IcRhi"
        "PXd7HnBUydEB5oaNm_4Zp1ZB8rUoWvWjyOO-HZqCj8E9H9FliVVufBfunZ4VL8jm"
        "pIkdZH7l3L6dIUmOpkf1EnztDJski-A3WhpbS_yPSX_3rUEQDvah2XgtztndVn_q"
        "c3d5HgidVi4iwuUli9gQQ7JyNrXQxueb9PvGFcAmtXdmc1evs2G1_u4ayZgpAvdl"
        "N_qKnmp7kLaNiNy3pwwbk19620QJCBGddhF8AIA3mW_2eY8gaC2Ylct-tEBg9ajl"
        "uJDWIl8Q64Y5cfdSt7WSkQ"
    ),
    "big",
)
_ATTACKER_N = int.from_bytes(
    _unb64(
        "npjsWqSWxam0gM0jjpzCtWI6GSjLvWxJnQrY5OZNbNYj_oa-kBvvz-VwLry6p4qD"
        "HTT0JyqHz-Yz8CRP-P5vADeIHjwDVNsRpLuG5TInwbnryijqJdgrqcMMqTpzIbki"
        "IeJDU1ZCkawh4B206NeL4he0Fc97ZaEp-qaFpVtoxo4X8kphBu7HlDUlhJSjRq9h"
        "gbBD_-ANADAU_qSFZxAHHor1xngkPAlPcheL7uM6dQRphxTHqyf5HFtt3EH70IMb"
        "2fi8uMo6zPeEjfu4bwiO3kQLn656JuKuX6qs2WZkyZRZO2N6Mlh_GWatl-XzBVop"
        "HdUveVWRCYcFoWJuwkO75Q"
    ),
    "big",
)
_ATTACKER_D = int.from_bytes(
    _unb64(
        "OUc3jWEGButMgnwUDGx3MbUBEJcYRhg22d3SCZFXgygvpbwaVMeSK75MbsTAkMPI"
        "qKK4TvDgTehw95jVvTJ--lAT-_9moJ3h2GHVzS75BtFT5BY0wmg5FL2Z9ABlFlfb"
        "iOtDr3Rm5F-LeHqiHLnEDmrLIlll0oWLOLgtalQCGjsjM6TOJS0f8MXtFN8746Ei"
        "qgIXWMYPhCZd2edllEWRMBRBZJxeehsX7U9WBB1AwZDMs7wGOJ9J6pFthJKbVuMV"
        "01TE0Cy6yTFiD1Ha_70GUCHri_vb-amb1W__cadmMdVdSGFabwIgmmd_Oi3u1Zbz"
        "5No0wz-WiSU1vOqYlyuLvQ"
    ),
    "big",
)
_K = (_PROVIDER_N.bit_length() + 7) // 8


def _int_b64(value: int) -> str:
    return oidc.b64url_encode(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def _jwk(kid=KID, n=_PROVIDER_N, **extra):
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _int_b64(n),
        "e": _int_b64(65537),
        **extra,
    }


def _sign(message: bytes, n: int, d: int) -> bytes:
    """RSASSA-PKCS1-v1_5 signing, using the provider's own encoder under test."""
    size = (n.bit_length() + 7) // 8
    encoded = oidc.pkcs1_v15_encode(message, "sha256", size)
    return pow(int.from_bytes(encoded, "big"), d, n).to_bytes(size, "big")


# -- a fake identity provider ------------------------------------------------


class FakeIdp:
    """Discovery + JWKS + token endpoint, in-process.

    Records every request, which is how PKCE and client authentication are
    checked without a network: the assertion is on *what was sent*.
    """

    def __init__(self):
        self.calls: list[dict] = []
        self.issuer = ISSUER
        self.keys = [_jwk()]
        self.token_status = 200
        self.token_error: dict = {}
        self.discovery_status = 200
        self.discovery_override: dict = {}
        self.kid = KID
        self.n = _PROVIDER_N
        self.d = _PROVIDER_D
        self.symmetric = False
        self.signing_secret = ""
        # What nonce the token endpoint puts in the id_token. Left None, it mints
        # an empty one — so a flow that never threads the real nonce through
        # fails, which is the nonce check showing up in the route tests.
        self.token_nonce: str | None = None
        self.token_form: dict = {}

    @property
    def discovery(self) -> dict:
        document = {
            "issuer": self.issuer,
            "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
            "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
            "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
        }
        document.update(self.discovery_override)
        return document

    # the HTTP surface

    def fetch(self, url, *, method="GET", data=None, headers=None):
        self.calls.append({"url": url, "method": method, "data": data, "headers": headers or {}})
        if url.endswith("/.well-known/openid-configuration"):
            return self._json(self.discovery_status, self.discovery)
        if url == self.discovery["jwks_uri"]:
            return self._json(200, {"keys": self.keys})
        if url == self.discovery["token_endpoint"]:
            return self._token(data or b"")
        raise AssertionError(f"unexpected HTTP request: {method} {url}")

    def token_request(self) -> dict:
        """The one POST this provider received — the token exchange."""
        posts = [c for c in self.calls if c["method"] == "POST"]
        assert len(posts) == 1, f"expected exactly one token request, saw {len(posts)}"
        return posts[0]

    @staticmethod
    def _json(status, payload):
        return oidc.Response(status, {}, json.dumps(payload).encode())

    def _token(self, body):
        self.token_form = {k: v[0] for k, v in parse_qs(body.decode()).items()}
        if self.token_status != 200:
            return self._json(self.token_status, self.token_error)
        return self._json(
            200,
            {
                "access_token": "an-access-token",
                "token_type": "Bearer",
                "id_token": self.id_token(nonce=self.token_nonce or ""),
            },
        )

    # token minting

    def id_token(self, *, nonce="nonce-under-test", header=None, **overrides) -> str:
        header = dict(header or {})
        if not self.symmetric:
            header.setdefault("kid", self.kid)
        claims = {
            "iss": self.issuer,
            "sub": "sub-alice",
            "aud": CLIENT_ID,
            "exp": int(time.time()) + 300,
            "iat": int(time.time()),
            "nonce": nonce,
            "email": "alice@example.org",
            "email_verified": True,
            "name": "Alice Example",
        }
        claims.update(overrides)
        head = oidc.b64url_encode(
            json.dumps({"alg": "HS256" if self.symmetric else "RS256", **header}).encode()
        )
        body = oidc.b64url_encode(json.dumps(claims).encode())
        signing_input = f"{head}.{body}".encode()
        if self.symmetric:
            signature = hmac.new(self.signing_secret.encode(), signing_input, "sha256").digest()
        else:
            signature = _sign(signing_input, self.n, self.d)
        return f"{head}.{body}.{oidc.b64url_encode(signature)}"

    # wiring

    def install(self, monkeypatch, **config):
        monkeypatch.setattr(settings, "AUTH_MODE", config.pop("AUTH_MODE", "oidc"))
        monkeypatch.setattr(oidc, "ISSUER", ISSUER)
        monkeypatch.setattr(oidc, "CLIENT_ID", CLIENT_ID)
        for name, value in config.items():
            monkeypatch.setattr(oidc, name, value)
        monkeypatch.setattr(oidc, "http", self)
        oidc.reset_caches()


@pytest.fixture
def idp(monkeypatch):
    """A provider with no allowlist — for tests that do not need one."""
    provider = FakeIdp()
    provider.install(monkeypatch)
    yield provider
    oidc.reset_caches()


@pytest.fixture
def client():
    return TestClient(main.app, base_url="https://testserver")


def _start(client, next_=None) -> tuple[str, str]:
    """Drive `/oidc/start`, returning (state, nonce) from the IdP redirect."""
    params = {"next": next_} if next_ else {}
    response = client.get(f"{P}/oidc/start", params=params, follow_redirects=False)
    assert response.status_code == 302, response.text
    query = parse_qs(urlparse(response.headers["location"]).query)
    return query["state"][0], query["nonce"][0]


def _transaction_of(client) -> dict:
    cookie = client.cookies.get(oidc.TRANSACTION_COOKIE)
    return oidc._deserialize("oidc-txn", cookie, oidc.TRANSACTION_MAX_AGE)


def _sign_in(client, monkeypatch, provider, **start_kwargs):
    """Start the flow and complete it with the nonce actually in play."""
    state, nonce = _start(client, **start_kwargs)
    provider.token_nonce = nonce
    return client.get(
        f"{P}/oidc/callback", params={"code": "auth-code-1", "state": state}, follow_redirects=False
    )


def _request(path=f"{P}/", *, scheme="https", headers=None, cookies=None) -> Request:
    """A minimal Request carrying cookies, for the helpers called outside a route."""
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    if cookies:
        raw.append((b"cookie", b"; ".join(f"{k}={v}".encode() for k, v in cookies.items())))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": scheme,
            "path": path,
            "root_path": "",
            "headers": raw,
            "query_string": b"",
            "client": ("203.0.113.7", 40000),
            # `server` is what lets request.url resolve, and request.url.scheme is
            # how the cookie's Secure flag is decided.
            "server": ("testserver", 443 if scheme == "https" else 80),
        }
    )


# =========================================================================
# 1. Signature verification — stdlib RSA, cross-checked against the RFC
# =========================================================================


def test_the_pkcs1_v15_prefixes_are_what_the_der_encoding_of_a_digestinfo_produces():
    """Cross-check the magic hex; do not trust it.

    The three DigestInfo prefixes are transcribed from RFC 8017 §9.2 note 1. A
    transcription error there makes every real token fail — loud — but it is
    still an error nobody should have to find in production, so this builds the
    same DER independently and demands the constants match.
    """
    oids = {
        "sha256": "0609608648016503040201",  # 2.16.840.1.101.3.4.2.1
        "sha384": "0609608648016503040202",
        "sha512": "0609608648016503040203",
    }
    for hash_name, oid in oids.items():
        algorithm_id = b"\x30" + bytes([len(oid) // 2 + 2]) + bytes.fromhex(oid) + b"\x05\x00"
        digest = hashlib.new(hash_name, b"message").digest()
        octet_string = b"\x04" + bytes([len(digest)]) + digest
        body = algorithm_id + octet_string
        built = b"\x30" + bytes([len(body)]) + body
        assert built == oidc._DIGEST_INFO[hash_name] + digest, hash_name


def test_the_pkcs1_v15_encoding_is_the_documented_byte_string():
    encoded = oidc.pkcs1_v15_encode(b"signing-input", "sha256", 256)
    assert encoded.startswith(b"\x00\x01")
    # partition, not rpartition: the DigestInfo contains 0x00 bytes, and the
    # separator is the FIRST one — the padding is all 0xff by construction.
    padding, separator, tail = encoded[2:].partition(b"\x00")
    assert separator and padding == b"\xff" * len(padding) and len(padding) >= 8
    assert tail == oidc._DIGEST_INFO["sha256"] + hashlib.sha256(b"signing-input").digest()
    assert len(encoded) == 256


def test_a_modulus_too_small_for_the_digest_is_an_error_not_a_short_block():
    with pytest.raises(oidc.OidcError, match="too small"):
        oidc.pkcs1_v15_encode(b"m", "sha512", 64)


def test_a_real_signature_verifies_and_every_mutation_of_it_does_not():
    message = b"header.payload"
    signature = _sign(message, _PROVIDER_N, _PROVIDER_D)
    verify = oidc._rsa_verify
    assert verify(_PROVIDER_N, 65537, _K, signature, message, "sha256")

    flipped = bytearray(signature)
    flipped[100] ^= 0x01
    other_key = bytearray(signature)
    other_key[-1] ^= 0xFF
    assert not verify(_PROVIDER_N, 65537, _K, bytes(flipped), message, "sha256")
    assert not verify(_PROVIDER_N, 65537, _K, bytes(other_key), message, "sha256")
    assert not verify(_PROVIDER_N, 65537, _K, signature, message + b"!", "sha256")
    assert not verify(_ATTACKER_N, 65537, _K, signature, message, "sha256")
    assert not verify(_PROVIDER_N + 2, 65537, _K, signature, message, "sha256")
    assert not verify(_PROVIDER_N, 65537, _K, signature[:-1], message, "sha256")
    # Numerically >= n is not a valid signature, and is rejected before modexp.
    assert not verify(_PROVIDER_N, 65537, _K, b"\xff" * _K, message, "sha256")


def test_hmac_verification_refuses_an_empty_client_secret():
    """`HMAC(key="", …)` is computable by anyone who knows the client id is blank."""
    assert not oidc._hs_verify("", b"\x00" * 32, b"m", "sha256")
    digest = hmac.new(b"k", b"m", "sha256").digest()
    assert oidc._hs_verify("k", digest, b"m", "sha256")
    assert not oidc._hs_verify("j", digest, b"m", "sha256")


# =========================================================================
# 2. id_token verification
# =========================================================================


def _verify(token, nonce="n", now=None):
    return oidc.verify_id_token(token, nonce=nonce, now=now)


def test_a_well_formed_id_token_verifies_and_yields_its_claims(idp):
    claims = _verify(idp.id_token(nonce="n"))
    assert claims["sub"] == "sub-alice"
    assert claims["email"] == "alice@example.org"


@pytest.mark.parametrize("alg", ["none", "None", "NONE", "ES256", "PS256", "RS257", "", "rs256"])
def test_an_alg_kairos_does_not_verify_is_refused_rather_than_guessed(idp, alg):
    """`alg: none` is the canonical JWT forgery; the rest are the same class.

    Refusing an unrecognised `alg` is also what closes algorithm confusion: a
    token asking to be checked as HS256 against the RSA *public* key — public
    material — never reaches the HMAC path at all.
    """
    head = oidc.b64url_encode(json.dumps({"alg": alg, "kid": KID}).encode())
    body = oidc.b64url_encode(
        json.dumps(
            {
                "iss": ISSUER,
                "sub": "sub-alice",
                "aud": CLIENT_ID,
                "exp": int(time.time()) + 60,
                "nonce": "n",
            }
        ).encode()
    )
    with pytest.raises(oidc.OidcError, match="alg"):
        _verify(f"{head}.{body}.", nonce="n")


def test_algorithm_confusion_hs256_keyed_with_the_public_modulus_is_refused(monkeypatch, idp):
    """The RSA public key is public. If it could double as an HMAC secret, anyone
    could mint a token the IdP never signed."""
    monkeypatch.setattr(oidc, "CLIENT_SECRET", CLIENT_SECRET)
    head = oidc.b64url_encode(json.dumps({"alg": "HS256"}).encode())
    body = oidc.b64url_encode(
        json.dumps(
            {
                "iss": ISSUER,
                "sub": "sub-alice",
                "aud": CLIENT_ID,
                "exp": int(time.time()) + 60,
                "nonce": "n",
            }
        ).encode()
    )
    signing_input = f"{head}.{body}".encode()
    signature = hmac.new(_int_b64(_PROVIDER_N).encode(), signing_input, "sha256").digest()
    with pytest.raises(oidc.OidcError, match="client secret"):
        _verify(f"{head}.{body}.{oidc.b64url_encode(signature)}", nonce="n")


def test_a_key_carried_in_the_token_header_is_never_consulted(monkeypatch, idp):
    """A `jwk` in the header is the classic self-signed JWT: the attacker signs
    with their own key and publishes it in the token. If the verifier read it,
    this token would verify. It must not."""
    monkeypatch.setattr(oidc, "CLIENT_SECRET", CLIENT_SECRET)
    head = oidc.b64url_encode(
        json.dumps(
            {
                "alg": "RS256",
                "kid": KID,
                "jwk": _jwk(kid="attacker", n=_ATTACKER_N),
            }
        ).encode()
    )
    body = oidc.b64url_encode(
        json.dumps(
            {
                "iss": ISSUER,
                "sub": "sub-alice",
                "aud": CLIENT_ID,
                "exp": int(time.time()) + 60,
                "nonce": "n",
            }
        ).encode()
    )
    signature = _sign(f"{head}.{body}".encode(), _ATTACKER_N, _ATTACKER_D)
    with pytest.raises(oidc.OidcError, match="signature"):
        _verify(f"{head}.{body}.{oidc.b64url_encode(signature)}", nonce="n")


def test_an_id_token_signed_with_a_key_the_provider_did_not_use_is_refused(idp):
    """Correct kid, correct claims, wrong signature — the one a payload-editing
    attacker actually produces."""
    idp.n, idp.d = _ATTACKER_N, _ATTACKER_D
    with pytest.raises(oidc.OidcError, match="signature"):
        _verify(idp.id_token(nonce="n"), nonce="n")


@pytest.mark.parametrize(
    "overrides,match",
    [
        ({"iss": "https://evil.example"}, "iss"),
        ({"aud": "another-client"}, "aud"),
        ({"exp": int(time.time()) - 3600}, "expired"),
        ({"nbf": int(time.time()) + 3600}, "nbf is in the future"),
        ({"iat": int(time.time()) + 3600}, "iat is in the future"),
        ({"nonce": "a-different-login"}, "nonce"),
        ({"sub": None}, "no sub"),
        ({"exp": "soon"}, "exp is not a number"),
        ({"aud": {"nope": 1}}, "aud is neither"),
        # A malformed *optional* claim must refuse, not be skipped. If it were
        # skipped, `"nbf": "soon"` would mean "no not-before check at all" —
        # fail-open on malformed input, in a security control.
        ({"nbf": "soon"}, "nbf is not a number"),
        ({"iat": {}}, "iat is not a number"),
        ({"nbf": []}, "nbf is not a number"),
        ({"iat": True}, "iat is not a number"),
    ],
)
def test_every_claim_check_is_load_bearing(idp, overrides, match):
    with pytest.raises(oidc.OidcError, match=match):
        _verify(idp.id_token(**{"nonce": "n", **overrides}), nonce="n")


def test_a_token_for_several_audiences_must_name_this_client_in_azp(idp):
    """OIDC Core §3.1.3.7. Without `azp`, another client in that list could
    replay its token here — its audience is this client too."""
    with pytest.raises(oidc.OidcError, match="azp"):
        _verify(idp.id_token(nonce="n", aud=[CLIENT_ID, "someone-elses-app"]), nonce="n")
    claims = _verify(idp.id_token(nonce="n", aud=[CLIENT_ID, "someone-elses-app"], azp=CLIENT_ID), nonce="n")
    assert claims["sub"] == "sub-alice"


@pytest.mark.parametrize("claim", ["exp", "nbf", "iat"])
@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_a_non_finite_timestamp_is_refused_rather_than_defeating_the_comparison(
    idp, claim, value
):
    """`json.loads` accepts NaN and Infinity; RFC 7519 does not.

    Every comparison against a NaN is false, so `{"exp": NaN}` would be a token
    that never expires — and `exp` is the claim that bounds replay. Same for
    `nbf`/`iat`, where NaN would turn the not-before check into no check.
    """
    with pytest.raises(oidc.OidcError, match=f"{claim} is not a finite number"):
        _verify(idp.id_token(nonce="n", **{claim: value}), nonce="n")


def test_clock_skew_is_bounded_rather_than_infinite(idp):
    """Skew is for clock drift, not for stale tokens."""
    assert (
        _verify(idp.id_token(nonce="n", exp=int(time.time()) - oidc.CLOCK_SKEW + 5), nonce="n")["sub"]
        == "sub-alice"
    )
    with pytest.raises(oidc.OidcError, match="expired"):
        _verify(idp.id_token(nonce="n", exp=int(time.time()) - oidc.CLOCK_SKEW - 30), nonce="n")


def test_a_crit_header_is_refused_because_none_of_them_are_understood(idp):
    token = idp.id_token(nonce="n", header={"crit": ["http://example.com/ext"], "x": 1})
    with pytest.raises(oidc.OidcError, match="critical"):
        _verify(token, nonce="n")


def test_an_hs256_token_is_accepted_only_under_the_client_secret(monkeypatch):
    provider = FakeIdp()
    provider.install(monkeypatch, CLIENT_SECRET="right-secret")
    provider.symmetric, provider.signing_secret = True, "right-secret"
    assert _verify(provider.id_token(nonce="n"), nonce="n")["sub"] == "sub-alice"

    provider.signing_secret = "wrong-secret"
    with pytest.raises(oidc.OidcError, match="client secret"):
        _verify(provider.id_token(nonce="n"), nonce="n")

    # With no secret configured at all, an HS token can never verify.
    monkeypatch.setattr(oidc, "CLIENT_SECRET", "")
    with pytest.raises(oidc.OidcError, match="client secret"):
        _verify(provider.id_token(nonce="n"), nonce="n")


@pytest.mark.parametrize("token", ["", "a.b", "a.b.c.d", None, 12345])
def test_something_that_is_not_a_jws_is_refused_before_parsing_it(idp, token):
    with pytest.raises(oidc.OidcError):
        _verify(token, nonce="n")


# -- JWKS selection and rotation


def test_an_unknown_kid_triggers_one_refetch_and_then_verifies(idp):
    """Key rotation must not need a restart — and must not become a fetch storm."""
    _verify(idp.id_token(nonce="n"), nonce="n")
    before = len(idp.calls)

    idp.keys = [*idp.keys, _jwk(kid="signing-key-2")]
    idp.kid = "signing-key-2"
    assert _verify(idp.id_token(nonce="n"), nonce="n")["sub"] == "sub-alice"
    fetches = len([c for c in idp.calls[before:] if c["url"].endswith("/certs")])
    assert fetches == 1, "the stale cache is free; the refresh is the only extra fetch"

    # A kid that never matches: one refresh, then the error — not a loop.
    before = len(idp.calls)
    with pytest.raises(oidc.OidcError, match="no usable RSA signing key"):
        _verify(idp.id_token(nonce="n", header={"kid": "still-not-there"}), nonce="n")
    assert len([c for c in idp.calls[before:] if c["url"].endswith("/certs")]) == 1


def test_an_ambiguous_or_encryption_key_is_refused_rather_than_guessed(idp):
    idp.keys = [*idp.keys, _jwk()]
    with pytest.raises(oidc.OidcError, match="refusing to guess"):
        _verify(idp.id_token(nonce="n"), nonce="n")

    oidc.reset_caches()
    idp.keys = [_jwk(use="enc")]
    with pytest.raises(oidc.OidcError, match="no usable RSA signing key"):
        _verify(idp.id_token(nonce="n"), nonce="n")


def test_a_jwks_with_no_keys_is_an_error_not_an_empty_verdict(idp):
    idp.keys = []
    with pytest.raises(oidc.OidcError, match="no keys"):
        _verify(idp.id_token(nonce="n"), nonce="n")


# -- discovery


def test_a_discovery_document_that_disagrees_about_the_issuer_is_refused(idp):
    """OIDC Discovery §4.3. A mismatch is either a typo pointing the login flow
    at another provider or a redirect off this trust root."""
    idp.issuer = "https://somewhere-else.example"
    with pytest.raises(oidc.OidcError, match="does not match"):
        oidc.metadata()


@pytest.mark.parametrize("missing", ["authorization_endpoint", "token_endpoint", "jwks_uri"])
def test_a_discovery_document_missing_an_endpoint_is_refused(idp, missing):
    idp.discovery_override = {missing: ""}
    with pytest.raises(oidc.OidcError):
        oidc.metadata()


def test_a_discovery_endpoint_off_https_is_refused(idp):
    idp.discovery_override = {"token_endpoint": "http://id.example.org/token"}
    with pytest.raises(oidc.OidcError, match="TLS"):
        oidc.metadata()


def test_the_discovery_document_is_fetched_once_then_cached(idp):
    oidc.metadata()
    oidc.metadata()
    assert len([c for c in idp.calls if c["url"].endswith("openid-configuration")]) == 1


# =========================================================================
# 3. Configuration: validate at boot, stay inert when OIDC is off
# =========================================================================


def test_an_oidc_deployment_with_no_allowlist_refuses_to_boot(monkeypatch):
    """Not a typo check — a policy refusal. An empty allowlist admits every
    account at the IdP, which is the exact shape this design exists to refuse."""
    monkeypatch.setattr(settings, "AUTH_MODE", "oidc")
    monkeypatch.setattr(oidc, "ISSUER", ISSUER)
    monkeypatch.setattr(oidc, "CLIENT_ID", CLIENT_ID)
    monkeypatch.setattr(oidc, "ALLOWED_SUBJECTS", frozenset())
    monkeypatch.setattr(oidc, "ALLOWED_EMAIL_DOMAINS", frozenset())
    with pytest.raises(RuntimeError, match="anyone the IdP vouched for"):
        oidc._validate_config()


@pytest.mark.parametrize(
    "field,value,match",
    [
        ("ISSUER", "", "KAIROS_OIDC_ISSUER"),
        ("ISSUER", "http://id.example.org", "TLS"),
        ("ISSUER", "id.example.org", "absolute https"),
        ("ISSUER", f"{ISSUER}?x=1", "no query or fragment"),
        ("CLIENT_ID", "", "KAIROS_OIDC_CLIENT_ID"),
        ("CLIENT_AUTH", "bearer", "client authentication method"),
        ("REDIRECT_URI", "http://polls.example.org/cb", "TLS"),
    ],
)
def test_a_mistyped_knob_is_a_startup_error_not_a_skipped_line(monkeypatch, field, value, match):
    """The #47 lesson: a security control the operator believes is in force and is
    not is worse than no control at all, so refuse the boot."""
    valid = {
        "ISSUER": ISSUER,
        "CLIENT_ID": CLIENT_ID,
        "CLIENT_AUTH": "post",
        "REDIRECT_URI": "",
        "ALLOWED_SUBJECTS": frozenset({"sub-alice"}),
        "ALLOWED_EMAIL_DOMAINS": frozenset(),
    }
    monkeypatch.setattr(settings, "AUTH_MODE", "oidc")
    for name, current in valid.items():
        monkeypatch.setattr(oidc, name, value if name == field else current)
    with pytest.raises(RuntimeError, match=match):
        oidc._validate_config()


def test_an_unconfigured_deployment_is_not_touched_by_any_of_this(monkeypatch):
    """ADR-0001/0002, asserted: with KAIROS_AUTH != oidc the validation is a
    no-op, so a stray KAIROS_OIDC_* cannot break self-host or ETH."""
    monkeypatch.setattr(settings, "AUTH_MODE", "header")
    for field in ("ISSUER", "CLIENT_ID", "CLIENT_SECRET", "REDIRECT_URI"):
        monkeypatch.setattr(oidc, field, "")
    monkeypatch.setattr(oidc, "CLIENT_AUTH", "nonsense")
    oidc._validate_config()
    assert oidc.identity_report().startswith("owner auth: header")


def _reimport_oidc():
    """Execute `oidc.py` again under a *different* module name.

    Deliberately not a reload: nothing is removed from `sys.modules`, so this
    cannot leak into another test module (which is how deleting `kairos.*`
    entries broke seven unrelated tests once). The point is to exercise the
    module-level code — the part that reads `os.environ` — which a test that
    only patches already-parsed attributes cannot reach.
    """
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location("kairos_oidc_import_probe", Path(oidc.__file__))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _with_env(monkeypatch, **values):
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_a_broken_oidc_variable_cannot_take_down_a_deployment_that_is_not_using_oidc(
    monkeypatch,
):
    """The regression this whole section exists for.

    A `KAIROS_OIDC_*` value that would refuse an OIDC boot must be inert when the
    mode is off. It is easy to get wrong: parsing the allowlists *before* the
    mode gate means one value pasted into the wrong shell — or exported for some
    other app on the box — refuses the boot of a header-mode self-hoster that
    never asked for OIDC. That is the ADR-0001/0002 regression, and patching the
    parsed values hides it, which is why this re-imports the module.
    """
    _with_env(
        monkeypatch,
        KAIROS_AUTH="header",
        KAIROS_OIDC_ISSUER="not a url",
        KAIROS_OIDC_ALLOWED_SUBJECTS="alice bob",
        KAIROS_OIDC_ALLOWED_EMAIL_DOMAINS="example .org",
        KAIROS_OIDC_CLIENT_ID="",
    )
    monkeypatch.setattr(settings, "AUTH_MODE", "header")
    module = _reimport_oidc()
    assert module.ALLOWED_SUBJECTS == frozenset()
    assert module.ALLOWED_EMAIL_DOMAINS == frozenset()
    assert module.identity_report().startswith("owner auth: header")


def test_the_same_broken_value_still_refuses_an_oidc_boot(monkeypatch):
    """The other half: the gate must not become a way to skip the check."""
    _with_env(
        monkeypatch,
        KAIROS_AUTH="oidc",
        KAIROS_OIDC_ISSUER=ISSUER,
        KAIROS_OIDC_CLIENT_ID=CLIENT_ID,
        KAIROS_OIDC_ALLOWED_SUBJECTS="alice bob",
    )
    monkeypatch.setattr(settings, "AUTH_MODE", "oidc")
    with pytest.raises(RuntimeError, match="opaque token"):
        _reimport_oidc()


def test_a_subject_entry_with_whitespace_is_refused_at_parse_time():
    for bad in ("alice bob", "alice\nbob", "alice\tbob"):
        with pytest.raises(RuntimeError, match="opaque token"):
            oidc._parse_subjects(bad)


@pytest.mark.parametrize(
    "bad",
    [
        "example .org",
        "http://example.org",
        "example.org/team",
        "*.example.org",
        "not_a_domain",
        "-example.org",
        "example..org",
        "exam ple.org",
    ],
)
def test_an_email_domain_entry_that_is_not_a_bare_domain_is_refused(bad):
    with pytest.raises(RuntimeError, match="bare domain"):
        oidc._parse_domains(bad)


def test_domain_entries_tolerate_the_two_spellings_people_paste():
    assert oidc._parse_domains("@Example.ORG, example.com.") == frozenset({"example.org", "example.com"})


def test_the_boot_line_names_the_boundary_and_never_a_secret(monkeypatch):
    monkeypatch.setattr(oidc, "ISSUER", ISSUER)
    monkeypatch.setattr(oidc, "CLIENT_ID", CLIENT_ID)
    monkeypatch.setattr(oidc, "CLIENT_SECRET", CLIENT_SECRET)
    monkeypatch.setattr(oidc, "REDIRECT_URI", f"https://polls.example.org{CALLBACK}")
    monkeypatch.setattr(oidc, "ALLOWED_SUBJECTS", frozenset({"a"}))
    monkeypatch.setattr(oidc, "ALLOWED_EMAIL_DOMAINS", frozenset({"example.org"}))
    monkeypatch.setattr(oidc, "TRUST_UNVERIFIED_EMAIL", False)
    monkeypatch.setattr(settings, "AUTH_MODE", "oidc")
    report = oidc.identity_report()
    assert "1 subject(s)" in report
    assert "1 email domain(s), email_verified required" in report
    assert CLIENT_SECRET not in report


def test_the_boot_line_says_when_the_edge_allowlist_is_not_the_identity_boundary(monkeypatch):
    """S1's CIDR list still gates the edge, but in oidc mode the allowlist is what
    decides who may own polls. Saying which is which prevents a wrong conclusion."""
    monkeypatch.setattr(settings, "AUTH_MODE", "oidc")
    monkeypatch.setattr(oidc, "ISSUER", ISSUER)
    monkeypatch.setattr(oidc, "CLIENT_ID", CLIENT_ID)
    monkeypatch.setattr(oidc, "ALLOWED_SUBJECTS", frozenset({"a"}))
    import ipaddress

    monkeypatch.setattr(settings, "TRUSTED_PROXY_NETWORKS", (ipaddress.ip_network("10.0.0.0/8"),))
    assert "not the identity boundary" in oidc.identity_report()


def test_boot_warnings_name_the_three_configurations_that_look_fine_and_are_not(monkeypatch):
    monkeypatch.setattr(oidc, "BOOT_WARNINGS", [])
    monkeypatch.setattr(settings, "AUTH_MODE", "oidc")
    monkeypatch.setattr(oidc, "ISSUER", ISSUER)
    monkeypatch.setattr(oidc, "CLIENT_ID", CLIENT_ID)
    monkeypatch.setattr(oidc, "ALLOWED_SUBJECTS", frozenset({"a"}))
    for field in ("CLIENT_SECRET", "REDIRECT_URI"):
        monkeypatch.setattr(oidc, field, "")
    monkeypatch.setattr(settings, "PUBLIC_URL", "")
    monkeypatch.setattr(settings, "ALLOW", {"alice"})
    oidc._validate_config()
    warnings = " ".join(oidc.boot_warnings())
    assert "public client" in warnings  # no client secret
    assert "derived from request headers" in warnings  # no redirect URI source
    assert "KAIROS_OIDC_ALLOWED_SUBJECTS" in warnings  # KAIROS_ALLOW is inert here


# =========================================================================
# 4. The owner allowlist — allowlist by known subject, never by the IdP's word
# =========================================================================


def _allowlist(monkeypatch, **config):
    """Pin the issuer alongside the allowlist: they are one deployment's pair."""
    defaults = {
        "ISSUER": ISSUER,
        "ALLOWED_SUBJECTS": frozenset({"sub-alice"}),
        "ALLOWED_EMAIL_DOMAINS": frozenset(),
    }
    for name, value in {**defaults, **config}.items():
        monkeypatch.setattr(oidc, name, value)


def test_an_exact_subject_is_allowed_and_nothing_else_is(monkeypatch):
    _allowlist(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    assert oidc.subject_allowed({"iss": ISSUER, "sub": "sub-alice"})
    for denied in (
        {"iss": ISSUER, "sub": "sub-mallory"},
        {"iss": ISSUER, "sub": "SUB-ALICE"},  # `sub` is opaque and case-sensitive
        {"iss": ISSUER, "sub": "sub-alice "},  # no normalisation games
        {"iss": "https://elsewhere.example", "sub": "sub-alice"},
        {"sub": "sub-alice"},  # no issuer at all
        {},
    ):
        assert not oidc.subject_allowed(denied), denied


def test_with_no_allowlist_configured_nobody_is_admitted(monkeypatch):
    _allowlist(monkeypatch, ALLOWED_SUBJECTS=frozenset())
    claims = {"iss": ISSUER, "sub": "sub-alice", "email": "alice@example.org", "email_verified": True}
    assert not oidc.subject_allowed(claims)
    assert "no owner allowlist" in oidc.deny_reason(claims)


def test_an_email_domain_matches_whole_domains_only(monkeypatch):
    _allowlist(monkeypatch, ALLOWED_SUBJECTS=frozenset(), ALLOWED_EMAIL_DOMAINS=frozenset({"example.org"}))
    verified = {"iss": ISSUER, "sub": "s", "email_verified": True}
    assert oidc.subject_allowed({**verified, "email": "alice@example.org"})
    assert oidc.subject_allowed({**verified, "email": "ALICE@EXAMPLE.ORG"})
    for denied in (
        "alice@sub.example.org",
        "alice@notexample.org",
        "alice@example.org.evil.example",
        "alice@example.or",
        "alice",
        "alice@",
    ):
        assert not oidc.subject_allowed({**verified, "email": denied}), denied


def test_a_domain_allowlist_entry_needs_a_verified_address_by_default(monkeypatch):
    """Otherwise domain allowlisting is a claim about a string: any account at the
    IdP can assert any address at that domain."""
    _allowlist(monkeypatch, ALLOWED_SUBJECTS=frozenset(), ALLOWED_EMAIL_DOMAINS=frozenset({"example.org"}))
    unverified = {"iss": ISSUER, "sub": "s", "email": "attacker@example.org"}
    assert not oidc.subject_allowed(unverified)
    assert not oidc.subject_allowed({**unverified, "email_verified": False})
    assert not oidc.subject_allowed({**unverified, "email_verified": "yes"})
    assert not oidc.subject_allowed({**unverified, "email_verified": 1})
    assert oidc.subject_allowed({**unverified, "email_verified": "true"})
    assert oidc.subject_allowed({**unverified, "email_verified": True})


def test_the_unverified_email_escape_hatch_is_named_for_what_it_weakens(monkeypatch):
    _allowlist(
        monkeypatch,
        ALLOWED_SUBJECTS=frozenset(),
        ALLOWED_EMAIL_DOMAINS=frozenset({"example.org"}),
        TRUST_UNVERIFIED_EMAIL=True,
    )
    assert oidc.subject_allowed({"iss": ISSUER, "sub": "s", "email": "anyone@example.org"})
    assert not oidc.subject_allowed({"iss": ISSUER, "sub": "s", "email": "anyone@elsewhere.example"})


def test_the_two_allowlist_knobs_are_independent(monkeypatch):
    """A subject grant does not need the address on the domain list, and a domain
    entry is deliberately *not* a subject grant — it admits any verified subject at
    that domain, which is the coarser of the two contracts."""
    _allowlist(
        monkeypatch,
        ALLOWED_SUBJECTS=frozenset({"sub-alice"}),
        ALLOWED_EMAIL_DOMAINS=frozenset({"example.org"}),
    )
    assert oidc.subject_allowed(
        {"iss": ISSUER, "sub": "sub-alice", "email": "alice@elsewhere.example", "email_verified": True}
    ), "an explicit subject grant does not care about the domain list"

    _allowlist(monkeypatch, ALLOWED_SUBJECTS=frozenset(), ALLOWED_EMAIL_DOMAINS=frozenset({"example.org"}))
    assert oidc.subject_allowed(
        {
            "iss": ISSUER,
            "sub": "sub-nobody-listed-individually",
            "email": "x@example.org",
            "email_verified": True,
        }
    ), "a domain entry admits every verified subject at that domain"


# =========================================================================
# 5. Redirect validation — `next` is attacker-supplied
# =========================================================================


@pytest.mark.parametrize(
    "hostile",
    [
        "https://evil.example/steal",
        "http://evil.example",
        "//evil.example/steal",
        "/\\evil.example",
        "\\\\evil.example",
        "/%2f%2fevil.example",
        "/scheduler/\\evil.example",
        "javascript:alert(1)",
        "data:text/html,<script>",
        "\r\nSet-Cookie: x=y",
        "//evil.example\n/scheduler/",
        "evil.example",
        "",
        None,
        42,
        ["/scheduler/"],
    ],
)
def test_an_off_site_return_address_falls_back_to_the_dashboard(hostile):
    assert oidc.safe_next(hostile) == f"{P}/"


@pytest.mark.parametrize("local", [f"{P}/", f"{P}/new", f"{P}/polls/abc/edit"])
def test_a_local_return_address_survives(local):
    assert oidc.safe_next(local) == local


def test_a_return_address_outside_this_deployment_prefix_is_refused():
    """With PREFIX=/scheduler, a `next` must not reach another app on the host."""
    assert oidc.safe_next("/other-app/admin") == f"{P}/"
    assert oidc.safe_next(P) == f"{P}/"  # the bare prefix, no trailing slash


# =========================================================================
# 6. The session cookie
# =========================================================================


def _session_token(monkeypatch, **overrides) -> str:
    claims = {
        "sub": "sub-alice",
        "iss": ISSUER,
        "email": "alice@example.org",
        "email_verified": True,
        "name": "Alice Example",
    }
    claims.update(overrides)
    return oidc._serialize("oidc-session", claims)


def _with_session(token, **kwargs) -> Request:
    return _request(cookies={oidc.SESSION_COOKIE: token}, **kwargs)


def test_a_valid_session_cookie_resolves_to_an_owner(monkeypatch):
    _allowlist(monkeypatch)
    user = oidc.session_user(_with_session(_session_token(monkeypatch)))
    assert user["uid"] == "sub-alice"
    assert user["name"] == "Alice Example"
    assert user["email"] == "alice@example.org"
    assert user["source"] == "oidc"


@pytest.mark.parametrize(
    "mutate",
    [
        # A flip in the token's *body*, not in its last base64url character. The
        # signature is 20 bytes = 160 bits, and 27 unpadded base64url characters
        # carry 162, so the final character has two bits no decoder reads (the
        # second review corrected four to two). Replacing it is therefore a
        # byte-level no-op whenever those two bits are the only thing that changed
        # -- 1 of the 16 possible final digests, i.e. 6.25%, about one run in 16 --
        # and the tampered token still verified. A body flip always changes bytes
        # the HMAC covers.
        lambda token: token[:3] + ("A" if token[3] != "A" else "B") + token[4:],
        lambda token: token + "x",
        lambda token: token[:-4],
    ],
)
def test_a_tampered_session_cookie_is_not_an_owner(monkeypatch, mutate):
    _allowlist(monkeypatch)
    good = _session_token(monkeypatch)
    assert oidc.session_user(_with_session(mutate(good))) is None


def test_a_session_cookie_signed_with_another_secret_is_not_an_owner(monkeypatch):
    """SESSION_SECRET is the only thing between a cookie and ownership of every
    poll in the deployment."""
    _allowlist(monkeypatch)
    forged = URLSafeTimedSerializer("a-different-secret", salt="oidc-session").dumps(
        {"sub": "sub-mallory", "iss": ISSUER, "email": "m@example.org", "email_verified": True}
    )
    assert oidc.session_user(_with_session(forged)) is None


def test_garbage_and_absent_cookies_are_simply_not_an_owner(monkeypatch):
    _allowlist(monkeypatch)
    assert oidc.session_user(_with_session("")) is None
    assert oidc.session_user(_with_session("not-a-token")) is None
    assert oidc.session_user(_request()) is None


def test_an_expired_session_cookie_is_refused(monkeypatch):
    _allowlist(monkeypatch)
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() - 2 * oidc.SESSION_MAX_AGE)
    stale = _session_token(monkeypatch)
    monkeypatch.setattr(time, "time", real_time)
    assert oidc.session_user(_with_session(stale)) is None


def test_removing_a_subject_from_the_allowlist_kills_its_live_sessions(monkeypatch):
    """The directory check, in this repo's terms: the allowlist is consulted on
    every request, not only at login, so revocation is immediate rather than
    "whenever that cookie happens to expire"."""
    _allowlist(monkeypatch)
    request = _with_session(_session_token(monkeypatch))
    assert oidc.session_user(request)["uid"] == "sub-alice"
    monkeypatch.setattr(oidc, "ALLOWED_SUBJECTS", frozenset({"sub-someone-else"}))
    assert oidc.session_user(request) is None


def test_a_session_from_a_previous_identity_provider_stops_working(monkeypatch):
    """Changing KAIROS_OIDC_ISSUER must not leave the old provider's subjects
    signed in, so the issuer is pinned into the cookie."""
    _allowlist(monkeypatch)
    stale = _session_token(monkeypatch, iss="https://old-id.example.org")
    assert oidc.session_user(_with_session(stale)) is None


def test_the_session_cookie_is_httponly_lax_scoped_and_secure_behind_tls(monkeypatch):
    _allowlist(monkeypatch)
    monkeypatch.setattr(settings, "PUBLIC_URL", "")
    response = PlainTextResponse("")
    oidc.set_session(response, _request(scheme="https"), {"sub": "sub-alice"})
    header = response.headers["set-cookie"]
    assert "HttpOnly" in header
    assert "SameSite=lax" in header  # `strict` would withhold it on the callback
    assert "Secure" in header
    assert f"Path={P}" in header  # not readable by a sibling app on the host


def test_a_plaintext_deployment_gets_a_cookie_without_the_secure_flag(monkeypatch):
    """Otherwise the shipped quickstart could never complete a login at all."""
    _allowlist(monkeypatch)
    monkeypatch.setattr(settings, "PUBLIC_URL", "")
    response = PlainTextResponse("")
    oidc.set_session(response, _request(scheme="http"), {"sub": "sub-alice"})
    assert "Secure" not in response.headers["set-cookie"]


# =========================================================================
# 7. The HTTP flow, end to end, against the fake provider
# =========================================================================


def test_the_sign_in_page_names_the_provider(client, idp):
    response = client.get(f"{P}/login")
    assert response.status_code == 200
    assert "id.example.org" in response.text
    assert "noindex" in response.text
    assert "Sign in with" in response.text


def test_start_redirects_to_the_idp_with_state_nonce_and_pkce(client, idp):
    response = client.get(f"{P}/oidc/start", follow_redirects=False)
    assert response.status_code == 302
    parsed = urlparse(response.headers["location"])
    assert parsed.netloc == "id.example.org"
    query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    assert query["response_type"] == "code"
    assert query["client_id"] == CLIENT_ID
    assert query["code_challenge_method"] == "S256"
    assert "openid" in query["scope"]
    assert len(query["state"]) >= 16 and len(query["nonce"]) >= 16
    assert client.cookies.get(oidc.TRANSACTION_COOKIE)


def test_each_start_mints_a_fresh_verifier_bound_to_its_own_challenge(client, idp):
    """PKCE, asserted end to end. A `plain` challenge would hand the IdP the
    secret itself, and a challenge not derived from the stored verifier would make
    the exchange fail at the provider rather than here."""
    response = client.get(f"{P}/oidc/start", follow_redirects=False)
    challenge = {k: v[0] for k, v in parse_qs(urlparse(response.headers["location"]).query).items()}[
        "code_challenge"
    ]
    verifier = _transaction_of(client)["verifier"]
    assert challenge == oidc.b64url_encode(hashlib.sha256(verifier.encode()).digest())
    assert challenge != verifier

    other = client.get(f"{P}/oidc/start", follow_redirects=False)
    other_challenge = {k: v[0] for k, v in parse_qs(urlparse(other.headers["location"]).query).items()}[
        "code_challenge"
    ]
    assert other_challenge != challenge, "a replayed verifier would be a fixed secret"


def test_the_token_exchange_carries_the_verifier_and_the_registered_redirect_uri(client, monkeypatch):
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    state, nonce = _start(client)
    verifier = _transaction_of(client)["verifier"]
    provider.token_nonce = nonce
    client.get(f"{P}/oidc/callback", params={"code": "auth-code-1", "state": state}, follow_redirects=False)
    assert provider.token_form["grant_type"] == "authorization_code"
    assert provider.token_form["code"] == "auth-code-1"
    assert provider.token_form["code_verifier"] == verifier
    assert provider.token_form["redirect_uri"].endswith(CALLBACK)


def test_the_post_token_authentication_shape_is_the_documented_one(client, monkeypatch):
    for auth_mode, expected in (("post", "client_secret"), ("basic", None)):
        provider = FakeIdp()
        provider.install(
            monkeypatch,
            CLIENT_AUTH=auth_mode,
            CLIENT_SECRET=CLIENT_SECRET,
            ALLOWED_SUBJECTS=frozenset({"sub-alice"}),
        )
        state, nonce = _start(client)
        provider.token_nonce = nonce
        client.get(f"{P}/oidc/callback", params={"code": "c", "state": state}, follow_redirects=False)
        call = next(c for c in provider.calls if c["method"] == "POST")
        form = {k: v[0] for k, v in parse_qs(call["data"].decode()).items()}
        if expected:
            assert form[expected] == CLIENT_SECRET
            assert "Authorization" not in call["headers"]
        else:
            assert "client_secret" not in form
            assert call["headers"]["Authorization"].startswith("Basic ")


def test_a_public_client_registration_sends_no_secret_at_all(client, monkeypatch):
    provider = FakeIdp()
    provider.install(monkeypatch, CLIENT_SECRET="", ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    state, nonce = _start(client)
    provider.token_nonce = nonce
    client.get(f"{P}/oidc/callback", params={"code": "c", "state": state}, follow_redirects=False)
    form = {k: v[0] for k, v in parse_qs(provider.token_request()["data"].decode()).items()}
    assert form["client_id"] == CLIENT_ID
    assert "client_secret" not in form


def test_a_correct_login_sets_a_session_cookie_and_lands_on_next(client, monkeypatch):
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    response = _sign_in(client, monkeypatch, provider, next_=f"{P}/new")
    assert response.status_code == 302
    assert response.headers["location"] == f"{P}/new"
    assert client.cookies.get(oidc.SESSION_COOKIE)
    assert auth.get_user(_request(cookies=dict(client.cookies)))["uid"] == "sub-alice"


def test_the_transaction_cookie_is_cleared_when_the_login_succeeds(client, monkeypatch):
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    _sign_in(client, monkeypatch, provider)
    assert not client.cookies.get(oidc.TRANSACTION_COOKIE)


def test_the_callback_is_single_use(client, monkeypatch):
    """Once cleared, a replayed authorization response has nothing left to bind
    to — including in the very browser that made it, which is the session-fixation
    shape."""
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    state, nonce = _start(client)
    provider.token_nonce = nonce
    first = client.get(f"{P}/oidc/callback", params={"code": "c", "state": state}, follow_redirects=False)
    assert first.status_code == 302
    replay = client.get(f"{P}/oidc/callback", params={"code": "c", "state": state}, follow_redirects=False)
    assert replay.status_code == 400
    assert not client.cookies.get(oidc.TRANSACTION_COOKIE)


@pytest.mark.parametrize("tamper", ["wrong-state", "no-transaction", "no-state"])
def test_the_callback_refuses_a_response_it_cannot_bind_to_this_browser(client, monkeypatch, tamper):
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    if tamper == "no-transaction":
        client.cookies.clear()
        params = {"code": "c", "state": "anything"}
    elif tamper == "no-state":
        _start(client)
        params = {"code": "c"}
    else:
        _start(client)
        params = {"code": "c", "state": "a-different-browser"}
    provider.token_nonce = "irrelevant"
    response = client.get(f"{P}/oidc/callback", params=params, follow_redirects=False)
    assert response.status_code == 400
    assert not client.cookies.get(oidc.SESSION_COOKIE)


def test_a_valid_login_by_a_subject_that_is_not_allowlisted_is_refused(client, monkeypatch):
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-someone-else"}))
    response = _sign_in(client, monkeypatch, provider)
    assert response.status_code == 403
    assert "allowlist" in response.text
    assert not client.cookies.get(oidc.SESSION_COOKIE)


def test_a_forged_callback_cannot_mint_a_session_for_an_allowlisted_subject(client, monkeypatch):
    """The strongest end-to-end statement of the feature: a well-formed response
    for a subject that *is* on the allowlist, carrying a token the provider did
    not sign, still gets nobody in."""
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    state, nonce = _start(client)
    forged = provider.id_token(nonce=nonce)[:-4] + "AAAA"
    provider._token = lambda body: oidc.Response(
        200,
        {},
        json.dumps(
            {
                "access_token": "at",
                "id_token": forged,
            }
        ).encode(),
    )
    response = client.get(f"{P}/oidc/callback", params={"code": "c", "state": state}, follow_redirects=False)
    assert response.status_code == 400
    assert not client.cookies.get(oidc.SESSION_COOKIE)


def test_a_provider_that_does_not_echo_the_nonce_gets_nobody_in(client, monkeypatch):
    """The nonce check, through the real route rather than through the helper.

    Everything else about this exchange is correct — a real code, the right state,
    a valid signature, an allowlisted subject — and the login still fails.
    """
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    state, _ = _start(client)  # provider.token_nonce deliberately left as None
    response = client.get(f"{P}/oidc/callback", params={"code": "c", "state": state}, follow_redirects=False)
    assert response.status_code == 400
    assert not client.cookies.get(oidc.SESSION_COOKIE)


@pytest.mark.parametrize("outcome", ["exchange-failed", "not-allowlisted", "no-state",
                                     "no-transaction", "idp-error"])
def test_no_terminal_outcome_leaves_the_transaction_cookie_behind(client, monkeypatch, outcome):
    """Single use has to mean single use on the *refused* paths too.

    Two of these used to return their page directly and leave a live transaction
    cookie standing. Not exploitable — `state` inside it is unguessable and
    HttpOnly, and a real IdP consumes the code on the first exchange — but the
    operator guide claims the cookie is retired on every outcome, and a security
    claim in a document someone relies on should be true.
    """
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    state, nonce = _start(client)

    if outcome == "no-transaction":
        state = "no-state-at-all"
    if outcome == "idp-error":
        response = client.get(f"{P}/oidc/callback",
                              params={"state": state, "error": "access_denied"},
                              follow_redirects=False)
    elif outcome == "no-state":
        response = client.get(f"{P}/oidc/callback", params={"code": "c"},
                              follow_redirects=False)
    elif outcome == "exchange-failed":
        provider.token_status = 400
        provider.token_error = {"error": "invalid_client", "error_description": "no"}
        response = client.get(f"{P}/oidc/callback", params={"code": "c", "state": state},
                              follow_redirects=False)
    else:  # not-allowlisted: a correct exchange, for a subject we did not admit
        provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-someone-else"}))
        provider.token_nonce = nonce
        response = client.get(f"{P}/oidc/callback", params={"code": "c", "state": state},
                              follow_redirects=False)

    assert response.status_code >= 400
    assert not client.cookies.get(oidc.TRANSACTION_COOKIE), (
        f"the transaction cookie survived the {outcome} path"
    )


def test_next_cannot_be_used_to_send_anyone_off_site(client, monkeypatch):
    """A hostile return address is sanitised before it is ever stored, and the
    redirect after a successful login is the dashboard — never another origin."""
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    for hostile in ("https://evil.example/steal", "/\\evil.example", "//evil.example"):
        _start(client, next_=hostile)
        assert _transaction_of(client)["next"] == f"{P}/", f"{hostile} was stored verbatim"

    state, nonce = _start(client, next_="/\\evil.example")
    provider.token_nonce = nonce
    response = client.get(f"{P}/oidc/callback", params={"code": "c", "state": state}, follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == f"{P}/"


def test_an_idp_error_is_a_readable_page_not_a_traceback(client, monkeypatch):
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    state, _ = _start(client)
    response = client.get(
        f"{P}/oidc/callback", params={"state": state, "error": "access_denied"}, follow_redirects=False
    )
    assert response.status_code == 400
    assert "access_denied" in response.text
    assert not client.cookies.get(oidc.SESSION_COOKIE)


def test_an_unverifiable_response_says_so_without_echoing_the_provider(client, monkeypatch):
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    state, _ = _start(client)
    provider.token_status = 400
    provider.token_error = {
        "error": "invalid_client",
        "error_description": "client secret is wrong for app 1234",
    }
    response = client.get(f"{P}/oidc/callback", params={"code": "c", "state": state}, follow_redirects=False)
    assert response.status_code == 400
    assert "1234" not in response.text  # provider internals stay in the log
    assert not client.cookies.get(oidc.SESSION_COOKIE)


def test_an_unreachable_provider_is_an_operator_message_not_a_500(client, monkeypatch):
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    monkeypatch.setattr(oidc, "http", _Unreachable())
    oidc.reset_caches()
    response = client.get(f"{P}/oidc/start", follow_redirects=False)
    assert response.status_code == 502
    assert "KAIROS_OIDC_ISSUER" in response.text


class _Unreachable:
    def fetch(self, url, **kwargs):
        raise oidc.OidcError(f"GET {url} failed: no route to host")


def test_a_provider_that_answers_without_an_id_token_is_refused(client, monkeypatch):
    """GitHub's OAuth is not OIDC. Saying so beats an inscrutable 400."""
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    state, _ = _start(client)
    provider._token = lambda body: oidc.Response(200, {}, json.dumps({"access_token": "at"}).encode())
    response = client.get(f"{P}/oidc/callback", params={"code": "c", "state": state}, follow_redirects=False)
    assert response.status_code == 400


def test_logout_needs_the_csrf_token_bound_to_that_session(client, monkeypatch):
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    _sign_in(client, monkeypatch, provider)
    assert client.cookies.get(oidc.SESSION_COOKIE)

    assert client.post(f"{P}/oidc/logout", data={}, follow_redirects=False).status_code == 403
    # A CSRF token for a *different* uid is not a token for this session.
    assert (
        client.post(
            f"{P}/oidc/logout", data={"csrf": make_csrf("someone-else")}, follow_redirects=False
        ).status_code
        == 403
    )

    signed_out = client.post(
        f"{P}/oidc/logout", data={"csrf": make_csrf("sub-alice")}, follow_redirects=False
    )
    assert signed_out.status_code == 302
    assert not client.cookies.get(oidc.SESSION_COOKIE)


def test_logout_without_a_session_just_goes_to_the_sign_in_page(client, monkeypatch):
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    response = client.post(f"{P}/oidc/logout", data={}, follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == f"{P}/login"


def test_an_already_signed_in_visitor_is_sent_straight_to_next(client, monkeypatch):
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    _sign_in(client, monkeypatch, provider)
    response = client.get(f"{P}/login", params={"next": f"{P}/new"}, follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == f"{P}/new"


def test_the_login_endpoints_have_a_budget_when_limits_are_on(client, monkeypatch):
    """They are the only unauthenticated endpoints that make an outbound call per
    request, so `KAIROS_RATE_LIMIT=on` has to actually charge them."""
    from kairos import ratelimit

    ratelimit.limiter.reset()
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "RATE_LIMITS", {**settings.DEFAULT_RATE_LIMITS, "login": (2, 60)})
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    try:
        codes = [client.get(f"{P}/oidc/start", follow_redirects=False).status_code for _ in range(3)]
        assert codes == [302, 302, 429]
    finally:
        ratelimit.limiter.reset()


def test_the_pkce_verifier_never_leaves_this_host_in_a_url(client, monkeypatch):
    """It survives the round trip in a signed cookie and nowhere else: not in the
    authorization URL, and not in the session that replaces the transaction."""
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    response = client.get(f"{P}/oidc/start", follow_redirects=False)
    verifier = _transaction_of(client)["verifier"]
    assert verifier not in response.headers["location"]
    _sign_in(client, monkeypatch, provider)
    assert verifier not in client.cookies.get(oidc.SESSION_COOKIE, "")


# =========================================================================
# 8. Unchanged: the header/self-host path, and the ETH runtime seam
# =========================================================================


def test_header_mode_is_exactly_as_it_was(client):
    """ADR-0001/0002, asserted rather than asserted-to. tests/conftest.py mirrors
    the ETH deployment (prefix /scheduler, header auth), so this is the flagship
    path, not a synthetic one."""
    assert settings.AUTH_MODE == "header"
    assert auth.get_user(_request(headers={"X-User": "alice"}))["uid"] == "alice"
    assert auth.get_user(_request()) is None
    for path in (f"{P}/login", f"{P}/oidc/start", f"{P}/oidc/callback"):
        assert client.get(path, follow_redirects=False).status_code == 404, path
    assert client.post(f"{P}/oidc/logout", data={}).status_code == 404


def test_the_session_cookie_is_not_readable_in_header_mode(client, monkeypatch):
    """A session minted by the oidc path must not authenticate anything when the
    deployment is not running it."""
    provider = FakeIdp()
    provider.install(monkeypatch, ALLOWED_SUBJECTS=frozenset({"sub-alice"}))
    _sign_in(client, monkeypatch, provider)
    token = client.cookies[oidc.SESSION_COOKIE]
    monkeypatch.setattr(settings, "AUTH_MODE", "header")
    assert auth.get_user(_request(cookies={oidc.SESSION_COOKIE: token})) is None


def test_get_user_is_still_replaceable_at_runtime():
    """The ETH/duplet adapter does `kairos.auth.get_user = …`. That must keep
    working: a documented escape hatch, not an implementation detail."""
    original = auth.get_user
    try:
        auth.get_user = lambda request: {"uid": "directory-42", "name": "D", "email": "d@x"}
        assert auth.get_user(_request())["uid"] == "directory-42"
    finally:
        auth.get_user = original
