# Owner login: first-party OIDC

Issue #53. This is the operator's guide to `KAIROS_AUTH=oidc` — Kairos
terminating OpenID Connect itself, with no authenticating proxy in front of it.

For the decision and the layering, see [ADR-0013](../../docs/adr/0013-first-party-oidc-client.md)
and the obligations register (`productization-obligations.md`, **S1**). For the
proxy topology instead, see [self-host-hardening.md](self-host-hardening.md) §1–2.

---

## 0. Which topology do I want?

Both are one compose command. They differ in *where* OIDC terminates.

| | `compose.oidc.yaml` | `compose.proxy.yaml` |
|---|---|---|
| OIDC terminates in | **Kairos** | `oauth2-proxy`, in front |
| Extra container to operate | none | one, with its own cookie secret |
| Identity header mapping | none | three, kept in step |
| IdPs that work | any OIDC provider | any OIDC provider **plus** non-OIDC ones (GitHub) |
| Wiring | ~4 env vars | ~8 env vars + a session store to think about |
| Env vars | `KAIROS_AUTH=oidc`, issuer, client id/secret, allowlist | `KAIROS_AUTH=header`, `KAIROS_ALLOW`, three header names, the proxy's own config |

Reach for `compose.oidc.yaml` by default. Reach for `compose.proxy.yaml` when
you already run Shibboleth, OpenAthens or oauth2-proxy — inside an institution
that has one, keeping OIDC termination in front of Kairos is the right answer,
and it is the only way to reach an IdP that is not OIDC at all.

Everything else in Kairos is identical between them. Respondents never need an
account in either case: share links and invite tokens are the same capability
model (ADR-0001).

---

## 1. The flow, and what each step defends against

```
GET  {prefix}/login          sign-in page (the default KAIROS_LOGIN_URL)
GET  {prefix}/oidc/start     state + nonce + PKCE verifier -> signed 10-minute
                             transaction cookie; 302 to the IdP
GET  {prefix}/oidc/callback  state matches that cookie; code exchanged with the
                             verifier; id_token verified; subject allowlisted;
                             signed 12-hour session cookie set
POST {prefix}/oidc/logout    clears the session cookie (CSRF-protected)
```

| Control | What it stops |
|---|---|
| `state`, in the transaction cookie | login CSRF — someone grafting their authorization response onto your session, or starting a login in your browser and finishing it in theirs |
| `nonce` | an id_token replayed from an earlier login, or one minted for a different client flow |
| PKCE (`S256`, never `plain`) | an intercepted authorization code being spent by whoever intercepted it |
| The transaction cookie itself | the callback being *callable*: without it there is no state to compare, so nothing can be replayed into it |
| Single use of the transaction cookie | replaying a successful callback response in the very browser that made it (the session-fixation shape) |
| Signature verification against the JWKS | a self-signed token. A `jwk` carried in the token's own header is **never** consulted |
| `alg` allowlist | `alg: none`, and algorithm confusion (HS256 keyed with the RSA *public* key, which is public material) |
| `iss`, `aud`, `azp`, `exp`, `nbf`, `iat` | a token from another provider, for another client, replayed across clients, or stale |
| **The subject allowlist** | *anyone the IdP vouches for* — see §2 |
| `next` validation | open redirect: `next=//evil.example` can never become a `Location` header |
| Re-checking the allowlist on **every request** | revocation: removing a subject takes effect immediately, not when its cookie expires |
| `KAIROS_TRUSTED_PROXY_CIDRS` | anything reaching the app port except your TLS terminator |

Everything above is tested offline against an in-process fake provider —
`tests/test_oidc.py`. No test needs a network.

---

## 2. Why an allowlist, and why by subject

**A successful exchange is necessary and not sufficient.** Kairos does not admit
"anyone the IdP vouched for".

The pattern comes from the ETH deployment's Shibboleth adapter
(`duplet-webserver/libs/duplet_common/auth.py`): the SP sits in the full
SWITCHaai federation, so *any* university account produces identity headers, and
the adapter therefore requires the asserted identity to resolve to a **known row
in the directory** with an explicit grant for that app. Its own comment is
*"spoofed headers fail the DB check"*. The same reasoning transfers verbatim: an
IdP that authenticates your whole organisation authenticates a lot of people who
are not your poll owners.

Kairos has no user directory — that is ADR-0009's job and this issue explicitly
does not build it. So the allowlist *is* the directory, and it is consulted on
every request, not only at login. Removing a subject from
`KAIROS_OIDC_ALLOWED_SUBJECTS` signs that person out immediately; nothing waits
for a cookie to expire.

**Two forms, and which to use.**

- `KAIROS_OIDC_ALLOWED_SUBJECTS` — exact `sub` values. Opaque, case-sensitive,
  stable for the life of the account, identical in shape on every provider.
  **Use this.** It is the closest thing to "a known row in a directory" that a
  stateless app can have.
- `KAIROS_OIDC_ALLOWED_EMAIL_DOMAINS` — a whole domain. Coarser: it trusts that
  anyone who can authenticate at the IdP with an address at that domain is one of
  yours. Convenient when your IdP is already scoped to your domain (Google
  Workspace, a single-realm Keycloak). By default a domain entry also requires
  `email_verified: true`, so it is a claim about a verified mailbox rather than
  about a string anyone can type.

**An empty allowlist refuses to boot.** Not a warning: `KAIROS_AUTH=oidc` with
neither variable set raises at startup. An unparseable entry — an email domain
that is not a bare domain, a subject containing whitespace, an issuer over plain
http to a non-loopback host — also refuses to boot, the same way
`KAIROS_TRUSTED_PROXY_CIDRS` does (#47). A security control the operator believes
is in force and is not is worse than no control.

### Finding your `sub`

The provider's own console is the source of truth, and it differs:

- **Keycloak** — the token, or the "Subject" field. A UUID per user.
- **Authentik** — each user's profile shows the `sub` (a UUID).
- **Google** — a stable 21-digit numeric string per account. It does *not* change
  when the user is renamed, and it does change if the account is deleted.
- **Microsoft Entra ID** — for a user in a tenant, a base64-ish string derived
  from the tenant and object id.

Faster than reading it off the console: sign in once with a temporarily broad
allowlist, then read the subject out of the server log. The rejection log line
and the boot line both name it, so a wrong guess is a one-line fix, not a
debugging session.

---

## 3. Configuration

| Variable | Required | Default | Notes |
|---|---|---|---|
| `KAIROS_AUTH` | yes | `demo` | set to `oidc` |
| `KAIROS_OIDC_ISSUER` | yes | — | the issuer identifier **verbatim**; must equal the `issuer` in the discovery document |
| `KAIROS_OIDC_CLIENT_ID` | yes | — | |
| `KAIROS_OIDC_CLIENT_SECRET` | for a confidential client | — | unset = public client (PKCE only) |
| `KAIROS_OIDC_ALLOWED_SUBJECTS` | one of the two | — | comma-separated exact `sub`s |
| `KAIROS_OIDC_ALLOWED_EMAIL_DOMAINS` | one of the two | — | comma-separated bare domains |
| `SESSION_SECRET` | yes | — | already required outside demo mode; also signs the session cookie |
| `KAIROS_PUBLIC_URL` | behind a proxy | derived | sets the redirect URI and the cookie's `Secure` flag |
| `KAIROS_OIDC_REDIRECT_URI` | no | derived | set it: this is the string to register on the IdP |
| `KAIROS_OIDC_SCOPES` | no | `openid email profile` | |
| `KAIROS_OIDC_CLIENT_AUTH` | no | `post` | or `basic` (RFC 6749 §2.3.1) |
| `KAIROS_OIDC_TRUST_UNVERIFIED_EMAIL` | no | off | named for what it weakens |
| `KAIROS_TRUSTED_PROXY_CIDRS` | behind a proxy | unset | the **edge** allowlist, not the identity one |

**The redirect URI must match byte for byte.** Scheme, host, port, path, and any
trailing slash. `https://polls.example.org/oidc/callback` and
`https://polls.example.org/oidc/callback/` are different URIs, and a mismatch
presents as an infinite sign-in loop with the provider's `redirect_uri_mismatch`
in the Kairos log. With `KAIROS_PREFIX=/scheduler` the callback is
`…/scheduler/oidc/callback`, and the transaction/session cookies are scoped to
that prefix.

`KAIROS_OIDC_CLIENT_AUTH=post` is the default because that is what the hosted
providers document; Authentik and Keycloak both accept HTTP Basic as well. If the
exchange returns `invalid_client`, try `basic` before suspecting the secret.

### A minimal working set

```sh
KAIROS_AUTH=oidc
KAIROS_DB_URL=sqlite:////data/kairos.db
SESSION_SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
KAIROS_PUBLIC_URL=https://polls.example.org
KAIROS_OIDC_ISSUER=https://id.example.org/realms/main
KAIROS_OIDC_CLIENT_ID=kairos
KAIROS_OIDC_CLIENT_SECRET=…
KAIROS_OIDC_ALLOWED_SUBJECTS=8f2c…
KAIROS_TRUSTED_PROXY_CIDRS=172.30.30.0/24
```

Every boot logs one line naming the boundary that is actually in force:

```
owner auth: oidc (issuer=…, client=kairos, redirect=…, allowlist=1 subject(s);
  session cookie kairos_oidc_session, 12h, allowlist re-checked on every request)
```

In any other mode the same line reads `owner auth: header (OIDC not configured)`
— so a green boot tells you which control decided your identity, rather than
leaving you to infer it from a working page.

---

## 4. Registering the client, per provider

**Authentik / Keycloak / Zitadel** — no external console. Create the
application, set the redirect URI to `https://<host><prefix>/oidc/callback`, and
read the `sub` off the user profile. Sign the id_token with RS256 (the default
everywhere) — Kairos verifies RS256/RS384/RS512 and HS256/384/512, and refuses
anything else rather than guessing. **ES256 is not implemented**; if your provider
is configured for it, switch it to RS256 (both Authentik and Keycloak default to
RS256) or use the proxy topology.

**Google** — console setup, by hand:
1. Create a project; enable the OpenID Connect API.
2. Credentials → Create credentials → OAuth client ID → **Web application**.
3. Add `https://<host><prefix>/oidc/callback` under **Authorized redirect URIs**.
   It must match exactly, including a trailing slash if you write one.
4. Copy the client id and secret. Changes can take minutes to hours to propagate,
   so a failure immediately after registering is not necessarily a mistake.
5. Scopes `openid email profile`; Google sets `email_verified` on Workspace
   accounts, which the domain allowlist requires.

**Microsoft Entra ID** — App registrations → Web, redirect URI
`https://<host><prefix>/oidc/callback`, then Certificates & secrets. For a
single-tenant app add "Accounts in this organizational directory only", or your
allowlist is the only thing keeping the tenant's other members out.

**Authelia** — its own OIDC endpoint is a provider like any other
(`https://auth.example.com`); point `KAIROS_OIDC_ISSUER` at it.

**GitHub cannot back this mode.** GitHub publishes discovery documents for its
own MCP server but *"does not currently implement OpenID Connect in its OAuth
flows and does not issue ID tokens for users or apps"* — its `/user` endpoint is
plain OAuth. Kairos authenticates from a verified id_token and refuses a token
response without one, with a log line saying exactly that. Use
`compose.proxy.yaml`, which reads GitHub's identity from the header oauth2-proxy
sets. That is the right answer for GitHub, not a gap to work around.

---

## 5. Operator checklist

- [ ] `KAIROS_TRUSTED_PROXY_CIDRS` is set and matches the pinned compose subnet.
      In this mode it is not the identity boundary, but a stale value is
      fail-closed and presents as **403 on every page**, which looks like a
      broken app rather than a security control.
- [ ] The app port is **not** published (`expose: 8003`, never `ports`). A
      published port is seen by the app as an in-subnet peer, which no allowlist
      value can reliably exclude.
- [ ] The image's `CMD` is used, or `uvicorn --no-proxy-headers` is passed if you
      launch uvicorn yourself — otherwise uvicorn rewrites the peer from
      `X-Forwarded-For` before Kairos sees it and the allowlist is checked against
      attacker input.
- [ ] `KAIROS_PUBLIC_URL` is set. It is what makes the session cookie `Secure` and
      the redirect URI correct; unset, both fall back to request headers and the
      app warns at boot.
- [ ] `SESSION_SECRET` is generated, durable and backed up. Rotating it signs out
      every owner and invalidates every response-edit token and invite signature
      in flight.
- [ ] The allowlist is set, and re-read after your first real sign-in. The boot
      line tells you how wide it is; the log names the subject when someone is
      refused.
- [ ] `KAIROS_RATE_LIMIT=on` for anything reachable by people you do not know.
      `/oidc/start` and `/oidc/callback` carry the `login` budget precisely
      because they are unauthenticated *and* make an outbound call per request.
- [ ] `/privacy` still needs no consent banner. Kairos sets only strictly
      necessary cookies (the session and the 10-minute transaction cookie), which
      the exemption covers. Adding any third-party embed changes that.
- [ ] Test a **rejected** subject before you need to: sign in with an account you
      did not allow and confirm you get the 403 and the log line. A deny path that
      has never been exercised is not a deny path.

---

## 6. What is NOT tested

Stated plainly, because a hand-rolled verifier deserves it. `tests/test_oidc.py`
runs entirely offline against a fake provider, so these are unproven:

- **That a real provider's discovery document and JWKS parse the way we assume.**
  The fake is built to the spec. Key-shape variance across vendors (a JWK without
  `alg`, a `kid` reused across rotations, a JWKS served from a different host than
  the issuer) has not been seen by this code.
- **That a real provider's signature is a standard RS256/HS256 signature.** The
  RFC 8017 DigestInfo prefixes are cross-checked in tests against an independent
  DER encoding, and a real signature round-trips against a real RSA key — but no
  token minted by Google, Microsoft, Authentik or Keycloak has passed through
  this verifier. **Run one real sign-in per provider before you rely on it.**
- **That a provider's redirect-URI matching is as strict as its documentation
  claims.** We send one exact string; what happens on a mismatch is the provider's
  behaviour, and it is the single most common setup failure.
- **Logout.** `POST /oidc/logout` clears the Kairos session only. The IdP's own
  session survives, so the next sign-in is one click rather than a fresh login.
  RP-initiated single logout is `end_session_endpoint`, which is
  provider-specific, and revoking the refresh token with it is out of scope.
- **Clock behaviour under real skew.** 60s of tolerance is asserted in tests, not
  observed against a real IdP's clock.
- **Anything about EC-signed tokens** (`ES256`/`ES384`/`ES512`) or RSA-PSS
  (`PS256`). Both are refused with a clear error rather than accepted
  unverified. Hand-rolling P-256 or PSS was not worth the attack surface; a
  provider configured for them should use RS256 or the proxy topology.

The escape hatches are the same ones as everywhere else in this repo:
`kairos.auth.get_user = mine` remains a documented runtime seam, and
`oidc.http` is a module attribute an operator can replace with a transport that
proxies, retries or records.

---

## 7. Changing IdP, changing subject

- **New provider, same people.** Subjects are provider-scoped, so switching IdPs
  changes every `sub`. Existing polls stay attached to the old `uid` and become
  invisible to the new sign-in. There is no account-linking layer (that is #32's
  job). Copy the old subjects into your records before you switch.
- **A subject that changes.** Some providers reissue `sub` on a directory
  migration. Add the new value to the allowlist *before* the migration and remove
  the old one after; there is no overlap window in which nobody can sign in, and
  the session cookie carries the issuer, so a token from the old provider stops
  being accepted as soon as `KAIROS_OIDC_ISSUER` changes.
- **Offboarding.** Remove the subject from the allowlist. Effective on that
  person's next request; no session revocation list to run.
