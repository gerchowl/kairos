# 0013 — First-party OIDC as an owner-auth family, allowlisted by subject

Status: **Accepted** (amends [0002](0002-accountless-respondents-header-auth.md))

## Context

ADR-0002 decided that Kairos implements no password/OAuth flow in core and takes
owner identity from **trusted reverse-proxy headers**. That is a good decision and
it stays: `KAIROS_AUTH=header` is untouched, and the ETH/duplet Shibboleth
adapter is untouched.

It is also not the only shape, and it is not the cheapest one for a self-hoster.
Header mode needs an authenticating proxy in front of the app, and **nginx cannot
terminate OIDC** — which is precisely why `oauth2-proxy` and `Authelia` exist as
separate boxes to bolt on. Every self-hosted app people actually run (Grafana,
Nextcloud, Vault, Gitea, Immich) terminates OIDC itself, because that is what
makes deployment four environment variables instead of an infrastructure project.

With the two existing identity families — proxy-asserted (ADR-0002) and capability
(ADR-0001) — plus first-party OIDC (#53), the ladder by operator effort is:

| Effort | Mode |
|---|---|
| zero | `demo` (single owner), capability tokens for respondents |
| **~4 env vars** | **first-party OIDC — `KAIROS_AUTH=oidc`** |
| an infrastructure project | proxy + `KAIROS_AUTH=header` |

OIDC is therefore promoted to the primary multi-user self-host path. The work is
identical whether the trigger is "no proxy is available" or "this is the default".

## Decision

Kairos can act as an OIDC relying party: authorization-code flow with `state`,
`nonce` and PKCE (`S256`), a **session cookie** signed with the existing
`SESSION_SECRET` (no session library, no session table), and a **subject
allowlist that denies by default**. It is hand-rolled on the standard library
plus the stack already present, on the ADR-0004 precedent.

Three parts of the decision are load-bearing:

1. **Allowlist by known subject, never "anyone the IdP vouched for".** A successful
   exchange is necessary and not sufficient. The pattern is the ETH deployment's
   own (`duplet-webserver/libs/duplet_common/auth.py`), where an asserted identity
   must resolve to a known directory row with an explicit per-app grant — because
   the SP sits in the full SWITCHaai federation, so *any* university account
   produces headers ("spoofed headers fail the DB check"). Kairos has no directory
   (that is ADR-0009, and this issue does not build it), so the allowlist *is* the
   directory, and it is re-checked on **every request** — which makes revocation
   immediate rather than cookie-expiry-bound. An empty allowlist refuses to boot.
2. **`kairos.auth.get_user` stays the runtime seam.** The ETH adapter replaces it
   (`kairos.auth.get_user = mine`); this mode is one more branch inside it, not a
   restructuring, and the escape hatch survives.
3. **These are layers, not alternatives.** Capability tokens remain for
   respondents whatever the owner auth is — they must, since respondents never get
   accounts. Owner auth picks family 1 (proxy) or family 2 (OIDC). And #47's CIDR
   allowlist is the trust boundary for family 1 only: with Kairos terminating OIDC,
   the allowlist that decides *who may own polls* becomes the **subject**
   allowlist, and the CIDR list keeps gating the edge and nothing else.

Out of scope, deliberately: accounts, dashboards, invitations, billing (#32/#33),
account linking, RP-initiated single logout, tiering and plan limits.

## Consequences

- Self-hosting multi-user Kairos no longer requires operating an auth proxy;
  `compose.oidc.yaml` is the shipped topology.
- **The trust boundary moves.** Two different controls now exist, and which one is
  load-bearing depends on the mode — so every boot logs which one is in force, and
  the mode's configuration is validated at startup rather than skipped.
- The signature verification is ours to own. Mitigated by refusing any `alg` we do
  not implement (which closes `alg: none` and algorithm confusion), never
  consulting a key carried in the token header, and cross-checking the PKCS#1
  DigestInfo against an independent DER encoding in tests. It is still the piece a
  real-provider smoke test must cover — `docs/design/oidc-login.md` §6 says exactly
  what is and is not proven, including that ES256 and RSA-PSS are refused rather
  than accepted unverified.
- `KAIROS_AUTH=oidc` with no `KAIROS_OIDC_*` set is byte-for-byte the previous
  behaviour: the configuration is parsed and validated only when the mode is on,
  and the routes exist in every mode but 404, so the route table does not change
  shape with the environment.
