# PLAN — Bring Kairos up to speed

> Written 2026-10-02. Supersedes `HANDOFF.md` (stale: claims v0.2.0 / "everything
> DONE"; actual is v0.9.0 with a large unstarted productization arc).
> `goal.md` is likewise closed out — P0–P3 landed, issue #23 closed. Note its
> guardrail still says "77-test baseline"; the real baseline is **116**.

## Where we actually are

| | |
|---|---|
| `main` | `0ed63da` — ADR-0011, house brand. **12 decision records: 10 Accepted, 2 Proposed** (0009 multi-tenancy, 0012 surface tiers). |
| Tests | **116 passing**, <1s on SQLite. |
| Released | v0.9.0. A release-please **0.9.1 PR has been open since Jul 1** with `main` sitting on unreleased commits. |
| Reverse-calendar arc | **Shipped.** Feed + deep-link RSVP + iMIP REQUEST/CANCEL + IMAP ingest + decision-time iMIP. Only P4 (live cross-client verification) partial. |
| Productization arc | **Not started.** **10 open issues** — #29–#37 plus Epic #38. |
| Direction | ADR-0012 (*Proposed*): widen from one shape to four (find-slots / find-dates / RSVP-choices / booking), three surface tiers, agent-first. |

## Guiding constraint — do not break the ETH path

Every issue must be **additive and nullable**. `KAIROS_AUTH=header` (ETH/duplet) and
the self-host path must behave **identically** after all of this. Each PR needs a
test asserting header-mode is unchanged, or it is not done. This is ADR-0001/0002
and it is the whole reason the epic is sequenced in five steps.

Second constraint, from ADR-0012: **A1–A3 (Turnstile #31, verified-creator-before-
mail, rate limits #37) are blocking for hosted custom pages**, not merely "before
public launch". A convincing page on our domain, mailed from our DKIM-signed domain,
is a phishing kit — and it destroys the mail reputation everything else depends on.

## Identity: three families, not one — how Google/GitHub/MS/OpenAthens fit

Asked whether the trust model should be IdPs and tokens rather than proxy
allowlists. It already is — they are three *different* families, and conflating
them is what makes the question feel open. Kairos supports all three; the design
question is which is default and how they compose.

| Family | Mechanism | Where it lives | Who uses it |
|---|---|---|---|
| **Proxy-asserted** | a trusted proxy injects `X-User` etc. | `KAIROS_AUTH=header` + #47 allowlist | Shibboleth, **OpenAthens**, oauth2-proxy, Authelia, Cloudflare Access, Tailscale — i.e. *any* SAML/OIDC IdP |
| **First-party login** | Kairos is the OAuth/OIDC client | planned, #32 (magic-link) and see below | Google, GitHub, Microsoft — federated/social |
| **Capability** | possession of a token in the URL | `KAIROS_AUTH=capability` (#30), invite tokens today | respondents, share links, agents |

**The key point: every IdP named above already works today without Kairos
knowing it exists.** Shibboleth and OpenAthens are SAML brokers; oauth2-proxy
and Authelia terminate OIDC. All of them reduce to the same thing — *something
verified the user and wrote the result into a request header* — which is exactly
the header-mode contract, and exactly what #47 makes safe to rely on. Point any
of them at Kairos, set `KAIROS_TRUSTED_PROXY_CIDRS` to the proxy, and you have
Google/GitHub/MS/ETH federation with **zero Kairos code**.

So the choice is not "IdPs vs proxy". It is:

- **Federated login *outside* Kairos (proxy) — recommended default.** Kairos
  stays a small, dependency-light backend with no OAuth surface, no token
  storage, no session/redirect/PKCE machinery. Every compliance-reviewed IdP
  stays in front of it. One integration, N IdPs.
- **Federated login *inside* Kairos — only when we must be the client.** Worth it
  when there is no proxy to deploy (hosted, single-tenant, no ops staff), or when
  we want a one-click "sign in with Google" without the operator running
  anything. Costs: a client per IdP, redirect URIs, `state`/`nonce`/PKCE, a
  session table, an *IdP-side* subject allowlist (which then replaces the CIDR
  allowlist as the trust boundary), plus account linking and recovery.

**Recommend: support both, default to the proxy.** #47 makes family 1 safe;
#32+ adds family 2 for the hosted case where no proxy exists; #30 adds family 3.
`auth.get_user` is already a documented runtime-seam (`kairos.auth.get_user =
mine`) for bespoke portals, which is a third escape hatch and should not be
removed.

**The composition rule to write down:** these are *not* alternatives to be
picked once — they are layers. Capability tokens stay for respondents whatever
the owner auth is (they must: respondents never get accounts). Owner auth picks
family 1 or 2. And #47's allowlist is the trust boundary for family 1 only —
if Kairos ever terminates OIDC itself, the allowlist stops being the thing that
matters, which is exactly why defaulting to family 1 is the conservative choice.

## Exposure gates that have no owner (raised from `docs/design/productization-obligations.md`)

The register names the hard pre-exposure gate as **A1–A3 + S1/S6 + M1**. S6 is
covered by #29, but two of them were **PLANNED with no issue and no owner in the
roadmap** — filed as #47 and #48:

| Obligation | What | Status in register |
|---|---|---|
| **S1** | Owner identity must come only from a **trusted** proxy; header-auth must not trust arbitrary upstreams | PARTIAL — allowlist PLANNED, no issue |
| **M1** | Outbound mail authenticated from our domain (SPF/DKIM/DMARC), never a personal Gmail | PLANNED, no issue |

**S1 is the one to take seriously first.** ADR-0002's whole model is "trust the
identity headers from whatever reverse proxy you run". The moment a hosted
instance is on the public internet that stops being free — without an allowlist,
anyone who can reach the port can assert any identity header they like. It is a
small change and it is a precondition for putting this thing online at all.

## Phase 0 — housekeeping (now)

1. ✅ Playwright MCP attach fixed (was never configured for opencode; added
   project-level `opencode.json`, gitignored — the global one is a read-only Nix
   store symlink).
2. ✅ Committed the `mcp/kairos_mcp.py` `KAIROS_PREFIX` fix — it hardcoded
   `/scheduler/api`, which **404s on every default deployment** including the
   README quickstart. Real bug; extracted `api_url()` and covered it with
   `tests/test_mcp_client.py` (9 cases, incl. one asserting the client's prefix
   still matches `settings.PREFIX` in a clean env).
3. ✅ ADR-0012 landed as **Proposed**, not Accepted — its 4 open questions are
   the operator's, and accepting it would force a FEATURE-MATRIX row for a
   feature that does not exist yet.
4. ✅ Stale `HANDOFF.md` rewritten to point here.
5. ✅ Filed #47 (S1 trusted-proxy allowlist) and #48 (M1 mail auth) — the two
   exposure gates that had no owner.
6. **Drain the PR queue** (4 open). Serial, one CI run at a time:
   `#28` release 0.9.1 → `#20` checkout 6→7 → `#22` ui-deps → `#46` python-deps.
   Note `#28` and `#46` both touch `pyproject.toml` — land the release first so
   the version bump does not have to rebase through the dependency hunks.

## Phase 1 — independent enablers (parallel, unblock hosting)

No dependencies. Land in this order — security first, because it is cheap and it
gates everything downstream.

| # | Issue | Why now |
|---|---|---|
| **#47** | Trusted-proxy allowlist (obligation **S1**) | **Security, and the true first thing to fix before any public deploy.** See the exposure-gates section above. Small, additive, no dependency on anything else. |
| **#51** | Scope / tier / rate-limit the API + MCP surface | **Security, and the worst hole in the repo today.** A single bearer key with no scopes, no tiers and **no rate limit anywhere** reaches all polls; MCP's `invite` / `nudge(force=True)` / `email_decision` send to **arbitrary third parties at unbounded rate**. With #48 landed that mail is DKIM-valid from our domain. Turnstile does not help — the API never touches `/new`. **Do the scoping and send budgets before any public launch; Stripe can wait.** |
| **#48** | SPF/DKIM/DMARC for our sending domain (obligation **M1**) | Must land before the hosted product sends real mail from our domain. |
| **#37** | Rate limiting + abuse protection (obligation **A3**) | The *public* endpoints (respond, invite, deep-link vote). Distinct from #51, which is the API/MCP surface — do not let one gate stand in for the other. |
| **#35** | Dockerfile + compose.yaml | Mechanical, self-contained, unblocks every deploy story. Podman-tested per house convention. |
| ~~#36~~ | ~~Postgres dialect~~ | ✅ **Decided 2026-10-02: SQLite, not Postgres.** See below. |

### #36 — decided: SQLite

No third SQL dialect. SQLite is already a first-class dialect (the whole suite
is SQLite e2e, the quickstart ships it), so a persistent volume buys the same
thing for far less surface than a new dialect + CI job.

What that commits us to, so it is a decision and not a dodge:

- **The deployment needs a persistent volume** for `kairos.db` — an ephemeral
  filesystem loses every poll on redeploy. That is the entire cost.
- **Tension with #34 (scale-to-zero).** A webhook mail adapter lets the *process*
  scale to zero; a SQLite file means the *volume* cannot. Fine for one
  always-warm instance, wrong for N instances sharing a DB.
- **Operational ceiling: one writer.** Fine at hobby / Pro-single-tenant scale.

**Revisit trigger:** more than one app instance, or write contention on the
volume.

## Phase 2 — the accountless chain (strictly serial)

This is the spine of Epic #38 and the reason it was decomposed. Each step depends
on the last; do not parallelize.

```
#29 admin_token + require_manage predicate   ← foundation, no deps (obligation S6)
      ↓
#30 KAIROS_AUTH=capability + /manage/<token>  ← needs require_manage to gate the route
      ↓
#31 Turnstile + manage_verified_at send-gate ← needs /manage to exist to verify
```

**#29–#31 = a complete hosted product with no signup at all** — magic-link managed,
Turnstile-gated. That is the target state, and it is achievable without ever
building #32/#33. Note the pieces #29 introduces (`admin_token`, `owner_id`,
`creator_email`, `manage_verified_at`) are **nullable**, so this is additive.

⚠ **#31 carries a consent obligation that is easy to miss.** Turnstile is a
third-party embed. Obligation **P1** (strictly-necessary cookies, no consent
banner) is currently **MET** precisely because Kairos embeds nothing third-party,
and P4 ("if Turnstile/analytics added, disclose + consent") is marked
*N/A until added* — i.e. #31 is the thing that flips it. `README.md`'s operator
cookie note says the same in prose. So #31 is not just "add a widget": it must
also either (a) use a click-to-load facade behind a per-deployment flag, or
(b) accept the banner, update `/privacy`, and re-check the P1 claim. Decide this
**in #31**, not after it ships — ADR-0012's whole threat model is about not
putting a consent-bannered, mail-capable origin on the public internet.

## Phase 3 — monetization (upsell, not blocking)

| # | Issue | Gate |
|---|---|---|
| **#32** | Accounts + login + dashboard + claim (Pro) | After #29–#31 are proven in prod. Claim = migrate an accountless poll via `admin_token`. |
| **#33** | Stripe billing | After #32. Do not start earlier — billing with no working hosted product is wasted work. |

## Phase 4 — operator-facing polish

- **#34** inbound-webhook mail adapter (`KAIROS_IMIP_INBOUND=webhook`) — additive
  alongside IMAP; required for scale-to-zero and for deliverability. Sequence after
  the hosted deploy path exists, since its value depends on #35.
- **P4 cross-client iMIP verification** — the one unchecked box in `goal.md`.
  Needs a real mailbox and real Apple/Outlook/Gmail clients. **Operator-only.**
- Refresh `README.md` / `FEATURE-MATRIX.md` as ADRs get accepted (the
  `guardrails-adr-matrix` pre-commit gate, run by the CI `gates` job, enforces
  the latter).

## Per-PR working agreement

Every issue ships the same way:

1. Read the issue + the design doc it cites. Do not re-litigate decided architecture.
2. Branch, implement, **add tests** (repo baseline is 116 and must not regress).
3. Header-mode-unchanged assertion (see guiding constraint).
4. `nix develop -c uv run pytest -q` green; run the repo's own gates pre-push
   (that is `nix develop -c git commit` — pre-commit runs ruff, pytest, the ADR
   gates and gitleaks).
5. **Fresh-context subagent review before merge** — the reviewer has not seen the
   implementation, which is the entire point. Treat self-review as theater.
6. Address findings, re-run CI, squash-merge conventional commit.
7. Tick the box in Epic #38 and the checkbox in the issue.

Never merge without green CI. **Note: `main` has no branch protection and this is
a user-owned repo, so there is no merge queue and nothing enforces checks — the
reviewer is the gate, not GitHub.** Never let an agent merge its own PR.

## Open decisions for the operator (not mine to make)

1. ~~#36 Postgres vs SQLite-on-volume~~ — ✅ **decided: SQLite.** Revisit trigger
   is >1 app instance.
2. **ADR-0012 open questions** — the four are listed under "ADR-0012 decisions"
   below, with recommendations.
3. **P4 live iMIP verification** — needs your real mailbox and clients.
4. ~~#31 consent shape~~ — folded into ADR-0012 Q4 below.

## ADR-0012 decisions — the four open questions

Straight from `docs/adr/0012-scheduling-primitive-surface-tiers.md` §Open
questions, with a recommendation on each.

**Q1 — Is Booking in or out of v1?**
It is the only one of the four shapes that needs genuinely new machinery:
exclusive first-come claims (so real transactions), recurrence expansion, and a
documented carve-out from ADR-0001 (an anonymous booking page lists free
intervals with no authenticated owner, which ADR-0001 forbids). The other three
shapes are the existing tables plus one orthogonal axis.
**Recommend: defer booking out of v1.** Deferring costs nothing structurally,
because choices are an orthogonal axis — #29's `sched_poll_questions` work is not
wasted either way. Booking is then additive instead of load-bearing.

**Q2 — What is the v1 block list?**
The ADR proposes `heading`, `prose`, `bullets`, `agenda`, `people`, `location`,
`callout`, `link_buttons`, `poll_grid`, `diagram` (~10 types).
**Recommend: accept the proposed list as v1.** The ADR's own reasoning caps
ambition here — blocks serve surface tiers 1–2 only, and anything more expressive
drops to the headless tier, so ~8 opinionated types is the ceiling by design.
Widening it later is additive.

**Q3 — Images: self-hosted upload, URL allowlist, or neither in v1?**
This is a security question, not a feature question. Inline SVG is executable
markup, and an LLM author turns prompt injection into stored XSS on the very
origin that serves capability tokens. The ADR permits author artwork **only** as
a separate `<img>` with `Content-Security-Policy: sandbox`.
**Recommend: neither in v1** — no upload, no URL allowlist. Generated
`diagram` blocks (which Kairos renders from structured data) carry the visual
weight. Revisit only with upload behind a real scanning/quota story, because
"an image host on your capability-token origin" is its own abuse surface.

**Q4 — Surface layer (Bun/TS) before or after P4?**
And the related consent question: if a third-party embed is ever offered,
click-to-load facade + per-deployment flag + a `/privacy` change.
**Recommend: after P4.** P4 (live cross-client iMIP verification) is described in
ADR-0012 as the *porting oracle* — a working end-to-end implementation to port
*from*. Building a TS surface layer before P4 means porting blind. Note the
global CLAUDE.md rule "don't guess API shapes — write a debug probe first", and
the ADR's own advice not to make this a rewrite decision before P4 exists.
On consent: ADR-0012's P1 break applies to **any** third-party embed, which
includes Turnstile in #31 — so that decision is needed *in* #31, not deferred to
a surface layer that may never arrive.
