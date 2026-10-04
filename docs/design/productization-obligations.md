# Productization obligations register

The enforceable contracts a **hosted / productized** Kairos must satisfy — the
guardrails-shaped list. Each obligation names its **source** (ADR / issue),
**enforcement** mode, and **status**. Enforcement modes, per `guardrails`
conventions (hard-gate deterministic, nudge probabilistic, run in CI as a shim):

- **GATE** — deterministic check at pre-commit + CI (`--no-verify`-proof only if in CI).
- **CI** — a CI job / test that must pass.
- **RUNTIME** — enforced in code on every request (fail-closed).
- **CONFIG** — a required deploy-time setting (documented, ideally start-time asserted).
- **EXTERNAL** — provider-side config (DKIM/DMARC, Stripe, Turnstile).
- **CHECKLIST** — manual, in the self-host hardening doc (can't be auto-gated).

Status: **MET** · **PARTIAL** · **PLANNED** (issue).

---

## 1. Security & auth

| # | Obligation | Source | Enforce | Status |
|---|---|---|---|---|
| S1 | Owner identity comes only from a **trusted** proxy; header-auth must not trust arbitrary upstreams | ADR-0002 | CONFIG + RUNTIME (trusted-proxy allowlist) | **PARTIAL** (#47) — `KAIROS_TRUSTED_PROXY_CIDRS` enforces at the edge (403 + log), and `proxy_headers=False` stops uvicorn rewriting the peer from a caller-supplied header. **Not MET**: the control is opt-in, so the default is fail-open (trust every peer), and `KAIROS_AUTH` still defaults to `demo`. Making it default-on under header mode is the remaining step — blocked on the duplet adapter (a different repo) which may launch uvicorn itself. **Second boundary (#53, ADR-0013):** in `KAIROS_AUTH=oidc` the control that decides *who may own polls* is the OIDC **subject allowlist** — denies by default, refuses to boot when empty, re-checked on every request so revocation is immediate rather than cookie-expiry-bound — while the CIDR list keeps gating the edge and nothing else. Two boundaries now exist and which one is load-bearing depends on the mode, so every boot logs which is in force |
| S2 | `SESSION_SECRET` required outside demo; refuse to boot without it | ADR-0003 | RUNTIME (fail-closed) | MET |
| S3 | Capability tokens are unguessable (`token_urlsafe(32)`) and never logged | ADR-0001 | RUNTIME + no-secret-in-logs | MET (entropy); PARTIAL (log audit) |
| S4 | No secrets committed to git | — | GATE (gitleaks, pre-commit + CI full-history) | MET |
| S5 | TLS everywhere; no plaintext transport | — | CHECKLIST + CONFIG | CHECKLIST |
| S6 | Every mutating route authorizes via one predicate (`require_manage`) | ADR-0001, #29 | RUNTIME | **PARTIAL** (#29) — one predicate (`auth.require_manage`, and `can_manage` where a route renders its own refusal) now decides management authority for the owner surface: an authenticated identity equal to the poll's `creator_id` **or** `owner_id`, else possession of the poll's `admin_token`, compared with `hmac.compare_digest` and failing closed on a NULL token. Every mutating owner route calls it — CI asserts each one does, plus a test that the pre-#29 inline `creator_id != user` comparison has not crept back. Header mode resolves on the creator rule, so ETH/self-host behaviour is byte-for-byte unchanged with the new columns NULL. **#30** then gated a second surface on it: `KAIROS_AUTH=capability` manages a poll with no account and no proxy, and its eight console actions call the same predicate with a token and **no identity** — the anonymous shape #29's docstring reserved for exactly this — with a CI guard asserting each one reaches it. **Not MET**: the REST surface authorizes via `require_api_key`, which is also a single predicate but reaches every poll by contract; per-poll scoping there belongs to #51. |
| S7 | No PII/secrets splatted into logs/traces | guardrails trace spine | GATE (no-raw-trace-fields, if traced) + review | N/A (no tracing yet) |

## 2. Tenant isolation

| # | Obligation | Source | Enforce | Status |
|---|---|---|---|---|
| T1 | No endpoint enumerates polls without an owner scope or token | ADR-0001 | RUNTIME + CI (test) | MET (no list endpoint today) |
| T2 | All owner-scoped reads go through the single scoping helper (`list_polls(owner)`) — no ad-hoc unscoped queries | ADR-0009, #29 | RUNTIME + review | PLANNED (#29) |
| T3 | `owner_id` nullable → single-team/ETH unaffected by tenancy | ADR-0009 | GATE (adr-matrix trace) + CI (ETH-mode tests) | PARTIAL |
| T4 | Enterprise/compliance isolation = self-host (own container + DB), not shared | ADR-0008/0009 | CHECKLIST | MET (self-host exists) |

## 3. Mail & deliverability

| # | Obligation | Source | Enforce | Status |
|---|---|---|---|---|
| M1 | Outbound is authenticated from our domain (SPF/DKIM/DMARC), never a personal Gmail | ADR-0011 | EXTERNAL + CONFIG + RUNTIME | **PARTIAL** (#48) — `KAIROS_HOSTED` + `KAIROS_FROM_DOMAIN` make a hosted deployment **refuse to send** (one logged refusal per process, enforced in the single `is_configured()` predicate every send path already consults) unless `SMTP_FROM` and `KAIROS_IMIP_ORGANIZER` are mailboxes on the declared domain — never a consumer provider. Each boot logs the identity it will send as. **Not MET**: the DNS half is entirely the operator's and unstarted — SPF/DKIM/DMARC are unpublished, no provider chosen. Kairos cannot read DNS, so it verifies that the identity *could* be authenticated, never that it *is*. **The sharpest residual risk, and the most likely state:** `KAIROS_HOSTED=1` + a correct `KAIROS_FROM_DOMAIN` + an on-domain `SMTP_FROM` + **zero DNS records published** passes every check and sends on-domain mail that is entirely unauthenticated and looks legitimate — so a green boot line is not evidence the records exist. M1 also does not protect reputation by itself: the phishing threat needs recipients to *receive* the mail (A2/#51), and what actually destroys a domain is the spam-complaint rate (A3), both volume properties. Operator-side runbook, records and staged DMARC plan: `docs/design/mail-auth.md` |
| M2 | Inbound iMIP replies parsed **fail-closed** (known UID + known invite + fresh SEQUENCE) | ADR-0005 | RUNTIME + CI (fixtures) | MET |
| M3 | Inbound transport pluggable (IMAP poll **or** webhook) | #34 | CONFIG | PARTIAL (IMAP MET; webhook PLANNED #34) |
| M4 | Bounces/complaints suppress the address (no repeat-send to dead inboxes) | — | RUNTIME + EXTERNAL | PLANNED |
| M5 | Native Gmail RSVP requires a non-Gmail organizer; else deep-link fallback | ADR-0006 | CONFIG + CHECKLIST | MET (documented; fallback shipped) |

## 4. Abuse & spam (public product only)

| # | Obligation | Source | Enforce | Status |
|---|---|---|---|---|
| A1 | Poll creation gated by a human check (Turnstile) | #31 | RUNTIME + EXTERNAL | **MET** (#31) — in `KAIROS_AUTH=capability`, the only unauthenticated creation path in the app, `POST {prefix}/new` now requires a Cloudflare Turnstile token that is verified **server-side** against `siteverify` with the deployment's secret (`turnstile.verify`), and so does `POST {prefix}/manage/link` — see A4's note and the abuse-owner paragraph below for why the second one was the gap #68 flagged. Every other refusal shape is honoured too: wrong secret, spent token, a token minted for the *other* form (`action` is bound per form), a token from another host, and — deliberately — **an unreachable verifier**, which is a refusal rather than a pass. Click-to-load, so the widget is fetched only after a click. Off by default and **inert outside capability mode** (the `/manage` routes 404 there, and `header`/`demo`/`oidc`/`none` are byte-for-byte unchanged); on by default once `KAIROS_HOSTED` is on, and an **unrecognised `KAIROS_TURNSTILE` reads as `on`** with a boot warning, following #67's `reach.policy()` — the one failure this issue was told not to ship is a gate that is off because a knob was misspelled. A deployment that turns it on without both keys **refuses to boot**. Each boot logs whether it is in force. **Residual, and each is a limit of the mechanism rather than a gap in it:** (1) it is a ceiling, not a limiter — it bounds *creating a poll*, not how much mail one verified creator sends afterwards, which is A3's per-peer budgets and A4's per-key/per-poll budgets; (2) it does not gate `POST /api/polls`, and should not: that surface's credential is a key, and putting a human check in front of an agent contradicts ADR-0010. What keeps the API from becoming the cannon instead is **A2's gate**, which refuses the mail rather than the poll; (3) a deployment can turn it off with `KAIROS_TURNSTILE=off`, which is an operator decision and is logged as a warning every boot; (4) correctness now depends on a third party being reachable — see the fail-closed note in `turnstile.verify`, where the alternative was rejected |
| A2 | No email sent to a **third party** until the creator's own email is verified (magic link opened) | ADR-0009, #31 | RUNTIME (`manage_verified_at`) + CI (spy-guard) | **MET** (#31, closing #30's PARTIAL) — one predicate, `capability.require_sendable(poll)`, is consulted by every path that can open SMTP on a poll's behalf. **A NULL `manage_verified_at` means *may not send***, so the gate ships closed: the column was added by #29 with no backfill, so every pre-existing row is NULL and no row has ever read as verified by accident. An **absent** key is NULL too, read with `.get()` rather than a truthiness test, because a gate whose *missing* input reads as "allowed" is the same defect #29's `can_manage` warns about. Placement is the point and is pinned by tests: ahead of the slot expansion on `/new`, ahead of `charge_poll_recipients` on every send, ahead of the date loop on `add_slots(notify=True)` — a gate that runs after the budget is spent spends the poll's whole mail allowance on a request it is about to refuse. **What is deliberately *not* gated:** the creation mail and `POST /manage/link`, because both mail the creator's own address and together they are *how* a creator becomes verifiable — gating them would close the hole by deleting the feature. **Not MET, and honestly:** (1) "verified" means *a manage link we mailed was opened*, not a mailbox-level proof — no SPF/DKIM `Received` chain is inspected, so a forwarded address satisfies it; (2) the column is never cleared, so verification is permanent for the life of the poll; (3) the gate is inert outside `KAIROS_AUTH=capability` — deliberately, and that is the compatibility argument rather than a gap: in `header`/`oidc` mode the creator is identified by the proxy or the IdP, there is no address to verify, the column is dead, and ADR-0001/0002 require those deployments to keep behaving exactly as they do; (4) it does not bound *volume* — it is a precondition, and A3/A4 are the ceilings |
| A4 | API/MCP keys are least-privilege, and outbound mail from the API is bounded per request and per poll | #51, ADR-0012 | RUNTIME | **MET** (#51) — six scopes (`polls:read`, `polls:write`, `respond`, `mail:send`, `mail:force`, `imip:poll`) declared per route and default-denied, so a read-only key provably cannot reach a mail-sending route (403); `force=True` needs its own scope *and* its own tighter budget; mail is capped at `KAIROS_MAIL_MAX_RECIPIENTS` recipients per request and `KAIROS_MAIL_PER_POLL` recipients per poll — the latter charged to the poll and shared with the web UI, so it holds regardless of key. Per-key budgets (`api`, `api_write`, `mail`, `mail_force`) reuse #37's limiter and its `RateLimited` signal. **Not MET**, on one count that matters: both mail budgets are per-request and per-poll, so at the shipped defaults the **total across polls from one key is unbounded** — 40 fresh polls × 100 recipients = 4000 recipients, no refusals (measured, and pinned by a test). Not a regression: there was no ceiling here before this issue either. ADR-0001/0002 require an unconfigured deployment to behave as it did, which is why `KAIROS_RATE_LIMIT=on` — the per-key budgets — is what closes it rather than a new default. Every boot logs which state the deployment is in, so the gap cannot be discovered by an operator who never reads this table. Also **not MET**: the scope→plan mapping is a stub — no tier ships, and which plan gets which scopes and limits is #33's decision with Stripe. **#31 changed one thing here:** the four senders on this surface (`invite`, `email-decision`, `imip-decision`, `add_slags(notify=True)`) and the shared `nudge_participants` now consult **A2's** gate, so an API-created accountless poll — the one shape with no creator in a browser anywhere in its loop — cannot mail anybody at all until a human opens its manage link. That is the layering A1 could not provide by itself: the human check stops the *poll* from being created anonymously, this stops the *mail* going out from one that was created with a key |
| A3 | Rate limits on public/email-sending endpoints (respond, invite, deep-link vote) | #37 | RUNTIME | **PARTIAL** (#37) — six named budgets (`read`, `respond`, `deeplink_vote`, `create`, `invite`, `send`) as a reusable `rate_limit` dependency. Charged to the real transport peer, or — behind a proxy with `KAIROS_TRUSTED_PROXY_CIDRS` set — to the nearest **untrusted** hop of the forwarded chain, walked right-to-left so a caller's own prepended claim is never reached. **Not MET**, on three counts: (1) opt-in — `KAIROS_RATE_LIMIT` defaults off so header-mode/self-host are unchanged (ADR-0001/0002), so a public deployment must switch it on; (2) the counters are per-process, so N instances give N× the budget; (3) a budget keyed on an address is evaded by address rotation, so this caps one source, not a motivated attacker. **#31 sharpened (1) rather than removing it:** the human check (A1) makes the limiter *less* load-bearing for anonymous creation, and boot now says so in those terms — but a limiter keyed on a peer still measures the wrong axis for an attacker aiming many requests at **one** victim address, which is the shape `POST /manage/link` had. That route is why A1 covers it too |

## 5. Privacy & legal

| # | Obligation | Source | Enforce | Status |
|---|---|---|---|---|
| P1 | Strictly-necessary cookies only; no consent banner unless analytics/3rd-party added | privacy page | RUNTIME + CHECKLIST | MET — **re-examined by #31 and still MET, on purpose rather than by omission.** The row was previously true because Kairos embedded nothing third-party; adding Turnstile is exactly the thing that would have made it false, so the mechanism chosen was a **click-to-load facade** (P4): no script, no widget and no third-party cookie is fetched on a page view of `/new` or `/manage`, only after the person presses the button that starts the check. The claim therefore survives unchanged *and* stays true for a self-hoster who enables the check, because there is no setting that turns the widget eager. A test renders the shared creation template with and without the gate's context key and compares the two strings, so "the other modes are unchanged" is a byte claim rather than an intention |
| P2 | Respondent data is deletable (poll delete cascades responses/invites) | — | RUNTIME + CI (test) | MET |
| P3 | Data-retention / account-deletion story for hosted accounts | #32 | RUNTIME + CHECKLIST | PLANNED (#32) |
| P4 | If Turnstile/analytics added, disclose + consent | P1 | RUNTIME (page renders it) + CHECKLIST | **MET** (#31) — `/privacy` renders `turnstile.disclosure()` **when, and only when, the check is in force on that deployment**, resolved at request time rather than captured at boot, so a page cannot disclose a third party the deployment never contacts or stay silent about one it does. It names the service, the origin the browser talks to, and *when*: nothing is fetched until the person presses the button. **The consent half is satisfied by not needing consent**, and that is a deliberate design decision rather than a lucky one: Turnstile is embedded through a **click-to-load facade**, so opening a page loads nothing from a third party, runs no third-party code and sets no third-party cookie — which is why P1's "no consent banner is required" survives unchanged. There is deliberately **no flag** to load it eagerly, because the only other state is one where our own privacy page is false, and a flag that selects between "true" and "false" is a flag that will be flipped. What the disclosure does *not* claim is what Cloudflare retains or whether the loaded widget sets a cookie of its own; that is the operator's to answer in `KAIROS_LEGAL_EXTRA`, and #33's billing surface is where a *second* third party (Stripe) would need the same row reopened |

## 6. Deploy & self-host

| # | Obligation | Source | Enforce | Status |
|---|---|---|---|---|
| D1 | One core, thin adapters — no per-deploy forks; features are env-selected | ADR-0008 | GATE (adr-matrix) + review | MET |
| D2 | Env values survive `set -u` sourcing (shell-quote on deploy) | deploy_env fix | CI (deploy lint) | MET (duplet) |
| D3 | OCI image wraps the same `uvicorn` app; venv path unaffected | ADR-0008, #35 | CI (image boots + probes) | PLANNED (#35) |
| D4 | Self-host ships a secure default topology (compose + Caddy/oauth2-proxy) + hardening checklist | #35 | CHECKLIST | PLANNED (#35) |
| D5 | Managed-DB support (Postgres) or documented SQLite-on-volume | #36 | CI (dialect tests) | PARTIAL (MySQL/SQLite MET; PG PLANNED) |

## 7. Governance & code quality

| # | Obligation | Source | Enforce | Status |
|---|---|---|---|---|
| G1 | Every **Accepted** ADR is cited in `FEATURE-MATRIX.md` | adr-matrix | GATE + CI | MET |
| G2 | iCalendar stays stdlib-only (no `icalendar`/`vobject`) | ADR-0004 | GATE + CI | MET |
| G3 | No third-party URL shortener | ADR-0007 | GATE + CI | MET |
| G4 | Dependency tree license-clean (no copyleft surprises) | — | CI (licenses) | MET |
| G5 | No known-CVE deps | — | CI (pip-audit) | MET |
| G6 | Full test suite green (SQLite + MariaDB lifecycles) | — | CI | MET |

## 8. Billing (SaaS tier only)

| # | Obligation | Source | Enforce | Status |
|---|---|---|---|---|
| B1 | Never touch card data — Stripe-hosted Checkout only (PCI-out-of-scope) | #33 | RUNTIME + CHECKLIST | PLANNED (#33) |
| B2 | Stripe webhooks verified + idempotent | #33 | RUNTIME + CI | PLANNED (#33) |
| B3 | Plan gates enforced server-side (never trust the client) | #33 | RUNTIME | PLANNED (#33) |

---

## Domain & brand (product identity) — DECIDED

**Decision (ADR-0011):** ship Kairos **as a nerdmachines tool** at
**`kairos.nerdmachines.com`** — a subdomain of the house brand we already own.
Keep the product name *Kairos*; give it a **bee or goose mascot** for
personality. No standalone domain purchase. This dissolves the domain problem
(a DNS record, not a naming project) and — via a non-Gmail organizer
`kairos@nerdmachines.com` — also unblocks native Gmail RSVP (M1 + M5).
**Open dependency:** confirm `nerdmachines.com` registration is under our control.

### Naming discussion (for the record — why we landed here)

- **"Kairos" is saturated** (Kairos AI / Power / Ventures / Aerospace…); every
  good TLD is taken or premium. That crowding is the real issue; domain scarcity
  is the symptom.
- **Compound/`get-`/`try-`/`-app` domains are stopgaps**, never the brand. What
  works: short distinctive/coined words (Spotify, Stripe, Figma) or, in-space,
  Calendly / Doodle / when2meet. `kairosscheduler.com` = fine address, not a brand.
- **Adjective+animal** explored: pick an animal whose behavior *is* coordination
  so the metaphor earns its keep — **bee** (waggle dance = "when & where" to the
  hive), **goose** (V-formation, honk-to-coordinate, migrates on schedule),
  crane, meerkat, penguin, owl (early-bird/night-owl). Verified-available
  standalones if ever needed: `gathergoose.com`, `rallyrook.com`.
- **Heuristic (Namecheap-verified):** short/real-word `.com`s are extinct
  (`beeup.com` taken since 2006); **alliterative adjective+animal compounds** are
  almost always free (~$12/yr). Bare `kairos.*`, `trykairos.io`, `kairosapp.io`,
  `kairoshq.*`, `nerdmachines.com` (ours) all registered.
- **Resolution:** for an OSS/agent-native tool the brand lives in the org +
  package, not a domain (ADR-0008, ADR-0010) → the house-brand subdomain wins;
  the animal becomes the **mascot**, not the brand.

### Availability pass — Namecheap-verified, 2026-07-01

(RDAP alone was unreliable for `.io`/`.sh` — several "available" RDAP hits were
actually taken; a real registrar check is required before buying.)

**Available (verified):**
| Domain | Price | Note |
|---|---|---|
| `kairosscheduler.com` | $14.98/yr ($6.79 first-yr promo) | descriptive, SEO-friendly — recommended |
| `kairospoll.com` | $14.98/yr ($6.79 first-yr) | short, on-purpose |
| `whenkairos.com` | $14.98/yr ($6.79 first-yr) | when2meet-flavored |

**Taken (verified — corrects earlier RDAP false-positives):** `kairos.sh`,
`kairos.io`, `kairos.app`, `kairos.dev`, `kairos.com`, `trykairos.io`,
`trykairos.com` (premium $995), `kairosapp.io`, `kairoshq.com/.io`. Bare
`kairos.*` is effectively gone (common Greek word); premium asks are steep
(`kairos.xyz` $399k, `kairos.tech` $12k, `kairos.so` $3.9k).

Mail (M1) needs DKIM/DMARC published on the sending domain — the records, the staged
DMARC plan and the verification steps are in
[`mail-auth.md`](mail-auth.md). A non-Gmail organizer here is also what unblocks
native Gmail RSVP (ADR-0006 / M5).

## Rollup

- **MET now:** S2, S4, M2, M5, P1, P2, P4, A1, A2, D1, D2, T1, G1–G6 (+ token entropy).
- **The gating theme:** most *unmet* obligations are **RUNTIME** (require the tenancy/mail/abuse code — issues #29–#37), not lint gates. Only S4 (gitleaks) is a new *GATE* worth adding now.
- **Where public exposure stands.** The abuse trio **A1–A3** now has two of three
  landed: **A1** (human check on the anonymous creation path, and on the re-link
  request) and **A2** (no mail to a third party until the creator's own address is
  verified) are both **MET**; **A3** is **PARTIAL** by design — its counters are
  per-process, opt-in, and keyed on an address — so `KAIROS_RATE_LIMIT=on` is still
  a required step rather than an optional one, and boot says so. With **S1/S6** and
  **M1** also in place, a hosted Kairos is no longer "an open email relay": the
  anonymous paths that *send* mail are gated, and the paths that send it in volume
  are budgeted. What is still not established is **M1's DNS half** (SPF/DKIM/DMARC
  are the operator's and unpublished), which no amount of Kairos code substitutes
  for, and **A4's unbounded across-polls total** under shipped defaults.
- **Self-host** needs **D3/D4** + the **S5/S1** hardening checklist to be a credible, secure default.

Each RUNTIME obligation lands with its feature issue; each should carry a **test** (its CI enforcement) so the obligation can't regress silently.
