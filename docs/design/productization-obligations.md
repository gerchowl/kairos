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
| S1 | Owner identity comes only from a **trusted** proxy; header-auth must not trust arbitrary upstreams | ADR-0002 | CONFIG + RUNTIME (trusted-proxy allowlist) | PARTIAL — allowlist PLANNED |
| S2 | `SESSION_SECRET` required outside demo; refuse to boot without it | ADR-0003 | RUNTIME (fail-closed) | MET |
| S3 | Capability tokens are unguessable (`token_urlsafe(32)`) and never logged | ADR-0001 | RUNTIME + no-secret-in-logs | MET (entropy); PARTIAL (log audit) |
| S4 | No secrets committed to git | — | GATE (gitleaks, pre-commit + CI full-history) | MET |
| S5 | TLS everywhere; no plaintext transport | — | CHECKLIST + CONFIG | CHECKLIST |
| S6 | Every mutating route authorizes via one predicate (`require_manage`) | ADR-0001, #29 | RUNTIME | PLANNED (#29) |
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
| M1 | Outbound is authenticated from our domain (SPF/DKIM/DMARC), never a personal Gmail | — | EXTERNAL + CONFIG | PLANNED |
| M2 | Inbound iMIP replies parsed **fail-closed** (known UID + known invite + fresh SEQUENCE) | ADR-0005 | RUNTIME + CI (fixtures) | MET |
| M3 | Inbound transport pluggable (IMAP poll **or** webhook) | #34 | CONFIG | PARTIAL (IMAP MET; webhook PLANNED #34) |
| M4 | Bounces/complaints suppress the address (no repeat-send to dead inboxes) | — | RUNTIME + EXTERNAL | PLANNED |
| M5 | Native Gmail RSVP requires a non-Gmail organizer; else deep-link fallback | ADR-0006 | CONFIG + CHECKLIST | MET (documented; fallback shipped) |

## 4. Abuse & spam (public product only)

| # | Obligation | Source | Enforce | Status |
|---|---|---|---|---|
| A1 | Poll creation gated by a human check (Turnstile) | #31 | RUNTIME + EXTERNAL | PLANNED (#31) |
| A2 | No email sent to a **third party** until the creator's own email is verified (magic link opened) | ADR-0009, #31 | RUNTIME (`manage_verified_at`) | PLANNED (#31) |
| A3 | Rate limits on public/email-sending endpoints (respond, invite, deep-link vote) | #37 | RUNTIME | PLANNED (#37) |

## 5. Privacy & legal

| # | Obligation | Source | Enforce | Status |
|---|---|---|---|---|
| P1 | Strictly-necessary cookies only; no consent banner unless analytics/3rd-party added | privacy page | RUNTIME + CHECKLIST | MET |
| P2 | Respondent data is deletable (poll delete cascades responses/invites) | — | RUNTIME + CI (test) | MET |
| P3 | Data-retention / account-deletion story for hosted accounts | #32 | RUNTIME + CHECKLIST | PLANNED (#32) |
| P4 | If Turnstile/analytics added, disclose + consent | P1 | CHECKLIST | N/A until added |

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

## Domain (product identity)

**Namecheap-verified, 2026-07-01** (RDAP alone was unreliable for `.io`/`.sh` —
several "available" RDAP hits were actually taken; a real registrar check is
required before buying).

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

Mail (M1) needs DKIM/DMARC on whichever is chosen; a non-Gmail organizer here is
also what unblocks native Gmail RSVP (ADR-0006 / M5).

## Rollup

- **MET now:** S2, S4, M2, M5, P1, P2, D1, D2, T1, G1–G6 (+ token entropy).
- **The gating theme:** most *unmet* obligations are **RUNTIME** (require the tenancy/mail/abuse code — issues #29–#37), not lint gates. Only S4 (gitleaks) is a new *GATE* worth adding now.
- **Before any public exposure**, the hard gate is the abuse trio **A1–A3** + **S1/S6** + **M1** — without those, a public Kairos is an open email relay.
- **Self-host** needs **D3/D4** + the **S5/S1** hardening checklist to be a credible, secure default.

Each RUNTIME obligation lands with its feature issue; each should carry a **test** (its CI enforcement) so the obligation can't regress silently.
