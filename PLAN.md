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
| **#47** | Trusted-proxy allowlist (register obligation **S1**) | **Security, and the true first thing to fix before any public deploy.** See the exposure-gates section above. Small, additive, no dependency on anything else. |
| **#48** | SPF/DKIM/DMARC for our sending domain (obligation **M1**) | Must land before the hosted product sends real mail from our domain; everything else about mail reputation assumes it. |
| **#37** | Rate limiting + abuse protection | **Security** (obligation **A3**). Public endpoints send email → spam vector. Independent of the account chain. |
| **#35** | Dockerfile + compose.yaml | Mechanical, self-contained, unblocks every deploy story. Podman-tested per house convention. |
| **#36** | Postgres dialect | ⚠ **Push back / evaluate first.** A third SQL dialect is a large surface. SQLite-on-volume may well be the right answer for the free tier. **Recommend deciding this before writing a line of dialect code.** |

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

1. **#36 Postgres vs SQLite-on-volume** — recommend deciding before coding.
2. **ADR-0012 open questions** — booking in v1? v1 block list? image policy?
   Surface layer (Bun/TS) before or after P4?
3. **P4 live iMIP verification** — needs your real mailbox and clients.
4. **#31 consent shape** — click-to-load facade, or accept the banner and update
   `/privacy`?
