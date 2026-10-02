# PLAN — Bring Kairos up to speed

> Written 2026-10-02. Supersedes `HANDOFF.md` (stale: claims v0.2.0 / "everything
> DONE"; actual is v0.9.0 with a large unstarted productization arc).
> `goal.md` is likewise closed out — P0–P3 landed, issue #23 closed.

## Where we actually are

| | |
|---|---|
| `main` | `0ed63da` — ADR-0011, house brand. 11 ADRs accepted. |
| Tests | **107 passing**, <1s on SQLite. |
| Released | v0.9.0. A release-please **0.9.1 PR has been open since Jul 1** with `main` sitting on unreleased commits. |
| Reverse-calendar arc | **Shipped.** Feed + deep-link RSVP + iMIP REQUEST/CANCEL + IMAP ingest + decision-time iMIP. Only P4 (live cross-client verification) partial. |
| Productization arc | **Not started.** 11 issues, #29–#38, under Epic #38. |
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

## Phase 0 — housekeeping (now)

1. ✅ Playwright MCP attach fixed (was never configured for opencode; added
   project-level `opencode.json`, gitignored — the global one is a read-only Nix
   store symlink).
2. Commit the `mcp/kairos_mcp.py` `KAIROS_PREFIX` fix — it hardcoded
   `/scheduler/api`, which **404s on every default deployment** including the
   README quickstart. Real bug, small fix.
3. Land ADR-0012 as a **draft decision record**, not an accepted ADR — it has 4
   open questions that are the operator's to answer.
4. Delete or rewrite stale `HANDOFF.md`.
5. **Drain the PR queue** (4 open). Serial, one CI run at a time:
   `#28` release 0.9.1 → `#20` checkout 6→7 → `#22` ui-deps → `#46` python-deps.

## Phase 1 — independent enablers (parallel, unblock hosting)

No dependencies. Land in this order — security first, because it is cheap and it
gates everything downstream.

| # | Issue | Why now |
|---|---|---|
| **#37** | Rate limiting + abuse protection | **Security.** Public endpoints send email → spam vector. Independent of the account chain; nothing else can safely face the internet first. Do this *before* any hosted deploy. |
| **#35** | Dockerfile + compose.yaml | Mechanical, self-contained, unblocks every deploy story. Podman-tested per house convention. |
| **#36** | Postgres dialect | ⚠ **Push back / evaluate first.** A third SQL dialect is a large surface. SQLite-on-volume may well be the right answer for the free tier. **Recommend deciding this before writing a line of dialect code.** |

## Phase 2 — the accountless chain (strictly serial)

This is the spine of Epic #38 and the reason it was decomposed. Each step depends
on the last; do not parallelize.

```
#29 admin_token + require_manage predicate   ← foundation, no deps
      ↓
#30 KAIROS_AUTH=capability + /manage/<token>  ← needs require_manage to gate the route
      ↓
#31 Turnstile + manage_verified_at send-gate ← needs /manage to exist to verify
```

**#29–#31 = a complete hosted product with no signup at all** — magic-link managed,
Turnstile-gated. That is the target state, and it is achievable without ever
building #32/#33. Note the pieces #29 introduces (`admin_token`, `owner_id`,
`creator_email`, `manage_verified_at`) are **nullable**, so this is additive.

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
- Refresh `README.md` / `FEATURE-MATRIX.md` as ADRs get accepted (CI gate
  `guardrails-adr-matrix` enforces the latter).

## Per-PR working agreement

Every issue ships the same way:

1. Read the issue + the design doc it cites. Do not re-litigate decided architecture.
2. Branch, implement, **add tests** (repo baseline is 107 and must not regress).
3. Header-mode-unchanged assertion (see guiding constraint).
4. `nix develop -c uv run pytest -q` green; run the repo's own gates pre-push.
5. **Fresh-context subagent review before merge** — the reviewer has not seen the
   implementation, which is the entire point. Treat self-review as theater.
6. Address findings, re-run CI, squash-merge conventional commit.
7. Tick the box in Epic #38 and the checkbox in the issue.

Never merge without green required checks. Never let an agent merge its own PR.

## Open decisions for the operator (not mine to make)

1. **#36 Postgres vs SQLite-on-volume** — recommend deciding before coding.
2. **ADR-0012 open questions** — booking in v1? v1 block list? image policy?
   Surface layer (Bun/TS) before or after P4?
3. **P4 live iMIP verification** — needs your real mailbox and clients.