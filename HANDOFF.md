# Kairos — session state

> **Read this first after any restart.** In-session task lists do not survive a
> crash or a new session; this file does. It is the durable version of "what is in
> flight and what is next". Longer-horizon plan in [`PLAN.md`](PLAN.md).

## Where we are

`main` = `fba7304` ("first-party OIDC owner login, allowlisted by subject", v0.10.0
released). Tests **717 passing**, <10s on SQLite. 8 CI jobs: tests / quickstart /
mysql / image / licenses / audit / gates / lockfile. All green.

Shipped since the bring-up triage — each reviewed by a fresh-context subagent, all
merged: **S1 trusted-proxy allowlist** (#55/#47), **OCI image + compose
topologies** (#56/#35), **M1 outbound mail identity gate + runbook** (#58/#48),
**public-surface rate limits** (#57/#37), **API/MCP scoping and send budgets**
(#61/#51), **`admin_token` + `require_manage`** (#60/#29), and **first-party OIDC
login** (#62/#53). Closed as decided: **#36** (SQLite, not Postgres).

The reverse-calendar arc (`goal.md`, #23) was shipped earlier; only P4 live
cross-client verification remains and it needs a real mailbox.

## In flight — three PRs, all CLEAN, NONE MERGED

All implemented and green, all waiting on a **fresh-context subagent review** that
has been unavailable.

| PR | Issue | Branch | Substance |
|---|---|---|---|
| **#66** | #59 | `fix/issue-59-release-lock` | `release-please-config.json` with a name-scoped TOML jsonpath so `uv.lock` tracks the version bump. Without it **every release breaks the image build** (`uv sync --locked`). Plus a `lockfile` CI job. |
| **#67** | #63, #64 | `feat/issues-63-64-poll-authz` | `reach.py` — one reach predicate, two enforcement points. Fixes: any `polls:read` key reading every poll's respondents, and `GET /polls/{id}` returning respondent names to any signed-in user. |
| **#68** | #30 | `feat/issue-30-capability` | `KAIROS_AUTH=capability` + `/manage/<token>` magic link, atomic `admin_token` rotation, manage console. **Unblocks #31.** |

Also queued: **#65** release-please 0.11.0 (bot PR — hold until the above land).

### Why they are not merged

`main` has **no branch protection** and this is a user-owned repo, so there is no
merge queue and **nothing enforces CI** — a fresh reviewer is the only gate. Of the
nine PRs reviewed that way, **eight came back FIX FIRST**, including a fail-open
authorization predicate (`None in (None, None)` granting poll management) and a
MariaDB password printed to the container log on every boot. Do not merge on
CI-green alone.

### Blocked: the task tool is down

`task` returns `FOREIGN KEY constraint failed` for **both** agent types
(`general`, `explore`) — the task subsystem's own database, not the model. Seven
retries. Implementer agents worked earlier in the same session, so the fault
appeared after the previous batch's worktree/branch cleanup. **If you are reading
this after a restart, try the review first — it may have recovered.**

Verified in the meantime (not a substitute for review): `uv.lock` has 31
`version =` lines and #66's filter is **name-scoped**, landing on line 182 only;
#68's `rotate_admin_token` is a true SQL compare-and-swap (`WHERE id = %s AND
admin_token = %s`), not read-then-write; #67's audit reuses `_api_routes` from
`test_api_scoping` rather than re-walking routes.

## Next, in order

1. Retry the subagent review on **#66**, **#67**, **#68**; fix findings; merge in
   that order (least security-critical first). #68 also **fixes a flaky test** on
   `main` — `test_a_tampered_session_cookie_is_not_an_owner`, ~1 run in 10, which
   flipped the last char of a base64url segment (spare bits) so the "tampered"
   cookie verified 4000/4000 times. Merging #68 clears it.
2. **#31** Turnstile + `manage_verified_at` send-gate — needs #68's `/manage`. Also
   gate `POST /manage/link`, which #68 flags as having **no abuse owner** under
   shipped defaults, so a third party can trigger nuisance mail at a victim address.
3. **#34** inbound-webhook mail adapter — independent. This is the Cloudflare
   Email Routing shape #54 depends on.
4. **#54** Cloudflare Workers + D1 dialect port — the largest remaining item and a
   **DB-driver rewrite**, not config (see PLAN.md). The D1-vs-Hyperdrive spike is
   already settled in favour of D1.
5. **#32** accounts + dashboard + claim, then **#33** Stripe, after the above.

## Decisions taken (do not relitigate)

- **SQLite, not Postgres** (#36). Persistent volume required; conflicts with #34
  scale-to-zero; one writer is the ceiling. Revisit trigger: >1 app instance.
- **D1 over Hyperdrive** (#54). Storage is a **tie** (500 MB each); D1 wins on no
  CU-hours ceiling and no second provider. **Retention TTL is load-bearing** —
  Workers Free is 100k req/day (~1,600 polls/day), a 14-day window overflows
  500 MB while 7–10 days fits.
- **Identity is three families, not one**: proxy-asserted (any SAML/OIDC broker,
  header mode + S1), first-party OIDC (#53, now the primary self-host path), and
  capability tokens (#30, for respondents). They are **layers, not alternatives**.
- **Cloudflare hosts the general version; ETH stays self-hosted** for academia and
  doubles as the self-deployment dogfood. CI stays on `ubuntu-latest`;
  self-hosted runners only if speed/privacy/cost actually bites, and never on the
  box serving academic traffic (a self-hosted runner executes PR code).

## Open decisions for the operator

1. **`KAIROS_POLL_REACH` defaults to `open`** (#67). It fixes the reported defect
   only when `KAIROS_HOSTED=on`, because defaulting to `scoped` would break ETH's
   shared-poll model. So **#63's defect is still live by default.** Is that right?
2. **#31's consent shape** — Turnstile is a third-party embed, which flips
   obligation P4 and the `/privacy` claim. Click-to-load facade, or banner?
3. **ADR-0012's four open questions** — recorded there as *recommendations*, not
   ratified: booking out of v1; the proposed ten blocks; neither image upload nor
   URL allowlist; surface layer after P4. ADR-0012 stays `Proposed`.
4. **#36** revisit if a second app instance is ever needed.

## Housekeeping

Conventional commits on main -> release-please PR -> merge = tag + GH release.
Dev: `direnv allow`; commit via `nix develop -c git commit` (runs ruff, pytest,
the ADR gates and gitleaks).

`git push` must be by **HTTPS URL** on this machine — the GitHub SSH key is not
authorized for `gerchowl`:
`git push https://github.com/gerchowl/kairos.git HEAD:<branch>`

Gotchas learned the hard way, recorded so they are not rediscovered:
- **Never reload the `kairos` package in a test fixture.** Deleting `sys.modules`
  entries leaks into every other test module. `get_connection()` reads
  `settings.DB_URL` at call time, so `monkeypatch.setattr(settings, ...)` suffices.
- **Check `git diff --numstat` after every edit.** A tool here reformats whole
  files silently; it inflated an 8-line change to 242 lines, three separate times.
- NOTE: the duplet adapter keeps mysql-connector-python — vendored duplet_common
  needs it (kairos itself uses pymysql because the CI license-allowlist gate flags
  the connector as GPL). It also patches `kairos.auth.get_user`, so that seam must
  keep working.