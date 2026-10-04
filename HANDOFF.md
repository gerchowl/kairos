# Kairos — session state

> **Read this first after any restart.** In-session task lists do not survive a
> crash or a new session; this file does. Longer-horizon plan in [`PLAN.md`](PLAN.md).

## Where we are

`main` = `5654d20` ("KAIROS_AUTH=capability + /manage/<token> magic-link console",
#30). Tests **1004 passing**, ~20s. 8 CI jobs: tests / quickstart / mysql / image /
licenses / audit / gates / lockfile. All green. v0.11.0 released.

Shipped since the bring-up triage, each reviewed by a fresh-context subagent and
merged by hand: **S1 trusted-proxy allowlist** (#55/#47), **OCI image + compose**
(#56/#35), **M1 mail identity gate + runbook** (#58/#48), **public rate limits**
(#57/#37), **API/MCP scopes + send budgets** (#61/#51), **`admin_token` +
`require_manage`** (#60/#29), **first-party OIDC** (#62/#53), **per-poll reach**
(#67/#63+#64), **capability mode + /manage console** (#68/#30), and the
**release-mechanism fix** (#66/#59). Closed as decided: **#36** (SQLite).

## Open

- **#71** release-please 0.12.0 — bot PR. Merge after confirming `uv.lock` is in
  its file list; that is what #59 fixed and #65 proved works.
- Next up: **#31** Turnstile + `manage_verified_at` send-gate (unblocked by #68).
  It must also gate `POST /manage/link`. Then **#34**, **#54**, **#32**, **#33**.

## What the reviews found (worth remembering)

Every PR in this batch came back **FIX FIRST**. The findings that mattered, all
real and all shipped:

- **A remote OOM, three times over.** `POST /new` bounded `increment` but not
  `dates`, then not `new_dates × time_pairs`. Measured **59 MB → 2.1 GB in 24 s**
  from one anonymous request; then **+5.99 GB at 16 concurrent**; then
  **+1.1 GB and 2,470,375 slot rows** from a 220 KB body. Each was refused *never*.
  #68 is what made the route reachable with no credential. The same class is
  **still open on the REST API** — filed as #70.
- **A fail-open authorization predicate.** `user.get("uid") in (creator_id, owner_id)`
  meant `None in (None, None)` is True, so an identity-less caller could manage any
  poll with a NULL `owner_id`. Unreachable via stock `get_user`, reachable via the
  documented `get_user = mine` seam.
- **A credential leak**: the MariaDB password printed to the container log on every
  boot, because it rode in `KAIROS_DB_URL` and the banner printed it verbatim.
- **Four wrong RFC citations** in the mail runbook, one of which (`pct` at
  `p=none`) would have led an operator to read a quiet inbox as a healthy domain.
- **Two route audits that certified a page that would 500** — one because it
  keyed on a literal parameter name, one because it counted stubbed calls rather
  than real SQL.

## Process notes that cost real time here

- `main` has **no branch protection**; a fresh reviewer is the only gate. Nine PRs
  reviewed, eight came back FIX FIRST. Do not merge on CI-green alone.
- **Never reload the `kairos` package in a test fixture.** Deleting `sys.modules`
  entries leaks into every other test module. `get_connection()` reads
  `settings.DB_URL` at call time, so `monkeypatch.setattr(settings, ...)` suffices.
- **Check `git diff --numstat` after every edit.** A tool here reformats whole
  files silently — it inflated an 8-line change to 242 lines, three separate times.
- **A conflict resolved by "keep both sides" is only correct for genuinely additive
  edits.** Where both sides rewrote the *same* block it produces orphaned
  docstrings and duplicated statements that still compile. #68's integration needed
  four decisions, each read before it was made. Assert the post-condition
  explicitly (one definition, the expected parameter, no repeated statement).
- **`cp -a` copies `.venv`**, whose console-script shebang points at the *source*
  clone — so mutation tests in a copied tree silently test pristine code. This
  produced two false greens in this repo. Rebuild the venv per copy, and assert
  `import kairos` resolves to the tree under test.
- `git push` must be by **HTTPS URL** here; the GitHub SSH key is not authorized for
  `gerchowl`.

## Decisions taken (do not relitigate)

- **SQLite, not Postgres** (#36). Persistent volume required; conflicts with #34
  scale-to-zero; one writer is the ceiling. Revisit: >1 app instance.
- **D1 over Hyperdrive** (#54). Storage is a tie at 500 MB; D1 wins on no CU-hours
  ceiling and no second provider. **Retention TTL is load-bearing** — Workers Free
  is 100k req/day, a 14-day window overflows 500 MB, 7–10 days fits.
- **Identity is three layers**: proxy-asserted (header mode + S1), first-party OIDC
  (#53), capability tokens (#30). Not alternatives.
- **Cloudflare hosts the general version; ETH stays self-hosted** and dogfoods the
  self-deployment path. CI stays on `ubuntu-latest`; self-hosted runners never on
  the box serving academic traffic (a runner executes PR code).

## Open decisions for the operator

1. **`KAIROS_POLL_REACH` defaults to `open`** (#67), so #63/#64's defect is fixed
   only under `KAIROS_POLL_REACH=scoped` or `KAIROS_HOSTED=on`. Defaulting to
   `scoped` would break ETH's shared-poll model. Is `open` the right default?
2. **#31's consent shape** — Turnstile is a third-party embed, flipping obligation
   P4 and the `/privacy` claim. Facade, or banner?
3. **ADR-0012's four questions** — recorded there as *recommendations*, not
   ratified: booking out of v1; the proposed ten blocks; neither image upload nor
   URL allowlist; surface layer after P4. ADR-0012 stays `Proposed`.
4. **#36** revisit if a second app instance is ever needed.
5. **#70** — whether the REST ceiling should equal the web one.

## Housekeeping

Conventional commits on main -> release-please PR -> merge = tag + GH release.
Dev: `direnv allow`; commit via `nix develop -c git commit`.