# Kairos — session state

> **Read this first after any restart.** In-session task lists do not survive a
> crash or a new session; this file does. Longer-horizon plan in [`PLAN.md`](PLAN.md).

## Where we are

`main` = `6a10e3c` ("chore(main): release 0.13.0"). Tests **1099 passing**, ~27s.
8 CI jobs: tests / quickstart / mysql / image / licenses / audit / gates /
lockfile. All green. **v0.13.0 released. PR queue empty.**

The accountless chain is **complete**: #29 (`admin_token` + `require_manage`) →
#30 (`KAIROS_AUTH=capability` + `/manage/<token>`) → #31 (Turnstile +
`manage_verified_at` send-gate). A hosted poll can be created and managed with no
signup, no proxy and no account.

Also shipped since the bring-up triage, each after a fresh-context review:
**S1 trusted-proxy allowlist** (#47), **OCI image + compose** (#35), **M1 mail
identity gate + runbook** (#48), **public rate limits** (#37), **API/MCP scopes +
send budgets** (#51), **first-party OIDC** (#53), **per-poll reach** (#67),
**release-mechanism fix** (#59). Closed as decided: **#36** (SQLite).

## Open

- **#34** inbound-webhook mail adapter — independent, and the Cloudflare
  Email Routing shape #54 depends on.
- **#54** Cloudflare Workers + D1 dialect port — a DB-driver rewrite, not config.
- **#32** accounts + dashboard + claim, then **#33** Stripe.
- **#70** the REST API's unbounded `dates × grid` — the fourth surface with the
  shape that produced three rounds of OOM fixes in #68.
- **#69** a ~1-in-140 flake on `main`: a test asserts `"1234"` is absent from a
  page, and `static_v = str(int(time.time()))` in asset URLs contains it. Fixed on
  a branch; needs landing.
- **#63 / #64** deliberately left **open**: #67 shipped the mechanism but did not
  auto-close them, because the defect is only closed once
  `KAIROS_POLL_REACH=scoped` or `KAIROS_HOSTED=on` is in force. Closing them would
  make the tracker claim a fix the default configuration does not deliver.

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

- **The `/manage/link` abuse owner, measured.** A *verified creator* bypassed the
  Turnstile gate entirely (it never applies to them) and sent **200 nuisance mails
  to one victim across 20 requests**, with `KAIROS_RATE_LIMIT` at its shipped
  default of off. The ten polls can be planted for a victim address through
  `POST /api/polls` with no human check at all, by design. Fixed by a cooldown
  that **answers** — a visible "check your inbox" on the second request — so the
  recovery path never fails silently. Bounded to 10 mails per victim per hour.
- **A test fake that hid a real cross-form replay.** The Turnstile test double
  answered whatever `action` the route asked for, so a token minted for `/new`
  would have been accepted at `/manage/link` in tests while Cloudflare itself
  binds the action from the token. The binding was always sound; the fake now
  mints from the token so the test asserts the real property.

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
   `scoped` would break ETH's shared-poll model. Is `open` right? If yes, the
   cheap fix is a boot warning when the policy is `open` **and** the bind is not
   loopback — the default state currently logs nothing.
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