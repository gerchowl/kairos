# Multi-tenancy & hosting — design sketch

Turning Kairos into a hosted product **without forking the self-host/ETH path**.
Guiding rule: every change is **additive + nullable**, so `KAIROS_AUTH=header`
(ETH) and existing polls behave exactly as today.

## Principles

- **Accountless-by-default, capability-first.** A poll is reached only via its
  unguessable tokens; there is no way to enumerate other people's polls.
- **`owner_id` is optional.** `NULL` = a capability-only poll (accountless /
  self-host single-team). Non-null = owned by an account (hosted Pro/Team).
- **One shared instance, shared DB, logical isolation.** Physical isolation is
  the *self-host* story (an org runs its own container — the ETH pattern).
- **Never containers-per-poll / DB-per-tenant** until an enterprise deal demands
  it (then it's just a dedicated self-host).

## Schema (additive, nullable — migrated via `_ensure_column`)

`sched_polls` gains:

| Column | Type | Meaning |
|---|---|---|
| `owner_id` | `VARCHAR(36) NULL` | account id (hosted) or header uid (ETH); `NULL` = accountless |
| `admin_token` | `VARCHAR(64) NULL` | management capability (the magic link) |
| `creator_email` | `VARCHAR(255) NULL` | where the manage link was sent |
| `manage_verified_at` | `TIMESTAMP NULL` | set when the creator first opens the manage link — **gates sending** |

New table, **hosted-only** (unused by self-host/ETH):

```
sched_accounts(id PK, email UNIQUE, plan, stripe_customer_id, created_at)
```

Migration backfill: existing rows get `admin_token = new_token()`; in header mode
`owner_id = creator_id`. Nothing breaks — all new columns default/NULL.

## Auth modes (`KAIROS_AUTH`)

| Mode | Manage authority | `owner_id` on create |
|---|---|---|
| `header` (ETH / today) | header user == poll creator | header uid |
| `capability` (hosted, accountless) | valid `admin_token` (magic link) | `NULL` |
| `account` (hosted Pro/Team) | `session.account_id == poll.owner_id` | account id |
| `demo` / `none` | existing behavior | — |

## One management predicate (used by every management route)

```python
def can_manage(poll: dict, request: Request) -> bool:
    # header mode:     header-uid == poll["owner_id"] (or creator_id)
    # capability mode: admin_token (path/cookie) == poll["admin_token"]
    # account mode:    session.account_id == poll["owner_id"]
    ...

def require_manage(request, poll):  # raises 403 / redirects to request-a-new-link
    ...
```

Every mutating route (`add_slots`, `invite`, `decide`, `delete`, `imip-decision`,
`email-decision`) calls `require_manage`. No route trusts a bare poll id.

## Data access (scoping)

- `create_poll(..., owner_id=None, creator_email=None)` → also mints `admin_token`,
  returns the `manage_url`.
- `get_poll_by_admin_token(token)` — resolve for management.
- `list_polls(owner_id)` — dashboard listing; **accountless polls are never listed
  anywhere** (capability-only). No unscoped list endpoint exists.
- Enforce the owner filter in **one helper**, not ad-hoc in routes → no cross-tenant
  over-fetch bug surface.

## Accountless creation flow (Turnstile + magic link)

1. `POST /new` with a **Turnstile** token + `creator_email` → server verifies the
   token (Cloudflare siteverify) → creates the poll (`owner_id NULL`, `admin_token`
   minted, `manage_verified_at NULL`) → emails `/{P}/manage/<admin_token>`.
   *Shipped by #31 — see "Step 3 shipped (#31)" below: click-to-load facade, one
   `action` per form, and fail closed including on an unreachable verifier.*
2. `GET /manage/<admin_token>` → set `manage_verified_at` on first open → management UI.
3. **Anti-spam gate:** invite/send routes require `manage_verified_at IS NOT NULL`
   (accountless) **or** an account plan. So before Kairos emails any third party,
   the creator has passed **human (Turnstile)** + **verified-deliverable-email
   (opened the magic link)** — and it's their *own* address on the hook.
   *Shipped by #31 as the one predicate `capability.require_sendable`. A NULL column
   may not send — which is why the API-created poll, the shape with no human anywhere
   in its loop, can be created and then cannot mail.*

## Accounts layer (Pro/Team) — optional upgrade, not a requirement

- Login via email magic-link (or OAuth) → session → `account`.
- Dashboard = `list_polls(account.id)`.
- **Claim:** a logged-in user can attach an accountless poll they hold the
  `admin_token` for → sets `owner_id = account.id`.
- Billing: `sched_accounts.plan` + `stripe_customer_id`; Stripe webhooks flip plan.

## Isolation guarantees

- **No enumeration** without a token or an authenticated account.
- **Single scoping helper** (`list_polls(owner)` + `can_manage`) — the only places
  that decide visibility.
- `admin_token` / invite tokens are **bearer capabilities** (treat as secrets;
  consider optional expiry / rotation).
- Physical isolation for customers who need it = **self-host** (their own
  container + DB), which is already the ETH deployment shape.

## ETH / self-host convergence (why this doesn't fork)

- `header` mode: `owner_id = uid`, `admin_token` unused, `manage_verified_at`
  read but **never consulted** (the header user is already trusted), Turnstile off.
  **Byte-for-byte today's behavior** — asserted on the rendered creation template,
  with and without the gate's context key, as two strings.
- All new columns are nullable/defaulted; `sched_accounts` is unused; the Turnstile
  + magic-link machinery is hosted-only and off by default, and the send-gate is
  inert outside capability mode.
- Same release artifact runs ETH (single-tenant, header-auth) and hosted
  (many capability-isolated polls, optional accounts) — the isolation model is a
  function of *deployment + auth mode*, never a branch.

## Build order (each independently shippable)

1. `admin_token` + `require_manage` predicate (unlocks accountless management; ETH
   unaffected since header mode short-circuits). **Shipped (#29).**
2. `KAIROS_AUTH=capability` + `/manage/<admin_token>` magic-link route. **Shipped (#30).**
3. Turnstile + `manage_verified_at` send-gate. **Shipped (#31)** — see below.
4. `sched_accounts` + login + dashboard + claim (Pro).
5. Stripe billing.

## Step 1 shipped (#29) — three decisions the next two steps inherit

The schema and the predicate landed in #29. Three choices below were made there
and are settled; **#30 and #31 should build on them, not re-derive them.**

1. **`admin_token` is minted on create and never backfilled.** The backfill line
   above ("existing rows get `admin_token = new_token()`") was *not* implemented:
   a token minted at migration time is mailed to nobody and read by nobody, so it
   grants zero authority while permanently marking the row as capability-managed.
   `NULL` means "no management capability was ever minted" and `require_manage`
   treats it as matching nothing — so pre-#29 polls stay header-owned, exactly as
   before. #30: `get_poll_by_admin_token()` (still to be written) resolves only
   polls minted after #29, which is the correct answer, not a gap.
2. **The predicate is `require_manage(poll, request, *, token=None, user=None)`.**
   `token` is passed explicitly and never sniffed out of the request, because
   `public.py` already has `{token}` path parameters holding *public* tokens.
   `user` lets a route pass the identity it already resolved, so the documented
   `auth.get_user` runtime seam runs at most once per request; omit it and the
   predicate resolves the caller itself, which is what an anonymous capability
   route wants. #30 gates `/manage/<token>` with
   `require_manage(poll, request, token=token)` and no identity at all.
3. **`admin_token` is not in any API response.** `create_poll` returns it in
   process (it has to, to be able to build a manage link), and `api.py` strips it
   — plus `creator_email` — from everything it serializes. Otherwise the single
   bearer API key would become a permanent per-poll credential that survives key
   rotation. #30, if an agent should be able to manage an accountless poll it
   created, should return an explicit `manage_url` field rather than the token.

Still to come, unchanged from the plan above: #30's magic-link mail and
`/manage/<token>` route, #31's Turnstile verification and the `manage_verified_at`
send-gate. The column exists and is guaranteed NULL on every existing poll, so
that gate is closed by default the day #31 ships.

## Step 2 shipped (#30) — `KAIROS_AUTH=capability` + `/manage/<admin_token>`

The accountless creation + management flow, with no account and no proxy. What is
settled here, so #31 (Turnstile + the send-gate) and #32 (accounts + dashboard)
build on it rather than re-derive it:

0. **A review found one 500 and one dead guard; both are fixed and pinned.**
   `_fail`, the accountless refusal renderer in `web.create_poll_submit`, was
   declared `(heading, detail)` and called with one argument — so *every* invalid
   submission on the shared creation path (empty title, unknown timezone, no dates,
   time-slot without times) raised a TypeError in **all five modes**, including
   ETH. Capability mode's own refusals come from a different function, which is
   exactly why the new suite missed it. And `rotate_admin_token` was written
   `WHERE admin_token IS NOT NULL`, which cannot detect that the caller's token
   lost a race: the loser was told it had rotated and would have minted a session
   around a capability that had already been replaced. It is now a
   compare-and-swap (`WHERE admin_token = <the token presented>`), so two
   exchanges of one link produce one winner and one refusal — asserted directly on
   the data-layer function, on SQLite and on MariaDB.
1. **The emailed link is consumed, and the cookie is the credential from then on.**
   `GET /manage/<token>` only renders a confirmation — a GET that consumed the
   capability would be defeated by link prefetching (Outlook Safe Links,
   Proofpoint, every corporate URL scanner), which spends the creator's only
   credential before they click. `POST /manage/<token>` is the exchange: it
   authorizes with `require_manage(poll, request, token=…)` (no identity — the
   anonymous shape #29 documented), stamps `manage_verified_at` on first open,
   **rotates** `admin_token`, and 302s to `{P}/manage`, which carries no token.
2. **Lifetimes, stated rather than invented.** The link has **no clock** — it does
   not expire, exactly like `public_token` and invite tokens, which never have. It
   expires by *use*, and that is the only expiry on it; how long that is worth is
   a product decision (#33), not a default TTL to smuggle in. The session cookie
   is signed, `HttpOnly`, `SameSite=Lax`, scoped to `{P}/manage`, and bounded at
   `KAIROS_CAPABILITY_SESSION_HOURS` (default 12h — #53's owner-session lifetime
   for #53's reason: a working day, and a scheduling poll is a short-lived
   artefact). It carries the capability itself, so rotation retires older cookies
   instead of leaving parallel credentials nobody remembers to revoke.
3. **`creator_id` stays `NOT NULL`, and accountless polls get a per-poll
   unguessable placeholder** (`anon:` + 14 CSPRNG bytes = 33 chars, fits
   `VARCHAR(36)`). A migration was the alternative and was rejected: SQLite cannot
   alter a column's nullability at all, so it needs the twelve-step table rebuild
   inside `init_schema()` — on every boot, on the live poll table, with five child
   tables pointing at it and `PRAGMA foreign_keys = ON` per connection, where
   dropping the parent cascades to every response, slot, invite, contact-log and
   notification row. A data migration that can delete the poll is not worth paying
   for a field whose only remaining job is "was there an account?". MySQL 5.7
   makes it a blocking table copy. Three properties the placeholder must have, each
   closing a way a sentinel could leak: **unguessable** (a constant sentinel is a
   fail-open in `can_manage`'s `uid == creator_id` the moment anyone can present
   it), **unique per poll** (a shared one makes `list_polls(creator_id)` return
   every accountless poll in the deployment — the cross-tenant over-fetch ADR-0009
   exists to prevent), and **unmistakably not an identity**. `owner_id` remains the
   NULL accountless marker, which is where #29 said it lived.
   Verified on MariaDB 11.8 as well as SQLite: the column is still `NOT NULL`, the
   unique index holds, and all four new queries behave.
4. **The console is its own small surface; `auth.get_user` is untouched.** It
   returns `None` in this mode — there is no account, and giving it one would have
   to mean `uid == creator_id`, which would make the placeholder creator
   load-bearing for authorization. Every action goes through one route
   (`POST /manage/{poll_id}/{action>`) and one `require_manage` call, and the
   shared engines are reused rather than copied (`web.nudge_participants`,
   `web.decided_slot_of`, `web.expand_new_dates`, `charge_poll_recipients`), so
   the per-participant cooldown and the per-poll send budget hold across surfaces
   (ADR-0012's parity invariant) instead of being re-implemented here.
5. **Rotation needs a way back, so `POST /manage/link` exists.** It re-mails the
   current capability to an address that already created a poll here. It never says
   how many it sent, it is capped at 10 links per request, and it draws the `send`
   budget — the one every SMTP-opening route already shares. It is CSRF-bound like
   the creation form, and it filters *before* it caps: `[:10]`-then-filter meant a
   creator with ten recent polls and one older linkable poll got no mail at all,
   since every poll minted since #29 has a capability and the list is newest-first.
   **It is not an address oracle in the body, and it was one in the response time.**
   The page is identical apart from its per-render CSRF binding (a signed token
   carrying the second it was minted — a function of the clock, not of the address).
   The *timing* was not identical: a match opens one SMTP connection per poll and a
   miss opens none, which measured **87x** (0.254s vs 0.003s) against a real relay.
   That confirms which addresses have created a poll here, and the Subject line of
   the mail a real hit triggers then leaks the poll titles. The response is now held
   to a 0.3s floor (`LINK_REQUEST_FLOOR_SECONDS`). A floor is a mitigation and not a
   proof: it equalises the two cases only while the relay answers inside it, and the
   real answer — queue the mail, answer before SMTP — is a delivery change rather
   than a route change. **And it is a price, not only a fix**: a *miss* used to
   answer in 3ms and now occupies a worker thread for 0.3s, so the route converts a
   cheap refusal into a held thread. That is bounded by the constant rather than by
   the attacker, a matching address was already paying SMTP latency, and
   `KAIROS_RATE_LIMIT=on` — which boot already insists on for this mode — caps the
   rate; but an operator reading this should know a miss is no longer free.
   Recorded here because the previous version of this sentence said "byte-identical …
   (not an address oracle)" and was true of the body and false of the response, which
   is how the timing channel survived review.
6. **Outbound mail is a precondition, not a feature.** In this mode the link *is*
   the credential, so `is_configured()` is consulted before a poll is created and
   creation is **refused** (503, with the operator-facing reason) when mail cannot
   send. A row whose management link exists in no inbox and cannot be retrieved is
   the exact failure this flow exists to prevent. Every boot says so.
7. **No new rate-limit rule and no new dependency — but the existing budgets are
   charged *in the right unit*.** The token routes take `read`; the re-link request
   takes `send`, charged **per recipient it mails**, because one post can open up to
   10 SMTP connections and charging the request would make the operator's `send`
   limit ten times weaker on exactly that route; and `invite` / `send` are charged
   inside the action handlers, because one route carries several rules (a
   route-level dependency cannot see the action in the path) and ADR-0012's parity
   invariant is about the *limits*, not just the per-poll budget.
   `KAIROS_RATE_LIMIT` and its `KAIROS_RATE_LIMIT_<RULE>` vocabulary are unchanged,
   and an unconfigured deployment still has no limits at all (ADR-0001/0002) — which
   is why boot now says, out loud, that an unconfigured capability deployment lets
   anyone who can reach the app have mail sent from its domain. That warning, plus
   one for a missing `KAIROS_PUBLIC_URL` (a manage link's origin must not come from
   request headers), is the whole operational contract of this mode. A missing
   `SESSION_SECRET` used to be on that list and no longer is: it **refuses to
   boot**, under the mode gate, because the cookie it signs is the only credential
   the console has and the alternative was a green boot, a 200 from `GET /manage`
   (the no-session branch never touches the secret) and then a 500 on the two routes
   that mint or verify a cookie. A hard requirement is #53's pattern — an OIDC
   deployment with no owner allowlist also refuses — and the gate costs every other
   mode nothing.
8. **`KAIROS_AUTH` is now validated at boot.** A typo like `capabilty` resolves
   nobody in `get_user`, so every owner page 401s and the deployment looks like one
   where everybody is logged out — a control the operator believes is in force and
   is not. An unrecognised value refuses to boot, naming the variable and the
   known modes, like `_parse_networks`, `_parse_rate_limit`, `parse_keyring` and
   `_validate_config` already do. Every mode that existed before is still accepted.
9. **The anonymous creation route is bounded before it loops — and the bound is the
   *product*, not the step.** In `time_slot` mode the grid is built by `while t +
   timedelta(minutes=increment) <= t_end`, over an uncapped repeated `dates` field,
   on a request #30 made anonymous. Two rounds of review found two versions of the
   same defect here, and the second one is the more useful lesson:

   * **`increment=0` never advances `t`.** With no credential at all (the anon CSRF
     token is scraped off the public `/new` form), one such POST took a real uvicorn
     from 59 MB to 2.1 GB without answering, and anyio's 40-thread default meant ~40
     were enough to take the deployment down — `/health` still answering, so it read
     as a hang. A non-numeric `increment` was a `ValueError` → 500 on the same line,
     and so was any `start_time_all` / `end_time_all` that `strptime` could not
     parse. Fixed by bounding `increment` to `1..1440` and the clocks to `HH:MM`,
     before the loop.
   * **Bounding `increment` bounds *one date*.** The grid is
     `dates × (end - start) / increment`, `dates` is uncapped, and Starlette's
     `max_fields` ceiling caps *fields*, not slots. A 17 KB body with 992 dates and a
     one-minute increment is 1,427,488 slot dicts: measured at **+2.2 GB with sixteen
     concurrent requests** (truncated only by a 2.5 GB address-space cap on the test
     server; ~6 GB uncapped), **every one of them returning 400 "too large"
     afterwards**, `/health` answering 200 throughout. Bounding the step had moved the
     amplification one field to the left, not closed it.

   So `web._expand_time_slots` computes the product — `dates × per-date iterations`,
   with `per_date` being the loop's own arithmetic and `n_dates` counting the fields
   the loop actually visits — and asks `capability.slot_cap_refusal` **before** the
   first dict is appended. The check in `create_accountless_poll` remains as the
   second line of defence and the one that states the ceiling to a creator, but it can
   no longer be the thing that bounds anything, and its comment now says so. The
   lesson worth keeping: **a size check that runs after the work is not a bound on
   the work**, and neither is a bound on one factor of a product. `tracemalloc` in
   the test suite is what holds the placement — the same 400 comes back either way,
   so only the allocation distinguishes them.

   *(Exact for a forward window. For a reversed one the floor division of a negative
   timedelta is negative where the loop builds nothing, so the prediction sits below
   the output — checked across all 12.4M reversed combinations and never above it.
   That direction cannot over- or under-refuse anything dangerous: a reversed window
   is accepted, builds zero slots, and is answered "At least one date is required.")*
10. **The console's `edit` action is the same defect class, on the one surface of this
    issue that writes to shared state — so it is bounded by the same number.** Three
    reviews, three surfaces, one mistake each time: a `while` that could not
    terminate, then a product that was never multiplied out, and now this. The edit
    form is a single comma-separated `dates` text box, so `_parse_dates` splits it and
    **Starlette's `max_fields` never sees the dates at all** — one ~1 MB field is
    95,000 valid dates. Those dates then multiply by *the poll's own time grid*, which
    grows by up to a full edit's worth of slots every time anyone edits, so the second
    factor is attacker-influenced over time even when it starts small.

    Measured with only the credential the app itself mails (create → read the link →
    exchange it for the console cookie), a 215 KB body of 20,000 dates against a
    125-pair poll is 2,500,000 slots: **+1.8 GB in 20.7 s and 2,470,375 rows written
    to the database**, status 302, no refusal on the path at all. The first two
    versions of this bug cost one request's memory; this one costs the deployment a
    poll that every later page view has to read.

    Two bounds, one number, and they are complementary rather than redundant:
    `capability._parse_dates` refuses **inside its own loop** once the parsed list
    would pass the ceiling — bounding the *input*, before 95,000 dates exist — and
    `web.expand_new_dates(poll, dates, cap=…)` refuses the **product** before the
    comprehension, which is what catches the slow axis, where a creator adds eight
    dates to a poll whose grid has grown to a thousand pairs. `expand_new_dates` takes
    the ceiling as a parameter rather than testing the mode itself, so the owner's
    edit form and the API's slots endpoint keep exactly the behaviour they had —
    a mode check inside that shared helper would have silently capped two surfaces
    this branch does not own, one of which (#51/#63/#64) has the same unbounded
    `dates × grid` product and should be given a ceiling of its own.
10. **A capability in a URL is in the access log, and that is an operator's
    problem.** `GET /manage/<token>` puts the live token in whatever the front end
    writes down — `INFO: 127.0.0.1:48348 - "GET /manage/6YBiM6… HTTP/1.1" 200 OK`
    is the real shape of it. Kairos never writes a capability to its own logs (no log
    line in `capability.py` carries one, asserted, and no creator address either), but
    the access log belongs to uvicorn or the reverse proxy. For a link nobody ever
    opens, the token is valid forever *and* sits in the log forever. What exists:
    single use (the token dies the moment it is exchanged), `Referrer-Policy:
    no-referrer` on the one page whose URL carries it, and no creator address in any
    log line. What an operator should do: keep request lines for `{prefix}/manage/`
    short-lived, or redact that path.
11. **`KAIROS_PUBLIC_URL` unset is a phishing risk, not a cosmetic one.** With
    `KAIROS_TRUSTED_PROXY_CIDRS` set only a trusted peer reaches the app, so the
    origin cannot be dictated — which is why this one warns instead of refusing. But
    a deployment without that allowlist derives the origin from caller-supplied
    headers, and `POST /new` with `Host: evil.example` mails, **from the operator's
    own sender and branding**, a *"Your manage link: Quarterly planning"* URL of
    `https://evil.example/scheduler/manage/<token>`. The link works on the attacker's
    host, the creator clicks it from a message that looks like it came from Kairos,
    and the credential is entered on a page the attacker serves. In every other mode
    a wrong origin means a broken link; here it means a working phishing page with
    your domain on it. `KAIROS_PUBLIC_URL` is the fix and this mode is the reason it
    exists.
12. **There is no logout route.** A shared browser ends its capability session by
    expiry or by opening a fresh link, not by a button. Deliberate for this step — a
    logout that cannot also retire the emailed link would be a half-measure that
    reads like a control — and worth revisiting with #32's accounts, where a session
    and its revocation can be the same object.

Deliberately **not** in this step: accounts / dashboard / claim (#32 — which is also
where a creator's several accountless polls stop being one-session-at-a-time), a
`manage_url` field on `POST /api/polls` (two lines in `api.py`, deferred while
#63/#64 are in it; `POST /manage/link` already reaches an API-created poll by its
`creator_email`), any expiry on the link, and the token-lifetime product question.
The `manage_verified_at` **send-gate** and Turnstile are #31's and ship below.

## Step 1.5 shipped (#63/#64) — reach, the question above management

`can_manage` (step 1) answers *may this caller manage this poll*. It never
answered *may this caller read this poll*, and the two surfaces answered the
second question differently: the web UI's mutating routes demanded the owner while
`GET /api/polls/{id}` and `GET /api/polls` handed a `polls:read` key the whole
instance. That is now one predicate, `reach.can_reach`, on both surfaces, under a
policy: `open` (default, byte-for-byte what header mode and self-host get) or
`scoped` (per poll: the owner or a participant in the UI; only the granted poll
ids on the API). Full rationale in `docs/design/poll-reach.md`.

Two statements above are now narrower than the code, and #32/#33 should read them
through this section rather than re-derive them:

1. **"Single scoping helper (`list_polls(owner)` + `can_manage`) — the only places
   that decide visibility" is no longer complete.** Reach is a third one, and it is
   the one that guards *reads*. Reach implies management authority (a manager
   always reaches) but not the reverse: an invited participant reaches a poll and
   manages nothing. `list_polls(owner)` is still the dashboard's scoping helper;
   `GET /api/polls` is scoped by `reach.only_reachable`.
2. **"No enumeration without a token or an authenticated account" holds for the
   hosted deployment only because `KAIROS_HOSTED=on` implies `scoped`.** Under the
   default `open` policy an authenticated key (or any signed-in user in header
   mode) does enumerate by `GET /api/polls` — which is the single-team model
   ADR-0001/0002 require, and why `open` cannot be the hosted default. It is a
   *deprecation* rather than a permanent answer: the boot log says at WARNING
   whenever scoped keys exist under `open` (their `~` claims are inert), and an
   unrecognised `KAIROS_HOSTED` reads as `scoped` rather than quietly selecting
   `open`, because a typo in that knob used to do exactly that. Issues #63/#64 are
   therefore closed by `scoped`, not by this default — see the closure note in the
   PR.
3. **The hosted deployment's reach also depends on how identity is asserted.** In
   `KAIROS_AUTH=header` mode with no `KAIROS_TRUSTED_PROXY_CIDRS`, `scoped` is
   exactly as strong as a header anyone can assert, and #31's Turnstile work is
   about the *anonymous* surface. The boot log warns about the combination; the
   hosted deployment runs OIDC, where the IdP is the identity.

## Step 3 shipped (#31) — Turnstile, and the `manage_verified_at` send-gate

Two gates on the anonymous surface, and the decisions behind them that #32/#33
should build on rather than re-derive.

### A1 — the human check

`kairos.turnstile`, consulted by `POST {prefix}/new` and by `POST {prefix}/manage/link`.

1. **It is not middleware, because the position is the whole point.** Each route
   calls `verify()` directly: after the CSRF token (local, and a drive-by should not
   cost an outbound request) and before the slot expansion, any row write and any
   SMTP connection. A middleware runs either side of both or neither. The test suite
   pins it by call order *and* by a `tracemalloc` ceiling, because a check that ran
   after the expansion would return the same 400 and allocate the same 2 GB.
2. **The browser's `success` is a claim.** `verify()` posts the token to
   `siteverify` with the *secret* and accepts only `success: true` plus a matching
   `action` and, where configured, a matching `hostname`. `action` is one value per
   gated form, so a token solved on the creation form cannot be replayed at the
   re-link form — the same reason #30 gave the two anonymous forms separate CSRF
   uids. Cloudflare's single-use tokens mean Kairos keeps no replay store of its own.
3. **Fail closed, including on "I could not check".** Unreachable, 500 and
   unparseable are refusals, one request each, no retry. The judgement: a gate whose
   availability a third party controls is not a gate, and every "I could not check"
   path here is reachable only by whoever can break our egress to Cloudflare. The
   cost of the alternative reading is one env var away, is in a boot warning, and
   produces an ERROR per attempt — the cost of this one is the feature.
4. **The config fails in the strict direction and out loud.** `KAIROS_TURNSTILE` is
   `off`/`on`; unset means `on` when `KAIROS_HOSTED` is on (the switch that already
   means "a deployment *we* operate") and `off` otherwise. An **unrecognised value
   reads as `on`**, following #67's `reach.policy()` after it measured
   `KAIROS_HOSTED=enabled` selecting the permissive reach policy on the deployment
   that had just asked to be hosted; here the same shape would silently remove the
   gate from the one deployment whose anonymous path sends mail from our domain. A
   deployment that turns the gate on **without both keys refuses to boot**, the
   `SESSION_SECRET` gate's shape for the same reason. Every boot logs whether the
   check is in force.
5. **Click-to-load, and no flag.** Nothing from Cloudflare is fetched until the
   person presses a button. That is what keeps obligation **P1** true — "no
   third-party cookies, therefore no consent banner" — in the configuration that
   actually ships, and `/privacy` discloses it either way (**P4**). There is
   deliberately **no** setting to load the widget eagerly, because the only other
   state is one where our own privacy page is false; a flag that selects between
   "true" and "false" is a flag that will be flipped. The price is one extra click
   on two forms. The widget is also *not rendered* on a page where the server would
   waive it (a verified creator's console), so a control the server ignores never
   spends a third-party request. *An earlier version of `static/turnstile.js`
   created the widget's `<script>` during `init()` and therefore fetched Cloudflare
   on every page view — the exact thing the facade exists to prevent. Found by
   driving the real page in a browser, not by reading it; `node --check` is now a
   pre-commit hook on `src/kairos/static/*.js`, which had no other gate.*
6. **`action` is required, including its absence — and Cloudflare's public
   *testing* keys therefore cannot be used.** Measured against the live endpoint:
   the documented test secret `1x…AA` answers `success: true` for **any** response
   string and returns no `action`. A deployment configured with one is
   simultaneously ungated (every token verifies) and refusing every submission
   ("Human check could not be confirmed"), which is a state no operator would guess.
   So a verifier that reports no action is a 503 refusal rather than a pass, and
   `identity_report`/`boot_warnings` name the test keys by value. Requiring the
   action is what stops one solved token crossing between the two gated forms, and
   "it did not say which form" is the same answer as "the other form": we cannot
   prove it.

### A2 — the send-gate

`capability.require_sendable(poll)`: **NULL `manage_verified_at` means the poll may
not send.**

7. **Absent is NULL.** The column is read with `.get()`, so a poll dict that
   predates it — or a stub in a test — is refused. A gate whose *missing* input reads
   as "allowed" is the same defect `can_manage` warns about for the sibling
   predicate, and it is the shape #29's review actually caught once.
8. **It ships closed.** #29 added the column with no backfill, so every pre-existing
   row is NULL and none has ever read as verified. That is why no migration risk
   needed solving here.
9. **One predicate, consulted ahead of the work.** `web.nudge_participants` is the
   single chokepoint for all five reminder paths on all three surfaces, so the gate
   is its first statement — before `charge_poll_recipients`, because a request that
   is about to be refused must not spend the poll's whole mail allowance first. The
   four decision/invite senders (`api.invite`, `api.email-decision`,
   `api.imip-decision`, `web.email_decision`) and the two console actions call it
   themselves. A spy-guard test asserts each route *reaches* it, in #29's S6 shape.
10. **The creation mail and `POST /manage/link` are deliberately not gated.** Both
   mail the creator's own address, and together they are how a creator becomes
   verifiable — gating them would close the hole by deleting the feature. A2 is about
   mail to *third parties*.
11. **It is inert outside capability mode**, and that is the compatibility argument
    rather than a gap: in `header`/`oidc` mode the creator is identified by the proxy
    or the IdP, there is no address to verify, the column is dead, and ADR-0001/0002
    require those deployments to keep behaving exactly as they do.
12. **What "verified" is not.** A manage link we mailed was opened — no SPF/DKIM
    `Received` chain is inspected, so a forwarded address satisfies it; and the
    column is never cleared, so verification is permanent for the life of the poll.

### The gap #68 named: `POST /manage/link` had no abuse owner

13. **It is gated by the same check.** With shipped defaults a third party could
    post a victim's address — the CSRF token is on every `/manage` page and scrapable
    in one request, and `KAIROS_RATE_LIMIT` defaults off — and have the deployment
    mail that victim up to ten manage links per post, from the operator's own sender
    and domain, for free. It cannot *take* a poll (the link goes to the address that
    owns it) and it learns nothing (the answer is identical either way), so what it
    buys an attacker is a nuisance: our mail reputation and a spam-complaint rate.
    Turnstile is the answer for the reason it is the answer on `/new`: the per-peer
    budget measured at a 1.11× effect elsewhere in this repo, and eviction by address
    rotation is not the axis that matters — the axis is one attacker aiming many
    requests at *one* victim.
14. **A per-address cooldown ships, and it answers.** It was rejected in the first
    review round and that rejection was **half right**: it is the control that
    actually matches the threat, and the objection to it — that it fails *silently* —
    is correct. A creator with ten polls asking twice in a day would be mailed
    nothing, and because the body may not differ from a miss, they would be told
    nothing either. On a recovery path that is indistinguishable from a broken
    deployment. So the conclusion was wrong and the reasoning was the fix: the
    cooldown now returns **its own visible answer** ("you already asked for a link
    for this address in the last hour… check your inbox"), which preserves the
    anti-timing property, never fails invisibly on a real creator's recovery path,
    and still stops the 200-mail case. `LINK_REQUEST_COOLDOWN_SECONDS` is an hour.

    Two design points make that answer safe to give:

    * **It is recorded on every named request, hit or miss.** Recording only on send
      would turn two requests into a membership test for "does this person poll
      here" — a strictly worse leak than the one #30's identical answer exists to
      prevent. Recorded unconditionally, the second ask reads the same either way,
      so the oracle property survives the control added to protect it. The cost is
      that the message cannot claim a link *was* sent (for a miss none was), so it
      says a request was handled and tells the reader to check their inbox — a
      message claiming "already sent" would be false to a creator who mistyped.
    * **It is checked after the human check, and applies to verified creators.**
      Before the check, "post the victim's address and fail Turnstile" would lock a
      real creator out of their own recovery path for an hour, needing no solve and
      no account — the cheapest denial of service on the surface. After the check,
      only a request allowed to send at all can consume the window.

15. **A verified creator is exempt from the check** (`session_verifies_creator`, read
    off the live capability cookie). They are already proof-of-human for this
    deployment and the recovery path is where a stressed person is. Note what it does
    *not* allow: the exemption cannot be obtained without having received a manage
    mail, so a first-time attacker still faces the check.

    **What it does allow is the case item 14 exists for.** Measured, before the
    cooldown: a verified creator posting a victim's address produced

    | posts | siteverify solves | nuisance mails at the victim |
    |---|---|---|
    | 1 | 0 | 10 |
    | 5 | 0 | 50 |
    | 20 | 0 | 200 |

    Zero solves, because the gate that would have charged one per request is exactly
    the gate a verified creator skips — so the cooldown is placed *after* the
    exemption, not behind it, and covers everyone. **The residual, stated where the
    rest of this file's residual risk lives: the fan-out is
    `MAX_LINKS_PER_REQUEST` (10) mails per request, so the bound is 10 nuisance mails
    per victim address per hour, not one** — and the ten polls that make it 10 can be
    planted for a victim address through `POST /api/polls` with no human check at all,
    by design (agent-first, ADR-0010), so an attacker's real cost is one solve per ten
    mails at one inbox. That multiplier is the honest shape of what is left, and it is
    why the next thing worth building is a two-step confirmation on this route rather
    than a stricter gate on the requester.

### Still not established

A1 and A2 are ceilings and preconditions, not limiters: what bounds how much mail one
verified creator sends afterwards is `KAIROS_RATE_LIMIT=on` plus the per-key budgets
(A3/A4), and boot says so in those terms rather than letting a green line imply a
closed door. A two-step confirmation on `/manage/link` (mail a *confirmation*, not the
capability) would be strictly stronger against the nuisance case than any check on the
requester, and is deliberately not built here: it changes that route's contract, which
#68 owns. M1's DNS half is still the operator's and still unpublished.

What #32 inherits, unchanged and pinned as tests in `tests/test_poll_reach.py`:

* **Reach attaches to a key, not to an account, because there is no account to
  attach it to.** `creator_id` on an API-created poll is the literal string
  `"api"` for *every* key, so no downstream code can infer "the key that made this
  poll" from the row. Per-account reach is one rule inside `can_reach` once
  `session.account_id` exists — the same place `can_manage` already has a
  `session.account_id == poll.owner_id` branch.
* **A key that creates a poll is not auto-granted reach over it**, for the same
  reason; auto-granting on create would hand every key every poll whose id it could
  guess. With accounts it becomes "the creating principal's reach includes what it
  created", which is a one-line change plus the provisioning story. Until then the
  creation response carries a `reach_warning` naming the grant the key needs, so a
  caller is never handed a poll id it cannot use without being told.
* **`KAIROS_API_KEY` is the explicit instance-wide grant** rather than an exemption
  from the scoped policy, so a deployment that tightens reach cannot lose its own
  service credential. #33's per-plan reach slots into the same field.
* **An invited or responding participant reaches the poll on the web surface.**
  That is deliberate, not an oversight: it is what lets a group deployment share a
  poll without making it public, and it is the same rule `public.py` already uses
  to bind a response to a signed-in respondent (`user_id`). A hosted product that
  wants participant-visibility narrowed is making a product decision about
  participation, not an authorization one.
