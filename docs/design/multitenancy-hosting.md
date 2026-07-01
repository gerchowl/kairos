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
2. `GET /manage/<admin_token>` → set `manage_verified_at` on first open → management UI.
3. **Anti-spam gate:** invite/send routes require `manage_verified_at IS NOT NULL`
   (accountless) **or** an account plan. So before Kairos emails any third party,
   the creator has passed **human (Turnstile)** + **verified-deliverable-email
   (opened the magic link)** — and it's their *own* address on the hook.

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
  ignored (the header user is already trusted), Turnstile off. **Byte-for-byte
  today's behavior.**
- All new columns are nullable/defaulted; `sched_accounts` is unused; the Turnstile
  + magic-link middleware is hosted-only and off by default.
- Same release artifact runs ETH (single-tenant, header-auth) and hosted
  (many capability-isolated polls, optional accounts) — the isolation model is a
  function of *deployment + auth mode*, never a branch.

## Build order (each independently shippable)

1. `admin_token` + `require_manage` predicate (unlocks accountless management; ETH
   unaffected since header mode short-circuits).
2. `KAIROS_AUTH=capability` + `/manage/<admin_token>` magic-link route.
3. Turnstile + `manage_verified_at` send-gate (hosted middleware).
4. `sched_accounts` + login + dashboard + claim (Pro).
5. Stripe billing.
