# Poll reach — who may read which poll

Issues [#63](https://github.com/gerchowl/kairos/issues/63) and
[#64](https://github.com/gerchowl/kairos/issues/64), one mechanism across two
surfaces. Implementation: `src/kairos/reach.py`.

## The gap

Two surfaces answered the same question about the same row differently, and the
weaker answer was the machine-facing one.

| | rule before |
|---|---|
| web UI, mutating routes (`web._owner_action`) | 403 unless `poll["creator_id"] == user["uid"]` |
| web UI, poll page (`web.view_poll`) | 200 for any signed-in user; participants table only for the owner |
| REST/MCP, `GET /polls/{poll_id}` | **no reach check at all** — `polls:read` and an id |
| REST/MCP, `GET /polls` | every poll on the instance, unscoped |

Measured consequences: a stranger got **200** with every respondent's **name** and
per-slot availability from `GET /api/polls/{id}`, and 200 from `/polls/{id}/event.ics`
(event time and title only). Respondent emails were not exposed and poll ids are
UUID4, so this needs id knowledge rather than enumeration — which is why severity
in the ETH header-mode deployment is low and why the hosted accountless product
needs it closed regardless.

Two different questions were being conflated. A **capability** (a scope, #51)
answers *what a caller may do*. **Reach** answers *which polls that is*. #51's
README said as much ("a scope is a capability, not a tenant") and the gap
underneath was still there: nothing in the data model attaches an identity to a
poll that two different API keys could tell apart.

## The model

One predicate, `reach.can_reach(poll, request)`, consulted by both surfaces,
under one of two policies (`KAIROS_POLL_REACH`):

| policy | web surface | API surface |
|---|---|---|
| `open` (default) | any signed-in user reaches any poll | any authenticated key reads any poll |
| `scoped` | the poll's manager (`can_manage`: creator/owner/`admin_token`) **or** an identity named on the poll (an invite addressed to it, or a response bound to its uid or address) | only the polls the key's `~<poll-id>` claim names |

**Why not a flat owner check.** ADR-0001/0002 forbid changing the self-host and
ETH behaviour, and in `KAIROS_AUTH=header` the authenticating proxy *is* the tenant
boundary — Kairos has no group membership of its own to scope reads with. Flat
owner-gating on `view_poll` would have broken the flagship deployment. Under
`scoped` the group keeps working: the owner, everyone invited to the poll, and
everyone who has already answered on it still open it. Only an unrelated identity
is refused. That is scoped visibility, not a binary.

**Why the default is `open`.** Every read that is legal today must stay legal in
the default configuration, and for a self-hoster that is the pre-existing rule.
`KAIROS_HOSTED` — the switch that already means "a deployment *we* operate", and
already gates outbound mail identity (M1/#48) — turns `scoped` on by default,
because the hosted accountless product is the multi-tenant case where `open` *is*
the IDOR. One knob, no second notion of "hosted" that could disagree with the
first, and the deployment where the defect is exploitable gets the fix without
anyone having to remember to set a flag.

## Configuring reach for keys

`KAIROS_API_KEYS` entries take an optional `~` clause:

```
KAIROS_API_KEYS="k1:polls:read,respond~*;k2:mail:send~<poll-uuid>+<poll-uuid>"
```

* `~*` — every poll on the instance. The **explicit** instance-wide grant #63 asked
  for, so a cron or an export can have one rather than being exempted from the rule.
* `~<poll-id>+<poll-id>` — exactly those polls.
* omitted — reaches no poll under `scoped`. Default-deny, the safe reading.

`+` rather than `,` inside the claim because `,` already separates scopes. The
clause is split off before the rest of an entry is parsed, so every keyring string
that was valid before reach existed parses through the identical code path.

`KAIROS_API_KEY` (the ETH/duplet adapter's `SCHEDULER_API_KEY`) is the one
instance-wide service grant, stated explicitly rather than by exemption, so
scoping a deployment cannot cost it the instance. `GET /api/whoami` reports what
the presenting key reaches, so an agent refused a poll can find out why in one
call instead of guessing.

`GET /polls` under `scoped` returns **only what the caller reaches**, and an empty
list — not a 403 — for a key granted no poll. The route is legal for that caller;
it simply has nothing in scope, and a 403 would tell a correctly-scoped agent that
its configuration is broken when it is exactly right.

## Enforcement, and what keeps it honest

* **API** — every route whose path names `{poll_id}` declares
  `api_scope(..., reach=True)`. On this surface reach is a pure function of the
  path id and the key's grant, so it is enforced in that declaration
  (`reach.guard_reach`), ahead of the handler, with no database read: under `open`
  it returns immediately (the default spends not one statement more than before),
  and under `scoped` a refused id is refused whether or not a poll with it exists.
* **Web** — the routes that already hold the poll ask in one line
  (`can_reach` / `require_reach`). The poll page hands the predicate the response
  and invite rows it fetched for the grid, so refusing a stranger costs no extra
  query, and the check sits before the only side effect on that path (marking
  notifications read).
* **The audit** — `tests/test_poll_reach.py` walks the live `/api` route table
  through #51's `_api_routes` (and its fixed, both-sides-anchored prefix filter)
  and fails if a route naming `{poll_id}` declares no reach. It is extended from
  "declares a scope" to "declares a reach" rather than standing up a parallel
  guard, and it is backed by driving every poll-id read with a key that has no
  reach — a declaration the handler ignored would pass the audit and still ship
  the IDOR.
* **REST and MCP agree** (ADR-0012) by construction: the MCP server is a thin HTTP
  client, and the parity harness is reused unchanged.

## Residuals, and what stays open for #32

1. **Per-account reach.** Reach attaches to a *key* here, not to an account,
   because accounts do not exist yet (#32). `creator_id` on an API-created poll is
   the literal string `"api"` for *every* key, so nothing downstream can infer
   "the key that made this poll" from the row. `can_reach` is the seam: it takes a
   poll and a caller and nothing else.
2. **A scoped key that creates a poll is not auto-granted reach over it.** It
   cannot be, for the reason above — auto-granting on create would hand every key
   every poll whose id it could guess. Until accounts exist, a scoped key that
   creates a poll must be granted reach to it in `KAIROS_API_KEYS`; the 403 names
   the poll and the knob. This is pinned as a test so #32 changes it deliberately.
3. **Per-plan reach** (#33): `scoping.Tier` resolves capabilities only. A tier may
   grow a reach field; no call site moves.
4. **In header mode, `scoped` is narrower than the proxy's own notion of the
   group.** A colleague who was neither the creator nor invited nor a respondent
   loses the page — correctly, under `scoped`, but it is why the ETH deployment
   should stay on `open` (its default) rather than assume `scoped` is free.
5. **What a permitted reader sees is unchanged.** Under `scoped` an invited
   colleague reads the same page they read before, including the availability grid
   with respondent names — the sharing rule the group is relying on. Narrowing
   *that* is a product decision about participation, not authorization.