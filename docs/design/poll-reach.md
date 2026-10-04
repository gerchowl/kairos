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

**Why `open` is nevertheless a deprecation.** The default keeps the compatibility
guarantee and nothing else: `open` is the pre-#63 rule, it still reproduces
#63/#64 exactly, and it is stated at boot as such. A deployment that configures
`KAIROS_API_KEYS` and gets a warning that its `~` claims are inert is being told
the truth about what it has. The migration is three configuration steps and no
code (README, "Poll reach"), so the default is a floor to stand on and a state to
leave, not an answer.

**Why an unrecognised `KAIROS_HOSTED` is `scoped`, against the mail gate's
reading.** `settings` resolves that knob as a recognised-true set
(`1/on/true/yes`); anything else leaves `HOSTED` False and sets
`HOSTED_UNKNOWN`, and the M1 mail gate reads that as *off* — correctly, because a
self-hoster's relay authenticates their own mail and unsetting the gate must not
break it. This module reads the same knob and deliberately does **not** inherit
that answer, because making HOSTED decide reach changed the cost of getting it
wrong:

| | misreading a typo costs | recoverable by |
|---|---|---|
| mail gate (M1) | a warning about DNS records nobody here can publish | fixing the spelling |
| reach | every respondent name on the instance | — |
| reach, other way | a deployment locked out of its own polls | `KAIROS_POLL_REACH=open` |

The first review of this PR measured `KAIROS_HOSTED=Y` selecting `open`: the one
spelling an operator actually types quietly chose the permissive policy on the
deployment that had just asked to be treated as hosted. An unknown value is
therefore read as "the operator meant hosted and misspelled it", gets the strict
policy, and is reported at WARNING with the way back — which is also the direction
whose mistake is cheap.

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

* **API** — every route whose path names a poll declares `api_scope(...,
  reach=True)`. On this surface reach is a pure function of the path id and the
  key's grant, so it is enforced in that declaration (`reach.guard_reach`), ahead
  of the handler, with no database read: under `open` it returns immediately (the
  default spends not one statement more than before), and under `scoped` a refused
  id is refused whether or not a poll with it exists.
* **Web** — the routes that already hold the poll ask in one line (`can_reach`).
  The poll page hands the predicate the response and invite rows it fetched for
  the grid, so refusing a stranger costs no extra query, and the check sits before
  the only side effect on that path (marking notifications read).
* **The poll id is found structurally.** `reach.poll_param` looks for the path
  parameter *after the `polls` segment* and reads that parameter's value, so a
  route that spells it `{pid}` is guarded and audited exactly like `{poll_id}`.
  The first review found the guard and the audit both matching the literal name,
  which is a fail-open with a green suite attached: a `{pid}` route skipped the
  check and was invisible to the audit at the same time. One function, asked of
  both.
* **A declared reach that cannot name its poll refuses.** `required_poll_id`
  raises rather than returning, so `reach=True` on a path with no poll id is a 500
  naming the route — not a silent pass. "I could not tell" and "you may read it"
  must never be the same answer.
* **What a refusal looks like differs by surface, on purpose.** The API surface
  answers 403 and never reads the poll, so "not yours" and "does not exist" are
  one code path by construction. The web surface must read the poll to apply the
  *named on this poll* half of the rule, so it could tell the two apart — and
  therefore answers 404 to both, with wording that names neither. That is why
  there is no `require_reach` beside `require_manage`: one helper raising one
  status while the route raised another *was* the oracle.
* **The audit, on both surfaces.** `tests/test_poll_reach.py` walks the live
  `/api` route table through #51's `_api_routes` (and its fixed, both-sides-
  anchored prefix filter) and fails if a route naming a poll declares no reach.
  It is extended from "declares a scope" to "declares a reach" rather than
  standing up a parallel guard. On the web surface there was no audit at all —
  only rate-limit bookkeeping — and the first review demonstrated the cost: a new
  unguarded `GET /polls/{poll_id}/rogue-export` answered 200 to an authenticated
  stranger under `scoped` with the suite green. There the audit reads what the
  routes *ask* (they authorize by calling, not by declaring), in three layers: the
  live route table, so a new poll-id route is unlisted and fails; the handler's own
  source, so a listed route cannot pass by not asking; and a real request as a
  stranger, so a route cannot pass by asking and ignoring. Each layer is driven on
  a synthetic app with the leaking request, because an audit that only proves it can
  notice has not proved anything.
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
   the poll and the knob. Pinned as a test so #32 changes it deliberately.

   The second review sharpened the shape of this residual. Under `scoped`,
   `POST /polls` returned an id the caller provably could not use — every later read
   and mutation 403, and the row is in nobody's `GET /polls` — which is the worst of
   both: auto-granting would be wrong, and silence makes the caller discover it
   later. Creation is *not* refused, because the deployment that should be creating
   polls with a bounded key would break; the response instead carries a
   `reach_warning` naming the poll, the knob and the grant that fixes it, at the
   moment the operator can still act on it. A `respond` key cannot hit this at all
   (`POST /polls` needs `polls:write`), so the two capabilities cannot disagree
   about creating; both facts are pinned.
3. **Per-plan reach** (#33): `scoping.Tier` resolves capabilities only. A tier may
   grow a reach field; no call site moves.
4. **In header mode, `scoped` is narrower than the proxy's own notion of the
   group.** A colleague who was neither the creator nor invited nor a respondent
   loses the page — correctly, under `scoped`, but it is why the ETH deployment
   should stay on `open` (its default) rather than assume `scoped` is free.

   The converse also holds and belongs next to it: in header mode with no
   `KAIROS_TRUSTED_PROXY_CIDRS`, `scoped` is *only* as strong as the headers.
   Anyone who can reach the port can assert `X-User: <a creator uid>` and reach
   that creator's polls. The boot log warns about exactly this combination.
5. **What a permitted reader sees is unchanged.** Under `scoped` an invited
   colleague reads the same page they read before, including the availability grid
   with respondent names — the sharing rule the group is relying on. Narrowing
   *that* is a product decision about participation, not authorization.