# Kairos

[![CI](https://github.com/gerchowl/kairos/actions/workflows/ci.yml/badge.svg)](https://github.com/gerchowl/kairos/actions/workflows/ci.yml)

**[Website](https://gerchowl.github.io/kairos/)** · **[▶ Try it in your browser](https://gerchowl.github.io/kairos/playground/)** — the actual Python server on Pyodide/WASM, nothing leaves your machine.

when2meet-style scheduling polls — self-hostable, reverse-proxy-auth friendly,
**agent-first API** (OpenAPI + llms.txt + MCP).

## Quickstart

```sh
uvx --from kairos-scheduler kairos          # SQLite + demo auth on :8003
```

or with Docker / a real database:

```sh
KAIROS_DB_URL=mysql://user:pass@host:3306/db \
KAIROS_AUTH=header SESSION_SECRET=$(openssl rand -hex 32) \
uvx --from 'kairos-scheduler[mysql]' kairos --host 0.0.0.0
```

## Container

`Dockerfile` + `compose.yaml` in this repo — SQLite on a named volume, non-root,
no build toolchain in the runtime layer.

```sh
podman compose up -d                  # build, run, http://127.0.0.1:8003/
podman compose logs -f kairos
```

The database is on the volume, so `down` and `up` keep every poll (`down -v`
deletes them). It publishes on **loopback only** and runs in demo auth, which
means one shared owner and no authentication — fine locally, never on a public
interface.

Real deployments add a TLS terminator and either Kairos-managed OIDC or an OIDC
proxy in front:

```sh
cp .env.example .env && $EDITOR .env   # secrets; compose refuses to start without them
podman compose -f compose.oidc.yaml up -d     # Kairos is the OIDC client (no auth proxy)
podman compose -f compose.proxy.yaml up -d    # oauth2-proxy in front, Kairos reads headers
```

MariaDB instead of SQLite, on the same image:
`podman compose -f compose.yaml -f compose.mysql.yaml up -d`.

**Read [`docs/design/self-host-hardening.md`](docs/design/self-host-hardening.md)
before exposing this to anyone** — TLS, the trusted-proxy allowlist, backups,
and the choices this image deliberately leaves to you (base image, registry,
retention).

## Features

- Full-day or time-slot polls, when2meet drag grids, heatmaps
- Public share links + personal email invites (required/optional participants)
- Convergence light: collecting → ready / partial / blocked
- Idempotent smart reminders + per-participant contact audit trail
- Decide a final date → .ics download + "email everyone" with the file attached
- Light/dark colorblind-friendly theme ([Dalton](https://github.com/gerchowl/dalton-colorscheme))
- Agents: REST API (Bearer), `/llms.txt`, OpenAPI, Swagger UI, MCP server
- **Reverse-calendar (optional):** push candidate slots *into* the respondent's
  calendar instead of reading their free/busy — subscribe-able feeds + native
  iMIP Accept/Maybe/Decline. Off by default (see below).

## Reverse the calendar (iMIP) — optional

Instead of asking for calendar access, Kairos can push the candidate slots **into
the respondent's calendar** and let them Accept/Maybe/Decline — capturing what's
*truly* blocking, not mechanical free/busy. Two layers, both opt-in:

- **Candidate feed** (`KAIROS_FEED=on`) — a subscribe-able, disposable `.ics`
  calendar of the poll's slots. The per-invite feed
  (`/p/i/<token>/feed.ics`) embeds deep-link Accept/Maybe/Decline URLs; tapping
  one records that slot and lands on the poll page (the instant surface —
  subscribed feeds refresh slowly, Google ~daily, so never rely on the calendar
  reflecting a vote quickly).
- **Native iMIP invitations** (`KAIROS_IMIP=on`) — real `METHOD:REQUEST`
  invites with Accept/Maybe/Decline buttons. `KAIROS_IMIP_ORGANIZER` is the
  mailbox replies route to; it **must equal** the IMAP mailbox Kairos polls
  (`KAIROS_IMAP_HOST/PORT/USER/PASSWORD/MAILBOX`). Schedule `POST /api/imip/poll`
  (cron / systemd timer, Bearer auth) to ingest replies; `POST
  /api/polls/{id}/imip-decision` sends the decided slot as a native invite.

**Cross-client reality (verified live):** Outlook and Apple render **native**
Accept/Maybe/Decline; **Gmail does not** for a Gmail-organized event (Google
policy) — the deep-link Accept/Maybe/Decline in the event description covers it,
so every client gets one-click RSVP. For native Gmail RSVP, use a non-Gmail
(custom-domain) organizer.

**Agent-native (no API key):** the invite link self-describes —
`GET /p/i/<token>/agent.json` returns the options, your current vote, and the
one-click vote URLs (also `feed.ics`, and `/s/<slot>/<yes|maybe|no>` to vote).
Hand your assistant the link and it RSVPs for you. See `/llms.txt`.

See `docs/design/reverse-calendar-imip.md` and issue #23 for the full design.

## Deployment model

Kairos supports three families of owner identity, and they are **layers, not
alternatives** — pick the owner one, and the capability one applies regardless.

Respondents never need accounts in any of them: share links and invite tokens are
self-contained.

| Owner auth | Wiring | Use it when |
|---|---|---|
| `demo` (default) | zero | local trial; one shared owner, no identity check |
| `oidc` | **~4 env vars** | **anything real.** Kairos terminates OIDC itself; no auth proxy |
| `header` | an infrastructure project | you already run Shibboleth, OpenAthens, oauth2-proxy, Authelia, Cloudflare Access or Tailscale |
| `none` | zero | public/respondent-only; the management UI is disabled |

The `oidc` mode is the primary multi-user self-host path because it is the only
one that is both multi-user and cheap — nginx cannot terminate OIDC, which is
why `oauth2-proxy` and Authelia exist as separate boxes. See
**[docs/design/oidc-login.md](docs/design/oidc-login.md)** for the whole picture.
`header` mode is unchanged and still the right answer inside an institution that
already has a broker; see `compose.proxy.yaml` for that wiring.

```sh
KAIROS_AUTH=oidc \
KAIROS_OIDC_ISSUER=https://id.example.org/realms/main \
KAIROS_OIDC_CLIENT_ID=kairos KAIROS_OIDC_CLIENT_SECRET=… \
KAIROS_OIDC_ALLOWED_SUBJECTS=<sub-from-your-IdP> \
SESSION_SECRET=$(openssl rand -hex 32) \
uvx --from kairos-scheduler kairos --host 0.0.0.0
```

`KAIROS_OIDC_ALLOWED_SUBJECTS` is **required** — an empty allowlist refuses to
boot, because Kairos will not admit "anyone the IdP vouched for". A successful
exchange is necessary and not sufficient; the identity has to resolve to a known
subject, and the allowlist is re-checked on every request, so removing a subject
signs that person out immediately. The pattern is the ETH deployment's own
directory check. (An email-domain allowlist is available and coarser; see the
guide.)

> **Before exposing a hosted instance in `header` mode, set `KAIROS_TRUSTED_PROXY_CIDRS`.**
> Header mode trusts whoever sets the identity headers, so anything that can reach the
> app port directly can assert any identity — including becoming any poll owner.
> Set it to the proxy's address(es), e.g. `KAIROS_TRUSTED_PROXY_CIDRS=10.0.0.0/8,127.0.0.1`.
> Requests from any other peer are refused with 403 and logged. Unset means *trust
> everyone*, which is only safe while the port is unreachable except through your
> proxy. The check uses the real transport peer, never `X-Forwarded-For`; if you
> run uvicorn yourself rather than via the `kairos` entrypoint, pass
> `proxy_headers=False` so it does not rewrite that address before Kairos sees it.
> In `oidc` mode the CIDR list still gates that edge, but it is no longer the
> identity boundary — the subject allowlist is. Every boot logs which is in force.

**Before exposing a hosted instance, set `KAIROS_RATE_LIMIT=on`** (and
`KAIROS_TRUSTED_PROXY_CIDRS`, which it depends on), and consider handing out
[scoped API keys](#api-keys-scopes-and-mail-budgets) rather than the single
all-power one. See
[Rate limiting](#rate-limiting-optional) below — the public token routes let
anyone with a link create rows, and the owner routes can fan out mail to every
address on a poll's participants table.
**Outbound mail (operators):** `SMTP_FROM` is the address every message is sent from,
and the poll owner appears only as the display name and in `Reply-To` — a poll owner's
own address cannot be authenticated from your domain. **Self-hosting? Stop here:**
point `SMTP_FROM` at your own mailbox, leave `KAIROS_HOSTED` unset, and nothing else
changes. Set `KAIROS_HOSTED=1` only when *you* send from *your* domain and therefore
own its reputation — then `KAIROS_FROM_DOMAIN` is required, and Kairos refuses to send
(rather than sending unauthenticated or from a personal mailbox) unless `SMTP_FROM`
and `KAIROS_IMIP_ORGANIZER` are mailboxes on it. SPF/DKIM/DMARC are DNS records Kairos
cannot publish or read, so it cannot confirm they exist — every boot logs the identity
it is about to send as. **[`docs/design/mail-auth.md`](docs/design/mail-auth.md) has the
exact records, the staged `p=none` → `quarantine` → `reject` plan, and how to verify
them.**

> **Cookie note for operators:** Kairos sets only strictly-necessary cookies (session, signed response-edit token, theme preference) — disclosed on `/privacy`, no consent banner required (ePrivacy Art. 5(3) / Swiss TCA 45c exemptions). If you add analytics or any third-party embeds to your deployment, that changes — you'll need consent management.

## Rate limiting (optional)

Off unless you switch it on, so self-host and the ETH/duplet deployment behave
exactly as before. `KAIROS_RATE_LIMIT=on` puts a budget on the abuse-sensitive
surface:

| Rule | Applies to | Ships at |
|---|---|---|
| `read` | token pages, `agent.json`, feeds, `.ics` | 120/min |
| `respond` | `POST /p/<token>`, `POST /p/i/<token>` | 20/min |
| `deeplink_vote` | `GET …/s/<slot>/<yes\|maybe\|no>` — one per poll slot | 300/min |
| `create` | `POST /new` | 10/min |
| `invite` | `POST /p/<id>/invite` | 30/min |
| `send` | `remind`, `remind-selected`, `email-decision` — actual SMTP | 10/hour |
| `login` | `GET …/oidc/start`, `GET …/oidc/callback` — unauthenticated, one outbound call each | 30/min |
| `api` | every authenticated `/api` call, charged to the **bearer key** | 600/min |
| `api_write` | mutating `/api` routes | 60/min |
| `mail` | `/api` routes that can send mail | 20/hour |
| `mail_force` | `/api/.../nudge` with `force=true` — see [scoped API keys](#api-keys-scopes-and-mail-budgets) | 5/hour |

The first six are charged to the caller's **transport address**; the last four to
the **bearer key**, which an API client cannot vary — see the scoped-key section
below for why that is the same limiter rather than a second one.

Override any of them with `KAIROS_RATE_LIMIT_<RULE>="<count>/<window>"`
(`second`/`minute`/`hour`/`day`), e.g. `KAIROS_RATE_LIMIT_SEND="30/hour"`. `0`
switches that one rule off. An unparseable value — or a rule name that does not
exist — **refuses to boot** rather than silently running unlimited.

`deeplink_vote` is sized against what the UI offers: `agent.json` gives an agent
one vote URL per slot, 15 minutes is the smallest increment offered, and the
default window is 09:00–17:00, so a **full week of 15-minute slots is 224 slots
= 224 requests**, which fits in one 60s window. That is a realistic worst case,
**not a maximum** — the date picker is an infinite-scroll calendar with no span
cap. A poll larger than the budget needs either a raised
`KAIROS_RATE_LIMIT_DEEPLINK_VOTE` or a sweep spread over more than one window.

### Behind a reverse proxy: set `KAIROS_TRUSTED_PROXY_CIDRS` too

Budgets are charged to the **real transport peer**, never `X-Forwarded-For`:
that header is caller-supplied, so a budget keyed on it would be one the caller
sets for themselves.

But behind a proxy the peer is *the proxy's* socket address for every request —
so if you front Kairos with a reverse proxy and have **not** set
`KAIROS_TRUSTED_PROXY_CIDRS`, the whole deployment shares **one** budget, and
`create` 10/min becomes the entire instance's allowance. Set it (you should
anyway — see above), and Kairos then charges each request to the nearest hop in
the forwarded chain that is *not* one of your proxies, which is the real client.

That resolution walks the chain **right to left**, skipping addresses inside the
allowlist. It has to: `X-Forwarded-For` is built by appending, so a caller's own
contribution is always at the left and the entry appended by your nearest proxy —
about a socket it actually held — is always reached first. A caller rotating the
left-hand value gets nowhere.

It also makes `proxy_headers=False` load-bearing: if you launch uvicorn yourself
rather than via the `kairos` entrypoint, pass it, or uvicorn rewrites the peer
from that header before Kairos sees it and the whole mechanism collapses. Kairos
logs a warning at startup when limits are on.

Over-budget requests get a `429` with a `Retry-After`, as an HTML page in a
browser and as JSON otherwise.

> **One instance, one counter set.** The counters live in the serving process, so
> **N app instances means an attacker gets N × the budget.** That is the one limit
> to know about before scaling out; #36 chose SQLite on the same reasoning (its
> operational ceiling is a single writer). Move the counters to a shared store
> before running more than one instance.

> **What this does not stop: address rotation.** A budget keyed on an address is
> evaded by never reusing one, and an attacker with an IPv6 /64 has ~2^64 of
> them. What the cap *does* bound is the ceiling on memory and CPU regardless of
> how many addresses arrive. Beating deliberate rotation needs an identity the
> client cannot vary — a cookie, or an API key — which is the bearer key #51
> already introduces.

## API keys: scopes and mail budgets

<!-- #51 scoping. Self-contained section: append-only, so it rebases cleanly. -->

`KAIROS_API_KEY` is a **single all-power key**: one bearer credential that reaches
every poll, every route, and every third party's inbox. That is fine for a
self-hoster with one agent, and it is what the ETH/duplet adapter sets, so it
stays exactly as it is. It is *not* fine for a key that ends up in an agent's
environment, gets pasted into a dotfile, and sends mail from your domain.

So there is a second, opt-in way to hand out keys:

```bash
KAIROS_API_KEYS="k1:polls:read,respond;k2:mail:send;k3:mail:force"
```

* `;` separates keys, `,` separates the scopes of one key.
* An entry is `<key>:<scopes>` or `<key>@<tier>` — never both, never neither. A
  bare key is **refused**, because that is the one typo that would silently mean
  full power; `KAIROS_API_KEY` is the only way to ask for that.
* An unparseable entry **refuses the boot** rather than being skipped, so you are
  never running with a scope you believe in and do not have.
* `KAIROS_API_KEY` keeps working alongside the keyring, and **scoping wins** if a
  key appears in both.

A scope is a **capability, not a tenant**: it says what a key may *do*, not which
polls it may see. Any key holding `polls:read` sees every poll, because
`GET /api/polls` is not scoped per poll — one deployment, one set of polls, which
is the single-team model this API has always had. Per-poll isolation is #29.

| Scope | Routes it unlocks |
|---|---|
| `polls:read` | `GET` poll, responses, invites, contacts, `event.ics` |
| `polls:write` | create / update / delete poll, add dates, decide, edit invitees and responses — *implies `polls:read`* |
| `respond` | `POST .../respond` — submit availability |
| `mail:send` | `invite`, `nudge`, `email-decision`, `imip-decision`, and `add_dates(notify=true)` |
| `mail:force` | `nudge` with `force=true`, the 24h cooldown bypass — *implies `mail:send`* |
| `imip:poll` | `POST /imip/poll`, the inbound mailbox poll |

Default deny: a route a key has no scope for answers **403** naming the missing
scope. `GET /api/whoami` reports what the presenting key holds, so an agent can
find out instead of guessing — and the MCP server exposes it as `whoami()`.

Two routes reach `mail:send` through a scope that is nominally something else
(`add_dates(notify=true)`, `nudge(force=true)`), because that is exactly how a
send path hides inside a harmless-looking route. Both are checked.

### `force` is not a licence to spam

`force=true` bypasses the reminder cooldown. It is an operator affordance for a
human in the UI, so from the API it takes `mail:force` **and** its own
`mail_force` budget of 5/hour. The web UI's `remind-selected` is unchanged: one
click for a person, and the 24h cooldown still applies to everyone else.

### Mail budgets

| Knob | Default | What it bounds | On exceeding it |
|---|---|---|---|
| `KAIROS_MAIL_MAX_RECIPIENTS` | `100` | the recipient list a single **request** supplies — in practice `invite`, the only route whose list comes from the caller rather than from the poll | **400**, naming the knob. The caller still holds every address, so batching costs it nothing |
| `KAIROS_MAIL_PER_POLL` | `2000/day` | recipients one **poll** may mail, counted across every send path — API and web UI alike — and charged to the poll, so it holds whatever key asks | **429** with `Retry-After` |

The two failure modes are deliberately different. A caller-supplied list is
refused outright; a fan-out over a poll's own participants is only *budgeted*,
because a poll with more participants than the ceiling is a real meeting rather
than an attack — and because the surfaces that reach it (the API's `nudge`, the
UI's `remind-selected`) have no way to batch, so a 400 there would be a dead end.

Everything else that fans out — `nudge`, `email-decision`, `imip-decision`,
`remind`, `remind-selected` — is bounded by the per-poll budget, whatever
surface asks and however the calls are split. That budget is the only one of these
controls a rotated or stolen key cannot escape.

Unlike the rate limits, these two ship **on**: they are keyed on nothing, so
nobody legitimate is punished, and at the shipped numbers they are inert for a
real workflow (`2000/day` is 500 participants × the ~4 messages a poll sends
each). Raise them for a bigger meeting; `0` disables either one.

### What these do *not* bound — read this before exposing an instance

**With the shipped defaults, the total number of third-party recipients one key
can reach is unbounded.** Both mail budgets are *per request* and *per poll*, so a
key that mails the per-request ceiling to a **fresh poll** each time is refused
nothing: 40 new polls × 100 recipients is 4 000 recipients mailed and not one
429. Each poll gets its own allowance; there is no ceiling on the number of polls.

This is deliberate, and it is not an oversight:

* It is **not a regression.** Before this change there was no per-request cap and
  no per-poll budget either, so the aggregate was unbounded then too.
* ADR-0001/0002 require a deployment with nothing configured to behave exactly as
  it did, and the ETH/duplet adapter sets no rate-limit variable. A rate limit
  that fires by default is a behaviour change for it.

What closes the aggregate is `KAIROS_RATE_LIMIT=on`, which enables the per-key
`api` / `api_write` / `mail` / `mail_force` budgets above — charged to the key
rather than to the poll, so N polls do not mean N allowances. **Set it, plus
`KAIROS_TRUSTED_PROXY_CIDRS`, before exposing a hosted instance.** Kairos logs
which of the two states it is in at every boot, so you do not have to remember:

```
per-key rate limits OFF -> the TOTAL across polls is UNBOUNDED: each poll gets its
own allowance, so N fresh polls get N of them. Set KAIROS_RATE_LIMIT=on before
exposing this deployment.
```

### Poll reach: which polls a caller may read

<!-- #63/#64 reach. Self-contained section: appended at the end of the #51 scoping
     block, so it rebases cleanly. -->

A scope says what a key may *do*; **reach** says which *polls* it may do it to.
Until now a scope was the only answer, so `polls:read` meant every poll on the
instance and `GET /api/polls` enumerated it — while the web UI, three routes away,
let only the owner manage a poll. Same rows, two rules, the weaker one on the
machine-facing surface.

`KAIROS_POLL_REACH` chooses the rule, on **both** surfaces:

| `KAIROS_POLL_REACH` | web UI (`/polls/{id}`, `event.ics`) | API (`/api/polls…`) |
|---|---|---|
| unset / `open` (**default**) | any signed-in user | any authenticated key, every poll |
| `scoped` | the poll's owner — **or** anyone invited to it or already answered on it | only the polls the key's `~` claim names |

Unset means `scoped` when `KAIROS_HOSTED=on` (a deployment *we* operate is the
multi-tenant case, where `open` is an IDOR) and `open` otherwise, so a self-hoster
and the ETH group deployment keep the behaviour they have today. An
unrecognised `KAIROS_POLL_REACH` refuses the boot.

An unrecognised `KAIROS_HOSTED` (`Y`, `enabled`, `2`, …) reads as **scoped**, and
the boot log says so at WARNING. The mail gate still reads that value as "not
hosted", which is right for mail — but this knob now decides who may read which
poll, so a misspelling must not quietly select the permissive policy. Fix the
spelling, or say `KAIROS_POLL_REACH=open` if the deployment really is self-hosted.

**`open` is a deprecation, not a recommendation.** It stays the default because
every read that is legal today has to stay legal today (ADR-0001/0002), but it is
the pre-#63 rule and it still reproduces #63/#64 in full: any authenticated caller
reads every poll. Moving a deployment to `scoped` is three steps and no code:

1. **Audit.** `GET /api/whoami` reports each key's reach claim; list the keys and
   what they should reach.
2. **Grant.** Add `~<poll-id>` per key, or `~*` for the deployment's own service
   key and cron jobs. `KAIROS_API_KEY` already holds `~*`, so the ETH/duplet
   adapter keeps the instance either way.
3. **Flip.** `KAIROS_POLL_REACH=scoped` (or `KAIROS_HOSTED=on`) and read the boot
   line: it states which rule is in force, and the warnings name anything that is
   still off.

Under `scoped`, a key says which polls it reaches:

```bash
KAIROS_API_KEYS="k1:polls:read,respond~*;k2:mail:send~<poll-uuid>"
```

`~*` is the explicit instance-wide grant (also what `KAIROS_API_KEY` holds, so
scoping a deployment never costs it the instance); `~<poll-id>+<poll-id>` names
some; **omitting the clause reaches no poll** — default deny. `GET /api/polls`
returns what the caller reaches (an empty list, not a 403, for a key granted
nothing), and `GET /api/whoami` reports the reach next to the scopes.

Flat owner-gating was the alternative, and it would have broken the group
deployment: in header mode the authenticating proxy *is* the tenant boundary, so
`scoped` admits everyone named on the poll rather than only its creator. Full
reasoning, and the cases this does not cover yet, in
`docs/design/poll-reach.md`.

**On the web surface, `scoped` is only as strong as the identity it trusts.** In
`KAIROS_AUTH=header` mode the caller's identity *is* a request header, so with no
`KAIROS_TRUSTED_PROXY_CIDRS` set, anyone who can reach the port can assert
`X-User: <a creator uid>` and reach that creator's polls. `scoped` there is
decorative until the app sits behind a proxy whose CIDRs are named — the boot log
warns when it is not.

Two things `scoped` does *not* do, both pinned by tests so a later change is
deliberate:

* a refusal on the web surface is **404**, the same answer a missing poll gets,
  because that surface has to read the poll in order to decide and must therefore
  not also tell a caller which of the two it was;
* a key that creates a poll it cannot reach is **not** auto-granted reach over it
  (nothing in the schema says which key made the row, issue #32) — the creation
  response carries a `reach_warning` naming the grant it needs instead.
