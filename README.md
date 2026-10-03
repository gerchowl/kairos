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

Real deployments add a TLS terminator and an OIDC proxy in front:

```sh
cp .env.example .env && $EDITOR .env   # secrets; compose refuses to start without them
podman compose -f compose.proxy.yaml up -d
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

Kairos trusts identity headers from whatever reverse proxy you already run
(`KAIROS_AUTH=header`): Shibboleth/Apache, oauth2-proxy, Authelia, Cloudflare
Access, Tailscale… Respondents never need accounts — share links and invite
tokens are self-contained. See `kairos/settings.py` for all env knobs.
`compose.proxy.yaml` wires up the generic case (Caddy + oauth2-proxy + any OIDC
provider); the ETH/duplet Shibboleth deployment is unchanged.

> **Before exposing a hosted instance, set `KAIROS_TRUSTED_PROXY_CIDRS`.** Header
> mode trusts whoever sets the identity headers, so anything that can reach the
> app port directly can assert any identity — including becoming any poll owner.
> Set it to the proxy's address(es), e.g. `KAIROS_TRUSTED_PROXY_CIDRS=10.0.0.0/8,127.0.0.1`.
> Requests from any other peer are refused with 403 and logged. Unset means *trust
> everyone*, which is only safe while the port is unreachable except through your
> proxy. The check uses the real transport peer, never `X-Forwarded-For`; if you
> run uvicorn yourself rather than via the `kairos` entrypoint, pass
> `proxy_headers=False` so it does not rewrite that address before Kairos sees it.

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

| Knob | Default | What it bounds |
|---|---|---|
| `KAIROS_MAIL_MAX_RECIPIENTS` | `100` | recipients one *request* may name (`invite`, `nudge(emails=…)`, the UI's `remind-selected`). `0` disables |
| `KAIROS_MAIL_PER_POLL` | `2000/day` | recipients one *poll* may mail, counted across **every** send path — API and web UI alike — and charged to the poll, so it holds whatever key asks |

The two failure modes are deliberately different. A caller-supplied list is
refused with a **400** and loses nothing: it still holds the addresses and can
send them in batches. A fan-out over a poll's participants is *budgeted* instead,
because a poll with more participants than the ceiling is a real meeting rather
than an attack, and it gets a **429** it can retry tomorrow.

Unlike the rate limits above, these two ship **on**. They are ceilings on blast
radius rather than budgets keyed on an identity, so they do not punish a shared
NAT address, and at the shipped numbers they are inert for any real workflow —
`2000/day` is 500 participants × the ~4 messages a poll sends each (invite,
reminder, new-dates notice, decision). Raise them for a bigger meeting; the
per-poll budget is also the only one of the four that a rotated or stolen key
cannot escape.
