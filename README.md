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

> **Before exposing a hosted instance, set `KAIROS_TRUSTED_PROXY_CIDRS`.** Header
> mode trusts whoever sets the identity headers, so anything that can reach the
> app port directly can assert any identity — including becoming any poll owner.
> Set it to the proxy's address(es), e.g. `KAIROS_TRUSTED_PROXY_CIDRS=10.0.0.0/8,127.0.0.1`.
> Requests from any other peer are refused with 403 and logged. Unset means *trust
> everyone*, which is only safe while the port is unreachable except through your
> proxy. The check uses the real transport peer, never `X-Forwarded-For`; if you
> run uvicorn yourself rather than via the `kairos` entrypoint, pass
> `proxy_headers=False` so it does not rewrite that address before Kairos sees it.

> **Before exposing a hosted instance, set `KAIROS_RATE_LIMIT=on`.** See
> [Rate limiting](#rate-limiting-optional) below — the public token routes let
> anyone with a link create rows, and the owner routes can fan out mail to every
> address on a poll's participants table.

> **Cookie note for operators:** Kairos sets only strictly-necessary cookies (session, signed response-edit token, theme preference) — disclosed on `/privacy`, no consent banner required (ePrivacy Art. 5(3) / Swiss TCA 45c exemptions). If you add analytics or any third-party embeds to your deployment, that changes — you'll need consent management.

## Rate limiting (optional)

Off unless you switch it on, so self-host and the ETH/duplet deployment behave
exactly as before. `KAIROS_RATE_LIMIT=on` puts a budget on the abuse-sensitive
surface:

| Rule | Applies to | Ships at |
|---|---|---|
| `read` | token pages, `agent.json`, feeds, `.ics` | 120/min |
| `respond` | `POST /p/<token>`, `POST /p/i/<token>` | 20/min |
| `deeplink_vote` | `GET …/s/<slot>/<yes\|maybe\|no>` — one per poll slot | 120/min |
| `create` | `POST /new` | 10/min |
| `invite` | `POST /polls/<id>/invite` | 30/min |
| `send` | `remind`, `remind-selected`, `email-decision` — actual SMTP | 10/hour |

Override any of them with `KAIROS_RATE_LIMIT_<RULE>="<count>/<window>"`
(`second`/`minute`/`hour`/`day`), e.g. `KAIROS_RATE_LIMIT_SEND="30/hour"`. `0`
switches that one rule off. An unparseable value — or a rule name that does not
exist — **refuses to boot** rather than silently running unlimited.

Requests are counted against the **real transport peer**, never
`X-Forwarded-For`: that header is caller-supplied, so a budget keyed on it
would be a budget the caller sets for themselves. That makes `proxy_headers=False`
load-bearing here too — if you launch uvicorn yourself instead of via the
`kairos` entrypoint, pass it, or a rotating `X-Forwarded-For` evades the budget
entirely. Kairos logs a warning at startup when limits are on.

Over-budget requests get a `429` with a `Retry-After`, as an HTML page in a
browser and as JSON otherwise.

> **One instance, one counter set.** The counters live in the serving process,
> so **N app instances means an attacker gets N × the budget.** That is the one
> limit to know about before scaling out; #36 chose SQLite on the same
> reasoning (its operational ceiling is a single writer). Move the counters to a
> shared store before running more than one instance.
