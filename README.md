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

> **Outbound mail (operators):** `SMTP_FROM` is the address every message is sent from,
> and the poll owner appears only as the display name and in `Reply-To` — a poll owner's
> own address cannot be authenticated from your domain. **Self-hosting? Stop here:**
> point `SMTP_FROM` at your own mailbox, leave `KAIROS_HOSTED` unset, and nothing else
> changes. Set `KAIROS_HOSTED=1` only when *you* send from *your* domain and therefore
> own its reputation — then `KAIROS_FROM_DOMAIN` is required, and Kairos refuses to send
> (rather than sending unauthenticated or from a personal mailbox) unless `SMTP_FROM`
> and `KAIROS_IMIP_ORGANIZER` are mailboxes on it. SPF/DKIM/DMARC are DNS records Kairos
> cannot publish or read, so it cannot confirm they exist — every boot logs the identity
> it is about to send as. **[`docs/design/mail-auth.md`](docs/design/mail-auth.md) has the
> exact records, the staged `p=none` → `quarantine` → `reject` plan, and how to verify
> them.**

> **Cookie note for operators:** Kairos sets only strictly-necessary cookies (session, signed response-edit token, theme preference) — disclosed on `/privacy`, no consent banner required (ePrivacy Art. 5(3) / Swiss TCA 45c exemptions). If you add analytics or any third-party embeds to your deployment, that changes — you'll need consent management.
