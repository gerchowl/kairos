# Feature matrix

Kairos features traced to the decisions that shape them (`docs/adr/`). The
`guardrails-adr-matrix` gate requires every **Accepted** ADR to appear here.

| Feature | Where | Decisions |
|---|---|---|
| Scheduling polls (full-day / time-slot, when2meet grid) | `web.py`, `public.py`, `helpers.py` | ADR-0001, ADR-0002 |
| Public share links + per-person invite links | `public.py`, `db.py` | ADR-0001 |
| Owner management (create/decide/invite) | `web.py`, `api.py` | ADR-0002 |
| Management authority in one predicate (`require_manage`, obligation S6) | `auth.py`, `db.py`, `web.py`, `api.py` | ADR-0001, ADR-0002, ADR-0009 |
| Env-only configuration | `settings.py` | ADR-0003 |
| Trusted-proxy allowlist (`KAIROS_TRUSTED_PROXY_CIDRS`, obligation S1) | `auth.py`, `main.py`, `cli.py` | ADR-0002 |
| Abuse limits on the public/email surface (`KAIROS_RATE_LIMIT`, obligation A3) | `ratelimit.py`, `public.py`, `web.py` | ADR-0001, ADR-0002, ADR-0003 |
| API key scopes + per-request / per-poll mail budgets + per-key budgets (`KAIROS_API_KEYS`) | `scoping.py`, `api.py`, `ratelimit.py` | ADR-0001, ADR-0002, ADR-0010 |
| iCalendar generation + parsing | `ics.py`, `imip_inbound.py` | ADR-0004 |
| Reverse-calendar: candidate feed + deep-link voting | `ics.py` (`build_feed_ics`), `public.py` | ADR-0005, ADR-0006 |
| Native iMIP invites (REQUEST/CANCEL) + IMAP-poll ingest | `ics.py`, `email_service.py`, `imip_inbound.py`, `api.py` | ADR-0005, ADR-0006 |
| Self-hosted short vote links (`/v/<code>`) | `db.py`, `web.py` | ADR-0007 |
| ETH/duplet deployment adapter | `duplet-webserver/apps/scheduler` | ADR-0008 |
| Container / self-host deployment (OCI image + compose, obligation D3/D4) | `Dockerfile`, `compose*.yaml`, `deploy/Caddyfile*`, `docs/design/self-host-hardening.md` | ADR-0008 |
| First-party OIDC owner login (`KAIROS_AUTH=oidc` + subject allowlist) | `oidc.py`, `auth.py`, `compose.oidc.yaml`, `docs/design/oidc-login.md` | ADR-0013 |
| Optional accounts / multi-tenancy (planned) | — | ADR-0009 |
| Agent surfaces: REST API, `/llms.txt`, OpenAPI, MCP, `agent.json` | `api.py`, `main.py`, `public.py`, `mcp/` | ADR-0010 |
| Brand & hosting home (nerdmachines house brand, `kairos.nerdmachines.com`) | `docs/design/productization-obligations.md` | ADR-0011 |
| Outbound-mail identity gate (`KAIROS_HOSTED` + `KAIROS_FROM_DOMAIN`, obligation M1) + SPF/DKIM/DMARC runbook | `email_service.py`, `settings.py`, `main.py`, `docs/design/mail-auth.md` | ADR-0011 |
