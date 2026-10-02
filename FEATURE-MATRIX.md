# Feature matrix

Kairos features traced to the decisions that shape them (`docs/adr/`). The
`guardrails-adr-matrix` gate requires every **Accepted** ADR to appear here.

| Feature | Where | Decisions |
|---|---|---|
| Scheduling polls (full-day / time-slot, when2meet grid) | `web.py`, `public.py`, `helpers.py` | ADR-0001, ADR-0002 |
| Public share links + per-person invite links | `public.py`, `db.py` | ADR-0001 |
| Owner management (create/decide/invite) | `web.py`, `api.py` | ADR-0002 |
| Env-only configuration | `settings.py` | ADR-0003 |
| Trusted-proxy allowlist (`KAIROS_TRUSTED_PROXY_CIDRS`, obligation S1) | `auth.py`, `main.py`, `cli.py` | ADR-0002 |
| iCalendar generation + parsing | `ics.py`, `imip_inbound.py` | ADR-0004 |
| Reverse-calendar: candidate feed + deep-link voting | `ics.py` (`build_feed_ics`), `public.py` | ADR-0005, ADR-0006 |
| Native iMIP invites (REQUEST/CANCEL) + IMAP-poll ingest | `ics.py`, `email_service.py`, `imip_inbound.py`, `api.py` | ADR-0005, ADR-0006 |
| Self-hosted short vote links (`/v/<code>`) | `db.py`, `web.py` | ADR-0007 |
| ETH/duplet deployment adapter | `duplet-webserver/apps/scheduler` | ADR-0008 |
| Container / self-host deployment (OCI image + compose, obligation D3/D4) | `Dockerfile`, `compose*.yaml`, `deploy/Caddyfile`, `docs/design/self-host-hardening.md` | ADR-0008 |
| Optional accounts / multi-tenancy (planned) | — | ADR-0009 |
| Agent surfaces: REST API, `/llms.txt`, OpenAPI, MCP, `agent.json` | `api.py`, `main.py`, `public.py`, `mcp/` | ADR-0010 |
| Brand & hosting home (nerdmachines house brand, `kairos.nerdmachines.com`) | `docs/design/productization-obligations.md` | ADR-0011 |
| Outbound-mail identity gate (`KAIROS_HOSTED` + `KAIROS_FROM_DOMAIN`, obligation M1) + SPF/DKIM/DMARC runbook | `email_service.py`, `settings.py`, `main.py`, `docs/design/mail-auth.md` | ADR-0011 |
