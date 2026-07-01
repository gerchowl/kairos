# Feature matrix

Kairos features traced to the decisions that shape them (`docs/adr/`). The
`guardrails-adr-matrix` gate requires every **Accepted** ADR to appear here.

| Feature | Where | Decisions |
|---|---|---|
| Scheduling polls (full-day / time-slot, when2meet grid) | `web.py`, `public.py`, `helpers.py` | ADR-0001, ADR-0002 |
| Public share links + per-person invite links | `public.py`, `db.py` | ADR-0001 |
| Owner management (create/decide/invite) | `web.py`, `api.py` | ADR-0002 |
| Env-only configuration | `settings.py` | ADR-0003 |
| iCalendar generation + parsing | `ics.py`, `imip_inbound.py` | ADR-0004 |
| Reverse-calendar: candidate feed + deep-link voting | `ics.py` (`build_feed_ics`), `public.py` | ADR-0005, ADR-0006 |
| Native iMIP invites (REQUEST/CANCEL) + IMAP-poll ingest | `ics.py`, `email_service.py`, `imip_inbound.py`, `api.py` | ADR-0005, ADR-0006 |
| Self-hosted short vote links (`/v/<code>`) | `db.py`, `web.py` | ADR-0007 |
| ETH/duplet deployment adapter | `duplet-webserver/apps/scheduler` | ADR-0008 |
| Container / hosted deployment (planned) | — | ADR-0008 |
| Optional accounts / multi-tenancy (planned) | — | ADR-0009 |
| Agent surfaces: REST API, `/llms.txt`, OpenAPI, MCP, `agent.json` | `api.py`, `main.py`, `public.py`, `mcp/` | ADR-0010 |
