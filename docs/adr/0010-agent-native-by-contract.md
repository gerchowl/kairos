# 0010 — Agent-native by contract

Status: **Accepted**

## Context
Kairos is built to be driven by agents, not just humans.

## Decision
Everything the UI does is available to agents: REST API (Bearer), `/llms.txt`,
OpenAPI/Swagger, an MCP server, and a **keyless per-invite `agent.json`**. The
invite link self-describes so an agent can RSVP from just the link.

## Consequences
- Agents are first-class; discovery is standardized.
- The capability model (ADR-0001) extends cleanly to agents (no key for
  invitee-scoped actions).
