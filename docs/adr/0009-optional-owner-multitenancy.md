# 0009 — Optional-owner multi-tenancy (capability-first)

Status: **Proposed**

## Context
A hosted product needs tenant separation without forking the self-host/ETH path.

## Decision
Tenancy is **capability-first**; `owner_id` is **nullable** (NULL =
accountless/single-team). Accounts + Turnstile + magic-link management are
additive and off by default. Physical isolation = self-host (own container + DB).

## Consequences
- An accountless hosted product is possible; ETH single-team is unaffected.
- No containers-per-poll, no DB-per-tenant. See `docs/design/multitenancy-hosting.md`.
