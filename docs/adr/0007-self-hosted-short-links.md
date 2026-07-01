# 0007 — Self-hosted short links, never a third-party shortener

Status: **Accepted**

## Context
Vote URLs carry capability tokens (ADR-0001); plain-text calendar `DESCRIPTION`s
need short links.

## Decision
A **self-hosted** `/v/<code>` shortener (`sched_short_links`, dedup by target) —
never TinyURL or any external shortener.

## Consequences
- Capability tokens never leave the server (no third-party logging/indexing).
- No external dependency; one small table.
