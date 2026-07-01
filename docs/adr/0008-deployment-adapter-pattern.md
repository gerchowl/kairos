# 0008 — Deployment adapter pattern: one core, thin adapters

Status: **Accepted**

## Context
Kairos ships to ETH shared hosting (Shibboleth, no root, init.d) and to
containers/hosted. These must not fork the codebase.

## Decision
Core Kairos is deployment-agnostic. Deployment specifics live in **thin adapters**
that pin a core version and override auth/env (e.g. duplet's `apps/scheduler`).
New features land in core as **env-selected options**, never adapter forks.

## Consequences
- One codebase serves shared-hosting + containers + hosted.
- The OCI image (planned) *wraps* the same `uvicorn` app; ETH's venv path is
  untouched.
