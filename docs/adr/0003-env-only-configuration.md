# 0003 — Configuration via environment variables only

Status: **Accepted**

## Context
Kairos runs on ETH shared hosting, containers, and (future) serverless. Config
files fragment across those; env is universal.

## Decision
All configuration is `KAIROS_*` environment variables (`settings.py`), with sane
defaults and fail-closed behavior (`SESSION_SECRET` required outside demo). No
config files.

## Consequences
- 12-factor; container/serverless-friendly.
- Deployment adapters (ADR-0008) are just env, not code.
