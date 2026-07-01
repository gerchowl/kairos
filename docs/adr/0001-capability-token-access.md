# 0001 — Capability-token access; no enumeration

Status: **Accepted**

## Context
Polls are shared with people who should not need accounts, managed by owners, and
increasingly driven by agents. We need access control that works for all three
without a login for respondents.

## Decision
Every poll and artifact is reachable **only** via an unguessable token:
`public_token` (view/vote), a per-invite token (which *is* the respondent's
identity), and `admin_token` (manage). Tokens are `secrets.token_urlsafe(32)`.
No endpoint lists polls without an authenticated owner scope or a token.

## Consequences
- No cross-poll enumeration — each poll is a capability island.
- A token is a **bearer capability**: sharing it shares the ability (documented).
- Enables accountless respondents (ADR-0002), agent access (ADR-0010), and
  optional owners (ADR-0009).
