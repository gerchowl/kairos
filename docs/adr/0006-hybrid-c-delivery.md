# 0006 — Hybrid-C delivery: feed for the many, iMIP for the finalist

Status: **Accepted**

## Context
Sending an iMIP invite per candidate slot clutters calendars; a read-only
subscription can't RSVP natively.

## Decision
Candidate slots are delivered as a **subscribe-able feed** with per-slot deep-link
voting; the **decided** slot is sent as a native iMIP `REQUEST`. No per-slot iMIP
fanout (that path — `build_cancel_ics` etc. — is retained but not the default).

## Consequences
- No invite clutter.
- The feed is eventually-consistent (Google ~daily); the **landing page**, not the
  calendar, is the instant-feedback surface.
