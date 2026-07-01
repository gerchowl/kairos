# 0005 — Reverse the calendar (iMIP/PARTSTAT), never read free/busy

Status: **Accepted**

## Context
Every scheduler reads your calendar to guess free/busy — invasive, and a poor
signal (it can't tell a hard meeting from a movable hold).

## Decision
Kairos **proposes candidate slots into the respondent's calendar** and captures
Accept/Maybe/Decline (`PARTSTAT`, RFC 6047 iMIP). It never requests calendar-read
access or OAuth calendar scopes.

## Consequences
- Captures *willingness*, not mechanical availability; only the human knows what's
  truly movable.
- No OAuth/calendar scopes; the hard problems become email deliverability + client
  interop (see `docs/design/reverse-calendar-imip.md`).
