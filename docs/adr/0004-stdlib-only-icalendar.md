# 0004 — Hand-rolled, stdlib-only iCalendar

Status: **Accepted**

## Context
iMIP needs precise iCalendar (RFC 5545/6047). The public tree must stay
license-clean (CI license gate); third-party calendar libs add deps and license
surface.

## Decision
`ics.py` generates and parses iCalendar with the **standard library only** —
75-octet line folding, UTF-8 safety, PARTSTAT mapping. No `icalendar`/`vobject`.

## Consequences
- Full control, zero license risk.
- More code to own; client quirks handled by hand (see the cross-client matrix
  in `docs/design/reverse-calendar-imip.md`).
