# Reverse the calendar — design notes & session handoff

**Tracking issue:** [gerchowl/kairos#23](https://github.com/gerchowl/kairos/issues/23)
**Branch:** `feat/reverse-calendar-imip`
**Status:** design captured, no code yet. Baseline green (`77 passed`).

This doc is the pick-up point for the "reverse the calendar" feature. It carries
the full design discussion plus a load-bearing constraint we discovered after
filing #23 (feed-refresh lag). Read this, then #23, then start at P0.

---

## The idea

Stop being calendar-invasive. Instead of reading a respondent's free/busy and
showing "available" slots, **push candidate slots into the respondent's own
calendar** and let them **Accept / Maybe / Decline from their calendar overlay**,
feeding the result back into the poll.

Why it's a *better* signal, not just different: free/busy is a lie — it can't
tell a hard external meeting from a movable focus-hold, and can't know the human
would gladly drop a soft block for the right thing. **Only the human knows what
is truly blocking.** We capture *willingness*, not mechanical availability.

Standards term: **iMIP** (RFC 6047) + `PARTSTAT`.

## Mechanism — `PARTSTAT` *is* accept/maybe/decline

| Kairos UI | iCalendar `PARTSTAT` |
|---|---|
| Accept | `ACCEPTED` |
| Maybe  | `TENTATIVE` |
| Decline| `DECLINED` |
| unanswered | `NEEDS-ACTION` |

A `VEVENT` with `METHOD:REQUEST` + the respondent as `ATTENDEE` makes Apple /
Outlook / Gmail render native Accept/Maybe/Decline buttons; clicking emails a
`METHOD:REPLY` back with `PARTSTAT`, which Kairos parses to update the poll.

## The catch: a "subscription" is not RSVP-able

- **Subscribed feed** (`webcal://…/poll.ics`) — slots *appear* in a toggleable
  calendar; **read-only**, can't RSVP natively.
- **iMIP invite** — real `REQUEST`, native RSVP, reply flows back.

Resolution = **hybrid C**: Round 1 read-only feed of all candidates with
deep-link voting; Round 2 a single iMIP `REQUEST` for the finalist.

## Decision lifecycle — final date revokes the rest (answered)

On "decide final date":
1. **Cancel losers** — `METHOD:CANCEL` (bumped `SEQUENCE`) per non-winning slot
   `UID`; clients auto-remove, no manual cleanup.
2. **Promote winner** — flip `TENTATIVE → CONFIRMED`, re-send `REQUEST`.
   **Recommend promoting the winning slot's existing `UID`** so the accepted
   hold *becomes* the meeting (no duplicate; prior acceptors stay accepted).

Needs **stable per-slot `UID` + `SEQUENCE`** tracking (new state vs. today's
one-shot ephemeral `.ics`).

## Opt-in + throwaway calendar (answered)

- iMIP per-slot is **opt-in**; default delivery = the feed (non-invasive).
- **Sender cannot control which calendar an iMIP invite lands in** — it goes to
  the user's *primary* calendar; folder-routing is user-side client config only.
- The disposable, one-click-hide/delete calendar is **intrinsically what the
  subscribed feed gives you** (subscribing creates a separate calendar).
- So: **feed = disposable "candidate holds" calendar; iMIP = the single
  confirmed meeting** (belongs in the real calendar anyway). iMIP's own cleanup
  comes from the protocol (`DECLINE` removes/greys, final `CANCEL` sweeps).

## ⚠ Feed-refresh lag — load-bearing constraint (new, post-#23)

The deep-link tap updates the **Kairos server instantly**, but the **feed view
in the calendar only changes on the client's next poll**, which is slow and
**not controllable by us**:

| Client | Subscribed-feed refresh | We control it? |
|---|---|---|
| **Google Calendar** | **~12–24 h** | ❌ (the killer gotcha) |
| Apple (mac/iOS) | 5 min–hourly setting; iOS power-mgmt stretches it | ⚠ user-side |
| Outlook | several hours | ❌ |

`REFRESH-INTERVAL;VALUE=DURATION:PT15M` (RFC 7986) is a *hint* — Apple honors,
Google ignores.

**Implications:**
1. **Instant-feedback surface is the Kairos landing page**, not the calendar.
   After a tap, confirm the vote + updated tally on the page. Never assume the
   calendar overlay reflects a vote quickly.
2. Declining a slot won't visibly disappear from the feed for a while (hours on
   Google). Feed = good for *browsing options*, weak for *seeing your own action*.
3. **iMIP wins the instant-feel battle**: native RSVP updates the event locally
   and immediately (no poll wait) *and* fires the reply. Another argument for
   hybrid C: feed for the many, iMIP for the few that matter.

## Metadata in events — mirror the web grid

`DESCRIPTION` (live tally + deep link), `STATUS` (TENTATIVE→CONFIRMED→CANCELLED),
`ATTENDEE` list each with `PARTSTAT` (= heatmap row), `COLOR` (RFC 7986;
green ready / amber partial / red blocked), `X-KAIROS-POLL-ID` /
`X-KAIROS-SLOT-STATUS` (machine round-trip).

## Where the code is today

- `src/kairos/ics.py` — `build_ics(poll, slot, url)` emits ONE `VEVENT` with
  `METHOD:PUBLISH` + `STATUS:CONFIRMED`. **No `ATTENDEE`/`ORGANIZER`/RSVP.**
  Helpers: `_esc`, `_fold`, `_as_date`, `_hm`, `_utc`. Fires only on decision.
- `src/kairos/email_service.py` + `templates/email/{invite,update,decision}.html`
  — outbound mail exists.
- `src/kairos/notifications.py` — idempotent reminders.
- Header-auth, accountless respondents, per-participant invite tokens.

So outbound `.ics` + email is solved; the new work is **bidirectional** +
**stateful UID/SEQUENCE** + (for iMIP) **inbound reply parsing**.

## Phased plan (from #23)

- [ ] **P0 — Feed (B):** read-only `webcal` endpoint per poll+participant; events
  carry deep-link accept/maybe/decline URLs + live `DESCRIPTION`/`COLOR`/`STATUS`.
  No new attack surface. Ships the throwaway-calendar UX. **← start here.**
- [ ] **P1 — iMIP outbound:** extend `ics.py` to `METHOD:REQUEST` with
  `ORGANIZER`/`ATTENDEE`/stable `UID`/`SEQUENCE`; opt-in per participant.
- [ ] **P2 — iMIP inbound:** reply ingestion (webhook/IMAP) → parse `PARTSTAT` →
  update poll; pluggable, fail-closed.
- [ ] **P3 — Decision reconciliation:** `CANCEL` losers + promote-winner `UID`
  to `CONFIRMED` (folds into existing decision flow).
- [ ] **P4 — Cross-client test matrix** + `falsify` on the PARTSTAT round-trip
  (Apple / Outlook desktop+web / Gmail). Load-bearing; do before committing to A/C.

## Sharp edges

Inbound mail = the real lift + new attack surface (P2 only). Client iMIP quirks
(Google auto-processes differently; "Maybe"→"Tentative"). Identity match by
`ATTENDEE mailto:` (trivial, accountless + invite tokens). Clutter ceiling —
never iMIP more than a shortlist. `SEQUENCE`/`UID` lifecycle correctness.

## Dev workflow (this repo)

- Env: `direnv allow`; run via `nix develop -c <cmd>` (e.g.
  `nix develop -c uv run pytest -q`). Baseline: **77 passed**.
- Commit: `nix develop -c git commit` (conventional commits on `main` →
  release-please PR → merge = tag + GH release).
- After release, bump pin in duplet `apps/scheduler/pyproject.toml` + `uv lock` +
  `deploy.sh ent scheduler`. (Kairos uses `pymysql`; the duplet adapter keeps
  `mysql-connector-python` for vendored `duplet_common`.)
