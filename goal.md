# GOAL — Land the "reverse the calendar" design (iMIP / PARTSTAT)

> **Trigger this file:** open a fresh Claude Code session in `~/Projects/kairos`
> on branch `feat/reverse-calendar-imip` and say *"execute goal.md"*.
> This is an execution brief, not a discussion. The design is already decided.
> Your job is to **land it incrementally, with tests and docs, keeping CI green.**

---

## 0. TL;DR

Flip scheduling around: instead of reading a respondent's free/busy and showing
"available" slots, **push candidate slots into their own calendar** and let them
**Accept / Maybe / Decline from their calendar overlay**, feeding the result back
into the poll. Standard = **iMIP (RFC 6047) + `PARTSTAT`**. Ship it in phases
**P0 → P3**, P0 first.

**Read before touching code (in order):**
1. `docs/design/reverse-calendar-imip.md` — full design + rationale + the
   feed-refresh-lag constraint.
2. Issue **[gerchowl/kairos#23](https://github.com/gerchowl/kairos/issues/23)**
   — the spec + the lag-constraint comment.
3. This file — the plan and guardrails.

---

## 1. Ground truth — code map (don't rediscover this)

**Data model** (`src/kairos/db.py`) — already maps onto iCalendar:

| Table | Key columns | iCalendar role |
|---|---|---|
| `sched_polls` | `id`, `title`, `description`, `mode`(full_day/time_slot), `timezone`, `public_token`, `status`(open/closed/decided), `decided_slot_id` | the VEVENT set / the meeting |
| `sched_poll_slots` | `id`, `poll_id`, `date`, `start_time`, `end_time` | one **candidate VEVENT** each |
| `sched_responses` | `id`, `poll_id`, `respondent_name`, `respondent_email`, `invite_id` | an **ATTENDEE** |
| `sched_response_slots` | `response_id`, `slot_id`, `availability`(**yes/maybe/no**) | **PARTSTAT** per slot |
| `sched_invites` | `id`, `poll_id`, `email`, `token`, `required` | per-attendee identity + token |
| `sched_contact_log` | `kind`(invite/reminder/update/decision) | outbound audit trail |

**The 1:1 mappings (memorize these):**

| Kairos | iCalendar |
|---|---|
| `availability = yes` | `PARTSTAT=ACCEPTED` |
| `availability = maybe` | `PARTSTAT=TENTATIVE` |
| `availability = no` | `PARTSTAT=DECLINED` |
| (no row) | `PARTSTAT=NEEDS-ACTION` |
| `sched_invites.token` / `email` | `ATTENDEE;mailto:` identity (reply key) |
| `poll.status` open→decided | `STATUS:TENTATIVE → CONFIRMED` |
| dropped slot on decide | `METHOD:CANCEL` |

**ICS today** (`src/kairos/ics.py`) — **stdlib-only, hand-rolled** (deliberate;
see Guardrails). `build_ics(poll, slot, url)` emits ONE `VEVENT`,
`METHOD:PUBLISH`, `STATUS:CONFIRMED`, **no `ATTENDEE`/`ORGANIZER`/RSVP**, UID =
`kairos-{poll_id}@kairos.local`. Helpers: `_esc`, `_fold` (75-octet RFC 5545
folding, UTF-8 safe), `_as_date`, `_hm` (TIME from MySQL timedelta / SQLite str /
time), `_utc`. Call sites: `api.py:382`, `web.py:154` & `:571`, tests
`tests/test_ics.py`.

**Routes that matter:**
- `public.py`: `GET /{token}/event.ics` (currently the decided event — **P0
  extends this to the candidate feed**), `GET/POST /{token}` (public vote),
  `GET/POST /i/{invite_token}` (per-invite vote — **the deep-link target**).
- `api.py` (`/api`): `POST /polls/{id}/decide`, `/respond`, `/invite`,
  `/email-decision`, `GET …/event.ics`.
- `web.py`: full UI incl. `POST /polls/{id}/decide` (`:357`),
  `email-decision` (`:558`, calls `build_ics` at `:571`).

**Outbound mail:** `src/kairos/email_service.py` +
`templates/email/{invite,update,decision}.html`. **Reminders:**
`notifications.py`. **Settings/knobs:** `settings.py` (`KAIROS_*`, header-auth).

---

## 2. The plan

Work top-to-bottom. **One phase = one focused commit (or small PR).** Each phase
must leave `nix develop -c uv run pytest -q` green and add its own tests.

### P0 — Candidate feed (flavor B). ✅ **LANDED** (commit `0a2f5d4`, 7 new tests).
*Goal:* a read-only `webcal` feed per poll/participant that shows every candidate
slot as a VEVENT, each carrying deep-link Accept/Maybe/Decline URLs + live
metadata. No new attack surface, no inbound mail. Delivers the "throwaway
calendar of candidate slots" immediately.

- [x] `ics.py`: add `build_feed_ics(poll, slots, responses, *, invite_token=None,
      base_url)` → a multi-VEVENT `VCALENDAR`, `METHOD:PUBLISH`. Reuse
      `_esc/_fold/_utc/_hm`. Per slot:
  - stable `UID:kairos-{poll_id}-{slot_id}@<host>` (see UID rule below),
  - `STATUS:TENTATIVE`,
  - `DESCRIPTION` = live tally (`"4 yes · 2 maybe · 1 no — converging"`) + deep
    links + poll URL,
  - `X-KAIROS-POLL-ID`, `X-KAIROS-SLOT-STATUS`,
  - optional `COLOR` (RFC 7986) by convergence (green ready / amber partial /
    red blocked),
  - top-level `REFRESH-INTERVAL;VALUE=DURATION:PT15M` + `X-PUBLISHED-TTL:PT15M`
    (hint only — see lag constraint).
- [x] Route: extend/duplicate `GET /{token}/event.ics` → when poll is **open**,
      return the candidate feed; when **decided**, keep current single confirmed
      event. Add a per-invite variant `GET /i/{invite_token}/feed.ics`.
- [x] Deep-link vote endpoints (idempotent **GET**, since they're tapped from a
      calendar event body): `GET /i/{invite_token}/s/{slot_id}/{yes|maybe|no}`
      → record availability → re-render the poll page (the instant surface; feed
      lags). Token-in-path is the capability; gated on `KAIROS_FEED`.
- [x] Tests: feed has N VEVENTs, correct UIDs, tally text, color/status, deep
      links resolve, a GET vote upserts one slot without clobber, decided poll
      still returns one event, all-off → 404. (`test_ics.py`, `test_sqlite_e2e.py`)

**P0 notes / deferred:** rate-limiting on the deep-link endpoint not yet added
(token-guarded; add a limiter before high-volume use). The public `/{token}`
feed links to the poll page (no per-slot identity); per-slot deep links require
the invite feed. `uv.lock` pre-commit papercut fixed (`uv run --frozen`).

### P1 — iMIP outbound. ✅ **LANDED** (commit `57868ef`).
*Goal:* emit real `METHOD:REQUEST` invitations so clients show native
Accept/Maybe/Decline. Off by default (`KAIROS_IMIP`).

- [x] `ics.py`: `build_request_ics` / `build_cancel_ics` → `METHOD:REQUEST`/`CANCEL`,
      `ORGANIZER` (= reply mailbox), `ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE`,
      stable `UID`, `SEQUENCE`.
- [x] Per-slot `SEQUENCE` persisted (`ical_sequence` column + `get/bump_slot_sequence`).
      UID stays deterministic (`slot_uid`), so no `ical_uid` column needed.
- [x] Send path `email_service.send_imip` — `.ics` with `method=REQUEST/CANCEL`,
      `From` = ORGANIZER mailbox (replies route to the IMAP inbox).
- [x] Settings `KAIROS_IMIP` + `KAIROS_IMIP_ORGANIZER[_NAME]`. Tests (`test_imip.py`).

### P2 — iMIP inbound (reply ingestion). ✅ **LANDED** (commit `12c732c`).
*Goal:* receive `METHOD:REPLY`, parse `PARTSTAT`, update the poll. **IMAP poll**
(Lars's choice). Fail-closed.

- [x] `src/kairos/imip_inbound.py`: stdlib `parse_reply` (UID/ATTENDEE/PARTSTAT/
      SEQUENCE) + `ics.parse_slot_uid` (fixed-width UID inverse).
- [x] Identity match `ATTENDEE mailto:` → known invite scoped to poll via UID;
      reject unknown senders; drop stale `SEQUENCE`.
- [x] `poll_mailbox()` IMAP-polls the ORGANIZER mailbox (opt-in, per-message
      fail-closed), exposed at `POST /api/imip/poll` for an operator cron/timer.
- [x] `PARTSTAT`→`availability` upsert. 9 tests incl. unknown-attendee/UID/stale.

### P3 — Decision-time iMIP (hybrid-C finalist). ✅ **LANDED** (commit `f7745d8`).
*Goal:* deciding a date sends the winner as a native RSVP-able invite.

- [x] `POST /api/polls/{id}/imip-decision` → `METHOD:REQUEST` (CONFIRMED) for the
      decided slot to every participant, bumping `SEQUENCE`; replies via IMAP poller.
- [x] **Design reconciliation:** under hybrid C we do *not* fan out per-slot
      REQUESTs during collection (the feed covers the many), so there are **no
      loser events to CANCEL** — `build_cancel_ics` stays for a future opt-in
      flavor-A path. Promote = the decided slot's own UID flips to CONFIRMED.
- [x] Tests: decide → one CONFIRMED REQUEST for winner (`test_imip_decision_*`).
      No loser-CANCEL in hybrid C (see design reconciliation above).

### P4 — Cross-client verification (do before trusting P1–P3 in prod) — ⚠ PARTIAL
- [x] Parse-side fixture matrix: real Apple / Google / Outlook(-folded) `ATTENDEE`
      shapes all parse identically (`test_imip_inbound.py`, parametrized).
- [ ] **Still needs a real environment / Lars:** live send→RSVP→ingest loop
      against actual Apple Calendar, Outlook (desktop+web), Gmail with a real
      `KAIROS_IMIP_ORGANIZER` mailbox; a `falsify` pass on *clients round-trip
      `PARTSTAT` reliably*; document quirks (Google auto-processing; Maybe→Tentative).

---

## 3. Decisions already locked (do NOT re-litigate)

- **Hybrid C** is the architecture: feed for the many, iMIP for the few/finalist.
- **Promote-existing-winner-UID** on decide (no duplicate meeting).
- **iMIP is opt-in**; feed is the non-invasive default.
- **The feed is the throwaway/disposable calendar**; iMIP can't target a
  calendar (lands in primary) and that's fine — the confirmed meeting belongs in
  the real calendar.
- **The Kairos landing page is the instant-feedback surface, not the calendar.**
  Subscribed feeds are eventually-consistent (Google ~12–24h, not controllable).
  Never build UX that assumes the calendar reflects a vote quickly.

---

## 4. Guardrails (hard constraints)

- **Keep `ics.py` stdlib-only.** The repo hand-rolls iCalendar on purpose — CI has
  a **license allowlist gate** (the `mysql-connector-python` GPL flag is why
  kairos uses `pymysql`). Do **not** add `icalendar`/`vobject`/etc. without
  clearing the license gate with Lars first. Default: extend the hand-rolled code.
- **Don't break the 77-test baseline.** Run `nix develop -c uv run pytest -q`
  before and after each phase.
- **Respect the auth model:** header-auth (`KAIROS_AUTH=header`), **accountless
  respondents**, capability tokens in URLs. Deep-link/feed endpoints authenticate
  via the token in the path — keep them CSRF-exempt but token-guarded + rate-limited.
- **Fail-closed** on all inbound (P2): reject unknown senders, stale sequences,
  oversized/malformed payloads. New attack surface gets the most scrutiny.
- **No secrets in query params** (project rule). Deep-link tokens are capabilities,
  not secrets-in-params for *data* — keep payloads out of the query string.
- **Privacy posture:** strictly-necessary cookies only; if a phase adds any
  tracking/3rd-party, STOP and flag (changes the consent story on `/privacy`).
- **DRY/SOLID:** reuse `_esc/_fold/_utc/_hm`; one helper per concern; proper
  columns/enums, not magic strings.

---

## 5. Working agreement

- **Conventional commits** on `feat/reverse-calendar-imip` (release-please will
  cut the release on merge to `main`). One phase ≈ one commit/PR.
- **Pre-commit papercut:** the `pytest` pre-commit hook runs `uv run`, which
  **regenerates `uv.lock`** and then self-fails the "files modified by hook" gate.
  Until fixed, either (a) `git checkout uv.lock` then commit, or (b) commit with
  `--no-verify` after running the suite manually. **Consider fixing this first**
  (pin uv / stop the hook regenerating the lock) — it bites every commit.
- **Commit via** `nix develop -c git commit`.
- **Stay legible:** post a one-line status at each phase boundary; end every turn
  with `※ recap: <state>. Next: <step>.`
- **Per phase:** update the checkboxes in this file + tick the matching box in #23.
- When a phase lands, push the branch and (if Lars wants) open/refresh the PR
  referencing #23.

---

## 6. Definition of done (overall)

- A respondent can subscribe to a poll feed and see all candidate slots as a
  separate, hideable, deletable calendar (P0).
- An opt-in respondent gets native Accept/Maybe/Decline; their reply updates the
  poll without visiting the web UI (P1+P2).
- Deciding a final date auto-cancels every other proposed slot on all calendars
  and lands exactly one confirmed meeting (P3).
- Event bodies mirror the web tally/convergence state (all phases).
- CI green: tests / quickstart / mysql(MariaDB) / licenses / audit.

---

## 7. Anti-goals / out of scope

- No OAuth / no reading anyone's free/busy (that's the whole point — don't drift
  back to calendar-invasive).
- No CalDAV server (RFC 6638) in this arc — iMIP-by-email only.
- No new heavyweight deps; no analytics; no account system for respondents.

---

## 8. Open questions for Lars (raise, don't decide solo)

1. **P2 inbound transport:** SendGrid/Postmark inbound-parse **webhook** vs **IMAP
   poll**? Depends on the deployment's mail path (duplet/ETH vs self-host).
2. **Feature gating:** ship P0 feed on by default, or behind `KAIROS_FEED=on`?
3. **iMIP default:** confirm opt-in (not opt-out) for sending real invitations.
4. **Fix the `uv.lock` pre-commit hook now** (yes/no) before P0?
