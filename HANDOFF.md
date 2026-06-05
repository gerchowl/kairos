# Next session — UX batch (user-requested 2026-06-05)

Repo: ~/Projects/kairos (public gerchowl/kairos). Dev: `direnv allow`, commit
via `nix develop -c git commit` (prek hooks need ruff). After release: tag,
bump tag in duplet apps/scheduler/pyproject.toml, uv lock, deploy ent.

## 1. Participants table rework (templates/poll.html + web.py)
- invites become part of the table: a trailing "(+)" row with inline inputs
  (email + optional-checkbox) that POSTs /invite; the row inherits active
  state filters visually
- button label "Add" (not "Send Invite") — sending happens via the table's
  reminder actions
- importance select -> a simple "optional" CHECKBOX (default unchecked =
  required)
- row deletion: hover -> X -> confirm (y/n) -> POST /polls/{id}/invites/{iid}/delete
  (new db.delete_invite + route + API DELETE endpoint; what about walk-in
  respondent rows? -> delete_response for those, same UX)

## 2. Full-day responses grid headers render badly (_macros.html fullday_grid)
- header cell should be stacked, no horizontal scrollbar on cards:
    <Day> DD     e.g.  Mon 08
    <Mon> MM           Jun 06
    YYYY               2026
  (their sketch: weekday+day / month / year stacked) — add a date_label
  macro/helper splitting the slot date; constrain column min-widths so the
  card doesn't overflow (table-fixed or smaller padding; test with 9 columns)

## 3. Playground chrome (DONE in this commit)
- standalone base.html had leftover portal Profile/Logout dropdown — replaced
  with plain user name. There is no registration/password flow in Kairos by
  design: owner identity comes from the operator's SSO proxy (or demo mode);
  respondents never need accounts.

## State: 62 tests green, CI (tests+quickstart+mariadb) green, Pages green,
## playground LIVE (WASM, threads patched inline), legal pages shipped.
