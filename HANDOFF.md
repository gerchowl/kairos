# Kairos — session state

All user-requested batches through 2026-06-05 are DONE and on main:
extraction (v0.1.0 consumed by duplet), GH Pages landing + WASM playground
(live), legal pages, flake/direnv/prek, email validation, PUBLIC_URL SSoT,
participants-table rework (in-table add/Add/optional-checkbox/hover-X
delete + API DELETE parity), stacked full-day headers, release-please,
dependabot, license + pip-audit CI.

Next release: merge the release-please PR when it appears (or tag manually),
then bump the pin in duplet apps/scheduler/pyproject.toml + uv lock +
deploy ent.

Notes: commits via `nix develop -c git commit`; playground wheels are
CI-vendored (gitignored locally — regenerate via pip download, see pages.yml).
