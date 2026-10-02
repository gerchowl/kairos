# Kairos — session state

**This file is superseded by [`PLAN.md`](PLAN.md).** It previously claimed the
project was "everything DONE at v0.2.0", which was already stale when written.

Current state (2026-10-02): `main` at the ADR-0011 house-brand commit, v0.9.0
released, 107 tests green. The reverse-calendar arc (`goal.md`, issue #23) is
**shipped** — only P4 live cross-client verification remains, and that needs a
real mailbox. Work is now the productization arc, issues #29–#38 under Epic #38.

Read `PLAN.md` for the sequenced roadmap and the per-PR working agreement.
Release flow: conventional commits on main -> release-please PR -> merge = tag
+ GH release -> bump the pin in duplet `apps/scheduler/pyproject.toml` + uv lock
+ `deploy.sh ent scheduler`.

NOTE: the duplet adapter keeps mysql-connector-python — vendored duplet_common
needs it (kairos itself uses pymysql because the CI license allowlist gate
flags the connector as GPL).

CI: tests / quickstart / mysql(MariaDB) / licenses(allowlist) /
audit(pip-audit) / gitleaks / ADR obligation gates. Dev: direnv allow;
commit via `nix develop -c git commit`.
