# Kairos — session state (2026-06-05)

Everything requested is DONE, released as v0.2.0 (release-please), and
deployed: duplet ent runs kairos v0.2.0 (health ok, old polls intact).

Release flow from now on: conventional commits on main -> release-please
PR -> merge = tag + GH release -> bump pin in duplet
apps/scheduler/pyproject.toml + uv lock + deploy.sh ent scheduler.
NOTE: the adapter keeps mysql-connector-python — vendored duplet_common
needs it (kairos itself uses pymysql since the CI license gate flagged
the connector as GPL).

CI: tests / quickstart / mysql(MariaDB) / licenses(allowlist) /
audit(pip-audit). Dependabot: uv + npm + actions, weekly, grouped.
Dev: direnv allow; commit via `nix develop -c git commit`.
