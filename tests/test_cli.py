"""The startup banner must never carry a credential (obligation S4/S7).

`kairos.cli` prints a one-line banner to stdout on boot. Under systemd that is
the journal; in a container it is `podman logs` and whatever ships it onward. A
MySQL `KAIROS_DB_URL` keeps the credential in its userinfo, so printing the raw
value publishes it in cleartext to a stream nobody audits and nobody rotates —
and the leak is *silent*: nothing looks wrong.

Measured before this file existed (image from #35):

    Kairos → http://0.0.0.0:8003/
      (auth=demo, db=mysql://kairos:SuperSecretPw123@db:3306/kairos, …)

The redaction is a display concern only. Nothing about how the app connects
changed: `dbconn.get_connection` still reads `settings.DB_URL` verbatim.
"""

import pytest

from kairos.cli import DEFAULT_DB_URL, redacted_db_url

SECRET = "SuperSecretPw123"


@pytest.mark.parametrize(
    "raw,expected",
    [
        # No credentials: passed through untouched, so the SQLite default and
        # every operator-visible path still read exactly as before.
        ("sqlite:///kairos.db", "sqlite:///kairos.db"),
        ("sqlite:////data/kairos.db", "sqlite:////data/kairos.db"),
        ("sqlite:///:memory:", "sqlite:///:memory:"),
        # Username only — no password to hide, and dropping it would make the
        # banner lie about who the app is connecting as.
        ("mysql://root@db:3306/kairos", "mysql://root@db:3306/kairos"),
        ("mysql://kairos@db:3306/kairos", "mysql://kairos@db:3306/kairos"),
        # The leak, with and without an explicit port.
        (
            f"mysql://kairos:{SECRET}@db:3306/kairos",
            "mysql://kairos:***@db:3306/kairos",
        ),
        (f"mysql://kairos:{SECRET}@db/kairos", "mysql://kairos:***@db/kairos"),
        # Percent-encoded secrets (`@` and `:` in a password are common) are
        # the case a naive `.*@` regex gets wrong by stopping at the wrong `@`.
        (
            "mysql://kairos:p%40ss%3Aword@db:3306/kairos",
            "mysql://kairos:***@db:3306/kairos",
        ),
    ],
)
def test_redacted_db_url(raw, expected):
    assert redacted_db_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        f"mysql://kairos:{SECRET}@db:3306/kairos",
        f"mysql://kairos:{SECRET}@db/kairos",
        "mysql://kairos:p%40ss%3Aword@db:3306/kairos",
    ],
)
def test_redacted_db_url_never_leaks(raw):
    assert SECRET not in redacted_db_url(raw)
    # ...and still says enough to be useful when diagnosing a connection.
    assert "db" in redacted_db_url(raw)


def test_banner_does_not_print_the_database_password(monkeypatch, capsys):
    """The real assertion: what `kairos` actually writes to stdout on boot.

    Asserting on the helper would only prove the helper works; this catches a
    future edit that re-introduces the raw value at the print site.
    """
    import uvicorn

    from kairos import cli

    monkeypatch.setenv("KAIROS_DB_URL", f"mysql://kairos:{SECRET}@db:3306/kairos")
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    monkeypatch.setattr("sys.argv", ["kairos", "--port", "9999"])
    cli.main()

    banner = capsys.readouterr().out
    assert banner.startswith("Kairos →"), banner
    assert SECRET not in banner, f"database password leaked to stdout: {banner}"
    # Non-secret parts survive, so the banner stays useful for support.
    assert "mysql://kairos:" in banner
    assert "db:3306/kairos" in banner


def test_banner_still_reports_a_sqlite_path(monkeypatch, capsys):
    """Redaction must not degrade the common case into uselessness."""
    import uvicorn

    from kairos import cli

    monkeypatch.delenv("KAIROS_DB_URL", raising=False)
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    monkeypatch.setattr("sys.argv", ["kairos", "--db", "/srv/data/kairos.db"])
    cli.main()

    assert "db=sqlite:////srv/data/kairos.db" in capsys.readouterr().out


def test_default_db_url_is_the_documented_relative_path():
    """The banner default must stay the relative path the volume relies on.

    `dbconn.get_connection` resolves `sqlite:///kairos.db` against the process
    working directory, which the image sets to the volume mount point. If this
    constant ever drifted to an absolute path, the image would start writing the
    database outside the volume and the two would silently disagree.
    """
    assert DEFAULT_DB_URL == "sqlite:///kairos.db"
