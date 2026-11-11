"""Database connectivity — SQLite by default, MySQL family via KAIROS_DB_URL.

The SQLite wrapper mimics the mysql-connector cursor API the queries were
written against (cursor(dictionary=True), %s placeholders), so the SQL layer
stays a single code path with small dialect branches.
"""

import sqlite3
from datetime import date, datetime
from urllib.parse import unquote, urlparse

from kairos import settings

IS_SQLITE = settings.DB_URL.startswith("sqlite")


# PR #92 round-3 finding (MEDIUM). The DATE/TIMESTAMP converters used to raise
# `date.fromisoformat(...)` -- an `"Invalid isoformat string"` -- from inside
# `cursor.fetchall()`, which is how a *single* malformed stored row turned the
# four poll-reading routes (/api/polls/{id}, /polls/{id}, /p/{token}, the ICS
# feeds) into 500s. The fix is two-layer:
#
#   1. make the converter TOLERANT -- an unparseable value becomes the raw
#      string (or `None` if even the decode fails), so `fetchall()` never
#      raises on it;
#   2. filter the resulting row at the db layer with `slot_is_readable`, so
#      a row with a bad date is skipped instead of being handed to the route.
#
# Both layers matter: without (1) `fetchall()` still raises, and without (2)
# a bad date would reach the renderer and 500 somewhere else. The write path
# (the `validation.*` predicates) refuses new bad rows -- this is the
# migration aid for rows that already exist on disk from before the validators
# were in place.

def _tolerant_date(b: bytes):
    """A DATE column converter that never raises on fetchall.

    Returns a `date` for a well-formed value, the decoded string for anything
    unparseable (so `validation.slot_is_readable` sees it and skips the row),
    or `None` if the bytes themselves cannot be decoded.
    """
    try:
        s = b.decode()
    except (UnicodeDecodeError, AttributeError):
        return None
    try:
        return date.fromisoformat(s)
    except ValueError:
        return s


def _tolerant_timestamp(b: bytes):
    """The TIMESTAMP counterpart -- same shape as `_tolerant_date`."""
    try:
        s = b.decode()
    except (UnicodeDecodeError, AttributeError):
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return s


if IS_SQLITE:
    sqlite3.register_converter("TIMESTAMP", _tolerant_timestamp)
    sqlite3.register_converter("DATE", _tolerant_date)


class _SqliteCursor:
    def __init__(self, cur, dictionary=False):
        self._cur, self._dict = cur, dictionary

    def execute(self, sql, params=()):
        return self._cur.execute(sql.replace("%s", "?"), params)

    def fetchone(self):
        row = self._cur.fetchone()
        if row is None:
            return None
        return dict(row) if self._dict else tuple(row)

    def fetchall(self):
        rows = self._cur.fetchall()
        return [dict(r) for r in rows] if self._dict else [tuple(r) for r in rows]

    @property
    def rowcount(self):
        return self._cur.rowcount

    def close(self):
        self._cur.close()


class _SqliteConn:
    def __init__(self, conn):
        self._conn = conn

    def cursor(self, dictionary=False):
        return _SqliteCursor(self._conn.cursor(), dictionary)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        # Mirrors `_MySQLConn.rollback` so callers (e.g. `db.add_slots_capped`,
        # which opens a transaction explicitly for the slot-cap race fix) can
        # unwind without a dialect branch.
        self._conn.rollback()

    def close(self):
        self._conn.close()


class _MySQLConn:
    """Adapts pymysql to the mysql-connector cursor API the code uses
    (cursor(dictionary=True))."""

    def __init__(self, conn):
        self._conn = conn

    def cursor(self, dictionary=False):
        import pymysql.cursors
        return self._conn.cursor(pymysql.cursors.DictCursor if dictionary else None)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


def get_connection():
    if IS_SQLITE:
        path = settings.DB_URL.split("///", 1)[-1] or ":memory:"
        conn = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return _SqliteConn(conn)
    import pymysql  # optional extra: kairos[mysql] — MIT (mysql-connector is GPL)
    u = urlparse(settings.DB_URL)
    return _MySQLConn(pymysql.connect(
        host=u.hostname or "127.0.0.1", port=u.port or 3306,
        user=unquote(u.username or "root"), password=unquote(u.password or ""),
        database=u.path.lstrip("/"), autocommit=False))


def db_now() -> datetime:
    """now() comparable to DB-written CURRENT_TIMESTAMP values.

    SQLite's CURRENT_TIMESTAMP is UTC; MySQL's is session-local time."""
    return datetime.utcnow() if IS_SQLITE else datetime.now()
