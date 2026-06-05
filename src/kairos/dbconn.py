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

if IS_SQLITE:
    sqlite3.register_converter("TIMESTAMP", lambda b: datetime.fromisoformat(b.decode()))
    sqlite3.register_converter("DATE", lambda b: date.fromisoformat(b.decode()))


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
