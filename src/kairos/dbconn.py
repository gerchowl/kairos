"""Database connectivity — SQLite by default, MySQL family via KAIROS_DB_URL.

The SQLite wrapper mimics the mysql-connector cursor API the queries were
written against (cursor(dictionary=True), %s placeholders), so the SQL layer
stays a single code path with small dialect branches.

Three backends:
  sqlite:///path            -> stdlib sqlite3 (self-host, tests, ETH; default)
  mysql://user:pw@host/db   -> pymysql (ETH's MariaDB)
  do-sqlite:///<name>       -> Cloudflare Durable Object SQLite storage
                               (hosted on Workers; spike #54). The actual
                               `sql` object is set by the Worker entrypoint
                               via `set_do_sql()` per request. The backend
                               only activates when KAIROS_DB_URL starts with
                               `do-sqlite`, so every other deployment is
                               byte-for-byte unaffected.
"""

import re
import sqlite3
from datetime import date, datetime
from urllib.parse import unquote, urlparse

from kairos import settings

IS_DO_SQLITE = settings.DB_URL.startswith("do-sqlite")
_IS_LOCAL_SQLITE = settings.DB_URL.startswith("sqlite")
# Public flag: "SQLite family — no ENUM, no ON UPDATE". Both file-backed and
# Durable-Object-backed SQLite follow the same DDL rules in db.py, so callers
# that branch on `IS_SQLITE` (schema rewrite, _ensure_column shape) keep
# working across both backends.
IS_SQLITE = _IS_LOCAL_SQLITE or IS_DO_SQLITE


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


if _IS_LOCAL_SQLITE:
    sqlite3.register_converter("TIMESTAMP", _tolerant_timestamp)
    sqlite3.register_converter("DATE", _tolerant_date)


# ---- Cloudflare Durable Object SQLite backend (#54 spike) ----------------
#
# The DO SQL API (`self.ctx.storage.sql.exec(sql, *binds)`) is SYNCHRONOUS,
# uses `?` placeholders, and is reachable only from inside the DO instance.
# The Worker entrypoint calls `set_do_sql(self.ctx.storage.sql)` at the start
# of every request; everything below reads that module-local, so the rest of
# `kairos.db` keeps its connection-per-call shape without any route changes.

_do_sql = None


def set_do_sql(sql):
    """Store the DO's `ctx.storage.sql` for the duration of a request.

    Each DO request runs on a single thread with a single in-flight call, so
    a module-level global is safe here — no asyncio.contextvars dance needed.
    """
    global _do_sql
    _do_sql = sql


_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _coerce_value(v):
    """Approximation of sqlite3.register_converter("TIMESTAMP"/"DATE") for DO SQL.

    DO SQL has no DECLARED_TYPES hook, so every column comes back as the raw
    JS value. sqlite3 would have parsed ISO strings in TIMESTAMP/DATE columns
    into `datetime`/`date`; the rest of kairos.db relies on that. Value-
    sniffing instead of schema-driven: a plain string that matches the ISO
    shape is parsed, everything else passes through.
    """
    if isinstance(v, str):
        if _TS_RE.match(v):
            try:
                return datetime.fromisoformat(v.replace(" ", "T", 1))
            except ValueError:
                return v
        if _DATE_RE.match(v):
            try:
                return date.fromisoformat(v)
            except ValueError:
                return v
    return v


def _bind_param(v):
    """Coerce Python values to JS-safe bindings for `sql.exec`.

    DO SQL binds accept string/int/float/bytes/null. Everything else — datetime,
    date, UUID, bool — needs explicit coercion or the runtime throws.
    """
    if v is None:
        return None
    if isinstance(v, bool):  # must precede int (True/False are ints)
        return 1 if v else 0
    if isinstance(v, (int, float, str, bytes, bytearray)):
        return v
    if isinstance(v, datetime):
        # SQLite's CURRENT_TIMESTAMP writes "YYYY-MM-DD HH:MM:SS" (space, not T);
        # keep that shape so string comparisons line up with existing rows.
        return v.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(v, date):
        return v.isoformat()
    return str(v)


def _row_to_dict(row, columns):
    """Coerce one DO SQL result row to a {column: pyvalue} dict.

    `row` is a JS proxy exposing attribute access per column name. `columns`
    is the cursor's `columnNames`. We go via `to_py` where available so the
    conversion matches Pyodide's own rules.
    """
    try:
        d = row.to_py()  # dict-like
        return {k: _coerce_value(v) for k, v in dict(d).items()}
    except Exception:
        return {c: _coerce_value(getattr(row, c)) for c in columns}


class _DOCursor:
    def __init__(self, sql, dictionary=False):
        self._sql, self._dict = sql, dictionary
        self._rows = []
        self._cols = []
        self._rowcount = 0

    def execute(self, sql_text, params=()):
        rewritten = sql_text.replace("%s", "?")
        binds = [_bind_param(p) for p in params] if params else []
        cursor = self._sql.exec(rewritten, *binds) if binds else self._sql.exec(rewritten)
        # Drain the cursor synchronously (DO SQL cursors must be consumed before
        # any `await`, and the whole backend is sync anyway).
        rows = []
        for r in cursor:
            rows.append(r)
        self._rows = rows
        try:
            self._cols = list(cursor.columnNames)
        except Exception:
            self._cols = []
        try:
            written = cursor.rowsWritten
        except Exception:
            written = 0
        self._rowcount = written if written else len(rows)
        return None

    def fetchone(self):
        if not self._rows:
            return None
        row = self._rows.pop(0)
        d = _row_to_dict(row, self._cols)
        return d if self._dict else tuple(d[c] for c in self._cols)

    def fetchall(self):
        out = []
        for r in self._rows:
            d = _row_to_dict(r, self._cols)
            out.append(d if self._dict else tuple(d[c] for c in self._cols))
        self._rows = []
        return out

    @property
    def rowcount(self):
        return self._rowcount

    def close(self):
        self._rows = []


class _DOConn:
    def __init__(self, sql):
        if sql is None:
            raise RuntimeError(
                "KAIROS_DB_URL=do-sqlite but no active DO sql binding — the "
                "Worker entrypoint must call dbconn.set_do_sql() before a "
                "request reaches kairos.db."
            )
        self._sql = sql

    def cursor(self, dictionary=False):
        return _DOCursor(self._sql, dictionary=dictionary)

    def commit(self):
        # DO SQL coalesces writes between awaits into an implicit transaction;
        # explicit BEGIN/COMMIT via exec() is refused by the runtime. No-op.
        pass

    def close(self):
        # Shared DO sql binding — don't actually close it.
        pass


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
    if IS_DO_SQLITE:
        return _DOConn(_do_sql)
    if _IS_LOCAL_SQLITE:
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

    SQLite's CURRENT_TIMESTAMP is UTC; MySQL's is session-local time. DO SQL
    is SQLite, so it follows the SQLite rule.
    """
    return datetime.utcnow() if (IS_SQLITE or IS_DO_SQLITE) else datetime.now()
