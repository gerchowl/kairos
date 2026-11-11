import re
import secrets
import uuid

from fastapi import HTTPException

from kairos.dbconn import IS_SQLITE, get_connection  # noqa: F401  (re-exported)
from kairos.validation import slot_is_readable


def _readable_slots(rows: list[dict]) -> list[dict]:
    """Filter unreadable rows out of a slot fetch.

    PR #92 round-3 finding (MEDIUM). A pre-validator row on disk (e.g. a
    stored `date` like `2026-1-5`) used to 500 every poll-read route:
    `cursor.fetchall()` raised inside the DATE converter. The converters are
    now tolerant (see `dbconn._tolerant_date`), so the raw string lands here
    and `slot_is_readable` skips it -- logged once per `(poll_id, slot_id)`
    pair so an operator sees the shape without the log filling on repeat
    views. Called at every point in this module that loads `sched_poll_slots`
    rows for a route to render; nothing downstream has to remember to filter.
    """
    return [s for s in rows if slot_is_readable(s)]

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS sched_polls (
        id VARCHAR(36) PRIMARY KEY,
        creator_id VARCHAR(36) NOT NULL,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        mode ENUM('full_day', 'time_slot') NOT NULL,
        timezone VARCHAR(64) DEFAULT 'Europe/Zurich',
        public_token VARCHAR(64) UNIQUE NOT NULL,
        status ENUM('open', 'closed', 'decided') DEFAULT 'open',
        decided_slot_id VARCHAR(36),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS sched_poll_slots (
        id VARCHAR(36) PRIMARY KEY,
        poll_id VARCHAR(36) NOT NULL,
        date DATE NOT NULL,
        start_time TIME,
        end_time TIME,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (poll_id) REFERENCES sched_polls(id) ON DELETE CASCADE
    )""",
    """CREATE TABLE IF NOT EXISTS sched_responses (
        id VARCHAR(36) PRIMARY KEY,
        poll_id VARCHAR(36) NOT NULL,
        respondent_name VARCHAR(255) NOT NULL,
        respondent_email VARCHAR(255),
        user_id VARCHAR(36),
        invite_id VARCHAR(36),
        notified_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (poll_id) REFERENCES sched_polls(id) ON DELETE CASCADE
    )""",
    """CREATE TABLE IF NOT EXISTS sched_response_slots (
        response_id VARCHAR(36) NOT NULL,
        slot_id VARCHAR(36) NOT NULL,
        availability ENUM('yes', 'maybe', 'no') NOT NULL,
        PRIMARY KEY (response_id, slot_id),
        FOREIGN KEY (response_id) REFERENCES sched_responses(id) ON DELETE CASCADE,
        FOREIGN KEY (slot_id) REFERENCES sched_poll_slots(id) ON DELETE CASCADE
    )""",
    """CREATE TABLE IF NOT EXISTS sched_invites (
        id VARCHAR(36) PRIMARY KEY,
        poll_id VARCHAR(36) NOT NULL,
        email VARCHAR(255) NOT NULL,
        token VARCHAR(64) UNIQUE NOT NULL,
        responded BOOLEAN DEFAULT FALSE,
        required BOOLEAN DEFAULT TRUE,
        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        notified_at TIMESTAMP NULL,
        FOREIGN KEY (poll_id) REFERENCES sched_polls(id) ON DELETE CASCADE
    )""",
    """CREATE TABLE IF NOT EXISTS sched_contact_log (
        id VARCHAR(36) PRIMARY KEY,
        poll_id VARCHAR(36) NOT NULL,
        email VARCHAR(255) NOT NULL,
        invite_id VARCHAR(36),
        kind ENUM('invite', 'reminder', 'update', 'decision') NOT NULL,
        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (poll_id) REFERENCES sched_polls(id) ON DELETE CASCADE
    )""",
    """CREATE TABLE IF NOT EXISTS sched_notifications (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        poll_id VARCHAR(36) NOT NULL,
        type ENUM('new_response', 'all_responded') NOT NULL,
        message TEXT NOT NULL,
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (poll_id) REFERENCES sched_polls(id) ON DELETE CASCADE
    )""",
    # Self-hosted short links (our own tiny-url) so capability vote URLs stay
    # short in plain-text calendar DESCRIPTIONs — and never leak to a 3rd party.
    """CREATE TABLE IF NOT EXISTS sched_short_links (
        code VARCHAR(16) PRIMARY KEY,
        target VARCHAR(512) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""",
    # Owner-minted API tokens (issue #82). Each row is one bearer credential the
    # signed-in owner minted from the admin panel, in addition to the static
    # KAIROS_API_KEY / KAIROS_API_KEYS env grants (#51). Only the sha256 hash of
    # the token is stored — the plaintext is shown exactly once at mint time —
    # so a database leak does not disclose working credentials. The `prefix`
    # column carries the first ~12 chars of the plaintext (`kai_` + 8 random
    # chars) for a non-sensitive display handle in the panel's list. All columns
    # are plain SQL so the schema also lands on the Durable-Object SQLite
    # backend drafted in PR #79: no partial indexes, no JSON columns, no
    # dialect-specific defaults beyond the shared ones.
    """CREATE TABLE IF NOT EXISTS sched_api_tokens (
        id VARCHAR(36) PRIMARY KEY,
        owner_uid VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        token_hash VARCHAR(64) UNIQUE NOT NULL,
        prefix VARCHAR(16) NOT NULL,
        scopes VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        last_used_at TIMESTAMP NULL,
        revoked_at TIMESTAMP NULL
    )""",
]


def new_id() -> str:
    return str(uuid.uuid4())


def new_token() -> str:
    return secrets.token_urlsafe(32)


def new_short_code() -> str:
    """~10 url-safe chars — unguessable (the code IS the capability), still tiny."""
    return secrets.token_urlsafe(8)[:10]


def make_short_link(target: str) -> str:
    """Return a stable short code for a target path (dedup so re-sends reuse it)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT code FROM sched_short_links WHERE target = %s", (target,))
    row = cursor.fetchone()
    if row:
        code = row[0]
    else:
        code = new_short_code()
        cursor.execute("INSERT INTO sched_short_links (code, target) VALUES (%s, %s)", (code, target))
        conn.commit()
    cursor.close()
    conn.close()
    return code


def resolve_short_link(code: str) -> str | None:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT target FROM sched_short_links WHERE code = %s", (code,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return row[0] if row else None


if IS_SQLITE:
    # SQLite has no ENUM / ON UPDATE clauses
    SCHEMA = [re.sub(r"ENUM\([^)]*\)", "TEXT", s).replace(" ON UPDATE CURRENT_TIMESTAMP", "")
              for s in SCHEMA]


def _ensure_column(cursor, table: str, column: str, ddl: str, backfill: str | None = None):
    """Idempotent column migration for pre-existing deployments."""
    if IS_SQLITE:
        cursor.execute(f"PRAGMA table_info({table})")  # noqa: S608
        exists = column in {row[1] for row in cursor.fetchall()}
    else:
        cursor.execute(f"SHOW COLUMNS FROM {table} LIKE '{column}'")  # noqa: S608
        exists = cursor.fetchone() is not None
    if not exists:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")  # noqa: S608
        if backfill:
            cursor.execute(backfill)


def _ensure_index(cursor, table: str, index: str, ddl: str):
    """Idempotent index creation for pre-existing deployments.

    An existence check rather than a bare `CREATE UNIQUE INDEX IF NOT EXISTS`:
    that spelling is SQLite/MariaDB-only (MySQL 8 has no IF NOT EXISTS for
    CREATE INDEX), and this layer claims the whole MySQL family. Probed on
    MariaDB 11.8 and SQLite: both take the DDL below, both refuse a duplicate
    non-NULL value, and both allow unlimited NULLs -- which is what makes a
    UNIQUE index safe to add to a table whose existing rows are all NULL.

    Re-runnable: drop the index, run init_schema() again, and it comes back --
    which is the whole reason this is a helper and not a raw statement in the
    schema list.

    Cost for an operator with a large table: building a unique index reads and
    sorts the whole column, so on MySQL 5.7 at 2M rows the bare CREATE UNIQUE
    INDEX measured 7.8s of blocking DDL, while the same statement with
    `ALGORITHM=INPLACE, LOCK=NONE` completed with concurrent DML. That is not
    what this function emits, because the syntax is dialect-specific and the
    only caller is a 4-column migration on the smallest table in the schema
    (~21k polls is the documented ceiling for a whole deployment) -- but an
    operator with a table far past that should add the clause by hand first,
    rather than discover it as downtime.
    """
    if IS_SQLITE:
        cursor.execute(f"PRAGMA index_list({table})")  # noqa: S608
        exists = index in {row[1] for row in cursor.fetchall()}
    else:
        cursor.execute(f"SHOW INDEX FROM {table} WHERE Key_name = '{index}'")  # noqa: S608
        exists = cursor.fetchone() is not None
    if not exists:
        cursor.execute(ddl)  # noqa: S608


def init_schema():
    conn = get_connection()
    cursor = conn.cursor()
    for stmt in SCHEMA:
        cursor.execute(stmt)
    # Nudge-engine timestamps (see web.nudge_participants)
    _ensure_column(cursor, "sched_poll_slots", "created_at",
                   "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
                   # backfill: pre-existing slots count as old as their poll,
                   # so adding the column doesn't mark every respondent stale
                   "UPDATE sched_poll_slots SET created_at = "
                   "(SELECT created_at FROM sched_polls WHERE id = poll_id)")
    _ensure_column(cursor, "sched_invites", "notified_at", "notified_at TIMESTAMP NULL")
    _ensure_column(cursor, "sched_invites", "required", "required BOOLEAN DEFAULT TRUE")
    _ensure_column(cursor, "sched_invites", "name", "name VARCHAR(255) NULL")
    _ensure_column(cursor, "sched_responses", "notified_at", "notified_at TIMESTAMP NULL")
    _ensure_column(cursor, "sched_responses", "required", "required BOOLEAN DEFAULT TRUE")
    # iMIP SEQUENCE per slot UID (issue #23): bumped on edit/cancel so clients
    # accept updates and tombstone the right event.
    _ensure_column(cursor, "sched_poll_slots", "ical_sequence", "ical_sequence INT DEFAULT 0")
    # Accountless management (issue #29; ADR-0009, obligation S6) -- the columns
    # #30's /manage/<token> route and #31's send-gate will read. Four nullable,
    # additive columns, so a deployment that never sets them behaves exactly as
    # before: a NULL admin_token means "no management capability was ever minted
    # for this poll", and require_manage() (auth.py) treats NULL as matching
    # nothing.
    #
    # Deliberately NOT backfilled. docs/design/multitenancy-hosting.md sketched
    # `admin_token = new_token()` for existing rows; a token minted at migration
    # time is mailed to nobody and read by nobody, so it would grant exactly zero
    # authority while permanently marking the row as capability-managed. NULL is
    # the honest state: those polls stay header-owned, exactly as before.
    _ensure_column(cursor, "sched_polls", "admin_token", "admin_token VARCHAR(64) NULL")
    # Same width as creator_id on purpose: in header mode owner_id carries that
    # same uid, so a different width would change which uids are storable.
    _ensure_column(cursor, "sched_polls", "owner_id", "owner_id VARCHAR(36) NULL")
    _ensure_column(cursor, "sched_polls", "creator_email", "creator_email VARCHAR(255) NULL")
    # The NULL is the load-bearing part, so it is measured rather than assumed.
    # On MySQL 5.7 (explicit_defaults_for_timestamp=OFF is its default) the bare
    # spelling is a trap whose form depends on the table: added to a table with
    # no other TIMESTAMP column it becomes
    #     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    # and stamps every existing row -- the fail-open state obligation A2 exists
    # to prevent, arrived at by a migration that reads as additive; added to
    # sched_polls, which already has created_at TIMESTAMP, it fails outright with
    # ERROR 1067 instead. Measured on 5.7.44: TIMESTAMP NULL and TIMESTAMP NULL
    # DEFAULT NULL both land as `NULL DEFAULT NULL` with existing rows NULL --
    # identical, so `DEFAULT NULL` is documentation, not protection, and it is
    # spelled out so nobody "simplifies" the NULL away.
    #
    # MariaDB cannot reproduce either outcome: it accepts
    # explicit_defaults_for_timestamp and ignores it for DDL, so even the bare
    # spelling lands NULL-able there. Which is exactly why the mariadb:11 CI job
    # proves nothing about this, and why the reasoning above is written from the
    # 5.7 measurement rather than from the family most people run.
    _ensure_column(cursor, "sched_polls", "manage_verified_at",
                   "manage_verified_at TIMESTAMP NULL DEFAULT NULL")
    # UNIQUE, because a management capability denotes exactly one poll: two rows
    # sharing a value would let each holder manage both, silently. NULLs are
    # exempt from UNIQUE on both dialects, so pre-existing rows are unaffected.
    _ensure_index(cursor, "sched_polls", "idx_sched_polls_admin_token",
                  "CREATE UNIQUE INDEX idx_sched_polls_admin_token ON sched_polls (admin_token)")
    conn.commit()
    cursor.close()
    conn.close()


def get_slot_sequence(slot_id: str) -> int:
    """Current iMIP SEQUENCE for a slot (0 if never sent)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT ical_sequence FROM sched_poll_slots WHERE id = %s", (slot_id,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return int(row[0]) if row and row[0] is not None else 0


def bump_slot_sequence(slot_id: str) -> int:
    """Increment and return a slot's iMIP SEQUENCE (call before CANCEL/re-REQUEST)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE sched_poll_slots SET ical_sequence = COALESCE(ical_sequence, 0) + 1 WHERE id = %s", (slot_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return get_slot_sequence(slot_id)


# -- Polls --

def create_poll(creator_id: str, title: str, description: str | None, mode: str, timezone: str, slots: list[dict],
                owner_id: str | None = None, creator_email: str | None = None) -> dict:
    """Create a poll, minting the management capability that authorises it.

    `owner_id` and `creator_email` are the accountless-tenancy fields (#29); both
    default to NULL, so a caller that knows nothing about them writes the row it
    always wrote. `owner_id` is the authenticated owner (the header uid in ETH,
    an account id once accounts exist); `creator_email` is where a management
    link was sent, which only the hosted accountless flow does (#30).

    Every new poll gets an `admin_token`, in every auth mode, so authorization
    never has to ask which mode produced a row. In header mode nobody is ever
    shown the token, so it grants nothing -- see init_schema() for why
    pre-existing rows keep NULL instead of one.

    `creator_email` must be a normalized address (`http.valid_email` caps one at
    RFC 5321's 254 octets, so it always fits the column). Callers taking it from
    a form must validate, not just check it is present: MySQL strict mode raises
    on an over-long value, and a 500 is the wrong answer to a long address.
    """
    poll_id = new_id()
    public_token = new_token()
    admin_token = new_token()  # same entropy as every other capability (ADR-0001)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO sched_polls (id, creator_id, title, description, mode, timezone, public_token,"
        " admin_token, owner_id, creator_email)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (poll_id, creator_id, title, description, mode, timezone, public_token,
         admin_token, owner_id, creator_email),
    )
    slot_rows = []
    for s in slots:
        slot_id = new_id()
        cursor.execute(
            "INSERT INTO sched_poll_slots (id, poll_id, date, start_time, end_time) VALUES (%s, %s, %s, %s, %s)",
            (slot_id, poll_id, s["date"], s.get("start_time"), s.get("end_time")),
        )
        slot_rows.append({"id": slot_id, "date": s["date"], "start_time": s.get("start_time"), "end_time": s.get("end_time")})
    conn.commit()
    cursor.close()
    conn.close()
    return {"id": poll_id, "creator_id": creator_id, "title": title, "description": description,
            "mode": mode, "timezone": timezone, "public_token": public_token, "status": "open",
            "decided_slot_id": None, "admin_token": admin_token, "owner_id": owner_id,
            "creator_email": creator_email, "manage_verified_at": None, "slots": slot_rows}


def get_poll(poll_id: str) -> dict | None:
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM sched_polls WHERE id = %s", (poll_id,))
    poll = cursor.fetchone()
    if not poll:
        cursor.close()
        conn.close()
        return None
    cursor.execute("SELECT * FROM sched_poll_slots WHERE poll_id = %s ORDER BY date, start_time", (poll_id,))
    poll["slots"] = _readable_slots(cursor.fetchall())
    cursor.close()
    conn.close()
    return poll


def get_poll_by_token(public_token: str) -> dict | None:
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM sched_polls WHERE public_token = %s", (public_token,))
    poll = cursor.fetchone()
    if not poll:
        cursor.close()
        conn.close()
        return None
    cursor.execute("SELECT * FROM sched_poll_slots WHERE poll_id = %s ORDER BY date, start_time", (poll["id"],))
    poll["slots"] = _readable_slots(cursor.fetchall())
    cursor.close()
    conn.close()
    return poll


# -- Accountless management (issue #30) -------------------------------------
#
# The three operations `/manage/<admin_token>` needs, kept in the data layer
# rather than in the route module because each one is a state change on the
# capability itself, and a route is the wrong place to make one look routine.


def get_poll_by_admin_token(admin_token: str | None) -> dict | None:
    """The poll a management capability denotes, or None.

    Mirrors `get_poll_by_token` and inherits its reason for re-reading the
    slots: the owner surface needs them for convergence and for the .ics.

    `None` in, `None` out -- an absent token is not a lookup for the empty
    string, which is what a caller that forgot to check would otherwise ask for.

    Resolving by token is *not* authorization. A row with a NULL admin_token --
    every poll that predates #29 -- is unreachable from here by construction, and
    for the rest the caller still calls `auth.require_manage`, which compares in
    constant time and fails closed.
    """
    if not admin_token:
        return None
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM sched_polls WHERE admin_token = %s", (admin_token,))
    poll = cursor.fetchone()
    if not poll:
        cursor.close()
        conn.close()
        return None
    cursor.execute("SELECT * FROM sched_poll_slots WHERE poll_id = %s ORDER BY date, start_time", (poll["id"],))
    poll["slots"] = _readable_slots(cursor.fetchall())
    cursor.close()
    conn.close()
    return poll


def rotate_admin_token(poll_id: str, expected: str) -> str | None:
    """Replace this poll's management capability with a fresh one, and return it.

    **Single use.** This is what makes the emailed link a magic link rather than
    a permanent bearer credential: the exchange consumes the token and hands back
    the new one inside the session cookie, so the value that travelled through an
    inbox stops working the moment anyone opens it. The same write retires every
    older capability cookie, because such a cookie *is* a capability.

    **Compare-and-swap, not an unconditional write.** `expected` is the token the
    caller presented, and the `WHERE` clause requires it to still be the row's
    token. Two exchanges racing on the same link therefore produce exactly one
    winner and one refusal, instead of two winners whose first session cookie is
    dead the moment it is minted. An unconditional `WHERE admin_token IS NOT
    NULL` cannot express that: it reports success to the loser, who would mint a
    session around a capability that has already been replaced -- a guard that
    reads as if it works while being unreachable.

    Returns None when `expected` no longer matches, which includes a row that
    carries no capability at all (NULL means "no management capability was ever
    minted for this poll", see `init_schema`) rather than handing such a row a
    credential it was deliberately created without. The caller must treat None as
    a refusal, not as "here is your new token".
    """
    token = new_token()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE sched_polls SET admin_token = %s WHERE id = %s AND admin_token = %s",
        (token, poll_id, expected),
    )
    conn.commit()
    rotated = cursor.rowcount > 0
    cursor.close()
    conn.close()
    return token if rotated else None


def mark_manage_verified(poll_id: str) -> bool:
    """Stamp `manage_verified_at` the first time a manage link is opened.

    True only for the write that actually set it, so a caller can tell "this is
    the first open" from "it was already open" -- the log line and the copy in the
    UI differ. The `IS NULL` guard is in the SQL rather than in a read-then-write,
    so two simultaneous first opens cannot both claim to be first and the column
    keeps the *first* time rather than the last.

    This is the write only. The **send-gate** -- refusing to put bytes in a third
    party's inbox until this column is set -- is obligation A2 and belongs to #31;
    nothing here gates anything, deliberately, so #31 can add that gate without
    re-deciding who may manage a poll.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE sched_polls SET manage_verified_at = CURRENT_TIMESTAMP"
        " WHERE id = %s AND manage_verified_at IS NULL",
        (poll_id,),
    )
    conn.commit()
    first = cursor.rowcount > 0
    cursor.close()
    conn.close()
    return first


def list_polls_by_creator_email(email: str) -> list[dict]:
    """Polls whose management link was sent to `email`, newest first.

    Backs the "email me a new link" request in `KAIROS_AUTH=capability` (#30),
    where a spent single-use link is recoverable only by re-mailing it to the
    address that already owns the poll.

    Filtered in SQL rather than by filtering `list_polls()` in Python, because the
    unscoped call reads every poll in the deployment into memory and this route
    is unauthenticated: it is charged to the peer by #37's `send` budget and must
    not be a whole-table scan on top of that. No index on `creator_email`, so this
    is a scan of the smallest table in the schema — the ~21k-poll ceiling #51
    documents — and the caller caps how many rows it will act on.

    Returns rows *without* slots: nothing here renders or serialises them.
    """
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM sched_polls WHERE creator_email = %s ORDER BY created_at DESC",
        (email,),
    )
    polls = cursor.fetchall()
    cursor.close()
    conn.close()
    return polls


def list_polls(creator_id: str | None = None) -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    if creator_id:
        cursor.execute("SELECT * FROM sched_polls WHERE creator_id = %s ORDER BY created_at DESC", (creator_id,))
    else:
        cursor.execute("SELECT * FROM sched_polls ORDER BY created_at DESC")
    polls = cursor.fetchall()
    for poll in polls:
        cursor.execute("SELECT COUNT(*) as cnt FROM sched_responses WHERE poll_id = %s", (poll["id"],))
        poll["response_count"] = cursor.fetchone()["cnt"]
    cursor.close()
    conn.close()
    return polls


def add_slots_capped(poll_id: str, slots: list[dict], cap: int) -> list[dict]:
    """Append new slots to a poll, atomic in count+check+insert.

    The **only** public slot-insertion entry point: finding 1 of PR #92
    round-2 noted that a plain `add_slots` beside this function left the race
    one bypass away (the capability-console `/manage/{id}/edit` called it,
    skipping the atomic guard — 128 concurrent workers reached **3,610
    slots** against a 1,000-cap poll on the pre-fix tree). So the bare
    helper has been **removed**, not just privatised: an ImportError at
    module-load is a louder refusal than a lint note. Every surface -- the
    web owner form, the capability console, REST and MCP -- calls this one
    function, with `cap=settings.max_slots_per_poll()`.

    The per-poll cap on #70 used to be checked in the route before calling
    a bare `add_slots`, and the PR #92 adversarial-review pass measured the race:
    **64 concurrent `POST /api/polls/{id}/slots` calls against the same key
    took the poll to 36,100 slots** on a 1,000-cap deployment, because every
    one of the 64 workers read the same `existing_count`, saw it was under
    the cap, and raced into insert.

    Closed at the data layer per dialect, so the route is just the caller:

      * **SQLite** — opens with `BEGIN IMMEDIATE`, which escalates the
        connection's write lock up front. No two writers can both be past
        the COUNT at the same time, and the second one's `BEGIN IMMEDIATE`
        blocks until the first commits (or times out on `busy_timeout`).
      * **MySQL / MariaDB** — `SELECT ... FOR UPDATE` on the poll row inside
        the transaction, so the second request serialises on the row lock
        rather than reading a stale count. `autocommit=False` is the default
        in `dbconn`, so a plain SELECT would be inside a transaction already
        but would not block a concurrent writer; `FOR UPDATE` is the piece
        that makes count+check+insert one critical section.
      * **Durable-Object SQLite** (draft #79, `IS_DO_SQLITE` branch in
        `dbconn`) — requests are serialised per DO for synchronous code,
        so the explicit `BEGIN IMMEDIATE` is redundant there but harmless.

    Raises `HTTPException(400)` with `capability.slot_cap_refusal`'s sentence,
    which is the one every surface already uses so an agent reading the
    refusal sees the same text REST / MCP / web all return.
    """
    from kairos import capability
    conn = get_connection()
    cursor = conn.cursor()
    try:
        if IS_SQLITE:
            # Escalate to a write lock up front, so count+check+insert is one
            # critical section. Python's sqlite3 module defers to its own
            # transaction machinery otherwise; an explicit BEGIN IMMEDIATE is
            # what makes a COUNT visible to this writer alone.
            cursor.execute("BEGIN IMMEDIATE")
            cursor.execute(
                "SELECT COUNT(*) FROM sched_poll_slots WHERE poll_id = %s", (poll_id,)
            )
        else:
            # MySQL/MariaDB: lock the poll row for the duration, so a
            # concurrent writer serialises on it rather than reading a stale
            # count. The row itself does not change; `FOR UPDATE` is the
            # smallest lock that covers the count+check+insert window.
            cursor.execute(
                "SELECT id FROM sched_polls WHERE id = %s FOR UPDATE", (poll_id,)
            )
            cursor.execute(
                "SELECT COUNT(*) FROM sched_poll_slots WHERE poll_id = %s", (poll_id,)
            )
        existing_count = cursor.fetchone()[0]
        if cap > 0 and existing_count + len(slots) > cap:
            conn.rollback()
            total = existing_count + len(slots)
            # The same sentence `expand_new_dates` raised before the race
            # window opened. `slot_cap_refusal` returns None when `cap` is
            # 0 (disabled) or the total fits, which the guard above already
            # covered, so the fallback is a defence-in-depth sentence.
            msg = capability.slot_cap_refusal(total, 0) or (
                f"That edit would bring the poll to {total:,} slots, over the "
                f"per-poll limit of {cap:,}."
            )
            raise HTTPException(400, msg)
        slot_rows = []
        for s in slots:
            slot_id = new_id()
            cursor.execute(
                "INSERT INTO sched_poll_slots (id, poll_id, date, start_time, end_time) "
                "VALUES (%s, %s, %s, %s, %s)",
                (slot_id, poll_id, s["date"], s.get("start_time"), s.get("end_time")),
            )
            slot_rows.append({"id": slot_id, "date": s["date"],
                              "start_time": s.get("start_time"), "end_time": s.get("end_time")})
        conn.commit()
        return slot_rows
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        cursor.close()
        conn.close()


def update_poll(poll_id: str, **fields) -> bool:
    allowed = {"title", "description", "timezone", "status", "decided_slot_id"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return False
    conn = get_connection()
    cursor = conn.cursor()
    set_clause = ", ".join(f"{k} = %s" for k in updates)
    cursor.execute(f"UPDATE sched_polls SET {set_clause} WHERE id = %s", (*updates.values(), poll_id))
    conn.commit()
    affected = cursor.rowcount
    cursor.close()
    conn.close()
    return affected > 0


def delete_poll(poll_id: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sched_polls WHERE id = %s", (poll_id,))
    conn.commit()
    affected = cursor.rowcount
    cursor.close()
    conn.close()
    return affected > 0


# -- Responses --

def _fetch_response(where: str, params: tuple) -> dict | None:
    """Fetch one response (+ slot availabilities) matching the WHERE clause."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        f"SELECT * FROM sched_responses WHERE {where} ORDER BY created_at DESC LIMIT 1",  # noqa: S608 — where is a literal
        params,
    )
    resp = cursor.fetchone()
    if resp:
        cursor.execute("SELECT slot_id, availability FROM sched_response_slots WHERE response_id = %s", (resp["id"],))
        resp["slot_availabilities"] = {r["slot_id"]: r["availability"] for r in cursor.fetchall()}
    cursor.close()
    conn.close()
    return resp


def find_response_by_email(poll_id: str, email: str) -> dict | None:
    """Find existing response by email for upsert logic."""
    if not email:
        return None
    return _fetch_response("poll_id = %s AND respondent_email = %s", (poll_id, email))


def find_response_by_user(poll_id: str, user_id: str) -> dict | None:
    """Find the authed user's existing response to a poll."""
    return _fetch_response("poll_id = %s AND user_id = %s", (poll_id, user_id))


def get_response(response_id: str) -> dict | None:
    """Load one response by id (for the anonymous browser-cookie path)."""
    return _fetch_response("id = %s", (response_id,))


def mark_invite_notified(invite_id: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE sched_invites SET notified_at = CURRENT_TIMESTAMP WHERE id = %s", (invite_id,))
    conn.commit()
    cursor.close()
    conn.close()


def mark_response_notified(response_id: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE sched_responses SET notified_at = CURRENT_TIMESTAMP WHERE id = %s", (response_id,))
    conn.commit()
    cursor.close()
    conn.close()


_UPSERT_AVAILABILITY = (
    "INSERT INTO sched_response_slots (response_id, slot_id, availability) VALUES (%s, %s, %s) "
    + ("ON CONFLICT(response_id, slot_id) DO UPDATE SET availability = excluded.availability"
       if IS_SQLITE else "ON DUPLICATE KEY UPDATE availability = VALUES(availability)"))


def update_response(response_id: str, name: str, slot_availabilities: dict[str, str],
                    user_id: str | None = None, email: str | None = None) -> dict:
    """Update an existing response (name + slot availabilities).

    user_id/email, when known, are bound to the response so later visits
    resolve it by account or email even if it was created anonymously.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE sched_responses SET respondent_name = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s", (name, response_id))
    if user_id:
        cursor.execute("UPDATE sched_responses SET user_id = %s WHERE id = %s", (user_id, response_id))
    if email:
        cursor.execute("UPDATE sched_responses SET respondent_email = %s WHERE id = %s", (email, response_id))
    for slot_id, availability in slot_availabilities.items():
        cursor.execute(_UPSERT_AVAILABILITY, (response_id, slot_id, availability))
    conn.commit()
    cursor.close()
    conn.close()
    return {"id": response_id, "respondent_name": name, "slot_availabilities": slot_availabilities}


def add_response(poll_id: str, name: str, email: str | None, slot_availabilities: dict[str, str],
                 user_id: str | None = None, invite_id: str | None = None) -> dict:
    response_id = new_id()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO sched_responses (id, poll_id, respondent_name, respondent_email, user_id, invite_id) VALUES (%s, %s, %s, %s, %s, %s)",
        (response_id, poll_id, name, email, user_id, invite_id),
    )
    for slot_id, availability in slot_availabilities.items():
        cursor.execute(
            "INSERT INTO sched_response_slots (response_id, slot_id, availability) VALUES (%s, %s, %s)",
            (response_id, slot_id, availability),
        )
    conn.commit()
    cursor.close()
    conn.close()
    return {"id": response_id, "poll_id": poll_id, "respondent_name": name,
            "respondent_email": email, "slot_availabilities": slot_availabilities}


def get_responses(poll_id: str) -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM sched_responses WHERE poll_id = %s ORDER BY created_at", (poll_id,))
    responses = cursor.fetchall()
    for resp in responses:
        cursor.execute("SELECT slot_id, availability FROM sched_response_slots WHERE response_id = %s", (resp["id"],))
        resp["slot_availabilities"] = {r["slot_id"]: r["availability"] for r in cursor.fetchall()}
    cursor.close()
    conn.close()
    return responses


# -- Invites --

def create_invite(poll_id: str, email: str, required: bool = True, name: str | None = None) -> dict:
    invite_id = new_id()
    token = new_token()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO sched_invites (id, poll_id, email, token, required, name)"
        " VALUES (%s, %s, %s, %s, %s, %s)",
        (invite_id, poll_id, email, token, required, name),
    )
    conn.commit()
    cursor.close()
    conn.close()
    return {"id": invite_id, "poll_id": poll_id, "email": email, "token": token,
            "responded": False, "required": required, "name": name}


def update_invite(poll_id: str, invite_id: str, name: str | None = None,
                  email: str | None = None,
                  required: bool | None = None) -> bool:
    """Update one invite's contact/required flag, iff it belongs to `poll_id`.

    The `AND poll_id = %s` in the WHERE is the IDOR guard (PR #85 round-2
    finding): every route that reaches this call has already authorized the
    `poll_id` path parameter, but the invite id came from the same URL and is
    not checked against the row's `poll_id` column -- so a route that forgets
    to pass the parent would turn its own authorized caller into one that may
    edit any invite on the instance. A mismatch answers exactly like a missing
    id (rowcount 0, False), so callers that render 404 for "no such invite"
    render the same 404 for "wrong parent" without a second branch -- and
    without the existence oracle a 403-vs-404 split would create.
    """
    sets, params = [], []
    if name is not None:
        sets.append("name = %s")
        params.append(name or None)
    if email is not None:
        sets.append("email = %s")
        params.append(email)
    if required is not None:
        sets.append("required = %s")
        params.append(required)
    if not sets:
        return False
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        f"UPDATE sched_invites SET {', '.join(sets)} WHERE id = %s AND poll_id = %s",
        (*params, invite_id, poll_id))
    updated = cursor.rowcount > 0
    conn.commit()
    cursor.close()
    conn.close()
    return updated


def update_response_contact(poll_id: str, response_id: str,
                            name: str | None = None,
                            email: str | None = None,
                            required: bool | None = None) -> bool:
    """Update one response's contact/required flag, iff it belongs to `poll_id`.

    Same IDOR guard as `update_invite` -- see that function's docstring.
    """
    sets, params = [], []
    if name is not None:
        sets.append("respondent_name = %s")
        params.append(name)
    if email is not None:
        sets.append("respondent_email = %s")
        params.append(email)
    if required is not None:
        sets.append("required = %s")
        params.append(required)
    if not sets:
        return False
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        f"UPDATE sched_responses SET {', '.join(sets)} WHERE id = %s AND poll_id = %s",
        (*params, response_id, poll_id))
    updated = cursor.rowcount > 0
    conn.commit()
    cursor.close()
    conn.close()
    return updated


def get_invite_by_token(token: str) -> dict | None:
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM sched_invites WHERE token = %s", (token,))
    invite = cursor.fetchone()
    cursor.close()
    conn.close()
    return invite


def get_invites(poll_id: str) -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM sched_invites WHERE poll_id = %s ORDER BY sent_at", (poll_id,))
    invites = cursor.fetchall()
    cursor.close()
    conn.close()
    return invites


def delete_invite(poll_id: str, invite_id: str) -> bool:
    """Delete one invite, iff it belongs to `poll_id`. See `update_invite`."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sched_invites WHERE id = %s AND poll_id = %s",
                   (invite_id, poll_id))
    deleted = cursor.rowcount > 0
    conn.commit()
    cursor.close()
    conn.close()
    return deleted


def delete_response(poll_id: str, response_id: str) -> bool:
    """Delete one response (and its response_slots), iff it belongs to `poll_id`.

    The belongs-to-poll check is a SELECT, not a WHERE on each DELETE: the
    response-slots DELETE keys on `response_id` only (its table has no poll_id
    column, so the FK cascade from the responses row is the only link to a
    poll), and running it unconditionally for the wrong parent would still
    wipe the child rows even though the response row itself would not go. The
    pre-check turns the whole call into a no-op on mismatch, so a caller sees
    the same rowcount-0 answer as "no such response" -- same IDOR guard as
    `update_invite`, see that docstring.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM sched_responses WHERE id = %s AND poll_id = %s",
        (response_id, poll_id),
    )
    if cursor.fetchone() is None:
        cursor.close()
        conn.close()
        return False
    cursor.execute("DELETE FROM sched_response_slots WHERE response_id = %s", (response_id,))
    cursor.execute("DELETE FROM sched_responses WHERE id = %s AND poll_id = %s",
                   (response_id, poll_id))
    deleted = cursor.rowcount > 0
    conn.commit()
    cursor.close()
    conn.close()
    return deleted


def mark_invite_responded(invite_id: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE sched_invites SET responded = TRUE WHERE id = %s", (invite_id,))
    conn.commit()
    cursor.close()
    conn.close()


# -- Notifications --

def create_notification(user_id: str, poll_id: str, notif_type: str, message: str) -> str:
    notif_id = new_id()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO sched_notifications (id, user_id, poll_id, type, message) VALUES (%s, %s, %s, %s, %s)",
        (notif_id, user_id, poll_id, notif_type, message),
    )
    conn.commit()
    cursor.close()
    conn.close()
    return notif_id


def get_notifications(user_id: str, unread_only: bool = False) -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    if unread_only:
        cursor.execute("SELECT * FROM sched_notifications WHERE user_id = %s AND is_read = FALSE ORDER BY created_at DESC", (user_id,))
    else:
        cursor.execute("SELECT * FROM sched_notifications WHERE user_id = %s ORDER BY created_at DESC LIMIT 50", (user_id,))
    notifs = cursor.fetchall()
    cursor.close()
    conn.close()
    return notifs


def log_contact(poll_id: str, email: str, kind: str, invite_id: str | None = None):
    """Audit trail: record every outbound mail for a poll participant."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO sched_contact_log (id, poll_id, email, invite_id, kind) VALUES (%s, %s, %s, %s, %s)",
        (new_id(), poll_id, email.strip().lower(), invite_id, kind),
    )
    conn.commit()
    cursor.close()
    conn.close()


def get_contact_log(poll_id: str) -> list[dict]:
    """All outbound contacts for a poll, newest first."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM sched_contact_log WHERE poll_id = %s ORDER BY sent_at DESC",
        (poll_id,),
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


def mark_all_notifications_read(user_id: str) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE sched_notifications SET is_read = TRUE WHERE user_id = %s AND is_read = FALSE", (user_id,))
    conn.commit()
    affected = cursor.rowcount
    cursor.close()
    conn.close()
    return affected


def mark_notification_read(notif_id: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE sched_notifications SET is_read = TRUE WHERE id = %s", (notif_id,))
    conn.commit()
    affected = cursor.rowcount
    cursor.close()
    conn.close()
    return affected > 0


def get_unread_notification_count(user_id: str) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM sched_notifications WHERE user_id = %s AND is_read = FALSE", (user_id,))
    count = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return count


# -- Owner-minted API tokens (issue #82) ------------------------------------
#
# The signed-in owner mints bearer credentials from the admin panel. Only the
# sha256 hash is stored; the plaintext is shown once at mint time and the
# `prefix` column carries 12 non-sensitive chars for the panel's list.
#
# The write side lives here; the authentication/hashing seam lives in
# `kairos.apitokens` so the same resolver can back `/api` today and `/mcp`
# tomorrow (issue #83) without a second DB module to forget.


def insert_api_token(token_id: str, owner_uid: str, name: str, token_hash: str,
                     prefix: str, scopes: str, expires_at, created_at=None) -> None:
    """Persist one minted token. `expires_at` and (optional) `created_at` are
    `datetime`s, `scopes` is a comma-joined grant string over `scoping.SCOPES`
    (validated by the caller).

    `created_at` is written explicitly rather than inheriting the column's
    `CURRENT_TIMESTAMP` default so every time column on this row is in the
    same dialect as `dbconn.db_now()` — the comparison `resolve_token` uses
    for expiry. SQLite's `CURRENT_TIMESTAMP` is UTC and MySQL's is session-
    local, so a mix of defaulted and Python-computed values would read back as
    different clocks on MySQL/MariaDB.
    """
    conn = get_connection()
    cursor = conn.cursor()
    if created_at is None:
        from kairos.dbconn import db_now
        created_at = db_now()
    cursor.execute(
        "INSERT INTO sched_api_tokens (id, owner_uid, name, token_hash, prefix,"
        " scopes, created_at, expires_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (token_id, owner_uid, name, token_hash, prefix, scopes, created_at, expires_at),
    )
    conn.commit()
    cursor.close()
    conn.close()


def get_api_token_by_hash(token_hash: str) -> dict | None:
    """The token row for a presented credential's sha256, or None.

    The caller hashed the bearer; this is a straight equality lookup on an
    indexed (UNIQUE) column, so the query is deterministic and timing-safe at
    the row level — the only way a lookup differs from a miss is the cost of
    one hashing pass the caller has already paid. Nothing here compares the
    plaintext; nothing here can, because the plaintext is not stored.

    Returns the whole row (revoked/expired tokens included); the caller is
    `kairos.apitokens.resolve_token`, which decides whether each state is a
    401 and in what wording — the wording is deliberately the same across
    expired / revoked / not-minted, so a probing caller cannot tell the three
    apart.
    """
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM sched_api_tokens WHERE token_hash = %s", (token_hash,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return row


def list_api_tokens(owner_uid: str) -> list[dict]:
    """Every token this owner has minted, newest first. Panel list."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM sched_api_tokens WHERE owner_uid = %s ORDER BY created_at DESC",
        (owner_uid,),
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


def revoke_api_token(token_id: str, owner_uid: str) -> bool:
    """Mark a token revoked, iff it belongs to this owner and is not already revoked.

    The `owner_uid` guard is in SQL rather than in a read-then-write, so an owner
    cannot revoke someone else's token by guessing an id — the row stays unchanged
    and the caller gets False. Idempotent on a second click: the second UPDATE
    matches zero rows (`revoked_at IS NULL` is already false), and the API panel
    reads that as "already revoked" rather than as a fresh action.
    """
    from kairos.dbconn import db_now
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE sched_api_tokens SET revoked_at = %s"
        " WHERE id = %s AND owner_uid = %s AND revoked_at IS NULL",
        (db_now(), token_id, owner_uid),
    )
    conn.commit()
    revoked = cursor.rowcount > 0
    cursor.close()
    conn.close()
    return revoked


def touch_api_token_last_used(token_id: str) -> None:
    """Stamp `last_used_at = now()` on one row. Not idempotent; the caller throttles.

    Separate from `get_api_token_by_hash` on purpose: the read happens on every
    authenticated request and is hot; the write happens at most once per minute
    per token (`kairos.apitokens._should_touch`) and would otherwise be the
    second SQLite write for every API call — enough to double the surface's
    write rate at no useful fidelity, since `last_used_at` is only for the
    panel's "last used" column.
    """
    from kairos.dbconn import db_now
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE sched_api_tokens SET last_used_at = %s WHERE id = %s",
        (db_now(), token_id),
    )
    conn.commit()
    cursor.close()
    conn.close()
