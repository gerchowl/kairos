import re
import secrets
import uuid

from kairos.dbconn import IS_SQLITE, get_connection  # noqa: F401  (re-exported)

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
]


def new_id() -> str:
    return str(uuid.uuid4())


def new_token() -> str:
    return secrets.token_urlsafe(32)


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
    conn.commit()
    cursor.close()
    conn.close()


# -- Polls --

def create_poll(creator_id: str, title: str, description: str | None, mode: str, timezone: str, slots: list[dict]) -> dict:
    poll_id = new_id()
    public_token = new_token()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO sched_polls (id, creator_id, title, description, mode, timezone, public_token) VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (poll_id, creator_id, title, description, mode, timezone, public_token),
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
            "decided_slot_id": None, "slots": slot_rows}


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
    poll["slots"] = cursor.fetchall()
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
    poll["slots"] = cursor.fetchall()
    cursor.close()
    conn.close()
    return poll


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


def add_slots(poll_id: str, slots: list[dict]) -> list[dict]:
    """Append new slots to an existing poll (additive edit — responses keep)."""
    conn = get_connection()
    cursor = conn.cursor()
    slot_rows = []
    for s in slots:
        slot_id = new_id()
        cursor.execute(
            "INSERT INTO sched_poll_slots (id, poll_id, date, start_time, end_time) VALUES (%s, %s, %s, %s, %s)",
            (slot_id, poll_id, s["date"], s.get("start_time"), s.get("end_time")),
        )
        slot_rows.append({"id": slot_id, "date": s["date"],
                          "start_time": s.get("start_time"), "end_time": s.get("end_time")})
    conn.commit()
    cursor.close()
    conn.close()
    return slot_rows


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


def update_invite(invite_id: str, name: str | None = None, email: str | None = None,
                  required: bool | None = None) -> bool:
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
    cursor.execute(f"UPDATE sched_invites SET {', '.join(sets)} WHERE id = %s",
                   (*params, invite_id))
    updated = cursor.rowcount > 0
    conn.commit()
    cursor.close()
    conn.close()
    return updated


def update_response_contact(response_id: str, name: str | None = None,
                            email: str | None = None,
                            required: bool | None = None) -> bool:
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
    cursor.execute(f"UPDATE sched_responses SET {', '.join(sets)} WHERE id = %s",
                   (*params, response_id))
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


def delete_invite(invite_id: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sched_invites WHERE id = %s", (invite_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    cursor.close()
    conn.close()
    return deleted


def delete_response(response_id: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sched_response_slots WHERE response_id = %s", (response_id,))
    cursor.execute("DELETE FROM sched_responses WHERE id = %s", (response_id,))
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
