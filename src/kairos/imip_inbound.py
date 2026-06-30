"""Inbound iMIP (RFC 6047): ingest METHOD:REPLY emails and fold each
attendee's PARTSTAT back into the poll.

Transport is an IMAP poll of the ORGANIZER mailbox (Lars's choice). The
network fetch (poll_mailbox) is a thin shell around the pure, fail-closed
parse/apply core below — that core is what the tests exercise.

Fail-closed: a reply is applied ONLY when its UID resolves to a live slot AND
its attendee address matches a known invite on that poll. Anything else is a
silent no-op. See docs/design/reverse-calendar-imip.md.
"""

import re

from kairos import settings
from kairos.db import (
    add_response,
    find_response_by_email,
    get_invites,
    get_poll,
    get_slot_sequence,
    mark_invite_responded,
    update_response,
)
from kairos.ics import parse_slot_uid

# PARTSTAT (RFC 5545) -> Kairos availability. Other values (NEEDS-ACTION,
# DELEGATED) carry no decision and are ignored.
_PARTSTAT = {"ACCEPTED": "yes", "TENTATIVE": "maybe", "DECLINED": "no"}

_MAILTO = re.compile(r"mailto:([^\s;:>]+)", re.I)
_PARTSTAT_RE = re.compile(r"PARTSTAT=([A-Z-]+)", re.I)


def _unfold(text: str) -> str:
    return text.replace("\r\n ", "").replace("\r\n\t", "").replace("\n ", "").replace("\n\t", "")


def parse_reply(ics_text: str) -> dict | None:
    """Pull (uid, email, partstat, sequence) out of a METHOD:REPLY body.

    Returns None unless it is a REPLY carrying a UID and an ATTENDEE PARTSTAT."""
    lines = _unfold(ics_text).replace("\r\n", "\n").split("\n")
    if not any(line.upper().startswith("METHOD:REPLY") for line in lines):
        return None
    uid = email = partstat = None
    sequence = 0
    for line in lines:
        upper = line.upper()
        if upper.startswith("UID:"):
            uid = line[4:].strip()
        elif upper.startswith("SEQUENCE:"):
            try:
                sequence = int(line.split(":", 1)[1].strip())
            except ValueError:
                sequence = 0
        elif upper.startswith("ATTENDEE") and "PARTSTAT" in upper:
            m_ps, m_mail = _PARTSTAT_RE.search(line), _MAILTO.search(line)
            if m_ps and m_mail:
                partstat = m_ps.group(1).upper()
                email = m_mail.group(1).strip()
    if not (uid and email and partstat):
        return None
    return {"uid": uid, "email": email, "partstat": partstat, "sequence": sequence}


def apply_reply(reply: dict) -> bool:
    """Fold a parsed reply into the poll. True iff it was applied.

    Fail-closed: unknown UID/slot, stale SEQUENCE, undecided PARTSTAT, or an
    address that isn't an invited attendee on this poll -> no-op."""
    ids = parse_slot_uid(reply["uid"])
    if not ids:
        return False
    poll_id, slot_id = ids
    availability = _PARTSTAT.get(reply["partstat"])
    if availability is None:
        return False

    poll = get_poll(poll_id)
    if not poll or not any(s["id"] == slot_id for s in poll["slots"]):
        return False
    # Drop replies to a superseded REQUEST.
    if reply.get("sequence", 0) < get_slot_sequence(slot_id):
        return False

    email = reply["email"].strip().lower()
    invite = next((i for i in get_invites(poll_id)
                   if (i.get("email") or "").strip().lower() == email), None)
    if not invite:
        return False  # only known invitees can drive the poll

    existing = find_response_by_email(poll_id, email)
    if existing:
        update_response(existing["id"], existing["respondent_name"],
                        {slot_id: availability}, email=email)
    else:
        add_response(poll_id, invite.get("name") or email, email,
                     {slot_id: availability}, invite_id=invite["id"])
        mark_invite_responded(invite["id"])
    return True


def _calendar_bodies(raw_bytes: bytes):
    """Yield text/calendar payloads from a raw RFC 822 message."""
    import email as email_mod
    msg = email_mod.message_from_bytes(raw_bytes)
    for part in msg.walk():
        if part.get_content_type() == "text/calendar":
            payload = part.get_payload(decode=True)
            if payload:
                charset = part.get_content_charset() or "utf-8"
                yield payload.decode(charset, errors="replace")


def poll_mailbox() -> int:
    """IMAP-poll the ORGANIZER mailbox once; apply unseen REPLYs. Returns the
    count applied. Opt-in (KAIROS_IMIP + IMAP host); fail-closed per message."""
    if not (settings.IMIP_ENABLED and settings.IMAP_HOST):
        return 0
    import imaplib
    applied = 0
    try:
        client = imaplib.IMAP4_SSL(settings.IMAP_HOST, settings.IMAP_PORT)
        client.login(settings.IMAP_USER, settings.IMAP_PASSWORD)
        client.select(settings.IMAP_MAILBOX)
        _, data = client.search(None, "UNSEEN")
        for num in (data[0] or b"").split():
            try:
                _, fetched = client.fetch(num, "(RFC822)")
                raw = fetched[0][1] if fetched and fetched[0] else None
                if not raw:
                    continue
                for body in _calendar_bodies(raw):
                    reply = parse_reply(body)
                    if reply and apply_reply(reply):
                        applied += 1
                client.store(num, "+FLAGS", "\\Seen")
            except Exception:
                continue  # one bad message must not stall the poll
        client.logout()
    except Exception:
        return applied
    return applied
