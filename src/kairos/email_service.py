"""Outbound mail for Kairos.

Identity model: all mail is authenticated and sent AS the app's service
account (SMTP_USER / SMTP_FROM) — never as the poll owner, which would fail
SPF/DMARC. The owner appears as the From *display name* ("X via Kairos") and
as Reply-To, so replies go to them.
"""

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

from kairos import settings
from kairos.helpers import env

ICS_FILENAME = "kairos-event.ics"

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "noreply@example.org")


def is_configured() -> bool:
    # SMTP_USER/PASSWORD are optional — many institutional relays accept
    # unauthenticated mail from internal IPs; auth is only needed for
    # authenticated submission with a real service mailbox.
    return bool(SMTP_HOST)


def _smtp_session() -> smtplib.SMTP:
    server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20)
    server.ehlo()
    if server.has_extn("starttls"):
        server.starttls()
        server.ehlo()
    if SMTP_USER and SMTP_PASSWORD:
        server.login(SMTP_USER, SMTP_PASSWORD)
    return server


def _sender_headers(msg, sender_name: str, reply_to: str | None):
    """From = service address with the owner as display name; replies -> owner."""
    msg["From"] = formataddr((f"{sender_name} via {settings.BRAND}", SMTP_FROM))
    if reply_to:
        msg["Reply-To"] = reply_to


def _calendar_part(ics_content: str, method: str = "PUBLISH") -> MIMEText:
    part = MIMEText(ics_content, "calendar", "utf-8")
    part.set_param("method", method)
    part.add_header("Content-Disposition", "attachment", filename=ICS_FILENAME)
    return part


def _ics_part(ics_content: str) -> MIMEText:
    return _calendar_part(ics_content, "PUBLISH")


def build_imip_message(to_email: str, subject: str, body_text: str,
                       ics_content: str, method: str,
                       organizer_email: str, organizer_name: str) -> MIMEMultipart:
    """iMIP REQUEST/CANCEL message. From = ORGANIZER mailbox so the client's
    METHOD:REPLY comes back to the mailbox Kairos polls (no Reply-To override)."""
    msg = MIMEMultipart("mixed")
    msg["Subject"] = subject
    msg["To"] = to_email
    msg["From"] = formataddr((organizer_name, organizer_email))
    msg.attach(MIMEText(body_text, "plain"))
    msg.attach(_calendar_part(ics_content, method))
    return msg


def send_imip(to_email: str, subject: str, body_text: str, ics_content: str,
              method: str, organizer_email: str, organizer_name: str) -> bool:
    """Send one iMIP REQUEST/CANCEL. False if SMTP not configured or send fails."""
    if not is_configured():
        return False
    msg = build_imip_message(to_email, subject, body_text, ics_content, method,
                             organizer_email, organizer_name)
    try:
        with _smtp_session() as server:
            server.send_message(msg)
        return True
    except Exception:
        return False


def build_invite_message(to_email: str, poll_title: str, invite_url: str,
                         sender_name: str, reply_to: str | None = None,
                         reminder: bool = False,
                         recipient_name: str | None = None) -> MIMEMultipart:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = (f"Reminder — please respond: {poll_title}" if reminder
                      else f"You're invited: {poll_title}")
    msg["To"] = to_email
    _sender_headers(msg, sender_name, reply_to)

    lead = ("a friendly reminder: please respond to the scheduling poll"
            if reminder else "invited you to respond to a scheduling poll")
    hi = f"Hi {recipient_name},\n\n" if recipient_name else ""
    text = f"""{hi}{sender_name} — {lead}: {poll_title}

Click here to respond: {invite_url}

No account needed — just click the link and pick your available times."""

    html = env.get_template("email/invite.html").render(
        sender_name=sender_name, poll_title=poll_title, invite_url=invite_url,
        reminder=reminder, recipient_name=recipient_name)

    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))
    return msg


def build_decision_message(to_email: str, poll_title: str, slot_label: str,
                           poll_url: str, ics_content: str, sender_name: str,
                           note: str = "", reply_to: str | None = None) -> MIMEMultipart:
    msg = MIMEMultipart("mixed")
    msg["Subject"] = f"Final date: {poll_title} — {slot_label}"
    msg["To"] = to_email
    _sender_headers(msg, sender_name, reply_to)

    text = f"""{sender_name} has decided on a final date for: {poll_title}

Final date: {slot_label}
{note + chr(10) + chr(10) if note else ''}Poll: {poll_url}

The attached calendar file ({ICS_FILENAME}) adds the event to your calendar."""

    html = env.get_template("email/decision.html").render(
        sender_name=sender_name, poll_title=poll_title,
        slot_label=slot_label, poll_url=poll_url, note=note)

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(text, "plain"))
    alt.attach(MIMEText(html, "html"))
    msg.attach(alt)
    msg.attach(_ics_part(ics_content))
    return msg


def send_invite_email(to_email: str, poll_title: str, invite_url: str,
                      sender_name: str, reply_to: str | None = None,
                      reminder: bool = False, recipient_name: str | None = None) -> bool:
    """Send an invite (or reminder) email. False if not configured / send fails."""
    if not is_configured():
        return False
    msg = build_invite_message(to_email, poll_title, invite_url, sender_name,
                               reply_to, reminder=reminder, recipient_name=recipient_name)
    try:
        with _smtp_session() as server:
            server.send_message(msg)
        return True
    except Exception:
        return False


def build_update_message(to_email: str, poll_title: str, url: str, sender_name: str,
                         reply_to: str | None = None, n_dates: int = 0) -> MIMEMultipart:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"New dates added: {poll_title}"
    msg["To"] = to_email
    _sender_headers(msg, sender_name, reply_to)

    text = f"""{sender_name} added {n_dates} new date{'' if n_dates == 1 else 's'} to the scheduling poll: {poll_title}

Your previous answers are kept — please mark your availability for the new dates:
{url}"""

    html = env.get_template("email/update.html").render(
        sender_name=sender_name, poll_title=poll_title, url=url, n_dates=n_dates)

    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))
    return msg


def send_update_emails(recipients: list[tuple[str, str]], poll_title: str,
                       sender_name: str, reply_to: str | None = None,
                       n_dates: int = 0) -> int:
    """Notify participants about added dates. recipients = [(email, their_url)]."""
    if not is_configured() or not recipients:
        return 0
    sent = 0
    try:
        with _smtp_session() as server:
            for to_email, url in recipients:
                msg = build_update_message(to_email, poll_title, url, sender_name,
                                           reply_to=reply_to, n_dates=n_dates)
                try:
                    server.send_message(msg)
                    sent += 1
                except Exception:
                    continue
    except Exception:
        return sent
    return sent


def send_decision_email(recipients: list[str], poll_title: str, slot_label: str,
                        poll_url: str, ics_content: str, sender_name: str,
                        note: str = "", reply_to: str | None = None) -> list[str]:
    """Email the decided date to all recipients, .ics attached.

    Returns the addresses actually sent (for the contact audit log)."""
    if not is_configured() or not recipients:
        return []

    sent: list[str] = []
    try:
        with _smtp_session() as server:
            for to_email in recipients:
                msg = build_decision_message(to_email, poll_title, slot_label,
                                             poll_url, ics_content, sender_name,
                                             note=note, reply_to=reply_to)
                try:
                    server.send_message(msg)
                    sent.append(to_email)
                except Exception:
                    continue
    except Exception:
        return sent
    return sent
