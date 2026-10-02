"""Outbound mail for Kairos.

Identity model: all mail is authenticated and sent AS the app's service
account (SMTP_USER / SMTP_FROM) — never as the poll owner, which would fail
SPF/DMARC. The owner appears as the From *display name* ("X via Kairos") and
as Reply-To, so replies go to them.
"""

import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

from kairos import settings
from kairos.helpers import env

ICS_FILENAME = "kairos-event.ics"
log = logging.getLogger("kairos.mail")

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "noreply@example.org")


# -- Obligation M1 (#48): refuse to send from an identity we cannot authenticate --
#
# SPF, DKIM and DMARC are DNS records. Kairos can publish none of them and read none
# of them (there is no DNS library here, and adding one is a licence/pip-audit gate),
# so it cannot verify that they are in force and must not pretend to. What it *can* do
# is refuse the one failure mode it can see: sending as an address whose domain nobody
# could publish authenticated DNS for us. Left alone, a half-configured hosted
# deployment sends DKIM-less, SPF-less mail from our domain until a recipient's
# provider quietly drops it; from a personal Gmail it mails from someone else's domain
# and spends their reputation too.
#
# Everything here is inert unless KAIROS_HOSTED is set. That flag is the whole reason
# self-host and ETH/duplet are unaffected: they authenticate their own mail with a
# relay they configured, and second-guessing that would break the deployment that has
# least to do with our brand domain.

# Domains nobody can publish DMARC for. "Never a personal Gmail" is structural rather
# than stylistic: gmail.com's DNS is Google's to set, Google terminates consumer
# accounts that send automated mail, and consumer SMTP submission is capped around
# 5000 messages/day. Matched exactly, plus brand labels, which covers the country
# variants (hotmail.co.uk, outlook.de, yahoo.co.jp) that an exact list always misses.
# Not a Public Suffix List — that is a new dependency, and the false-positive risk is
# nil here anyway because these names are only ever checked against addresses the
# operator typed in themselves.
#
# This list is a floor, not a ceiling. The load-bearing check is alignment against
# KAIROS_FROM_DOMAIN, which rejects any foreign domain at all, a provider Kairos has
# never heard of included.
_CONSUMER_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "ymail.com", "rocketmail.com", "icloud.com", "me.com", "mac.com",
    "aol.com", "gmx.com", "gmx.net", "web.de", "t-online.de",
    "protonmail.com", "proton.me", "pm.me", "tutanota.com", "tuta.io",
    "zohomail.com", "fastmail.fm",
    "mail.ru", "yandex.ru", "yandex.com", "qq.com", "163.com", "126.com",
    "sina.com", "sohu.com", "nate.com", "hanmail.net", "naver.com", "daum.net",
    "comcast.net", "verizon.net", "att.net", "sbcglobal.net", "bellsouth.net",
    "cox.net", "charter.net", "earthlink.net", "optonline.net", "btinternet.com",
    "shaw.ca", "rogers.com", "sympatico.ca", "interia.pl", "onet.pl",
})

_CONSUMER_LABELS = frozenset({
    "gmail", "googlemail", "outlook", "hotmail", "yahoo", "ymail", "rocketmail",
    "icloud", "aol", "gmx", "yandex", "protonmail", "tutanota", "zohomail",
    "t-online", "wanadoo", "sbcglobal", "bellsouth", "earthlink", "optonline",
    "btinternet", "interia", "onet", "sympatico",
})

# RFC 2606 reserved names. Worth a message of their own because SMTP_FROM *defaults*
# to one of these, so "the operator forgot to set it" is the likeliest misconfiguration
# here and should not be reported as a mysterious misalignment.
_PLACEHOLDER_DOMAINS = frozenset({"example.com", "example.net", "example.org"})


def domain_of(address: str) -> str:
    """The domain of an email address, normalised for comparison.

    Accepts a bare domain too (KAIROS_FROM_DOMAIN is one) and strips the angle
    brackets a From header carries. Returns "" for anything that is not a domain — a
    bare word, a second "@", nothing at all — because callers must treat that as a
    failure rather than as "no domain", which would align with everything.
    """
    value = (address or "").strip().strip("<>").strip().rsplit("@", 1)[-1]
    value = value.strip().rstrip(".").lower()
    return value if "." in value and "@" not in value else ""


def is_consumer_provider(address: str) -> bool:
    """Is this a consumer/personal mailbox domain rather than one we control?"""
    domain = domain_of(address)
    if not domain:
        return False
    return domain in _CONSUMER_DOMAINS or any(lbl in _CONSUMER_LABELS for lbl in domain.split("."))


def _aligned_with(domain: str, declared: str) -> bool:
    """Would DMARC see `domain` as aligned with the visible From?

    DMARC requires SPF or DKIM to pass on a domain sharing the From's Organizational
    Domain, and computing an Organizational Domain needs the Public Suffix List.
    Rather than approximate it, the operator names it (KAIROS_FROM_DOMAIN) and the
    check becomes "is the sender that domain or a subdomain of it".

    The subdomain form is the *preferred* one — a dedicated mail.example.com sends for
    the brand but keeps its reputation separate — so allowing it here is not a
    loophole. The boundary does have to be a label boundary, though:
    "evil-example.com" must not pass for "example.com", hence the leading dot.
    """
    if not domain or not declared:
        return False
    return domain == declared or domain.endswith("." + declared)


def _identity_addresses() -> tuple[tuple[str, str], ...]:
    """Every address Kairos puts in a From or ORGANIZER header, as (var, value).

    KAIROS_IMIP_ORGANIZER counts because build_imip_message sends From = the organizer
    (deliberately, so a client's METHOD:REPLY comes back to the mailbox Kairos polls)
    and the ICS carries ORGANIZER:mailto:<that same address>. An organizer mailbox off
    the declared domain therefore fails DMARC for the invitation itself, not merely
    for replies to it.
    """
    slots = [("SMTP_FROM", SMTP_FROM)]
    if settings.IMIP_ENABLED and settings.IMIP_ORGANIZER:
        slots.append(("KAIROS_IMIP_ORGANIZER", settings.IMIP_ORGANIZER))
    return tuple(slots)


def sender_refusal() -> str | None:
    """Why outbound mail must not be sent right now, or None to send.

    Every message goes out as one identity, so this checks a list of address slots
    rather than branching per mail type: one refused identity silences all of them.
    Returns a sentence naming the knob to fix rather than a bare boolean, because the
    point of this is that a human reads it in a log.
    """
    if not settings.HOSTED:
        return None

    declared = domain_of(settings.FROM_DOMAIN)
    if not declared:
        return ("KAIROS_HOSTED is set but KAIROS_FROM_DOMAIN is not, so there is no domain "
                "to authenticate outbound mail from. Set KAIROS_FROM_DOMAIN to the domain "
                "you publish SPF/DKIM/DMARC for (docs/design/mail-auth.md), or unset "
                "KAIROS_HOSTED if this deployment authenticates its own mail.")
    if is_consumer_provider(declared):
        return (f"KAIROS_FROM_DOMAIN={declared!r} is a consumer mailbox provider, not a domain "
                f"we can publish SPF/DKIM/DMARC for. Every message would go out "
                f"unauthenticated (obligation M1). Use a domain we control.")

    for var, address in _identity_addresses():
        domain = domain_of(address)
        if not domain:
            return (f"{var}={address!r} is not an email address, so the From domain cannot "
                    f"be authenticated. Set it to a mailbox on {declared!r}.")
        if domain in _PLACEHOLDER_DOMAINS:
            return (f"{var}={address!r} is a reserved placeholder domain, not a mailbox we "
                    f"control. Set it to a real address on {declared!r}.")
        if is_consumer_provider(domain):
            return (f"{var}={address!r} is a consumer mailbox provider. Mail from it cannot "
                    f"be authenticated as ours (obligation M1) — set a mailbox on "
                    f"{declared!r}.")
        if not _aligned_with(domain, declared):
            return (f"{var}={address!r} is not on KAIROS_FROM_DOMAIN={declared!r}. DMARC "
                    f"authenticates the visible From domain, so this mail would be "
                    f"unauthenticated (obligation M1).")
    return None


_refusal_logged = False


def check_sender() -> str | None:
    """Evaluate the M1 gate, logging a refusal once per process.

    Log-once because the API's invite path calls send_invite_email per recipient, so a
    200-person poll would otherwise bury the actual cause under 200 identical lines.

    Deliberately independent of mail_identity_report(), which has already logged the same
    refusal at INFO on the way up: the boot line states the configuration, this one says
    an actual send was attempted and blocked. Collapsing them would lose the second fact.
    """
    global _refusal_logged
    reason = sender_refusal()
    if reason and not _refusal_logged:
        log.error("refusing to send mail (obligation M1): %s", reason)
        _refusal_logged = True
    return reason


def mail_identity_report() -> str:
    """One line describing the outbound identity, logged at every startup.

    M1 is EXTERNAL + CONFIG as well as RUNTIME: SPF/DKIM/DMARC are DNS records Kairos
    cannot read, so the only honest thing it can do is say which identity it is
    configured to send as and point at the records that must exist for it. That turns
    "did it rot" from DNS archaeology into one line in the boot log.
    """
    if not SMTP_HOST:
        state = "mail is off (SMTP_HOST unset)"
    elif reason := sender_refusal():
        return f"outbound mail: REFUSING TO SEND — {reason}"
    else:
        slots = ", ".join(f"{var}={value}" for var, value in _identity_addresses())
        state = f"sending as {slots}"
    if not settings.HOSTED:
        return (f"outbound mail: {state}. KAIROS_HOSTED is unset, so the M1 gate is off "
                f"and Kairos does not require SPF/DKIM/DMARC here (docs/design/mail-auth.md "
                f"if you ever host this for others).")
    return (f"outbound mail: {state}, authenticated as {settings.FROM_DOMAIN!r}. SPF/DKIM/"
            f"DMARC must be published for it — Kairos cannot read DNS, so it cannot confirm "
            f"they exist (docs/design/mail-auth.md).")


def is_configured() -> bool:
    """Is mail switched on *and* may we send it?

    SMTP_USER/PASSWORD are optional — many institutional relays accept
    unauthenticated mail from internal IPs; auth is only needed for
    authenticated submission with a real service mailbox.

    The M1 gate lives here because this is the one predicate every send path already
    consults (send_imip, send_invite_email, send_update_emails, send_decision_email),
    so a refused identity silences all of them and a new send path cannot forget it.
    """
    if not SMTP_HOST:
        return False
    return check_sender() is None


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
    METHOD:REPLY comes back to the mailbox Kairos polls (no Reply-To override).

    The calendar is the richer part of a multipart/alternative (text/calendar
    with method=REQUEST, INLINE — not an attachment). Gmail/Apple only render
    native Accept/Maybe/Decline for this shape; a mixed attachment gets imported
    as a plain event with no RSVP (and Apple then replies without PARTSTAT)."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["To"] = to_email
    msg["From"] = formataddr((organizer_name, organizer_email))
    msg.attach(MIMEText(body_text, "plain", "utf-8"))
    cal = MIMEText(ics_content, "calendar", "utf-8")
    cal.set_param("method", method)  # Content-Type: text/calendar; charset=utf-8; method=REQUEST
    msg.attach(cal)
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


def webcal_from(invite_url: str) -> str:
    """webcal:// subscription URL for an invite's candidate feed (the 'shared cal')."""
    base = invite_url.replace("https://", "webcal://").replace("http://", "webcal://")
    return f"{base}/feed.ics"


def build_invite_message(to_email: str, poll_title: str, invite_url: str,
                         sender_name: str, reply_to: str | None = None,
                         reminder: bool = False,
                         recipient_name: str | None = None,
                         subscribe_url: str | None = None) -> MIMEMultipart:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = (f"Reminder — please respond: {poll_title}" if reminder
                      else f"You're invited: {poll_title}")
    msg["To"] = to_email
    _sender_headers(msg, sender_name, reply_to)

    lead = ("a friendly reminder: please respond to the scheduling poll"
            if reminder else "invited you to respond to a scheduling poll")
    hi = f"Hi {recipient_name},\n\n" if recipient_name else ""
    subscribe_txt = ""
    if subscribe_url:
        subscribe_txt = f"""

Or add it to your own calendar and vote from there:
  {subscribe_url}
Every candidate time appears in your calendar with one-click Accept / Maybe / Decline.
Note: a subscribed calendar refreshes on your app's own schedule — minutes to a day
(Google can be ~daily). Your vote saves instantly on the website; the calendar copy
catches up later.

🤖 Have an assistant? This invite link is agent-native & self-describing
({invite_url}/agent.json) — hand it the link and your AI reads the options and RSVPs
for you. (Keep the link private — it votes as you.)"""
    text = f"""{hi}{sender_name} — {lead}: {poll_title}

Two ways to respond:

Open the poll and pick times: {invite_url}{subscribe_txt}

No account. No calendar access. Every other scheduler wants to read your whole
calendar to guess when you're free — {settings.BRAND} just asks you. (You're the
only one who knows what's actually movable.)"""

    html = env.get_template("email/invite.html").render(
        sender_name=sender_name, poll_title=poll_title, invite_url=invite_url,
        reminder=reminder, recipient_name=recipient_name, subscribe_url=subscribe_url)

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
                      reminder: bool = False, recipient_name: str | None = None,
                      subscribe_url: str | None = None) -> bool:
    """Send an invite (or reminder) email. False if not configured / send fails."""
    if not is_configured():
        return False
    msg = build_invite_message(to_email, poll_title, invite_url, sender_name,
                               reply_to, reminder=reminder, recipient_name=recipient_name,
                               subscribe_url=subscribe_url)
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
