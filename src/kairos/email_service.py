"""Outbound mail for Kairos.

Identity model: all mail is authenticated and sent AS the app's service
account (SMTP_USER / SMTP_FROM) — never as the poll owner, which would fail
SPF/DMARC. The owner appears as the From *display name* ("X via Kairos") and
as Reply-To, so replies go to them.
"""

import ipaddress
import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
from typing import NamedTuple

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
# 5000 messages/day. This list is a floor, not a ceiling -- _aligned_with rejects any
# foreign domain at all, a provider Kairos has never heard of included.
#
# _CONSUMER_LABELS exists to catch the country variants (hotmail.co.uk, outlook.de,
# yahoo.co.jp, mail.msn.com) that an exact list always misses. It cannot be a Public
# Suffix List -- that is a new dependency -- so it matches brand names anywhere in the
# domain. That over-matches operator domains that contain a brand name, which is why
# the address checks below only apply it to domains that are NOT already aligned with
# the operator's declared domain: alignment is the authoritative test, and it cannot
# be spoofed by a coincidence in the label.
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
    "gmail", "googlemail", "outlook", "hotmail", "live", "msn",
    "yahoo", "ymail", "rocketmail", "icloud", "aol", "gmx", "yandex",
    "protonmail", "proton", "tutanota", "zohomail", "t-online", "wanadoo",
    "sbcglobal", "bellsouth", "earthlink", "optonline", "btinternet", "interia",
    "onet", "sympatico", "qq", "163", "126", "sina", "sohu", "nate", "hanmail",
    "naver", "daum",
})

# RFC 2606 reserved names. Worth a message of their own because SMTP_FROM *defaults*
# to one of these, so "the operator forgot to set it" is the likeliest misconfiguration
# here and should not be reported as a mysterious misalignment.
_PLACEHOLDER_DOMAINS = frozenset({"example.com", "example.net", "example.org"})


class MailRefusal(NamedTuple):
    """Why outbound is blocked, in both machine- and human-readable form.

    Two fields because the two audiences differ: `message` is for the server log,
    where naming the misconfigured variable is the whole point, while `code` is stable
    enough for a caller to branch on. Callers surface `code` rather than `message` --
    the message names internal addresses, and the person clicking Send in a hosted
    deployment is a customer, not the operator.
    """

    code: str
    message: str


def is_ip_literal(value: str) -> bool:
    """Is this an IP address rather than a domain name?

    DKIM's `d=` tag must be a domain name, and DMARC alignment is defined over domain
    names, so an IP literal can never be authenticated however it is published. An IPv6
    literal additionally carries colons that no hostname may contain.
    """
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def domain_of(value: str) -> str:
    """The domain of a bare addr-spec or a bare domain, normalised. "" if not one.

    Accepts `local@domain`, a bare `domain`, and either wrapped in angle brackets.
    Everything else returns "". Strict on purpose, because SMTP_FROM is interpolated
    into formataddr() as an *address* and formataddr does not escape what it is given:

        formataddr(("Ada", "evil@attacker.test, kairos@our.domain"))
        -> 'Ada <evil@attacker.test, kairos@our.domain>'

    which is a single From header whose first address is the attacker's. smtplib then
    derives the envelope sender from exactly that first address (send_message() calls
    getaddresses(msg["From"])[0][1] when no from_addr is given), so a value that merely
    *contains* our domain would sail through a naive "does it end in our domain" check
    while the message goes out as somebody else entirely. Requiring one bare addr-spec
    removes the whole class rather than trying to detect each separator.

    Returns "" for an IP literal, which is never a domain name.
    """
    text = (value or "").strip()
    if text.startswith("<") and text.endswith(">"):
        text = text[1:-1].strip()
    if not text:
        return ""
    local, sep, domain = text.rpartition("@")
    if sep:
        # A local part must exist and must not contain any character that could begin a
        # second address, a group, or a quoted string -- those separators are precisely
        # how an address list came to look aligned. "+" is deliberately allowed: it is
        # valid atext, which is what reply+<token>@ (#34) depends on.
        if not local or any(c in local for c in '<>@,;:"()[]\\'):
            return ""
    else:
        domain = text  # a bare domain, as KAIROS_FROM_DOMAIN is written
    domain = domain.strip().rstrip(".").lower()
    if not domain or "." not in domain or is_ip_literal(domain):
        return ""
    return "" if any(c in domain for c in '<>@,;:"()[]\\ \t') else domain


def _is_known_consumer_domain(domain: str) -> bool:
    """Exact match against the consumer-provider list (no label heuristic)."""
    return domain in _CONSUMER_DOMAINS


def is_consumer_provider(value: str) -> bool:
    """Does this look like a consumer/personal mailbox domain?

    Exact set first, then the brand-label heuristic, which is what catches the country
    and sub-addressed variants (`hotmail.co.uk`, `mail.gmail.com`, `mail.msn.com`).

    The label half over-matches by construction: it cannot tell `gmx.de` from an
    operator's own `gmx.example.com`. It is therefore only ever applied to a domain
    that has *already* failed alignment, where a false positive costs nothing, and to
    senders -- never to the operator's own declared domain. Use
    `_is_known_consumer_domain` for that.
    """
    domain = domain_of(value)
    if not domain:
        return False
    return _is_known_consumer_domain(domain) or any(
        lbl in _CONSUMER_LABELS for lbl in domain.split("."))


def aligned_with(domain: str, declared: str) -> bool:
    """Would DMARC see `domain` as aligned with the visible From?

    DMARC requires SPF or DKIM to pass on a domain whose Organizational Domain equals
    the From's (relaxed alignment, RFC 7489 3.1.1), and computing an Organizational
    Domain needs the Public Suffix List. Rather than approximate it, the operator names
    it (KAIROS_FROM_DOMAIN) and the check becomes "is the sender that domain or a
    subdomain of it".

    That is a *narrower* test than relaxed alignment, not an equivalent one: it treats
    any subdomain of the declared domain as aligned, which is right for the usual
    single-registration case (mail.example.com under example.com) but would be wrong
    for a public suffix -- under example.co.uk, co.uk is a public suffix, so
    attacker.example.co.uk is a *different* registrable domain and would not in fact be
    aligned. Documented in docs/design/mail-auth.md; an operator with such a domain must
    declare the registrable parent.

    The subdomain form is the *preferred* shape -- a dedicated mail.example.com sends
    for the brand but keeps its reputation separate -- so allowing it is not a loophole.
    The boundary does have to be a label boundary, though: "evil-example.com" must not
    pass for "example.com", hence the leading dot.
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


def sender_refusal() -> MailRefusal | None:
    """Why outbound mail must not be sent right now, or None to send.

    Every message goes out as one identity, so this checks a list of address slots
    rather than branching per mail type: one refused identity silences all of them.
    """
    if not settings.HOSTED:
        return None

    raw = (settings.FROM_DOMAIN or "").strip()
    declared = domain_of(raw)
    if not declared:
        if not raw:
            return MailRefusal(
                "m1_from_domain_unset",
                "KAIROS_HOSTED is set but KAIROS_FROM_DOMAIN is not, so there is no domain "
                "to authenticate outbound mail from. Set KAIROS_FROM_DOMAIN to the domain you "
                "publish SPF/DKIM/DMARC for (docs/design/mail-auth.md), or unset "
                "KAIROS_HOSTED if this deployment authenticates its own mail.")
        return MailRefusal(
            "m1_from_domain_not_a_domain",
            f"KAIROS_FROM_DOMAIN={raw!r} is not a domain name"
            + (" (an IP address can never be authenticated: DKIM's d= tag and DMARC "
               "alignment are both defined over domain names)"
               if is_ip_literal(raw) else "")
            + ". Set it to the domain you publish SPF/DKIM/DMARC for "
              "(docs/design/mail-auth.md).")
    # Exact-match only here, not the label heuristic: the declared domain is asserted by
    # the operator, so a brand-name label inside it may well be theirs (`gmx.nerdmachines.com`)
    # and there is no alignment to fall back on. The residual is that a country variant
    # (hotmail.co.uk) as the *declared* domain escapes this check -- acceptable, because
    # an operator who declares someone else's domain cannot publish the SPF/DKIM/DMARC
    # records that M1 exists to require, so the configuration fails visibly at delivery
    # rather than silently succeeding.
    if _is_known_consumer_domain(declared):
        return MailRefusal(
            "m1_from_domain_consumer",
            f"KAIROS_FROM_DOMAIN={declared!r} is a consumer mailbox provider, not a domain "
            f"we can publish SPF/DKIM/DMARC for. Every message would go out "
            f"unauthenticated (obligation M1). Use a domain we control.")

    for var, address in _identity_addresses():
        domain = domain_of(address)
        if not domain:
            return MailRefusal(
                "m1_address_unreadable",
                f"{var}={address!r} is not a single valid email address, so the From domain "
                f"cannot be authenticated. Set it to one bare address on {declared!r}.")
        # Alignment is the authoritative test, so the consumer list (which cannot help
        # but over-match a domain like gmx.nerdmachines.com) is only consulted for
        # domains alignment has already rejected.
        if not aligned_with(domain, declared):
            if domain in _PLACEHOLDER_DOMAINS:
                return MailRefusal(
                    "m1_address_placeholder",
                    f"{var}={address!r} is a reserved placeholder domain, not a mailbox we "
                    f"control. Set it to a real address on {declared!r}.")
            if is_consumer_provider(domain):
                return MailRefusal(
                    "m1_address_consumer",
                    f"{var}={address!r} is a consumer mailbox provider. Mail from it cannot "
                    f"be authenticated as ours (obligation M1) — set a mailbox on "
                    f"{declared!r}.")
            return MailRefusal(
                "m1_address_misaligned",
                f"{var}={address!r} is not on KAIROS_FROM_DOMAIN={declared!r}. DMARC "
                f"authenticates the visible From domain, so this mail would be "
                f"unauthenticated (obligation M1).")
    return None


_last_refusal_logged: str | None = None


def check_sender() -> MailRefusal | None:
    """Evaluate the M1 gate, logging a refusal once per distinct reason.

    Log-once because the API's invite path calls send_invite_email per recipient, so a
    200-person poll would otherwise bury the actual cause under 200 identical lines.
    Keyed on the reason rather than a bool so a *different* refusal is still reported if
    the configuration is changed under a long-running process.

    Deliberately independent of mail_identity_report(), which has already logged the same
    refusal at INFO on the way up: the boot line states the configuration, this one says
    an actual send was attempted and blocked. Collapsing them would lose the second fact.
    """
    global _last_refusal_logged
    refusal = sender_refusal()
    if refusal and refusal.message != _last_refusal_logged:
        log.error("refusing to send mail (obligation M1, %s): %s", refusal.code, refusal.message)
        _last_refusal_logged = refusal.message
    return refusal


def mail_identity_report() -> str:
    """One line describing the outbound identity, logged at every startup.

    M1 is EXTERNAL + CONFIG as well as RUNTIME: SPF/DKIM/DMARC are DNS records Kairos
    cannot read, so the only honest thing it can do is say which identity it is
    configured to send as and point at the records that must exist for it. That turns
    "did it rot" from DNS archaeology into one line in the boot log.
    """
    if settings.HOSTED_UNKNOWN:
        state = (f"but KAIROS_HOSTED={settings.HOSTED_RAW!r} is not a value Kairos "
                 f"recognises, so the M1 gate is OFF — use 1/on/true/yes")
    elif not settings.HOSTED:
        state = ("and KAIROS_HOSTED is unset, so the M1 gate is off and Kairos does not "
                 "require SPF/DKIM/DMARC here")
    else:
        state = f"and the M1 gate is ON for {domain_of(settings.FROM_DOMAIN) or 'nothing yet'}"

    if not SMTP_HOST:
        detail = "mail is off (SMTP_HOST unset)"
    elif refusal := sender_refusal():
        return f"outbound mail: REFUSING TO SEND ({refusal.code}) — {refusal.message}"
    else:
        slots = ", ".join(f"{var}={value}" for var, value in _identity_addresses())
        detail = f"sending as {slots}"
    tail = ("SPF/DKIM/DMARC must be published for it — Kairos cannot read DNS, so it cannot "
            "confirm they exist (docs/design/mail-auth.md)."
            if settings.HOSTED else
            "docs/design/mail-auth.md if you ever host this for others.")
    return f"outbound mail: {detail}, {state}. {tail}"


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


def build_manage_message(to_email: str, poll_title: str, manage_url: str) -> MIMEMultipart:
    """The magic link that authenticates a poll's manager (#30).

    No `sender_name` and no `reply_to`: an accountless creator has neither — they
    are an address on a form, not an identity — so the From line is the service
    account alone rather than a fabricated human. That is also why the poll title
    is the subject's only content besides the link itself: the recipient is being
    told that a link addressed to *them* is a credential, and everything else in
    the message has to make that unmissable.
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Your manage link: {poll_title}"
    msg["To"] = to_email
    msg["From"] = formataddr((settings.BRAND, SMTP_FROM))

    text = f"""{settings.BRAND} — here is the link that lets you manage this scheduling poll:

{manage_url}

What it is
----------
This link is the credential. There is no account and no password behind it:
whoever holds it can manage "{poll_title}" -- add dates, invite people, decide
the date, delete the poll.

It works once. Opening it exchanges it for a private session in your browser,
and the link itself stops working. That is deliberate: a link that stayed valid
forever would still be sitting in your mailbox, your browser history and any
forwarded copy of this message.

Keep this page. To manage the poll again later, open
{settings.BRAND}, create a poll, or use the "email me a new link" box on the
manage page with this address.

If you did not create this poll, ignore this message and delete it -- nobody's
poll is reachable from it without this link, and the only address it was sent to
is yours."""

    html = env.get_template("email/manage.html").render(
        poll_title=poll_title, manage_url=manage_url, brand=settings.BRAND)

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(text, "plain"))
    alt.attach(MIMEText(html, "html"))
    msg.attach(alt)
    return msg


def send_manage_email(to_email: str, poll_title: str, manage_url: str) -> bool:
    """Mail one poll's manage link. False if not configured / the send failed.

    The one outbound message whose failure is not cosmetic: in
    `KAIROS_AUTH=capability` the link IS the credential, so a False here means the
    poll exists and nobody can reach it. Callers treat it as such rather than as
    a missing flash message.
    """
    if not is_configured():
        return False
    msg = build_manage_message(to_email, poll_title, manage_url)
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
