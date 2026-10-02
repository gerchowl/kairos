"""Kairos configuration — all via environment variables, no config files.

KAIROS_DB_URL      sqlite:///kairos.db (default) | mysql://user:pass@host:port/db
KAIROS_PREFIX      URL prefix the app is mounted under (default "", e.g. "/scheduler")
KAIROS_AUTH        owner-auth mode: demo (default) | header | none
KAIROS_AUTH_UID_HEADER    header carrying the user id    (header mode, default X-User)
KAIROS_AUTH_EMAIL_HEADER  header carrying the email      (default X-Email)
KAIROS_AUTH_NAME_HEADER   header carrying a display name (default X-Name)
KAIROS_ALLOW       optional comma list of allowed uids/emails (header mode)
KAIROS_TRUSTED_PROXY_CIDRS  comma list of CIDRs/IPs allowed to set identity
                   headers, e.g. 10.0.0.0/8,127.0.0.1. When set, requests
                   arriving from any other peer are REJECTED (403) — fail
                   closed. Unset means trust any peer, which is correct only
                   while the app port is unreachable except through your proxy,
                   and required before exposing a hosted instance (S1).
KAIROS_BRAND       display name (default "Kairos")
KAIROS_HOME_URL    brand-link target in the navbar (default the app itself)
SESSION_SECRET     signing key for cookies/CSRF (required outside demo mode)
SMTP_HOST/PORT/USER/PASSWORD/FROM   outbound mail (optional; unauth relay ok)
KAIROS_HOSTED      declares a deployment WE operate (the hosted product, not a
                    self-hoster's own box). Off by default. When on, outbound
                    mail is refused unless it is authenticated from
                    KAIROS_FROM_DOMAIN — obligation M1.
KAIROS_FROM_DOMAIN the domain outbound is authenticated as, e.g.
                    nerdmachines.com or a dedicated mail.nerdmachines.com.
                    Hosted mode only; see docs/design/mail-auth.md.
KAIROS_FEED        reverse-calendar slot feeds + deep-link voting: off (default) | on
KAIROS_IMIP        native iMIP invitations (Accept/Maybe/Decline): off (default) | on
KAIROS_IMIP_ORGANIZER       reply mailbox = ORGANIZER mailto (must equal IMAP mailbox)
KAIROS_IMIP_ORGANIZER_NAME  ORGANIZER display name (default KAIROS_BRAND)
KAIROS_IMAP_HOST/PORT/USER/PASSWORD/MAILBOX   inbound iMIP reply polling (P2)
"""

import ipaddress
import os


def _parse_networks(raw: str, var: str) -> tuple:
    """Parse a comma list of IPs/CIDRs into networks. Fails loudly.

    A typo here would silently widen or void the allowlist, so an unparseable
    entry is a startup error rather than a skipped line.
    """
    networks = []
    for item in (s.strip() for s in raw.split(",")):
        if not item:
            continue
        try:
            # strict=True on purpose: "10.0.0.5/24" is a typo for a 256-address
            # network and "192.168.1.7/16" would silently trust 65536 hosts. On a
            # security allowlist, refuse it. A bare "10.0.0.5" still parses (as a
            # /32), which is the form people actually mean.
            networks.append(ipaddress.ip_network(item, strict=True))
        except ValueError as exc:
            raise RuntimeError(f"{var}: {item!r} is not a valid IP or CIDR ({exc})") from exc
    return tuple(networks)


DB_URL = os.environ.get("KAIROS_DB_URL", "sqlite:///kairos.db")
PREFIX = os.environ.get("KAIROS_PREFIX", "").rstrip("/")
AUTH_MODE = os.environ.get("KAIROS_AUTH", "demo")
AUTH_UID_HEADER = os.environ.get("KAIROS_AUTH_UID_HEADER", "X-User")
AUTH_EMAIL_HEADER = os.environ.get("KAIROS_AUTH_EMAIL_HEADER", "X-Email")
AUTH_NAME_HEADER = os.environ.get("KAIROS_AUTH_NAME_HEADER", "X-Name")
ALLOW = {a.strip().lower() for a in os.environ.get("KAIROS_ALLOW", "").split(",") if a.strip()}
BRAND = os.environ.get("KAIROS_BRAND", "Kairos")
HOME_URL = os.environ.get("KAIROS_HOME_URL", PREFIX + "/")
LOGIN_URL = os.environ.get("KAIROS_LOGIN_URL", "")  # owner sign-in page; empty -> 401 message
PUBLIC_URL = os.environ.get(
    "KAIROS_PUBLIC_URL", ""
)  # SSoT base for share links; empty -> derive from request headers
API_KEY = os.environ.get("KAIROS_API_KEY") or os.environ.get("SCHEDULER_API_KEY", "")

# Obligation S1 (issue #47): in header mode the owner identity comes from
# request headers, so whoever can reach the port can assert any identity —
# unless we know the request actually came through our proxy. Empty tuple =
# unset = trust every peer (the pre-existing behaviour, so the ETH/duplet and
# self-host deployments are untouched). Never consult X-Forwarded-For here:
# that header is exactly the thing an attacker controls.
TRUSTED_PROXY_CIDRS = os.environ.get("KAIROS_TRUSTED_PROXY_CIDRS", "")
TRUSTED_PROXY_NETWORKS = _parse_networks(TRUSTED_PROXY_CIDRS, "KAIROS_TRUSTED_PROXY_CIDRS")

# Obligation M1 (issue #48): outbound mail must be authenticated from a domain we
# control (SPF + DKIM + DMARC), never from a personal mailbox. Those records live in
# DNS, which Kairos can neither read nor publish, so the honest split is:
#
#   - this pair makes the *identity* we are about to send as explicit and checkable,
#     and turns a sender nobody could authenticate for us into a refusal rather than
#     a silent send;
#   - the DNS records themselves are the operator's, and docs/design/mail-auth.md
#     says exactly which ones to publish and how to check them.
#
# HOSTED is what separates the two worlds, and it is opt-in on purpose. A self-hoster
# or the ETH/duplet deployment has configured a relay that authenticates their own
# mail, which is their business and not something this app may second-guess — so unset
# means "no M1 gate", byte-for-byte the previous behaviour. Set it when *we* send from
# *our* domain and therefore own the reputation.
# A recognised-true set rather than "anything else is false": a typo like KAIROS_HOSTED=y
# must not silently disarm the gate, which is the failure mode a security control should
# never have. An unrecognised value keeps HOSTED off (the safe direction for self-host)
# but records itself so the boot line can WARN rather than quietly do nothing.
HOSTED_RAW = os.environ.get("KAIROS_HOSTED", "").strip()
HOSTED_TRUE = ("1", "on", "true", "yes")
HOSTED = HOSTED_RAW.lower() in HOSTED_TRUE
HOSTED_UNKNOWN = bool(HOSTED_RAW) and HOSTED_RAW.lower() not in HOSTED_TRUE + (
    "0", "off", "false", "no", "")
# Normalised, not validated: a typo must fail as a loud refusal naming this knob, not as
# an import error that would also break self-host, where the variable is unused. See
# kairos.email_service.sender_refusal().
FROM_DOMAIN = os.environ.get("KAIROS_FROM_DOMAIN", "").strip().strip(".").lower()

# Legal pages (/imprint, /privacy) — rendered when KAIROS_OPERATOR is set.
# Structured input, no HTML needed; the operator carries the legal duty
# (CH nDSG / GDPR). Kairos itself sets only strictly-necessary cookies,
# so no consent banner is required — the privacy page discloses them.
OPERATOR = os.environ.get("KAIROS_OPERATOR", "")  # name / org
OPERATOR_ADDRESS = os.environ.get("KAIROS_OPERATOR_ADDRESS", "")  # postal address, comma-separated
OPERATOR_EMAIL = os.environ.get("KAIROS_OPERATOR_EMAIL", "")
LEGAL_EXTRA = os.environ.get("KAIROS_LEGAL_EXTRA", "")  # free-form extra paragraph

# Reverse-calendar feed (issue #23): subscribe-able candidate-slot .ics feeds +
# deep-link Accept/Maybe/Decline. Off by default — opt in per deployment, since
# it exposes additional public (token-guarded) endpoints. See goal.md / docs.
FEED_ENABLED = os.environ.get("KAIROS_FEED", "off").strip().lower() in ("1", "on", "true", "yes")

# Native iMIP invitations (RFC 6047): real Accept/Maybe/Decline buttons in the
# client. Off by default. IMIP_ORGANIZER is the mailbox Kairos polls for replies
# (it MUST equal the IMAP mailbox below) — clients send METHOD:REPLY there.
IMIP_ENABLED = os.environ.get("KAIROS_IMIP", "off").strip().lower() in ("1", "on", "true", "yes")
IMIP_ORGANIZER = os.environ.get("KAIROS_IMIP_ORGANIZER", "")
IMIP_ORGANIZER_NAME = os.environ.get("KAIROS_IMIP_ORGANIZER_NAME", BRAND)

# Inbound iMIP reply ingestion via IMAP poll (P2). Same mailbox as IMIP_ORGANIZER.
IMAP_HOST = os.environ.get("KAIROS_IMAP_HOST", "")
IMAP_PORT = int(os.environ.get("KAIROS_IMAP_PORT", "993"))
IMAP_USER = os.environ.get("KAIROS_IMAP_USER", "")
IMAP_PASSWORD = os.environ.get("KAIROS_IMAP_PASSWORD", "")
IMAP_MAILBOX = os.environ.get("KAIROS_IMAP_MAILBOX", "INBOX")


def session_secret() -> str:
    secret = os.environ.get("SESSION_SECRET", "")
    if not secret:
        if AUTH_MODE == "demo":
            return "kairos-demo-not-secret"
        raise RuntimeError("SESSION_SECRET is not configured")
    return secret
