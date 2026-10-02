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
KAIROS_FEED        reverse-calendar slot feeds + deep-link voting: off (default) | on
KAIROS_IMIP        native iMIP invitations (Accept/Maybe/Decline): off (default) | on
KAIROS_IMIP_ORGANIZER       reply mailbox = ORGANIZER mailto (must equal IMAP mailbox)
KAIROS_IMIP_ORGANIZER_NAME  ORGANIZER display name (default KAIROS_BRAND)
KAIROS_IMAP_HOST/PORT/USER/PASSWORD/MAILBOX   inbound iMIP reply polling (P2)
KAIROS_RATE_LIMIT      abuse limits on the public/email surface: off (default) | on
KAIROS_RATE_LIMIT_<RULE>   per-rule override, "<count>/<window>", e.g. "20/minute"
                   (window = second|minute|hour|day; count 0 disables that one
                   rule). Rules: READ RESPOND DEEPLINK_VOTE CREATE INVITE SEND.
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


# Abuse limits on the public/email surface — obligation A3, issue #37.
#
# OFF unless KAIROS_RATE_LIMIT is set, and that is the whole point: ADR-0001/0002
# require header-mode and self-host deployments to behave identically after this
# work, and the ETH/duplet adapter sets no rate-limit env at all. Turning it on
# is an operator decision (see README); this only makes the knob exist.
RATE_LIMIT_ENABLED = os.environ.get("KAIROS_RATE_LIMIT", "off").strip().lower() in ("1", "on", "true", "yes")

# Shipped defaults, per rule: (count, window seconds). Deliberately generous on
# the respondent-facing rules — a legitimate agent sweep of a 15-minute-slot
# week is ~100 votes (ADR-0010) — and tight on the ones that write rows or send
# mail. Every value is overridable; none of them apply unless enabled.
DEFAULT_RATE_LIMITS = {
    "read": (120, 60),  # token pages: poll, invite, agent.json, feeds, .ics
    "respond": (20, 60),  # POST /p/<token>, POST /p/i/<token>
    "deeplink_vote": (120, 60),  # GET .../s/<slot>/<yes|maybe|no> — one per slot
    "create": (10, 60),  # POST /new
    "invite": (30, 60),  # POST /polls/<id>/invite — grows the recipient list
    "send": (10, 3600),  # remind / remind-selected / email-decision — actual SMTP
}

_WINDOW_SECONDS = {
    "second": 1,
    "minute": 60,
    "hour": 3600,
    "day": 86400,
}


def _parse_rate_limit(raw: str, var: str) -> tuple[int, int]:
    """Parse "<count>/<window>" into (count, window_seconds). Fails loudly.

    Same reasoning as _parse_networks: an unparseable limit is not a skipped
    line, it is an abuse control the operator believes is in force and is not.
    Refuse the boot instead. "0" is accepted and means "this rule is off".
    """
    count_raw, sep, window = raw.strip().partition("/")
    if not sep:
        raise RuntimeError(f"{var}: {raw!r} must look like '20/minute' (count/window)")
    try:
        count = int(count_raw)
    except ValueError:
        raise RuntimeError(f"{var}: {count_raw!r} is not an integer count") from None
    if count < 0:
        raise RuntimeError(f"{var}: {raw!r} must be 0 (unlimited) or a positive count")
    seconds = _WINDOW_SECONDS.get(window.strip().lower())
    if seconds is None:
        raise RuntimeError(f"{var}: {window!r} is not a known window ({', '.join(_WINDOW_SECONDS)})")
    return count, seconds


def _parse_rate_limits(env: dict) -> dict:
    """Defaults overlaid with KAIROS_RATE_LIMIT_<RULE>, rejecting unknown names."""
    limits = dict(DEFAULT_RATE_LIMITS)
    for name in DEFAULT_RATE_LIMITS:
        var = f"KAIROS_RATE_LIMIT_{name.upper()}"
        raw = env.get(var)
        if raw is not None and raw.strip():
            limits[name] = _parse_rate_limit(raw, var)
    known = {f"KAIROS_RATE_LIMIT_{name.upper()}" for name in DEFAULT_RATE_LIMITS}
    for var in env:
        if var.startswith("KAIROS_RATE_LIMIT_") and var not in known:
            raise RuntimeError(
                f"{var} is not a rate-limit rule — known rules: "
                f"{', '.join(sorted(n.upper() for n in DEFAULT_RATE_LIMITS))}"
            )
    return limits


RATE_LIMITS = _parse_rate_limits(os.environ)


def session_secret() -> str:
    secret = os.environ.get("SESSION_SECRET", "")
    if not secret:
        if AUTH_MODE == "demo":
            return "kairos-demo-not-secret"
        raise RuntimeError("SESSION_SECRET is not configured")
    return secret
