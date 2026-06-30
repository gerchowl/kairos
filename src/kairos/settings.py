"""Kairos configuration — all via environment variables, no config files.

KAIROS_DB_URL      sqlite:///kairos.db (default) | mysql://user:pass@host:port/db
KAIROS_PREFIX      URL prefix the app is mounted under (default "", e.g. "/scheduler")
KAIROS_AUTH        owner-auth mode: demo (default) | header | none
KAIROS_AUTH_UID_HEADER    header carrying the user id    (header mode, default X-User)
KAIROS_AUTH_EMAIL_HEADER  header carrying the email      (default X-Email)
KAIROS_AUTH_NAME_HEADER   header carrying a display name (default X-Name)
KAIROS_ALLOW       optional comma list of allowed uids/emails (header mode)
KAIROS_BRAND       display name (default "Kairos")
KAIROS_HOME_URL    brand-link target in the navbar (default the app itself)
SESSION_SECRET     signing key for cookies/CSRF (required outside demo mode)
SMTP_HOST/PORT/USER/PASSWORD/FROM   outbound mail (optional; unauth relay ok)
KAIROS_FEED        reverse-calendar slot feeds + deep-link voting: off (default) | on
KAIROS_IMIP        native iMIP invitations (Accept/Maybe/Decline): off (default) | on
KAIROS_IMIP_ORGANIZER       reply mailbox = ORGANIZER mailto (must equal IMAP mailbox)
KAIROS_IMIP_ORGANIZER_NAME  ORGANIZER display name (default KAIROS_BRAND)
KAIROS_IMAP_HOST/PORT/USER/PASSWORD/MAILBOX   inbound iMIP reply polling (P2)
"""

import os

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
PUBLIC_URL = os.environ.get("KAIROS_PUBLIC_URL", "")  # SSoT base for share links; empty -> derive from request headers
API_KEY = os.environ.get("KAIROS_API_KEY") or os.environ.get("SCHEDULER_API_KEY", "")

# Legal pages (/imprint, /privacy) — rendered when KAIROS_OPERATOR is set.
# Structured input, no HTML needed; the operator carries the legal duty
# (CH nDSG / GDPR). Kairos itself sets only strictly-necessary cookies,
# so no consent banner is required — the privacy page discloses them.
OPERATOR = os.environ.get("KAIROS_OPERATOR", "")            # name / org
OPERATOR_ADDRESS = os.environ.get("KAIROS_OPERATOR_ADDRESS", "")  # postal address, comma-separated
OPERATOR_EMAIL = os.environ.get("KAIROS_OPERATOR_EMAIL", "")
LEGAL_EXTRA = os.environ.get("KAIROS_LEGAL_EXTRA", "")      # free-form extra paragraph

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
