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
API_KEY = os.environ.get("KAIROS_API_KEY") or os.environ.get("SCHEDULER_API_KEY", "")


def session_secret() -> str:
    secret = os.environ.get("SESSION_SECRET", "")
    if not secret:
        if AUTH_MODE == "demo":
            return "kairos-demo-not-secret"
        raise RuntimeError("SESSION_SECRET is not configured")
    return secret
