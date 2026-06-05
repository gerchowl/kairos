"""CSRF tokens for cookie-authenticated forms.

Signed, user-bound, time-limited tokens (same SESSION_SECRET, distinct salt).
Render csrf_field(user) inside each <form method=post>; verify in the POST
handler with require_csrf(user, form).
"""

from fastapi import HTTPException
from itsdangerous import BadSignature, SignatureExpired

from .auth import _serializer

CSRF_MAX_AGE = 86400


def make_csrf(uid: str) -> str:
    return _serializer(salt="csrf").dumps({"uid": uid})


def check_csrf(uid: str, token: str) -> bool:
    if not token:
        return False
    try:
        data = _serializer(salt="csrf").loads(token, max_age=CSRF_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return False
    return data.get("uid") == uid


def csrf_field(user: dict) -> str:
    return f'<input type="hidden" name="csrf" value="{make_csrf(user["uid"])}">'


def require_csrf(user: dict, form):
    if not check_csrf(user["uid"], form.get("csrf", "")):
        raise HTTPException(status_code=403, detail="Invalid or expired CSRF token")
