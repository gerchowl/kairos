"""Admin panel for owner-minted API tokens — issue #82.

Three routes, in the owner surface and nowhere else:

  GET  /tokens              list this owner's tokens + mint form
  POST /tokens              mint a new token, display the plaintext once
  POST /tokens/{id}/revoke  revoke one of this owner's tokens

**Who sees it.** `kairos.auth.get_user` is the one seam (demo / header / oidc),
and all three resolve to a `user` with a `uid`. Capability mode (#30) has no
account — the manage link *is* the credential, there is nothing to attribute a
token to — so the panel refuses with a clear message rather than pretending to
work. `KAIROS_AUTH=none` has no owner surface at all, so the route 401s like
every other owner page.

**CSRF.** Each POST reads a `csrf` field from the form and runs
`kairos.csrf.require_csrf(user, form)`. The same token is used throughout the
panel (bound to the owner's uid, signed, time-limited); a submit from another
origin or by another owner is a 403.

**Rate limit.** Not applied. The three routes are owner-authenticated (demo /
header / oidc), and #37's limits are peer-keyed budgets sized for *anonymous*
surfaces — a legitimate owner tweaking their token list would spend them
immediately, and an attacker who gets as far as an owner session has already
beaten every control that would make rate limiting the useful one. The
established pattern on the owner surface (see every POST in `web.py` behind
`_owner_action`) does not carry a `rate_limit` dependency either.

**Ownership.** Every DB call takes `owner_uid` and the UPDATE/revoke includes
it in the WHERE, so an owner cannot touch another owner's row by guessing an
id — `db.revoke_api_token` is the belt, the owner-only list read is the
braces.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from kairos import apitokens, settings
from kairos.auth import get_user
from kairos.csrf import require_csrf
from kairos.db import list_api_tokens, revoke_api_token
from kairos.dbconn import db_now
from kairos.http import form_data
from kairos.scoping import SCOPES
from kairos.templating import render

log = logging.getLogger("kairos.panel")

P = settings.PREFIX
router = APIRouter(prefix=P) if P else APIRouter()

# The flash messages the mint/revoke POSTs set as a `msg=...` query param. A
# short map rather than inline strings so the template can read them off the
# query string without the routes repeating them. Deliberately short — the one
# authoritative display of a minted plaintext happens in the HTML the POST
# renders directly, not via a redirect.
_MSG_TEXT = {
    "revoked": "Token revoked. It cannot be used from the API any more.",
    "already-revoked": "That token was already revoked.",
}


def _msg_text(request: Request) -> str | None:
    """The flash message for this request, from `?msg=...`, or None."""
    msg = (request.query_params.get("msg") or "").strip()
    return _MSG_TEXT.get(msg)


def _panel_unavailable_in_this_mode():
    """The panel's refusal for capability / none modes — one answer, two uses.

    The accountless (`capability`) mode has no uid to attribute a token to and
    `none` has no owner auth at all, so neither can serve the panel. Rendered
    as a 404, not a 401, because the page does not exist in these modes rather
    than existing-but-forbidden: an operator who flipped to one of these modes
    has a working deployment, and finding a Kairos API-token page lurking under
    their URL would be the wrong answer.
    """
    from kairos.templating import create_env
    env = create_env()
    detail = (
        "This Kairos deployment manages polls by emailed capability link, so "
        "there are no owner accounts to mint tokens from. Use KAIROS_API_KEY / "
        "KAIROS_API_KEYS to configure static credentials, or switch "
        "KAIROS_AUTH to demo, header or oidc to enable owner-minted tokens."
        if settings.AUTH_MODE == "capability"
        else "This deployment has no owner authentication configured "
             "(KAIROS_AUTH=none), so no account can mint API tokens. Configure "
             "KAIROS_AUTH=demo, header or oidc to enable owner-minted tokens."
    )
    return render(
        env, "message.html", status_code=404,
        title="Tokens unavailable", heading="API tokens are not available here",
        error=False, user=None, detail=detail,
    )


def _login_or_401(next_path: str):
    """Mirror `web._login_or_401` without importing from it (cycles).

    The two-sentence copy is deliberately the same: an owner sent from
    `/tokens` to a login should read the same prompt as one sent from `/`.
    """
    from kairos.templating import create_env
    env = create_env()
    if settings.LOGIN_URL:
        return RedirectResponse(f"{settings.LOGIN_URL}?next={next_path}", status_code=302)
    return render(env, "message.html", status_code=401, title="Sign in required",
                  heading="Sign in required", error=True, user=None,
                  detail="This page is for poll owners. Sign in via your "
                         "organization's portal or identity proxy.")


def _render_panel(request, user, *, minted_plaintext=None, mint_error=None):
    """The one template render for `GET /tokens` and the post-mint redisplay.

    Stitches together everything the page needs: the owner's rows, the preset
    menu, the scope list, the CSRF-bound owner uid, and (for the one-time
    disclosure) the plaintext that was just minted. The plaintext is passed
    as an argument rather than through the session so there is no chance of
    it surviving across a redirect or into another owner's view — it exists
    only inside this HTTPResponse and is dropped the moment the page renders.
    """
    # Import inside to avoid a top-level cycle through web -> panel at startup.
    from kairos.templating import create_env
    from kairos.web import _nav_ctx

    env = create_env()
    rows = list_api_tokens(user["uid"])
    now = db_now()
    for row in rows:
        exp = row.get("expires_at")
        row["expired"] = exp is not None and _coerce_dt(exp) <= now
        row["revoked"] = row.get("revoked_at") is not None
        if row["revoked"]:
            row["state"] = "revoked"
        elif row["expired"]:
            row["state"] = "expired"
        else:
            row["state"] = "active"
    return render(
        env,
        "tokens.html",
        user=user,
        title="API tokens",
        rows=rows,
        scopes=SCOPES,
        presets=apitokens.PRESETS,
        default_preset=apitokens.DEFAULT_PRESET,
        prefix=apitokens.TOKEN_PREFIX,
        minted_plaintext=minted_plaintext,
        mint_error=mint_error,
        message=_msg_text(request),
        **_nav_ctx(user),
    )


def _coerce_dt(value):
    """Coerce a DB-read value to a `datetime`, for the "expired?" check.

    SQLite's `detect_types=PARSE_DECLTYPES` returns datetimes already; MariaDB's
    driver returns them too; a raw string is handled as the defensive fallback
    for mocks and the Durable-Object sqlite backend. Mirrors
    `kairos.apitokens._parse_dt` but is intentionally separate: this is a
    display-side classification, not an authentication branch, and swapping
    them would make a template render depend on an authentication helper.
    """
    from datetime import datetime
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return datetime.min


@router.get("/tokens")
def tokens_page(request: Request):
    """List this owner's tokens + the mint form. Owner-only, CSRF-protected POSTs."""
    if settings.AUTH_MODE in ("capability", "none"):
        return _panel_unavailable_in_this_mode()
    user = get_user(request)
    if not user:
        return _login_or_401(f"{P}/tokens")
    return _render_panel(request, user)


@router.post("/tokens")
def mint_token(request: Request, form=Depends(form_data)):
    """Mint a new token for the signed-in owner. The plaintext is in the response
    once; nothing else ever shows it.

    Validates the form up front (name, scopes, expiry) and re-renders the panel
    with an inline error on refusal — the invalid-input path writes nothing and
    costs the operator nothing to retry. On success, `apitokens.mint` returns
    the plaintext; we hand it to the template, which puts it inside a one-time
    disclosure banner and does not persist it beyond that render.
    """
    if settings.AUTH_MODE in ("capability", "none"):
        return _panel_unavailable_in_this_mode()
    user = get_user(request)
    if not user:
        return _login_or_401(f"{P}/tokens")
    require_csrf(user, form)
    name = (form.get("name") or "").strip()
    expiry_code = (form.get("expiry") or apitokens.DEFAULT_PRESET).strip()
    requested_scopes = [s for s in form.getlist("scopes") if s]
    seconds = apitokens.preset_seconds(expiry_code)
    if seconds is None:
        return _render_panel(request, user,
                             mint_error=f"Unknown expiry {expiry_code!r}.")
    try:
        plaintext, _row = apitokens.mint(
            owner_uid=user["uid"], name=name,
            scopes_list=requested_scopes, expires_in_seconds=seconds,
        )
    except ValueError as exc:
        return _render_panel(request, user, mint_error=str(exc))
    log.info("owner %s minted token %s with scopes %s",
             user["uid"], _row["prefix"], _row["scopes"])
    return _render_panel(request, user, minted_plaintext=plaintext)


@router.post("/tokens/{token_id}/revoke")
def revoke_token_route(token_id: str, request: Request,
                       form=Depends(form_data)):
    """Revoke one of this owner's tokens. Owner-only, CSRF-protected.

    A 404 for a token that does not belong to this owner (via the SQL guard in
    `db.revoke_api_token`). A second click answers `?msg=already-revoked`
    rather than throwing a 404, because that would read as "it worked", not
    as "it already was gone".
    """
    if settings.AUTH_MODE in ("capability", "none"):
        return _panel_unavailable_in_this_mode()
    user = get_user(request)
    if not user:
        return _login_or_401(f"{P}/tokens")
    require_csrf(user, form)
    revoked = revoke_api_token(token_id, user["uid"])
    # The missing / wrong-owner case and the "already revoked" case both come
    # back as False — one from the WHERE clause's owner guard, the other from
    # the `revoked_at IS NULL` guard. Distinguish them by re-reading the list
    # under the owner, so the owner is never told "that id does not exist" for
    # one of their own tokens (an information leak in the wrong direction).
    if not revoked:
        rows = list_api_tokens(user["uid"])
        if any(r["id"] == token_id for r in rows):
            return RedirectResponse(f"{P}/tokens?msg=already-revoked", status_code=302)
        raise HTTPException(404, "Token not found")
    log.info("owner %s revoked token %s", user["uid"], token_id)
    return RedirectResponse(f"{P}/tokens?msg=revoked", status_code=302)
