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
every other owner page. **Demo on a HOSTED deployment** is also out: demo
shares one dev identity across every visitor, which is fine as a local-dev
affordance but not on a `KAIROS_HOSTED` instance where every visitor would
see and revoke each other's tokens. Plain local demo (`HOSTED` off) still
has the panel.

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
from kairos.scoping import SCOPES  # noqa: F401 — kept for test monkeypatch seam
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


def _panel_is_unavailable() -> bool:
    """True if the current deployment cannot serve the panel at all.

    The accountless (`capability`) mode has no uid to attribute a token to and
    `none` has no owner auth at all, so neither can serve the panel.

    **Hosted demo is also out.** `demo` mode shares one dev identity across
    every visitor, which is fine as a local-dev affordance but not on a
    `KAIROS_HOSTED` deployment: any visitor would see and mint tokens under the
    shared uid, and one visitor's token would be revocable by the next. The
    panel therefore self-404s when `AUTH=demo` AND `HOSTED=on`. Plain local
    `demo` (not hosted) still has the panel, so a developer poking at the
    feature sees it.

    One function with `apitokens.tokens_enabled()` (inverted): the panel self-
    404s iff `resolve_token` refuses bearers, so flipping into any of these
    modes takes down the surface *and* its credentials at the same instant.
    Duplicating the check lets one half drift (PR #85 round-2 finding #3) --
    tokens outlived the panel, so a mode switch left live bearers behind.
    """
    return not apitokens.tokens_enabled()


def _panel_unavailable_in_this_mode():
    """The panel's refusal for capability / none / hosted-demo — one answer, three uses.

    Rendered as a 404, not a 401, because the page does not exist in these
    modes rather than existing-but-forbidden: an operator who flipped to one
    of these modes has a working deployment, and finding a Kairos API-token
    page lurking under their URL would be the wrong answer.
    """
    from kairos.templating import create_env
    env = create_env()
    if settings.AUTH_MODE == "capability":
        detail = (
            "This Kairos deployment manages polls by emailed capability link, so "
            "there are no owner accounts to mint tokens from. Use KAIROS_API_KEY / "
            "KAIROS_API_KEYS to configure static credentials, or switch "
            "KAIROS_AUTH to demo, header or oidc to enable owner-minted tokens."
        )
    elif settings.AUTH_MODE == "demo" and settings.HOSTED:
        detail = (
            "This deployment runs in demo mode on a KAIROS_HOSTED instance, so "
            "every visitor shares one identity — not an account to mint "
            "revocable tokens against. Configure KAIROS_AUTH=header or oidc to "
            "enable owner-minted tokens."
        )
    else:
        detail = (
            "This deployment has no owner authentication configured "
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


# Response headers for every panel render. `no-store` keeps the page out of a
# shared cache (a proxy) and the browser's history-back store, and the mint
# response disclosing the plaintext *especially* does not belong in either.
# `Pragma: no-cache` is for HTTP/1.0 intermediaries the typical tunnel still
# traverses. The panel has no reason to be cached at all — the list changes on
# every mint/revoke and the CSRF token is bound to one owner's session — so
# this applies to every response the panel returns, not just the one with the
# plaintext in it.
_NO_STORE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "Pragma": "no-cache",
}


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
        headers=dict(_NO_STORE_HEADERS),
        user=user,
        title="API tokens",
        rows=rows,
        # The checkbox list is the OWNER_GRANTABLE set only; operator-only
        # capabilities (`mail:force`, `imip:poll`) are never offered by the
        # UI and the server rejects them even if the form POST names one.
        # Sorted so the rendered order matches the documented set.
        scopes=sorted(apitokens.OWNER_GRANTABLE),
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
    if _panel_is_unavailable():
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
    if _panel_is_unavailable():
        return _panel_unavailable_in_this_mode()
    user = get_user(request)
    if not user:
        return _login_or_401(f"{P}/tokens")
    require_csrf(user, form)
    name = (form.get("name") or "").strip()
    expiry_code = (form.get("expiry") or apitokens.DEFAULT_PRESET).strip()
    requested_scopes = [s for s in form.getlist("scopes") if s]
    # Issue #82's "all" grant, expanded at mint time to the current
    # OWNER_GRANTABLE set (not a wildcard). The checkbox is a convenience on
    # top of the per-scope boxes; expanding here rather than storing "*" means
    # a grant minted today cannot silently widen when a new owner-grantable
    # capability is added — the owner's intent was the set as it was at mint,
    # not whatever the set becomes next year. Future capabilities will need a
    # new, deliberate mint, which is the issue's whole posture.
    if (form.get("scopes_all") or "").strip():
        requested_scopes = sorted(apitokens.OWNER_GRANTABLE)
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
    if _panel_is_unavailable():
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
            return RedirectResponse(
                f"{P}/tokens?msg=already-revoked",
                status_code=302, headers=dict(_NO_STORE_HEADERS),
            )
        raise HTTPException(404, "Token not found")
    log.info("owner %s revoked token %s", user["uid"], token_id)
    return RedirectResponse(
        f"{P}/tokens?msg=revoked",
        status_code=302, headers=dict(_NO_STORE_HEADERS),
    )
