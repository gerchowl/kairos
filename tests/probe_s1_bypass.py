"""Probe: can a forged X-Forwarded-For get past KAIROS_TRUSTED_PROXY_CIDRS?

Run *inside* the container, against `http://127.0.0.1:8003`, by CI's `image` job
and by anyone reproducing the claim in `docs/design/self-host-hardening.md`:

    podman cp tests/probe_s1_bypass.py <container>:/probe.py
    podman exec <container> python /probe.py http://127.0.0.1:8003

Loopback is not incidental. Uvicorn's `ProxyHeadersMiddleware` only rewrites
`scope["client"]` for peers it considers local (`forwarded_allow_ips`, 127.0.0.1
by default), so a request that arrives over a published port is NOT rewritten by
uvicorn and the probe cannot see the difference. From inside, both arms differ
only by `proxy_headers`, which is the variable under test.

Exit code is the assertion: 0 = the allowlist held, 1 = it was bypassed and a
poll was created under a forged identity. That direction is deliberate, so CI
can `!` it for the positive control (bare uvicorn must bypass) and use it
directly for the shipped CMD (must not).

The route is `POST /new`, not `POST /api/polls`: the API surface is
Bearer-key gated (`Depends(require_api_key)`) and its creator comes from
`user["uid"]`, which is the literal string "api". It never reads an identity
header, so it cannot demonstrate anything about header trust — a probe built on
it passes for the wrong reason.

Not collected by pytest (only `test_*.py` is); this is a CI/manual probe.
"""

import re
import sys
import urllib.error
import urllib.parse
import urllib.request

FORGED_IDENTITY = {
    # The address the caller claims. Inside the allowlist, so uvicorn's rewrite
    # (if enabled) makes the request look like it came from the trusted proxy.
    "X-Forwarded-For": "192.0.2.7",
    # The identity the caller asserts. In header mode this becomes the owner.
    "X-User": "attacker",
    "X-Email": "attacker@example.org",
}
MARKER = "s1-bypass-marker"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def call(request):
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        response = opener.open(request)
        return response.status, response.read(), response.headers
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.headers


def main() -> int:
    base = sys.argv[1]
    prefix = sys.argv[2] if len(sys.argv) > 2 else ""
    new = f"{prefix}/new"

    status, body, _ = call(urllib.request.Request(base + new, headers=FORGED_IDENTITY))
    print(f"  GET  {new}  forged XFF + X-User: attacker -> {status}")
    if status != 200:
        print("  allowlist held: the page did not render for the forged identity")
        return 0

    # The form carries a CSRF token bound to the asserted uid, which the
    # attacker obtained precisely because step 1 succeeded.
    match = re.search(r'name="csrf" value="([^"]+)"', body.decode(errors="replace"))
    if not match:
        print("  rendered, but no CSRF field found — cannot complete the forgery")
        return 0

    form = urllib.parse.urlencode(
        {
            "csrf": match.group(1),
            "title": MARKER,
            "mode": "full_day",
            "timezone": "Europe/Zurich",
            "dates": "2026-12-01",
        }
    ).encode()
    status, _, headers = call(urllib.request.Request(base + new, data=form, headers=FORGED_IDENTITY))
    print(f"  POST {new}  forged identity, CSRF bound to 'attacker' -> {status}")
    if status != 302:
        print("  form submission refused; no poll created")
        return 0

    print(f"  poll created at {headers.get('Location')}")
    status, body, _ = call(urllib.request.Request(f"{base}{prefix}/", headers=FORGED_IDENTITY))
    listed = MARKER in body.decode(errors="replace")
    print(f"  GET  {prefix}/  dashboard as attacker -> {status}, lists the poll: {listed}")
    print("  ALLOWLIST BYPASSED: the forged identity owns a poll")
    return 1


if __name__ == "__main__":
    sys.exit(main())
