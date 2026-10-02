"""`kairos` console entrypoint — instant local instance (SQLite + demo auth)."""

import argparse
import os
from urllib.parse import urlparse, urlunparse

DEFAULT_DB_URL = "sqlite:///kairos.db"


def redacted_db_url(raw: str) -> str:
    """`raw` with any URL password replaced, for display.

    The startup banner is printed to stdout, which in a container is the
    container log — and from there the journal and every log shipper. A MySQL
    URL carries its credential in the userinfo, so printing the raw value
    publishes it in cleartext to a stream nobody audits and nobody rotates.
    The credential still lives where it belongs: the environment.

    Userinfo is rebuilt rather than pattern-matched, because a regex over a URL
    is how you end up leaking the part after the password on some other scheme.
    """
    parsed = urlparse(raw)
    if parsed.password is None:
        return raw  # sqlite paths, and any URL without credentials
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunparse(parsed._replace(netloc=f"{parsed.username}:***@{host}"))


def main():
    parser = argparse.ArgumentParser(description="Run a Kairos scheduling-poll server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8003)
    parser.add_argument("--db", default=None, help="sqlite path or KAIROS_DB_URL (default ./kairos.db)")
    args = parser.parse_args()

    if args.db:
        os.environ["KAIROS_DB_URL"] = args.db if "://" in args.db else f"sqlite:///{args.db}"

    import uvicorn

    from kairos import settings

    trusted = (
        f"trusted-proxies={settings.TRUSTED_PROXY_CIDRS}"
        if settings.TRUSTED_PROXY_NETWORKS
        else "trusted-proxies=ANY (set KAIROS_TRUSTED_PROXY_CIDRS to restrict)"
    )
    print(
        f"Kairos → http://{args.host}:{args.port}{settings.PREFIX}/  "
        f"(auth={settings.AUTH_MODE}, "
        f"db={redacted_db_url(os.environ.get('KAIROS_DB_URL', DEFAULT_DB_URL))}, "
        f"{trusted})"
    )
    # proxy_headers=False is load-bearing, not a preference. Uvicorn defaults it
    # on and then rewrites scope["client"] from X-Forwarded-For for peers it
    # deems local — so kairos.auth.peer_address() would hand back the client's
    # *claimed* address and KAIROS_TRUSTED_PROXY_CIDRS would be checked against
    # a value the caller supplied. Verified against uvicorn 0.54: with
    # proxy_headers=True a request carrying `X-Forwarded-For: 203.0.113.99`
    # reports client.host=203.0.113.99; with it False, client.host is the true
    # peer. Kairos reads forwarded headers itself where it needs them
    # (auth.get_base_url).
    uvicorn.run("kairos.main:app", host=args.host, port=args.port, proxy_headers=False)


if __name__ == "__main__":
    main()
