"""Abuse limits on the public/email surface — obligation A3, issue #37.

Public endpoints are an open write surface (a stranger with a share link can
create polls, rows and notifications), and the owner-side endpoints are an
outbound-mail surface (one `remind-selected` fans out to every address on the
participants table). Before a hosted Kairos is public, both need a budget.

**Deliberately in-process.** SQLite is the only dialect #36 shipped, its stated
operational ceiling is one writer, and a counter table would add a write to
every public request — contending with poll writes for the thing that is
already the bottleneck. The honest cost: **counters are per-process, so N app
instances give an attacker N x the budget.** #36's revisit trigger ("more than
one app instance") is exactly the trigger for moving these to a shared store.
The seam is `RateLimiter.check`, which takes the limit and window as arguments
and holds no settings of its own — swapping the dict for Redis or a SQL table
is a change inside this file, not at the call sites.

**Fail-open vs fail-closed.** Split by what can actually fail, because they are
not the same failure:

- *Misconfiguration* → **fail closed, at boot.** `_parse_rate_limit` raises, so
  a typo'd limit is a process that refuses to start rather than a control that
  silently is not there (#47's lesson).
- *Unset* → **not a failure at all.** No env means no limiting, which is what
  ADR-0001/0002 require of header mode and self-host.
- *An internal fault here* → **fail open**, logged. This is the one judgement
  call. The alternative locks every respondent out of the poll for a bug in a
  dict increment; the abuse this guards is bounded anyway (a poll's own invite
  list, and the existing 24h reminder cooldown). It is also not attacker-
  reachable — there is no untrusted input on this path, and the keyspace is
  bounded — so "fail open" cannot be triggered from the outside. **If the
  counters ever move to a shared store, that stops being true and this branch
  must flip to fail closed.** Marked in the code.
"""

import logging
import math
import threading
import time

from fastapi import Request

from kairos import settings
from kairos.auth import peer_address

log = logging.getLogger("kairos.ratelimit")

# Cap on distinct (rule, peer) buckets held in memory. Source addresses are
# attacker-chosen (each request can present a new one), so the dict is an
# unbounded-growth target unless it is trimmed.
MAX_BUCKETS = 50_000

_warned_no_peer = False


class RateLimiter:
    """Fixed-window request counters, keyed by (rule, caller).

    Fixed windows rather than sliding ones because the numbers an operator sets
    here are meant to be readable ("20/minute") and because a respondent (or
    their agent) legitimately emits a burst proportional to the poll's slot
    count, which a sliding log punishes. The cost is the usual one: a client can
    spend 2x the limit by straddling a window boundary. That is a factor of two
    on a control whose job is to stop orders-of-magnitude abuse.

    Settings are read at call time by the caller, not captured here, so tests
    (and a future reconfigure) can change them without rebuilding this.
    """

    def __init__(self, max_buckets: int = MAX_BUCKETS):
        self._buckets: dict = {}  # (rule, key) -> (window_start, count, window)
        self._max_buckets = max_buckets
        self._lock = threading.Lock()

    def check(
        self, rule: str, limit: int, window: int, key: str, now: float | None = None
    ) -> tuple[bool, int]:
        """Charge one request against (rule, key).

        Returns (allowed, retry_after_seconds). Never raises — the fail-open
        behaviour described in the module docstring lives at the call site.
        """
        if limit <= 0:
            return True, 0
        now = time.monotonic() if now is None else now
        with self._lock:
            if len(self._buckets) > self._max_buckets:
                self._trim(now)
            bucket = (rule, key)
            start, count, width = self._buckets.get(bucket, (now, 0, window))
            if now - start >= width:
                start, count = now, 0
            if count >= limit:
                return False, max(1, math.ceil(width - (now - start)))
            self._buckets[bucket] = (start, count + 1, width)
        return True, 0

    def _trim(self, now: float) -> None:
        """Drop expired buckets; if still over cap, drop the oldest.

        Caller holds the lock. Dropping the oldest first is safe because those
        windows are closest to resetting anyway — a trimmed caller gets one more
        request, not unlimited ones, and only above 50k distinct keys.
        """
        stale = [k for k, (start, _, width) in self._buckets.items() if now - start >= width]
        for bucket in stale:
            del self._buckets[bucket]
        if len(self._buckets) <= self._max_buckets:
            return
        overflow = len(self._buckets) - self._max_buckets
        oldest = sorted(self._buckets, key=lambda k: self._buckets[k][0])[:overflow]
        for bucket in oldest:
            del self._buckets[bucket]

    def reset(self) -> None:
        """Forget every counter. Tests only — there is no endpoint for this."""
        with self._lock:
            self._buckets.clear()


limiter = RateLimiter()


class RateLimited(Exception):
    """A budget was exhausted. Adapters turn this into an HTTP response."""

    def __init__(self, rule: str, retry_after: int):
        super().__init__(f"rate limit {rule!r} exceeded")
        self.rule = rule
        self.retry_after = retry_after


def caller_key(request: Request) -> str | None:
    """The identity the budget is charged to, or None if there is not one.

    Always the real transport peer, never X-Forwarded-For: that header is
    attacker-controlled, so keying on it would make the budget one the caller
    sets themselves. Same rule, same reason as `peer_is_trusted`.

    Returns None when the ASGI scope carries no client address — a unix-socket
    listener, or a TestClient. Such a caller is not attributable, and folding
    every local request into one shared bucket would break the operator's own
    deployment, which is the regression ADR-0001/0002 forbid. Unattributable
    means unlimited here, loudly.
    """
    global _warned_no_peer
    peer = peer_address(request)
    if peer is None:
        if not _warned_no_peer:
            _warned_no_peer = True
            log.warning(
                "cannot rate limit: this request carries no transport peer "
                "(unix-socket listener?). It is allowed through; a public TCP "
                "deployment always has a peer address."
            )
        return None
    return peer


class rate_limit:  # lower-case so call sites read `Depends(rate_limit("..."))`
    """FastAPI dependency: charge this request against a named budget.

        @router.post("/p/{token}")
        def submit(request: Request, _=Depends(rate_limit("respond"))): ...

    A class rather than a closure so the rule it enforces is inspectable — the
    route-audit test reads `dependant.call.rule` off the app's route table,
    which is what stops a new public route from shipping unprotected.
    """

    def __init__(self, rule: str):
        if rule not in settings.RATE_LIMITS:
            raise RuntimeError(
                f"{rule!r} is not a rate-limit rule ({', '.join(sorted(settings.RATE_LIMITS))})"
            )
        self.rule = rule

    def __call__(self, request: Request) -> None:
        if not settings.RATE_LIMIT_ENABLED:
            return
        key = caller_key(request)
        if key is None:
            return
        limit, window = settings.RATE_LIMITS[self.rule]
        try:
            allowed, retry_after = limiter.check(self.rule, limit, window, key)
        except Exception:
            # Fail OPEN (see the module docstring) — and only because this is a
            # bug, not an input. Flip to fail closed when the counters move to a
            # shared store, where an outage would also mean "no limits anywhere".
            log.exception("rate limiter failed; allowing the request")
            return
        if not allowed:
            log.warning("rate limit %s exceeded by peer %s", self.rule, key)
            raise RateLimited(self.rule, retry_after)


def install(app) -> None:
    """Register the app-level handler that turns `RateLimited` into a response.

    One handler, content-negotiated, rather than a variant of the dependency per
    surface: a token page can be opened from a tap on a calendar event, so the
    person standing there gets an HTML page with a Retry-After; the API and MCP
    surfaces (#51) get JSON. Both carry the header, because a well-behaved
    client needs to know when to come back.
    """
    from fastapi.responses import JSONResponse

    from kairos.helpers import env
    from kairos.templating import render

    if settings.RATE_LIMIT_ENABLED:
        # Same load-bearing dependency the trusted-proxy allowlist has, for the
        # same reason: budgets are charged to scope["client"], and a server that
        # rewrote that from X-Forwarded-For first would make every request look
        # like a brand-new caller. Measured over a real socket, with the rewrite
        # on, a rotating XFF evades the budget entirely.
        log.warning(
            "KAIROS_RATE_LIMIT is on, so the ASGI server MUST NOT rewrite the client "
            "address from X-Forwarded-For -- budgets are charged to the transport peer, "
            "and a rewritten peer makes every request look like a new caller. The "
            "`kairos` entrypoint passes proxy_headers=False; if you launch uvicorn "
            "yourself, do the same (uvicorn --no-proxy-headers)."
        )

    @app.exception_handler(RateLimited)
    async def _rate_limited(request: Request, exc: RateLimited):
        retry_after = str(exc.retry_after)
        if "text/html" in request.headers.get("accept", ""):
            return render(
                env, "message.html", status_code=429, title="Slow down",
                heading="Too many requests",
                detail=f"This link is being used too often. Please wait "
                       f"{exc.retry_after} seconds and try again.",
                error=True, noindex=True, headers={"Retry-After": retry_after},
            )
        return JSONResponse(
            {"detail": f"Rate limit exceeded for '{exc.rule}'. Retry in {exc.retry_after}s."},
            status_code=429,
            headers={"Retry-After": retry_after},
        )
