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

**What this does not stop: source-address rotation.** A budget keyed on an
address is evaded by never reusing one. An attacker with an IPv6 /64 has ~2^64
addresses and defeats every budget here trivially, which is why production
limiters bind something the client cannot vary — a cookie, or an API key. The
mitigation in scope is the *ceiling*, not the identity: the keyspace is bounded
at `MAX_BUCKETS` so rotation cannot be turned into unbounded memory or CPU, and
the budgets still cap how much a caller can do from **one** address, which is the
polite-abuse and single-source-flood case this actually targets.

The API surface (issue #51) is that missing "something the client cannot vary",
and it landed on the bearer key: `kairos.scoping` charges four more rules
(`api`, `api_write`, `mail`, `mail_force`) to `key:<digest>` instead of to a
peer, using **this** limiter and this `RateLimited` signal. One mechanism, two
things to charge. Its per-poll send budget additionally reuses `check` with
`cost=n`, because it counts recipients rather than requests.

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
from kairos.auth import address_is_trusted, canonical_address, peer_address, peer_is_trusted

log = logging.getLogger("kairos.ratelimit")

# Cap on distinct (rule, peer) buckets held in memory. Source addresses are
# attacker-chosen (each request can present a new one), so the dict is an
# unbounded-growth target unless it is trimmed.
MAX_BUCKETS = 50_000

# Unattributed requests (no peer in scope) cannot be charged to anyone. Counted,
# not warned-once: a control that is silently inert is worse than one that is off.
_no_peer_events = 0
_NO_PEER_REWARN_EVERY = 1000


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
        # Bounding memory must be amortised over the traffic that caused it.
        # Sweeping whenever the table is full makes the cost per request
        # O(len(table)) forever, once an attacker has filled it -- measured at
        # ~4ms per request at 50k buckets, paid by *every* user behind the
        # attacker. Once per `sweep_every` charges instead, it is ~8 element
        # visits per request amortised regardless of table size.
        self._sweep_every = max(1, max_buckets // 8)
        self._charges_since_sweep = 0
        self.sweeps = 0  # test-visible: how often the bound actually ran
        self._lock = threading.Lock()

    def check(
        self,
        rule: str,
        limit: int,
        window: int,
        key: str,
        now: float | None = None,
        cost: int = 1,
    ) -> tuple[bool, int]:
        """Charge one request against (rule, key).

        `cost` charges N units rather than one, for a budget denominated in
        something other than requests — issue #51's per-poll send budget counts
        *recipients*, so 60 invites of 10 addresses each is 600 and not 60. It is
        charged under the one lock and refused before any of it lands, so a
        partial charge is not expressible. At `cost=1` the rule below is
        byte-for-byte the pre-#51 one.

        Returns (allowed, retry_after_seconds). Never raises — the fail-open
        behaviour described in the module docstring lives at the call site.
        """
        if limit <= 0:
            return True, 0
        now = time.monotonic() if now is None else now
        with self._lock:
            bucket = (rule, key)
            start, count, width = self._buckets.get(bucket, (now, 0, window))
            if now - start >= width:
                start, count = now, 0
            if count + cost > limit:
                return False, max(1, math.ceil(width - (now - start)))
            # pop-then-set so dict order is least-recently-charged first, which
            # is the order both eviction paths below walk.
            self._buckets.pop(bucket, None)
            self._buckets[bucket] = (start, count + cost, width)
            if len(self._buckets) > self._max_buckets:
                # Hard ceiling. O(1) amortised: evict exactly as many entries as
                # this insert added, never a scan and never a sort. This is the
                # path that runs on *every* request once an attacker has filled
                # the table, so it has to be O(1) -- it is not, an earlier version
                # swept the whole 50k-entry table here and cost ~4ms per request
                # that every user behind the attacker then paid.
                while len(self._buckets) > self._max_buckets:
                    del self._buckets[next(iter(self._buckets))]
                # Reclaiming the expired ones in bulk is quality-of-eviction, not
                # a memory requirement, so it is amortised over traffic instead.
                self._charges_since_sweep += 1
                if self._charges_since_sweep >= self._sweep_every:
                    self._charges_since_sweep = 0
                    self.sweeps += 1
                    self._sweep_expired(now)
        return True, 0

    def _sweep_expired(self, now: float) -> None:
        """Drop every window that has already turned over. Caller holds the lock.

        O(len(table)), which is why it is amortised rather than run per request.
        It exists so the O(1) eviction in `check` usually sheds an expired window
        instead of a live one: a table only overflows in the first place if the
        caller is churning through distinct addresses, and those windows are
        mostly stale by the time the cap is reached.
        """
        stale = [k for k, (start, _, width) in self._buckets.items() if now - start >= width]
        for bucket in stale:
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


def forwarded_client(request: Request) -> str | None:
    """The nearest hop in the forwarded chain that one of *our* proxies did not assert.

    Only consulted when the transport peer is trusted **and** an allowlist is
    configured. Without an allowlist there is nothing that says which hop to
    believe, so the header stays caller-supplied and is ignored entirely.

    Why right-to-left, and why that is not rotation-attackable: XFF is built by
    *appending*, so a request that reached us through two of our proxies reads
    `<client-claim>, <ip-proxy-a-saw>, <ip-proxy-b-saw>`, and the right-hand
    entries are the ones written by the hops closest to us. An attacker's own
    contribution can only be at the **left** end -- they send a header, our proxy
    appends the address it actually saw. So walking from the right and skipping
    addresses inside our allowlist always lands on a value asserted by our own
    nearest proxy about a socket it directly held; the attacker's value is never
    reached. It could only be reached if a proxy *replaced* the header instead of
    appending, which is a proxy misconfiguration rather than caller input, and is
    the same class of hazard the `proxy_headers` warning already names.

    Walking from the left instead would hand back the attacker's own claim --
    precisely the rotation this control exists to stop.
    """
    if not settings.TRUSTED_PROXY_NETWORKS or not peer_is_trusted(request):
        return None
    for hop in reversed(request.headers.get("x-forwarded-for", "").split(",")):
        hop = hop.strip()
        if hop and not address_is_trusted(hop):
            return hop
    # Every hop is inside the allowlist (or the header is absent): there is no
    # untrusted hop to name, so the caller falls back to the peer.
    return None


def caller_key(request: Request) -> str | None:
    """The identity the budget is charged to, or None if there is not one.

    The real transport peer -- never a bare `X-Forwarded-For`, because that header
    is attacker-controlled and keying on it would make the budget one the caller
    sets for themselves.

    Behind a reverse proxy the peer is the *proxy's* socket address for every
    single request, so keying on it alone would hand the whole deployment one
    shared budget: every user behind that proxy would spend the same `create`
    10/min and the same `send` 10/hour. Not hypothetical -- TLS termination in
    front is universal, and the README tells operators Kairos sits behind
    "whatever reverse proxy you already run". So when the peer is trusted and an
    allowlist is configured, the nearest untrusted forwarded hop identifies the
    caller instead. See `forwarded_client`.

    Returns None when the ASGI scope carries no client address (a unix-socket
    listener). Such a caller is not attributable, and folding every local request
    into one shared bucket would break the operator's own deployment, which is the
    regression ADR-0001/0002 forbid. Unattributable means unlimited here, loudly
    and repeatedly -- see `_note_unattributable`.
    """
    peer = peer_address(request)
    if peer is None:
        _note_unattributable()
        return None
    return canonical_address(forwarded_client(request) or peer)


def _note_unattributable() -> None:
    """Warn about traffic that cannot be charged to anyone, and keep a count.

    Warn-once was too quiet: the condition is nearly always a deployment mistake
    (a unix-socket listener where a TCP one was expected) that nobody notices for
    weeks, and a control that is silently inert is worse than one that is switched
    off. Re-warn periodically so a long-lived process still says something.
    """
    global _no_peer_events
    _no_peer_events += 1
    if _no_peer_events <= 3 or _no_peer_events % _NO_PEER_REWARN_EVERY == 0:
        log.warning(
            "cannot rate limit: request #%d carries no transport peer "
            "(unix-socket listener?). Allowed through unattributed; a public TCP "
            "deployment always has a peer address.",
            _no_peer_events,
        )


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
                env,
                "message.html",
                status_code=429,
                title="Slow down",
                heading="Too many requests",
                detail=f"This link is being used too often. Please wait "
                f"{exc.retry_after} seconds and try again.",
                error=True,
                noindex=True,
                headers={"Retry-After": retry_after},
            )
        return JSONResponse(
            {"detail": f"Rate limit exceeded for '{exc.rule}'. Retry in {exc.retry_after}s."},
            status_code=429,
            headers={"Retry-After": retry_after},
        )
