"""Kairos configuration — all via environment variables, no config files.

KAIROS_DB_URL      sqlite:///kairos.db (default) | mysql://user:pass@host:port/db
KAIROS_PREFIX      URL prefix the app is mounted under (default "", e.g. "/scheduler")
KAIROS_AUTH        owner-auth mode: demo (default) | header | oidc |
                   capability | none. An unrecognised value refuses to boot
                   (it would otherwise silently disable owner auth).
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
KAIROS_HOSTED      declares a deployment WE operate (the hosted product, not a
                    self-hoster's own box). Off by default. When on, outbound
                    mail is refused unless it is authenticated from
                    KAIROS_FROM_DOMAIN — obligation M1.
KAIROS_FROM_DOMAIN the domain outbound is authenticated as, e.g.
                    nerdmachines.com or a dedicated mail.nerdmachines.com.
                    Hosted mode only; see docs/design/mail-auth.md.
KAIROS_FEED        reverse-calendar slot feeds + deep-link voting: off (default) | on
KAIROS_IMIP        native iMIP invitations (Accept/Maybe/Decline): off (default) | on
KAIROS_IMIP_ORGANIZER       reply mailbox = ORGANIZER mailto (must equal IMAP mailbox)
KAIROS_IMIP_ORGANIZER_NAME  ORGANIZER display name (default KAIROS_BRAND)
KAIROS_IMAP_HOST/PORT/USER/PASSWORD/MAILBOX   inbound iMIP reply polling (P2)
KAIROS_RATE_LIMIT      abuse limits on the public/email surface: off (default) | on
KAIROS_RATE_LIMIT_<RULE>   per-rule override, "<count>/<window>", e.g. "20/minute"
                   (window = second|minute|hour|day; count 0 disables that one
                   rule). Rules: READ RESPOND DEEPLINK_VOTE CREATE INVITE SEND
                   (public/web, charged to the transport peer) plus API
                   API_WRITE MAIL MAIL_FORCE (the /api surface, charged to the
                   bearer key — see kairos/scoping.py). One switch, two
                   families; both are off unless this is on.
KAIROS_API_KEYS   least-privilege API keys, ';'-separated, each either
                   "<key>:<scope>[,<scope>...]" or "<key>@<tier>", e.g.
                   "k1:polls:read,respond;k2:mail:send". Scopes: polls:read
                   polls:write respond mail:send mail:force imip:poll. A bare key
                   is refused (that would silently mean full power). Unset = no
                   scoped keys, and the single KAIROS_API_KEY keeps every
                   capability, unchanged (ADR-0001).
KAIROS_MAIL_MAX_RECIPIENTS  recipients one request may name, on every send path
                   (issue #51). 0 disables the cap. Default 100.
KAIROS_MAIL_PER_POLL  send budget for ONE poll as "<count>/<window>", counted in
                   recipients across every send path and charged to the poll, so
                   it holds regardless of which key asks. 0 disables. Default
                   "2000/day".
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

# The owner-auth mode, validated at import rather than merely read. Every mode is
# a string-dispatch in `auth.get_user`, so an unrecognised value is a mode that
# resolves nobody: `get_user` returns None, every owner page 401s, and a deployment
# whose owner auth silently stopped existing looks exactly like a deployment whose
# users are all logged out. That is the "a control the operator believes is in
# force and is not" failure, which this repo answers by refusing to boot --
# `_parse_networks` (#47) for an allowlist entry, `_parse_rate_limit` (#37) for a
# budget, `parse_keyring` (#51) for a key, `_validate_config` (#53) for OIDC.
#
# A recognised-value set rather than "anything else is false": a typo must not be
# able to silently disarm owner auth, which is what an `in (...)` check would let
# it do. An *empty* value is not a synonym for the default either -- `KAIROS_AUTH=`
# in a compose file would otherwise resolve nobody instead of falling back to
# `demo`, and quietly resolving nobody is the worse answer of the two, but falling
# back to `demo` means "everybody is the same owner", which is the one direction
# that fails open. Refusing to boot is the honest third option. Every mode that existed before #30 is in the set, so header mode (ETH),
# self-host and demo are byte-for-byte unchanged; only a value that was never a
# mode now fails, and it fails loudly instead of quietly.
AUTH_MODES = ("demo", "header", "oidc", "capability", "none")
# NOT stripped: `KAIROS_AUTH=" demo"` must be refused like any other unrecognised
# value rather than quietly resolving to the mode where everybody is the same
# owner. A strip here would make one stray space in a compose file the
# fail-open, which is precisely what the check above exists to prevent.
AUTH_MODE_RAW = os.environ.get("KAIROS_AUTH", "demo")
if AUTH_MODE_RAW not in AUTH_MODES:
    raise RuntimeError(
        f"KAIROS_AUTH: {AUTH_MODE_RAW!r} is not an owner-auth mode "
        f"({', '.join(AUTH_MODES)}). Kairos refuses to boot rather than run with no "
        f"owner auth at all — see README.md."
    )
AUTH_MODE = AUTH_MODE_RAW
AUTH_UID_HEADER = os.environ.get("KAIROS_AUTH_UID_HEADER", "X-User")
AUTH_EMAIL_HEADER = os.environ.get("KAIROS_AUTH_EMAIL_HEADER", "X-Email")
AUTH_NAME_HEADER = os.environ.get("KAIROS_AUTH_NAME_HEADER", "X-Name")
ALLOW = {a.strip().lower() for a in os.environ.get("KAIROS_ALLOW", "").split(",") if a.strip()}
BRAND = os.environ.get("KAIROS_BRAND", "Kairos")
HOME_URL = os.environ.get("KAIROS_HOME_URL", PREFIX + "/")
# Owner sign-in page; empty -> 401 message. In oidc mode Kairos serves its own
# sign-in page, so that is the default there — the other modes have no such
# page, and their operator points this at their proxy's (/oauth2/start).
LOGIN_URL = os.environ.get("KAIROS_LOGIN_URL") or ((PREFIX + "/login") if AUTH_MODE == "oidc" else "")
PUBLIC_URL = os.environ.get(
    "KAIROS_PUBLIC_URL", ""
)  # SSoT base for share links; empty -> derive from request headers
API_KEY = os.environ.get("KAIROS_API_KEY") or os.environ.get("SCHEDULER_API_KEY", "")

# Issue #51: least-privilege keys for the API/MCP surface, as
# "<key>:<scope>[,<scope>]", "<key>@<tier>". Exported raw and parsed by
# kairos.scoping, which owns the grammar — including the refusal to boot on a
# malformed entry, which cannot live here without importing the scope vocabulary
# (and an import cycle back through kairos.ratelimit). Empty = no scoped keys,
# which is the state every existing deployment is in: KAIROS_API_KEY alone still
# works and still reaches everything.
API_KEYS = os.environ.get("KAIROS_API_KEYS", "")

# Obligation S1 (issue #47): in header mode the owner identity comes from
# request headers, so whoever can reach the port can assert any identity —
# unless we know the request actually came through our proxy. Empty tuple =
# unset = trust every peer (the pre-existing behaviour, so the ETH/duplet and
# self-host deployments are untouched). Never consult X-Forwarded-For here:
# that header is exactly the thing an attacker controls.
TRUSTED_PROXY_CIDRS = os.environ.get("KAIROS_TRUSTED_PROXY_CIDRS", "")
TRUSTED_PROXY_NETWORKS = _parse_networks(TRUSTED_PROXY_CIDRS, "KAIROS_TRUSTED_PROXY_CIDRS")

# Obligation M1 (issue #48): outbound mail must be authenticated from a domain we
# control (SPF + DKIM + DMARC), never from a personal mailbox. Those records live in
# DNS, which Kairos can neither read nor publish, so the honest split is:
#
#   - this pair makes the *identity* we are about to send as explicit and checkable,
#     and turns a sender nobody could authenticate for us into a refusal rather than
#     a silent send;
#   - the DNS records themselves are the operator's, and docs/design/mail-auth.md
#     says exactly which ones to publish and how to check them.
#
# HOSTED is what separates the two worlds, and it is opt-in on purpose. A self-hoster
# or the ETH/duplet deployment has configured a relay that authenticates their own
# mail, which is their business and not something this app may second-guess — so unset
# means "no M1 gate", byte-for-byte the previous behaviour. Set it when *we* send from
# *our* domain and therefore own the reputation.
# A recognised-true set rather than "anything else is false": a typo like KAIROS_HOSTED=y
# must not silently disarm the gate, which is the failure mode a security control should
# never have. An unrecognised value keeps HOSTED off (the safe direction for self-host)
# but records itself so the boot line can WARN rather than quietly do nothing.
HOSTED_RAW = os.environ.get("KAIROS_HOSTED", "").strip()
HOSTED_TRUE = ("1", "on", "true", "yes")
HOSTED = HOSTED_RAW.lower() in HOSTED_TRUE
HOSTED_UNKNOWN = bool(HOSTED_RAW) and HOSTED_RAW.lower() not in HOSTED_TRUE + ("0", "off", "false", "no", "")
# Normalised, not validated: a typo must fail as a loud refusal naming this knob, not as
# an import error that would also break self-host, where the variable is unused. See
# kairos.email_service.sender_refusal().
FROM_DOMAIN = os.environ.get("KAIROS_FROM_DOMAIN", "").strip().strip(".").lower()

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

# The largest sweep `deeplink_vote` is sized for, derived from what the UI
# offers rather than asserted:
#   * 15 minutes is the SMALLEST increment in new_poll.html's slot-length select
#   * the default window is 09:00-17:00 (web.py create_poll_submit) = 8 hours
#   * 8h / 15min = 32 slots per day
#   * a full week of days = 224 slots, and agent.json hands an agent one vote URL
#     per slot, so a full-week sweep is 224 requests
# This is a realistic worst case, NOT a maximum: the date picker is an
# infinite-scroll calendar with no span cap, and `increment` is not validated on
# POST, so a poll can be arbitrarily larger. No per-source budget can be derived
# from a maximum that does not exist. A poll bigger than the budget needs either a
# raised KAIROS_RATE_LIMIT_DEEPLINK_VOTE or a sweep spread over more than one
# window; both are documented in the README.
SLOTS_PER_DAY_AT_FINEST_OFFERED_INCREMENT = 32  # (17:00 - 09:00) / 15min
FULL_WEEK_SWEEP_VOTES = SLOTS_PER_DAY_AT_FINEST_OFFERED_INCREMENT * 7

# Shipped defaults, per rule: (count, window seconds). Generous on the
# respondent-facing rules, tight on the ones that write rows or open an SMTP
# connection. Every value is overridable; none apply unless enabled.
DEFAULT_RATE_LIMITS = {
    "read": (120, 60),  # token pages: poll, invite, agent.json, feeds, .ics
    "respond": (20, 60),  # POST /p/<token>, POST /p/i/<token>
    # One vote URL per slot, so an agent sweep of a poll costs len(slots)
    # requests. Sized to clear FULL_WEEK_SWEEP_VOTES inside a single window;
    # asserted against it in tests/test_ratelimit.py.
    "deeplink_vote": (300, 60),
    "create": (10, 60),  # POST /new
    "invite": (30, 60),  # POST /polls/<id>/invite — grows the recipient list
    "send": (10, 3600),  # remind / remind-selected / email-decision — actual SMTP
    # OIDC login. The only two rules here on endpoints that are unauthenticated
    # *and* make an outbound call to a third party per request (token exchange,
    # and a JWKS fetch on a cache miss), so they are the cheapest possible
    # amplification. Inert in every other mode — the routes 404.
    "login": (30, 60),  # GET /oidc/start, GET /oidc/callback
    # The /api surface, issue #51. Same switch, same override syntax, same
    # limiter and the same `RateLimited` signal as the six above; the only
    # difference is what the budget is charged to — a bearer key rather than a
    # transport peer, because an API caller presents something it cannot vary and
    # a peer-keyed budget is evaded by source rotation. Sized, in order:
    #   `api` is the floor under every authenticated call. An agent that walks a
    #   poll through the API spends tens of requests, so 600/min is a runaway-loop
    #   ceiling rather than a workflow budget.
    #   `api_write` covers the mutating routes. A full-week slot sweep is ONE
    #   add_dates call, not one per slot, so this is orders of magnitude above any
    #   real workflow.
    #   `mail` is the tight one, per ADR-0012's parity rule it must NOT be tighter
    #   than the human path: the web UI's `send` above is 10/hour per address, and
    #   an agent key is a single identity behind one NAT often enough that the
    #   budget has to be the larger of the two or the agent path is second-class.
    #   `mail_force` is the cooldown bypass, deliberately the tightest thing here:
    #   5/hour is "a human pressing the button a few times", not "an agent looping".
    "api": (600, 60),
    "api_write": (60, 60),
    "mail": (20, 3600),
    "mail_force": (5, 3600),
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


def _parse_count(raw: str, var: str) -> int:
    """A non-negative integer knob. 0 means "no limit", never "no value"."""
    try:
        count = int(raw.strip())
    except ValueError:
        raise RuntimeError(f"{var}: {raw!r} is not an integer count") from None
    if count < 0:
        raise RuntimeError(f"{var}: {raw!r} must be 0 (no limit) or a positive count")
    return count


# Blast-radius ceilings on outbound mail (issue #51). ON by default, unlike the
# rate limits above, and deliberately so:
#
#   * a rate limit is keyed on an identity and punishes a shared one — a whole
#     office behind one NAT, or the ETH/duplet deployment's single egress — so
#     #37's are opt-in and stay that way;
#   * this is a ceiling on how much mail a *request* may name and how much one
#     *poll* may send. Neither is keyed on an address, neither punishes anybody
#     legitimate at the shipped values, and both are finite — which is the whole
#     difference between "a mail cannon" and "an API".
#
# The per-request cap is on the recipient LIST the caller supplies, so refusing
# costs the caller nothing they cannot get back by splitting the call. Fan-out
# routes (nudge, email-decision) take their recipients from the poll, where a
# big list is a real meeting rather than an attack, so they are bounded by the
# per-poll budget below instead — a 429 they can retry tomorrow, not a 400 that
# makes a 500-person meeting undecidable.
MAIL_MAX_RECIPIENTS = _parse_count(
    os.environ.get("KAIROS_MAIL_MAX_RECIPIENTS", "100"), "KAIROS_MAIL_MAX_RECIPIENTS"
)

# Recipients one poll may mail per window, across every send path (API and web
# UI), charged to the poll so it holds regardless of which key asks. 2000/day is
# 500 participants x the ~4 messages a legitimate poll sends each (invite,
# reminder, new-dates notice, decision), so a large meeting fits in one window
# and a mail cannon does not. Raise it for bigger meetings; 0 disables.
MAIL_PER_POLL = _parse_rate_limit(os.environ.get("KAIROS_MAIL_PER_POLL", "2000/day"), "KAIROS_MAIL_PER_POLL")


def session_secret() -> str:
    secret = os.environ.get("SESSION_SECRET", "")
    if not secret:
        if AUTH_MODE == "demo":
            return "kairos-demo-not-secret"
        raise RuntimeError("SESSION_SECRET is not configured")
    return secret
