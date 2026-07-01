# 0002 — Accountless respondents; reverse-proxy header auth for owners

Status: **Accepted**

## Context
Respondents should not need accounts. Owners need identity, but Kairos should not
own authentication (passwords, OAuth, sessions).

## Decision
Respondents self-identify (name) or use their invite token. Owner identity comes
from **trusted reverse-proxy headers** (`KAIROS_AUTH=header`) — Shibboleth,
oauth2-proxy, Authelia, Cloudflare Access, Tailscale. Kairos implements no
password/OAuth flow in core.

## Consequences
- Must sit behind an **authenticating proxy**; exposed raw, header spoofing =
  impersonation (documented as the #1 self-host hardening requirement).
- Integrates with existing SSO for free.
- Hosted adds `capability`/`account` auth modes (ADR-0009) without changing this.
