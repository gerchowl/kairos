# M1 — authenticating outbound mail (SPF / DKIM / DMARC)

Obligation **M1** from [`productization-obligations.md`](productization-obligations.md):
*"Outbound is authenticated from our domain (SPF/DKIM/DMARC), never a personal
Gmail."* Source: ADR-0011 (nerdmachines house brand). Issue #48.

This is the runbook for the part of M1 that **Kairos cannot do for you**. Kairos
publishes no DNS and reads no DNS — it has no DNS library, and adding one is a
licence/pip-audit gate — so it can neither set these records nor confirm they are in
force. What it *does* do is refuse to send from a sender nobody could authenticate
for us (see [the code half](#the-code-half-fail-closed-refusal)), so that a
half-configured deployment stops loudly instead of quietly mailing from a personal
mailbox.

> **Prerequisite, still open:** every record below lives in the DNS zone for a domain
> we control. The register's open dependency — *confirm `nerdmachines.com` registration is
> under our control* — gates all of it. Nothing here works around that.

If you are **self-hosting** Kairos for your own team, none of this applies to you:
set `SMTP_FROM` to your own mailbox, leave `KAIROS_HOSTED` unset, and your existing
relay and DNS keep working exactly as before. This document is for the case where
*we* send from *our* domain.

---

### The code half: fail-closed refusal

`kairos.email_service` enforces the precondition that the records above are supposed
to satisfy, so a misconfiguration is a refusal rather than a silent send:

- **`KAIROS_HOSTED`** turns the gate on. Unset (the default), every check below is
  skipped and behaviour is byte-for-byte what it always was — which is what keeps
  self-host and ETH/duplet untouched.
- **`KAIROS_FROM_DOMAIN`** names the domain outbound is authenticated as.
- The gate runs in `is_configured()`, the one predicate every send path already
  consults (`send_invite_email`, `send_imip`, `send_update_emails`,
  `send_decision_email`), so a refused identity silences all of them and a new send
  path cannot forget it. A refusal is logged **once** per process, naming the knob.
- In hosted mode Kairos refuses to send when `KAIROS_FROM_DOMAIN` is unset or is a
  consumer mailbox provider, or when `SMTP_FROM` / `KAIROS_IMIP_ORGANIZER` is not a
  mailbox on that domain.
- Every boot logs one line naming the identity it is about to send as, whether the
  gate is in force, and that the DNS records must exist — the only honest signal
  available, since Kairos cannot read DNS.

The gate deliberately does **not** claim to verify SPF/DKIM/DMARC. It verifies that
the identity being used is one that *could* be authenticated, which is the part
Kairos can actually see.

## 1. The shape to use: a dedicated sending subdomain

**Proposed default (an operator decision, not a code decision): send from
`mail.nerdmachines.com`, not `nerdmachines.com`.**

Three reasons, in order of how much they matter:

1. **Reputation isolation.** A sending domain's reputation is a single shared
   resource. If anything ever abuses Kairos — a spam poll, a scraped API key, a
   mass-invite on a hostile list — the damage lands on whatever domain we send from.
   A dedicated subdomain means the brand domain (which presumably also carries other
   mail) is not in the blast radius. This is the highest-value, lowest-effort
   mitigation available and it costs one DNS record set.

2. **SPF does not have to be renegotiated.** The apex almost certainly already has
   an SPF record — if you read mail from Gmail you have `include:`d Google there. To
   add a second sender to the apex you must append to that record, against a hard
   limit of **10 DNS-query lookups** (RFC 7208 §4.6.4), and you then cannot use
   `-all` (hard fail) without being certain you have listed every sender. On a fresh
   subdomain the record is yours alone and `-all` is safe.

3. **DMARC policy isolation.** Receivers look for a DMARC record starting at the
   visible From domain and walk **up** to the organisational domain if there is none.
   So a sending subdomain with *no* DMARC record of its own inherits the apex's
   policy. If the apex ever reaches `p=reject`, a misconfigured send from the
   subdomain is judged against that strict policy. Publishing an explicit record on
   the sending subdomain is what actually isolates it.

The cost is one more thing to remember, and the code enforces it: with
`KAIROS_FROM_DOMAIN=mail.nerdmachines.com`, the **iMIP organizer mailbox must live on
that subdomain too** (see [§6](#6-replies-forwarding-and-alignment)). A relay that
only signs `mail.*` cannot send an invitation whose visible From is
`organizer@nerdmachines.com` and have it authenticate.

---

## 2. The DNS records

Assume the sending domain is `mail.nerdmachines.com` and the From address is
`kairos@mail.nerdmachines.com`. Substitute your own — these are the shapes.

### SPF

```
mail.nerdmachines.com.  TXT  "v=spf1 include:<your-provider's-spf> -all"
```

- **`-all` (hard fail) vs `~all` (soft fail).** Use `~all` while you are still
  finding senders, then switch to `-all` once you are confident. `-all` on a record
  that omits a real sender does not degrade gracefully — it gets your transactional
  mail rejected outright.
- **One record.** Publish exactly one SPF record per domain. Two `v=spf1` records is a
  permanent error and receivers ignore both.
- The `include:` target is provider-specific. Get the exact value from your provider's
  dashboard; do not guess it, because a wrong `include:` is silently unauthorised.
- If your provider gives you a **custom MAIL FROM / Return-Path** domain (Cloudflare
  Email Routing, SendGrid, SES all do), also add that to SPF **and** note that its
  domain must be DMARC-aligned too if you ever set strict alignment (§7).

### DKIM

```
<selector>._domainkey.mail.nerdmachines.com.  TXT  "<public key>"
```

- **4096-bit is the target** (RFC 8301 §3; the ceiling). RSA 2048 is the fallback when
  the provider caps it — **Google Workspace caps DKIM at 2048-bit** and offers no
  larger key, and most transactional providers default to 2048. Use 4096 where your
  provider allows it; where it does not, 2048 is fine. A *key mismatch* is
  catastrophic, a 2048-bit key is not — do not hand-roll a longer key your provider
  will not actually sign with.
- **The selector is yours to choose** and the provider generates it (`s1`, `s2`, or a
  random token). Two DKIM selectors may coexist — that is how you rotate without an
  outage: publish the new key, switch the provider, wait for the old signature to age
  out of in-flight mail, then delete the old record.
- **Publish the key on the sending subdomain**, not the apex, if you use a dedicated
  one. The `d=` tag in the signature then equals the visible From domain exactly,
  which passes **even strict** alignment.
- **Rotation is a standing chore.** DKIM keys are meant to be rotated, and providers
  differ in whether they do it for you or hand you a button (Google Workspace issues
  a new selector and leaves the previous one valid until you remove it). Whichever
  way yours works, the old selector must stay in DNS for as long as the provider can
  still sign with it. See [§8](#8-did-it-rot).

### DMARC — staged, never written straight at `reject`

```
_dmarc.mail.nerdmachines.com.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@<domain>; fo=1; pct=100"
```

| Tag | Value | Why |
|---|---|---|
| `p` | `none` → `quarantine` → `reject` | see the staging plan below |
| `rua` | `mailto:dmarc@<domain>` | aggregate reports; **the only way you find out** |
| `fo` | `1` | report on any DKIM/SPF failure, not just when both fail |
| `pct` | `100` | see below — this is the one people get wrong |

**Use `rua` only, never `ruf`.** `ruf` requests forensic reports containing the full
original message and headers, which for Kairos means respondents' email addresses in
the inbox of whoever you route them to — a privacy problem that contradicts
obligation P1. Most large receivers ignore `ruf` anyway.

**Why `pct=100`.** `pct` is the percentage of failing mail the policy is *applied* to.
It defaults to 100, but it is worth pinning explicitly, and it matters most during
staging: with `pct=10` you are applying the policy to a tenth of your mail and
looking at reports derived from that tenth. The failures you are hunting for live in
the other 90%. So the sequence is `p=none pct=100` → `p=quarantine pct=100` →
`p=reject pct=100`, keeping the whole volume under observation the entire way. If you
later want to canary `p=reject` in production, use a deliberately small `pct` for that
one step, with `rua` still on, and raise it only once the reports stay clean.

**Relaxed alignment, do not tighten it.** Leave `adkim`/`aspf` unset (both default to
`relaxed`, where a subdomain of the From domain counts). `strict` also requires the
**envelope** sender (MAIL FROM / Return-Path) to be aligned, which most providers do
not do by default and which fails in ways that are hard to diagnose from the sending
side.

### The DMARC staging plan, and why it takes weeks

| Stage | Record | Hold for | Promote when |
|---|---|---|---|
| 1 | `p=none; pct=100; rua=…` | **≥ 7 days**, ideally 14 | every aggregate report is clean — zero legit sources listed as failing |
| 2 | `p=quarantine; pct=100` | **≥ 7 days** | still zero reports from senders you don't recognise |
| 3 | `p=reject; pct=100` | permanent | — |

**A full reporting window is required before moving to `p=reject`, and this is not
optional bookkeeping.** DMARC aggregate reports are generated *by the receiver*, and
receivers batch them — commonly once every 24 hours, and some only weekly. `p=none`
generates reports too, which is the point of starting there: you cannot see what you
have not been reporting. A full week is the floor because it covers every weekday
pattern (a Monday-only sender looks perfectly healthy on a Tuesday), and two weeks is
better. Promoting on a partial window is how a domain reaches `p=reject` and then
silently eats the mail of a sender nobody had a report for yet — most often a
monitoring system or a CRM that sends rarely.

Do not put a date on the promotion in advance and do not skip to `quarantine` for
someone's benefit. If you need protection sooner, `p=none` plus a third-party DMARC
monitor is worth more than an early `quarantine`.

---

## 3. Verification — the part that cannot be automated in CI

CI cannot verify this: it would be checking *our* idea of *your* DNS against a
repository that has no credentials for it, and would go stale silently. It is an
operator-run check, on a schedule ([§8](#8-did-it-rot)).

```bash
D=mail.nerdmachines.com

dig +short TXT "$D"                      # SPF: exactly one v=spf1
dig +short TXT "s1._domainkey.$D"        # DKIM: one or more 255-char chunks
dig +short TXT "_dmarc.$D"               # DMARC: v=DMARC1, pct=100

# Mail-path checks (send a real message to a mailbox you control, then inspect it):
#   Authentication-Results: ... spf=pass ... dkim=pass ... dmarc=pass
#   DKIM-Signature: d=mail.nerdmachines.com
#   Return-Path: <bounce@mail.nerdmachines.com>
```

Then confirm the parts that decide everything:

- **`Authentication-Results` shows `dmarc=pass`.** Not spf=pass, not dkim=pass — those
  can both pass while DMARC fails on alignment. `dmarc=pass` is the one that matters.
- **Google does not filter on alignment alone.** Google requires the From domain to be
  aligned with the SPF **or** DKIM organisational domain, or the message is filtered.
  Gmail classifies bulk senders on **content**, not on the sender's claim about being
  transactional — see [§4](#4-what-actually-destroys-a-sending-domain).
- **A long TXT value must be split into ≤255-character chunks** by your DNS provider,
  reassembled automatically. If `dig` returns one string but a resolver returns
  something shorter, the DKIM key is truncated and *every* signature fails.
- **Test from a domain you do not control**, not from a mailbox on the sending domain.
  Mail from `kairos@mail.nerdmachines.com` to `someone@mail.nerdmachines.com` skips
  the filtering you are trying to observe.

---

## 4. What actually destroys a sending domain

Not missing DKIM — that mostly costs you deliverability to the biggest receivers.
The thing that ends a domain is **spam-complaint rate**. Google's stated ceiling is
around **0.1%**, and a domain that reaches roughly **0.3%** or higher is in serious
trouble. One complaint per 1,000 messages is a domain you may not get back.

Two consequences for Kairos specifically:

- **Transactional mail is exempt from the one-click-unsubscribe requirement**, but
  Gmail classifies by **content**, not by the sender's claim to be transactional. Mail
  that reads as promotional drags the unsubscribe requirement in with it. Kairos'
  mail is transactional in substance (a poll invitation, a decision, a reminder) —
  keep it that way. Subject lines like `"You're invited: Q3 Planning"` are fine;
  anything resembling a campaign is not.
- **Sending to people who did not ask is the whole risk.** Every recipient Kairos
  mails received that mail because they were invited to a poll by a third party. That
  is obligations **A2** (verify the creator before any third-party send) and **A3**
  (rate limits) doing load-bearing work for deliverability, not just for abuse. Until
  those land, hosted volume should stay small and deliberate.

Consider adding `List-Unsubscribe: <mailto:…>` to outgoing mail as cheap insurance.
It is *not* in this PR: an unsubscribe address that does not honour the request is
worse than none, so it needs a real mailbox behind it and is a decision for whoever
owns the mail provider. It belongs with #31/#37 rather than with an authentication
issue.

**BIMI / VMC is not authentication.** A Verified Mark Certificate is a logo in the
inbox, not a delivery factor, costs money per domain, and does nothing about DMARC. Do
not buy one before `p=reject` is actually in force.

---

## 5. Kairos configuration

```bash
KAIROS_HOSTED=1
KAIROS_FROM_DOMAIN=mail.nerdmachines.com
SMTP_HOST=smtp.provider.example        # provider-specific
SMTP_PORT=587
SMTP_USER=kairos@mail.nerdmachines.com
SMTP_PASSWORD=…
SMTP_FROM=kairos@mail.nerdmachines.com # must be on KAIROS_FROM_DOMAIN
```

Plus, if you enable native iMIP:

```bash
KAIROS_IMIP=on
KAIROS_IMIP_ORGANIZER=kairos@mail.nerdmachines.com   # must be on KAIROS_FROM_DOMAIN
KAIROS_IMAP_HOST=…  KAIROS_IMAP_USER=…  KAIROS_IMAP_PASSWORD=…
```

Two things the code checks that are easy to get wrong:

- **`SMTP_FROM` must be on `KAIROS_FROM_DOMAIN`** — same domain or a subdomain. The
  built-in default is the reserved placeholder `noreply@example.org`, which a hosted
  deployment will refuse.
- **`KAIROS_IMIP_ORGANIZER` must be on it too**, because Kairos sends iMIP invites
  *from* the organizer address and writes the same address into `ORGANIZER:`.
- **The envelope sender matters for future strict alignment.** Kairos does not set
  `MAIL FROM` — the relay does. Check that the provider's bounce domain is aligned, or
  note it as a known limitation while you stay on relaxed alignment.

---

## 6. Replies, forwarding, and alignment

### What Kairos already guarantees

Every outbound message puts exactly one domain in the identity headers, and that
domain is the authenticated one:

| Mail | `From:` | `ORGANIZER:` | `Reply-To:` |
|---|---|---|---|
| Invite / reminder / update / decision | `SMTP_FROM` on our domain | — | poll owner (their own address) |
| iMIP `REQUEST` / `CANCEL` | `IMIP_ORGANIZER` on our domain | same address | *none* — deliberately |

Two consequences worth stating, because both are load-bearing:

- **The owner's address never appears in `From:`.** A poll owner's personal address
  cannot be DKIM-signed by our domain, so a message sent *as* them fails SPF/DMARC
  (RFC 7489 §5.2) — the design already put them in `Reply-To` and the display name
  instead. That is correct and should not be "fixed".
- **iMIP invites send no `Reply-To` override.** The client must answer
  `METHOD:REPLY` to `ORGANIZER:` so it lands in the mailbox Kairos polls
  (`KAIROS_IMIP_ORGANIZER` must equal the IMAP mailbox). Adding a `Reply-To` here
  would break native RSVP, which is why `_sender_headers` is not used for iMIP.

### iMIP replies arriving

A client's RSVP button produces a **new message submitted by the attendee's own
provider**, not a forward. `From:` is the attendee, so DMARC is evaluated on *their*
domain with *their* SPF/DKIM and passes normally. Nothing is required from us.

The one awkward case is a client that rewrites `From:` to the organizer to preserve
thread identity. That message then claims our domain from someone else's server. It
will fail DMARC. **This does not damage our sending reputation** — it is an inbound
message, and the damage M1 is about comes from *our outbound* mail failing or earning
complaints. It may cause the reply to be filtered, which is a delivery annoyance. If
it turns out to be common with your users, the fix is on the inbound side (an inbound
provider that ARC-seals and re-signs, or SMTP submission with impersonation rights) —
which is [#34](https://github.com/gerchowl/kairos/issues/34)'s territory, not this
issue's.

### Forwarded notifications

If a respondent *forwards* a poll notification to a colleague, the forward is
authorised by **their** provider's SPF, but it is not aligned with our `From:` and
carries no DKIM for our domain — so DMARC fails on it. This is inherent to forwarding
and Kairos cannot fix it from the sending side. ARC (RFC 8617) lets the last hop
re-evaluate the chain, and major clients implement it inconsistently.

**Do not design around forwarded mail.** iMIP does not need it: the RSVP button is a
direct submission. Forwarding is a courtesy, and its limits are worth telling users
about in the invite text rather than engineering around.

### `reply+<token>@` sub-addressing (#34)

Reply routing by sub-address — `reply+<token>@mail.nerdmachines.com` — is sound for
DMARC, because **only the domain is authenticated; the local part is not part of the
From.** The gate admits `reply+abc123@mail.nerdmachines.com` as readily as
`kairos@mail.nerdmachines.com`, and there is a test pinning that.

Two things are **not** automatic, and both are provider-side:

1. **Your inbound provider must deliver sub-addresses.** `user+anything@domain`
   resolving to `user@domain` is common but not universal. **Verify it before
   building on it**: send a real message to `reply+selftest@<domain>` and confirm it
   arrives. If it does not, every reply token silently vanishes.
2. **A sub-addressed envelope sender breaks strict alignment** if the provider sets
   MAIL FROM to the literal `reply+token@` while the visible From is the base
   mailbox. Fine on relaxed alignment; a reason not to set `aspf=s`.

Kairos does not yet emit sub-addressed replies — that is [#34](https://github.com/gerchowl/kairos/issues/34)'s
design, and inventing a token format here would collide with it. The gate is built so
that whatever #34 lands is admitted without loosening M1.

---

## 7. Operator decisions left open

None of these are code decisions, and none were made here:

| Decision | Proposed default | Notes |
|---|---|---|
| Sending domain | `mail.nerdmachines.com` | §1; the single highest-value choice here |
| Mail provider | *(undecided)* | anything with custom-domain DKIM and real DMARC reporting; **not** a consumer mailbox |
| DKIM key length | 4096, fall back to 2048 | Workspace caps at 2048; §2 |
| `p=reject` date | after ≥ 7 days clean at `quarantine` | operator's calendar, not a code constant |
| DMARC report mailbox | `dmarc@<domain>` | must be a mailbox someone actually reads |
| Domain control | confirm `nerdmachines.com` is ours | already an open dependency in the register; gates everything above |
| BIMI / VMC | not now | §4; costs money, does not authenticate |
| `List-Unsubscribe` | defer to #31/#37 | needs a real opt-out path first |

---

## 8. "Did it rot"

M1 is a standing obligation, not a setup task. Re-run §3 after **any** of: changing
provider or sending domain, changing `SMTP_FROM` or `KAIROS_IMIP_ORGANIZER`, rotating
DKIM keys, a provider-announced key rotation, or **quarterly** as a floor. Set the
recurring reminder when the domain goes live — there is no in-repo flag that can do
this honestly, because a self-asserted "verified on" date rots exactly as silently as
the records it claims to describe.

## 9. Status

M1 is **PARTIAL**. The code half is landed and tested: a hosted deployment refuses to
send from an identity that cannot be authenticated, and logs what it is about to send
at every boot. The DNS half is entirely the operator's and is unstarted — no records
have been published and no provider has been chosen. Until they are, `KAIROS_HOSTED=1`
plus a correct `KAIROS_FROM_DOMAIN` will still fail closed if the sender is wrong, but
a correctly configured sender with **no** SPF/DKIM/DMARC published will send
unauthenticated mail. Kairos cannot detect that, and this document is where that fact
is recorded.
