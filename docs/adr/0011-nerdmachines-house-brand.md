# 0011 — Kairos ships under the nerdmachines house brand

Status: **Accepted**

## Context
Productizing Kairos raised a naming/domain question. The findings:

- **"Kairos" is a saturated name** — Kairos AI, Kairos Power (nuclear), Kairos
  Ventures, Kairos Aerospace, and more. Every good TLD is taken or premium
  (`kairos.xyz` $399k, `kairos.tech` $12k, `kairos.so` $3.9k;
  `kairos.{com,io,sh,app,dev}` all registered — Namecheap-verified 2026-07-01).
- **Descriptive-compound / `get-`/`try-`/`-app` domains are stopgaps**, not
  brands. What becomes memorable is a short, distinctive, *ownable* word
  (Spotify, Stripe, Figma) or, in this space, a coined/short one (Calendly,
  Doodle). `kairosscheduler.com` is a fine *address* but never the brand.
- For an **OSS, self-hostable, agent-native** tool, the brand already lives in
  the package (`kairos-scheduler` on PyPI) and repo (`gerchowl/kairos`), not a
  marketing domain (ADR-0010, ADR-0008).
- **`nerdmachines.com` is registered to the existing nerdmachines org** — a
  house brand we already own.

## Decision
Ship Kairos **as a nerdmachines tool**, hosted at **`kairos.nerdmachines.com`**
(a subdomain of the house brand). Keep the product name **Kairos** (already
invested: repo, package, ADRs, code). Do **not** buy or defend a standalone
domain; a house-brand subdomain is the honest home for a tool.

Give Kairos a **mascot** for personality — a **bee** (the waggle dance = telling
the hive *when & where* to go, the best scheduling metaphor in nature) or a
**goose** (V-formation, honk-to-coordinate, migrates on schedule). The mascot is
personality (UI, OG image, CLI banner), not the brand identity.

## Consequences
- The domain problem dissolves: a DNS record, not a naming project or a purchase.
- House-brand trust (`nerdmachines`) + product name (`Kairos`) + playful mascot —
  all three, no rebrand, no SEO fight for a contested standalone.
- Mail (M1) DKIM/DMARC is configured on `nerdmachines.com`; the iMIP organizer
  becomes e.g. `kairos@nerdmachines.com` — a **non-Gmail organizer**, which also
  unblocks native Gmail RSVP (ADR-0006, obligation M5).
- **Dependency:** confirm `nerdmachines.com` is under our control (the org is
  ours; verify the registration). If not, fall back to a verified-available
  standalone (`gathergoose.com` / `rallyrook.com` / `kairosscheduler.com`).
- If Kairos ever becomes a standalone business chasing consumer fame, revisit the
  *name* (not just the domain) deliberately then.
