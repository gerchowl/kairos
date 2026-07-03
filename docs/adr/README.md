# Architecture Decision Records

Load-bearing decisions in Kairos. Format: one file per decision, `NNNN-slug.md`,
status one of **Proposed** / **Accepted** / **Superseded**. Every **Accepted** ADR
must appear in the repo `FEATURE-MATRIX.md` (enforced by `guardrails-adr-matrix`).

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-capability-token-access.md) | Capability-token access; no enumeration | **Accepted** |
| [0002](0002-accountless-respondents-header-auth.md) | Accountless respondents; reverse-proxy header auth for owners | **Accepted** |
| [0003](0003-env-only-configuration.md) | Configuration via environment variables only | **Accepted** |
| [0004](0004-stdlib-only-icalendar.md) | Hand-rolled, stdlib-only iCalendar | **Accepted** |
| [0005](0005-reverse-the-calendar.md) | Reverse the calendar (iMIP/PARTSTAT), never read free/busy | **Accepted** |
| [0006](0006-hybrid-c-delivery.md) | Hybrid-C delivery: feed for the many, iMIP for the finalist | **Accepted** |
| [0007](0007-self-hosted-short-links.md) | Self-hosted short links, never a third-party shortener | **Accepted** |
| [0008](0008-deployment-adapter-pattern.md) | Deployment adapter pattern: one core, thin adapters | **Accepted** |
| [0009](0009-optional-owner-multitenancy.md) | Optional-owner multi-tenancy (capability-first) | **Proposed** |
| [0010](0010-agent-native-by-contract.md) | Agent-native by contract | **Accepted** |
| [0011](0011-nerdmachines-house-brand.md) | Ship under the nerdmachines house brand (`kairos.nerdmachines.com`) | **Accepted** |
