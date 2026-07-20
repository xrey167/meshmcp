# License Decision — pending the owner's choice

**Status: unresolved. This is a decision document, not a license.** The
authoritative terms are in [`LICENSE`](LICENSE) until the owner selects an option
below and replaces it.

## The problem this resolves

The current `LICENSE` is **proprietary and read-only**: it grants permission to
*view* the source for evaluation but explicitly forbids running, executing,
installing, deploying, copying beyond transient reads, modifying, or
distributing without prior written permission. The README, however, contains
build-and-run instructions. A reader who follows the quick start would be doing
something the license forbids.

Two things must not happen while this is unresolved:

1. **No one may silently pick a new legal license.** The choice below is the
   owner's alone; an assistant/contributor must not decide it.
2. **The project must not be labeled "open source."** The current terms are not
   an OSI-approved open-source license.

Interim action taken (no license change): the README now states the current
legal status up front and frames the build/run steps as contingent on obtaining
permission or on the owner selecting an open option below. See the "License &
current status" note at the top of the README.

## Options

### 1. Apache-2.0 core + commercial managed control plane  *(recommended default)*
- **Core gateway / data plane** (mesh transport, stdio + HTTP gatewaying, policy
  engine, approvals, audit, session core) under **Apache-2.0**: permissive,
  patent grant, widely trusted, maximal adoption.
- **Commercial license** for the hosted control plane, enterprise identity,
  centralized policy distribution, compliance exports, multi-tenancy, HA
  integrations, and support.
- **Pros:** fastest adoption of the security wedge; clean OSS/commercial split;
  patent grant reassures enterprises.
- **Cons:** permissive core can be embedded by competitors; monetization relies
  on the managed/enterprise layer.

### 2. AGPL-3.0 core + commercial licensing
- Core under **AGPL-3.0**; sell exceptions/commercial licenses and enterprise
  services.
- **Pros:** network-copyleft discourages closed SaaS forks; strong dual-license
  leverage.
- **Cons:** AGPL deters some corporate adopters and complicates embedding.

### 3. Source-available with explicit local-evaluation / non-production rights
- A clearly drafted source-available license (e.g. BSL-style with a change date,
  or a bespoke evaluation license) granting **local evaluation and
  non-production use**, reserving production/commercial use.
- **Pros:** keeps commercial control while letting people legally try it.
- **Cons:** not open source; license novelty can slow adoption; needs careful
  drafting (ideally counsel-reviewed).

### 4. Fully proprietary, no public build-and-run instructions
- Keep the proprietary license; **remove build-and-run instructions** from
  public docs so the repo and license are consistent.
- **Pros:** maximal control.
- **Cons:** no community, no external evaluation, minimal adoption.

## Recommendation (if the owner delegates)

**Option 1 — Apache-2.0 for the core gateway/data plane, commercial licensing for
the hosted control plane, enterprise identity, centralized policy distribution,
compliance exports, multi-tenancy, HA integrations, and support.** It best fits
the "self-hosted agent firewall" wedge (adoption of the security core matters
more than restricting it) while preserving a commercial layer.

## What happens after the owner chooses

1. Replace `LICENSE` with the chosen license text (and add a per-component
   `LICENSE` split if Option 1/2).
2. Update the README status note and any badges accordingly (only then may
   "open source" be used, and only for an OSI-approved choice).
3. Add third-party notices: inventory generated/adapted protocol files and the
   embedded NetBird / WireGuard components and include the required attributions
   (a `NOTICE` / `THIRD-PARTY-NOTICES` file).
4. Flag any residual legal questions (patent grant scope, contributor license
   agreement / DCO, trademark policy) for counsel rather than resolving them
   here.

**Legal note:** this document is engineering guidance, not legal advice. The
final license text and any dual-licensing/CLA arrangement should be reviewed by
qualified counsel.
