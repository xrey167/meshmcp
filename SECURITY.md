# Security Policy

meshmcp is a security product — a self-hosted agent firewall for private MCP
servers. We take vulnerabilities in it seriously.

## Reporting a vulnerability

**Please report security issues privately. Do not open a public issue for a
suspected vulnerability.**

Use GitHub's **private vulnerability reporting** for this repository:

1. Go to the repository's **Security** tab → **Report a vulnerability** (GitHub
   → Security Advisories → "Report a vulnerability").
2. Include: affected version/commit, a description, reproduction steps or a
   proof of concept, the impact you observed, and any suggested remediation.

If private reporting is unavailable to you, contact the maintainer through their
GitHub profile to arrange a private channel. Do **not** post details publicly
until a fix is available and coordinated.

### What to expect

- **Acknowledgement:** we aim to acknowledge a report within a few business
  days.
- **Triage:** we will confirm the issue, determine severity, and share a
  remediation plan.
- **Coordinated disclosure:** we prefer coordinated disclosure and will agree a
  timeline with you. Please allow reasonable time for a fix before public
  disclosure. We are happy to credit reporters who wish to be named.

## Scope

In scope — the core security surfaces:

- Transport-bound identity and the mesh boundary.
- The policy filter and enforcement pipeline (tool/method policy, capabilities,
  labels/taint, rate limits, approvals).
- The control plane (enrollment, registry, policy distribution) and its RBAC.
- The approval plane.
- The audit log and its signed-checkpoint verification.
- Session resumption and (experimental) router/federation delegation.
- Secret injection and isolation.

Especially valuable: **authorization bypasses** (e.g. a request shape that skips
tool policy), **identity-spoofing** (getting the gateway to trust a
caller-supplied identity instead of the transport), **audit
forgery/over-claiming**, **privilege escalation on the control or approval
plane**, and **secret exfiltration** beyond the documented boundary.

### Known limitations (not vulnerabilities by themselves)

These are documented design boundaries in
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md); reports should show a break
*within* the stated guarantee:

- A **compromised gateway** is the enforcement point; if it is compromised it
  can allow calls and sign its own audit. External anchoring bounds undetected
  audit rollback.
- A **malicious backend** that receives an injected secret is within that
  secret's exposure boundary.
- **Router/federation delegated identity** is **experimental** (see the
  capability matrix); do not rely on delegated identity as a control yet.
- meshmcp guarantees in-order **delivery**, not exactly-once **execution**.

## Supported versions

meshmcp is pre-1.0 (v0.1). Security fixes land on the default branch and the
latest release. There is no long-term-support branch yet; see
[docs/CAPABILITY-MATRIX.md](docs/CAPABILITY-MATRIX.md) for what is stable.

## Disclosures and hardening record

Reproduced findings and their fixes, tests, and residual risk are tracked in
[`docs/spec/SECURITY-CLOSURE.md`](docs/spec/SECURITY-CLOSURE.md).

## Licensing note

meshmcp's license is currently proprietary/read-only and under review (see
[`LICENSE`](LICENSE) and [`LICENSE-DECISION.md`](LICENSE-DECISION.md)). Reporting
a vulnerability under this policy does not grant any license to use the Software.
