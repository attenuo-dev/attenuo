# Security Policy

onbehalf is authorization infrastructure. A bug here is not a crash; it is an agent doing something its principal never allowed. We treat security reports as the most important input the project receives.

## Reporting a vulnerability

**Do not open a public issue or pull request for a security problem.**

Report privately through either channel:

- Email `security@<domain>` (placeholder until the project domain is set; until then use GitHub private reporting).
- GitHub private vulnerability reporting: [github.com/7Mudit/onbehalf/security/advisories/new](https://github.com/7Mudit/onbehalf/security/advisories/new).

Please include as much of the following as you can:

- The type of issue (authorization bypass, attenuation violation, audit-chain tamper, denial of service, information disclosure, and so on).
- The affected crate(s) and version or commit.
- Steps to reproduce, or a proof of concept. A failing test is ideal.
- The impact as you understand it: what an attacker gains.
- Whether the issue is already public anywhere.

Reports in English, please. You will not be asked to sign anything.

## What to expect

| Step | Target |
| --- | --- |
| Acknowledgement of your report | within 72 hours |
| Initial assessment and severity | within 7 days |
| Fix, advisory and release for confirmed issues | as soon as practicable; we aim for well under the disclosure deadline |
| Coordinated public disclosure | 90 days after the report, or earlier once a fix is released and users have had time to update |

We follow a 90-day coordinated disclosure window. If a fix needs longer, we will tell you why and agree a new date with you. If the issue is being exploited in the wild, we disclose faster. We credit reporters in the advisory and the changelog unless you ask us not to.

We publish advisories through GitHub Security Advisories and, for published crates, through the [RustSec advisory database](https://rustsec.org/).

## Severity

The highest severity class for this project, regardless of how hard it is to trigger, is any of:

- **Authorization bypass**: a request is allowed that the policy or the delegation chain should have denied, or a token is accepted that should have been rejected (invalid signature, expired, revoked, wrong audience).
- **Attenuation violation**: a delegated token, or a chain of delegations, ends up with more capability than its parent. Attenuation must only ever narrow.
- **Audit-chain tamper**: an audit record can be inserted, altered, reordered or removed without the chain verification detecting it, or a decision can be made without producing a record.

As with SpiceDB, an incorrect answer from the authorization API is a vulnerability even when the service stays up, because callers make security decisions on that answer.

Lower severity classes: denial of service against the server, information disclosure through error messages or logs, and weaknesses that require an already-compromised signing key or an operator misconfiguration outside the documented deployment model.

## Supported versions

| Version | Supported |
| --- | --- |
| `main` | yes, fixes land here first |
| latest `0.x` release | yes |
| older `0.x` releases | no, please upgrade |

Once 1.0 is released this table will list the maintained minor series. Pre-1.0, only the latest release receives security fixes.

## Scope and assumptions

The threat model in `docs/spec/` describes what onbehalf defends against and what it assumes of its deployment (for example, that signing keys are held by a trusted issuer and that the server is reached over TLS). Findings that only apply outside those assumptions are still welcome, and we may fix them, but they are triaged as hardening rather than vulnerabilities.

## Safe harbour

We will not pursue or support legal action against researchers who act in good faith: who make a reasonable effort to avoid privacy violations, data destruction and service disruption, who only test against their own deployments, and who give us a reasonable time to respond before disclosing.
