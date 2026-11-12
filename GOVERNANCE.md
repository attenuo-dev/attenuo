# Governance

This document describes how decisions are made in the attenuo project and how that is expected to change as the project grows. The current roster is in [MAINTAINERS.md](MAINTAINERS.md).

## Current model: single maintainer

attenuo is at an early stage and has one maintainer, who acts as a benevolent dictator for now: they have final say on design, scope, releases and this document. This is stated plainly so that nobody mistakes the project for something it is not yet. The intent is to move to the shared model below as soon as there are people to share it with.

Even with one maintainer the project binds itself to its own process:

- Design changes to the token format, policy request shape, audit schema or public API go through an RFC with a seven-day comment window ([docs/spec/README.md](docs/spec/README.md)).
- Architectural decisions are recorded as ADRs ([docs/decisions/README.md](docs/decisions/README.md)).
- Every change to `main`, including the maintainer's own, goes through a pull request that passes CI (or, while GitHub Actions cannot run, the same checks run locally and recorded in the pull request). Branch protection enforces this once the repository is public.
- Security reports are handled under [SECURITY.md](SECURITY.md) regardless of who reported them.

## Roles

**Contributor**: anyone who has had a pull request merged, filed a useful issue, reviewed code, or improved the docs. No formal step; you are one once you have done it.

**Reviewer**: a contributor the maintainers trust to review in a given area (for example the policy crate or the audit chain). Reviewers are listed in `.github/CODEOWNERS` for their area and their approval counts toward the review requirement. Reviewers cannot merge.

**Maintainer**: has write access, can merge, cut releases and approve RFCs. Listed in [MAINTAINERS.md](MAINTAINERS.md) and as owners in `.github/CODEOWNERS`.

## Becoming a maintainer

A reviewer can be nominated as a maintainer by an existing maintainer after a sustained period of contribution, typically several months of substantial, high-quality work and reviews that show good judgement about the project's security invariants. The nomination is a pull request adding the person to `MAINTAINERS.md`. It is open for at least seven days and needs approval from all existing maintainers (while there is one maintainer, that is the one). The nominee must have accepted the DCO process and the code of conduct.

## Stepping down and removal

Maintainers may step down at any time by PR. A maintainer who has been inactive for six months is moved to the emeritus list, with thanks, and can be reinstated by the normal nomination process. A maintainer can be removed for cause (code of conduct violations, acting against the project's interest) by consensus of the other maintainers; while there is only one maintainer this clause cannot apply and the code of conduct contact is the safety valve.

## Decision making once there are several maintainers

- Routine changes: one approving review from a maintainer or the relevant code owner, CI green, then merge. The author does not approve their own PR.
- RFCs and ADRs: lazy consensus. After the final comment period, an RFC is accepted unless a maintainer has objected with a stated reason. Objections are resolved by discussion; if that fails, a simple majority of maintainers decides, and the result and dissent are recorded in the document.
- Governance changes (this file, MAINTAINERS.md, licence): require approval from two-thirds of maintainers and a fourteen-day comment window.
- Releases: any maintainer may cut a release following the process in [CONTRIBUTING.md](CONTRIBUTING.md). Security releases follow [SECURITY.md](SECURITY.md).

## Changing this document

Propose changes by pull request. Until there are three or more maintainers, the single-maintainer rules above apply to changes here too, with the seven-day window kept so the discussion is on the record.
