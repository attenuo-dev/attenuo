# Specifications and the RFC process

This folder holds the documents that define what attenuo is on the wire and at its boundaries: the RFCs, the threat model, and the protocol and API specifications. Markdown in this folder is the source of truth; anything rendered elsewhere is derived from it.

## What needs an RFC

An RFC is a design document. One is required before implementing any change that affects:

- the **token format**: claims, encoding, signature scheme, attenuation rules, expiry and revocation semantics;
- the **policy request shape**: what the policy engine is asked, the entity and context schema, how decisions are returned;
- the **audit schema**: the record layout, the hash chain, what is and is not recorded;
- the **public API**: HTTP routes and payloads of `attenuo-server`, the public items of the published crates, CLI flags and configuration keys.

Everything else (bug fixes, refactors, performance work, internal module changes, new tests, docs) does not need an RFC. If a change needs a decision but does not touch the list above, write an ADR instead (see [`../decisions/README.md`](../decisions/)). When in doubt, open an issue and ask; a maintainer will say which it is.

## Numbering and naming

RFCs are numbered sequentially with four digits: `rfc-NNNN-short-title.md`. `rfc-0001-attenuo.md` is the founding RFC and describes the system as a whole. Take the next free number when you open the PR; if two RFCs collide, the second to merge renumbers.

## Statuses

Each RFC starts with a metadata block:

```markdown
- RFC: 0002
- Title: Token attenuation caveats
- Status: draft
- Created: 2026-10-22
- Updated: 2026-10-22
- Supersedes: (none)
- Superseded by: (none)
- Tracking issue: #NN
```

| Status | Meaning |
| --- | --- |
| `draft` | Open as a pull request or merged with open questions. Not binding. Implementation may start behind a feature flag or in a branch, with no compatibility promise. |
| `accepted` | The design is agreed. Implementation can proceed on `main`. Changes to the text after this point are editorial, or go through a new RFC. |
| `implemented` | Shipped in a tagged release. The RFC records the version in which it landed. The text now matches the code; if they disagree, that is a bug in one of them and gets an issue. |
| `superseded` | Replaced by a later RFC, named in `Superseded by`. Kept for history. |
| `rejected` | Considered and declined. Merged with the reasons recorded so the discussion is not repeated. |

```
draft ──► accepted ──► implemented ──► superseded
  │
  └──► rejected
```

## Process

1. Open an issue first if the idea is not yet concrete. It is cheaper to be told "no" or "yes, but smaller" before writing the full document.
2. Copy an existing RFC for structure and write the new one as `rfc-NNNN-short-title.md` with `Status: draft`. The required sections are: Summary, Motivation, Guide-level explanation (how a user sees it), Reference-level explanation (precise enough to implement from), Security considerations (threat model impact, what an attacker gains if this is wrong), Compatibility (token, API and audit format versioning), Drawbacks, Alternatives, Unresolved questions.
3. Open one pull request per RFC. Review happens in the PR. Revise with new commits; do not rewrite history on an RFC PR, because the discussion refers to it.
4. Final comment period. When discussion has settled, a maintainer announces a seven-day final comment period with the intended disposition (accept or reject). While the project has a single maintainer this is still done, in the PR, so the window for objections exists on the record.
5. Merge with `Status: accepted` (or `rejected`). Create a tracking issue that lists the implementation PRs.
6. When the feature ships in a release, a small PR flips the status to `implemented` and records the version.

Security-sensitive RFCs (anything under the token format or audit schema headings) additionally require the Security considerations section to name the property or integration tests that will guard the invariant, as [`CONTRIBUTING.md`](https://github.com/7Mudit/attenuo/blob/main/CONTRIBUTING.md) requires for code.

## Index

| RFC | Title | Status |
| --- | --- | --- |
| [0001](rfc-0001-attenuo.md) | attenuo: delegated authorization for agents | draft |

Add a row for each new RFC.
