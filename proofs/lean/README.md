# Lean proof of the covering rule

This directory holds a model of attenuo's covering rule in Lean 4 and machine-checked proofs
that, in the model, delegation never widens authority: a call that a later hop's capabilities
permit is permitted by every earlier hop's capabilities, the root's included.

What is proven, and what is not:

- **Proven:** the theorems below, about the Lean definitions in this directory, checked by
  Lean's kernel with no `sorry` and no axioms beyond Lean's standard three.
- **Not proven:** that the Rust code in `crates/attenuo-core` computes what the Lean
  definitions compute. The Rust code is not verified. The correspondence rests on reading the
  two side by side (the table below) and on the existing Rust property tests and fuzz targets,
  which check the same properties on the Rust code with generated inputs.
- **Assumed:** a few facts about JSON values and run limits, listed under
  [Assumptions](#assumptions). The theorems hold for every value type and every limits type
  that has them; whether the Rust types have them is again a matter of reading.

## Running it

Lean is installed with [elan](https://github.com/leanprover/elan). The toolchain is pinned in
`lean-toolchain` (Lean 4.35.0); elan fetches it on first use. Only Lean's core library is used,
no Mathlib, so the build takes seconds.

```sh
curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf \
  | sh -s -- -y --default-toolchain none
scripts/check-lean.sh                # from the repository root
```

`scripts/check-lean.sh` builds the proof with warnings as errors, fails if a source file holds
`sorry`, `admit`, an `axiom` declaration, `native_decide` or `implemented_by`, and runs
`PrintAxioms.lean` to check that every main theorem depends only on `propext`, `Quot.sound`
and `Classical.choice`. With `--if-installed` it prints `skipped: lean not installed` and exits
0 when `lake` is not on `PATH`; without it, a missing Lean is a failure. `scripts/dev.sh lean`
and `just lean` run it, and so does the CI job `lean`.

Build output goes to `.lake/`, which is ignored. `lake-manifest.json` is tracked; the project
has no dependencies, so it lists none.

## Theorems

| Theorem | Statement |
| --- | --- |
| `Constraint.implies_sound` | If constraint `c` implies `d` and a value satisfies `c`, it satisfies `d`. |
| `Constraint.implies_refl` | Every constraint implies itself. |
| `Constraint.implies_trans` | If `a` implies `b` and `b` implies `c`, then `a` implies `c`. |
| `patternCovers_sound` | If pattern `p` covers pattern `c` and `c` matches a name, `p` matches it. |
| `patternCovers_refl`, `patternCovers_trans` | Pattern covering is reflexive and transitive. |
| `Capability.coversCalls_sound` | If capability `p` covers the calls of `c` and `c` permits a call, `p` permits it. |
| `Capability.covers_sound` | The same for `covers` (calls and limits). |
| `Capability.covers_refl` | A capability with one constraint per argument covers itself. |
| `Capability.covers_trans` | Capability covering is transitive. |
| `CapSet.covers_sound` | If set `P` covers set `C` and `C` permits a call, `P` permits it. |
| `CapSet.covers_refl`, `CapSet.covers_trans` | Set covering is reflexive (for well-formed members) and transitive. |
| `CapSet.attenuateWith_covered` | When `attenuate_with` succeeds, whatever the limit adjustment, its result is non-empty and covered by the parent set. |
| `CapSet.attenuate_covered`, `CapSet.attenuate_sound` | The same for `attenuate`, and a call the result permits is permitted by the parent set. |
| `chain_permits_all` | In a valid chain, a call the last hop's capabilities permit is permitted by every hop's capabilities. |
| `chain_root_permits` | In particular, by the root hop's. |
| `chainValid_extend` | Appending a hop that `attenuate` derived from the last hop keeps a valid chain valid. |
| `render_parsePath` | A string `parse_path` accepts reads back as the same string from its parsed form. |
| `prefix_of_pathStrWithin` | Every string a `path_prefix` admits starts with the constraint's own path. This is the fact behind the `(PathPrefix(q), Prefix(p)) => q.starts_with(p)` case of `implies`. |
| `pathStrWithin_trans` | Being at or below a path is transitive. |

`Attenuo/Examples.lean` also evaluates the model on the cases of the Rust unit tests
`exact_and_glob_patterns` and `constraint_implication` and on the examples in the
`ArgConstraint::PathPrefix` doc comment, and checks it gives the Rust answers. These are
checks of single inputs, not proofs.

### `#print axioms`

Output of `lake env lean PrintAxioms.lean` with Lean 4.35.0:

```text
'Attenuo.render_parsePath' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.prefix_of_pathStrWithin' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.pathStrWithin_trans' depends on axioms: [propext, Quot.sound]
'Attenuo.Constraint.implies_sound' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.Constraint.implies_refl' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.Constraint.implies_trans' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.patternCovers_sound' depends on axioms: [propext, Quot.sound]
'Attenuo.patternCovers_refl' depends on axioms: [propext, Quot.sound]
'Attenuo.patternCovers_trans' depends on axioms: [propext, Quot.sound]
'Attenuo.Capability.coversCalls_sound' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.Capability.covers_sound' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.Capability.covers_refl' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.Capability.covers_trans' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.CapSet.covers_sound' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.CapSet.covers_refl' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.CapSet.covers_trans' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.CapSet.attenuateWith_covered' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.CapSet.attenuate_covered' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.CapSet.attenuate_sound' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.chain_permits_all' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.chain_root_permits' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.chainValid_extend' depends on axioms: [propext, Classical.choice, Quot.sound]
```

These three are the axioms of Lean's standard library; no axiom of this project appears.

## Lean definitions and the Rust they model

Rust items are in `crates/attenuo-core/src/capability.rs` unless another file is named.

| Lean | Rust |
| --- | --- |
| `Str` (`List Char`) | `str`, `String` |
| `splitSlash`, `joinSlash` | `str::split('/')`, `[&str]::join("/")` |
| `refused` and its parts (`isControl`, `hasEncodedSeparator`, `hasDoubleEncoded`, `lookalikeSeparators`, `hasDoubleSlash`) | the refusals at the top of `parse_path`; `LOOKALIKE_SEPARATORS`; `char::is_control` |
| `PathSegs`, `parsePath` | `PathSegments`, `parse_path` |
| `within`, `pathStrWithin` | `path_within`, `path_str_within` |
| `JsonValue.veq` | `jcs::value_eq` (`crates/attenuo-core/src/jcs.rs`) |
| `JsonValue.asStr`, `ofStr` | `Value::as_str`, `Value::String` |
| `JsonValue.asLong`, `ofLong` | `as_long`, `Value::from(i64)` |
| `JsonValue.admitsAllEqual` | `range_admits_all_equal` |
| `Constraint` (`equals`, `oneOf`, `strPrefix`, `pathPrefix`, `range`) | `ArgConstraint` (`Equals`, `OneOf`, `Prefix`, `PathPrefix`, `Range`) |
| `Constraint.lo`, `Constraint.hi` | `ArgConstraint::bounds` |
| `Constraint.sat` | `ArgConstraint::satisfied_by` |
| `Constraint.isEmpty` | `ArgConstraint::is_empty` |
| `Constraint.implies` | `ArgConstraint::implies`, one Lean case per Rust match arm |
| `stripStar`, `patternMatches`, `patternCovers` | `str::strip_suffix('*')`, `pattern_matches`, `pattern_covers` |
| `ToolCall` | `ToolCall` (`crates/attenuo-core/src/call.rs`); `namesOk` is `check_names().is_ok()` |
| `Capability` | `Capability` |
| `Capability.permits` | `Capability::permits` |
| `Capability.coversCalls` | `Capability::covers_calls` |
| `Capability.covers` | `Capability::covers` |
| `Capability.wellFormed` | the one-entry-per-key property of the `BTreeMap` of constraints |
| `LimitsModel.narrows`, `LimitsModel.clampTo` | `Limits::narrows`, `Limits::clamp_to` (`crates/attenuo-core/src/limits.rs`) |
| `CapSet`, `CapSet.permits`, `CapSet.covers` | `CapabilitySet`, `CapabilitySet::permits`, `CapabilitySet::covers` |
| `findIndexed` | `iter().enumerate().find(..)` |
| `attenuateOne`, `attenuateAll`, `CapSet.attenuateWith` | the loop body, the loop, and `CapabilitySet::attenuate_with` |
| `CapSet.attenuate` | `CapabilitySet::attenuate` |
| `linksValid`, `chainValid` | the capability check of `DelegationChain::validate_at` (`crates/attenuo-core/src/chain.rs`): every hop after the first holds a non-empty set its parent's set covers |
| `List.getLast` of the hops | `DelegationChain::effective_capabilities` |

## Assumptions

The model does not define JSON or its canonical form. `JsonValue` takes any type of values with
the operations below, and the theorems hold for every such type. Each fact is one the Rust code
appears to have by reading; none is proven about it. `ToyValue` in `Attenuo/Value.lean` is a
type with all of them, so they are consistent.

- `veq` is an equivalence. Rust: `value_eq` compares number keys, array members in order and
  object members by key, and is `==` otherwise.
- `asStr` gives the same answer for canonically equal values, and `asStr (ofStr s) = some s`.
  Rust: `value_eq` on strings is string equality.
- `asLong (ofLong n) = some n` and `asStr (ofLong n) = none`.
- A value that `as_long` reads as `n` is canonically equal to `Value::from(n)`. Rust: an
  integer has the same key as itself; a float `as_long` accepts is a whole number of at most
  922337203685477 in magnitude, and `format_f64` writes it with the integer's digits.
- `range_admits_all_equal(range, a)` is true exactly when every value canonically equal to `a`
  is an integer in the range. Rust: this is the purpose of the SR-71 check, which refuses an
  integer whose nearest float is written with the same digits.
- `Limits::narrows` is reflexive and transitive. Only `covers_refl` and `covers_trans` use this;
  soundness does not, since limits never change which call a capability permits.

## What the model leaves out

- **The Rust code itself.** No Rust is extracted, translated by a tool or verified. A
  difference between the Rust and the Lean definitions would not be caught here; the property
  tests and fuzz targets below are what check the Rust.
- **JSON values and canonical form.** Abstracted as above. RFC 8785 serialization, number
  formatting (`format_f64`, ryu), `as_long`'s float handling and object key order are not
  modelled.
- **Strings.** Strings are lists of Unicode scalar values. Rust compares UTF-8 bytes; for
  prefixes and for the ASCII bytes the path checks look for, the two agree. There is no Unicode
  normalisation in either, and the model does not reason about NFKC or Windows best-fit
  conversion: `lookalikeSeparators` is the Rust list, copied.
- **Glob details and name validity.** Patterns are exact, `*` or `prefix*`, as in Rust. Which
  names are valid (`crates/attenuo-core/src/names.rs`, `Capability::validate`,
  `ToolCall::check_names`) is not modelled: `permits` takes the call's name check as a given
  boolean, the same on both sides of every theorem.
- **Numeric representation.** Bounds and integers are unbounded `Int`; a missing bound is
  `i64::MIN` or `i64::MAX` as in Rust. Overflow cannot occur in the model; the Rust code
  compares `i64` values and does no arithmetic on them.
- **Run limits.** `Limits` is abstract: `narrows` with the two facts above, and `clamp_to` and
  the lease store's `remaining` folded into one arbitrary adjustment function in
  `attenuateWith`. Limit enforcement at call time, counters and budgets are not modelled. The
  `attenuate` theorem holds for any adjustment because `attenuate_with` checks `covers` on the
  adjusted capability before it keeps it.
- **The rest of a chain.** `validate_at` also checks the subject, depth, agent and lease ids,
  names, limits, issue and expiry times and duplicates. None of that is modelled; only its
  covering check is. Token signatures, `ou_sig`, DPoP, leases and revocation, approvals and
  audit are out of scope.
- **Cedar.** The policy engine is a second, separate check on every call. The theorems are
  about capabilities only and say nothing about policies.
- **Sets as lists.** `BTreeMap` and `BTreeSet` are lists. Order and duplicates change nothing in
  the soundness theorems; reflexivity needs one constraint per argument name, which a
  `BTreeMap` guarantees.

## Rust tests that check the same properties

On the Rust code, with generated inputs, in `crates/attenuo-core/tests/attenuation_props.rs`:

- `coverage_is_sound_for_capabilities`, `coverage_is_sound_for_sets`,
  `coverage_is_sound_for_narrowed_children`: soundness of `covers`
  (`Capability.covers_sound`, `CapSet.covers_sound`).
- `implication_is_sound`, `path_implication_is_sound`,
  `path_prefix_narrows_the_string_prefix_of_its_text`: soundness of `implies`
  (`Constraint.implies_sound`, `prefix_of_pathStrWithin`).
- `covers_is_reflexive_for_capabilities`, `covers_is_reflexive_for_sets`,
  `constraint_implies_is_reflexive`: reflexivity.
- `covers_is_transitive_for_capabilities`, `covers_is_transitive_for_sets`,
  `covers_is_transitive_along_chains`: transitivity (`chain_permits_all`).
- `attenuation_never_widens`: chains built by `extend` (`chainValid_extend`,
  `CapSet.attenuate_sound`).
- `widened_hop_is_rejected`: `validate_at` refuses a hop its parent does not cover.

Fuzz targets (`fuzz/fuzz_targets/`): `capability_attenuation` checks soundness, reflexivity,
transitivity and agreement of `attenuate` with `covers`; `chain_validate` checks that a chain
`validate_at` accepts satisfies the attenuation invariants.

## Findings

Writing the model found no case where the Rust `covers` accepts a child capability that
permits a call its parent does not. Every arm of `ArgConstraint::implies` was proven sound
against `satisfied_by`, given the assumptions above. One precondition surfaced: `covers` is
reflexive only when a capability has one constraint per argument name, which the Rust
`BTreeMap` guarantees and the model states as `Capability.wellFormed`.
