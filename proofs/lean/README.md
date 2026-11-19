# Lean proof of the covering rule

This directory holds a model of attenuo's covering rule in Lean 4 and machine-checked proofs
that, in the model, delegation never widens authority: a call that a later hop's capabilities
permit is permitted by every earlier hop's capabilities, the root's included.

What is proven, and what is not:

- **Proven:** the theorems below, about the Lean definitions in this directory, checked by
  Lean's kernel with no `sorry` and no axioms beyond Lean's standard three.
- **Not proven:** that the Rust code in `crates/attenuo-core` computes what the Lean
  definitions compute. The Rust code is not verified. The correspondence rests on reading the
  two side by side (the table below), on the existing Rust property tests and fuzz targets,
  which check the same properties on the Rust code with generated inputs, and on a
  [differential test](#differential-test): the model, run as a program, and the Rust code give
  the same answer on each of 31,500 generated cases. That is evidence, not proof.
- **Assumed:** a few facts about JSON values and run limits, listed under
  [Assumptions](#assumptions). The theorems hold for every value type and every limits type
  that has them. `Attenuo/Concrete.lean` gives a value type that mirrors `serde_json::Value`
  for scalars and a limits type that mirrors a `Limits` holding only `calls`, and proves that
  both have them; whether the Rust types behave as these do is what the differential test
  samples.

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
and `Classical.choice`. The build includes the `differential` executable. With `--if-installed` it prints `skipped: lean not installed` and exits
0 when `lake` is not on `PATH`; without it, a missing Lean is a failure. `scripts/dev.sh lean`
and `just lean` run it, and so does the CI job `lean`.

`scripts/check-lean-differential.sh` runs the [differential test](#differential-test). It takes
the same `--if-installed` flag, needs cargo as well, and runs after `check-lean.sh` in
`scripts/dev.sh lean`, `just lean` and the CI job `lean`.

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
| `jsonValueJVal`, `limitsModelCallsLimit` | The concrete value and limits types (`Attenuo/Concrete.lean`) have every fact the classes ask for (`JVal.admitsAllEqual_iff` is the SR-71 one). |
| `concrete_covers_sound`, `concrete_attenuate_sound` | `CapSet.covers_sound` and `CapSet.attenuate_sound` on those types, the ones the differential test runs. |
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
'Attenuo.JVal.admitsAllEqual_iff' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.jsonValueJVal' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.limitsModelCallsLimit' depends on axioms: [propext, Quot.sound]
'Attenuo.concrete_covers_sound' depends on axioms: [propext, Classical.choice, Quot.sound]
'Attenuo.concrete_attenuate_sound' depends on axioms: [propext, Classical.choice, Quot.sound]
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
| `JVal` (`Attenuo/Concrete.lean`) | `serde_json::Value` without arrays and objects |
| `JVal.canon` | `jcs::value_eq` on scalars: `number_key` for numbers, `==` otherwise |
| `JVal.asLong`, `JVal.admitsAllEqual` | `as_long`, `range_admits_all_equal` |
| `hasFloat`, `nearestDouble`, `shortestDigits` | `format_f64(n as f64) == n.to_string()` in `range_admits_all_equal`; `n as f64`; `format_f64` (ryu) on whole doubles |
| `CallsLimit`, its `narrows` and `clampTo` | `Limits` with only `calls`, `Limits::narrows`, `Limits::clamp_to` |

## Assumptions

The model does not define JSON or its canonical form. `JsonValue` takes any type of values with
the operations below, and the theorems hold for every such type. Each fact is one the Rust code
appears to have by reading; none is proven about it. `ToyValue` in `Attenuo/Value.lean` is a
type with all of them, so they are consistent, and so is `JVal` in `Attenuo/Concrete.lean`, the
type the differential test runs on.

- `veq` is an equivalence. Rust: `value_eq` compares number keys, array members in order and
  object members by key, and is `==` otherwise.
- `asStr` gives the same answer for canonically equal values, and `asStr (ofStr s) = some s`.
  Rust: `value_eq` on strings is string equality.
- `asLong (ofLong n) = some n` and `asStr (ofLong n) = none`. In the model `n` is any integer;
  Rust's `Value::from` takes an `i64`, so for a faithful value type this law fails outside
  `i64`. The model applies `ofLong` only to range bounds, which are `i64` in Rust, so `JVal`
  adds values that Rust cannot hold (`JVal.big`, an integer outside `i64` as `ofLong` makes it)
  for the law to hold. No case of the differential test holds one.
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
- **JSON values and canonical form.** Abstracted as above. The proofs are about any value type
  with the facts listed. The concrete `JVal` mirrors scalars (strings, integers, floats,
  booleans, `null`); it has no arrays or objects, so object key order and nested canonical
  equality are not exercised. Its `shortestDigits` is a reimplementation of ryu's shortest
  digits for whole doubles only, checked against Rust by the differential test and not proven
  equal to it.
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
  `attenuateWith`. The concrete `CallsLimit` the differential test runs on has `calls` only. Limit enforcement at call time, counters and budgets are not modelled. The
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

## Differential test

The Lean definitions, run as a program on `JVal` and `CallsLimit`, and the Rust code are given
the same inputs and must give the same answers. The Rust test
`crates/attenuo-core/tests/lean_differential.rs` draws the cases with a fixed seed, evaluates
each with the Rust functions and writes the case and Rust's answer to a file, one per line. The
Lean executable `differential` (`Differential.lean`, `Attenuo/Cases.lean`, which documents the
format) reads that file and prints the model's answer to each line, and
`scripts/check-lean-differential.sh` fails on any line where the two differ, printing the
first ten. The Rust test alone needs no Lean, so `cargo test --workspace` runs it without the
comparison.

The cases reuse the strategies of the property tests (`tests/strategies/mod.rs`) and add
inputs at the edges: constraints narrowed from another (the children a delegation draws) and
near misses one step wider; `path_prefix` bases and values one segment, one `/`, one `-` or one
`..` apart, malformed bases, percent escapes, lookalike separators and control characters;
`5` against `5.0`, `-0.0`, the bounds of `i64` and `u64`, `WHOLE_FLOAT_MAX` and one past it,
`2^53` and its neighbours, integers whose nearest double is or is not written with their
digits (SR-71), floats from `5e-324` to `f64::MAX`; empty `one_of`, inverted and unbounded
ranges built unchecked; and limits with `calls` raised and lowered.

| Function | Rust | Cases | Agree |
| --- | --- | ---: | ---: |
| `Constraint.sat` | `ArgConstraint::satisfied_by` | 4,000 | 4,000 |
| `Constraint.implies` | `ArgConstraint::implies` | 7,000 | 7,000 |
| `patternMatches` | `pattern_matches` | 2,000 | 2,000 |
| `patternCovers` | `pattern_covers`, through `covers_calls` of two capabilities with tool `*` and no constraints (the function is private) | 2,000 | 2,000 |
| `Capability.permits` | `Capability::permits` | 3,000 | 3,000 |
| `Capability.covers` | `Capability::covers` | 4,000 | 4,000 |
| `CapSet.permits` | `CapabilitySet::permits` | 2,500 | 2,500 |
| `CapSet.covers` | `CapabilitySet::covers` | 3,000 | 3,000 |
| `CapSet.attenuate` | `CapabilitySet::attenuate`: success or which error, and on success the same set | 4,000 | 4,000 |

Every boolean function is drawn with each answer in at least a tenth of its cases, and
`attenuate` with each outcome in at least a twentieth (the test checks both). With ten times
as many cases on three other seeds (945,000 cases) the two also agreed; those runs are not
part of the check.

Left out of the cases, by construction (the encoder refuses them, so none is dropped
silently):

- JSON arrays and objects (not in `JVal`).
- Limits other than `calls` (`sum`, `calls_per`, `distinct`): not in `CallsLimit`. `remaining`
  in `attenuate_with` is not exercised; the cases call `attenuate`.
- Capability server and tool patterns that `names.rs` refuses. A narrowed pattern that would
  be refused (`res/` from `res/*`) is replaced by its parent pattern and counted in the test's
  output. Call names may be invalid: the model takes `check_names().is_ok()` as an input, so
  invalid names are in the model and are drawn.
- Unicode normalisation. Strings may hold any code point, the lookalike separators among
  them, and both sides compare code points; neither normalises, so no case tests a property of
  NFKC or best-fit conversion.
- The rest of a chain (`validate_at`) and `attenuate_with`'s lease-store lowering.

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
permits a call its parent does not. The differential test found no case where the model and
the Rust code disagree. Making the model executable found one assumption that a faithful
value type cannot meet as stated: `asLong (ofLong n) = some n` for every integer `n`, where Rust
has `Value::from(i64)` only (see [Assumptions](#assumptions)). It does not affect the theorems,
since the model only applies `ofLong` to `i64` bounds. Every arm of `ArgConstraint::implies` was proven sound
against `satisfied_by`, given the assumptions above. One precondition surfaced: `covers` is
reflexive only when a capability has one constraint per argument name, which the Rust
`BTreeMap` guarantees and the model states as `Capability.wellFormed`.
