# Lean proof of the covering rule

- Status: built, 2026-11-13. Lean 4.35.0, core library only.
- Sources: [`proofs/lean/`](https://github.com/attenuo-dev/attenuo/tree/main/proofs/lean); the full write-up, with the theorem list, the `#print axioms` output and the Lean-to-Rust table, is [`proofs/lean/README.md`](https://github.com/attenuo-dev/attenuo/blob/main/proofs/lean/README.md).

## What it shows

attenuo's central invariant is that delegation never widens authority ([RFC-0001 section 2](../spec/rfc-0001-attenuo.md#2-security-properties), P2). It rests on one rule: a hop's capabilities must be covered by its parent's ([capabilities and attenuation](../concepts/capabilities-and-attenuation.md#attenuation)).

`proofs/lean/` models that rule in Lean 4: argument constraints (`equals`, `one_of`, `prefix`, `path_prefix`, `range`), name patterns, capabilities, capability sets, `covers`, `permits`, `attenuate` and the covering check of `DelegationChain::validate_at`. For the model, Lean's kernel checks that:

- if a parent capability or set covers a child and the child permits a call, the parent permits it;
- covering is reflexive and transitive, and so is constraint implication;
- in a valid chain, a call the last hop permits is permitted by every hop, the root included;
- when `attenuate` succeeds, its result is covered by the parent set.

The proofs use no `sorry` and no axiom beyond Lean's standard three (`propext`, `Quot.sound`, `Classical.choice`).

## What it does not show

The Rust code is not verified. The Lean definitions were written by reading `crates/attenuo-core/src/capability.rs` and `chain.rs`, one Lean case per Rust match arm, and the correspondence is checked by that reading, by the existing property tests (`crates/attenuo-core/tests/attenuation_props.rs`) and fuzz targets (`capability_attenuation`, `chain_validate`), which test the same properties on the Rust code, and by a differential test. On the concrete value and limits types of `proofs/lean/Attenuo/Concrete.lean`, whose class laws are proven, the model run as a program and the Rust code give the same answer on every one of the 31,500 cases a fixed seed draws: 4,000 for `satisfied_by`, 7,000 for `implies`, 2,000 each for `pattern_matches` and `pattern_covers`, 3,000 for `Capability::permits`, 4,000 for `Capability::covers`, 2,500 for `CapabilitySet::permits`, 3,000 for `CapabilitySet::covers` and 4,000 for `attenuate` (outcome and resulting set). That is evidence on those inputs, not proof. The cases leave out JSON arrays and objects, limits other than `calls` (and `attenuate_with`'s lease-store lowering), capability patterns `names.rs` refuses, and any property of Unicode normalisation, which neither side performs; the README lists them under [Differential test](https://github.com/attenuo-dev/attenuo/blob/main/proofs/lean/README.md#differential-test).

Making the model executable found one assumption a faithful value type cannot meet as stated: the model asks `asLong (ofLong n) = some n` for every integer, and Rust's `Value::from` takes only an `i64`. The model applies `ofLong` only to `i64` range bounds, so the theorems are unaffected; the concrete type adds values outside `i64` that Rust cannot hold, and no case uses them.

The model also assumes a few facts about JSON values (canonical equality, `as_long`, the SR-71 range check) and run limits, and leaves out string encoding, number formatting, name validity, limit enforcement, Cedar policies, expiry, leases and DPoP. The README lists each assumption and omission.

## Running it

`scripts/check-lean.sh` builds the proof, fails on `sorry` or a new axiom, and checks the axioms of the main theorems. `scripts/check-lean-differential.sh` runs the differential test: the Rust test `crates/attenuo-core/tests/lean_differential.rs` writes the cases with Rust's answers, the Lean executable `differential` answers them from the model, and the script fails on the first disagreements. `scripts/dev.sh lean` runs both when Lean is installed and skips them otherwise; `just lean` and the CI job `lean` run them always.
