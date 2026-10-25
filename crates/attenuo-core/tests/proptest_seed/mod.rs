//! The property-test seed policy, shared by the proptest files of this crate. An identical copy
//! lives in each crate that has property tests (`attenuo-core`, `attenuo-audit`); change both.
//!
//! - `PROPTEST_CASES=<n>` sets the number of cases of every property test (default: the count
//!   the test passes in).
//! - `PROPTEST_RNG_SEED=<u64>` fixes the seed, so a run replays exactly. CI pins it. This is
//!   proptest's own variable (a made-up `PROPTEST_SEED` would draw proptest's "Ignoring unknown
//!   env-var" warning); the helper parses it strictly and panics on a bad value instead of
//!   proptest's warn-and-fall-back.
//! - Without `PROPTEST_RNG_SEED` the seed is random and printed to the test's captured output,
//!   which the harness shows when the test fails: rerun with that `PROPTEST_RNG_SEED` to replay.
//!
//! Failure persistence stays off: no `proptest-regressions/` files are written (the directory
//! is gitignored as well). A failure is kept as its seed and, once understood, as a
//! deterministic regression test next to the properties.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

use proptest::test_runner::{Config as ProptestConfig, RngSeed};

const CASES_VAR: &str = "PROPTEST_CASES";
const SEED_VAR: &str = "PROPTEST_RNG_SEED";

/// The config every property test uses: `default_cases` unless `PROPTEST_CASES` says
/// otherwise, the seed from `PROPTEST_RNG_SEED` or a random one that is printed, no persistence.
pub fn proptest_config(default_cases: u32) -> ProptestConfig {
    let cases = parse_cases(std::env::var(CASES_VAR).ok().as_deref()).unwrap_or(default_cases);
    let seed = parse_seed(std::env::var(SEED_VAR).ok().as_deref()).unwrap_or_else(|| {
        let seed = RandomState::new().build_hasher().finish();
        println!("proptest: random seed, replay with {SEED_VAR}={seed}");
        seed
    });
    ProptestConfig {
        cases,
        rng_seed: RngSeed::Fixed(seed),
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// `PROPTEST_CASES`: unset or empty is `None`; anything but a positive integer panics.
fn parse_cases(value: Option<&str>) -> Option<u32> {
    let value = value.filter(|v| !v.is_empty())?;
    match value.parse::<u32>() {
        Ok(n) if n > 0 => Some(n),
        _ => panic!("{CASES_VAR} must be a positive integer, got {value:?}"),
    }
}

/// `PROPTEST_RNG_SEED`: unset or empty is `None`; anything but a decimal u64 panics.
fn parse_seed(value: Option<&str>) -> Option<u64> {
    let value = value.filter(|v| !v.is_empty())?;
    match value.parse::<u64>() {
        Ok(seed) => Some(seed),
        Err(_) => panic!("{SEED_VAR} must be a decimal u64, got {value:?}"),
    }
}

#[test]
fn proptest_seed_is_parsed() {
    assert_eq!(parse_seed(None), None);
    assert_eq!(parse_seed(Some("")), None);
    assert_eq!(parse_seed(Some("0")), Some(0));
    assert_eq!(parse_seed(Some("20261024")), Some(20_261_024));
    assert_eq!(parse_seed(Some("18446744073709551615")), Some(u64::MAX));
}

#[test]
#[should_panic(expected = "PROPTEST_RNG_SEED must be a decimal u64, got \"0xbeef\"")]
fn an_invalid_proptest_seed_panics_naming_the_variable() {
    parse_seed(Some("0xbeef"));
}

#[test]
fn proptest_cases_are_parsed() {
    assert_eq!(parse_cases(None), None);
    assert_eq!(parse_cases(Some("")), None);
    assert_eq!(parse_cases(Some("4096")), Some(4096));
}

#[test]
#[should_panic(expected = "PROPTEST_CASES must be a positive integer, got \"0\"")]
fn an_invalid_proptest_case_count_panics_naming_the_variable() {
    parse_cases(Some("0"));
}
