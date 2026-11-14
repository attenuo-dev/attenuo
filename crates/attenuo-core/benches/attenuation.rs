//! Cost of `CapabilitySet::covers`, the attenuation check run at every delegation hop.
//!
//! The parent holds `n` capabilities (`srv{i}:tool_*` with a `repo` prefix constraint); the
//! child holds `n` narrower ones, each covered by exactly one parent capability. `covers` is
//! `O(n * n)` in the worst case, which these sizes show.
//!
//! The `bounds` group measures attenuation at the request bounds of SR-123
//! ([`MAX_CAPABILITIES`] capabilities, [`MAX_ONE_OF_VALUES`] values in a `one_of`), each in its
//! worst case: every comparison runs to the end and fails.

use std::hint::black_box;

use attenuo_core::{ArgConstraint, Capability, CapabilitySet, MAX_CAPABILITIES, MAX_ONE_OF_VALUES};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use serde_json::{json, Value};

fn sets(n: usize) -> (CapabilitySet, CapabilitySet) {
    let parent = (0..n)
        .map(|i| {
            Capability::new(format!("srv{i:02}"), "tool_*")
                .with_constraint("repo", ArgConstraint::Prefix("org/".into()))
        })
        .collect::<CapabilitySet>();
    let child = (0..n)
        .map(|i| {
            Capability::new(format!("srv{i:02}"), "tool_read")
                .with_constraint("repo", ArgConstraint::Prefix("org/team/".into()))
        })
        .collect::<CapabilitySet>();
    (parent, child)
}

fn bench_covers(c: &mut Criterion) {
    let mut group = c.benchmark_group("covers");
    for n in [1usize, 8, 32] {
        let (parent, child) = sets(n);
        assert!(parent.covers(&child), "n={n}: child must be covered");
        assert!(!child.covers(&parent), "n={n}: widening must be rejected");
        group.bench_with_input(BenchmarkId::new("covered", n), &n, |b, _| {
            b.iter(|| black_box(&parent).covers(black_box(&child)))
        });
        group.bench_with_input(BenchmarkId::new("rejected_widening", n), &n, |b, _| {
            b.iter(|| black_box(&child).covers(black_box(&parent)))
        });
    }
    group.finish();
}

/// `0..n` as JSON values, with the last replaced by `last`.
fn values(n: usize, last: Value) -> Vec<Value> {
    let mut v: Vec<Value> = (0..n).map(|i| json!(i)).collect();
    v[n - 1] = last;
    v
}

fn bench_bounds(c: &mut Criterion) {
    let mut group = c.benchmark_group("bounds");
    group.sample_size(10);
    // One implication between two `one_of` lists at the bound; the child's last value is not in
    // the parent's, so every value is looked for and the last one through the whole list.
    let n = MAX_ONE_OF_VALUES;
    let child = ArgConstraint::OneOf(values(n, json!("absent")));
    let parent = ArgConstraint::OneOf(values(n, json!("other")));
    assert!(!child.implies(&parent));
    group.bench_function("one_of_implies_1024x1024", |b| {
        b.iter(|| black_box(&child).implies(black_box(&parent)))
    });
    // 1,024 requested capabilities against 1,024 parent capabilities, each request covered
    // only by the parent capability that sorts last.
    let parent: CapabilitySet = (0..MAX_CAPABILITIES - 1)
        .map(|j| Capability::new(format!("a{j:04}"), "*"))
        .chain([Capability::new("z", "*")])
        .collect();
    let requested: CapabilitySet = (0..MAX_CAPABILITIES)
        .map(|i| Capability::new("z", format!("t{i:04}")))
        .collect();
    assert!(parent.attenuate(&requested).is_ok());
    group.bench_function("attenuate_1024_by_1024", |b| {
        b.iter(|| black_box(&parent).attenuate(black_box(&requested)))
    });
    // One requested capability with a `one_of` at the bound against `k` parent capabilities on
    // the same tool, each with a `one_of` at the bound that lacks only the request's last
    // value: every parent is compared in full, twice (`covers`, then `covers_calls`). 400 such
    // capabilities are about what a 2 MiB request body holds, so a root token can carry them.
    let request = CapabilitySet::from_iter([Capability::new("s", "t")
        .with_constraint("a", ArgConstraint::OneOf(values(n, json!("absent"))))]);
    for k in [1usize, 400] {
        let parent: CapabilitySet = (0..k)
            .map(|j| {
                Capability::new("s", "t")
                    .with_constraint("a", ArgConstraint::OneOf(values(n, json!(format!("p{j}")))))
            })
            .collect();
        assert_eq!(parent.len(), k);
        assert!(parent.attenuate(&request).is_err());
        group.bench_with_input(
            BenchmarkId::new("one_of_request_vs_parents", k),
            &k,
            |b, _| b.iter(|| black_box(&parent).attenuate(black_box(&request))),
        );
    }
    group.finish();
}

criterion_group!(benches, bench_covers, bench_bounds);
criterion_main!(benches);
