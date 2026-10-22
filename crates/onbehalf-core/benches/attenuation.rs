//! Cost of `CapabilitySet::covers`, the attenuation check run at every delegation hop.
//!
//! The parent holds `n` capabilities (`srv{i}:tool_*` with a `repo` prefix constraint); the
//! child holds `n` narrower ones, each covered by exactly one parent capability. `covers` is
//! `O(n * n)` in the worst case, which these sizes show.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use onbehalf_core::{ArgConstraint, Capability, CapabilitySet};

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

criterion_group!(benches, bench_covers);
criterion_main!(benches);
