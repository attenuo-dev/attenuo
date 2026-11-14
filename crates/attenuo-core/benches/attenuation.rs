//! Cost of `CapabilitySet::covers`, the attenuation check run at every delegation hop.
//!
//! The parent holds `n` capabilities (`srv{i}:tool_*` with a `repo` prefix constraint); the
//! child holds `n` narrower ones, each covered by exactly one parent capability. `covers` is
//! `O(n * n)` in the worst case, which these sizes show.
//!
//! The `bounds` group measures attenuation at the request bounds of SR-123
//! ([`MAX_CAPABILITIES`] capabilities, [`MAX_CONSTRAINTS`] constraints and
//! [`MAX_ONE_OF_VALUES_TOTAL`] `one_of` values in all, [`MAX_ONE_OF_VALUES`] in one list), each
//! in its worst case: every requested capability is compared with every parent capability,
//! each comparison runs to the end, and all but the last parent fail.

use std::hint::black_box;

use attenuo_core::{
    ArgConstraint, Capability, CapabilitySet, MAX_CAPABILITIES, MAX_CONSTRAINTS, MAX_ONE_OF_VALUES,
    MAX_ONE_OF_VALUES_TOTAL,
};
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
    // value: every parent is compared in full. 400 such capabilities are about what a 2 MiB
    // request body holds; since the bound on the values of a whole token no token can carry
    // them, but the implication is measured here as it was before (17.7 s, then).
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
    // Within every bound: 1,024 requested capabilities against 1,023 parent capabilities on
    // the same tool, each request covered only by a last parent (`s:t*`), with one constraint
    // per capability (1,024 in all), of each kind that compares values.
    let cover = || Capability::new("s", "t*");
    let pair =
        |name: &str, p: &dyn Fn(usize) -> ArgConstraint, r: &dyn Fn(usize) -> ArgConstraint| {
            let parent: CapabilitySet = (0..MAX_CAPABILITIES - 1)
                .map(|j| Capability::new("s", "t").with_constraint("a", p(j)))
                .chain([cover()])
                .collect();
            let requested: CapabilitySet = (0..MAX_CAPABILITIES)
                .map(|i| Capability::new("s", "t").with_constraint("a", r(i)))
                .collect();
            assert!(requested.validate_size().is_ok() && parent.validate_size().is_ok());
            assert!(parent.attenuate(&requested).is_ok(), "{name}");
            (name.to_owned(), parent, requested)
        };
    // 150 numbers: about 600 bytes, 600 KB a side.
    let array = |last: Value| {
        let mut v: Vec<Value> = (0..150).map(|i| json!(i)).collect();
        v[149] = last;
        Value::Array(v)
    };
    let cases = [
        pair(
            "equals",
            &|j| ArgConstraint::Equals(json!(format!("p{j}"))),
            &|i| ArgConstraint::Equals(json!(format!("r{i}"))),
        ),
        pair(
            "one_of_of_one",
            &|j| ArgConstraint::OneOf(vec![json!(format!("p{j}"))]),
            &|i| ArgConstraint::OneOf(vec![json!(format!("r{i}"))]),
        ),
        pair(
            "equals_600_byte_arrays",
            &|j| ArgConstraint::Equals(array(json!(format!("p{j}")))),
            &|i| ArgConstraint::Equals(array(json!(format!("r{i}")))),
        ),
        pair(
            "path_prefix",
            &|j| ArgConstraint::path_prefix(format!("/w/p{j}")).unwrap(),
            &|i| ArgConstraint::OneOf(vec![json!(format!("/w/r{i}/x"))]),
        ),
    ];
    assert_eq!(MAX_CONSTRAINTS, MAX_CAPABILITIES);
    for (name, parent, requested) in &cases {
        group.bench_function(format!("within_bounds_1024_by_1024/{name}"), |b| {
            b.iter(|| black_box(parent).attenuate(black_box(requested)))
        });
    }
    // Two constraints per capability (the constraint bound with half the capabilities), the
    // first equal on both sides, so every pair compares both.
    let half = MAX_CONSTRAINTS / 2;
    let two = |tag: String| {
        Capability::new("s", "t")
            .with_constraint("a", ArgConstraint::Equals(array(json!("x"))))
            .with_constraint("b", ArgConstraint::Equals(json!(tag)))
    };
    let parent: CapabilitySet = (0..half - 1)
        .map(|j| two(format!("p{j}")))
        .chain([cover()])
        .collect();
    let requested: CapabilitySet = (0..half).map(|i| two(format!("r{i}"))).collect();
    assert!(requested.validate_size().is_ok() && parent.attenuate(&requested).is_ok());
    group.bench_function("within_bounds_512_by_512/two_constraints", |b| {
        b.iter(|| black_box(&parent).attenuate(black_box(&requested)))
    });
    // The values bound as 32 lists of 32 a side.
    let lists = |tag: &str, n: usize| -> CapabilitySet {
        (0..n)
            .map(|i| {
                Capability::new("s", "t").with_constraint(
                    "a",
                    ArgConstraint::OneOf(values(32, json!(format!("{tag}{i}")))),
                )
            })
            .collect()
    };
    let mut parent = lists("p", MAX_ONE_OF_VALUES_TOTAL / 32 - 1);
    parent.insert(cover());
    let requested = lists("r", MAX_ONE_OF_VALUES_TOTAL / 32);
    assert!(requested.validate_size().is_ok() && parent.attenuate(&requested).is_ok());
    group.bench_function("within_bounds_32_by_32/one_of_32", |b| {
        b.iter(|| black_box(&parent).attenuate(black_box(&requested)))
    });
    group.finish();
}

/// Reading a request body of about 1.6 MB: 400 capabilities with a `one_of` of 1,024 values
/// each, alike but for the last value. Read before any bound is checked; a `BTreeSet` built
/// one insertion at a time wrote each capability's canonical form about `2 log n` times.
fn bench_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("bounds");
    group.sample_size(10);
    let set: CapabilitySet = (0..400)
        .map(|j| {
            Capability::new("s", "t").with_constraint(
                "a",
                ArgConstraint::OneOf(values(MAX_ONE_OF_VALUES, json!(format!("p{j}")))),
            )
        })
        .collect();
    let body = serde_json::to_string(&set).unwrap();
    group.bench_function("read_400_lists_of_1024", |b| {
        b.iter(|| serde_json::from_str::<CapabilitySet>(black_box(&body)).unwrap())
    });
    group.finish();
}

criterion_group!(benches, bench_covers, bench_bounds, bench_read);
criterion_main!(benches);
