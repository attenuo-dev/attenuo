//! Property tests for budget planning (fuzzing round 2,
//! `docs/research/fuzzing-2026-10-24-round2.md`): the cases of the `budget_plan` fuzz target
//! that run without a nightly toolchain.
//!
//! Random sequences of charges and refunds over a small set of counters run against the
//! memory store and the SQLite store side by side, and against a model that keeps only the
//! charged, unrefunded decisions: a `calls`, `sum` or `calls_per` counter is the sum of what
//! they charged, a `distinct` value counts while one of them used it (SR-62), a run-usage
//! counter is the sum capped at `MAX_LIMIT`. After every step both stores agree with the model
//! and with each other; a `distinct` count is its number of value rows with `used > 0`; no
//! counter exceeds its `max`; and refunding every decision leaves every counter at 0.

use std::collections::BTreeMap;

use attenuo_audit::{AuditError, ChargeOutcome, LeaseStore, MemoryLeaseStore, SqliteLeaseStore};
use attenuo_core::limits::MAX_LIMIT;
use attenuo_core::{Charge, LeaseId, LimitKind};
use proptest::prelude::*;
use time::macros::datetime;
use time::OffsetDateTime;

mod proptest_seed;
use proptest_seed::proptest_config;

const LEASES: [&str; 2] = ["root", "child"];
const VALUES: u8 = 3;

fn t0() -> OffsetDateTime {
    datetime!(2026-10-24 12:00 UTC)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Counter {
    Calls(usize),
    Sum(usize),
    Per(usize, u8),
    Distinct(usize, u8),
    UsageAmount,
    UsageDest(u8),
}

#[derive(Debug, Clone, Copy)]
struct Step {
    counter: Counter,
    amount: u64,
}

#[derive(Debug, Clone)]
enum Op {
    Charge(Vec<Step>),
    Refund(usize),
}

/// The `max` of every limit, per lease: calls, sum, calls_per, distinct.
type Maxima = [[u64; 4]; 2];

fn step() -> impl Strategy<Value = Step> {
    let lease = 0usize..2;
    let value = 0u8..VALUES;
    let amount = prop_oneof![3 => 0u64..4, 1 => Just(MAX_LIMIT), 1 => Just(MAX_LIMIT - 1)];
    let counter = prop_oneof![
        lease.clone().prop_map(Counter::Calls),
        lease.clone().prop_map(Counter::Sum),
        (lease.clone(), value.clone()).prop_map(|(l, v)| Counter::Per(l, v)),
        (lease, value.clone()).prop_map(|(l, v)| Counter::Distinct(l, v)),
        Just(Counter::UsageAmount),
        value.prop_map(Counter::UsageDest),
    ];
    (counter, amount).prop_map(|(counter, amount)| Step {
        counter,
        amount: match counter {
            Counter::Sum(_) | Counter::UsageAmount => amount,
            _ => 1,
        },
    })
}

fn ops() -> impl Strategy<Value = Vec<Op>> {
    prop::collection::vec(
        prop_oneof![
            2 => prop::collection::vec(step(), 0..5).prop_map(Op::Charge),
            1 => (0usize..12).prop_map(Op::Refund),
        ],
        0..16,
    )
}

fn maxima() -> impl Strategy<Value = Maxima> {
    let m = prop_oneof![4 => 0u64..4, 1 => Just(MAX_LIMIT)];
    prop::array::uniform2(prop::array::uniform4(m))
}

fn charge(maxima: &Maxima, s: &Step) -> Charge {
    let token = |lease: usize, kind: LimitKind, arg: Option<&str>, value: Option<u8>| Charge {
        hop: lease,
        cap: 0,
        lease: LeaseId::new(LEASES[lease]),
        kind,
        arg: arg.map(str::to_owned),
        value: value.map(|v| format!("\"v{v}\"").into_bytes()),
        amount: s.amount,
        max: maxima[lease][match kind {
            LimitKind::Calls => 0,
            LimitKind::Sum => 1,
            LimitKind::CallsPer => 2,
            LimitKind::Distinct => 3,
        }],
        usage: false,
    };
    let usage = |kind, value: Option<u8>| Charge {
        hop: 0,
        cap: 0,
        lease: LeaseId::new(LEASES[0]),
        kind,
        arg: Some("bank/send".into()),
        value: value.map(|v| format!("\"v{v}\"").into_bytes()),
        amount: s.amount,
        max: MAX_LIMIT,
        usage: true,
    };
    match s.counter {
        Counter::Calls(l) => token(l, LimitKind::Calls, None, None),
        Counter::Sum(l) => token(l, LimitKind::Sum, Some("amount"), None),
        Counter::Per(l, v) => token(l, LimitKind::CallsPer, Some("to"), Some(v)),
        Counter::Distinct(l, v) => token(l, LimitKind::Distinct, Some("to#host"), Some(v)),
        Counter::UsageAmount => usage(LimitKind::Sum, None),
        Counter::UsageDest(v) => usage(LimitKind::CallsPer, Some(v)),
    }
}

fn universe() -> Vec<Counter> {
    let mut out = vec![Counter::UsageAmount];
    for v in 0..VALUES {
        out.push(Counter::UsageDest(v));
    }
    for l in 0..2 {
        out.push(Counter::Calls(l));
        out.push(Counter::Sum(l));
        for v in 0..VALUES {
            out.push(Counter::Per(l, v));
            out.push(Counter::Distinct(l, v));
        }
    }
    out
}

#[derive(Default)]
struct Model {
    decisions: BTreeMap<String, (Vec<(Counter, u64)>, bool)>,
}

impl Model {
    fn active(&self) -> impl Iterator<Item = &(Counter, u64)> {
        self.decisions
            .values()
            .filter(|(_, refunded)| !refunded)
            .flat_map(|(c, _)| c)
    }

    fn value(&self, c: Counter) -> u64 {
        if matches!(c, Counter::Distinct(..)) {
            return u64::from(self.active().any(|(k, _)| *k == c));
        }
        let total: u128 = self
            .active()
            .filter(|(k, _)| *k == c)
            .map(|(_, a)| u128::from(*a))
            .sum();
        match c {
            Counter::UsageAmount | Counter::UsageDest(_) => total.min(u128::from(MAX_LIMIT)) as u64,
            _ => u64::try_from(total).unwrap(),
        }
    }

    fn count(&self, lease: usize) -> u64 {
        (0..VALUES)
            .filter(|&v| self.value(Counter::Distinct(lease, v)) > 0)
            .count() as u64
    }

    fn plan(&self, maxima: &Maxima, steps: &[Step]) -> (ChargeOutcome, Vec<(Counter, u64)>) {
        let mut logged: Vec<(Counter, u64)> = Vec::new();
        let mut after = Vec::new();
        for (index, s) in steps.iter().enumerate() {
            let c = charge(maxima, s);
            if let Counter::Distinct(lease, _) = s.counter {
                let added = logged
                    .iter()
                    .filter(|(k, a)| {
                        matches!(k, Counter::Distinct(l, _) if *l == lease)
                            && *a > 0
                            && self.value(*k) == 0
                    })
                    .count() as u64;
                let count = self.count(lease) + added;
                let logged_here = logged.iter().any(|(k, _)| *k == s.counter);
                if self.value(s.counter) > 0 || logged_here {
                    if !logged_here {
                        logged.push((s.counter, 0));
                    }
                    after.push(count);
                } else if count < c.max {
                    logged.push((s.counter, 1));
                    after.push(count + 1);
                } else {
                    return (ChargeOutcome::Exhausted { index, used: count }, Vec::new());
                }
                continue;
            }
            let pending: u128 = logged
                .iter()
                .filter(|(k, _)| *k == s.counter)
                .map(|(_, a)| u128::from(*a))
                .sum();
            let mut current = u128::from(self.value(s.counter)) + pending;
            if c.usage {
                current = current.min(u128::from(MAX_LIMIT));
                logged.push((s.counter, s.amount));
                after.push((current + u128::from(s.amount)).min(u128::from(MAX_LIMIT)) as u64);
            } else if current + u128::from(s.amount) <= u128::from(c.max) {
                logged.push((s.counter, s.amount));
                after.push((current + u128::from(s.amount)) as u64);
            } else {
                return (
                    ChargeOutcome::Exhausted {
                        index,
                        used: current as u64,
                    },
                    Vec::new(),
                );
            }
        }
        (ChargeOutcome::Charged { used_after: after }, logged)
    }

    fn restored(&self, id: &str) -> u64 {
        let (logged, _) = &self.decisions[id];
        logged
            .iter()
            .filter(|(c, _)| match c {
                Counter::Calls(_) | Counter::Sum(_) | Counter::Per(..) => true,
                Counter::Distinct(..) => !self
                    .decisions
                    .iter()
                    .any(|(d, (l, r))| d != id && !r && l.iter().any(|(k, _)| k == c)),
                _ => false,
            })
            .count() as u64
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Refund {
    Restored(u64),
    Unknown,
    Again,
}

fn refund(store: &dyn LeaseStore, id: &str) -> Refund {
    match store.refund(id, t0()) {
        Ok(n) => Refund::Restored(n),
        Err(AuditError::UnknownCharge(_)) => Refund::Unknown,
        Err(AuditError::ChargeRefunded(_)) => Refund::Again,
        Err(e) => panic!("refund failed: {e}"),
    }
}

/// Every counter of the universe and each lease's `distinct` count, with the store's own
/// invariants checked.
fn snapshot(store: &dyn LeaseStore, maxima: &Maxima) -> (Vec<u64>, Vec<u64>) {
    let probes: Vec<Charge> = universe()
        .iter()
        .map(|&counter| charge(maxima, &Step { counter, amount: 0 }))
        .collect();
    let values = store.budget_used(&probes).unwrap();
    let count_probes: Vec<Charge> = (0..2)
        .map(|l| {
            Charge::probe(
                LeaseId::new(LEASES[l]),
                0,
                LimitKind::Distinct,
                Some("to#host".into()),
                maxima[l][3],
            )
        })
        .collect();
    let counts = store.budget_used(&count_probes).unwrap();
    for (l, count) in counts.iter().enumerate() {
        let rows = universe()
            .iter()
            .zip(&values)
            .filter(|(c, used)| matches!(c, Counter::Distinct(x, _) if *x == l) && **used > 0)
            .count() as u64;
        assert_eq!(*count, rows, "distinct count is not its number of values");
        assert!(*count <= maxima[l][3]);
    }
    for (p, used) in probes.iter().zip(&values) {
        assert!(*used <= p.max);
    }
    (values, counts)
}

fn run(maxima: &Maxima, ops: &[Op], stores: &[&dyn LeaseStore]) {
    let mut model = Model::default();
    let mut ids: Vec<String> = Vec::new();
    for (n, op) in ops.iter().enumerate() {
        match op {
            Op::Charge(steps) => {
                let id = format!("d{n}");
                let charges: Vec<Charge> = steps.iter().map(|s| charge(maxima, s)).collect();
                let (expected, logged) = model.plan(maxima, steps);
                for s in stores {
                    assert_eq!(s.charge(&id, &charges, t0()).unwrap(), expected);
                }
                if matches!(expected, ChargeOutcome::Charged { .. }) && !logged.is_empty() {
                    model.decisions.insert(id.clone(), (logged, false));
                }
                ids.push(id);
            }
            Op::Refund(i) => {
                let id = ids
                    .get(*i)
                    .cloned()
                    .unwrap_or_else(|| format!("unknown-{i}"));
                let expected = match model.decisions.get(&id) {
                    None => Refund::Unknown,
                    Some((_, true)) => Refund::Again,
                    Some((_, false)) => Refund::Restored(model.restored(&id)),
                };
                for s in stores {
                    assert_eq!(refund(*s, &id), expected, "refund of {id}");
                }
                if let Some(d) = model.decisions.get_mut(&id) {
                    d.1 = true;
                }
            }
        }
        let values: Vec<u64> = universe().iter().map(|&c| model.value(c)).collect();
        let counts: Vec<u64> = (0..2).map(|l| model.count(l)).collect();
        for s in stores {
            assert_eq!(snapshot(*s, maxima), (values.clone(), counts.clone()));
        }
        for lease in LEASES {
            let lease = LeaseId::new(lease);
            assert_eq!(
                stores[0].budget_summary(&lease).unwrap(),
                stores[1].budget_summary(&lease).unwrap()
            );
        }
    }
    let open: Vec<String> = model
        .decisions
        .iter()
        .filter(|(_, (_, r))| !r)
        .map(|(d, _)| d.clone())
        .collect();
    for id in open {
        for s in stores {
            assert!(matches!(refund(*s, &id), Refund::Restored(_)));
        }
    }
    for s in stores {
        let (values, counts) = snapshot(*s, maxima);
        assert!(values.iter().chain(&counts).all(|v| *v == 0));
    }
}

proptest! {
    #![proptest_config(proptest_config(256))]

    #[test]
    fn stores_agree_with_the_model(maxima in maxima(), ops in ops()) {
        let memory = MemoryLeaseStore::new();
        let sqlite = SqliteLeaseStore::open_in_memory().unwrap();
        run(&maxima, &ops, &[&memory, &sqlite]);
    }
}

/// A file store is much slower per case (a new database file each time), so it runs an
/// eighth of the in-memory count: 32 by default, `PROPTEST_CASES / 8` when that is set.
fn file_store_config() -> ProptestConfig {
    let config = proptest_config(256);
    ProptestConfig {
        cases: (config.cases / 8).max(1),
        ..config
    }
}

proptest! {
    #![proptest_config(file_store_config())]

    /// The same against the SQLite store in a file, as the server runs it.
    #[test]
    fn a_file_store_agrees_with_the_model(maxima in maxima(), ops in ops()) {
        let dir = tempfile::tempdir().unwrap();
        let memory = MemoryLeaseStore::new();
        let sqlite = SqliteLeaseStore::open(dir.path().join("leases.sqlite")).unwrap();
        run(&maxima, &ops, &[&memory, &sqlite]);
    }
}
