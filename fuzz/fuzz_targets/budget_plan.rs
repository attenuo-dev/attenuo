//! Budget planning in the lease store (`attenuo_audit::budget::plan`, through
//! `LeaseStore::charge` and `LeaseStore::refund`): random sequences of charges and refunds
//! over a small set of counters, run against the memory store and against the SQLite store in
//! a temporary file, side by side, and against a model.
//!
//! The model keeps only the decisions that are charged and not refunded; every counter is
//! derived from them: a `calls`, `sum` or `calls_per` counter is the sum of what those
//! decisions charged to it, a `distinct` value is counted while at least one of them used it
//! (SR-62), a run-usage counter is that sum capped at `MAX_LIMIT`.
//!
//! Checked after every step, in both stores:
//!
//! - both stores give the same outcome (`Charged` with the same figures, the same `Exhausted`
//!   index and figure, the same refund count or error kind) and the same counters, and so does
//!   the model;
//! - a `distinct` count equals the number of its value rows with `used > 0`;
//! - no token-limit counter exceeds its `max`; a refund never takes one below zero (the stores
//!   read counters as `u64`, so a negative row would be an error);
//! - after every decision is refunded, every counter is 0.
#![no_main]

use std::collections::BTreeMap;

use arbitrary::{Arbitrary, Result, Unstructured};
use attenuo_audit::{AuditError, ChargeOutcome, LeaseStore, MemoryLeaseStore, SqliteLeaseStore};
use attenuo_core::limits::MAX_LIMIT;
use attenuo_core::{Charge, LeaseId, LimitKind};
use libfuzzer_sys::fuzz_target;
use time::OffsetDateTime;

const LEASES: &[&str] = &["root", "child"];
const CAPS: usize = 2;
const VALUES: u8 = 4;

/// One counter of the small universe the sequences charge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Counter {
    Calls { lease: usize, cap: usize },
    Sum { lease: usize, cap: usize },
    Per { lease: usize, cap: usize, value: u8 },
    Distinct { lease: usize, cap: usize, value: u8 },
    UsageCalls,
    UsageAmount,
    UsageDest { value: u8 },
}

/// A `distinct` limit's count of values (a model key, not a charge).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct DistinctCount {
    lease: usize,
    cap: usize,
}

#[derive(Debug, Clone, Copy)]
struct Step {
    counter: Counter,
    amount: u64,
}

#[derive(Debug)]
enum Op {
    Charge(Vec<Step>),
    /// Refund the n-th decision id handed out so far (or an unknown one past the end).
    Refund(usize),
    /// Charge again under an id already used.
    Recharge(usize, Vec<Step>),
}

/// The `max` of each limit, fixed for the whole sequence, as a token fixes it.
#[derive(Debug, Clone)]
struct Maxima {
    /// Which sequence this is: lease names and decision ids carry it, so sequences sharing one
    /// SQLite file never touch each other's counters.
    run: u64,
    calls: [[u64; CAPS]; 2],
    sum: [[u64; CAPS]; 2],
    per: [[u64; CAPS]; 2],
    distinct: [[u64; CAPS]; 2],
}

#[derive(Debug)]
struct Input {
    maxima: Maxima,
    ops: Vec<Op>,
    sqlite: bool,
}

fn small_max(u: &mut Unstructured<'_>) -> Result<u64> {
    Ok(match u.int_in_range(0u8..=7)? {
        0 => MAX_LIMIT,
        1 => MAX_LIMIT - 1,
        _ => u.int_in_range(0u64..=4)?,
    })
}

fn grid(u: &mut Unstructured<'_>) -> Result<[[u64; CAPS]; 2]> {
    Ok([
        [small_max(u)?, small_max(u)?],
        [small_max(u)?, small_max(u)?],
    ])
}

fn amount(u: &mut Unstructured<'_>) -> Result<u64> {
    Ok(match u.int_in_range(0u8..=7)? {
        0 => MAX_LIMIT,
        1 => MAX_LIMIT - 1,
        2 => 0,
        _ => u.int_in_range(1u64..=3)?,
    })
}

fn step(u: &mut Unstructured<'_>) -> Result<Step> {
    let lease = u.int_in_range(0usize..=1)?;
    let cap = u.int_in_range(0usize..=CAPS - 1)?;
    let value = u.int_in_range(0u8..=VALUES - 1)?;
    let counter = match u.int_in_range(0u8..=6)? {
        0 => Counter::Calls { lease, cap },
        1 => Counter::Sum { lease, cap },
        2 => Counter::Per { lease, cap, value },
        3 => Counter::Distinct { lease, cap, value },
        4 => Counter::UsageCalls,
        5 => Counter::UsageAmount,
        _ => Counter::UsageDest { value },
    };
    let amount = match counter {
        Counter::Sum { .. } | Counter::UsageAmount => amount(u)?,
        _ => 1,
    };
    Ok(Step { counter, amount })
}

fn steps(u: &mut Unstructured<'_>) -> Result<Vec<Step>> {
    (0..u.int_in_range(0usize..=6)?).map(|_| step(u)).collect()
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let maxima = Maxima {
            run: 0,
            calls: grid(u)?,
            sum: grid(u)?,
            per: grid(u)?,
            distinct: grid(u)?,
        };
        let sqlite = u.ratio(3u8, 4u8)?;
        let mut ops = Vec::new();
        for _ in 0..u.int_in_range(0usize..=24)? {
            ops.push(match u.int_in_range(0u8..=9)? {
                0..=5 => Op::Charge(steps(u)?),
                6..=8 => Op::Refund(u.int_in_range(0usize..=24)?),
                _ => Op::Recharge(u.int_in_range(0usize..=24)?, steps(u)?),
            });
        }
        Ok(Input {
            maxima,
            ops,
            sqlite,
        })
    }
}

fn value_bytes(v: u8) -> Vec<u8> {
    format!("\"v{v}\"").into_bytes()
}

impl Maxima {
    fn lease(&self, i: usize) -> LeaseId {
        LeaseId::new(format!("{}-{}", LEASES[i], self.run))
    }

    fn charge(&self, s: &Step) -> Charge {
        let token = |lease: usize, cap: usize, kind, arg: Option<&str>, value, max| Charge {
            hop: lease,
            cap,
            lease: self.lease(lease),
            kind,
            arg: arg.map(str::to_owned),
            value,
            amount: s.amount,
            max,
            usage: false,
        };
        let usage = |kind, value| Charge {
            hop: 0,
            cap: 0,
            lease: self.lease(0),
            kind,
            arg: Some("bank/send".into()),
            value,
            amount: s.amount,
            max: MAX_LIMIT,
            usage: true,
        };
        match s.counter {
            Counter::Calls { lease, cap } => token(
                lease,
                cap,
                LimitKind::Calls,
                None,
                None,
                self.calls[lease][cap],
            ),
            Counter::Sum { lease, cap } => token(
                lease,
                cap,
                LimitKind::Sum,
                Some("amount"),
                None,
                self.sum[lease][cap],
            ),
            Counter::Per { lease, cap, value } => token(
                lease,
                cap,
                LimitKind::CallsPer,
                Some("to"),
                Some(value_bytes(value)),
                self.per[lease][cap],
            ),
            Counter::Distinct { lease, cap, value } => token(
                lease,
                cap,
                LimitKind::Distinct,
                Some("to#host"),
                Some(value_bytes(value)),
                self.distinct[lease][cap],
            ),
            Counter::UsageCalls => usage(LimitKind::Calls, None),
            Counter::UsageAmount => usage(LimitKind::Sum, None),
            Counter::UsageDest { value } => usage(LimitKind::CallsPer, Some(value_bytes(value))),
        }
    }

    fn count_probe(&self, c: DistinctCount) -> Charge {
        Charge::probe(
            self.lease(c.lease),
            c.cap,
            LimitKind::Distinct,
            Some("to#host".into()),
            self.distinct[c.lease][c.cap],
        )
    }
}

/// Every counter of the universe, in a fixed order.
fn universe() -> Vec<Counter> {
    let mut out = vec![Counter::UsageCalls, Counter::UsageAmount];
    for value in 0..VALUES {
        out.push(Counter::UsageDest { value });
    }
    for lease in 0..2 {
        for cap in 0..CAPS {
            out.push(Counter::Calls { lease, cap });
            out.push(Counter::Sum { lease, cap });
            for value in 0..VALUES {
                out.push(Counter::Per { lease, cap, value });
                out.push(Counter::Distinct { lease, cap, value });
            }
        }
    }
    out
}

fn counts() -> Vec<DistinctCount> {
    (0..2)
        .flat_map(|lease| (0..CAPS).map(move |cap| DistinctCount { lease, cap }))
        .collect()
}

/// The model: the decisions charged and not refunded, and what each charged.
#[derive(Default)]
struct Model {
    /// Decision id -> (charged counters with amounts, refunded).
    decisions: BTreeMap<String, (Vec<(Counter, u64)>, bool)>,
}

impl Model {
    fn active(&self) -> impl Iterator<Item = &Vec<(Counter, u64)>> {
        self.decisions
            .values()
            .filter(|(_, refunded)| !refunded)
            .map(|(c, _)| c)
    }

    /// What counter `c` holds: a sum (capped for usage), or for a `distinct` value 1 while an
    /// active decision used it.
    fn value(&self, c: Counter) -> u64 {
        if matches!(c, Counter::Distinct { .. }) {
            // Held while any active decision used it, whether it added it or not (SR-62).
            return u64::from(self.active().flatten().any(|(k, _)| *k == c));
        }
        let total: u128 = self
            .active()
            .flatten()
            .filter(|(k, _)| *k == c)
            .map(|(_, a)| u128::from(*a))
            .sum();
        match c {
            Counter::UsageCalls | Counter::UsageAmount | Counter::UsageDest { .. } => {
                total.min(u128::from(MAX_LIMIT)) as u64
            }
            _ => u64::try_from(total).expect("token-limit counters stay within u64"),
        }
    }

    fn count(&self, d: DistinctCount) -> u64 {
        (0..VALUES)
            .filter(|&value| {
                self.value(Counter::Distinct {
                    lease: d.lease,
                    cap: d.cap,
                    value,
                }) > 0
            })
            .count() as u64
    }

    /// What charging `steps` would do: the outcome and the counters with amounts to log.
    fn plan(&self, maxima: &Maxima, steps: &[Step]) -> (ChargeOutcome, Vec<(Counter, u64)>) {
        let mut logged: Vec<(Counter, u64)> = Vec::new();
        let mut after = Vec::new();
        let held = |logged: &[(Counter, u64)], c: Counter| {
            self.value(c) > 0 || logged.iter().any(|(k, _)| *k == c)
        };
        for (index, s) in steps.iter().enumerate() {
            let charge = maxima.charge(s);
            match s.counter {
                Counter::Distinct { lease, cap, value } => {
                    let key = Counter::Distinct { lease, cap, value };
                    let dc = DistinctCount { lease, cap };
                    let count = self.count(dc)
                        + (0..VALUES)
                            .filter(|&v| {
                                let k = Counter::Distinct {
                                    lease,
                                    cap,
                                    value: v,
                                };
                                self.value(k) == 0 && logged.iter().any(|(x, a)| *x == k && *a > 0)
                            })
                            .count() as u64;
                    if held(&logged, key) {
                        if !logged.iter().any(|(k, _)| *k == key) {
                            logged.push((key, 0));
                        }
                        after.push(count);
                    } else if count < charge.max {
                        logged.push((key, 1));
                        after.push(count + 1);
                    } else {
                        return (ChargeOutcome::Exhausted { index, used: count }, Vec::new());
                    }
                }
                c => {
                    let current: u128 = u128::from(self.value(c))
                        + logged
                            .iter()
                            .filter(|(k, _)| *k == c)
                            .map(|(_, a)| u128::from(*a))
                            .sum::<u128>();
                    let usage = charge.usage;
                    let current = if usage {
                        current.min(u128::from(MAX_LIMIT))
                    } else {
                        current
                    };
                    let next = current + u128::from(s.amount);
                    if usage {
                        logged.push((c, s.amount));
                        after.push(next.min(u128::from(MAX_LIMIT)) as u64);
                    } else if next <= u128::from(charge.max) {
                        logged.push((c, s.amount));
                        after.push(next as u64);
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
            }
        }
        (ChargeOutcome::Charged { used_after: after }, logged)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RefundResult {
    Restored(u64),
    Unknown,
    AlreadyRefunded,
}

fn refund_result(r: std::result::Result<u64, AuditError>) -> RefundResult {
    match r {
        Ok(n) => RefundResult::Restored(n),
        Err(AuditError::UnknownCharge(_)) => RefundResult::Unknown,
        Err(AuditError::ChargeRefunded(_)) => RefundResult::AlreadyRefunded,
        Err(e) => panic!("refund failed: {e}"),
    }
}

fn now() -> OffsetDateTime {
    attenuo_fuzz::fixture().now
}

/// Read every counter of the universe and every `distinct` count from `store`, and check the
/// store's own invariants.
fn snapshot(store: &dyn LeaseStore, maxima: &Maxima) -> (Vec<u64>, Vec<u64>) {
    let charges: Vec<Charge> = universe()
        .iter()
        .map(|&counter| maxima.charge(&Step { counter, amount: 0 }))
        .collect();
    let values = store.budget_used(&charges).expect("counters read");
    let count_probes: Vec<Charge> = counts()
        .into_iter()
        .map(|d| maxima.count_probe(d))
        .collect();
    let totals = store.budget_used(&count_probes).expect("counts read");
    for (d, total) in counts().into_iter().zip(&totals) {
        let rows = universe()
            .iter()
            .zip(&values)
            .filter(|(c, used)| {
                matches!(c, Counter::Distinct { lease, cap, .. } if *lease == d.lease && *cap == d.cap)
                    && **used > 0
            })
            .count() as u64;
        assert_eq!(*total, rows, "distinct count is not its number of values");
        assert!(*total <= maxima.distinct[d.lease][d.cap]);
    }
    for (c, used) in universe().iter().zip(&values) {
        let max = maxima
            .charge(&Step {
                counter: *c,
                amount: 0,
            })
            .max;
        assert!(*used <= max, "{c:?} holds {used}, over its max {max}");
        if matches!(c, Counter::Distinct { .. }) {
            assert!(*used <= 1);
        }
    }
    (values, totals)
}

fn temp_db() -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("attenuo-fuzz-budget-{}.sqlite", std::process::id()));
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    path
}

/// Sequences run against one SQLite file before it is replaced by a fresh one.
const SEQUENCES_PER_FILE: u64 = 2000;

thread_local! {
    static SQLITE: std::cell::RefCell<Option<SqliteLeaseStore>> =
        const { std::cell::RefCell::new(None) };
    static RUN: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fuzz_target!(|input: Input| {
    let run = RUN.with(|r| {
        r.set(r.get() + 1);
        r.get()
    });
    let mut maxima = input.maxima.clone();
    maxima.run = run;
    let maxima = &maxima;
    if input.sqlite {
        SQLITE.with(|cell| {
            let mut slot = cell.borrow_mut();
            if slot.is_none() || run % SEQUENCES_PER_FILE == 0 {
                *slot = None;
                *slot = Some(SqliteLeaseStore::open(temp_db()).expect("sqlite store opens"));
            }
        });
    }
    SQLITE.with(|cell| {
        let slot = cell.borrow();
        let sqlite = slot.as_ref().filter(|_| input.sqlite);
        sequence(&input, maxima, sqlite);
    });
});

fn sequence(input: &Input, maxima: &Maxima, sqlite: Option<&SqliteLeaseStore>) {
    let run = maxima.run;
    let memory = MemoryLeaseStore::new();
    let mut stores: Vec<&dyn LeaseStore> = vec![&memory];
    if let Some(s) = sqlite {
        stores.push(s);
    }
    let mut model = Model::default();
    let mut ids: Vec<String> = Vec::new();

    for (n, op) in input.ops.iter().enumerate() {
        match op {
            Op::Charge(steps) | Op::Recharge(_, steps) => {
                let id = match op {
                    Op::Recharge(i, _) if !ids.is_empty() => ids[i % ids.len()].clone(),
                    _ => format!("r{run}-d{n}"),
                };
                let charges: Vec<Charge> = steps.iter().map(|s| maxima.charge(s)).collect();
                let outcomes: Vec<_> = stores
                    .iter()
                    .map(|s| s.charge(&id, &charges, now()))
                    .collect();
                let already = model.decisions.contains_key(&id);
                if already && !charges.is_empty() {
                    for o in &outcomes {
                        assert!(
                            matches!(o, Err(AuditError::Storage(_))),
                            "a decision was charged twice: {o:?}"
                        );
                    }
                } else {
                    let (expected, logged) = model.plan(maxima, steps);
                    for o in outcomes {
                        let o = o.expect("charge succeeds");
                        assert_eq!(o, expected, "charge outcome differs from the model");
                    }
                    if matches!(expected, ChargeOutcome::Charged { .. }) && !logged.is_empty() {
                        model.decisions.insert(id.clone(), (logged, false));
                    }
                    if !ids.contains(&id) {
                        ids.push(id);
                    }
                }
            }
            Op::Refund(i) => {
                let id = ids
                    .get(*i)
                    .cloned()
                    .unwrap_or_else(|| format!("r{run}-unknown-{i}"));
                let expected = match model.decisions.get(&id) {
                    None => RefundResult::Unknown,
                    Some((_, true)) => RefundResult::AlreadyRefunded,
                    Some((logged, false)) => {
                        // Token-limit counters restored: every non-usage, non-distinct row,
                        // plus each distinct value no other active decision holds.
                        let mut n = 0u64;
                        for (c, _) in logged {
                            match c {
                                Counter::Calls { .. }
                                | Counter::Sum { .. }
                                | Counter::Per { .. } => n += 1,
                                Counter::Distinct { .. } => {
                                    let others = model
                                        .decisions
                                        .iter()
                                        .filter(|(d, (_, r))| **d != id && !r)
                                        .any(|(_, (l, _))| l.iter().any(|(k, _)| k == c));
                                    if !others {
                                        n += 1;
                                    }
                                }
                                _ => {}
                            }
                        }
                        RefundResult::Restored(n)
                    }
                };
                for s in &stores {
                    assert_eq!(
                        refund_result(s.refund(&id, now())),
                        expected,
                        "refund result differs from the model"
                    );
                }
                if let Some(d) = model.decisions.get_mut(&id) {
                    d.1 = true;
                }
            }
        }
        // Every store agrees with the model, counter by counter.
        let expected_values: Vec<u64> = universe().iter().map(|&c| model.value(c)).collect();
        let expected_counts: Vec<u64> = counts().into_iter().map(|d| model.count(d)).collect();
        for s in &stores {
            let (values, totals) = snapshot(*s, maxima);
            assert_eq!(values, expected_values, "counters differ from the model");
            assert_eq!(
                totals, expected_counts,
                "distinct counts differ from the model"
            );
        }
        if stores.len() == 2 {
            for i in 0..LEASES.len() {
                let lease = maxima.lease(i);
                assert_eq!(
                    stores[0].budget_summary(&lease).unwrap(),
                    stores[1].budget_summary(&lease).unwrap(),
                    "the stores summarise differently"
                );
            }
        }
    }

    // Refund everything still charged: every counter goes back to 0.
    let open: Vec<String> = model
        .decisions
        .iter()
        .filter(|(_, (_, r))| !r)
        .map(|(d, _)| d.clone())
        .collect();
    for id in open {
        for s in &stores {
            assert!(matches!(
                refund_result(s.refund(&id, now())),
                RefundResult::Restored(_)
            ));
        }
    }
    for s in &stores {
        let (values, totals) = snapshot(*s, maxima);
        assert!(
            values.iter().chain(&totals).all(|v| *v == 0),
            "counters left after refunding every decision: {values:?} {totals:?}"
        );
    }
}
