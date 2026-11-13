//! Run limits (ADR-0010): what the counters of a call's matching limits hold, and the
//! figures stated for an admin dry run.

use attenuo_audit::RunLimits;
use attenuo_core::{Charge, LimitKind};
use attenuo_policy::{BudgetContext, UsageContext};
use serde_json::Value;

/// What [`Pipeline::budget_view`] found for a call: the run limits that match it (ADR-0010)
/// and, for a destructive tool, the run's usage of it (run-limits design section 3.5).
///
/// [`Pipeline::budget_view`]: super::Pipeline::budget_view
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BudgetView {
    /// Every counter the call would be charged against: the matching limits, then the run-usage
    /// counters ([`Charge::usage`]). Empty when no limit matches and the tool is not
    /// destructive.
    pub charges: Vec<Charge>,
    /// What Cedar sees as `context.usage`. `None` when the tool keeps no usage (it is not
    /// destructive), or when the call was refused before usage was read.
    pub usage: Option<UsageContext>,
    /// Set when the run's usage could not be read and no limit matched the call: `usage` is
    /// then the worst case ([`UNREADABLE_USAGE`]) and the call is decided by the policy.
    ///
    /// [`UNREADABLE_USAGE`]: super::UNREADABLE_USAGE
    pub usage_error: Option<String>,
    /// What Cedar sees as `context.budget`, with the refusal of the limit check, if any.
    pub context: BudgetContext,
    /// For `budget_exhausted`: the limit the call would take past its `max`.
    pub hit: Option<LimitHit>,
    /// The per-user window counters the call would be charged against (run limits phase 3),
    /// with the run usage. Empty when no loaded policy reads a window or the call keeps no
    /// usage.
    pub windows: Vec<attenuo_core::WindowCharge>,
}

/// A run limit a call would exceed: the `limit` member of a `budget_exhausted` denial
/// (JSON-RPC `-32003` `data.limit`, AuthZEN `context.limit`). The hop is named by its
/// position, not its lease id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitHit {
    /// Position of the hop whose limit it is (0 is the root).
    pub hop: usize,
    /// Which kind of limit was hit.
    pub kind: LimitKind,
    /// The argument the limit counts, as [`Charge::arg`] names it; `None` for `calls`.
    pub arg: Option<String>,
    /// The limit's `max`.
    pub max: u64,
    /// What the counter held before the call.
    pub used: u64,
}

impl LimitHit {
    pub(super) fn of(charge: &Charge, used: u64) -> Self {
        Self {
            hop: charge.hop,
            kind: charge.kind,
            arg: charge.arg.clone(),
            max: charge.max,
            used,
        }
    }

    /// `{hop, kind, arg, max, used}`, `arg` only for `sum`, `calls_per` and `distinct` (`url#host`
    /// for a derived value). For `distinct`, `used` is how many values the limit has seen.
    pub fn to_json(&self) -> Value {
        let mut v = serde_json::json!({
            "hop": self.hop,
            "kind": self.kind.as_str(),
            "max": self.max,
            "used": self.used,
        });
        if let Some(arg) = &self.arg {
            v["arg"] = arg.clone().into();
        }
        v
    }

    pub(super) fn detail(&self) -> String {
        format!(
            "limit `{}`{} of hop {} would be exceeded: max {}, used {}",
            self.kind,
            self.arg
                .as_ref()
                .map(|a| format!(" on `{a}`"))
                .unwrap_or_default(),
            self.hop,
            self.max,
            self.used
        )
    }
}

/// Where [`Pipeline::budget_view_from`] reads the counters a call would be charged against.
///
/// [`Pipeline::budget_view_from`]: super::Pipeline::budget_view_from
#[derive(Debug, Clone, Copy)]
pub enum CounterSource<'a> {
    /// The lease store: what the live pipeline reads ([`Pipeline::budget_view`]).
    ///
    /// [`Pipeline::budget_view`]: super::Pipeline::budget_view
    Store,
    /// A run-limit situation the caller states (the admin dry run's `budget` block). The
    /// store is never read, and nothing here can write to it.
    Stated(&'a StatedBudget),
}

/// The most entries [`StatedBudget::limits`] may hold.
pub const MAX_STATED_LIMITS: usize = 64;

/// A run-limit situation stated instead of read from the lease store, for the admin dry run
/// (`POST /admin/policies/evaluate` with `budget`). The figures are a test case's `budget`
/// (`limited`, `calls_remaining`, `amount_remaining`, `destination_new`); `limits` pins the
/// counter of single limits; `usage` is the run's usage of the tool (`context.usage`).
///
/// [`counters`](Self::counters) turns this into what the store would hold for each limit of
/// the chain that matches the call, so [`Pipeline::budget_view_from`] runs the same limit check
/// (and `budget_exhausted`) as the live pipeline.
///
/// [`Pipeline::budget_view_from`]: super::Pipeline::budget_view_from
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatedBudget {
    /// `context.budget.limited` when no limit of the chain matches the call (default `true`).
    pub limited: Option<bool>,
    /// What every matching `calls` limit has left before the call: its counter is `max -
    /// calls_remaining` (0 when that is negative). Unset: nothing used.
    pub calls_remaining: Option<u64>,
    /// The same for `sum` limits.
    pub amount_remaining: Option<u64>,
    /// `false`: the call's value was already counted by every matching `calls_per` limit (once)
    /// and `distinct` limit. Unset or `true`: the value is new.
    pub destination_new: Option<bool>,
    /// Counters of single limits, over the figures above.
    pub limits: Vec<StatedLimit>,
    /// The run's usage of the tool, for its run-usage counters.
    pub usage: UsageContext,
}

/// One entry of [`StatedBudget::limits`]: the counter of the limit of `kind` (on `arg`) in hop
/// `hop`, the shape of the `limit` member of a `budget_exhausted` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatedLimit {
    /// Position of the hop whose limit it is (0 is the root).
    pub hop: usize,
    /// Which kind of limit the counter belongs to.
    pub kind: LimitKind,
    /// The counted argument, as [`Charge::arg`] names it; `None` for `calls`.
    pub arg: Option<String>,
    /// When set, the limit's `max` must be this.
    pub max: Option<u64>,
    /// What the counter holds before the call: calls or the summed amount, for `calls_per`
    /// the calls with the call's value, for `distinct` how many values the limit has seen.
    pub used: u64,
}

impl StatedLimit {
    fn matches(&self, c: &Charge) -> bool {
        !c.usage
            && self.hop == c.hop
            && self.kind == c.kind
            && self.arg == c.arg
            && self.max.is_none_or(|m| m == c.max)
    }
}

impl StatedBudget {
    /// What the store would hold for each of `charges`, in the shape of `read_counters`: per
    /// charge its counter, and for a `distinct` limit also its count of values.
    pub fn counters(&self, charges: &[Charge]) -> (Vec<u64>, Vec<u64>) {
        let seen = u64::from(self.destination_new == Some(false));
        let spent = |max: u64, left: Option<u64>| left.map_or(0, |l| max.saturating_sub(l));
        let figure = |n: i64| u64::try_from(n).unwrap_or(0);
        charges
            .iter()
            .map(|c| {
                if c.usage {
                    let u = match c.kind {
                        LimitKind::Calls => figure(self.usage.calls),
                        LimitKind::Sum => figure(self.usage.amount),
                        LimitKind::CallsPer | LimitKind::Distinct => {
                            u64::from(self.usage.destination_seen)
                        }
                    };
                    return (u, 0);
                }
                let pinned = self.limits.iter().find(|l| l.matches(c)).map(|l| l.used);
                match c.kind {
                    LimitKind::Calls => (pinned.unwrap_or(spent(c.max, self.calls_remaining)), 0),
                    LimitKind::Sum => (pinned.unwrap_or(spent(c.max, self.amount_remaining)), 0),
                    LimitKind::CallsPer => (pinned.unwrap_or(seen), 0),
                    LimitKind::Distinct => (seen, pinned.unwrap_or(0).max(seen)),
                }
            })
            .unzip()
    }

    /// The first entry of [`limits`](Self::limits) that names no limit among `charges`, as a
    /// diagnostic: a stated counter the call would not read is a mistake in the request.
    pub fn unmatched(&self, charges: &[Charge]) -> Option<String> {
        self.limits.iter().enumerate().find_map(|(i, l)| {
            (!charges.iter().any(|c| l.matches(c))).then(|| {
                format!(
                    "`limits[{i}]` (hop {}, `{}`{}{}) names no limit of the chain that matches \
                     the call",
                    l.hop,
                    l.kind,
                    l.arg
                        .as_ref()
                        .map(|a| format!(" on `{a}`"))
                        .unwrap_or_default(),
                    l.max.map(|m| format!(", max {m}")).unwrap_or_default(),
                )
            })
        })
    }

    /// `context.budget` for a call no limit of the chain matches: the stated figures as given,
    /// as `attenuo policy test` sets them (members left out are those of an unlimited call;
    /// `limited` defaults to `true`). There is no limit, so nothing is refused.
    pub fn unlimited_context(&self) -> BudgetContext {
        let d = BudgetContext::default();
        let long = |n: Option<u64>, d: i64| n.map_or(d, |n| i64::try_from(n).unwrap_or(i64::MAX));
        BudgetContext {
            limited: self.limited.unwrap_or(true),
            calls_remaining: long(self.calls_remaining, d.calls_remaining),
            amount_remaining: long(self.amount_remaining, d.amount_remaining),
            destination_new: self.destination_new.unwrap_or(d.destination_new),
            refusal: None,
        }
    }
}

/// `context.budget` as JSON: `{limited, calls_remaining, amount_remaining, destination_new}`.
/// What the AuthZEN response and the admin dry run report.
pub fn budget_json(b: &BudgetContext) -> Value {
    serde_json::json!({
        "limited": b.limited,
        "calls_remaining": b.calls_remaining,
        "amount_remaining": b.amount_remaining,
        "destination_new": b.destination_new,
    })
}

/// Read what the counters of `charges` hold, in one read: per charge, its counter, and for a
/// `distinct` charge also how many values its limit has seen (0 for any other charge). A
/// `distinct` charge's own counter says whether its value was seen (1) or not (0).
pub(super) fn read_counters(
    leases: &dyn RunLimits,
    charges: &[Charge],
) -> Result<(Vec<u64>, Vec<u64>), attenuo_audit::AuditError> {
    let distinct: Vec<usize> = (0..charges.len())
        .filter(|&i| charges[i].kind == LimitKind::Distinct && !charges[i].usage)
        .collect();
    if distinct.is_empty() {
        let used = leases.budget_used(charges)?;
        let counts = vec![0; used.len()];
        return Ok((used, counts));
    }
    let mut probes = charges.to_vec();
    probes.extend(distinct.iter().map(|&i| {
        let c = &charges[i];
        Charge::probe(c.lease.clone(), c.cap, c.kind, c.arg.clone(), c.max)
    }));
    let mut used = leases.budget_used(&probes)?;
    let tail = used.split_off(charges.len());
    let mut counts = vec![0; charges.len()];
    for (&i, count) in distinct.iter().zip(tail) {
        counts[i] = count;
    }
    Ok((used, counts))
}

/// One `distinct` charge in [`Pipeline::budget_view`]: the limit's count of values before it
/// (with the values new earlier in the same call) and what it adds, 1 for a new value and 0
/// for one the limit has seen (`seen > 0`).
///
/// [`Pipeline::budget_view`]: super::Pipeline::budget_view
pub(super) fn distinct_step(
    new_values: &mut Vec<((usize, usize), u64)>,
    c: &Charge,
    seen: u64,
    count: u64,
) -> (u64, u64) {
    let key = (c.hop, c.cap);
    let earlier = new_values
        .iter()
        .find(|(k, _)| *k == key)
        .map_or(0, |(_, n)| *n);
    if seen > 0 {
        return (count.saturating_add(earlier), 0);
    }
    match new_values.iter_mut().find(|(k, _)| *k == key) {
        Some((_, n)) => *n += 1,
        None => new_values.push((key, 1)),
    }
    (count.saturating_add(earlier), 1)
}
