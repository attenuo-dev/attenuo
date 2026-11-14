//! Implication with what it reads from each constraint computed once (SR-123).
//!
//! [`ArgConstraint::implies`] between two `one_of` lists compared every value of one with
//! every value of the other through [`crate::jcs::value_eq`], and attenuation did that for
//! every pair of a requested and a parent capability, up to three times per pair. Here each
//! constraint is wrapped in a [`Prepared`] that computes, on first use and once, what
//! implication reads from it:
//!
//! - the canonical key ([`crate::jcs::value_key`]) of an `equals` value, and the set of keys
//!   of a `one_of`: two values are [`value_eq`](crate::jcs::value_eq) exactly when their keys
//!   are equal, so "is every child value in the parent's list" is one set lookup per child
//!   value;
//! - for a `one_of` on the child side, what every value has in common, so that its
//!   implication of a `prefix`, `path_prefix` or `range` costs the size of the parent's
//!   constraint, not the length of the list: the longest common prefix of the values when they
//!   are all strings, the longest common run of segments when they are all plain paths, and
//!   the smallest and largest integer when they are all integers a range can judge.
//!
//! Each summary gives exactly the answer of the per-value test it replaces; the reasoning is
//! at each one, and `tests` compares every answer with the pairwise implementation kept
//! there, on generated constraints.
//!
//! A [`PreparedSet`] holds the parent capabilities of one attenuation or coverage check, so
//! that a parent's lists are hashed once, however many requested capabilities are compared
//! with it.

use std::cell::OnceCell;
use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashSet};
use std::hash::{BuildHasher, BuildHasherDefault, Hash, Hasher};
use std::sync::OnceLock;

use serde_json::Value;

use super::{
    exact_long, parse_path, path_within, pattern_covers, ArgConstraint, Capability, PathSegments,
};
use crate::jcs::value_key;

/// A value's canonical key ([`value_key`]) with its hash, taken once with one keyed hasher
/// for the process, so that keys of different constraints compare by hash first and a set
/// lookup does not hash the key again.
struct Key {
    hash: u64,
    bytes: Vec<u8>,
}

impl Key {
    fn of(v: &Value) -> Self {
        #[cfg(test)]
        count::bump(&count::KEYS);
        static STATE: OnceLock<RandomState> = OnceLock::new();
        let bytes = value_key(v);
        Self {
            hash: STATE.get_or_init(RandomState::new).hash_one(&bytes),
            bytes,
        }
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.bytes == other.bytes
    }
}

impl Eq for Key {}

impl Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

/// Passes a [`Key`]'s hash through: it is already a keyed hash of the bytes.
#[derive(Default)]
struct PassThrough(u64);

impl Hasher for PassThrough {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        // Only `write_u64` is called, by `Key::hash`; fold anything else in all the same.
        for &b in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(b);
        }
    }
    fn write_u64(&mut self, n: u64) {
        self.0 = n;
    }
}

/// The canonical keys of a `one_of`'s values, each once.
type KeySet = HashSet<Key, BuildHasherDefault<PassThrough>>;

/// Is `k` in `set`? One lookup, counted in tests.
fn holds(set: &KeySet, k: &Key) -> bool {
    #[cfg(test)]
    count::bump(&count::LOOKUPS);
    set.contains(k)
}

/// Operation counts, per thread, for the tests that bound the work of an attenuation without
/// timing it.
#[cfg(test)]
pub(super) mod count {
    use std::cell::Cell;
    use std::thread::LocalKey;

    thread_local! {
        /// Canonical keys written ([`super::Key::of`]).
        pub(crate) static KEYS: Cell<u64> = const { Cell::new(0) };
        /// Set lookups ([`super::holds`]).
        pub(crate) static LOOKUPS: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn bump(c: &'static LocalKey<Cell<u64>>) {
        c.with(|c| c.set(c.get() + 1));
    }

    /// Run `f` and return what it did: (keys written, lookups).
    pub(crate) fn of<R>(f: impl FnOnce() -> R) -> (R, u64, u64) {
        let read = |c: &'static LocalKey<Cell<u64>>| c.with(Cell::get);
        let (k, l) = (read(&KEYS), read(&LOOKUPS));
        let r = f();
        (r, read(&KEYS) - k, read(&LOOKUPS) - l)
    }
}

/// What every value of a `one_of` that is all plain paths has in common
/// ([`Prepared::paths`]).
struct PathSummary<'c> {
    /// Whether the values are absolute; `None` when some are and some are not.
    absolute: Option<bool>,
    /// The longest run of leading segments every value has.
    common: Vec<&'c str>,
    /// The fewest segments of a value without a trailing `/`; `None` when every value has one.
    fewest_without_slash: Option<usize>,
}

/// A constraint, with what implication reads from it computed on first use.
pub(super) struct Prepared<'c> {
    c: &'c ArgConstraint,
    empty: OnceCell<bool>,
    /// `equals`: the value's key.
    key: OnceCell<Key>,
    /// `path_prefix`, and `equals` of a string: the string read as a path, `None` when it is
    /// not a plain path.
    path: OnceCell<Option<PathSegments<'c>>>,
    /// `one_of`: the values' keys.
    keys: OnceCell<KeySet>,
    /// `one_of`: the longest common prefix of the values when every value is a string.
    strings: OnceCell<Option<&'c [u8]>>,
    /// `one_of`: [`PathSummary`] when every value is a plain path.
    paths: OnceCell<Option<PathSummary<'c>>>,
    /// `one_of`: the smallest and largest value when every value is an integer that a range
    /// judges by itself ([`exact_long`]).
    longs: OnceCell<Option<(i64, i64)>>,
}

impl<'c> Prepared<'c> {
    pub(super) fn new(c: &'c ArgConstraint) -> Self {
        Self {
            c,
            empty: OnceCell::new(),
            key: OnceCell::new(),
            path: OnceCell::new(),
            keys: OnceCell::new(),
            strings: OnceCell::new(),
            paths: OnceCell::new(),
            longs: OnceCell::new(),
        }
    }

    fn is_empty(&self) -> bool {
        *self.empty.get_or_init(|| self.c.is_empty())
    }

    fn key(&self, v: &Value) -> &Key {
        self.key.get_or_init(|| Key::of(v))
    }

    fn path(&self, s: &'c str) -> Option<&PathSegments<'c>> {
        self.path.get_or_init(|| parse_path(s).ok()).as_ref()
    }

    fn keys(&self, vs: &[Value]) -> &KeySet {
        self.keys.get_or_init(|| vs.iter().map(Key::of).collect())
    }

    /// Every value is a string starting with `p` exactly when every value is a string and `p`
    /// is a prefix of the bytes they all start with (`str::starts_with` compares bytes).
    fn strings(&self, vs: &'c [Value]) -> Option<&'c [u8]> {
        *self.strings.get_or_init(|| {
            let mut common: Option<&'c [u8]> = None;
            for v in vs {
                let s = v.as_str()?.as_bytes();
                common = Some(match common {
                    None => s,
                    Some(c) => &c[..c.iter().zip(s).take_while(|(a, b)| a == b).count()],
                });
            }
            common
        })
    }

    fn paths(&self, vs: &'c [Value]) -> Option<&PathSummary<'c>> {
        self.paths
            .get_or_init(|| {
                let mut out: Option<PathSummary<'c>> = None;
                for v in vs {
                    let p = parse_path(v.as_str()?).ok()?;
                    let without = (!p.dir).then_some(p.segments.len());
                    out = Some(match out {
                        None => PathSummary {
                            absolute: Some(p.absolute),
                            common: p.segments,
                            fewest_without_slash: without,
                        },
                        Some(mut s) => {
                            if s.absolute != Some(p.absolute) {
                                s.absolute = None;
                            }
                            let keep = s
                                .common
                                .iter()
                                .zip(&p.segments)
                                .take_while(|(a, b)| a == b)
                                .count();
                            s.common.truncate(keep);
                            s.fewest_without_slash = match (s.fewest_without_slash, without) {
                                (Some(a), Some(b)) => Some(a.min(b)),
                                (a, b) => a.or(b),
                            };
                            s
                        }
                    });
                }
                out
            })
            .as_ref()
    }

    fn longs(&self, vs: &[Value]) -> Option<(i64, i64)> {
        *self.longs.get_or_init(|| {
            let mut out: Option<(i64, i64)> = None;
            for v in vs {
                let n = exact_long(v)?;
                out = Some(out.map_or((n, n), |(lo, hi)| (lo.min(n), hi.max(n))));
            }
            out
        })
    }

    /// [`ArgConstraint::implies`]: does every value satisfying this constraint satisfy
    /// `other`? The same answer as the pairwise definition kept in `tests`, arm by arm.
    pub(super) fn implies(&self, other: &Prepared<'_>) -> bool {
        if self.is_empty() {
            return true;
        }
        match (self.c, other.c) {
            // Keys are equal exactly when the values are `value_eq`.
            (ArgConstraint::Equals(a), ArgConstraint::Equals(b)) => self.key(a) == other.key(b),
            (ArgConstraint::Equals(a), ArgConstraint::OneOf(bs)) => {
                holds(other.keys(bs), self.key(a))
            }
            // Not empty, so at least one value: all equal `b` when its only key is `b`'s.
            (ArgConstraint::OneOf(as_), ArgConstraint::Equals(b)) => {
                let keys = self.keys(as_);
                keys.len() == 1 && holds(keys, other.key(b))
            }
            (ArgConstraint::OneOf(as_), ArgConstraint::OneOf(bs)) => {
                let (mine, theirs) = (self.keys(as_), other.keys(bs));
                mine.len() <= theirs.len() && mine.iter().all(|k| holds(theirs, k))
            }
            (ArgConstraint::OneOf(as_), ArgConstraint::Prefix(p)) => self
                .strings(as_)
                .is_some_and(|common| common.starts_with(p.as_bytes())),
            // `path_within(base, v)` for every `v`: the same kind of path as each, `base`'s
            // segments leading each (so leading their longest common run), and when `base`
            // ends in `/`, every value without a trailing `/` longer than `base`. A base that
            // is not a plain path admits nothing, and the list is not empty.
            (ArgConstraint::OneOf(as_), ArgConstraint::PathPrefix(base)) => {
                let (Some(base), Some(s)) = (other.path(base), self.paths(as_)) else {
                    return false;
                };
                s.absolute == Some(base.absolute)
                    && s.common.starts_with(&base.segments)
                    && (!base.dir
                        || s.fewest_without_slash
                            .is_none_or(|n| n > base.segments.len()))
            }
            // `range_admits_all_equal` for every value: each an integer [`exact_long`] reads,
            // and each within the bounds, so the smallest and the largest are.
            (ArgConstraint::OneOf(as_), ArgConstraint::Range { .. }) => {
                match (self.longs(as_), other.c.bounds()) {
                    (Some((lo, hi)), Some((min, max))) => min <= lo && hi <= max,
                    _ => false,
                }
            }
            // `path_str_within(base, s)`, with each side read as a path once.
            (ArgConstraint::Equals(a), ArgConstraint::PathPrefix(base)) => {
                match (a.as_str().and_then(|s| self.path(s)), other.path(base)) {
                    (Some(v), Some(b)) => path_within(b, v),
                    _ => false,
                }
            }
            (ArgConstraint::PathPrefix(q), ArgConstraint::PathPrefix(base)) => {
                match (self.path(q), other.path(base)) {
                    (Some(v), Some(b)) => path_within(b, v),
                    _ => false,
                }
            }
            (ArgConstraint::Range { .. }, ArgConstraint::OneOf(bs)) => match self.c.bounds() {
                Some((lo, hi)) if lo == hi => holds(other.keys(bs), &Key::of(&lo.into())),
                _ => false,
            },
            // The rest compare at most one value with one constraint, at the cost of the two
            // constraints' own sizes.
            _ => self.c.implies_direct(other.c),
        }
    }
}

/// A capability with its constraints [`Prepared`].
pub(super) struct PreparedCap<'c> {
    pub(super) cap: &'c Capability,
    constraints: BTreeMap<&'c str, Prepared<'c>>,
}

impl<'c> PreparedCap<'c> {
    pub(super) fn new(cap: &'c Capability) -> Self {
        Self {
            cap,
            constraints: cap
                .constraints
                .iter()
                .map(|(k, c)| (k.as_str(), Prepared::new(c)))
                .collect(),
        }
    }

    /// [`Capability::covers_calls`] of `self` (the parent) over `child`.
    pub(super) fn covers_calls(&self, child: &PreparedCap<'_>) -> bool {
        pattern_covers(&self.cap.server, &child.cap.server)
            && pattern_covers(&self.cap.tool, &child.cap.tool)
            && self.constraints.iter().all(|(arg, parent_c)| {
                child
                    .constraints
                    .get(arg)
                    .is_some_and(|child_c| child_c.implies(parent_c))
            })
    }

    /// [`Capability::covers`] of `self` (the parent) over `child`.
    pub(super) fn covers(&self, child: &PreparedCap<'_>) -> bool {
        self.covers_calls(child) && child.cap.limits.narrows(&self.cap.limits)
    }
}

/// The capabilities of a parent set, [`Prepared`] for one attenuation or coverage check.
pub(super) struct PreparedSet<'c>(pub(super) Vec<PreparedCap<'c>>);

impl<'c> PreparedSet<'c> {
    pub(super) fn new(caps: impl IntoIterator<Item = &'c Capability>) -> Self {
        Self(caps.into_iter().map(PreparedCap::new).collect())
    }
}

#[cfg(test)]
mod tests;
