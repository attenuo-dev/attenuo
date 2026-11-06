//! Bounding repeated audit records of one condition.
//!
//! Two kinds of `deny` record the proxy writes can repeat without end while nothing changes:
//! the `stream.end` of `GET` listen streams cut for one chain and reason ([`crate::guard`]),
//! and the lease refusal of an undecided request (`initialize`, `tools/list`, a notification,
//! `GET`, `DELETE`) from a client that keeps retrying on a revoked, expired or unknown lease
//! ([`crate::proxy`]). Each is bounded by a [`RecordWindow`]: the first record per
//! (delegation chain digest, fixed tool name, reason) is written, and later ones within the
//! window are counted through [`crate::Authorizer::observe_record_suppressed`] instead. The
//! refusal itself is never relaxed: a suppressed refusal is still a `401`, a suppressed stream
//! end still ends its stream.
//!
//! Tool-call decisions and decided requests (`attenuo/token.exchange`, `attenuo/lease.renew`)
//! are never bounded: each is its own decision, recorded each time.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::jsonrpc::PASSTHROUGH_METHODS;

/// Default of [`crate::ProxyConfig::record_window_max_keys`] (`[proxy] record_window_max_keys`):
/// how many (chain, tool, reason) windows a [`RecordWindow`] keeps at once. When it is full of
/// windows that are all still open, a further record is admitted rather than suppressed: the
/// bound may fail open (more records), never closed (fewer).
pub const DEFAULT_RECORD_WINDOW_MAX_KEYS: usize = 10_000;

/// Default of [`crate::ProxyConfig::record_window`] (`[proxy] record_window_seconds`): how
/// long, after a record of one bounded kind, further occurrences of the same delegation chain,
/// tool name and reason are counted instead of recorded. It bounds both kinds, the
/// `stream.end` records of `GET` listen streams ([`crate::guard`]) and the lease refusals of
/// undecided requests. A minute keeps the record of when the condition began (the client
/// first met the refusal, or its streams first ended), and one more a minute while it lasts,
/// without one record per retry or per stream: a client holding several listen streams (or
/// several sessions) of one token sees them all end at the same expiry or revocation. The
/// suppressed occurrences are in the metric `audit_records_suppressed_total` and the proxy
/// log.
pub const DEFAULT_RECORD_WINDOW: Duration = Duration::from_secs(60);

/// The tool names a lease refusal of a request with no allowlisted method is recorded under:
/// a `POST` whose first refused message is a notification or a client reply, a `GET` and a
/// `DELETE`. With [`PASSTHROUGH_METHODS`] they are every tool name a lease-refusal record can
/// carry ([`is_lease_refusal_tool`]).
pub const LEASE_REFUSAL_HTTP_TOOLS: [&str; 3] = ["http.POST", "http.GET", "http.DELETE"];

/// Is `tool` a name the proxy records a lease refusal of an undecided request under? A fixed
/// set, so a metric labelled by it stays bounded.
pub fn is_lease_refusal_tool(tool: &str) -> bool {
    PASSTHROUGH_METHODS.contains(&tool) || LEASE_REFUSAL_HTTP_TOOLS.contains(&tool)
}

/// The bound on one kind of repeated record: at most one per delegation chain (its digest, so
/// a parent and a sub-agent of one run each keep their own), fixed tool name and reason every
/// `window`. The first record of a window is written, never a later one, so the log shows when
/// the condition began; the window opens at that record and a new record is written for the
/// first occurrence after it closes. Shared by every request (or stream) of one proxy router.
#[derive(Debug)]
pub struct RecordWindow {
    window: Duration,
    max_keys: usize,
    slots: Mutex<HashMap<(String, &'static str, String), Slot>>,
}

#[derive(Debug)]
struct Slot {
    opened: Instant,
    /// The record that opened the window, once written.
    first: Option<Uuid>,
    suppressed: u64,
    /// The admitted record was not written ([`RecordWindow::forget`]): the window is closed,
    /// and the next occurrence is recorded.
    closed: bool,
}

impl Slot {
    fn open_at(&self, now: Instant, window: Duration) -> bool {
        !self.closed && now.saturating_duration_since(self.opened) < window
    }
}

/// What [`RecordWindow::admit`] says about one occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Write the record. `suppressed_before` occurrences of the same chain, tool and reason
    /// were not recorded in the window that just closed.
    Record {
        /// Occurrences left unrecorded in the window that just closed.
        suppressed_before: u64,
    },
    /// Do not write it: the window's first record (`None` while it is still being written)
    /// stands for this occurrence too.
    Suppress {
        /// The id of the window's first record, once it is written.
        first: Option<Uuid>,
    },
}

impl RecordWindow {
    /// A bound of `window` holding at most [`DEFAULT_RECORD_WINDOW_MAX_KEYS`] windows.
    pub fn new(window: Duration) -> Self {
        Self::with_max_keys(window, DEFAULT_RECORD_WINDOW_MAX_KEYS)
    }

    /// A bound of `window` holding at most `max_keys` windows (at least one).
    pub fn with_max_keys(window: Duration, max_keys: usize) -> Self {
        Self {
            window,
            max_keys: max_keys.max(1),
            slots: Mutex::new(HashMap::new()),
        }
    }

    /// The window's length.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// The most windows held at once.
    pub fn max_keys(&self) -> usize {
        self.max_keys
    }

    /// Should a record of `tool` for `chain_key` and `reason` at `now` be written? An
    /// [`Admission::Record`] opens a window, so of several concurrent occurrences exactly one
    /// is told to record; tell [`RecordWindow::recorded`] the record's id once written. A
    /// poisoned lock, or a table full of open windows, admits the record (fails open). If the
    /// record could not be written, tell [`RecordWindow::forget`] instead, so the window does
    /// not stand on a record that is not in the log (SR-81).
    pub fn admit(
        &self,
        chain_key: &str,
        tool: &'static str,
        reason: &str,
        now: Instant,
    ) -> Admission {
        let fresh = || Slot {
            opened: now,
            first: None,
            suppressed: 0,
            closed: false,
        };
        let Ok(mut slots) = self.slots.lock() else {
            return Admission::Record {
                suppressed_before: 0,
            };
        };
        let key = (chain_key.to_owned(), tool, reason.to_owned());
        if let Some(slot) = slots.get_mut(&key) {
            if slot.open_at(now, self.window) {
                slot.suppressed += 1;
                return Admission::Suppress { first: slot.first };
            }
            let suppressed_before = slot.suppressed;
            *slot = fresh();
            return Admission::Record { suppressed_before };
        }
        if slots.len() >= self.max_keys {
            let window = self.window;
            slots.retain(|_, s| s.open_at(now, window));
            if slots.len() >= self.max_keys {
                return Admission::Record {
                    suppressed_before: 0,
                };
            }
        }
        slots.insert(key, fresh());
        Admission::Record {
            suppressed_before: 0,
        }
    }

    /// The record admitted for `chain_key`, `tool` and `reason` was written as `id`: later
    /// suppressed occurrences of its window name it.
    pub fn recorded(&self, chain_key: &str, tool: &'static str, reason: &str, id: Uuid) {
        if let Ok(mut slots) = self.slots.lock() {
            if let Some(slot) = slots.get_mut(&(chain_key.to_owned(), tool, reason.to_owned())) {
                slot.first.get_or_insert(id);
            }
        }
    }

    /// The record admitted for `chain_key`, `tool` and `reason` was not written (the audit
    /// append failed): close its window, so the next occurrence is admitted and recorded
    /// rather than suppressed behind a record that is not in the log (SR-81). Occurrences
    /// suppressed meanwhile are carried into that record's `suppressed_before`. A window whose
    /// record was already written is left alone, and so is a poisoned table.
    pub fn forget(&self, chain_key: &str, tool: &'static str, reason: &str) {
        if let Ok(mut slots) = self.slots.lock() {
            if let Some(slot) = slots.get_mut(&(chain_key.to_owned(), tool, reason.to_owned())) {
                if slot.first.is_none() {
                    slot.closed = true;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: Duration = Duration::from_secs(1);
    const T: &str = "stream.end";

    #[test]
    fn the_first_record_of_a_window_is_written_and_repeats_are_counted() {
        let r = RecordWindow::with_max_keys(60 * SEC, 16);
        let t0 = Instant::now();
        let record = |n| Admission::Record {
            suppressed_before: n,
        };
        assert_eq!(r.admit("c1", T, "token_expired", t0), record(0));
        // Still being written: nothing to name yet.
        assert_eq!(
            r.admit("c1", T, "token_expired", t0 + SEC),
            Admission::Suppress { first: None }
        );
        let id = Uuid::new_v4();
        r.recorded("c1", T, "token_expired", id);
        assert_eq!(
            r.admit("c1", T, "token_expired", t0 + 59 * SEC),
            Admission::Suppress { first: Some(id) }
        );
        // The window runs from the first record, not from the last repeat: a client that keeps
        // trying gets a new record every window, and the old one is never replaced.
        assert_eq!(r.admit("c1", T, "token_expired", t0 + 60 * SEC), record(2));
        r.recorded("c1", T, "token_expired", Uuid::new_v4());
        assert!(matches!(
            r.admit("c1", T, "token_expired", t0 + 61 * SEC),
            Admission::Suppress { first: Some(other) } if other != id
        ));
        assert_eq!(r.admit("c1", T, "token_expired", t0 + 200 * SEC), record(1));
    }

    #[test]
    fn chains_tools_and_reasons_have_their_own_windows() {
        let r = RecordWindow::with_max_keys(60 * SEC, 16);
        let t0 = Instant::now();
        let first = Admission::Record {
            suppressed_before: 0,
        };
        assert_eq!(r.admit("c1", "initialize", "lease_revoked", t0), first);
        assert_eq!(r.admit("c2", "initialize", "lease_revoked", t0), first);
        assert_eq!(r.admit("c1", "initialize", "lease_expired", t0), first);
        assert_eq!(r.admit("c1", "http.GET", "lease_revoked", t0), first);
        assert!(matches!(
            r.admit("c2", "initialize", "lease_revoked", t0),
            Admission::Suppress { .. }
        ));
        // `recorded` for one tool names nothing under another.
        let id = Uuid::new_v4();
        r.recorded("c1", "http.GET", "lease_revoked", id);
        assert_eq!(
            r.admit("c1", "initialize", "lease_revoked", t0 + SEC),
            Admission::Suppress { first: None }
        );
        assert_eq!(
            r.admit("c1", "http.GET", "lease_revoked", t0 + SEC),
            Admission::Suppress { first: Some(id) }
        );
    }

    #[test]
    fn a_full_table_records_rather_than_suppresses() {
        let r = RecordWindow::with_max_keys(60 * SEC, 2);
        let t0 = Instant::now();
        let first = Admission::Record {
            suppressed_before: 0,
        };
        assert_eq!(r.admit("c1", T, "token_expired", t0), first);
        assert_eq!(r.admit("c2", T, "token_expired", t0), first);
        // Both windows open: c3 is recorded every time, never suppressed.
        assert_eq!(r.admit("c3", T, "token_expired", t0), first);
        assert_eq!(r.admit("c3", T, "token_expired", t0 + SEC), first);
        // Once the old windows close they make room, and c3 is bounded again.
        assert_eq!(r.admit("c3", T, "token_expired", t0 + 61 * SEC), first);
        assert!(matches!(
            r.admit("c3", T, "token_expired", t0 + 62 * SEC),
            Admission::Suppress { .. }
        ));
    }

    #[test]
    fn a_short_window_closes_sooner() {
        // `[proxy] record_window_seconds = 1`: a repeat 1.1 s after the first record opens a
        // new window, where the default minute would still suppress it.
        let r = RecordWindow::with_max_keys(SEC, DEFAULT_RECORD_WINDOW_MAX_KEYS);
        assert_eq!(r.window(), SEC);
        let t0 = Instant::now();
        let first = Admission::Record {
            suppressed_before: 0,
        };
        assert_eq!(r.admit("c1", "initialize", "lease_revoked", t0), first);
        assert!(matches!(
            r.admit("c1", "initialize", "lease_revoked", t0 + SEC / 2),
            Admission::Suppress { .. }
        ));
        assert_eq!(
            r.admit(
                "c1",
                "initialize",
                "lease_revoked",
                t0 + Duration::from_millis(1_100)
            ),
            Admission::Record {
                suppressed_before: 1
            }
        );
        let default = RecordWindow::new(DEFAULT_RECORD_WINDOW);
        assert_eq!(default.window(), 60 * SEC);
        assert_eq!(default.max_keys(), DEFAULT_RECORD_WINDOW_MAX_KEYS);
        assert_eq!(
            default.admit("c1", "initialize", "lease_revoked", t0),
            first
        );
        assert!(matches!(
            default.admit(
                "c1",
                "initialize",
                "lease_revoked",
                t0 + Duration::from_millis(1_100)
            ),
            Admission::Suppress { .. }
        ));
    }

    #[test]
    fn a_full_table_at_the_smallest_configurable_size_records() {
        // `[proxy] record_window_max_keys = 100`, the smallest accepted.
        let r = RecordWindow::with_max_keys(60 * SEC, 100);
        assert_eq!(r.max_keys(), 100);
        let t0 = Instant::now();
        let first = Admission::Record {
            suppressed_before: 0,
        };
        for i in 0..100 {
            assert_eq!(r.admit(&format!("c{i}"), T, "lease_revoked", t0), first);
        }
        // The table is full of open windows: the 101st chain is recorded every time.
        for s in 0..3 {
            assert_eq!(r.admit("c100", T, "lease_revoked", t0 + s * SEC), first);
        }
        // A chain already in the table is still bounded.
        assert!(matches!(
            r.admit("c0", T, "lease_revoked", t0 + SEC),
            Admission::Suppress { .. }
        ));
    }

    #[test]
    fn a_poisoned_table_records() {
        let r = std::sync::Arc::new(RecordWindow::with_max_keys(60 * SEC, 16));
        let t0 = Instant::now();
        assert!(matches!(
            r.admit("c1", T, "lease_revoked", t0),
            Admission::Record { .. }
        ));
        let poison = r.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poison.slots.lock().unwrap();
            panic!("poison the table");
        })
        .join();
        assert!(r.slots.is_poisoned());
        assert_eq!(
            r.admit("c1", T, "lease_revoked", t0 + SEC),
            Admission::Record {
                suppressed_before: 0
            }
        );
        // `recorded` on a poisoned table is a no-op, not a panic.
        r.recorded("c1", T, "lease_revoked", Uuid::new_v4());
    }

    #[test]
    fn a_forgotten_record_does_not_open_a_window_sr81() {
        let r = RecordWindow::with_max_keys(60 * SEC, 16);
        let t0 = Instant::now();
        let first = Admission::Record {
            suppressed_before: 0,
        };
        assert_eq!(r.admit("c1", T, "lease_revoked", t0), first);
        // A concurrent occurrence while the append runs is suppressed, as before.
        assert_eq!(
            r.admit("c1", T, "lease_revoked", t0 + SEC),
            Admission::Suppress { first: None }
        );
        // The append failed: the next occurrence records, and counts the one suppressed.
        r.forget("c1", T, "lease_revoked");
        assert_eq!(
            r.admit("c1", T, "lease_revoked", t0 + 2 * SEC),
            Admission::Record {
                suppressed_before: 1
            }
        );
        // Failed again, and again: nothing is suppressed behind a record that is not there.
        r.forget("c1", T, "lease_revoked");
        assert_eq!(r.admit("c1", T, "lease_revoked", t0 + 3 * SEC), first);
        // This one is written: the window is open from here as usual.
        let id = Uuid::new_v4();
        r.recorded("c1", T, "lease_revoked", id);
        assert_eq!(
            r.admit("c1", T, "lease_revoked", t0 + 4 * SEC),
            Admission::Suppress { first: Some(id) }
        );
        // `forget` after a written record changes nothing.
        r.forget("c1", T, "lease_revoked");
        assert_eq!(
            r.admit("c1", T, "lease_revoked", t0 + 5 * SEC),
            Admission::Suppress { first: Some(id) }
        );
        // A closed window makes room in a full table.
        let full = RecordWindow::with_max_keys(60 * SEC, 1);
        assert_eq!(full.admit("c1", T, "lease_revoked", t0), first);
        full.forget("c1", T, "lease_revoked");
        assert_eq!(full.admit("c2", T, "lease_revoked", t0 + SEC), first);
        assert!(matches!(
            full.admit("c2", T, "lease_revoked", t0 + 2 * SEC),
            Admission::Suppress { .. }
        ));
    }

    #[test]
    fn lease_refusal_tools_are_a_fixed_set() {
        for t in PASSTHROUGH_METHODS.iter().chain(&LEASE_REFUSAL_HTTP_TOOLS) {
            assert!(is_lease_refusal_tool(t), "{t}");
        }
        for t in [
            "tools/call",
            "stream.end",
            "lease.renew",
            "token.exchange",
            "",
        ] {
            assert!(!is_lease_refusal_tool(t), "{t}");
        }
    }
}
