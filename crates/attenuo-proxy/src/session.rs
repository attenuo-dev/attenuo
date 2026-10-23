//! `Mcp-Session-Id` binding (SR-11).
//!
//! The upstream assigns a session id in a response header (normally to `initialize`). The proxy
//! records which principal the id was assigned to: the originating user (`subject`, `issuer`)
//! and the chain's root lease, so every agent of one delegation run shares the session and
//! nobody else can use it. A later request carrying the id must come from the same principal:
//!
//! | Session id in the request | Result |
//! |---|---|
//! | none | forwarded; a session id in the response is bound to the caller |
//! | bound to the caller | forwarded; the binding's idle timer restarts |
//! | bound to someone else | 403, JSON-RPC `-32003` with reason `session_mismatch`, audited |
//! | unknown (never assigned through this proxy, or idle past the TTL) | 404, the MCP signal to start a new session |
//!
//! A response that names a session id already bound to another principal has the header
//! removed. A successful `DELETE` ends the binding. The registry is in memory and bounded
//! (SR-36): expired bindings (idle past the TTL) are dropped as new ones arrive, oldest first and
//! without a scan, and when every slot holds a live binding a new one is refused, so the
//! response that would have created it gets `503` with reason `session_registry_full`. A live
//! binding of another user is never evicted to make room. Each principal (the chain's root lease:
//! one user's root grant, shared by every agent it delegates to) may hold at most
//! `max_per_principal` live bindings (SR-49); one more gets `429` with reason
//! `too_many_sessions`, so one user cannot fill the registry and lock everyone else out. Session
//! ids are secrets that grant access to a session, so logs only carry [`session_tag`], a short
//! hash prefix.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use attenuo_core::{DelegationChain, LeaseId};
use sha2::{Digest, Sha256};

/// Default idle lifetime of a binding.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(3600);
/// Default maximum number of bindings held.
pub const DEFAULT_MAX_SESSIONS: usize = 100_000;
/// Default maximum number of live bindings one principal (root lease) holds (SR-49).
pub const DEFAULT_MAX_SESSIONS_PER_PRINCIPAL: usize = 64;

/// Who a session belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOwner {
    pub subject: String,
    pub issuer: String,
    pub root_lease: LeaseId,
}

impl SessionOwner {
    /// The owner a chain represents; `None` for a chain with no hops.
    pub fn of(chain: &DelegationChain) -> Option<Self> {
        let root = chain.hops.first()?;
        Some(Self {
            subject: chain.originating_user.subject.clone(),
            issuer: chain.originating_user.issuer.clone(),
            root_lease: root.lease.clone(),
        })
    }
}

/// Outcome of [`SessionRegistry::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCheck {
    /// Bound to this owner.
    Owned,
    /// Bound to a different owner.
    Mismatch,
    /// Not bound (or expired).
    Unknown,
}

struct Entry {
    owner: SessionOwner,
    last_seen: Instant,
    /// This entry's key in [`Inner::by_age`].
    seq: u64,
}

/// Outcome of [`SessionRegistry::bind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindOutcome {
    /// Bound (or already bound) to this owner; the idle timer restarted.
    Bound,
    /// Live and bound to someone else; nothing changed.
    Taken,
    /// The registry holds `max` live bindings; nothing changed. No live binding is ever
    /// evicted to make room (SR-36).
    Full,
    /// This owner's root lease already holds `max_per_principal` live bindings; nothing
    /// changed (SR-49).
    PrincipalFull,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<String, Entry>,
    /// `(last_seen, seq)` to session id, oldest first, so expired entries are found without a
    /// scan.
    by_age: BTreeMap<(Instant, u64), String>,
    /// Live bindings per root lease (SR-49). A lease with none has no key.
    per_principal: HashMap<LeaseId, usize>,
    next_seq: u64,
}

impl Inner {
    fn insert(&mut self, session_id: &str, owner: SessionOwner, now: Instant) {
        self.remove(session_id);
        let seq = self.next_seq;
        self.next_seq += 1;
        self.by_age.insert((now, seq), session_id.to_owned());
        *self
            .per_principal
            .entry(owner.root_lease.clone())
            .or_default() += 1;
        self.entries.insert(
            session_id.to_owned(),
            Entry {
                owner,
                last_seen: now,
                seq,
            },
        );
    }

    fn touch(&mut self, session_id: &str, now: Instant) {
        if let Some(e) = self.entries.get_mut(session_id) {
            let id = self
                .by_age
                .remove(&(e.last_seen, e.seq))
                .unwrap_or_else(|| session_id.to_owned());
            e.last_seen = now;
            self.by_age.insert((now, e.seq), id);
        }
    }

    fn remove(&mut self, session_id: &str) {
        if let Some(e) = self.entries.remove(session_id) {
            self.by_age.remove(&(e.last_seen, e.seq));
            self.uncount(&e.owner);
        }
    }

    fn uncount(&mut self, owner: &SessionOwner) {
        if let Some(n) = self.per_principal.get_mut(&owner.root_lease) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.per_principal.remove(&owner.root_lease);
            }
        }
    }

    fn held_by(&self, owner: &SessionOwner) -> usize {
        self.per_principal
            .get(&owner.root_lease)
            .copied()
            .unwrap_or(0)
    }

    /// Drop every entry idle for `ttl` or longer, oldest first; stops at the first live one.
    fn purge_expired(&mut self, now: Instant, ttl: Duration) {
        while let Some(((seen, _), _)) = self.by_age.first_key_value() {
            if now.saturating_duration_since(*seen) < ttl {
                break;
            }
            if let Some((_, id)) = self.by_age.pop_first() {
                if let Some(e) = self.entries.remove(&id) {
                    self.uncount(&e.owner);
                }
            }
        }
    }
}

/// The in-memory session id to owner map.
pub struct SessionRegistry {
    inner: Mutex<Inner>,
    ttl: Duration,
    max: usize,
    max_per_principal: usize,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new(DEFAULT_SESSION_TTL, DEFAULT_MAX_SESSIONS)
    }
}

impl SessionRegistry {
    pub fn new(ttl: Duration, max: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            ttl,
            max: max.max(1),
            max_per_principal: DEFAULT_MAX_SESSIONS_PER_PRINCIPAL,
        }
    }

    /// Set the most live bindings one principal (root lease) may hold (SR-49); at least one.
    pub fn with_max_per_principal(mut self, max: usize) -> Self {
        self.max_per_principal = max.max(1);
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while holding the lock cannot leave a half-written entry; keep going.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn expired(&self, e: &Entry, now: Instant) -> bool {
        now.saturating_duration_since(e.last_seen) >= self.ttl
    }

    /// Is `session_id` bound to `owner`? Refreshes the idle timer when it is.
    pub fn check(&self, session_id: &str, owner: &SessionOwner, now: Instant) -> SessionCheck {
        let mut inner = self.lock();
        let (expired, owned) = match inner.entries.get(session_id) {
            None => return SessionCheck::Unknown,
            Some(e) => (self.expired(e, now), &e.owner == owner),
        };
        if expired {
            inner.remove(session_id);
            SessionCheck::Unknown
        } else if owned {
            inner.touch(session_id, now);
            SessionCheck::Owned
        } else {
            SessionCheck::Mismatch
        }
    }

    /// Bind `session_id` to `owner`, unless it is live and bound to someone else
    /// ([`BindOutcome::Taken`]), the owner's root lease already holds `max_per_principal` live
    /// bindings ([`BindOutcome::PrincipalFull`], SR-49), or the registry is full of live
    /// bindings ([`BindOutcome::Full`]). Expired bindings are dropped first, oldest first, in
    /// time proportional to how many expired, so only live bindings count against either
    /// limit; a live binding is never evicted.
    pub fn bind(&self, session_id: &str, owner: &SessionOwner, now: Instant) -> BindOutcome {
        let mut inner = self.lock();
        inner.purge_expired(now, self.ttl);
        if let Some(e) = inner.entries.get(session_id) {
            if &e.owner != owner {
                return BindOutcome::Taken;
            }
            inner.touch(session_id, now);
            return BindOutcome::Bound;
        }
        if inner.held_by(owner) >= self.max_per_principal {
            return BindOutcome::PrincipalFull;
        }
        if inner.entries.len() >= self.max {
            return BindOutcome::Full;
        }
        inner.insert(session_id, owner.clone(), now);
        BindOutcome::Bound
    }

    /// Forget a session (after a successful `DELETE`).
    pub fn remove(&self, session_id: &str) {
        self.lock().remove(session_id);
    }

    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A short, stable tag for a session id that is safe to log: the first 12 hex characters of
/// its SHA-256.
pub fn session_tag(session_id: &str) -> String {
    let mut s = hex::encode(Sha256::digest(session_id.as_bytes()));
    s.truncate(12);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(subject: &str, lease: &str) -> SessionOwner {
        SessionOwner {
            subject: subject.into(),
            issuer: "idp".into(),
            root_lease: LeaseId::new(lease),
        }
    }

    #[test]
    fn bind_check_mismatch_expiry() {
        let reg = SessionRegistry::new(Duration::from_secs(10), 10);
        let t = Instant::now();
        let (alice, bob) = (owner("alice", "l1"), owner("bob", "l2"));
        assert_eq!(reg.check("s1", &alice, t), SessionCheck::Unknown);
        assert_eq!(reg.bind("s1", &alice, t), BindOutcome::Bound);
        assert_eq!(reg.check("s1", &alice, t), SessionCheck::Owned);
        assert_eq!(reg.check("s1", &bob, t), SessionCheck::Mismatch);
        // The same user under another root lease (another run) is someone else too.
        assert_eq!(
            reg.check("s1", &owner("alice", "l9"), t),
            SessionCheck::Mismatch
        );
        assert_eq!(
            reg.bind("s1", &bob, t),
            BindOutcome::Taken,
            "cannot steal a live binding"
        );
        // Use keeps it alive; idleness past the TTL expires it.
        let t2 = t + Duration::from_secs(8);
        assert_eq!(reg.check("s1", &alice, t2), SessionCheck::Owned);
        let t3 = t2 + Duration::from_secs(10);
        assert_eq!(reg.check("s1", &alice, t3), SessionCheck::Unknown);
        assert_eq!(reg.bind("s1", &bob, t3), BindOutcome::Bound);
        reg.remove("s1");
        assert!(reg.is_empty());
    }

    /// SR-36: a full registry refuses new bindings; it never evicts a live one.
    #[test]
    fn a_full_registry_refuses_instead_of_evicting_live_bindings() {
        let reg = SessionRegistry::new(Duration::from_secs(10), 3);
        let t = Instant::now();
        let (a, b) = (owner("a", "l"), owner("b", "l2"));
        for (i, s) in ["s1", "s2", "s3"].iter().enumerate() {
            assert_eq!(
                reg.bind(s, &a, t + Duration::from_millis(i as u64)),
                BindOutcome::Bound
            );
        }
        // Another user flooding the registry gets nothing, and a's sessions survive.
        assert_eq!(reg.bind("s4", &b, t), BindOutcome::Full);
        assert_eq!(reg.len(), 3);
        for s in ["s1", "s2", "s3"] {
            assert_eq!(reg.check(s, &a, t), SessionCheck::Owned, "{s}");
        }
        // Re-binding an id already held is not a new slot.
        assert_eq!(reg.bind("s1", &a, t), BindOutcome::Bound);
        // Once idle past the TTL, entries are reclaimed, oldest first.
        let later = t + Duration::from_secs(10) + Duration::from_millis(1);
        assert_eq!(
            reg.check("s3", &a, later - Duration::from_secs(1)),
            SessionCheck::Owned
        );
        assert_eq!(reg.bind("s4", &b, later), BindOutcome::Bound);
        assert_eq!(reg.len(), 2, "s1 and s2 expired, s3 was refreshed");
        assert_eq!(reg.check("s3", &a, later), SessionCheck::Owned);
        assert_eq!(reg.check("s1", &a, later), SessionCheck::Unknown);
    }

    /// SR-49: one principal (root lease) holds at most `max_per_principal` live bindings, other
    /// principals keep binding, and an expired or removed binding frees the principal's slot.
    #[test]
    fn a_principal_cannot_hold_more_than_its_share_sr49() {
        let reg = SessionRegistry::new(Duration::from_secs(10), 100).with_max_per_principal(2);
        let t = Instant::now();
        let (a, a_other_run, b) = (owner("a", "l1"), owner("a", "l3"), owner("b", "l2"));
        assert_eq!(reg.bind("s1", &a, t), BindOutcome::Bound);
        assert_eq!(
            reg.bind("s2", &a, t + Duration::from_secs(1)),
            BindOutcome::Bound
        );
        assert_eq!(reg.bind("s3", &a, t), BindOutcome::PrincipalFull);
        // Re-binding a held id is not a new slot.
        assert_eq!(reg.bind("s1", &a, t), BindOutcome::Bound);
        // Other principals, including another root grant of the same user, are unaffected.
        assert_eq!(reg.bind("b1", &b, t), BindOutcome::Bound);
        assert_eq!(reg.bind("x1", &a_other_run, t), BindOutcome::Bound);
        // A removed binding frees a slot.
        reg.remove("s2");
        assert_eq!(reg.bind("s3", &a, t), BindOutcome::Bound);
        assert_eq!(reg.bind("s4", &a, t), BindOutcome::PrincipalFull);
        // Expired bindings stop counting: s1 and s3 were last seen at t.
        let later = t + Duration::from_secs(10);
        assert_eq!(reg.bind("s4", &a, later), BindOutcome::Bound);
        assert_eq!(reg.bind("s5", &a, later), BindOutcome::Bound);
        assert_eq!(reg.bind("s6", &a, later), BindOutcome::PrincipalFull);
        let inner = reg.lock();
        let counted: usize = inner.per_principal.values().sum();
        assert_eq!(counted, inner.entries.len());
    }

    #[test]
    fn index_stays_consistent_through_touch_and_remove() {
        let reg = SessionRegistry::new(Duration::from_secs(5), 100);
        let t = Instant::now();
        let a = owner("a", "l");
        for i in 0..50u64 {
            reg.bind(&format!("s{i}"), &a, t + Duration::from_millis(i));
        }
        for i in (0..50u64).step_by(2) {
            assert_eq!(
                reg.check(&format!("s{i}"), &a, t + Duration::from_secs(3)),
                SessionCheck::Owned
            );
        }
        reg.remove("s1");
        // Odd ones (never refreshed) expire; even ones (refreshed at +3 s) do not.
        reg.bind("new", &a, t + Duration::from_secs(6));
        assert_eq!(reg.len(), 26);
        let inner = reg.lock();
        assert_eq!(inner.by_age.len(), inner.entries.len());
    }

    #[test]
    fn tags_are_short_and_do_not_contain_the_id() {
        let tag = session_tag("very-secret-session-id");
        assert_eq!(tag.len(), 12);
        assert!(!tag.contains("secret"));
        assert_eq!(tag, session_tag("very-secret-session-id"));
    }
}
