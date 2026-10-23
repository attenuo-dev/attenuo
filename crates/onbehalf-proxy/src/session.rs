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
//! removed. A successful `DELETE` ends the binding. The registry is in memory and bounded;
//! when full, expired entries are dropped first and then the least recently used one. Session
//! ids are secrets that grant access to a session, so logs only carry [`session_tag`], a short
//! hash prefix.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use onbehalf_core::{DelegationChain, LeaseId};
use sha2::{Digest, Sha256};

/// Default idle lifetime of a binding.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(3600);
/// Default maximum number of bindings held.
pub const DEFAULT_MAX_SESSIONS: usize = 100_000;

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
}

/// The in-memory session id to owner map.
pub struct SessionRegistry {
    entries: Mutex<HashMap<String, Entry>>,
    ttl: Duration,
    max: usize,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new(DEFAULT_SESSION_TTL, DEFAULT_MAX_SESSIONS)
    }
}

impl SessionRegistry {
    pub fn new(ttl: Duration, max: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max: max.max(1),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        // A panic while holding the lock cannot leave a half-written entry; keep going.
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Is `session_id` bound to `owner`? Refreshes the idle timer when it is.
    pub fn check(&self, session_id: &str, owner: &SessionOwner, now: Instant) -> SessionCheck {
        let mut entries = self.lock();
        match entries.get_mut(session_id) {
            Some(e) if now.duration_since(e.last_seen) >= self.ttl => {
                entries.remove(session_id);
                SessionCheck::Unknown
            }
            Some(e) if &e.owner == owner => {
                e.last_seen = now;
                SessionCheck::Owned
            }
            Some(_) => SessionCheck::Mismatch,
            None => SessionCheck::Unknown,
        }
    }

    /// Bind `session_id` to `owner` unless it is bound to someone else. Returns `false` (and
    /// changes nothing) in that case.
    pub fn bind(&self, session_id: &str, owner: &SessionOwner, now: Instant) -> bool {
        let mut entries = self.lock();
        if let Some(e) = entries.get_mut(session_id) {
            let live = now.duration_since(e.last_seen) < self.ttl;
            if live && &e.owner != owner {
                return false;
            }
            e.owner = owner.clone();
            e.last_seen = now;
            return true;
        }
        if entries.len() >= self.max {
            let ttl = self.ttl;
            entries.retain(|_, e| now.duration_since(e.last_seen) < ttl);
            if entries.len() >= self.max {
                if let Some(oldest) = entries
                    .iter()
                    .min_by_key(|(_, e)| e.last_seen)
                    .map(|(k, _)| k.clone())
                {
                    entries.remove(&oldest);
                }
            }
        }
        entries.insert(
            session_id.to_owned(),
            Entry {
                owner: owner.clone(),
                last_seen: now,
            },
        );
        true
    }

    /// Forget a session (after a successful `DELETE`).
    pub fn remove(&self, session_id: &str) {
        self.lock().remove(session_id);
    }

    pub fn len(&self) -> usize {
        self.lock().len()
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
        assert!(reg.bind("s1", &alice, t));
        assert_eq!(reg.check("s1", &alice, t), SessionCheck::Owned);
        assert_eq!(reg.check("s1", &bob, t), SessionCheck::Mismatch);
        // The same user under another root lease (another run) is someone else too.
        assert_eq!(
            reg.check("s1", &owner("alice", "l9"), t),
            SessionCheck::Mismatch
        );
        assert!(!reg.bind("s1", &bob, t), "cannot steal a live binding");
        // Use keeps it alive; idleness past the TTL expires it.
        let t2 = t + Duration::from_secs(8);
        assert_eq!(reg.check("s1", &alice, t2), SessionCheck::Owned);
        let t3 = t2 + Duration::from_secs(10);
        assert_eq!(reg.check("s1", &alice, t3), SessionCheck::Unknown);
        assert!(reg.bind("s1", &bob, t3));
        reg.remove("s1");
        assert!(reg.is_empty());
    }

    #[test]
    fn registry_is_bounded() {
        let reg = SessionRegistry::new(Duration::from_secs(10), 3);
        let t = Instant::now();
        let a = owner("a", "l");
        for (i, s) in ["s1", "s2", "s3", "s4"].iter().enumerate() {
            assert!(reg.bind(s, &a, t + Duration::from_millis(i as u64)));
        }
        assert_eq!(reg.len(), 3);
        // The least recently used one went.
        assert_eq!(reg.check("s1", &a, t), SessionCheck::Unknown);
        assert_eq!(reg.check("s4", &a, t), SessionCheck::Owned);
    }

    #[test]
    fn tags_are_short_and_do_not_contain_the_id() {
        let tag = session_tag("very-secret-session-id");
        assert_eq!(tag.len(), 12);
        assert!(!tag.contains("secret"));
        assert_eq!(tag, session_tag("very-secret-session-id"));
    }
}
