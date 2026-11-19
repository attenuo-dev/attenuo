//! The policy engine in force, swapped whole on a reload (audit findings A-7 and A-8).

use std::sync::{Arc, PoisonError, RwLock};

use attenuo_policy::PolicyEngine;

/// The policy engine in force. A decision takes one [`snapshot`](Self::snapshot) and runs
/// every stage on it; a reload compiles a new engine with no lock held
/// ([`PolicyEngine::with_policies_reloaded`]) and [`swap`](Self::swap)s it in. The lock is
/// held only to copy or replace the pointer, so a reload never holds up a decision for
/// longer than that, and a decision never sees two policy sets.
///
/// The lock guards a single `Arc` that is replaced in one store, so a panic cannot leave it
/// half-written: poisoning is ignored.
#[derive(Debug)]
pub struct SharedPolicy {
    current: RwLock<Arc<PolicyEngine>>,
}

impl SharedPolicy {
    /// Put `engine` in force.
    pub fn new(engine: PolicyEngine) -> Self {
        Self {
            current: RwLock::new(Arc::new(engine)),
        }
    }

    /// The engine in force now. It stays usable, unchanged, after a later swap.
    pub fn snapshot(&self) -> Arc<PolicyEngine> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Put `engine` in force and return the engine it replaces. Decisions that took a
    /// snapshot before finish on the old engine.
    pub fn swap(&self, engine: Arc<PolicyEngine>) -> Arc<PolicyEngine> {
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        std::mem::replace(&mut *current, engine)
    }
}

impl From<PolicyEngine> for SharedPolicy {
    fn from(engine: PolicyEngine) -> Self {
        Self::new(engine)
    }
}
