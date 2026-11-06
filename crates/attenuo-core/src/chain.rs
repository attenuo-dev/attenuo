//! Delegation chains: the originating user and every agent hop, with attenuation enforced.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use crate::capability::CapabilitySet;
use crate::digest::sha256_json;
use crate::error::ChainError;

/// Default upper bound on hops; deeper chains are almost always a bug or an attack.
pub const DEFAULT_MAX_DEPTH: usize = 8;

/// Identifier of an agent (a workload identity, e.g. a SPIFFE ID or client_id).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentId(pub String);

impl AgentId {
    /// Wrap an agent identifier.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Identifier of a revocation lease. Every hop holds one; revoking it denies the hop and
/// everything delegated from it on the next call.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LeaseId(pub String);

impl LeaseId {
    /// Wrap a lease identifier.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

/// The human (or service account) on whose behalf the whole chain acts.
///
/// This block is produced once, by the component that verified the user's identity token,
/// and is carried unchanged through every hop. Downstream components verify its signature
/// (see `attenuo-token`) rather than trusting the hop that forwarded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginatingUser {
    /// Stable subject identifier from the identity provider.
    pub subject: String,
    /// Issuer of the identity assertion the subject was taken from.
    pub issuer: String,
    /// When the user authenticated.
    #[serde(with = "time::serde::rfc3339")]
    pub authenticated_at: OffsetDateTime,
    /// Additional verified attributes policies may use (roles, MFA level, tenant).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, Value>,
}

/// One delegation step: an agent holding a capability set for a bounded time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hop {
    /// The agent acting at this hop.
    pub agent: AgentId,
    /// What the agent may call; covered by the parent hop's set.
    pub capabilities: CapabilitySet,
    /// When the hop was issued.
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
    /// When the hop expires; no later than the parent hop's expiry.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// The revocation lease of this hop.
    pub lease: LeaseId,
}

/// The full chain: who it is for, and who has acted on their behalf so far (root first).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationChain {
    /// The user the whole chain acts for.
    pub originating_user: OriginatingUser,
    /// Every hop, root first.
    pub hops: Vec<Hop>,
}

impl DelegationChain {
    /// Start a chain: the first agent receives `capabilities` directly from the user's grant.
    ///
    /// # Errors
    ///
    /// [`ChainError::EmptySubject`], [`ChainError::EmptyAgentId`] or [`ChainError::EmptyLeaseId`]
    /// for an empty subject, agent or lease id; [`ChainError::AttenuationViolated`] (with
    /// [`AttenuationError::Empty`](crate::AttenuationError::Empty)) for an empty capability set;
    /// [`ChainError::InvalidName`] or [`ChainError::InvalidLimit`] for a capability that fails
    /// [`CapabilitySet::validate`] or [`CapabilitySet::validate_limits`]; and
    /// [`ChainError::TtlOutOfRange`] when `now + ttl` is not a representable time.
    pub fn root(
        originating_user: OriginatingUser,
        agent: AgentId,
        capabilities: CapabilitySet,
        now: OffsetDateTime,
        ttl: Duration,
        lease: LeaseId,
    ) -> Result<Self, ChainError> {
        if originating_user.subject.is_empty() {
            return Err(ChainError::EmptySubject);
        }
        if capabilities.is_empty() {
            return Err(ChainError::AttenuationViolated {
                index: 0,
                parent: 0,
                source: crate::error::AttenuationError::Empty,
            });
        }
        if agent.0.is_empty() {
            return Err(ChainError::EmptyAgentId { index: 0 });
        }
        if lease.0.is_empty() {
            return Err(ChainError::EmptyLeaseId { index: 0 });
        }
        capabilities
            .validate()
            .map_err(|source| ChainError::InvalidName { index: 0, source })?;
        capabilities
            .validate_limits()
            .map_err(|source| ChainError::InvalidLimit { index: 0, source })?;
        Ok(Self {
            originating_user,
            hops: vec![Hop {
                agent,
                capabilities,
                issued_at: now,
                expires_at: now.checked_add(ttl).ok_or(ChainError::TtlOutOfRange)?,
                lease,
            }],
        })
    }

    /// Delegate from the last hop to `agent`, requesting `requested` capabilities.
    ///
    /// Fails if `requested` is not covered by the last hop's capabilities (attenuation), if the
    /// chain is already at `max_depth`, if `agent` already acts somewhere in the chain
    /// ([`ChainError::DuplicateAgent`]), if `agent` or `lease` is empty or `lease` is already
    /// used, or if the chain is currently invalid. The new hop's expiry is clamped to its
    /// parent's so a child can never outlive its parent.
    ///
    /// # Errors
    ///
    /// Whatever [`validate_at`](Self::validate_at) reports for the chain as it is; then, for the
    /// new hop: [`ChainError::TooDeep`], [`ChainError::EmptyAgentId`],
    /// [`ChainError::EmptyLeaseId`], [`ChainError::DuplicateAgent`],
    /// [`ChainError::DuplicateLease`], [`ChainError::InvalidName`], [`ChainError::InvalidLimit`],
    /// and [`ChainError::AttenuationViolated`] when the last hop does not cover `requested`. A
    /// `ttl` too large to add is not an error: the expiry is the parent's.
    pub fn extend(
        &self,
        agent: AgentId,
        requested: CapabilitySet,
        now: OffsetDateTime,
        ttl: Duration,
        lease: LeaseId,
        max_depth: usize,
    ) -> Result<Self, ChainError> {
        self.validate_at(now, max_depth)?;
        let parent_index = self.hops.len() - 1;
        let parent = &self.hops[parent_index];
        if self.hops.len() + 1 > max_depth {
            return Err(ChainError::TooDeep {
                depth: self.hops.len() + 1,
                max: max_depth,
            });
        }
        let index = self.hops.len();
        if agent.0.is_empty() {
            return Err(ChainError::EmptyAgentId { index });
        }
        if lease.0.is_empty() {
            return Err(ChainError::EmptyLeaseId { index });
        }
        if let Some(first) = self.hops.iter().position(|h| h.agent == agent) {
            return Err(ChainError::DuplicateAgent {
                index,
                first,
                agent: agent.0,
            });
        }
        if let Some(first) = self.hops.iter().position(|h| h.lease == lease) {
            return Err(ChainError::DuplicateLease {
                index,
                first,
                lease: lease.0,
            });
        }
        requested
            .validate()
            .map_err(|source| ChainError::InvalidName { index, source })?;
        requested
            .validate_limits()
            .map_err(|source| ChainError::InvalidLimit { index, source })?;
        let capabilities = parent
            .capabilities
            .attenuate(&requested)
            .map_err(|source| ChainError::AttenuationViolated {
                index: parent_index + 1,
                parent: parent_index,
                source,
            })?;
        // `now + ttl` panics on overflow, and `ttl` can come straight from a request body
        // (`requested_ttl_seconds`). An unrepresentable expiry is simply "later than the
        // parent's", so clamp it like any other.
        let expires_at = match now.checked_add(ttl) {
            Some(t) => std::cmp::min(t, parent.expires_at),
            None => parent.expires_at,
        };
        let mut next = self.clone();
        next.hops.push(Hop {
            agent,
            capabilities,
            issued_at: now,
            expires_at,
            lease,
        });
        Ok(next)
    }

    /// Check every structural invariant at time `now`.
    ///
    /// Call this on every chain received from the outside, after signature verification.
    ///
    /// Checked, in order: a non-empty subject; at least one hop and at most `max_depth`; then
    /// per hop: non-empty agent and lease ids, capability patterns that are valid names
    /// ([`crate::names`]), well-formed limits ([`crate::limits`]), `issued_at < expires_at`, not expired at `now`,
    /// a lease and an agent id that no earlier hop uses, and, against the parent hop,
    /// `issued_at` not before the parent's, an expiry not after the parent's, and capabilities
    /// the parent covers (limits included: each no larger than the parent's).
    ///
    /// `issued_at` is not compared with `now`: chains are validated at arbitrary times (tests,
    /// replays of the audit log), and a chain from a token was stamped by the issuer's clock.
    ///
    /// # Errors
    ///
    /// The first broken invariant from the list above, as its [`ChainError`] variant, carrying
    /// the hop's position.
    pub fn validate_at(&self, now: OffsetDateTime, max_depth: usize) -> Result<(), ChainError> {
        if self.originating_user.subject.is_empty() {
            return Err(ChainError::EmptySubject);
        }
        if self.hops.is_empty() {
            return Err(ChainError::NoHops);
        }
        if self.hops.len() > max_depth {
            return Err(ChainError::TooDeep {
                depth: self.hops.len(),
                max: max_depth,
            });
        }
        for (i, hop) in self.hops.iter().enumerate() {
            if hop.agent.0.is_empty() {
                return Err(ChainError::EmptyAgentId { index: i });
            }
            if hop.lease.0.is_empty() {
                return Err(ChainError::EmptyLeaseId { index: i });
            }
            hop.capabilities
                .validate()
                .map_err(|source| ChainError::InvalidName { index: i, source })?;
            hop.capabilities
                .validate_limits()
                .map_err(|source| ChainError::InvalidLimit { index: i, source })?;
            if hop.issued_at >= hop.expires_at {
                return Err(ChainError::IssuedAfterExpiry { index: i });
            }
            if hop.expires_at <= now {
                return Err(ChainError::HopExpired {
                    index: i,
                    expires_at: hop
                        .expires_at
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default(),
                });
            }
            let earlier = &self.hops[..i];
            if let Some(first) = earlier.iter().position(|h| h.lease == hop.lease) {
                return Err(ChainError::DuplicateLease {
                    index: i,
                    first,
                    lease: hop.lease.0.clone(),
                });
            }
            if let Some(first) = earlier.iter().position(|h| h.agent == hop.agent) {
                return Err(ChainError::DuplicateAgent {
                    index: i,
                    first,
                    agent: hop.agent.0.clone(),
                });
            }
            if i > 0 {
                let parent = &self.hops[i - 1];
                if hop.issued_at < parent.issued_at {
                    return Err(ChainError::IssuedBeforeParent {
                        index: i,
                        parent: i - 1,
                    });
                }
                if hop.expires_at > parent.expires_at {
                    return Err(ChainError::ExpiryNotMonotonic {
                        index: i,
                        parent: i - 1,
                    });
                }
                if !parent.capabilities.covers(&hop.capabilities) || hop.capabilities.is_empty() {
                    let source = parent
                        .capabilities
                        .attenuate(&hop.capabilities)
                        .err()
                        .unwrap_or(crate::error::AttenuationError::Empty);
                    return Err(ChainError::AttenuationViolated {
                        index: i,
                        parent: i - 1,
                        source,
                    });
                }
            }
        }
        Ok(())
    }

    /// Number of hops.
    pub fn depth(&self) -> usize {
        self.hops.len()
    }

    /// The agent currently acting (last hop).
    pub fn current_agent(&self) -> Option<&AgentId> {
        self.hops.last().map(|h| &h.agent)
    }

    /// Capabilities in force for the current agent (last hop).
    pub fn effective_capabilities(&self) -> Option<&CapabilitySet> {
        self.hops.last().map(|h| &h.capabilities)
    }

    /// Lease ids of every hop, root first. Revoking any of them invalidates the chain.
    pub fn leases(&self) -> Vec<&LeaseId> {
        self.hops.iter().map(|h| &h.lease).collect()
    }

    /// Stable digest of the whole chain, used to bind audit records to it.
    pub fn digest(&self) -> String {
        sha256_json(self)
    }

    /// Digest of the chain cut after hop `index` (the chain as it was when that hop was
    /// issued). `prefix_digest(depth - 1)` equals [`digest`](Self::digest). `None` when `index`
    /// is out of range.
    ///
    /// The issuer records this per lease (`LeaseStore::bind`), so a chain received without its
    /// signature can be matched hop by hop against what was actually issued.
    pub fn prefix_digest(&self, index: usize) -> Option<String> {
        if index >= self.hops.len() {
            return None;
        }
        if index + 1 == self.hops.len() {
            return Some(self.digest());
        }
        let prefix = DelegationChain {
            originating_user: self.originating_user.clone(),
            hops: self.hops[..=index].to_vec(),
        };
        Some(prefix.digest())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{ArgConstraint, Capability};
    use serde_json::json;
    use time::macros::datetime;

    fn user() -> OriginatingUser {
        OriginatingUser {
            subject: "user:mudit".into(),
            issuer: "https://idp.example".into(),
            authenticated_at: datetime!(2026-10-22 20:00 UTC),
            attributes: BTreeMap::new(),
        }
    }

    fn caps(v: Vec<Capability>) -> CapabilitySet {
        CapabilitySet::from_iter(v)
    }

    fn t0() -> OffsetDateTime {
        datetime!(2026-10-22 21:00 UTC)
    }

    #[test]
    fn root_then_extend_narrows() {
        let root = DelegationChain::root(
            user(),
            AgentId::new("agent:planner"),
            caps(vec![Capability::new("github", "*")]),
            t0(),
            Duration::hours(1),
            LeaseId::new("l1"),
        )
        .unwrap();
        let child = root
            .extend(
                AgentId::new("agent:coder"),
                caps(vec![Capability::new("github", "create_issue")
                    .with_constraint(
                        "repo",
                        ArgConstraint::Prefix("acme/".into()),
                    )]),
                t0() + Duration::minutes(1),
                Duration::hours(5),
                LeaseId::new("l2"),
                DEFAULT_MAX_DEPTH,
            )
            .unwrap();
        assert_eq!(child.depth(), 2);
        // child expiry is clamped to the parent's
        assert_eq!(child.hops[1].expires_at, root.hops[0].expires_at);
        child
            .validate_at(t0() + Duration::minutes(2), DEFAULT_MAX_DEPTH)
            .unwrap();
    }

    #[test]
    fn extend_cannot_widen() {
        let root = DelegationChain::root(
            user(),
            AgentId::new("a"),
            caps(vec![Capability::new("github", "read_*")]),
            t0(),
            Duration::hours(1),
            LeaseId::new("l1"),
        )
        .unwrap();
        let err = root
            .extend(
                AgentId::new("b"),
                caps(vec![Capability::new("github", "delete_repo")]),
                t0(),
                Duration::minutes(5),
                LeaseId::new("l2"),
                DEFAULT_MAX_DEPTH,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ChainError::AttenuationViolated {
                index: 1,
                parent: 0,
                ..
            }
        ));
    }

    #[test]
    fn tampered_chain_is_rejected_on_validate() {
        let root = DelegationChain::root(
            user(),
            AgentId::new("a"),
            caps(vec![Capability::new("github", "read_*")]),
            t0(),
            Duration::hours(1),
            LeaseId::new("l1"),
        )
        .unwrap();
        let mut child = root
            .extend(
                AgentId::new("b"),
                caps(vec![Capability::new("github", "read_file")]),
                t0(),
                Duration::minutes(5),
                LeaseId::new("l2"),
                DEFAULT_MAX_DEPTH,
            )
            .unwrap();
        // an attacker edits the last hop to add a capability
        child.hops[1]
            .capabilities
            .insert(Capability::new("github", "delete_repo"));
        assert!(matches!(
            child.validate_at(t0(), DEFAULT_MAX_DEPTH),
            Err(ChainError::AttenuationViolated { index: 1, .. })
        ));
        // or stretches the expiry past the parent
        let mut child2 = root
            .extend(
                AgentId::new("b"),
                caps(vec![Capability::new("github", "read_file")]),
                t0(),
                Duration::minutes(5),
                LeaseId::new("l2"),
                DEFAULT_MAX_DEPTH,
            )
            .unwrap();
        child2.hops[1].expires_at = t0() + Duration::hours(2);
        assert!(matches!(
            child2.validate_at(t0(), DEFAULT_MAX_DEPTH),
            Err(ChainError::ExpiryNotMonotonic {
                index: 1,
                parent: 0
            })
        ));
    }

    #[test]
    fn expiry_and_depth() {
        let root = DelegationChain::root(
            user(),
            AgentId::new("a"),
            caps(vec![Capability::new("*", "*")]),
            t0(),
            Duration::minutes(10),
            LeaseId::new("l1"),
        )
        .unwrap();
        assert!(matches!(
            root.validate_at(t0() + Duration::minutes(10), DEFAULT_MAX_DEPTH),
            Err(ChainError::HopExpired { index: 0, .. })
        ));
        let mut chain = root;
        for i in 0..7 {
            chain = chain
                .extend(
                    AgentId::new(format!("a{i}")),
                    caps(vec![Capability::new("*", "*")]),
                    t0(),
                    Duration::minutes(1),
                    LeaseId::new(format!("l-hop{i}")),
                    DEFAULT_MAX_DEPTH,
                )
                .unwrap();
        }
        assert_eq!(chain.depth(), 8);
        assert!(matches!(
            chain.extend(
                AgentId::new("overflow"),
                caps(vec![Capability::new("*", "*")]),
                t0(),
                Duration::minutes(1),
                LeaseId::new("lx"),
                DEFAULT_MAX_DEPTH,
            ),
            Err(ChainError::TooDeep { depth: 9, max: 8 })
        ));
    }

    /// SR-06: a huge TTL used to panic in `now + ttl` (reachable from `POST /token` with
    /// `requested_ttl_seconds` = u64::MAX). It must clamp on extend and fail cleanly on root.
    #[test]
    fn huge_ttl_does_not_panic() {
        let root = DelegationChain::root(
            user(),
            AgentId::new("a"),
            caps(vec![Capability::new("github", "read_*")]),
            t0(),
            Duration::hours(1),
            LeaseId::new("l1"),
        )
        .unwrap();
        for ttl in [Duration::MAX, Duration::seconds(i64::MAX)] {
            let child = root
                .extend(
                    AgentId::new("b"),
                    caps(vec![Capability::new("github", "read_file")]),
                    t0(),
                    ttl,
                    LeaseId::new("l2"),
                    DEFAULT_MAX_DEPTH,
                )
                .unwrap();
            assert_eq!(child.hops[1].expires_at, root.hops[0].expires_at);
            assert_eq!(
                DelegationChain::root(
                    user(),
                    AgentId::new("a"),
                    caps(vec![Capability::new("github", "read_*")]),
                    t0(),
                    ttl,
                    LeaseId::new("l1"),
                ),
                Err(ChainError::TtlOutOfRange)
            );
        }
    }

    fn two_hops() -> DelegationChain {
        DelegationChain::root(
            user(),
            AgentId::new("a"),
            caps(vec![Capability::new("github", "read_*")]),
            t0(),
            Duration::hours(1),
            LeaseId::new("l1"),
        )
        .unwrap()
        .extend(
            AgentId::new("b"),
            caps(vec![Capability::new("github", "read_file")]),
            t0() + Duration::minutes(1),
            Duration::minutes(30),
            LeaseId::new("l2"),
            DEFAULT_MAX_DEPTH,
        )
        .unwrap()
    }

    /// SR-16: one live lease repeated on every hop of a hand-written chain.
    #[test]
    fn duplicate_lease_is_rejected() {
        let mut c = two_hops();
        c.hops[1].lease = LeaseId::new("l1");
        assert_eq!(
            c.validate_at(t0() + Duration::minutes(2), DEFAULT_MAX_DEPTH),
            Err(ChainError::DuplicateLease {
                index: 1,
                first: 0,
                lease: "l1".into()
            })
        );
    }

    /// SR-16 / SR-10: an agent cannot appear twice, whether validated or extended.
    #[test]
    fn duplicate_agent_is_rejected_on_validate_and_extend() {
        let mut c = two_hops();
        c.hops[1].agent = AgentId::new("a");
        assert!(matches!(
            c.validate_at(t0() + Duration::minutes(2), DEFAULT_MAX_DEPTH),
            Err(ChainError::DuplicateAgent {
                index: 1,
                first: 0,
                ..
            })
        ));
        let err = two_hops()
            .extend(
                AgentId::new("a"),
                caps(vec![Capability::new("github", "read_file")]),
                t0() + Duration::minutes(2),
                Duration::minutes(5),
                LeaseId::new("l3"),
                DEFAULT_MAX_DEPTH,
            )
            .unwrap_err();
        assert_eq!(
            err,
            ChainError::DuplicateAgent {
                index: 2,
                first: 0,
                agent: "a".into()
            }
        );
        assert!(err.to_string().contains("already acts at hop 0"));
        // reusing a lease id on extend is refused too
        assert!(matches!(
            two_hops().extend(
                AgentId::new("c"),
                caps(vec![Capability::new("github", "read_file")]),
                t0() + Duration::minutes(2),
                Duration::minutes(5),
                LeaseId::new("l2"),
                DEFAULT_MAX_DEPTH,
            ),
            Err(ChainError::DuplicateLease {
                index: 2,
                first: 1,
                ..
            })
        ));
    }

    #[test]
    fn empty_ids_are_rejected() {
        let at = t0() + Duration::minutes(2);
        let mut c = two_hops();
        c.hops[1].agent = AgentId::new("");
        assert_eq!(
            c.validate_at(at, DEFAULT_MAX_DEPTH),
            Err(ChainError::EmptyAgentId { index: 1 })
        );
        let mut c = two_hops();
        c.hops[0].lease = LeaseId::new("");
        assert_eq!(
            c.validate_at(at, DEFAULT_MAX_DEPTH),
            Err(ChainError::EmptyLeaseId { index: 0 })
        );
        let root = |agent: &str, lease: &str| {
            DelegationChain::root(
                user(),
                AgentId::new(agent),
                caps(vec![Capability::new("github", "read_*")]),
                t0(),
                Duration::hours(1),
                LeaseId::new(lease),
            )
        };
        assert_eq!(root("", "l1"), Err(ChainError::EmptyAgentId { index: 0 }));
        assert_eq!(root("a", ""), Err(ChainError::EmptyLeaseId { index: 0 }));
    }

    #[test]
    fn issued_at_ordering_is_checked() {
        let at = t0() + Duration::minutes(2);
        // issued at (or after) its own expiry
        let mut c = two_hops();
        c.hops[1].issued_at = c.hops[1].expires_at;
        assert_eq!(
            c.validate_at(at, DEFAULT_MAX_DEPTH),
            Err(ChainError::IssuedAfterExpiry { index: 1 })
        );
        // issued before the parent that delegated to it
        let mut c = two_hops();
        c.hops[1].issued_at = t0() - Duration::minutes(1);
        assert_eq!(
            c.validate_at(at, DEFAULT_MAX_DEPTH),
            Err(ChainError::IssuedBeforeParent {
                index: 1,
                parent: 0
            })
        );
        two_hops().validate_at(at, DEFAULT_MAX_DEPTH).unwrap();
    }

    #[test]
    fn digest_changes_when_chain_changes() {
        let root = DelegationChain::root(
            user(),
            AgentId::new("a"),
            caps(vec![Capability::new("github", "read_*")]),
            t0(),
            Duration::hours(1),
            LeaseId::new("l1"),
        )
        .unwrap();
        let d1 = root.digest();
        let mut edited = root.clone();
        edited
            .originating_user
            .attributes
            .insert("role".into(), json!("admin"));
        assert_ne!(d1, edited.digest());
        let s = serde_json::to_string(&root).unwrap();
        let back: DelegationChain = serde_json::from_str(&s).unwrap();
        assert_eq!(back.digest(), d1);
    }

    #[test]
    fn prefix_digest_is_the_digest_at_issuance() {
        let child = two_hops();
        let root = DelegationChain {
            originating_user: child.originating_user.clone(),
            hops: child.hops[..1].to_vec(),
        };
        assert_eq!(child.prefix_digest(0), Some(root.digest()));
        assert_eq!(child.prefix_digest(1), Some(child.digest()));
        assert_eq!(child.prefix_digest(2), None);
        assert_ne!(child.prefix_digest(0), child.prefix_digest(1));
    }

    #[test]
    fn invalid_capability_names_are_rejected_sr13() {
        let now = OffsetDateTime::now_utc();
        let user = OriginatingUser {
            subject: "alice".into(),
            issuer: "https://idp".into(),
            authenticated_at: now,
            attributes: Default::default(),
        };
        let bad = CapabilitySet::from_iter([Capability::new("evil/github", "*")]);
        assert!(matches!(
            DelegationChain::root(
                user.clone(),
                AgentId::new("a"),
                bad.clone(),
                now,
                Duration::hours(1),
                LeaseId::new("l1"),
            ),
            Err(ChainError::InvalidName { index: 0, .. })
        ));
        let root = DelegationChain::root(
            user,
            AgentId::new("a"),
            CapabilitySet::from_iter([Capability::new("*", "*")]),
            now,
            Duration::hours(1),
            LeaseId::new("l1"),
        )
        .unwrap();
        // `*` covers it, but it is still not a name a call can have.
        assert!(matches!(
            root.extend(
                AgentId::new("b"),
                bad.clone(),
                now,
                Duration::hours(1),
                LeaseId::new("l2"),
                8
            ),
            Err(ChainError::InvalidName { index: 1, .. })
        ));
        // A received chain is checked too.
        let mut forged = root.clone();
        forged.hops[0].capabilities = bad;
        assert!(matches!(
            forged.validate_at(now, 8),
            Err(ChainError::InvalidName { index: 0, .. })
        ));
    }
}
