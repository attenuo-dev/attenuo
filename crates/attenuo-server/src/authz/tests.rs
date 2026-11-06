use super::authorizer::VerifiedTokens;
use super::*;
use attenuo_audit::LeaseStore;
use attenuo_audit::{MemoryAudit, MemoryLeaseStore};
use attenuo_core::{AgentId, Capability, CapabilitySet, LeaseId, OriginatingUser};
use attenuo_core::{Decision, DelegationChain, ToolCall};
use attenuo_policy::PolicyEngineBuilder;
use attenuo_proxy::Authorizer;
use serde_json::json;
use std::sync::{Arc, RwLock};
use time::Duration;
use time::OffsetDateTime;

fn setup() -> (
    Pipeline,
    Arc<MemoryLeaseStore>,
    Arc<MemoryAudit>,
    DelegationChain,
) {
    let now = OffsetDateTime::now_utc();
    let engine = PolicyEngineBuilder::new()
        .with_policies_str("permit(principal, action, resource);")
        .with_unknown_tools(attenuo_policy::UnknownTools::Allow)
        .build()
        .unwrap();
    let leases = Arc::new(MemoryLeaseStore::new());
    let audit = Arc::new(MemoryAudit::new());
    let chain = DelegationChain::root(
        OriginatingUser {
            subject: "alice".into(),
            issuer: "idp".into(),
            authenticated_at: now,
            attributes: Default::default(),
        },
        AgentId::new("planner"),
        CapabilitySet::from_iter([Capability::new("github", "read_*")]),
        now,
        Duration::hours(1),
        LeaseId::new("l1"),
    )
    .unwrap();
    let p = Pipeline::new(Arc::new(RwLock::new(engine)), leases.clone(), audit.clone());
    (p, leases, audit, chain)
}

#[test]
fn unknown_lease_denies_and_is_audited() {
    let (p, _leases, audit, chain) = setup();
    let call = ToolCall::new("github", "read_file", json!({}));
    let d = p.decide(&chain, &call, OffsetDateTime::now_utc());
    assert_eq!(d.reason, REASON_LEASE_UNKNOWN);
    assert_eq!(audit.len().unwrap(), 1);
    assert_eq!(audit.snapshot().unwrap()[0].record.id, d.decision_id);
}

#[test]
fn proxy_rejections_are_audited_as_denials() {
    let (p, _leases, audit, chain) = setup();
    let call = ToolCall::new("github", "http.GET", json!({})).with_session("abc123");
    let id = p.record_rejection(
        &chain,
        &call,
        attenuo_proxy::REASON_SESSION_MISMATCH,
        OffsetDateTime::now_utc(),
    );
    let entries = audit.snapshot().unwrap();
    assert_eq!(entries.len(), 1);
    let r = &entries[0].record;
    assert_eq!(r.id, id);
    assert_eq!(r.decision, Decision::Deny);
    assert_eq!(r.reason, "session_mismatch");
    assert_eq!(r.tool, "http.GET");
    assert_eq!(r.session_id.as_deref(), Some("abc123"));
    // Every decision record is counted in decisions_total, recorded refusals too.
    assert!(p
        .metrics()
        .render()
        .contains("attenuo_decisions_total{decision=\"deny\",reason=\"session_mismatch\"} 1\n"));
}

#[test]
fn live_lease_reaches_policy_and_revocation_denies() {
    let (p, leases, _audit, chain) = setup();
    let now = OffsetDateTime::now_utc();
    leases
        .register(&LeaseId::new("l1"), None, now + Duration::hours(1))
        .unwrap();
    let ok = ToolCall::new("github", "read_file", json!({}));
    assert!(p.decide(&chain, &ok, now).is_allow());
    let no = ToolCall::new("github", "delete_repo", json!({}));
    assert_eq!(
        p.decide(&chain, &no, now).reason,
        attenuo_policy::REASON_CAPABILITY_DENIED
    );
    leases.revoke(&LeaseId::new("l1"), "test", now).unwrap();
    assert_eq!(p.decide(&chain, &ok, now).reason, REASON_LEASE_REVOKED);
}

#[test]
fn any_hop_with_an_unrenewed_lease_denies() {
    let (p, leases, _audit, root) = setup();
    let now = OffsetDateTime::now_utc();
    let child = root
        .extend(
            AgentId::new("coder"),
            CapabilitySet::from_iter([Capability::new("github", "read_file")]),
            now,
            Duration::minutes(30),
            LeaseId::new("l2"),
            8,
        )
        .unwrap();
    leases
        .register(&LeaseId::new("l1"), None, now + Duration::minutes(5))
        .unwrap();
    leases
        .register(
            &LeaseId::new("l2"),
            Some(&LeaseId::new("l1")),
            now + Duration::minutes(5),
        )
        .unwrap();
    let call = ToolCall::new("github", "read_file", json!({}));
    assert!(p.decide(&child, &call, now).is_allow());

    // Parent lapses, child's own lease is fine: deny.
    leases
        .renew(&LeaseId::new("l1"), now - Duration::seconds(1), now)
        .unwrap();
    assert_eq!(p.decide(&child, &call, now).reason, REASON_LEASE_EXPIRED);
    // Renewing the parent restores access; the audit trail has all three decisions.
    leases
        .renew(&LeaseId::new("l1"), now + Duration::minutes(5), now)
        .unwrap();
    assert!(p.decide(&child, &call, now).is_allow());
}

#[test]
fn expired_lease_denies() {
    let (p, leases, _audit, chain) = setup();
    let now = OffsetDateTime::now_utc();
    leases
        .register(&LeaseId::new("l1"), None, now - Duration::seconds(1))
        .unwrap();
    let call = ToolCall::new("github", "read_file", json!({}));
    assert_eq!(p.decide(&chain, &call, now).reason, REASON_LEASE_EXPIRED);
}

#[test]
fn decide_returns_the_record_it_appended() {
    let (p, leases, audit, chain) = setup();
    let now = OffsetDateTime::now_utc();
    leases
        .register(&LeaseId::new("l1"), None, now + Duration::hours(1))
        .unwrap();
    let d = p.decide(
        &chain,
        &ToolCall::new("github", "read_file", json!({})),
        now,
    );
    let stored = &audit.snapshot().unwrap()[0];
    assert_eq!(d.audit_seq, Some(stored.seq));
    assert_eq!(d.decision_id, stored.record.id);
    assert_eq!(d.reason, stored.record.reason);
    assert_eq!(d.policy_ids, stored.record.policy_ids);
}

#[tokio::test]
async fn verified_tokens_are_cached_but_expiry_is_rechecked() {
    let (p, _leases, _audit, _chain) = setup();
    let issuer = attenuo_token::Issuer::generate(attenuo_token::IssuerConfig {
        issuer: "https://attenuo.test".into(),
        audience: "attenuo".into(),
        max_depth: 4,
        default_ttl: Duration::minutes(5),
    });
    let now = OffsetDateTime::now_utc();
    let user = OriginatingUser {
        subject: "alice".into(),
        issuer: "idp".into(),
        authenticated_at: now,
        attributes: Default::default(),
    };
    let caps = CapabilitySet::from_iter([Capability::new("github", "read_*")]);
    let issued = issuer
        .issue_root(user, AgentId::new("planner"), caps, None, now)
        .unwrap();
    let auth = ServerAuthorizer::new(issuer.verifier(), Arc::new(p));

    let first = auth.authenticate(&issued.token, now).await.unwrap();
    assert_eq!(first, issued.chain);
    assert_eq!(auth.verified.chains.lock().unwrap().len(), 1);
    let again = auth.authenticate(&issued.token, now).await.unwrap();
    assert_eq!(again, issued.chain, "served from the cache");

    // Past the token's expiry the cached chain is refused, like a fresh verification.
    let later = issued.expires_at + Duration::seconds(1);
    assert!(auth.authenticate(&issued.token, later).await.is_err());

    // A token that differs in one byte is verified on its own (and fails); failures are
    // not cached.
    let mut forged = issued.token.clone().into_bytes();
    let last = forged.len() - 2;
    forged[last] = if forged[last] == b'A' { b'B' } else { b'A' };
    let forged = String::from_utf8(forged).unwrap();
    assert!(auth.authenticate(&forged, now).await.is_err());
    assert_eq!(auth.verified.chains.lock().unwrap().len(), 1);
}

/// SR-46: a token over `VERIFIED_TOKEN_MAX_BYTES` is verified, but not kept.
#[tokio::test]
async fn oversized_tokens_are_verified_but_not_cached() {
    let (p, _leases, _audit, _chain) = setup();
    let issuer = attenuo_token::Issuer::generate(attenuo_token::IssuerConfig {
        issuer: "https://attenuo.test".into(),
        audience: "attenuo".into(),
        max_depth: 4,
        default_ttl: Duration::minutes(5),
    });
    let now = OffsetDateTime::now_utc();
    let user = OriginatingUser {
        subject: "alice".into(),
        issuer: "idp".into(),
        authenticated_at: now,
        attributes: Default::default(),
    };
    // A long constraint list, as a child narrowing `github:read_*` could carry.
    let values: Vec<serde_json::Value> = (0..2000)
        .map(|i| json!(format!("acme/repo-{i:05}")))
        .collect();
    let cap = Capability::new("github", "read_*")
        .with_constraint("repo", attenuo_core::ArgConstraint::OneOf(values));
    let issued = issuer
        .issue_root(
            user,
            AgentId::new("planner"),
            CapabilitySet::from_iter([cap]),
            None,
            now,
        )
        .unwrap();
    assert!(issued.token.len() > VERIFIED_TOKEN_MAX_BYTES);
    let auth = ServerAuthorizer::new(issuer.verifier(), Arc::new(p));
    assert_eq!(
        auth.authenticate(&issued.token, now).await.unwrap(),
        issued.chain
    );
    assert_eq!(auth.verified.chains.lock().unwrap().len(), 0);
}

#[test]
fn verified_token_cache_stays_bounded() {
    let issuer = attenuo_token::Issuer::generate(attenuo_token::IssuerConfig {
        issuer: "https://attenuo.test".into(),
        audience: "attenuo".into(),
        max_depth: 4,
        default_ttl: Duration::minutes(5),
    });
    let now = OffsetDateTime::now_utc();
    let user = OriginatingUser {
        subject: "alice".into(),
        issuer: "idp".into(),
        authenticated_at: now,
        attributes: Default::default(),
    };
    let caps = CapabilitySet::from_iter([Capability::new("github", "read_*")]);
    let issued = issuer
        .issue_root(user, AgentId::new("planner"), caps, None, now)
        .unwrap();
    let v = issuer.verifier().verify(&issued.token, now).unwrap();
    let cache = VerifiedTokens::new(3);
    for i in 0..10 {
        cache.insert(VerifiedTokens::key(&format!("t{i}")), &v, now);
        assert!(cache.chains.lock().unwrap().len() <= 3);
    }
    // Expired entries go first when the cache is full.
    let expired_at = v.chain.hops[0].expires_at;
    let cache = VerifiedTokens::new(2);
    cache.insert(VerifiedTokens::key("a"), &v, now);
    cache.insert(VerifiedTokens::key("b"), &v, now);
    cache.insert(VerifiedTokens::key("c"), &v, expired_at);
    let chains = cache.chains.lock().unwrap();
    assert_eq!(chains.len(), 1);
    assert!(chains.contains_key(&VerifiedTokens::key("c")));
}
