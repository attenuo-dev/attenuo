//! Cost of `Verifier::verify` on a token it has not seen: what the server's verified-token
//! cache saves on a hit and pays on a miss (the proxy's `token_verify_miss` stage).
//!
//! - `verify/{hops}`: a root token (1 hop) and a token two exchanges further down (3 hops),
//!   verified by the issuer's own verifier (one trusted key).
//! - `verify_3_keys/{hops}`: the same tokens, verified by a verifier that trusts three keys,
//!   the token's own last. The header `kid` and `ou_kid` each name one key, so this should
//!   cost what `verify` does.
//! - `chain_clone/{hops}`: `DelegationChain::clone`, which `verify` did once to return the
//!   chain beside the claims.
//! - `ou_sig_message/{hops}`: building the bytes `ou_sig` signs (RFC 8785 canonical JSON of
//!   the user block and the root hop), done once per verification.
//! - `ed25519_verify`: one bare Ed25519 verification (`ring`) of a 1 KiB message; `verify`
//!   does two, the outer JWT signature and `ou_sig`.
//!
//! ```text
//! cargo bench -p attenuo-token --bench verify
//! ```

use std::collections::BTreeMap;
use std::hint::black_box;

use attenuo_core::{AgentId, ArgConstraint, Capability, CapabilitySet, OriginatingUser};
use attenuo_token::claims::ou_sig_message;
use attenuo_token::{Issuer, IssuerConfig};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde_json::json;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

const ISS: &str = "https://attenuo.example";

fn t0() -> OffsetDateTime {
    datetime!(2026-10-24 12:00 UTC)
}

fn config() -> IssuerConfig {
    IssuerConfig {
        issuer: ISS.into(),
        audience: "mcp-proxy".into(),
        max_depth: 8,
        default_ttl: Duration::minutes(10),
    }
}

fn user() -> OriginatingUser {
    OriginatingUser {
        subject: "user:alice".into(),
        issuer: "https://idp.example".into(),
        authenticated_at: datetime!(2026-10-24 11:00 UTC),
        attributes: BTreeMap::from([("mfa".to_string(), json!(true))]),
    }
}

fn caps() -> CapabilitySet {
    CapabilitySet::from_iter([
        Capability::new("fake", "read_file")
            .with_constraint("repo", ArgConstraint::Prefix("alice/".into())),
        Capability::new("fake", "create_issue")
            .with_constraint("repo", ArgConstraint::Prefix("alice/public-".into())),
    ])
}

/// A token of `hops` hops: the root, then `hops - 1` exchanges with the same capabilities.
fn token(issuer: &Issuer, hops: usize) -> String {
    let mut t = issuer
        .issue_root(
            user(),
            AgentId::new("agent:planner"),
            caps(),
            Some(Duration::hours(1)),
            t0(),
        )
        .unwrap()
        .token;
    for i in 1..hops {
        t = issuer
            .exchange(
                &t,
                AgentId::new(format!("agent:sub{i}")),
                caps(),
                None,
                t0(),
            )
            .unwrap()
            .token;
    }
    t
}

fn bench_verify(c: &mut Criterion) {
    let signer = Issuer::generate(config());
    let one_key = signer.verifier();
    // A verifier trusting two unrelated keys ahead of the signer's.
    let mut three = Issuer::generate(config());
    three
        .trust_previous_key(&Issuer::generate(config()).public_key_pem())
        .unwrap();
    three.trust_previous_key(&signer.public_key_pem()).unwrap();
    let three_keys = three.verifier();
    assert_eq!(three_keys.key_ids().len(), 3);
    assert_eq!(three_keys.key_ids()[2], signer.key_id());

    let mut group = c.benchmark_group("token");
    for hops in [1usize, 3] {
        let tok = token(&signer, hops);
        let verified = one_key.verify(&tok, t0()).unwrap();
        assert_eq!(verified.chain.hops.len(), hops);
        three_keys.verify(&tok, t0()).unwrap();
        group.bench_with_input(BenchmarkId::new("verify", hops), &hops, |b, _| {
            b.iter(|| one_key.verify(black_box(&tok), t0()).unwrap())
        });
        group.bench_with_input(BenchmarkId::new("verify_3_keys", hops), &hops, |b, _| {
            b.iter(|| three_keys.verify(black_box(&tok), t0()).unwrap())
        });
        let chain = verified.chain;
        group.bench_with_input(BenchmarkId::new("chain_clone", hops), &hops, |b, _| {
            b.iter(|| black_box(&chain).clone())
        });
        group.bench_with_input(BenchmarkId::new("ou_sig_message", hops), &hops, |b, _| {
            b.iter(|| ou_sig_message(black_box(ISS), &chain.originating_user, &chain.hops[0]))
        });
    }
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let msg = vec![7u8; 1024];
    let sig = pair.sign(&msg);
    let public = UnparsedPublicKey::new(&ED25519, pair.public_key().as_ref().to_vec());
    group.bench_function("ed25519_verify", |b| {
        b.iter(|| public.verify(black_box(&msg), sig.as_ref()).unwrap())
    });
    group.finish();
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
