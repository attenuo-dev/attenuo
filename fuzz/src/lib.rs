//! Shared helpers for the attenuo fuzz targets: JSON and string generators biased towards
//! edge cases, and a fixed token issuer whose key the targets can use to re-sign mutated
//! tokens (so the checks after the signature are reached).

use std::sync::OnceLock;

use arbitrary::{Result, Unstructured};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use attenuo_core::{AgentId, Capability, CapabilitySet, OriginatingUser};
use attenuo_token::{Issuer, IssuerConfig, Verifier};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Map, Number, Value};
use time::{Duration, OffsetDateTime};

/// Strings that tend to break parsers and comparisons.
const EDGE_STRINGS: &[&str] = &[
    "",
    "*",
    "a*",
    "/",
    "a/b",
    "a//b",
    "resources/*",
    "read_*",
    "read_file",
    "github",
    "acme/",
    "acme/repo",
    "agent:planner",
    "user:mudit",
    "\u{0}",
    "\n",
    "\r\n",
    "\u{7f}",
    "\u{202e}",
    "\u{fe0f}",
    "é",
    "e\u{301}",
    "Ａ",
    "\u{10ffff}",
    "\\",
    "\"",
    "%00",
    "../",
    "dpop+jwt",
    "attenuo+jwt",
    "EdDSA",
    "ES256",
    "none",
    "http://localhost/mcp",
    "HTTPS://Example.COM:443/a?b#c",
];

/// An arbitrary string, often one of [`EDGE_STRINGS`], sometimes long or full of controls.
pub fn edge_string(u: &mut Unstructured<'_>) -> Result<String> {
    Ok(match u.int_in_range(0u8..=9)? {
        0..=3 => (*u.choose(EDGE_STRINGS)?).to_string(),
        4 => {
            let base: String = (*u.choose(EDGE_STRINGS)?).to_string();
            let n = u.int_in_range(0usize..=300)?;
            base.repeat(n.max(1))
        }
        5 => {
            let n = u.int_in_range(0usize..=40)?;
            (0..n)
                .map(|_| {
                    u.int_in_range(0u32..=0x20)
                        .map(|c| char::from_u32(c).unwrap_or('?'))
                })
                .collect::<Result<String>>()?
        }
        _ => u.arbitrary::<String>()?,
    })
}

/// A number at or near the edges of what JSON implementations agree on.
pub fn edge_number(u: &mut Unstructured<'_>) -> Result<Value> {
    Ok(match u.int_in_range(0u8..=9)? {
        0 => Value::from(i64::MIN),
        1 => Value::from(i64::MAX),
        2 => Value::from(u64::MAX),
        3 => Value::from(-1i64),
        4 => Value::from(0),
        5 => Value::from(1u64 << 53),
        6 => Number::from_f64(u.arbitrary::<f64>()?)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        7 => Value::from(u.arbitrary::<i64>()?),
        8 => Value::from(u.arbitrary::<u64>()?),
        _ => Value::from(u.arbitrary::<i32>()?),
    })
}

/// An arbitrary JSON value of at most `depth` levels, biased towards edge numbers and strings,
/// and sometimes a deep single-path nest or a large array.
pub fn json_value(u: &mut Unstructured<'_>, depth: u32) -> Result<Value> {
    let leaf_only = depth == 0;
    let pick = if leaf_only {
        u.int_in_range(0u8..=3)?
    } else {
        u.int_in_range(0u8..=7)?
    };
    Ok(match pick {
        0 => Value::Null,
        1 => Value::Bool(u.arbitrary()?),
        2 => edge_number(u)?,
        3 => Value::String(edge_string(u)?),
        4 | 5 => {
            let n = u.int_in_range(0usize..=6)?;
            let mut m = Map::new();
            for _ in 0..n {
                m.insert(edge_string(u)?, json_value(u, depth - 1)?);
            }
            Value::Object(m)
        }
        6 => {
            let n = u.int_in_range(0usize..=6)?;
            Value::Array(
                (0..n)
                    .map(|_| json_value(u, depth - 1))
                    .collect::<Result<_>>()?,
            )
        }
        _ => {
            // Deep nesting or a wide array, built cheaply.
            if u.arbitrary()? {
                let levels = u.int_in_range(1usize..=200)?;
                let mut v = json_value(u, 0)?;
                for _ in 0..levels {
                    v = if u.arbitrary()? {
                        Value::Array(vec![v])
                    } else {
                        let mut m = Map::new();
                        m.insert("a".into(), v);
                        Value::Object(m)
                    };
                }
                v
            } else {
                let n = u.int_in_range(0usize..=2000)?;
                let item = json_value(u, 0)?;
                Value::Array(vec![item; n])
            }
        }
    })
}

/// The issuer string of the fixed issuer.
pub const ISS: &str = "https://attenuo.fuzz";
/// The audience of the fixed issuer.
pub const AUD: &str = "mcp-proxy";
/// Max chain depth of the fixed issuer.
pub const MAX_DEPTH: usize = 8;

/// A token issuer with a fixed key, a valid token chain from it and the raw key material.
pub struct Fixture {
    pub issuer: Issuer,
    pub verifier: Verifier,
    pub pair: Ed25519KeyPair,
    pub encoding_key: jsonwebtoken::EncodingKey,
    pub kid: String,
    /// The clock every target verifies at.
    pub now: OffsetDateTime,
    /// A two-hop token, valid at `now`.
    pub token: String,
    /// Its decoded claims.
    pub claims: Value,
}

const SEED: [u8; 32] = [7u8; 32];

fn pkcs8_from_seed(seed: &[u8; 32]) -> Vec<u8> {
    // RFC 8410 PKCS#8 v1 for Ed25519: fixed prefix, then the 32-byte seed.
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(seed);
    der
}

/// The shared fixture, built once per process.
pub fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let der = pkcs8_from_seed(&SEED);
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(&der)
        );
        let issuer = Issuer::from_pem(
            IssuerConfig {
                issuer: ISS.into(),
                audience: AUD.into(),
                max_depth: MAX_DEPTH,
                default_ttl: Duration::minutes(10),
            },
            &pem,
        )
        .expect("fixed key loads");
        let pair = Ed25519KeyPair::from_seed_unchecked(&SEED).expect("seed");
        let encoding_key = jsonwebtoken::EncodingKey::from_ed_der(&der);
        let now = time::macros::datetime!(2026-10-23 12:00 UTC);
        let user = OriginatingUser {
            subject: "user:mudit".into(),
            issuer: "https://idp.example".into(),
            authenticated_at: now,
            attributes: [("mfa".to_string(), Value::Bool(true))].into(),
        };
        let root = issuer
            .issue_root(
                user,
                AgentId::new("agent:planner"),
                CapabilitySet::from_iter([
                    Capability::new("github", "read_*"),
                    Capability::new("github", "create_issue"),
                ]),
                None,
                now,
            )
            .expect("root issues");
        let child = issuer
            .exchange(
                &root.token,
                AgentId::new("agent:coder"),
                CapabilitySet::from_iter([Capability::new("github", "read_file")]),
                None,
                now,
            )
            .expect("exchange works");
        let payload = child.token.split('.').nth(1).expect("payload");
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("b64")).expect("json");
        assert_eq!(pair.public_key().as_ref().len(), 32);
        Fixture {
            kid: issuer.key_id(),
            verifier: issuer.verifier(),
            issuer,
            pair,
            encoding_key,
            now,
            token: child.token,
            claims,
        }
    })
}

impl Fixture {
    /// Sign `claims` as a JWT with the fixed key. `header` replaces the standard
    /// `{"alg":"EdDSA","typ":"attenuo+jwt","kid":..}` when given.
    pub fn sign_jwt(&self, header: Option<&Value>, claims: &Value) -> String {
        let default = serde_json::json!({"alg": "EdDSA", "typ": "attenuo+jwt", "kid": self.kid});
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header.unwrap_or(&default)).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let input = format!("{h}.{p}");
        let sig = self.pair.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
    }

    /// Recompute `ou_sig` over the (possibly mutated) `iss`, user block and root hop, as a
    /// holder of the issuer key would. Leaves `claims` alone when those do not deserialize.
    pub fn resign_ou(&self, claims: &mut Value) {
        let iss = claims.get("iss").and_then(Value::as_str).map(str::to_owned);
        let user = claims
            .pointer("/chain/originating_user")
            .cloned()
            .and_then(|v| serde_json::from_value::<OriginatingUser>(v).ok());
        let root = claims
            .pointer("/chain/hops/0")
            .cloned()
            .and_then(|v| serde_json::from_value::<attenuo_core::Hop>(v).ok());
        if let (Some(iss), Some(user), Some(root)) = (iss, user, root) {
            let msg = attenuo_token::claims::ou_sig_message(&iss, &user, &root);
            let sig = URL_SAFE_NO_PAD.encode(self.pair.sign(&msg).as_ref());
            if let Some(obj) = claims.as_object_mut() {
                obj.insert("ou_sig".into(), Value::String(sig));
            }
        }
    }
}

/// Check, independently of `validate_at`, the properties an accepted chain must have:
/// bounded depth, a non-empty subject, and every hop narrower and no longer-lived than its
/// parent. Panics (a fuzz finding) if one does not hold.
pub fn assert_chain_sound(chain: &attenuo_core::DelegationChain, now: OffsetDateTime) {
    assert!(!chain.originating_user.subject.is_empty());
    assert!(!chain.hops.is_empty() && chain.hops.len() <= MAX_DEPTH);
    for (i, hop) in chain.hops.iter().enumerate() {
        assert!(hop.expires_at > now, "accepted an expired hop");
        assert!(hop.issued_at < hop.expires_at);
        assert!(hop.capabilities.validate().is_ok());
        if i > 0 {
            let parent = &chain.hops[i - 1];
            assert!(
                parent.capabilities.covers(&hop.capabilities),
                "accepted a widening hop"
            );
            assert!(hop.expires_at <= parent.expires_at);
            assert!(chain.hops[..i].iter().all(|h| h.agent != hop.agent));
            assert!(chain.hops[..i].iter().all(|h| h.lease != hop.lease));
        }
    }
}

/// A small, valid, signed audit export and the keys that verify it.
pub struct AuditFixture {
    pub export: attenuo_audit::Export,
    pub keys: attenuo_audit::CheckpointKeys,
    /// The JSONL text of `export`.
    pub text: String,
}

/// Five entries (`1..=5`), checkpoints at 3 and 5, a header for `1..=5`.
pub fn audit_fixture() -> &'static AuditFixture {
    use attenuo_audit::{checkpoint_line, entry_line, header_line, AuditEntry, Checkpoint};
    use attenuo_core::{Decision, DecisionRecord, LeaseId, ToolCall};
    static A: OnceLock<AuditFixture> = OnceLock::new();
    A.get_or_init(|| {
        let f = fixture();
        let chain = attenuo_core::DelegationChain::root(
            OriginatingUser {
                subject: "user:mudit".into(),
                issuer: "https://idp.example".into(),
                authenticated_at: f.now,
                attributes: Default::default(),
            },
            AgentId::new("agent:planner"),
            CapabilitySet::from_iter([Capability::new("github", "*")]),
            f.now,
            Duration::minutes(10),
            LeaseId::new("lease-1"),
        )
        .expect("chain");
        let mut entries: Vec<AuditEntry> = Vec::new();
        for i in 0..5u128 {
            let call = ToolCall::new("github", "read_file", serde_json::json!({"n": i as u64}));
            let mut record = DecisionRecord::new(
                f.now + Duration::seconds(i as i64),
                if i % 2 == 0 {
                    Decision::Allow
                } else {
                    Decision::Deny
                },
                "policy_allow",
                &chain,
                &call,
                vec![format!("p{i}")],
            );
            record.id = uuid::Uuid::from_u128(i + 1);
            entries.push(AuditEntry::next(entries.last(), record));
        }
        let signer = f.issuer.detached_signer();
        let checkpoints: Vec<Checkpoint> = [3usize, 5]
            .iter()
            .map(|&s| Checkpoint::sign(&signer, s as u64, &entries[s - 1].entry_hash, f.now))
            .collect::<std::result::Result<_, _>>()
            .expect("sign");
        let header = attenuo_audit::ExportHeader::new(1, 5, "2026-10-23T12:00:00Z".into());
        let mut text = header_line(&header);
        for e in &entries {
            text.push_str(&entry_line(e));
        }
        for c in &checkpoints {
            text.push_str(&checkpoint_line(c));
        }
        let x = URL_SAFE_NO_PAD.encode(f.pair.public_key().as_ref());
        let keys = attenuo_audit::CheckpointKeys::from_jwks(&serde_json::json!({
            "keys": [{"kty": "OKP", "crv": "Ed25519", "kid": signer.kid(), "x": x}]
        }))
        .expect("jwks");
        let export = attenuo_audit::parse_export(&text).expect("fixture export parses");
        let report = attenuo_audit::verify_export(&export, &keys).expect("verifies");
        assert!(report.report.ok, "fixture export must verify: {report:?}");
        AuditFixture { export, keys, text }
    })
}
