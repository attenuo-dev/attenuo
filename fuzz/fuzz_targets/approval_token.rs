//! Approval tokens (`attenuo_token::approval`, ADR-0009) and the store's approval matching.
//!
//! - **bytes**: flip, insert or delete bytes of a valid approval token. Anything
//!   `Verifier::verify_approval` accepts must decode to exactly the original claims.
//! - **re-signed**: edit the claims or header and re-sign with the issuer key (an issuer-key
//!   holder). Anything accepted has `typ` `attenuo-approval+jwt`, the issuer's `iss` and
//!   `aud`, an `exp` after now and a well-formed `cnf`; `check_binding` accepts exactly the
//!   run, lease, call hash and key the claims name.
//! - **cross-type**: an approval token is never a delegation token and the other way round.
//! - **take**: an approval granted for call A, stored in the memory store and the SQLite
//!   store, is taken by a retry of call B (A with mutated arguments) exactly when A and B have
//!   the same canonical JSON, by `take_approval` and by `take_approval_by_id`, at most once,
//!   and only by the hop and run it was made for.
#![no_main]

use std::collections::BTreeMap;

use arbitrary::{Arbitrary, Result, Unstructured};
use attenuo_audit::{
    Approval, ApprovalMethod, ApprovalState, Approver, LeaseStore, MemoryLeaseStore,
    SqliteLeaseStore,
};
use attenuo_core::{
    jcs, AgentId, Capability, CapabilitySet, DelegationChain, LeaseId, OriginatingUser, ToolCall,
};
use attenuo_fuzz::{edge_number, edge_string, json_value};
use attenuo_token::approval::{ApprovalClaims, ApprovalGrant, APPROVAL_TOKEN_TYPE};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use libfuzzer_sys::fuzz_target;
use serde_json::{json, Map, Value};
use time::Duration;

const JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
const APPROVAL_ID: &str = "00000000-0000-4000-8000-000000000001";

const CLAIMS: &[&str] = &[
    "iss", "aud", "sub", "by", "chain_id", "lease", "ch", "iat", "exp", "jti", "cnf", "extra",
];

fn base_call() -> ToolCall {
    ToolCall::new(
        "bank",
        "send",
        json!({"to": "alice@example.com", "amount": 10, "memo": "rent", "tags": ["a", "b"],
               "nested": {"x": 1.5, "y": [1, 2.0, -0.0]}}),
    )
}

fn grant_token(jkt: Option<&str>) -> String {
    let f = attenuo_fuzz::fixture();
    f.issuer
        .issue_approval(&ApprovalGrant {
            approval_id: APPROVAL_ID,
            approver: "user:mudit",
            by: "user",
            chain_id: "lease-root",
            lease: "lease-hop",
            call_hash: &base_call().call_hash(),
            granted_at: f.now,
            expires_at: f.now + Duration::minutes(5),
            jkt,
        })
        .expect("approval token issues")
}

#[derive(Debug)]
enum Edit {
    Set(&'static str, Value),
    Remove(&'static str),
}

/// A change to a call's arguments that may or may not change their canonical form.
#[derive(Debug)]
enum ArgEdit {
    /// Replace a member with a new value.
    Set(String, Value),
    /// Remove a member.
    Remove(String),
    /// Respell an integer as a float (`10` -> `10.0`), which must not change the hash.
    Respell(String),
    /// Reorder the members, which must not change the hash.
    Reorder,
    /// Append a character to a string member.
    Append(String, char),
    /// Swap two list elements.
    Swap(String),
}

#[derive(Debug)]
enum Input {
    Bytes(bool, Vec<(u16, u8, u8)>),
    Resign(
        Vec<Edit>,
        Option<Value>,
        (String, String, String, Option<String>),
    ),
    CrossType,
    Take {
        edits: Vec<ArgEdit>,
        other_lease: bool,
        other_server: bool,
        sqlite: bool,
    },
}

fn binding_part(u: &mut Unstructured<'_>, real: &str) -> Result<String> {
    Ok(if u.ratio(2u8, 3u8)? {
        real.to_string()
    } else {
        edge_string(u)?
    })
}

const KEYS: &[&str] = &["to", "amount", "memo", "tags", "nested", "new", ""];

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        Ok(match u.int_in_range(0u8..=3)? {
            0 => Input::Bytes(u.arbitrary()?, u.arbitrary()?),
            1 => {
                let edits = (0..u.int_in_range(0usize..=4)?)
                    .map(|_| -> Result<Edit> {
                        let k = *u.choose(CLAIMS)?;
                        Ok(match u.int_in_range(0u8..=4)? {
                            0 => Edit::Remove(k),
                            1 => Edit::Set(k, edge_number(u)?),
                            2 => Edit::Set(k, Value::String(edge_string(u)?)),
                            3 => Edit::Set(k, json!({"jkt": *u.choose(&[JKT, "", "x", "AAAA"])?})),
                            _ => Edit::Set(k, json_value(u, 2)?),
                        })
                    })
                    .collect::<Result<_>>()?;
                let header = if u.ratio(1u8, 3u8)? {
                    Some(json!({
                        "alg": *u.choose(&["EdDSA", "none", "HS256"])?,
                        "typ": *u.choose(&[APPROVAL_TOKEN_TYPE, "attenuo+jwt", "JWT", "Attenuo-Approval+JWT", ""])?,
                        "kid": json_value(u, 1)?,
                    }))
                } else {
                    None
                };
                let call_hash = base_call().call_hash();
                let binding = (
                    binding_part(u, "lease-root")?,
                    binding_part(u, "lease-hop")?,
                    binding_part(u, &call_hash)?,
                    match u.int_in_range(0u8..=2)? {
                        0 => None,
                        1 => Some(JKT.to_string()),
                        _ => Some(edge_string(u)?),
                    },
                );
                Input::Resign(edits, header, binding)
            }
            2 => Input::CrossType,
            _ => {
                let edits = (0..u.int_in_range(0usize..=3)?)
                    .map(|_| -> Result<ArgEdit> {
                        let k = (*u.choose(KEYS)?).to_string();
                        Ok(match u.int_in_range(0u8..=5)? {
                            0 => ArgEdit::Set(
                                k,
                                if u.arbitrary()? {
                                    edge_number(u)?
                                } else {
                                    json_value(u, 3)?
                                },
                            ),
                            1 => ArgEdit::Remove(k),
                            2 => ArgEdit::Respell(k),
                            3 => ArgEdit::Reorder,
                            4 => ArgEdit::Append(
                                k,
                                *u.choose(&['\u{0}', ' ', '\u{301}', 'A', '\u{200b}', '"'])?,
                            ),
                            _ => ArgEdit::Swap(k),
                        })
                    })
                    .collect::<Result<_>>()?;
                Input::Take {
                    edits,
                    other_lease: u.ratio(1u8, 8u8)?,
                    other_server: u.ratio(1u8, 8u8)?,
                    sqlite: u.ratio(1u8, 3u8)?,
                }
            }
        })
    }
}

fn apply_arg(args: &mut Map<String, Value>, e: &ArgEdit) {
    match e {
        ArgEdit::Set(k, v) => {
            args.insert(k.clone(), v.clone());
        }
        ArgEdit::Remove(k) => {
            args.remove(k);
        }
        ArgEdit::Respell(k) => {
            if let Some(Value::Number(n)) = args.get(k) {
                if let Some(f) = n.as_f64().and_then(serde_json::Number::from_f64) {
                    args.insert(k.clone(), Value::Number(f));
                }
            }
        }
        ArgEdit::Reorder => {
            let rev: Vec<(String, Value)> = std::mem::take(args).into_iter().rev().collect();
            args.extend(rev);
        }
        ArgEdit::Append(k, c) => {
            if let Some(Value::String(s)) = args.get_mut(k) {
                s.push(*c);
            }
        }
        ArgEdit::Swap(k) => {
            if let Some(Value::Array(a)) = args.get_mut(k) {
                if a.len() >= 2 {
                    a.swap(0, 1);
                }
            }
        }
    }
}

fn decode_claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("payload");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("b64")).expect("json")
}

fn chain() -> DelegationChain {
    let f = attenuo_fuzz::fixture();
    let mut chain = DelegationChain::root(
        OriginatingUser {
            subject: "user:mudit".into(),
            issuer: "https://idp.example".into(),
            authenticated_at: f.now,
            attributes: BTreeMap::new(),
        },
        AgentId::new("agent:planner"),
        CapabilitySet::from_iter([Capability::new("bank", "*")]),
        f.now,
        Duration::minutes(10),
        LeaseId::new("lease-root"),
    )
    .expect("chain");
    let mut hop = chain.hops[0].clone();
    hop.agent = AgentId::new("agent:payer");
    hop.lease = LeaseId::new("lease-hop");
    chain.hops.push(hop);
    chain
}

fn take_in(store: &dyn LeaseStore, retry: &ToolCall, other_lease: bool) -> (bool, bool) {
    let f = attenuo_fuzz::fixture();
    let (root, hop, other) = (
        LeaseId::new("lease-root"),
        LeaseId::new("lease-hop"),
        LeaseId::new("lease-other"),
    );
    let exp = f.now + Duration::minutes(10);
    store.register(&root, None, exp).unwrap();
    store.register(&hop, Some(&root), exp).unwrap();
    store.register(&other, Some(&root), exp).unwrap();
    let call = base_call();
    let pending = Approval {
        id: APPROVAL_ID.into(),
        chain_id: root.clone(),
        lease: hop.clone(),
        call_hash: call.call_hash(),
        server: call.server.clone(),
        tool: call.tool.clone(),
        arguments: serde_json::to_value(&call.arguments).unwrap(),
        labels: Vec::new(),
        untrusted_args: Vec::new(),
        decision_id: "d-gated".into(),
        chain: chain(),
        created_at: f.now,
        expires_at: f.now + Duration::minutes(5),
        state: ApprovalState::Pending,
        approver: None,
        decided_at: None,
        consumed_by: None,
        jkt: None,
    };
    store.create_approval(&pending).unwrap();
    let approver = Approver {
        subject: "user:mudit".into(),
        method: ApprovalMethod::IdToken,
    };
    store
        .decide_approval(APPROVAL_ID, true, &approver, f.now)
        .unwrap();
    let lease = if other_lease { &other } else { &hop };
    let hash = retry.call_hash();
    let by_scan = store
        .take_approval(&root, lease, &hash, "d-1", f.now)
        .unwrap();
    // Single use: a second take finds nothing.
    assert!(store
        .take_approval(&root, lease, &hash, "d-2", f.now)
        .unwrap()
        .is_none());
    if by_scan.is_some() {
        store.restore_approval(APPROVAL_ID, "d-1").unwrap();
    }
    let by_id = store
        .take_approval_by_id(APPROVAL_ID, &root, lease, &hash, "d-3", f.now)
        .unwrap();
    assert!(store
        .take_approval_by_id(APPROVAL_ID, &root, lease, &hash, "d-4", f.now)
        .unwrap()
        .is_none());
    (by_scan.is_some(), by_id.is_some())
}

fuzz_target!(|input: Input| {
    let f = attenuo_fuzz::fixture();
    let original_claims: ApprovalClaims = f
        .verifier
        .verify_approval(&grant_token(Some(JKT)), f.now)
        .expect("the fixture approval token verifies");
    match input {
        Input::Bytes(bound, ops) => {
            let token = grant_token(bound.then_some(JKT));
            let expected = f.verifier.verify_approval(&token, f.now).unwrap();
            let mut bytes = token.into_bytes();
            for (pos, op, b) in ops {
                if bytes.is_empty() {
                    break;
                }
                let i = pos as usize % bytes.len();
                match op % 3 {
                    0 => bytes[i] ^= b.max(1),
                    1 => bytes.insert(i, b),
                    _ => {
                        bytes.remove(i);
                    }
                }
            }
            let Ok(token) = String::from_utf8(bytes) else {
                return;
            };
            if let Ok(c) = f.verifier.verify_approval(&token, f.now) {
                assert_eq!(
                    c, expected,
                    "a byte-mutated approval token verified with other claims"
                );
            }
        }
        Input::Resign(edits, header, (chain_id, lease, ch, jkt)) => {
            let mut claims = decode_claims(&grant_token(Some(JKT)));
            for e in &edits {
                match e {
                    Edit::Set(k, v) => {
                        claims[*k] = v.clone();
                    }
                    Edit::Remove(k) => {
                        if let Some(m) = claims.as_object_mut() {
                            m.remove(*k);
                        }
                    }
                }
            }
            let default_header = json!({"alg": "EdDSA", "typ": APPROVAL_TOKEN_TYPE, "kid": f.kid});
            let header = header.unwrap_or(default_header);
            let token = f.sign_jwt(Some(&header), &claims);
            if let Ok(c) = f.verifier.verify_approval(&token, f.now) {
                assert_eq!(header["typ"], APPROVAL_TOKEN_TYPE);
                assert_eq!(c.iss, attenuo_fuzz::ISS);
                assert_eq!(c.aud, attenuo_fuzz::AUD);
                assert!(c.exp > f.now.unix_timestamp());
                assert!(c.cnf.as_ref().is_none_or(|k| k.is_well_formed()));
                let ok = c
                    .check_binding(&chain_id, &lease, &ch, jkt.as_deref())
                    .is_ok();
                let expected = c.chain_id == chain_id
                    && c.lease == lease
                    && c.ch == ch
                    // An approval is bound to a key only: a certificate binding matches nothing.
                    && c.cnf.as_ref().map(|k| k.key_thumbprint()) == jkt.as_deref().map(Some);
                assert_eq!(ok, expected, "check_binding disagrees with the claims");
            }
            // An approval token is never a delegation token.
            assert!(f.verifier.verify(&token, f.now).is_err());
        }
        Input::CrossType => {
            assert!(f.verifier.verify_approval(&f.token, f.now).is_err());
            assert!(f.verifier.verify(&grant_token(None), f.now).is_err());
            assert_eq!(original_claims.ch, base_call().call_hash());
        }
        Input::Take {
            edits,
            other_lease,
            other_server,
            sqlite,
        } => {
            let base = base_call();
            let mut args: Map<String, Value> = base.arguments.clone().into_iter().collect();
            for e in &edits {
                apply_arg(&mut args, e);
            }
            let server = if other_server { "bank2" } else { "bank" };
            let retry = ToolCall::new(server, "send", Value::Object(args));
            let same = !other_server
                && jcs::to_vec(&retry.arguments).unwrap() == jcs::to_vec(&base.arguments).unwrap();
            assert_eq!(
                same,
                !other_server
                    && jcs::value_eq(
                        &serde_json::to_value(&retry.arguments).unwrap(),
                        &serde_json::to_value(&base.arguments).unwrap()
                    )
            );
            assert_eq!(
                retry.call_hash() == base.call_hash(),
                same,
                "the call hash disagrees with canonical equality"
            );
            let expect = same && !other_lease;
            let memory = MemoryLeaseStore::new();
            let mut stores: Vec<Box<dyn LeaseStore>> = vec![Box::new(memory)];
            if sqlite {
                stores.push(Box::new(SqliteLeaseStore::open_in_memory().unwrap()));
            }
            for s in &stores {
                let (by_scan, by_id) = take_in(s.as_ref(), &retry, other_lease);
                assert_eq!(by_scan, expect, "take_approval matched wrongly");
                assert_eq!(by_id, expect, "take_approval_by_id matched wrongly");
            }
        }
    }
});
