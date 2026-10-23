//! `Verifier::verify` on structurally mutated copies of a valid token.
//!
//! Three attacker models, picked by the input:
//!
//! - **bytes**: flip, insert or delete bytes of the compact token without re-signing. Anything
//!   accepted must decode to exactly the original claims.
//! - **re-signed JWT**: edit the claims (or header) and re-sign the JWT with the issuer key,
//!   leaving `ou_sig` alone, as a second legitimate issuer key would. Anything accepted must
//!   keep the original issuer, user block and root hop, and its chain must be sound.
//! - **re-signed JWT and ou_sig**: a full issuer-key holder. Anything accepted must still be
//!   internally consistent: a sound chain, `sub`/`act`/`exp` matching it.
//!
//! Edits include deep `act` nesting, very long `hops` arrays, unicode in names, and edge
//! numbers in every numeric claim.
#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use onbehalf_fuzz::{edge_number, edge_string, json_value};
use serde_json::{json, Value};

const PATHS: &[&str] = &[
    "/iss",
    "/aud",
    "/sub",
    "/jti",
    "/iat",
    "/exp",
    "/typ",
    "/ou_sig",
    "/ou_sig_v",
    "/ou_kid",
    "/may_act",
    "/cnf",
    "/cnf/jkt",
    "/act",
    "/act/sub",
    "/act/act",
    "/act/act/sub",
    "/chain",
    "/chain/originating_user",
    "/chain/originating_user/subject",
    "/chain/originating_user/issuer",
    "/chain/originating_user/authenticated_at",
    "/chain/originating_user/attributes",
    "/chain/originating_user/attributes/mfa",
    "/chain/hops",
    "/chain/hops/0",
    "/chain/hops/0/agent",
    "/chain/hops/0/capabilities",
    "/chain/hops/0/issued_at",
    "/chain/hops/0/expires_at",
    "/chain/hops/0/lease",
    "/chain/hops/1",
    "/chain/hops/1/agent",
    "/chain/hops/1/capabilities",
    "/chain/hops/1/capabilities/0",
    "/chain/hops/1/capabilities/0/server",
    "/chain/hops/1/capabilities/0/tool",
    "/chain/hops/1/capabilities/0/constraints",
    "/chain/hops/1/issued_at",
    "/chain/hops/1/expires_at",
    "/chain/hops/1/lease",
];

const TIMES: &[&str] = &[
    "2026-10-23T12:00:00Z",
    "2026-10-23T12:10:00Z",
    "2026-10-23T12:10:01Z",
    "2026-10-23T11:59:59Z",
    "2026-10-23T13:10:00+01:00",
    "9999-12-31T23:59:59Z",
    "0000-01-01T00:00:00Z",
    "2026-10-23T12:10:00.000000001Z",
    "2026-10-23T12:10:00.999999999-00:00",
];

#[derive(Debug)]
enum Edit {
    Set(&'static str, Value),
    Remove(&'static str),
    /// Nest `act` this deep.
    DeepAct(usize),
    /// Append copies of the last hop, each with a fresh agent and lease.
    ExtraHops(usize, Value),
    /// Widen the last hop's capabilities.
    Widen(Value),
}

fn edit(u: &mut Unstructured<'_>) -> Result<Edit> {
    Ok(match u.int_in_range(0u8..=9)? {
        0..=2 => Edit::Set(u.choose(PATHS)?, json_value(u, 4)?),
        3 => Edit::Set(u.choose(PATHS)?, Value::String(edge_string(u)?)),
        4 => Edit::Set(u.choose(PATHS)?, edge_number(u)?),
        5 => Edit::Set(u.choose(PATHS)?, Value::String((*u.choose(TIMES)?).into())),
        6 => Edit::Remove(u.choose(PATHS)?),
        7 => Edit::DeepAct(u.int_in_range(1usize..=1000)?),
        8 => Edit::ExtraHops(u.int_in_range(1usize..=500)?, json_value(u, 0)?),
        _ => Edit::Widen(match u.int_in_range(0u8..=2)? {
            0 => json!([{"server": "*", "tool": "*"}]),
            1 => json!([{"server": "github", "tool": "read_*"}]),
            _ => json!([{"server": "github", "tool": "read_file",
                         "constraints": {"x": {"op": "prefix", "value": ""}}}]),
        }),
    })
}

fn apply(claims: &mut Value, e: &Edit) {
    match e {
        Edit::Set(path, v) => {
            if let Some(slot) = claims.pointer_mut(path) {
                *slot = v.clone();
            } else if let Some((parent, key)) = path.rsplit_once('/') {
                if let Some(Value::Object(m)) = claims.pointer_mut(parent) {
                    m.insert(key.to_owned(), v.clone());
                }
            }
        }
        Edit::Remove(path) => {
            if let Some((parent, key)) = path.rsplit_once('/') {
                match claims.pointer_mut(parent) {
                    Some(Value::Object(m)) => {
                        m.remove(key);
                    }
                    Some(Value::Array(a)) => {
                        if let Ok(i) = key.parse::<usize>() {
                            if i < a.len() {
                                a.remove(i);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        Edit::DeepAct(n) => {
            let mut act = json!({"sub": "agent:planner"});
            for i in 0..*n {
                act = json!({"sub": format!("agent:{i}"), "act": act});
            }
            claims["act"] = act;
        }
        Edit::ExtraHops(n, caps) => {
            if let Some(Value::Array(hops)) = claims.pointer_mut("/chain/hops") {
                if let Some(last @ Value::Object(_)) = hops.last().cloned() {
                    for i in 0..*n {
                        let mut h = last.clone();
                        h["agent"] = json!(format!("agent:x{i}"));
                        h["lease"] = json!(format!("lease-{i}"));
                        if !caps.is_null() {
                            h["capabilities"] = caps.clone();
                        }
                        hops.push(h);
                    }
                }
            }
        }
        Edit::Widen(caps) => {
            if let Some(Value::Array(hops)) = claims.pointer_mut("/chain/hops") {
                if let Some(last @ Value::Object(_)) = hops.last_mut() {
                    last["capabilities"] = caps.clone();
                }
            }
        }
    }
}

#[derive(Debug)]
enum Input {
    Bytes(Vec<(u16, u8, u8)>),
    ResignJwt(Vec<Edit>, Option<Value>),
    ResignAll(Vec<Edit>),
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        Ok(match u.int_in_range(0u8..=2)? {
            0 => Input::Bytes(u.arbitrary()?),
            1 => {
                let n = u.int_in_range(1usize..=4)?;
                let edits = (0..n).map(|_| edit(u)).collect::<Result<_>>()?;
                let header = if u.ratio(1u8, 4u8)? {
                    Some(json!({
                        "alg": *u.choose(&["EdDSA", "none", "HS256", "ES256", "RS256"])?,
                        "typ": *u.choose(&["onbehalf+jwt", "JWT", "dpop+jwt", ""])?,
                        "kid": json_value(u, 1)?,
                    }))
                } else {
                    None
                };
                Input::ResignJwt(edits, header)
            }
            _ => {
                let n = u.int_in_range(1usize..=4)?;
                Input::ResignAll((0..n).map(|_| edit(u)).collect::<Result<_>>()?)
            }
        })
    }
}

fn verified_claims(token: &str) -> Option<onbehalf_token::VerifiedToken> {
    let f = onbehalf_fuzz::fixture();
    f.verifier.verify(token, f.now).ok()
}

fuzz_target!(|input: Input| {
    let f = onbehalf_fuzz::fixture();
    let original: onbehalf_token::Claims =
        serde_json::from_value(f.claims.clone()).expect("fixture claims");
    match input {
        Input::Bytes(ops) => {
            let mut bytes = f.token.as_bytes().to_vec();
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
            if let Some(v) = verified_claims(&token) {
                assert_eq!(
                    v.claims, original,
                    "byte-mutated token verified with other claims"
                );
            }
        }
        Input::ResignJwt(edits, header) => {
            let mut claims = f.claims.clone();
            for e in &edits {
                apply(&mut claims, e);
            }
            let token = f.sign_jwt(header.as_ref(), &claims);
            if let Some(v) = verified_claims(&token) {
                onbehalf_fuzz::assert_chain_sound(&v.chain, f.now);
                assert_eq!(v.claims.iss, original.iss);
                assert_eq!(v.chain.originating_user, original.chain.originating_user);
                let (a, b) = (&v.chain.hops[0], &original.chain.hops[0]);
                assert!(
                    a.agent == b.agent
                        && a.capabilities == b.capabilities
                        && a.issued_at == b.issued_at
                        && a.lease == b.lease,
                    "root hop changed without a new ou_sig"
                );
            }
        }
        Input::ResignAll(edits) => {
            let mut claims = f.claims.clone();
            for e in &edits {
                apply(&mut claims, e);
            }
            f.resign_ou(&mut claims);
            let token = f.sign_jwt(None, &claims);
            if let Some(v) = verified_claims(&token) {
                onbehalf_fuzz::assert_chain_sound(&v.chain, f.now);
                assert_eq!(v.claims.sub, v.chain.originating_user.subject);
                assert_eq!(
                    Some(v.claims.exp),
                    v.chain.hops.last().map(|h| h.expires_at.unix_timestamp())
                );
                assert_eq!(
                    onbehalf_token::ActClaim::from_chain(&v.chain).as_ref(),
                    Some(&v.claims.act)
                );
                assert_eq!(v.claims.ou_sig_v, onbehalf_token::OU_SIG_VERSION);
                if let Some(cnf) = &v.claims.cnf {
                    assert!(cnf.is_well_formed());
                }
            }
        }
    }
});
