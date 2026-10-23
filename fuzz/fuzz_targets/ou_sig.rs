//! The `ou_sig` construction: building the signed message never panics for a user block and
//! root hop the issuer can be handed, the encoding is injective (two different
//! `(iss, user, root hop)` triples never produce the same bytes, so a signature cannot be
//! moved between them), and a signature over one triple never verifies for another. Also runs
//! `verify_detached` on arbitrary keys, contexts and signatures.
#![no_main]

use std::collections::BTreeMap;

use arbitrary::{Arbitrary, Result, Unstructured};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use libfuzzer_sys::fuzz_target;
use onbehalf_core::{AgentId, Capability, CapabilitySet, Hop, LeaseId, OriginatingUser};
use onbehalf_fuzz::{edge_string, json_value};
use ring::signature::{UnparsedPublicKey, ED25519};
use time::{OffsetDateTime, UtcOffset};

fn instant(u: &mut Unstructured<'_>) -> Result<OffsetDateTime> {
    let secs = match u.int_in_range(0u8..=3)? {
        // Anything `time` can represent, including years before 0.
        0 => u.int_in_range(-377_705_116_800i64..=253_402_300_799)?,
        1 => u.int_in_range(-62_167_219_200i64..=-62_167_219_100)?,
        _ => u.int_in_range(0i64..=4_102_444_800)?,
    };
    let t = OffsetDateTime::from_unix_timestamp(secs).expect("in range");
    let t = t
        .replace_nanosecond(u.int_in_range(0u32..=999_999_999)?)
        .unwrap_or(t);
    if u.ratio(1u8, 4u8)? {
        let h = u.int_in_range(-23i8..=23)?;
        let m = u.int_in_range(0i8..=59)?;
        let off = UtcOffset::from_hms(h, if h < 0 { -m } else { m }, 0).unwrap_or(UtcOffset::UTC);
        return Ok(t.checked_to_offset(off).unwrap_or(t));
    }
    Ok(t)
}

fn user(u: &mut Unstructured<'_>) -> Result<OriginatingUser> {
    let mut attributes = BTreeMap::new();
    for _ in 0..u.int_in_range(0usize..=3)? {
        attributes.insert(edge_string(u)?, json_value(u, 3)?);
    }
    Ok(OriginatingUser {
        subject: edge_string(u)?,
        issuer: edge_string(u)?,
        authenticated_at: instant(u)?,
        attributes,
    })
}

fn hop(u: &mut Unstructured<'_>) -> Result<Hop> {
    let n = u.int_in_range(0usize..=3)?;
    let caps: CapabilitySet = (0..n)
        .map(|_| Ok(Capability::new(edge_string(u)?, edge_string(u)?)))
        .collect::<Result<_>>()?;
    Ok(Hop {
        agent: AgentId::new(edge_string(u)?),
        capabilities: caps,
        issued_at: instant(u)?,
        expires_at: instant(u)?,
        lease: LeaseId::new(edge_string(u)?),
    })
}

#[derive(Debug)]
struct Input {
    iss: String,
    user: OriginatingUser,
    root: Hop,
    other: (String, OriginatingUser, Hop),
    key: Vec<u8>,
    context: String,
    payload: Vec<u8>,
    sig: String,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let iss = edge_string(u)?;
        let user = user(u)?;
        let root = hop(u)?;
        // The second triple is a small edit of the first, so collisions are tried where
        // they are likeliest.
        let mut other = (iss.clone(), user.clone(), root.clone());
        match u.int_in_range(0u8..=7)? {
            0 => other.0 = edge_string(u)?,
            1 => other.1.subject = edge_string(u)?,
            2 => other.1.issuer = edge_string(u)?,
            3 => other.1.authenticated_at = instant(u)?,
            4 => {
                other
                    .1
                    .attributes
                    .insert(edge_string(u)?, json_value(u, 2)?);
            }
            5 => other.2.agent = AgentId::new(edge_string(u)?),
            6 => other.2.lease = LeaseId::new(edge_string(u)?),
            _ => other = (edge_string(u)?, self::user(u)?, hop(u)?),
        }
        Ok(Input {
            iss,
            user,
            root,
            other,
            key: u.arbitrary()?,
            context: edge_string(u)?,
            payload: u.arbitrary()?,
            sig: edge_string(u)?,
        })
    }
}

fn same_root(a: &Hop, b: &Hop) -> bool {
    // `expires_at` is deliberately not covered by ou_sig.
    a.agent == b.agent
        && a.capabilities == b.capabilities
        && a.issued_at == b.issued_at
        && a.issued_at.offset() == b.issued_at.offset()
        && a.lease == b.lease
}

/// Times outside RFC 3339's years 0..=9999 have no JSON form; `Issuer::issue_root` refuses a
/// chain with one (it used to panic in the `ou_sig` encoding).
fn encodable(user: &OriginatingUser, root: &Hop) -> bool {
    serde_json::to_vec(user).is_ok() && serde_json::to_vec(root).is_ok()
}

fuzz_target!(|input: Input| {
    let f = onbehalf_fuzz::fixture();
    // The issuer must refuse, not panic, whatever the user block holds.
    let _ = f.issuer.issue_root(
        input.user.clone(),
        AgentId::new("agent:planner"),
        CapabilitySet::from_iter([Capability::new("github", "read_*")]),
        None,
        f.now,
    );
    if !encodable(&input.user, &input.root) || !encodable(&input.other.1, &input.other.2) {
        return;
    }
    let m1 = onbehalf_token::claims::ou_sig_message(&input.iss, &input.user, &input.root);
    let (iss2, user2, root2) = &input.other;
    let m2 = onbehalf_token::claims::ou_sig_message(iss2, user2, root2);
    let same_triple = input.iss == *iss2
        && input.user == *user2
        && input.user.authenticated_at.offset() == user2.authenticated_at.offset()
        && same_root(&input.root, root2);
    if m1 == m2 {
        assert!(
            same_triple,
            "two different ou_sig inputs encode to the same bytes"
        );
    }
    let sig = f.pair.sign(&m1);
    let pk = UnparsedPublicKey::new(&ED25519, ring::signature::KeyPair::public_key(&f.pair));
    assert!(pk.verify(&m1, sig.as_ref()).is_ok());
    if m1 != m2 {
        assert!(pk.verify(&m2, sig.as_ref()).is_err());
    }

    // verify_detached on arbitrary inputs: no panic, and a random signature never verifies.
    let pk_raw = ring::signature::KeyPair::public_key(&f.pair)
        .as_ref()
        .to_vec();
    let _ = onbehalf_token::verify_detached(&input.key, &input.context, &input.payload, &input.sig);
    let ok = onbehalf_token::verify_detached(&pk_raw, &input.context, &input.payload, &input.sig);
    if ok {
        // Only possible if the fuzzer reproduced a real signature, which it cannot.
        let raw = URL_SAFE_NO_PAD.decode(&input.sig).unwrap_or_default();
        panic!("random detached signature verified: {raw:?}");
    }
});
