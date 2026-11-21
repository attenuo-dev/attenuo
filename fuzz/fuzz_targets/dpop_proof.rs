//! DPoP proof parsing and verification (`attenuo_token::dpop::verify_proof`, and the server's
//! `Dpop::verify` with its replay cache) with arbitrary `htu`, `htm`, `iat`, `ath`, `jti`,
//! headers and `jwk`, either as raw text or as a correctly signed proof whose fields are
//! fuzzed. A proof that verifies must match the request it was checked against, and a second
//! use of it must be refused.
#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use libfuzzer_sys::fuzz_target;
use attenuo_fuzz::{edge_number, edge_string, json_value};
use attenuo_token::dpop::{
    access_token_hash, jwk_thumbprint, normalize_htu, verify_proof, ProofCheck,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Map, Value};
use time::Duration;

const URLS: &[&str] = &[
    "http://localhost/mcp/github",
    "HTTP://LOCALHOST:80/mcp/github?x=1#f",
    "https://attenuo.example/token",
    "https://attenuo.example:443/token",
    "https://user@attenuo.example/token",
    "http:///x",
    "ftp://x/y",
    "http://[::1]:8080/a",
    "http://localhost",
    "http://localhost/",
];
const METHODS: &[&str] = &["POST", "GET", "post", "DELETE", ""];

fn key() -> &'static (Ed25519KeyPair, Value) {
    static K: std::sync::OnceLock<(Ed25519KeyPair, Value)> = std::sync::OnceLock::new();
    K.get_or_init(|| {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).unwrap();
        let x = URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
        (pair, json!({"kty": "OKP", "crv": "Ed25519", "x": x}))
    })
}

fn pick_str(u: &mut Unstructured<'_>, list: &[&str]) -> Result<String> {
    if u.ratio(1u8, 4u8)? {
        edge_string(u)
    } else {
        Ok((*u.choose(list)?).to_string())
    }
}

/// A claim value: usually sane, sometimes anything.
fn field(u: &mut Unstructured<'_>, sane: Value) -> Result<Option<Value>> {
    Ok(match u.int_in_range(0u8..=7)? {
        0 => None,
        1 => Some(json_value(u, 2)?),
        2 => Some(edge_number(u)?),
        3 => Some(Value::String(edge_string(u)?)),
        _ => Some(sane),
    })
}

#[derive(Debug)]
struct Input {
    proof: String,
    method: String,
    url: String,
    token: Option<String>,
    max_age: u64,
    future_skew: u64,
    reuse: bool,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let f = attenuo_fuzz::fixture();
        let now = f.now.unix_timestamp();
        let method = pick_str(u, METHODS)?;
        let url = pick_str(u, URLS)?;
        let token = if u.arbitrary()? {
            Some(if u.arbitrary()? {
                f.token.clone()
            } else {
                edge_string(u)?
            })
        } else {
            None
        };
        let max_age = match u.int_in_range(0u8..=3)? {
            0 => u.arbitrary()?,
            1 => u64::MAX,
            _ => u.int_in_range(1u64..=600)?,
        };
        let future_skew = match u.int_in_range(0u8..=2)? {
            0 => u.arbitrary()?,
            _ => u.int_in_range(0u64..=60)?,
        };
        let proof = if u.ratio(1u8, 5u8)? {
            u.arbitrary()?
        } else {
            let (pair, jwk) = key();
            let iat = match u.int_in_range(0u8..=5)? {
                0 => json!(u.arbitrary::<i64>()?),
                1 => json!(now.wrapping_sub(i64::MIN)),
                2 => json!(now.wrapping_add(i64::MIN)),
                3 => json!(now + u.int_in_range(-700i64..=700)?),
                _ => json!(now),
            };
            let mut claims = Map::new();
            let ath = token.as_deref().map(access_token_hash).unwrap_or_default();
            let jti = json!(format!("jti-{}", u.arbitrary::<u32>()?));
            for (k, sane) in [
                ("jti", jti),
                ("htm", json!(method)),
                ("htu", json!(pick_str(u, URLS)?)),
                ("iat", iat),
                ("ath", json!(ath)),
            ] {
                if let Some(v) = field(u, sane)? {
                    claims.insert(k.into(), v);
                }
            }
            let mut header = Map::new();
            for (k, sane) in [
                ("typ", json!("dpop+jwt")),
                (
                    "alg",
                    json!(*u.choose(&["EdDSA", "EdDSA", "ES256", "none"])?),
                ),
                ("jwk", jwk.clone()),
            ] {
                if let Some(v) = field(u, sane)? {
                    header.insert(k.into(), v);
                }
            }
            if u.ratio(1u8, 16u8)? {
                header.insert("crit".into(), json!(["x"]));
            }
            let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
            let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
            let input = format!("{h}.{p}");
            let sig = URL_SAFE_NO_PAD.encode(pair.sign(input.as_bytes()).as_ref());
            format!("{input}.{sig}")
        };
        Ok(Input {
            proof,
            method,
            url,
            token,
            max_age,
            future_skew,
            reuse: u.arbitrary()?,
        })
    }
}

fn claims_of(proof: &str) -> (Value, Value) {
    let mut parts = proof.split('.');
    let dec = |s: Option<&str>| {
        serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(s.unwrap()).unwrap()).unwrap()
    };
    (dec(parts.next()), dec(parts.next()))
}

fuzz_target!(|input: Input| {
    let f = attenuo_fuzz::fixture();
    let _ = normalize_htu(&input.url);
    let max_age_secs = i64::try_from(input.max_age).unwrap_or(i64::MAX).max(1);
    let future_secs = i64::try_from(input.future_skew).unwrap_or(i64::MAX);
    let check = ProofCheck {
        method: &input.method,
        url: &input.url,
        access_token: input.token.as_deref(),
        now: f.now,
        max_age: Duration::seconds(max_age_secs),
        future_skew: Duration::seconds(future_secs),
    };
    if let Ok(v) = verify_proof(&input.proof, &check) {
        let (header, claims) = claims_of(&input.proof);
        assert_eq!(claims["htm"].as_str(), Some(input.method.as_str()));
        let htu = normalize_htu(claims["htu"].as_str().unwrap());
        assert!(htu.is_some() && htu == normalize_htu(&input.url));
        let age = f.now.unix_timestamp() as i128 - v.iat as i128;
        assert!(
            age <= max_age_secs as i128 && -age <= future_secs as i128,
            "proof outside the window accepted: iat {}",
            v.iat
        );
        assert_eq!(Some(v.iat), claims["iat"].as_i64());
        if let Some(t) = &input.token {
            assert!(v.covers(t));
            assert_eq!(v.ath.as_deref(), Some(access_token_hash(t).as_str()));
        }
        assert_eq!(
            jwk_thumbprint(&header["jwk"]).ok().as_deref(),
            Some(v.jkt.as_str())
        );
        assert!(!v.jti.is_empty() && v.jti.len() <= 256);
        assert!(v.replay_until(check.max_age) > f.now.unix_timestamp());
    }

    // The server's wrapper adds the one-time-use check.
    let dpop = attenuo_server::dpop::Dpop::new(
        attenuo_server::config::DpopMode::Optional,
        input.max_age,
        16,
        None,
    );
    let first = dpop.verify(
        &input.proof,
        &input.method,
        &input.url,
        input.token.as_deref(),
        f.now,
    );
    if first.is_ok() && input.reuse {
        let again = dpop.verify(
            &input.proof,
            &input.method,
            &input.url,
            input.token.as_deref(),
            f.now,
        );
        assert!(again.is_err(), "a DPoP proof was accepted twice");
    }
});
