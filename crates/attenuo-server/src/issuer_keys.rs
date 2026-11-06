//! The issuer's own public keys as a JWK Set (RFC 7517, OKP keys per RFC 8037), served at
//! `GET /.well-known/jwks.json`. The cache of identity-provider keys is a different module,
//! `idp::jwks`.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Value};

/// Length of an Ed25519 SubjectPublicKeyInfo DER: a 12-byte prefix plus the 32-byte key.
const ED25519_SPKI_LEN: usize = 44;

/// Decode a `PUBLIC KEY` PEM to its SPKI DER bytes.
pub(crate) fn spki_der_from_pem(pem: &str) -> anyhow::Result<Vec<u8>> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect();
    let der = STANDARD.decode(b64)?;
    if der.len() != ED25519_SPKI_LEN {
        anyhow::bail!("not an Ed25519 SubjectPublicKeyInfo ({} bytes)", der.len());
    }
    Ok(der)
}

/// `{"keys": [ { kty: OKP, crv: Ed25519, alg: EdDSA, use: sig, kid, x } ]}` for each
/// `(kid, PUBLIC KEY PEM)`: the signing key first, then any retired keys still trusted.
pub(crate) fn jwks_from_keys(keys: &[(String, String)]) -> anyhow::Result<Value> {
    let mut out = Vec::with_capacity(keys.len());
    for (kid, pem) in keys {
        let der = spki_der_from_pem(pem)?;
        let raw = &der[ED25519_SPKI_LEN - 32..];
        out.push(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "kid": kid,
            "x": URL_SAFE_NO_PAD.encode(raw),
        }));
    }
    Ok(json!({ "keys": out }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use attenuo_token::{Issuer, IssuerConfig};

    fn issuer() -> Issuer {
        Issuer::generate(IssuerConfig {
            issuer: "i".into(),
            audience: "a".into(),
            max_depth: 4,
            default_ttl: time::Duration::minutes(5),
        })
    }

    #[test]
    fn jwk_x_matches_pem_key() {
        let issuer = issuer();
        let pem = issuer.public_key_pem();
        let jwks = jwks_from_keys(&issuer.trusted_public_keys()).unwrap();
        let k = &jwks["keys"][0];
        assert_eq!(k["crv"], "Ed25519");
        assert_eq!(k["kid"].as_str().unwrap(), issuer.key_id());
        assert_eq!(k["kid"].as_str().unwrap().len(), 22);
        let x = URL_SAFE_NO_PAD.decode(k["x"].as_str().unwrap()).unwrap();
        assert_eq!(x.len(), 32);
        assert_eq!(&spki_der_from_pem(&pem).unwrap()[12..], &x[..]);
        assert!(jwks_from_keys(&[(
            "k".into(),
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----".into()
        )])
        .is_err());
    }

    #[test]
    fn jwks_lists_current_then_retired_keys() {
        let old = issuer();
        let mut new = issuer();
        new.trust_previous_key(&old.public_key_pem()).unwrap();
        let jwks = jwks_from_keys(&new.trusted_public_keys()).unwrap();
        let kids: Vec<&str> = jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap())
            .collect();
        assert_eq!(kids, [new.key_id(), old.key_id()]);
    }
}
