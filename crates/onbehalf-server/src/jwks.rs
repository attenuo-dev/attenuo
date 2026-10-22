//! The issuer's public key as a JWK Set (RFC 7517, OKP keys per RFC 8037).

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Length of an Ed25519 SubjectPublicKeyInfo DER: a 12-byte prefix plus the 32-byte key.
const ED25519_SPKI_LEN: usize = 44;

/// Decode a `PUBLIC KEY` PEM to its SPKI DER bytes.
pub fn spki_der_from_pem(pem: &str) -> anyhow::Result<Vec<u8>> {
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

/// Key id: the first 16 hex characters of SHA-256 over the SPKI DER.
pub fn key_id(spki_der: &[u8]) -> String {
    let digest = hex::encode(Sha256::digest(spki_der));
    digest[..16].to_string()
}

/// `{"keys": [ { kty: OKP, crv: Ed25519, alg: EdDSA, use: sig, kid, x } ]}`.
pub fn jwks_from_public_pem(pem: &str) -> anyhow::Result<Value> {
    let der = spki_der_from_pem(pem)?;
    let raw = &der[ED25519_SPKI_LEN - 32..];
    Ok(json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "kid": key_id(&der),
            "x": URL_SAFE_NO_PAD.encode(raw),
        }]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use onbehalf_token::{Issuer, IssuerConfig};

    #[test]
    fn jwk_x_matches_pem_key() {
        let issuer = Issuer::generate(IssuerConfig {
            issuer: "i".into(),
            audience: "a".into(),
            max_depth: 4,
            default_ttl: time::Duration::minutes(5),
        });
        let pem = issuer.public_key_pem();
        let jwks = jwks_from_public_pem(&pem).unwrap();
        let k = &jwks["keys"][0];
        assert_eq!(k["crv"], "Ed25519");
        assert_eq!(k["kid"].as_str().unwrap().len(), 16);
        let x = URL_SAFE_NO_PAD.decode(k["x"].as_str().unwrap()).unwrap();
        assert_eq!(x.len(), 32);
        assert_eq!(&spki_der_from_pem(&pem).unwrap()[12..], &x[..]);
        assert!(
            jwks_from_public_pem("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----")
                .is_err()
        );
    }
}
