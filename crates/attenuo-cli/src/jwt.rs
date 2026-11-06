//! Decoding delegation tokens locally, and verifying them (and approval tokens) against a
//! JWKS.

use anyhow::{anyhow, bail, Context, Result};
use attenuo_token::{ApprovalClaims, Claims, VerifiedToken, Verifier};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::Value;
use time::OffsetDateTime;

/// DER prefix of an Ed25519 SubjectPublicKeyInfo; the 32-byte key follows.
const SPKI_ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Header and claims of a token, decoded without checking the signature.
#[derive(Debug)]
pub(crate) struct Decoded {
    pub header: Value,
    pub claims: Claims,
    pub claims_json: Value,
}

/// Decode a compact JWS. **Nothing is verified**: the output is whatever the sender wrote.
pub(crate) fn decode_unverified(token: &str) -> Result<Decoded> {
    let mut parts = token.trim().split('.');
    let (Some(h), Some(p), Some(_sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        bail!("not a JWT: expected three dot-separated parts");
    };
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(h)
            .context("JWT header is not base64url")?,
    )
    .context("JWT header is not JSON")?;
    let payload = URL_SAFE_NO_PAD
        .decode(p)
        .context("JWT payload is not base64url")?;
    let claims_json: Value = serde_json::from_slice(&payload).context("JWT payload is not JSON")?;
    let claims: Claims = serde_json::from_value(claims_json.clone())
        .context("payload is not an attenuo delegation token (missing `chain`, `act`, ...)")?;
    Ok(Decoded {
        header,
        claims,
        claims_json,
    })
}

/// SubjectPublicKeyInfo PEM for the JWKS key to verify with: the one whose `kid` matches the
/// token header if there is a `kid`, else the first Ed25519 key.
pub(crate) fn pem_from_jwks(jwks: &Value, kid: Option<&str>) -> Result<String> {
    let keys = jwks["keys"]
        .as_array()
        .ok_or_else(|| anyhow!("JWKS has no `keys` array"))?;
    let jwk = keys
        .iter()
        .filter(|k| k["kty"] == "OKP" && k["crv"] == "Ed25519")
        .find(|k| kid.is_none_or(|want| k["kid"].as_str() == Some(want)))
        .ok_or_else(|| {
            anyhow!(
                "JWKS has no Ed25519 key{}",
                kid.map_or(String::new(), |k| format!(" with kid `{k}`"))
            )
        })?;
    let x = URL_SAFE_NO_PAD
        .decode(jwk["x"].as_str().ok_or_else(|| anyhow!("JWK has no `x`"))?)
        .context("JWK `x` is not base64url")?;
    if x.len() != 32 {
        bail!("JWK `x` is {} bytes, expected 32", x.len());
    }
    let mut der = SPKI_ED25519_PREFIX.to_vec();
    der.extend_from_slice(&x);
    let b64 = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for line in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line)?);
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    Ok(pem)
}

/// Verify `token` with the JWKS key. `issuer` and `audience` default to the token's own claims,
/// so by default this proves "signed by this server's key, unexpired, chain valid", not "issued
/// for a particular audience"; pass them to pin those.
pub(crate) fn verify_with_jwks(
    token: &str,
    decoded: &Decoded,
    jwks: &Value,
    issuer: Option<&str>,
    audience: Option<&str>,
    now: OffsetDateTime,
) -> Result<VerifiedToken> {
    let pem = pem_from_jwks(jwks, decoded.header["kid"].as_str())?;
    let max_depth = decoded.claims.chain.hops.len().max(1);
    let mut verifier = Verifier::from_public_pem(
        issuer.unwrap_or(&decoded.claims.iss),
        audience.unwrap_or(&decoded.claims.aud),
        max_depth.max(attenuo_core::chain::DEFAULT_MAX_DEPTH),
        &pem,
    )?;
    // During a key rotation the originating-user signature may come from a retired key that
    // the JWKS still lists, so trust every key it publishes.
    for other in jwks["keys"].as_array().into_iter().flatten() {
        if let Some(k) = other["kid"].as_str() {
            if let Ok(extra) = pem_from_jwks(jwks, Some(k)) {
                verifier = verifier.with_public_pem(&extra)?;
            }
        }
    }
    Ok(verifier.verify(token, now)?)
}

/// A verifier for `iss`/`aud` trusting every Ed25519 key of `jwks`, the one named `kid` first.
fn jwks_verifier(
    jwks: &Value,
    kid: Option<&str>,
    issuer: &str,
    audience: &str,
) -> Result<Verifier> {
    let pem = pem_from_jwks(jwks, kid)?;
    let mut verifier = Verifier::from_public_pem(
        issuer,
        audience,
        attenuo_core::chain::DEFAULT_MAX_DEPTH,
        &pem,
    )?;
    for other in jwks["keys"].as_array().into_iter().flatten() {
        if let Some(k) = other["kid"].as_str() {
            if let Ok(extra) = pem_from_jwks(jwks, Some(k)) {
                verifier = verifier.with_public_pem(&extra)?;
            }
        }
    }
    Ok(verifier)
}

/// The binding an approval token is checked against; `None` members are not checked.
#[derive(Debug, Default)]
pub(crate) struct ApprovalBinding<'a> {
    pub chain_id: Option<&'a str>,
    pub lease: Option<&'a str>,
    pub call_hash: Option<&'a str>,
    /// `Some(None)`: the hop is a bearer hop, so the token must carry no `cnf`.
    pub jkt: Option<Option<&'a str>>,
}

/// Header and claims of an approval token, decoded without checking anything.
pub(crate) fn decode_approval_unverified(token: &str) -> Result<(Value, Value)> {
    let mut parts = token.trim().split('.');
    let (Some(h), Some(p), Some(_sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        bail!("not a JWT: expected three dot-separated parts");
    };
    let decode = |part: &str, what: &str| -> Result<Value> {
        serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(part)
                .with_context(|| format!("JWT {what} is not base64url"))?,
        )
        .with_context(|| format!("JWT {what} is not JSON"))
    };
    Ok((decode(h, "header")?, decode(p, "payload")?))
}

/// Verify an approval token with the JWKS keys: signature, `typ`, `iss`, `aud` (both default to
/// the token's own), `exp`, then each binding member that is given.
pub(crate) fn verify_approval_with_jwks(
    token: &str,
    jwks: &Value,
    issuer: Option<&str>,
    audience: Option<&str>,
    binding: &ApprovalBinding<'_>,
    now: OffsetDateTime,
) -> Result<ApprovalClaims> {
    let (header, claims) = decode_approval_unverified(token)?;
    let own = |k: &str| claims[k].as_str().unwrap_or_default().to_string();
    let verifier = jwks_verifier(
        jwks,
        header["kid"].as_str(),
        issuer.map_or_else(|| own("iss"), str::to_owned).as_str(),
        audience.map_or_else(|| own("aud"), str::to_owned).as_str(),
    )?;
    let c = verifier.verify_approval(token.trim(), now)?;
    let differs = |want: Option<&str>, got: &str, claim: &str| -> Result<()> {
        match want {
            Some(w) if w != got => bail!("`{claim}` is `{got}`, expected `{w}`"),
            _ => Ok(()),
        }
    };
    differs(binding.chain_id, &c.chain_id, "chain_id")?;
    differs(binding.lease, &c.lease, "lease")?;
    differs(binding.call_hash, &c.ch, "ch")?;
    if let Some(want) = binding.jkt {
        let got = c.cnf.as_ref().map(|k| k.jkt.as_str());
        if got != want {
            bail!(
                "`cnf.jkt` is {}, expected {}",
                got.unwrap_or("absent"),
                want.unwrap_or("absent")
            );
        }
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use attenuo_core::{AgentId, Capability, CapabilitySet, OriginatingUser};
    use attenuo_token::{Issuer, IssuerConfig};
    use serde_json::json;
    use time::Duration;

    fn issuer() -> Issuer {
        Issuer::generate(IssuerConfig {
            issuer: "http://ob".into(),
            audience: "attenuo".into(),
            max_depth: 4,
            default_ttl: Duration::minutes(5),
        })
    }

    fn jwks_for(issuer: &Issuer) -> Value {
        let pem = issuer.public_key_pem();
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = STANDARD.decode(b64).unwrap();
        json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": issuer.key_id(),
                         "x": URL_SAFE_NO_PAD.encode(&der[12..])}]})
    }

    fn mint(issuer: &Issuer) -> String {
        let now = OffsetDateTime::now_utc();
        let user = OriginatingUser {
            subject: "alice".into(),
            issuer: "https://idp.example".into(),
            authenticated_at: now,
            attributes: Default::default(),
        };
        issuer
            .issue_root(
                user,
                AgentId::new("planner"),
                CapabilitySet::from_iter([Capability::new("github", "*")]),
                None,
                now,
            )
            .unwrap()
            .token
    }

    #[test]
    fn decode_and_verify_round_trip() {
        let issuer = issuer();
        let token = mint(&issuer);
        let d = decode_unverified(&token).unwrap();
        assert_eq!(d.claims.sub, "alice");
        assert_eq!(d.header["typ"], "attenuo+jwt");
        let now = OffsetDateTime::now_utc();
        let v = verify_with_jwks(&token, &d, &jwks_for(&issuer), None, None, now).unwrap();
        assert_eq!(v.chain.depth(), 1);
        // Pinning a different audience fails.
        assert!(
            verify_with_jwks(&token, &d, &jwks_for(&issuer), None, Some("other"), now).is_err()
        );
    }

    #[test]
    fn verify_rejects_other_key_and_tampering() {
        let issuer = issuer();
        let token = mint(&issuer);
        let d = decode_unverified(&token).unwrap();
        let now = OffsetDateTime::now_utc();
        let other = jwks_for(&self::issuer());
        assert!(verify_with_jwks(&token, &d, &other, None, None, now).is_err());
        // Flip a payload byte: decoding may still work, verification must not.
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        let mut payload = URL_SAFE_NO_PAD.decode(&parts[1]).unwrap();
        let s = String::from_utf8(payload.clone())
            .unwrap()
            .replace("alice", "mallo");
        payload = s.into_bytes();
        parts[1] = URL_SAFE_NO_PAD.encode(payload);
        let forged = parts.join(".");
        let fd = decode_unverified(&forged).unwrap();
        assert_eq!(fd.claims.sub, "mallo");
        assert!(verify_with_jwks(&forged, &fd, &jwks_for(&issuer), None, None, now).is_err());
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode_unverified("nope").is_err());
        assert!(decode_unverified("a.b.c").is_err());
        assert!(decode_unverified("a.b.c.d").is_err());
        let not_ob = format!(
            "{}.{}.sig",
            URL_SAFE_NO_PAD.encode(b"{}"),
            URL_SAFE_NO_PAD.encode(b"{\"sub\":\"x\"}")
        );
        assert!(decode_unverified(&not_ob).is_err());
    }

    #[test]
    fn jwks_selection() {
        let i = issuer();
        let j = jwks_for(&i);
        assert!(pem_from_jwks(&j, Some(&i.key_id())).is_ok());
        assert!(pem_from_jwks(&j, Some("zzz")).is_err());
        assert!(pem_from_jwks(&json!({"keys": []}), None).is_err());
        assert!(pem_from_jwks(&json!({}), None).is_err());
    }
}
