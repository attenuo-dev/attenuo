//! Ed25519 key handling: generation, PEM import/export, and detached signatures.
//!
//! Tokens are signed with EdDSA (Ed25519) through `jsonwebtoken`; the same key signs the
//! originating-user block. Private keys are stored and exchanged as PKCS#8 (`PRIVATE KEY` PEM),
//! public keys as SubjectPublicKeyInfo (`PUBLIC KEY` PEM), which is what `openssl genpkey
//! -algorithm ed25519` and `openssl pkey -pubout` produce.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

use crate::error::TokenError;

/// DER prefix of a SubjectPublicKeyInfo for an Ed25519 key (RFC 8410 §4): a 44-byte structure
/// whose last 32 bytes are the raw public key.
const SPKI_ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// An Ed25519 signing key together with its PKCS#8 encoding.
pub(crate) struct SigningKey {
    pkcs8_der: Vec<u8>,
    pair: Ed25519KeyPair,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey").finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Generate a fresh random key pair.
    pub(crate) fn generate() -> Result<Self, TokenError> {
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| TokenError::Key("failed to generate Ed25519 key".into()))?;
        Self::from_pkcs8_der(doc.as_ref().to_vec())
    }

    /// Parse a PKCS#8 `PRIVATE KEY` PEM (v1 or v2).
    pub(crate) fn from_pem(pem: &str) -> Result<Self, TokenError> {
        Self::from_pkcs8_der(pem_decode(pem, "PRIVATE KEY")?)
    }

    fn from_pkcs8_der(pkcs8_der: Vec<u8>) -> Result<Self, TokenError> {
        let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&pkcs8_der)
            .map_err(|e| TokenError::Key(format!("invalid Ed25519 PKCS#8 key: {e}")))?;
        Ok(Self { pkcs8_der, pair })
    }

    /// The PKCS#8 DER document, as `jsonwebtoken::EncodingKey::from_ed_der` expects it.
    pub(crate) fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8_der
    }

    /// PKCS#8 `PRIVATE KEY` PEM. Handle with care: this is the issuer's secret.
    pub(crate) fn private_pem(&self) -> String {
        pem_encode(&self.pkcs8_der, "PRIVATE KEY")
    }

    /// The public half.
    pub(crate) fn public_key(&self) -> PublicKey {
        let mut raw = [0u8; 32];
        raw.copy_from_slice(self.pair.public_key().as_ref());
        PublicKey { raw }
    }

    /// Detached Ed25519 signature over `message`, base64url (no padding).
    pub(crate) fn sign_detached(&self, message: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(self.pair.sign(message).as_ref())
    }
}

/// An Ed25519 public key (raw 32 bytes).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PublicKey {
    raw: [u8; 32],
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", URL_SAFE_NO_PAD.encode(self.raw))
    }
}

impl PublicKey {
    /// Parse a SubjectPublicKeyInfo `PUBLIC KEY` PEM holding an Ed25519 key.
    pub(crate) fn from_pem(pem: &str) -> Result<Self, TokenError> {
        let der = pem_decode(pem, "PUBLIC KEY")?;
        if der.len() != 44 || der[..12] != SPKI_ED25519_PREFIX {
            return Err(TokenError::Key("public key is not an Ed25519 SPKI".into()));
        }
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&der[12..]);
        Ok(Self { raw })
    }

    /// SubjectPublicKeyInfo `PUBLIC KEY` PEM.
    pub(crate) fn to_pem(&self) -> String {
        let mut der = SPKI_ED25519_PREFIX.to_vec();
        der.extend_from_slice(&self.raw);
        pem_encode(&der, "PUBLIC KEY")
    }

    /// Raw 32-byte key, as `jsonwebtoken::DecodingKey::from_ed_der` expects it.
    pub(crate) fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Verify a detached signature produced by [`SigningKey::sign_detached`].
    pub(crate) fn verify_detached(&self, message: &[u8], signature_b64: &str) -> bool {
        let Ok(sig) = URL_SAFE_NO_PAD.decode(signature_b64) else {
            return false;
        };
        UnparsedPublicKey::new(&ED25519, &self.raw)
            .verify(message, &sig)
            .is_ok()
    }
}

fn pem_encode(der: &[u8], label: &str) -> String {
    let b64 = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn pem_decode(pem: &str, label: &str) -> Result<Vec<u8>, TokenError> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let body = pem
        .split_once(&begin)
        .and_then(|(_, rest)| rest.split_once(&end))
        .map(|(body, _)| body)
        .ok_or_else(|| TokenError::Key(format!("expected a `{label}` PEM block")))?;
    let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD
        .decode(b64)
        .map_err(|e| TokenError::Key(format!("invalid PEM base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_pem_round_trip_keeps_public_key() {
        let k = SigningKey::generate().unwrap();
        let back = SigningKey::from_pem(&k.private_pem()).unwrap();
        assert_eq!(k.public_key(), back.public_key());
    }

    #[test]
    fn public_pem_round_trip() {
        let k = SigningKey::generate().unwrap();
        let pk = k.public_key();
        let pem = pk.to_pem();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert_eq!(PublicKey::from_pem(&pem).unwrap(), pk);
        // jsonwebtoken's own PEM parser accepts it too
        jsonwebtoken::DecodingKey::from_ed_pem(pem.as_bytes()).unwrap();
    }

    #[test]
    fn detached_signature_verifies_only_for_same_message_and_key() {
        let k = SigningKey::generate().unwrap();
        let other = SigningKey::generate().unwrap();
        let sig = k.sign_detached(b"hello");
        assert!(k.public_key().verify_detached(b"hello", &sig));
        assert!(!k.public_key().verify_detached(b"hellp", &sig));
        assert!(!other.public_key().verify_detached(b"hello", &sig));
        assert!(!k.public_key().verify_detached(b"hello", "not base64!"));
    }

    #[test]
    fn rejects_wrong_pem_label_and_garbage() {
        let k = SigningKey::generate().unwrap();
        assert!(matches!(
            PublicKey::from_pem(&k.private_pem()),
            Err(TokenError::Key(_))
        ));
        assert!(matches!(
            SigningKey::from_pem("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"),
            Err(TokenError::Key(_))
        ));
    }
}
