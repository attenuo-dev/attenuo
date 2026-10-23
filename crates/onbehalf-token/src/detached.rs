//! Domain-separated detached signatures, for things that are signed but are not tokens
//! (audit checkpoints, see `onbehalf-audit`).
//!
//! The signed message is `len(context) as u32 big-endian || context || payload`, so a signature
//! made for one `context` string never verifies under another, and never verifies as a token
//! signature or as the originating-user signature (which has no such prefix). The key is the
//! issuer's own Ed25519 key, so a verifier needs nothing beyond the JWKS the server already
//! publishes.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::signature::{UnparsedPublicKey, ED25519};

use crate::keys::SigningKey;

fn frame(context: &str, payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + context.len() + payload.len());
    msg.extend_from_slice(&(context.len() as u32).to_be_bytes());
    msg.extend_from_slice(context.as_bytes());
    msg.extend_from_slice(payload);
    msg
}

/// A cloneable handle that signs with the issuer's current key (see `Issuer::detached_signer`).
#[derive(Clone)]
pub struct DetachedSigner {
    key: Arc<SigningKey>,
}

impl std::fmt::Debug for DetachedSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetachedSigner")
            .field("kid", &self.kid())
            .finish()
    }
}

impl DetachedSigner {
    pub(crate) fn new(key: Arc<SigningKey>) -> Self {
        Self { key }
    }

    /// `kid` of the signing key, as it appears in the JWKS.
    pub fn kid(&self) -> String {
        self.key.public_key().kid()
    }

    /// Sign `payload` under `context`. Returns base64url (no padding).
    pub fn sign(&self, context: &str, payload: &[u8]) -> String {
        self.key.sign_detached(&frame(context, payload))
    }
}

/// Verify a signature made by [`DetachedSigner::sign`] against a raw 32-byte Ed25519 public key
/// (the `x` of a JWKS entry, base64url-decoded).
pub fn verify_detached(
    public_key: &[u8],
    context: &str,
    payload: &[u8],
    signature_b64: &str,
) -> bool {
    let Ok(sig) = URL_SAFE_NO_PAD.decode(signature_b64) else {
        return false;
    };
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&frame(context, payload), &sig)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> (DetachedSigner, Vec<u8>) {
        let key = Arc::new(SigningKey::generate().unwrap());
        let raw = key.public_key().raw().to_vec();
        (DetachedSigner::new(key), raw)
    }

    #[test]
    fn signature_is_bound_to_context_payload_and_key() {
        let (s, pk) = signer();
        let (_, other) = signer();
        let sig = s.sign("ctx-a", b"payload");
        assert!(verify_detached(&pk, "ctx-a", b"payload", &sig));
        assert!(!verify_detached(&pk, "ctx-b", b"payload", &sig));
        assert!(!verify_detached(&pk, "ctx-a", b"payloae", &sig));
        assert!(!verify_detached(&other, "ctx-a", b"payload", &sig));
        assert!(!verify_detached(&pk, "ctx-a", b"payload", "***"));
    }

    #[test]
    fn context_and_payload_cannot_trade_bytes() {
        let (s, pk) = signer();
        let sig = s.sign("ab", b"c");
        assert!(!verify_detached(&pk, "a", b"bc", &sig));
    }
}
