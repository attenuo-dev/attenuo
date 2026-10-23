//! Canonical hashing helpers shared by tokens and the audit log.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// SHA-256 over the RFC 8785 canonical JSON encoding of `value` ([`crate::jcs`]),
/// hex-encoded.
///
/// The bytes depend only on the JSON value: not on map types, member order or `serde_json`'s
/// `preserve_order` feature, so a verifier in another language computes the same digest.
///
/// # Panics
///
/// If `value` has no canonical form ([`crate::jcs::JcsError`]: a NaN or infinite float, a
/// non-string map key, a duplicate member, raw JSON). Nothing decoded from JSON holds one, and
/// the types of this crate never do.
pub fn sha256_json<T: Serialize + ?Sized>(value: &T) -> String {
    let bytes = crate::jcs::to_vec(value).expect("value has a canonical JSON form");
    sha256_bytes(&bytes)
}

/// SHA-256 over raw bytes, hex-encoded.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn key_order_does_not_change_digest() {
        let mut a = BTreeMap::new();
        a.insert("b", 1);
        a.insert("a", 2);
        let mut b = BTreeMap::new();
        b.insert("a", 2);
        b.insert("b", 1);
        assert_eq!(sha256_json(&a), sha256_json(&b));
    }

    #[test]
    fn digest_is_over_the_canonical_form() {
        // Nested `serde_json` objects keep insertion order (`preserve_order` is on in this
        // workspace); the digest does not depend on it, nor on `2.0` versus `2`.
        let a: serde_json::Value = serde_json::from_str(r#"{"o":{"b":1,"a":2.0}}"#).unwrap();
        let b: serde_json::Value = serde_json::from_str(r#"{"o":{"a":2,"b":1}}"#).unwrap();
        assert_eq!(sha256_json(&a), sha256_json(&b));
        assert_eq!(sha256_json(&a), sha256_bytes(br#"{"o":{"a":2,"b":1}}"#));
    }

    #[test]
    fn known_vector() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
