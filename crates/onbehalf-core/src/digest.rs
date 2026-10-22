//! Canonical hashing helpers shared by tokens and the audit log.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// SHA-256 over the canonical JSON encoding of `value`, hex-encoded.
///
/// Canonical here means: `serde_json` with map keys sorted (the default `Map` is a `BTreeMap`),
/// no whitespace. Callers must use `BTreeMap`-backed structures for anything that must hash
/// stably; the types in this crate do.
pub fn sha256_json<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("serializable value");
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
    fn known_vector() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
