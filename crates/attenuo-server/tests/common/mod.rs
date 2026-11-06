//! Helpers shared by the server integration tests. Each test file that uses them declares
//! `mod common;`; a file uses only some of them, hence the `dead_code` allow.
//!
//! `admin_policies.rs` keeps its own `sha256_hex` on purpose: it checks the policy hash the
//! server reports against an independent computation.
#![allow(dead_code)]

use std::time::{Duration, Instant};

use attenuo_server::config::AgentConfig;

/// Lower-case hex SHA-256 of `s`, the form of a `secret_sha256` in the server config.
pub fn sha256_hex(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

/// One `[[agents]]` entry per id, each with the SHA-256 of `secret(id)` as its secret.
pub fn agent_configs(ids: &[&str], secret: impl Fn(&str) -> String) -> Vec<AgentConfig> {
    ids.iter()
        .map(|id| AgentConfig {
            id: (*id).into(),
            secret_sha256: sha256_hex(&secret(id)),
        })
        .collect()
}

/// Polls `f` every 10 ms until it is true; panics after 20 s.
pub async fn wait_for(mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(20);
    while !f() {
        assert!(Instant::now() < end, "timed out");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
