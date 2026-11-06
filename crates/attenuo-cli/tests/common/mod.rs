//! Helpers shared by the CLI integration tests. Each test file that uses them declares
//! `mod common;`; a file uses only some of them, hence the `dead_code` allow.
#![allow(dead_code)]

use std::process::Command;

/// The `attenuo` binary, with the environment variables that would supply a token, a secret,
/// a server URL or a DPoP key removed, so a developer's shell cannot change a test's outcome.
pub fn attenuo() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_attenuo"));
    for var in [
        "ATTENUO_ADMIN_TOKEN",
        "ATTENUO_CLIENT_SECRET",
        "ATTENUO_TOKEN",
        "ATTENUO_SERVER",
        "ATTENUO_DPOP_KEY",
    ] {
        c.env_remove(var);
    }
    c
}

/// Lower-case hex SHA-256 of `s`, the form of a `secret_sha256` in the server config.
pub fn sha256_hex(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}
