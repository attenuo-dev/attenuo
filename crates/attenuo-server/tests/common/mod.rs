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

/// A server run the way `serve` runs one, through [`attenuo_server::run`], on `127.0.0.1:0`,
/// for tests that stop a server and start another on the same database.
pub struct Running {
    addr: std::net::SocketAddr,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Running {
    /// Run `router`, built over `state` from `cfg`.
    pub async fn start(
        cfg: attenuo_server::Config,
        state: std::sync::Arc<attenuo_server::AppState>,
        router: axum::Router,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            attenuo_server::run(&cfg, state, router, listener, async move {
                let _ = stopped.await;
            })
            .await
        });
        Self { addr, stop, task }
    }

    /// `http://{addr}{path}`.
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    /// Stop as `serve` does after a signal, wait until `run` has returned, drop `state` (the
    /// caller's last reference) and wait until the state is gone, which releases the database.
    /// Nothing is retried: [`attenuo_server::AppState::released`] resolves when the state is
    /// dropped, and the deadline only turns a server that never lets go into a failure.
    pub async fn stop(self, state: std::sync::Arc<attenuo_server::AppState>) {
        let released = state.released();
        let _ = self.stop.send(());
        self.task.await.unwrap().unwrap();
        drop(state);
        tokio::time::timeout(Duration::from_secs(10), released)
            .await
            .expect("the stopped server still holds its state, and the database");
    }
}
