//! Helpers shared by the server integration tests. Each test file that uses them declares
//! `mod common;`; a file uses only some of them, hence the `dead_code` allow.
//!
//! `admin_policies.rs` keeps its own `sha256_hex` on purpose: it checks the policy hash the
//! server reports against an independent computation.
#![allow(dead_code)]

use std::time::{Duration, Instant};

use attenuo_server::config::AgentConfig;

pub mod tls;

/// A free loopback port, for a listener the server binds itself (`run`, `serve`).
///
/// The port is released before the server binds it, so it must be one no other test can be given
/// in between. A `127.0.0.1:0` bind takes its port from the system's ephemeral range, and
/// the tests in this binary run in parallel and bind that way all the time: one of them
/// could get the port just released, and the request meant for this server would reach
/// that one. So the port comes from below the ephemeral range, and a counter keeps two
/// calls in this process apart.
pub fn free_port() -> std::net::SocketAddr {
    use std::sync::atomic::{AtomicU16, Ordering};
    const FIRST: u16 = 20_000;
    const COUNT: u16 = 12_000;
    static NEXT: AtomicU16 = AtomicU16::new(0);
    // Start at a different place in each process, so two test binaries do not walk the same ports.
    // The odd factor spreads neighbouring process ids apart.
    let start = u16::try_from(u64::from(std::process::id()) * 7919 % u64::from(COUNT)).unwrap_or(0);
    for _ in 0..COUNT {
        let step = NEXT.fetch_add(1, Ordering::Relaxed) % COUNT;
        let port = FIRST + (start + step) % COUNT;
        if let Ok(l) = std::net::TcpListener::bind(("127.0.0.1", port)) {
            return l.local_addr().unwrap();
        }
    }
    panic!(
        "no free loopback port between {FIRST} and {}",
        FIRST + COUNT - 1
    );
}

/// Lower-case hex SHA-256 of `s`, the form of a `secret_sha256` in the server config.
pub fn sha256_hex(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

/// One `[[agents]]` entry per id, each with the SHA-256 of `secret(id)` as its secret.
pub fn agent_configs(ids: &[&str], secret: impl Fn(&str) -> String) -> Vec<AgentConfig> {
    ids.iter()
        .map(|id| AgentConfig::with_secret_sha256(*id, sha256_hex(&secret(id))))
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
