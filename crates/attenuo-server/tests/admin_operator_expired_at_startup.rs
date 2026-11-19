//! An `[[admin.operators]]` entry that has already expired when the server starts: the server
//! starts, logs a warning naming the operator, and refuses its token as expired (ADR-0016).
//!
//! This test is alone in its test binary on purpose. It captures the warning with a
//! subscriber that is the default for the test's thread only. `tracing` caches, per call site
//! and for the whole process, whether any subscriber wants that call site. When another test
//! of the same binary reaches the same `warn!` on its own thread (any test that builds a
//! server with an expired operator) at the moment this test installs its subscriber, the
//! cache can be left at "nobody is interested" and the warning is skipped. That happened about
//! once in 200 runs under load in `admin_operators.rs`. With one test in the process, no other
//! thread reaches the call site.

use std::path::Path;

use attenuo_proxy::testing::spawn_router;
use attenuo_server::operators::token_sha256_hex;
use attenuo_server::Config;
use reqwest::StatusCode;
use serde_json::Value;

const LEGACY: &str = "legacy-admin-token-0123456789abcdef";

/// One `[[admin.operators]]` entry as TOML.
fn entry(name: &str, token: &str, role: &str, expires_at: Option<&str>) -> String {
    let mut s = format!(
        "[[admin.operators]]\nname = \"{name}\"\ntoken_sha256 = \"{}\"\nrole = \"{role}\"\n",
        token_sha256_hex(token)
    );
    if let Some(at) = expires_at {
        s.push_str(&format!("expires_at = \"{at}\"\n"));
    }
    s
}

/// Write `<dir>/attenuo.toml` with `[admin] token` (when `legacy` is set) and `operators`
/// (TOML entries), and return its path. The file is replaced in one rename, so a reload never
/// reads half of it.
fn write_config(dir: &Path, legacy: Option<&str>, operators: &str) -> std::path::PathBuf {
    let path = dir.join("attenuo.toml");
    let tmp = dir.join("attenuo.toml.tmp");
    let token = legacy.map_or(String::new(), |t| format!("token = \"{t}\"\n"));
    std::fs::write(
        &tmp,
        format!(
            "[issuer]\nprivate_key_pem_path = \"{}\"\n\n[audit]\nsqlite_path = \"{}\"\n\n\
             [admin]\n{token}\n{operators}",
            dir.join("keys/issuer.pem").display(),
            dir.join("audit.sqlite").display(),
        ),
    )
    .unwrap();
    std::fs::rename(&tmp, &path).unwrap();
    path
}

async fn whoami(client: &reqwest::Client, base: &str, bearer: &str) -> (StatusCode, Value) {
    let resp = client
        .get(format!("{base}/admin/whoami"))
        .bearer_auth(bearer)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// A `MakeWriter` that keeps what is logged.
#[derive(Clone, Default)]
struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// An entry that has already expired when the server starts does not stop it: a warning
/// names the operator, and its token is refused as expired.
#[tokio::test]
async fn an_expired_entry_at_startup_warns_and_does_not_authenticate() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        Some(LEGACY),
        &(entry("old", "old-token", "admin", Some("2020-01-01T00:00:00Z"))
            + &entry("ada", "ada-token", "admin", None)),
    );
    let cfg = Config::load(&path).unwrap();
    let logs = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .finish();
    let (router, _state) =
        tracing::subscriber::with_default(subscriber, || attenuo_server::build(&cfg)).unwrap();
    let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    let line = logged
        .lines()
        .find(|l| l.contains("expired"))
        .unwrap_or_else(|| panic!("no warning: {logged}"));
    assert!(line.contains("WARN"), "{line}");
    assert!(line.contains("`old`"), "{line}");
    assert!(line.contains("2020-01-01T00:00:00Z"), "{line}");
    assert!(!logged.contains("ada"), "{logged}");

    let server = spawn_router(router).await.unwrap();
    let client = reqwest::Client::new();
    let (status, v) = whoami(&client, &server.url(""), "old-token").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(v["code"], "admin_credential_expired");
    assert_eq!(
        whoami(&client, &server.url(""), "ada-token").await.0,
        StatusCode::OK
    );
}
