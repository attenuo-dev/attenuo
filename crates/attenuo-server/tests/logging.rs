//! The log output (`[logging]`, audit O-2 and O-3): the JSON format, and `redact_subjects`
//! across the log sites a request passes through (dev root mint, exchange, the proxy's
//! request span, the decision line), with the audit record keeping the real subject.
//!
//! The process has one global subscriber with both formats, each writing to its own shared
//! buffer, so lines from the server's worker and blocking threads are captured too. Tests in
//! this file run in parallel and share the buffers: each one looks only for its own markers.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use attenuo_policy::{ArgType, ToolAttrs};
use attenuo_proxy::testing::{spawn_router, FakeMcpServer, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::logging::{self, LogFormat};
use attenuo_server::telemetry::SubjectDigest;
use attenuo_server::Config;
use reqwest::StatusCode;
use serde_json::{json, Value};

const ADMIN: &str = "test-admin-token";
const AGENT: &str = "coder";
const AGENT_SECRET: &str = "coder-secret";

static TEXT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static JSON: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// Appends to one of the shared buffers.
struct Capture(&'static Mutex<Vec<u8>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Installs, once per process, the global subscriber with a text layer and a JSON layer built
/// the way `telemetry::init` builds its log layer, both without colour (as off a terminal).
fn install_capture() {
    use tracing_subscriber::layer::SubscriberExt;
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let subscriber = tracing_subscriber::registry()
            .with(logging::layer(LogFormat::Text, false, || Capture(&TEXT)))
            .with(logging::layer(LogFormat::Json, false, || Capture(&JSON)));
        tracing::subscriber::set_global_default(subscriber)
            .expect("no other test in this binary may install a global subscriber");
    });
}

fn captured(buf: &Mutex<Vec<u8>>) -> String {
    String::from_utf8(buf.lock().unwrap().clone()).unwrap()
}

/// Every line of the JSON buffer, parsed: a line that is not one JSON object fails the test.
fn json_lines() -> Vec<Value> {
    captured(&JSON)
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap_or_else(|e| panic!("{e}: {l}")))
        .inspect(|v| assert!(v.is_object(), "{v}"))
        .collect()
}

#[test]
fn a_json_line_is_one_object_with_timestamp_level_target_message_fields_and_spans() {
    install_capture();
    let span = tracing::info_span!("mcp_request", server = ?"github", chain_depth = 2_u64);
    span.in_scope(|| {
        tracing::info!(
            decision = "allow",
            seq = 41_u64,
            marker = "json-format-marker",
            "decision"
        );
    });
    let lines = json_lines();
    let line = lines
        .iter()
        .find(|v| v["marker"] == "json-format-marker")
        .expect("the event was written as a JSON line");
    assert!(
        line["timestamp"].as_str().is_some_and(|t| t.len() >= 20),
        "{line}"
    );
    assert_eq!(line["level"], "INFO");
    assert_eq!(line["target"], "logging");
    assert_eq!(line["message"], "decision");
    // The event's own fields, at the top level, with their types.
    assert_eq!(line["decision"], "allow");
    assert_eq!(line["seq"], 41);
    // The span the text format prints before the message: its name and fields.
    assert_eq!(line["span"]["name"], "mcp_request");
    assert_eq!(line["span"]["server"], "\"github\"");
    assert_eq!(line["span"]["chain_depth"], 2);
    assert_eq!(line["spans"][0]["name"], "mcp_request");
    // No colour codes in either format.
    assert!(!captured(&JSON).contains('\u{1b}'));
    assert!(!captured(&TEXT).contains('\u{1b}'));
    // The same event in the text layer, for comparison.
    assert!(captured(&TEXT).contains("mcp_request{server=\"github\" chain_depth=2}"));
}

/// A running server and what must outlive it.
struct Running {
    server: Spawned,
    state: Arc<attenuo_server::AppState>,
    _upstream: Spawned,
    _dir: tempfile::TempDir,
}

/// A server like the end-to-end tests' one: a fake GitHub upstream, the dev root mint and one
/// agent, with `[logging] redact_subjects` as given.
async fn start(redact: bool) -> Running {
    install_capture();
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policies.cedar");
    std::fs::write(
        &policy_path,
        "@id(\"reads\")\npermit(principal, action == Action::\"github/read_file\", resource);\n",
    )
    .unwrap();
    let upstream = FakeMcpServer::new(&["read_file"]).spawn().await.unwrap();
    let mut cfg = Config::default();
    cfg.issuer.issuer = "https://attenuo.test".into();
    cfg.issuer.audience = "attenuo-test".into();
    cfg.issuer.private_key_pem_path = Some(dir.path().join("issuer.pem"));
    cfg.policy.policies_path = Some(policy_path);
    cfg.policy.catalog = BTreeMap::from([(
        "github".to_string(),
        BTreeMap::from([(
            "read_file".to_string(),
            ToolAttrs::new()
                .with_input("repo", ArgType::String)
                .readonly(true),
        )]),
    )]);
    cfg.upstreams = vec![UpstreamConfig::new("github", upstream.url("/mcp"))];
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    cfg.agents = vec![attenuo_server::config::AgentConfig::with_secret_sha256(
        AGENT,
        {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(AGENT_SECRET.as_bytes()))
        },
    )];
    cfg.logging.redact_subjects = redact;
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    Running {
        server,
        state,
        _upstream: upstream,
        _dir: dir,
    }
}

/// Mint a root token for `subject`, exchange it to `coder`, and make one tools/call through
/// the proxy: every log site a proxied request passes through. Returns the audit entries.
async fn run_request(server: &Spawned, subject: &str) -> Vec<Value> {
    let client = reqwest::Client::new();
    let root: Value = client
        .post(server.url("/admin/root-token"))
        .bearer_auth(ADMIN)
        .json(&json!({
            "subject": subject,
            "issuer": "https://idp.example",
            "agent": "planner",
            "capabilities": ["github:read_file"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let resp = client
        .post(server.url("/token"))
        .json(&json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": root["access_token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "actor": AGENT,
            "authorization_details": [{"type": "attenuo_capabilities",
                "capabilities": [{"server": "github", "tool": "read_file"}]}],
            "client_id": AGENT,
            "client_secret": AGENT_SECRET,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let child: Value = resp.json().await.unwrap();
    let resp = client
        .post(server.url("/mcp/github"))
        .bearer_auth(child["access_token"].as_str().unwrap())
        .header("accept", "application/json, text/event-stream")
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"repo": "a/b"}}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let audit: Value = client
        .get(server.url("/admin/audit?from=1&limit=1000"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    audit["entries"].as_array().unwrap().clone()
}

/// O-3: with `redact_subjects`, the subject is in no log line of either format, the digest
/// the trace export would use is, and the audit log still names the user.
#[tokio::test]
async fn redacted_subjects_are_digests_in_every_log_line_but_not_in_the_audit_log() {
    let subject = "redact-me-7f3a@example.com";
    let run = start(true).await;
    let entries = run_request(&run.server, subject).await;
    let digest =
        SubjectDigest::derive(run.state.issuer.private_key_pem().as_bytes()).digest(subject);
    let shown = format!("hmac:{digest}");

    let text = captured(&TEXT);
    let json = captured(&JSON);
    assert!(!text.contains("redact-me-7f3a"), "{text}");
    assert!(!json.contains("redact-me-7f3a"), "{json}");
    // The dev root mint, the exchange, the decision line, and the proxy's request span.
    let mine = |m: &str| {
        json_lines()
            .into_iter()
            .filter(|v| v["message"] == m && (v["subject"] == shown.as_str()))
            .count()
    };
    assert_eq!(
        mine("dev root token minted (no user credential verified)"),
        1,
        "{json}"
    );
    assert_eq!(mine("token exchanged"), 1, "{json}");
    assert_eq!(mine("decision"), 1, "{json}");
    assert!(
        json_lines()
            .iter()
            .any(|v| v["span"]["name"] == "mcp_request" && v["span"]["subject"] == shown.as_str()),
        "{json}"
    );
    assert!(text.contains(&format!("subject={shown}")), "{text}");

    // The audit log is unchanged: the call's records (decision, result) name the subject.
    let runs: Vec<&Value> = entries
        .iter()
        .filter(|e| e["record"]["tool"] == "read_file")
        .collect();
    assert!(!runs.is_empty());
    for e in runs {
        assert_eq!(e["record"]["originating_subject"], subject, "{e}");
    }
}

/// The default is unchanged: the subject is logged as it is (Debug-formatted, SR-18).
#[tokio::test]
async fn subjects_are_logged_in_clear_by_default() {
    let subject = "clear-subject-91c2@example.com";
    let run = start(false).await;
    run_request(&run.server, subject).await;
    let text = captured(&TEXT);
    assert!(text.contains(&format!("subject=\"{subject}\"")), "{text}");
    assert!(json_lines()
        .iter()
        .any(|v| v["message"] == "decision" && v["subject"] == format!("\"{subject}\"")));
}

/// SR-122: an `[[idps]]` entry with `[idps.id_jag_ceiling]` that still accepts ID tokens starts,
/// with a warning that names it; an entry that accepts ID-JAGs only starts without one.
#[tokio::test]
async fn a_ceiling_that_id_tokens_get_past_is_warned_about_at_start_sr122() {
    install_capture();
    let build = |issuer: &str, credentials: &str| {
        let cfg = Config {
            idps: vec![toml::from_str(&format!(
                "issuer = \"{issuer}\"\n{credentials}\n\
                 [id_jag_ceiling]\nscopes = {{ \"s\" = [\"github:*\"] }}\n"
            ))
            .unwrap()],
            ..Config::default()
        };
        attenuo_server::build(&cfg).expect("a warning, not a refusal")
    };
    let warned = "https://ceiling-warned-7f3a.example";
    let quiet = "https://ceiling-quiet-7f3a.example";
    let _both = build(warned, "");
    let _jag_only = build(quiet, r#"credentials = ["id-jag"]"#);
    let lines = json_lines();
    let warning = lines
        .iter()
        .find(|v| v["message"].as_str().is_some_and(|m| m.contains(warned)))
        .expect("the start-up warning names the entry");
    assert_eq!(warning["level"], "WARN", "{warning}");
    let text = warning["message"].as_str().unwrap();
    assert!(
        text.contains("does not apply to ID tokens")
            && text.contains(r#"credentials = ["id-jag"]"#),
        "{text}"
    );
    assert!(
        !lines.iter().any(|v| v["message"]
            .as_str()
            .is_some_and(|m| m.contains(quiet) && m.contains("does not apply to ID tokens"))),
        "no warning for an entry that accepts ID-JAGs only"
    );
}
