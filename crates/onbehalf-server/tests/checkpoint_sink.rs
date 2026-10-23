//! `[audit.sink]` end to end (SR-21): signed checkpoints leave the host through a webhook, a
//! JSON Lines file or an S3-compatible PUT, and the shipped copies cross-check an export.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::routing::{post, put};
use axum::Router;
use onbehalf_audit::{cross_check, parse_export, parse_shipped, ShippedCheckpoint};
use onbehalf_proxy::testing::{spawn_router, Spawned};
use onbehalf_server::config::{SinkKind, SinkSection};
use onbehalf_server::{AppState, Config};
use serde_json::{json, Value};

const ADMIN: &str = "admin";
const PUBLIC_URL: &str = "http://127.0.0.1:1";

/// A receiver that answers 503 to the first `fail_first` requests, then 200, and keeps what it
/// was sent.
#[derive(Default)]
struct Receiver {
    fail_first: usize,
    seen: AtomicUsize,
    got: Mutex<Vec<(String, HeaderMap, Bytes)>>,
}

async fn receive(
    State(r): State<Arc<Receiver>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let n = r.seen.fetch_add(1, Ordering::SeqCst);
    if n < r.fail_first {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    r.got
        .lock()
        .unwrap()
        .push((uri.path().to_string(), headers, body));
    StatusCode::OK
}

async fn receiver(fail_first: usize) -> (Arc<Receiver>, Spawned) {
    let r = Arc::new(Receiver {
        fail_first,
        ..Default::default()
    });
    let app = Router::new()
        .route("/hook", post(receive))
        .route("/{bucket}/{*key}", put(receive))
        .with_state(r.clone());
    (r, spawn_router(app).await.unwrap())
}

struct Harness {
    server: Spawned,
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

fn config(dir: &tempfile::TempDir, sink: SinkSection) -> Config {
    let mut cfg = Config::default();
    cfg.audit.sqlite_path = dir
        .path()
        .join("audit.sqlite")
        .to_string_lossy()
        .into_owned();
    cfg.audit.checkpoint_every = 2;
    cfg.audit.sink = Some(sink);
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    cfg.server.public_url = Some(PUBLIC_URL.into());
    cfg
}

async fn start(dir: tempfile::TempDir, cfg: Config) -> Harness {
    let (router, state) = onbehalf_server::build(&cfg).unwrap();
    Harness {
        server: spawn_router(router).await.unwrap(),
        state,
        _dir: dir,
    }
}

impl Harness {
    /// One root token: two audit entries (the issuance and the admin action).
    async fn mint(&self) {
        let r = reqwest::Client::new()
            .post(self.server.url("/admin/root-token"))
            .bearer_auth(ADMIN)
            .json(&json!({"subject": "alice", "issuer": "https://idp.example",
                          "agent": "planner", "capabilities": ["github:*"]}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }

    async fn export(&self) -> String {
        reqwest::Client::new()
            .get(self.server.url("/admin/audit/export"))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    }

    async fn readyz(&self) -> (StatusCode, Value) {
        let r = reqwest::get(self.server.url("/readyz")).await.unwrap();
        (r.status(), r.json().await.unwrap())
    }
}

async fn wait_for(mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(20);
    while !f() {
        assert!(Instant::now() < end, "timed out");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn fast(mut s: SinkSection) -> SinkSection {
    s.initial_backoff_ms = 5;
    s.max_backoff_seconds = 1;
    s.timeout_seconds = 5;
    s
}

#[tokio::test]
async fn webhook_sink_ships_each_checkpoint_with_retries_sr21() {
    let (rx, rx_server) = receiver(2).await;
    let dir = tempfile::tempdir().unwrap();
    let mut sink = fast(SinkSection::new(SinkKind::Webhook));
    sink.url = Some(rx_server.url("/hook"));
    sink.bearer_token = Some("sink-secret".into());
    let cfg = config(&dir, sink);
    let h = start(dir, cfg).await;
    for _ in 0..2 {
        h.mint().await;
    }
    // Checkpoints at seq 2 and 4; the first two POSTs were refused and retried.
    wait_for(|| rx.got.lock().unwrap().len() == 2).await;
    assert!(rx.seen.load(Ordering::SeqCst) >= 4);

    let got = rx.got.lock().unwrap().clone();
    let mut shipped_text = String::new();
    for (i, (path, headers, body)) in got.iter().enumerate() {
        assert_eq!(path, "/hook");
        assert_eq!(headers["authorization"], "Bearer sink-secret");
        assert_eq!(headers["content-type"], "application/json");
        let s: ShippedCheckpoint = serde_json::from_slice(body).unwrap();
        assert_eq!(s.checkpoint.seq, 2 * (i as u64 + 1), "in order");
        assert_eq!(s.inconsistency(), None);
        assert_eq!(s.public_url.as_deref(), Some(PUBLIC_URL));
        assert_eq!(
            (s.kid.as_str(), s.signature.as_str()),
            (s.checkpoint.kid.as_str(), s.checkpoint.signature.as_str())
        );
        assert_eq!(
            headers["x-onbehalf-checkpoint-seq"],
            s.checkpoint.seq.to_string().as_str()
        );
        assert_eq!(
            headers["x-onbehalf-checkpoint-sha256"],
            s.checkpoint_sha256.as_str()
        );
        h.state.checkpoint_keys.verify(&s.checkpoint).unwrap();
        // The body is canonical JSON, so it is also a valid line of a shipped file.
        assert_eq!(body.as_ref(), s.to_canonical_json().as_slice());
        shipped_text.push_str(&s.to_line());
    }

    // The live export agrees with what was shipped.
    let export = parse_export(&h.export().await).unwrap();
    let report = cross_check(
        &export,
        &parse_shipped(&shipped_text).unwrap(),
        &h.state.checkpoint_keys,
    );
    assert!(report.ok, "{report:?}");
    assert_eq!((report.in_range, report.matched), (2, 2));

    let (code, body) = h.readyz().await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(
        body,
        json!({"ready": true, "degraded": false,
               "checks": {"audit": "ok", "leases": "ok", "checkpoint_sink": "ok"}})
    );
    let metrics = h.state.metrics.render();
    assert!(
        metrics.contains("onbehalf_audit_sink_delivered_total 2\n"),
        "{metrics}"
    );
    assert!(
        metrics.contains("onbehalf_audit_sink_failures_total 2\n"),
        "{metrics}"
    );
    assert!(metrics.contains("onbehalf_audit_sink_dropped_total 0\n"));
}

#[tokio::test]
async fn a_failing_sink_degrades_readyz_and_counts_drops_sr21() {
    // Nothing listens here: every delivery fails.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/hook", closed.local_addr().unwrap());
    drop(closed);
    let make = |fail_readiness: bool| {
        let mut sink = fast(SinkSection::new(SinkKind::Webhook));
        sink.url = Some(url.clone());
        sink.queue_capacity = 1;
        sink.fail_readiness = fail_readiness;
        sink
    };

    // Default: degraded, still ready.
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir, make(false));
    cfg.audit.checkpoint_every = 1;
    let h = start(dir, cfg).await;
    for _ in 0..4 {
        h.mint().await;
    }
    let sink = h.state.checkpoint_sink.as_ref().unwrap();
    wait_for(|| sink.status().failing_for.is_some()).await;
    let (code, body) = h.readyz().await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(body["degraded"], true);
    assert_eq!(body["checks"]["checkpoint_sink"], "degraded");
    let metrics = h.state.metrics.render();
    // Eight checkpoints: seq 1 is in flight, the queue holds the newest, six were pushed out.
    assert!(
        metrics.contains("onbehalf_audit_sink_dropped_total 6\n"),
        "{metrics}"
    );
    assert!(metrics.contains("onbehalf_audit_sink_queue_depth 1\n"));
    assert!(!metrics.contains("onbehalf_audit_sink_oldest_undelivered_timestamp_seconds 0\n"));

    // fail_readiness: 503.
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir, make(true));
    cfg.audit.checkpoint_every = 1;
    let h = start(dir, cfg).await;
    for _ in 0..3 {
        h.mint().await;
    }
    let (code, body) = h.readyz().await;
    assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body,
        json!({"ready": false, "degraded": true,
               "checks": {"audit": "ok", "leases": "ok", "checkpoint_sink": "degraded"}})
    );
}

#[tokio::test]
async fn file_sink_appends_jsonl_that_cross_checks_the_export_sr21() {
    let dir = tempfile::tempdir().unwrap();
    let anchor = tempfile::tempdir().unwrap();
    let path = anchor.path().join("checkpoints.jsonl");
    let mut sink = SinkSection::new(SinkKind::File);
    sink.path = Some(path.clone());
    let cfg = config(&dir, sink);
    let h = start(dir, cfg).await;
    for _ in 0..3 {
        h.mint().await;
    }
    let sink = h.state.checkpoint_sink.as_ref().unwrap();
    wait_for(|| sink.handle().delivered() == 3).await;
    let text = std::fs::read_to_string(&path).unwrap();
    let lines = parse_shipped(&text).unwrap();
    assert_eq!(
        lines.iter().map(|l| l.checkpoint.seq).collect::<Vec<_>>(),
        vec![2, 4, 6]
    );
    let export = parse_export(&h.export().await).unwrap();
    let report = cross_check(&export, &lines, &h.state.checkpoint_keys);
    assert!(report.ok && report.matched == 3, "{report:?}");
}

#[tokio::test]
async fn s3_sink_puts_sigv4_signed_objects_sr21() {
    let (rx, rx_server) = receiver(1).await;
    let dir = tempfile::tempdir().unwrap();
    let mut sink = fast(SinkSection::new(SinkKind::S3));
    sink.endpoint = Some(rx_server.url(""));
    sink.bucket = Some("audit-anchor".into());
    sink.region = Some("eu-west-1".into());
    sink.access_key_id = Some("AKIDTEST".into());
    sink.secret_access_key = Some("secret/key".into());
    let cfg = config(&dir, sink);
    let h = start(dir, cfg).await;
    h.mint().await;
    wait_for(|| rx.got.lock().unwrap().len() == 1).await;
    let (path, headers, body) = rx.got.lock().unwrap()[0].clone();
    let s: ShippedCheckpoint = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        path,
        format!(
            "/audit-anchor/onbehalf/checkpoints/{:020}-{}.json",
            s.checkpoint.seq,
            &s.checkpoint_sha256[..16]
        )
    );
    let payload_hash = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&body));
    assert_eq!(headers["x-amz-content-sha256"], payload_hash.as_str());
    // Recompute the signature from what arrived: the server signed exactly these headers.
    let h_ = |n: &str| headers[n].to_str().unwrap().to_string();
    let signed = vec![
        ("content-type".to_string(), h_("content-type")),
        ("host".to_string(), h_("host")),
        (
            "x-amz-content-sha256".to_string(),
            h_("x-amz-content-sha256"),
        ),
        ("x-amz-date".to_string(), h_("x-amz-date")),
    ];
    let creds = onbehalf_server::sink::S3Credentials {
        access_key_id: "AKIDTEST".into(),
        secret_access_key: "secret/key".into(),
        session_token: None,
    };
    let expected =
        onbehalf_server::sink::sigv4_authorization(&onbehalf_server::sink::SigV4Request {
            method: "PUT",
            canonical_uri: &path,
            canonical_query: "",
            headers: &signed,
            payload_sha256: &payload_hash,
            region: "eu-west-1",
            service: "s3",
            amz_date: &h_("x-amz-date"),
            creds: &creds,
        });
    assert_eq!(h_("authorization"), expected);
    assert!(expected.starts_with("AWS4-HMAC-SHA256 Credential=AKIDTEST/"));
    assert!(expected.contains("/eu-west-1/s3/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, "));
}

#[test]
fn sink_config_parses_from_toml_and_is_validated_at_startup() {
    let cfg = Config::from_toml(
        r#"
[audit.sink]
kind = "webhook"
url = "https://anchor.example/ckpt"
max_lag_seconds = 60
queue_capacity = 8
"#,
    )
    .unwrap();
    let s = cfg.audit.sink.as_ref().unwrap();
    assert_eq!(
        (s.kind, s.max_lag_seconds, s.queue_capacity),
        (SinkKind::Webhook, 60, 8)
    );
    assert_eq!(
        (
            s.initial_backoff_ms,
            s.max_backoff_seconds,
            s.fail_readiness
        ),
        (500, 60, false)
    );
    assert!(Config::from_toml("[audit.sink]\nkind = \"ftp\"\n").is_err());
    assert!(Config::from_toml("[audit.sink]\nkind = \"file\"\nbogus = 1\n").is_err());
    // A file sink without a path fails at startup, not at the first checkpoint.
    let bad = Config::from_toml("[audit.sink]\nkind = \"file\"\n").unwrap();
    let err = AppState::from_config(&bad).err().unwrap().to_string();
    assert!(err.contains("needs `path`"), "{err}");
}
