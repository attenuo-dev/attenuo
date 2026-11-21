//! `[leases.notify]` end to end: a revocation request that revoked at least one lease sends
//! one signed `lease.revoked` notice naming the top leases, their chains and the audit record;
//! a revocation that changed nothing sends nothing; a receiver that is down never slows or
//! fails a revocation, and its notice is retried and then given up; a notice left in the
//! outbox at shutdown is delivered once after a restart, and a delivered one is not sent
//! again; with the section unset nothing is stored or sent.
//!
//! "Nothing else arrives" is checked against a later notice, which the same delivery thread
//! sends after any stray one, never by sleeping for a while. The log lines of every test in
//! this binary go to one buffer, which is checked for tokens and secrets.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use attenuo_audit::LeaseRegistry;
use attenuo_core::{LeaseId, RecordKind};
use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::config::LeaseNotifySection;
use attenuo_server::logging::{self, LogFormat};
use attenuo_server::{AppState, Config};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use common::{agent_configs, Running};
use serde_json::{json, Value};

const ADMIN: &str = "lease-notifier-test-admin-token";
const SECRET: &str = "lease-notifier-test-secret-0123456789abcdef";
/// Put in the URL's query: a credential there must never reach a log line.
const URL_CREDENTIAL: &str = "url-credential-5f1d";
const AGENTS: &[&str] = &["coder", "reviewer"];

static LOGS: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct Capture;

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        LOGS.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The process's one subscriber, built as the server builds its text log layer.
fn install_capture() {
    use tracing_subscriber::layer::SubscriberExt;
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let subscriber =
            tracing_subscriber::registry().with(logging::layer(LogFormat::Text, false, || Capture));
        tracing::subscriber::set_global_default(subscriber).unwrap();
    });
}

fn logs() -> String {
    String::from_utf8_lossy(&LOGS.lock().unwrap()).into_owned()
}

/// A receiver that answers 500 to the first `fail_first` requests, then 204, and keeps every
/// request it was sent.
#[derive(Default)]
struct Receiver {
    fail_first: usize,
    seen: AtomicUsize,
    got: Mutex<Vec<(HeaderMap, Bytes)>>,
}

async fn receive(State(r): State<Arc<Receiver>>, headers: HeaderMap, body: Bytes) -> StatusCode {
    let n = r.seen.fetch_add(1, Ordering::SeqCst);
    r.got.lock().unwrap().push((headers, body));
    if n < r.fail_first {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::NO_CONTENT
    }
}

/// A receiver, and the URL to give the server (with a credential in its query).
async fn receiver(fail_first: usize) -> (Arc<Receiver>, Spawned, String) {
    let r = Arc::new(Receiver {
        fail_first,
        ..Default::default()
    });
    let app = Router::new()
        .route("/hook", post(receive))
        .with_state(r.clone());
    let spawned = spawn_router(app).await.unwrap();
    let url = spawned.url(&format!("/hook?key={URL_CREDENTIAL}"));
    (r, spawned, url)
}

impl Receiver {
    fn requests(&self) -> Vec<(HeaderMap, Bytes)> {
        self.got.lock().unwrap().clone()
    }

    /// The bodies of the requests that were answered 2xx.
    fn delivered(&self) -> Vec<Value> {
        self.requests()
            .iter()
            .skip(self.fail_first)
            .map(|(_, b)| serde_json::from_slice(b).unwrap())
            .collect()
    }

    /// Wait until `n` notices were delivered, and return them.
    async fn wait_delivered(&self, n: usize) -> Vec<Value> {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let got = self.delivered();
            if got.len() >= n {
                return got;
            }
            assert!(Instant::now() < end, "only {} of {n} notices", got.len());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Wait until `n` requests arrived (answered or not).
    async fn wait_requests(&self, n: usize) {
        let end = Instant::now() + Duration::from_secs(20);
        while self.seen.load(Ordering::SeqCst) < n {
            assert!(Instant::now() < end, "no request {n} in time");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// A TCP listener that accepts connections and never answers, until [`hang_up`].
async fn dead_receiver() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://{}/hook?key={URL_CREDENTIAL}",
        listener.local_addr().unwrap()
    );
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    (url, task)
}

/// Close the [`dead_receiver`] and every connection it holds.
async fn hang_up(dead: tokio::task::JoinHandle<()>) {
    dead.abort();
    let _ = dead.await;
}

/// Check `X-Attenuo-Signature` against the body, computing the HMAC here, and the other
/// headers against the body.
fn assert_signed(headers: &HeaderMap, body: &[u8]) {
    let sig = headers["x-attenuo-signature"].to_str().unwrap();
    let (t, v1) = sig
        .strip_prefix("t=")
        .and_then(|r| r.split_once(",v1="))
        .unwrap_or_else(|| panic!("bad signature header {sig}"));
    let t: u64 = t.parse().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(now.abs_diff(t) < 60, "timestamp is now");
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, SECRET.as_bytes());
    let mut msg = format!("{t}.").into_bytes();
    msg.extend_from_slice(body);
    ring::hmac::verify(&key, &msg, &hex::decode(v1).unwrap()).expect("signature verifies");
    let v: Value = serde_json::from_slice(body).unwrap();
    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(headers["x-attenuo-event"], "lease.revoked");
    assert_eq!(
        headers["x-attenuo-event-id"].to_str().unwrap(),
        v["event_id"]
    );
}

struct Minted {
    token: String,
    lease: String,
}

struct Harness {
    server: Running,
    state: Arc<AppState>,
    client: reqwest::Client,
    dir: tempfile::TempDir,
    /// Every token minted, to check that none appears in a notice or a log line.
    tokens: Mutex<Vec<String>>,
}

impl Harness {
    /// A server notifying `url` (none when `None`), with the secret in `secret_env`.
    async fn start(
        url: Option<&str>,
        secret_env: &str,
        tweak: impl FnOnce(&mut LeaseNotifySection),
    ) -> Self {
        Self::start_in(tempfile::tempdir().unwrap(), url, secret_env, tweak).await
    }

    /// [`start`](Self::start) on the database in `dir`, as a restarted server would.
    async fn start_in(
        dir: tempfile::TempDir,
        url: Option<&str>,
        secret_env: &str,
        tweak: impl FnOnce(&mut LeaseNotifySection),
    ) -> Self {
        install_capture();
        std::env::set_var(secret_env, SECRET);
        let mut cfg = Config::default();
        cfg.issuer.private_key_pem_path = Some(dir.path().join("keys/issuer.pem"));
        cfg.audit.sqlite_path = dir
            .path()
            .join("audit.sqlite")
            .to_string_lossy()
            .into_owned();
        cfg.admin.token = Some(ADMIN.into());
        cfg.dev.allow_root_mint = true;
        cfg.agents = agent_configs(AGENTS, |id| format!("{id}-secret"));
        if let Some(url) = url {
            let mut n = LeaseNotifySection::with_url(url);
            n.secret_env = secret_env.into();
            n.initial_backoff_ms = 10;
            n.max_backoff_seconds = 1;
            tweak(&mut n);
            cfg.leases.notify = Some(n);
        }
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        Self {
            server: Running::start(cfg, state.clone(), router).await,
            state,
            client: reqwest::Client::new(),
            dir,
            tokens: Mutex::default(),
        }
    }

    /// Stop the notifier's delivery thread, delivering first whatever is queued: once this
    /// returns nothing more is sent.
    async fn quiesce(&self) {
        let s = self.state.clone();
        tokio::task::spawn_blocking(move || {
            s.lease_notifier
                .as_ref()
                .unwrap()
                .shutdown(Duration::from_secs(10))
        })
        .await
        .unwrap();
    }

    /// Stop with no grace for the notifier, so what was not delivered stays in the outbox, and
    /// return the directory with the database.
    async fn stop(self) -> tempfile::TempDir {
        let Self {
            server,
            state,
            client,
            dir,
            ..
        } = self;
        drop(client);
        let s = state.clone();
        tokio::task::spawn_blocking(move || {
            if let Some(n) = &s.lease_notifier {
                n.shutdown(Duration::ZERO);
            }
        })
        .await
        .unwrap();
        server.stop(state).await;
        dir
    }

    async fn minted(&self, resp: reqwest::Response) -> Minted {
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        let m = Minted {
            token: v["access_token"].as_str().unwrap().into(),
            lease: v["lease"].as_str().unwrap().into(),
        };
        self.tokens.lock().unwrap().push(m.token.clone());
        m
    }

    async fn mint_root(&self, subject: &str) -> Minted {
        let resp = self
            .client
            .post(self.server.url("/admin/root-token"))
            .bearer_auth(ADMIN)
            .json(&json!({
                "subject": subject,
                "issuer": "https://idp.example",
                "agent": "planner",
                "capabilities": ["github:*"],
            }))
            .send()
            .await
            .unwrap();
        self.minted(resp).await
    }

    async fn exchange(&self, parent: &Minted, actor: &str) -> Minted {
        let resp = self
            .client
            .post(self.server.url("/token"))
            .json(&json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": parent.token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "actor": actor,
                "authorization_details": [{
                    "type": "attenuo_capabilities",
                    "capabilities": [{"server": "github", "tool": "read_file"}],
                }],
                "client_id": actor,
                "client_secret": format!("{actor}-secret"),
            }))
            .send()
            .await
            .unwrap();
        self.minted(resp).await
    }

    /// `POST /admin/leases/{id}/revoke`: the status and the body.
    async fn revoke(&self, lease: &str, reason: &str) -> (StatusCode, Value) {
        let resp = self
            .client
            .post(self.server.url(&format!("/admin/leases/{lease}/revoke")))
            .bearer_auth(ADMIN)
            .json(&json!({ "reason": reason }))
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap())
    }

    /// `POST /admin/leases/revoke` with `body`.
    async fn revoke_selected(&self, body: Value) -> Value {
        let resp = self
            .client
            .post(self.server.url("/admin/leases/revoke"))
            .bearer_auth(ADMIN)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json().await.unwrap()
    }

    fn metric(&self, series: &str) -> u64 {
        let text = self.state.metrics.render();
        let prefix = format!("{series} ");
        text.lines()
            .find_map(|l| l.strip_prefix(prefix.as_str()))
            .unwrap_or_else(|| panic!("no {series}"))
            .trim()
            .parse()
            .unwrap()
    }

    /// Wait briefly for a counter the delivery thread moves after the receiver answered.
    async fn metric_reaches(&self, series: &str, want: u64) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let got = self.metric(series);
            if got >= want || Instant::now() > deadline {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn readyz(&self) -> (StatusCode, Value) {
        let resp = self
            .client
            .get(self.server.url("/readyz"))
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap())
    }

    /// No minted token, no secret, no URL credential in `text`.
    fn assert_clean(&self, text: &str) {
        for t in self.tokens.lock().unwrap().iter() {
            assert!(!text.contains(t.as_str()), "a token in: {text}");
        }
        for s in [SECRET, ADMIN, URL_CREDENTIAL] {
            assert!(!text.contains(s), "{s} in: {text}");
        }
    }
}

/// The `lease_revoke` record a notice names agrees with it.
fn assert_matches_record(h: &Harness, notice: &Value) {
    let id = notice["audit_record_id"].as_str().unwrap();
    let entry = h
        .state
        .audit
        .entry_by_record_id(id)
        .unwrap()
        .expect("the record exists");
    let r = entry.record;
    assert_eq!(r.kind, RecordKind::LeaseRevoke);
    assert_eq!(r.tool, "admin.lease.revoke");
    assert_eq!(r.originating_subject, notice["by_subject"]);
    let at =
        r.at.format(&time::format_description::well_known::Rfc3339)
            .unwrap();
    assert_eq!(notice["revoked_at"], at);
    for l in notice["lease_ids"].as_array().unwrap() {
        assert!(
            r.leases.iter().any(|x| x.0 == l.as_str().unwrap()),
            "{l} is in the record's leases"
        );
    }
}

/// One revocation with a cascade sends exactly one signed notice, for the lease named, with
/// its chain and the audit record; a selector revocation sends one for its top leases; a
/// revocation that changes nothing sends nothing.
#[tokio::test]
async fn a_revocation_sends_one_signed_notice_and_one_that_changes_nothing_sends_none() {
    let (r, _hook, url) = receiver(0).await;
    let h = Harness::start(Some(&url), "ATTENUO_TEST_LEASE_NOTIFY_SECRET_1", |_| {}).await;
    let root = h.mint_root("alice").await;
    let coder = h.exchange(&root, "coder").await;
    let reviewer = h.exchange(&coder, "reviewer").await;

    let (status, resp) = h.revoke(&coder.lease, "incident 42").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["revoked"], 2, "the coder and the reviewer under it");
    let got = r.wait_delivered(1).await;
    let n = &got[0];
    assert_eq!(n["type"], "lease.revoked");
    assert_eq!(n["lease_ids"], json!([coder.lease]));
    assert_eq!(n["chain_ids"], json!([root.lease]));
    assert_eq!(n["truncated"], false);
    assert_eq!(n["selector"], Value::Null);
    assert_eq!(n["revoked"], 2);
    assert_eq!(n["reason"], "incident 42");
    assert_eq!(n["by"], "admin");
    assert_eq!(n["by_subject"], "urn:attenuo:admin");
    assert_eq!(n["audit_record_id"], resp["audit_id"]);
    assert_matches_record(&h, n);
    assert!(
        !n.to_string().contains(&reviewer.lease),
        "descendants are not listed"
    );

    // Nothing changes: already revoked, unknown, a selector that matches nothing.
    let (status, again) = h.revoke(&coder.lease, "again").await;
    assert_eq!(
        (status, again["revoked"].as_u64()),
        (StatusCode::OK, Some(0))
    );
    let (status, _) = h.revoke("no-such-lease", "typo").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let none = h.revoke_selected(json!({"user": "nobody"})).await;
    assert_eq!(none["revoked_count"], 0);

    // A selector: alice has the rest of her first chain (its root) and a second chain.
    let root2 = h.mint_root("alice").await;
    let child2 = h.exchange(&root2, "coder").await;
    let bob = h.mint_root("bob").await;
    let sel = h.revoke_selected(json!({"user": "alice"})).await;
    assert_eq!(sel["revoked_count"], 3, "{sel}");
    let got = r.wait_delivered(2).await;
    assert_eq!(
        got.len(),
        2,
        "nothing was sent for the revocations that changed nothing"
    );
    let s = &got[1];
    let mut tops = vec![root.lease.clone(), root2.lease.clone()];
    tops.sort();
    assert_eq!(s["lease_ids"], json!(tops), "{s}");
    assert_eq!(s["chain_ids"], json!(tops));
    assert!(!s.to_string().contains(&child2.lease));
    assert_eq!(s["selector"], json!({"user": "alice"}));
    assert_eq!(s["revoked"], 3);
    assert_eq!(s["reason"], "revoked by admin");
    assert_eq!(s["audit_record_id"], sel["audit_id"]);
    assert_ne!(s["event_id"], got[0]["event_id"]);
    assert_matches_record(&h, s);
    assert!(h
        .state
        .leases
        .is_active(&LeaseId::new(bob.lease), time::OffsetDateTime::now_utc())
        .unwrap());

    let requests = r.requests();
    assert_eq!(requests.len(), 2, "one request per notice");
    for (headers, body) in &requests {
        assert_signed(headers, body);
        h.assert_clean(&String::from_utf8_lossy(body));
    }
    assert_eq!(
        h.metric_reaches("attenuo_lease_notify_delivered_total", 2)
            .await,
        2
    );
    assert_eq!(h.metric("attenuo_lease_notify_dropped_total"), 0);
    assert_eq!(h.metric("attenuo_approval_notify_delivered_total"), 0);
    let (status, ready) = h.readyz().await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ready["checks"]["lease_notifier"], "ok", "{ready}");
    assert_eq!(ready["degraded"], false);
    h.assert_clean(&logs());
}

/// A receiver that never answers delays no revocation, fills the small queue (counted as
/// dropped), and marks the notifier degraded on `/readyz` without making it not ready.
#[tokio::test]
async fn a_dead_receiver_never_delays_or_fails_a_revocation() {
    let (url, dead) = dead_receiver().await;
    let h = Harness::start(Some(&url), "ATTENUO_TEST_LEASE_NOTIFY_SECRET_2", |n| {
        n.timeout_seconds = 30;
        n.queue_capacity = 1;
    })
    .await;
    let budget = Duration::from_secs(2);
    for i in 0..3 {
        let root = h.mint_root(&format!("dead-{i}")).await;
        let child = h.exchange(&root, "coder").await;
        let started = Instant::now();
        let (status, resp) = h.revoke(&root.lease, "dead receiver").await;
        let took = started.elapsed();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["revoked"], 2);
        assert!(
            took < budget,
            "revocation took {took:?} with a receiver that never answers"
        );
        assert!(!h
            .state
            .leases
            .is_active(&LeaseId::new(child.lease), time::OffsetDateTime::now_utc())
            .unwrap());
    }
    // Three notices into a queue of one behind a request that hangs: one dropped at least.
    assert!(h.metric("attenuo_lease_notify_dropped_total") >= 1);
    assert_eq!(h.metric("attenuo_lease_notify_delivered_total"), 0);
    let (status, ready) = h.readyz().await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ready["ready"], true);
    assert_eq!(ready["checks"]["lease_notifier"], "degraded", "{ready}");
    assert_eq!(ready["degraded"], true);
    hang_up(dead).await;
    h.stop().await;
}

/// A receiver that keeps failing gets `max_attempts` requests with the same event and body,
/// and then the notice is given up: counted, and its outbox row closed. The log lines name
/// the host only.
#[tokio::test]
async fn a_failing_receiver_is_retried_then_given_up_after_max_attempts() {
    let (r, _hook, url) = receiver(usize::MAX).await;
    let h = Harness::start(Some(&url), "ATTENUO_TEST_LEASE_NOTIFY_SECRET_3", |n| {
        n.max_attempts = 3;
    })
    .await;
    let root = h.mint_root("carol").await;
    let (status, _) = h.revoke(&root.lease, "give up").await;
    assert_eq!(status, StatusCode::OK);
    r.wait_requests(3).await;
    assert_eq!(
        h.metric_reaches("attenuo_lease_notify_dropped_total", 1)
            .await,
        1
    );
    assert_eq!(h.metric("attenuo_lease_notify_failures_total"), 3);
    assert_eq!(h.metric("attenuo_lease_notify_delivered_total"), 0);
    h.quiesce().await;
    let requests = r.requests();
    assert_eq!(requests.len(), 3, "max_attempts requests, then given up");
    for (headers, body) in &requests {
        assert_signed(headers, body);
        assert_eq!(body, &requests[0].1, "the same body each time");
    }
    assert_eq!(h.state.leases.outbox_open_count_of("lease.").unwrap(), 0);
    assert_eq!(h.metric("attenuo_lease_notify_outbox_rows"), 0);
    let text = logs();
    assert!(
        text.contains("[leases.notify] delivery failed on every attempt; dropped"),
        "{text}"
    );
    assert!(text.contains("127.0.0.1"), "the host is named");
    h.assert_clean(&text);
}

/// A notice left in the outbox at shutdown is delivered once, signed, with the same event id,
/// by a server started on the same database; a notice delivered before a restart is not sent
/// again after it.
#[tokio::test]
async fn a_restart_delivers_an_undelivered_notice_once_and_not_a_delivered_one() {
    const ENV: &str = "ATTENUO_TEST_LEASE_NOTIFY_SECRET_4";
    let (url, dead) = dead_receiver().await;
    let h = Harness::start(Some(&url), ENV, |n| {
        n.timeout_seconds = 1;
        n.max_attempts = 100;
    })
    .await;
    let root = h.mint_root("dave").await;
    let (_, resp) = h.revoke(&root.lease, "before the restart").await;
    let open = h.state.leases.outbox_open(10).unwrap();
    assert_eq!(open.len(), 1, "{open:?}");
    assert_eq!(open[0].kind, "lease.revoked");
    assert_eq!(open[0].approval_id, root.lease);
    let event_id = open[0].event_id.clone();
    assert_eq!(
        event_id,
        attenuo_server::notify::event_id_for(
            attenuo_server::notify::NoticeKind::LeaseRevoked,
            resp["audit_id"].as_str().unwrap()
        )
    );
    hang_up(dead).await;
    let dir = h.stop().await;

    let (r, _hook, url) = receiver(0).await;
    let h = Harness::start_in(dir, Some(&url), ENV, |_| {}).await;
    let got = r.wait_delivered(1).await;
    assert_eq!(got[0]["event_id"], event_id);
    assert_eq!(got[0]["lease_ids"], json!([root.lease]));
    // A fresh revocation is delivered after it: the backlog went first, once.
    let root2 = h.mint_root("dave").await;
    h.revoke(&root2.lease, "after the restart").await;
    let got = r.wait_delivered(2).await;
    assert_eq!(got[1]["lease_ids"], json!([root2.lease]));
    assert_eq!(
        h.metric_reaches("attenuo_lease_notify_delivered_total", 2)
            .await,
        2
    );
    assert_eq!(h.metric("attenuo_lease_notify_outbox_rows"), 0);
    let delivered_event = got[1]["event_id"].clone();
    for (headers, body) in &r.requests() {
        assert_signed(headers, body);
    }
    let dir = h.stop().await;

    // Both were delivered: a second restart sends neither again. A third revocation is the
    // marker; the delivery thread would send anything old before it.
    let (r2, _hook2, url2) = receiver(0).await;
    let h = Harness::start_in(dir, Some(&url2), ENV, |_| {}).await;
    let root3 = h.mint_root("dave").await;
    h.revoke(&root3.lease, "marker").await;
    let got = r2.wait_delivered(1).await;
    h.quiesce().await;
    let got_all = r2.delivered();
    assert_eq!(got_all.len(), 1, "nothing is sent again: {got_all:?}");
    assert_eq!(got[0]["lease_ids"], json!([root3.lease]));
    assert_ne!(got[0]["event_id"], delivered_event);
    assert_ne!(got[0]["event_id"], json!(event_id));
    h.assert_clean(&logs());
}

/// With `[leases.notify]` unset, a revocation stores and sends nothing, and `/readyz` has no
/// `lease_notifier` check.
#[tokio::test]
async fn nothing_is_stored_or_sent_when_the_section_is_unset() {
    let h = Harness::start(None, "ATTENUO_TEST_LEASE_NOTIFY_SECRET_5", |_| {}).await;
    assert!(h.state.lease_notifier.is_none());
    let root = h.mint_root("erin").await;
    let child = h.exchange(&root, "coder").await;
    let (status, resp) = h.revoke(&root.lease, "unset").await;
    assert_eq!(
        (status, resp["revoked"].as_u64()),
        (StatusCode::OK, Some(2))
    );
    let sel = h.revoke_selected(json!({"chain_id": child.lease})).await;
    assert_eq!(sel["revoked_count"], 0);
    assert!(h.state.leases.outbox_open(10).unwrap().is_empty());
    assert_eq!(h.state.leases.outbox_last_open_id().unwrap(), None);
    assert_eq!(h.metric("attenuo_lease_notify_delivered_total"), 0);
    assert_eq!(h.metric("attenuo_lease_notify_outbox_rows"), 0);
    let (status, ready) = h.readyz().await;
    assert_eq!(status, StatusCode::OK);
    assert!(ready["checks"].get("lease_notifier").is_none(), "{ready}");
}

/// Startup fails without the signing secret, naming the variable and the section, never a
/// value.
#[test]
fn startup_fails_without_the_signing_secret_and_names_only_the_variable() {
    let mut cfg = Config::default();
    let mut notify = LeaseNotifySection::with_url("https://hooks.example/revoked");
    assert_eq!(notify.secret_env, "ATTENUO_LEASE_NOTIFY_SECRET");
    notify.secret_env = "ATTENUO_TEST_LEASE_NOTIFY_SECRET_UNSET".into();
    cfg.leases.notify = Some(notify.clone());
    let err = attenuo_server::build(&cfg)
        .err()
        .expect("refused")
        .to_string();
    assert!(
        err.contains("ATTENUO_TEST_LEASE_NOTIFY_SECRET_UNSET"),
        "{err}"
    );
    assert!(err.contains("[leases.notify]"), "{err}");

    std::env::set_var("ATTENUO_TEST_LEASE_NOTIFY_SECRET_SHORT", "short");
    notify.secret_env = "ATTENUO_TEST_LEASE_NOTIFY_SECRET_SHORT".into();
    cfg.leases.notify = Some(notify.clone());
    let err = attenuo_server::build(&cfg)
        .err()
        .expect("refused")
        .to_string();
    assert!(
        err.contains("shorter than 32 bytes") && !err.contains("short\""),
        "{err}"
    );

    notify.url = "https://user:pw@hooks.example/".into();
    cfg.leases.notify = Some(notify);
    let err = attenuo_server::build(&cfg)
        .err()
        .expect("refused")
        .to_string();
    assert!(
        err.contains("[leases.notify] url must not carry user info"),
        "{err}"
    );
}
