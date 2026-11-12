//! `[approvals.notify]` end to end: a gated call queues a signed `approval.pending` notice,
//! an operator's decision an `approval.decided` one, and an approval nobody decides an
//! `approval.expired` one. A receiver that fails is retried; one that never answers delays
//! neither the gated call nor the decision.
//!
//! No test waits for time to pass: the server runs on a [`ManualClock`], and a test steps it
//! past an approval's TTL ([`Harness::advance`]). "Nothing else arrives" is checked against a
//! later notice that the same thread delivers after any stray one, or after stopping the
//! delivery thread, never by sleeping for a while.

// Configs are built field by field from `Config::default()`, as in the other server tests.
#![allow(clippy::field_reassign_with_default)]

mod common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use attenuo_audit::LeaseStore;
use attenuo_core::{Clock, ManualClock, ToolCall};
use attenuo_policy::ToolAttrs;
use attenuo_proxy::testing::{spawn_router, FakeMcpServer, Spawned};
use attenuo_proxy::UpstreamConfig;
use attenuo_server::config::NotifySection;
use attenuo_server::{AppState, Config};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use common::Running;
use serde_json::{json, Value};

const ADMIN: &str = "notifier-test-admin";
const SECRET: &str = "notifier-test-secret-0123456789abcdef";

/// Ask before anything destructive once the run has read something untrusted.
const POLICY: &str = r#"
@id("allow")
permit(principal, action, resource);

@id("confirm_destructive_after_untrusted_read")
@obligation("approval")
forbid(principal, action, resource)
when { resource.destructive && context.session.tainted && !context.approval.present };
"#;

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

async fn receiver(fail_first: usize) -> (Arc<Receiver>, Spawned) {
    let r = Arc::new(Receiver {
        fail_first,
        ..Default::default()
    });
    let app = Router::new()
        .route("/hook", post(receive))
        .with_state(r.clone());
    (r, spawn_router(app).await.unwrap())
}

impl Receiver {
    /// The bodies of the requests that were answered 2xx.
    fn delivered(&self) -> Vec<Value> {
        self.got
            .lock()
            .unwrap()
            .iter()
            .skip(self.fail_first)
            .map(|(_, b)| serde_json::from_slice(b).unwrap())
            .collect()
    }

    /// Wait until a delivered notice of `kind` arrives, and return it.
    async fn wait_for(&self, kind: &str) -> Value {
        self.wait_until(kind, |v| v["type"] == kind).await
    }

    /// Wait until a delivered notice of `kind` for approval `id` arrives, and return it.
    async fn wait_for_approval(&self, kind: &str, id: &str) -> Value {
        self.wait_until(kind, |v| v["type"] == kind && v["approval_id"] == id)
            .await
    }

    /// Poll the delivered notices until one matches `found`.
    async fn wait_until(&self, what: &str, found: impl Fn(&Value) -> bool) -> Value {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(v) = self.delivered().into_iter().find(&found) {
                return v;
            }
            assert!(Instant::now() < end, "no {what} notice in time");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// A TCP listener that accepts connections and never answers, until [`hang_up`].
async fn dead_receiver() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    (url, task)
}

/// Close the [`dead_receiver`] and every connection it holds, so a request still waiting on
/// it fails at once instead of at its timeout: stopping the server then does not wait for it.
async fn hang_up(dead: tokio::task::JoinHandle<()>) {
    dead.abort();
    let _ = dead.await;
}

/// Check `X-Attenuo-Signature` against the body, computing the HMAC here.
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
}

struct Harness {
    /// Run through `attenuo_server::run`, as `serve` runs it, so that [`Harness::stop`] stops
    /// it the same way.
    server: Running,
    state: Arc<AppState>,
    /// The server's clock, notifier included: [`Harness::advance`] steps it.
    clock: Arc<ManualClock>,
    _upstream_task: Spawned,
    client: reqwest::Client,
    dir: tempfile::TempDir,
}

impl Harness {
    /// A server notifying `url`, with the secret in the environment variable `secret_env`
    /// (one per test, so tests running in parallel do not share one).
    async fn start(url: &str, secret_env: &str, tweak: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        Self::start_in(dir, ManualClock::new(), url, secret_env, tweak).await
    }

    /// [`start`](Self::start) on the database in `dir` and on `clock`, as a restarted server
    /// would.
    async fn start_in(
        dir: tempfile::TempDir,
        clock: Arc<ManualClock>,
        url: &str,
        secret_env: &str,
        tweak: impl FnOnce(&mut Config),
    ) -> Self {
        std::env::set_var(secret_env, SECRET);
        let upstream = FakeMcpServer::new(&["read_web", "delete_repo"]);
        let upstream_task = upstream.spawn().await.unwrap();
        let policy_path = dir.path().join("policies.cedar");
        std::fs::write(&policy_path, POLICY).unwrap();
        let mut cfg = Config::default();
        cfg.audit.sqlite_path = dir
            .path()
            .join("audit.sqlite")
            .to_string_lossy()
            .into_owned();
        cfg.policy.policies_path = Some(policy_path);
        cfg.policy.catalog = BTreeMap::from([(
            "github".to_string(),
            BTreeMap::from([
                ("read_web".to_string(), ToolAttrs::new().readonly(true)),
                ("delete_repo".to_string(), ToolAttrs::new()),
            ]),
        )]);
        cfg.upstreams = vec![UpstreamConfig::new("github", upstream_task.url("/mcp"))];
        cfg.admin.token = Some(ADMIN.into());
        cfg.dev.allow_root_mint = true;
        let mut notify = NotifySection::new(url);
        notify.secret_env = secret_env.into();
        notify.initial_backoff_ms = 10;
        notify.max_backoff_seconds = 1;
        cfg.approvals.notify = Some(notify);
        tweak(&mut cfg);
        let (router, state) = attenuo_server::build_with_clock(&cfg, clock.clone()).unwrap();
        Self {
            server: Running::start(cfg, state.clone(), router).await,
            state,
            clock,
            _upstream_task: upstream_task,
            client: reqwest::Client::new(),
            dir,
        }
    }

    /// Move the server's clock forward by `by`, and have the notifier's expiry watcher look
    /// at it at once.
    fn advance(&self, by: Duration) {
        self.clock.advance(by);
        self.notifier().clock_advanced();
    }

    fn notifier(&self) -> &attenuo_server::notify::ApprovalNotifier {
        self.state.approval_notifier.as_ref().unwrap()
    }

    /// Step the clock past the expiry of approval `id`.
    fn advance_past_expiry(&self, id: &str) {
        let expires_at = self.state.leases.approval(id).unwrap().unwrap().expires_at;
        let left = Duration::try_from(expires_at - self.clock.now_utc()).unwrap_or_default();
        self.advance(left + Duration::from_secs(1));
    }

    /// Stop the notifier's threads, delivering first whatever is queued: once this returns
    /// nothing more is sent, so a count read afterwards is final.
    async fn quiesce(&self) {
        let s = self.state.clone();
        tokio::task::spawn_blocking(move || {
            s.approval_notifier
                .as_ref()
                .unwrap()
                .shutdown(Duration::from_secs(10))
        })
        .await
        .unwrap();
    }

    /// Stop the way `serve` does after a signal, with no grace for the notifier: what was
    /// not delivered stays in the outbox. Returns once the server has let go of the database
    /// ([`Running::stop`]), with the directory holding it, so a server started on it next
    /// finds it free.
    async fn stop(self) -> tempfile::TempDir {
        let Self {
            server,
            state,
            _upstream_task,
            client,
            dir,
            ..
        } = self;
        drop(client);
        // `run` gives the notifier its grace after the drain; it finds it already stopped.
        let s = state.clone();
        tokio::task::spawn_blocking(move || {
            s.approval_notifier
                .as_ref()
                .unwrap()
                .shutdown(Duration::ZERO)
        })
        .await
        .unwrap();
        server.stop(state).await;
        dir
    }

    async fn root(&self) -> String {
        let resp = self
            .client
            .post(self.server.url("/admin/root-token"))
            .bearer_auth(ADMIN)
            .json(&json!({
                "subject": "alice",
                "issuer": "https://idp.example",
                "agent": "planner",
                "capabilities": ["github:*"],
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = resp.json().await.unwrap();
        v["access_token"].as_str().unwrap().to_string()
    }

    async fn call(&self, token: &str, tool: &str, repo: &str) -> Value {
        let resp = self
            .client
            .post(self.server.url("/mcp/github"))
            .header("accept", "application/json, text/event-stream")
            .bearer_auth(token)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": tool, "arguments": {"repo": repo}}}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json().await.unwrap()
    }

    /// Taint the run, then make a destructive call: its approval id.
    async fn gated(&self, token: &str, repo: &str) -> String {
        assert!(self
            .call(token, "read_web", "x")
            .await
            .get("result")
            .is_some());
        let v = self.call(token, "delete_repo", repo).await;
        assert_eq!(v["error"]["code"], -32008, "{v}");
        v["error"]["data"]["approval_id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn admin_decide(&self, id: &str, decision: &str) -> Value {
        let resp = self
            .client
            .post(self.server.url(&format!("/admin/approvals/{id}")))
            .bearer_auth(ADMIN)
            .json(&json!({ "decision": decision }))
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

    /// The receiver records a request before the queue thread counts it delivered, so a
    /// counter read right after `wait_for` can be one short: wait for it, briefly.
    async fn metric_reaches(&self, series: &str, want: u64) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let got = self.metric(series);
            if got >= want || Instant::now() > deadline {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

#[tokio::test]
async fn pending_and_decided_notices_are_signed_and_carry_no_arguments() {
    let (r, hook) = receiver(0).await;
    let h = Harness::start(&hook.url("/hook"), "ATTENUO_TEST_NOTIFY_SECRET_1", |_| {}).await;
    let token = h.root().await;
    let id = h.gated(&token, "alice/secret-repo").await;

    let pending = r.wait_for("approval.pending").await;
    let shown = h.state.leases.approval(&id).unwrap().unwrap();
    assert_eq!(pending["approval_id"], id);
    assert_eq!(pending["decision_id"], shown.decision_id);
    assert_eq!(pending["chain_id"], shown.chain_id.0);
    assert_eq!(pending["server"], "github");
    assert_eq!(pending["tool"], "delete_repo");
    let call = ToolCall::new(
        "github",
        "delete_repo",
        json!({"repo": "alice/secret-repo"}),
    );
    assert_eq!(pending["call_hash"], call.call_hash());
    assert_eq!(pending["subject"], "alice");
    assert_eq!(pending["issuer"], "https://idp.example");
    assert_eq!(pending["agent"], "planner");
    assert_eq!(pending["chain_depth"], 1);
    assert!(pending["requested_at"].as_str().is_some());
    assert!(pending["expires_at"].as_str().is_some());
    assert!(pending["reason"]
        .as_str()
        .unwrap()
        .contains("untrusted results from github/read_web"));
    assert!(pending.get("decision").is_none());

    let decided_body = h.admin_decide(&id, "decline").await;
    assert_eq!(decided_body["state"], "declined");
    let decided = r.wait_for("approval.decided").await;
    assert_eq!(decided["approval_id"], id);
    assert_eq!(decided["decision"], "decline");
    assert_eq!(
        decided["decided_by"],
        json!({"subject": "urn:attenuo:admin", "by": "operator"})
    );
    assert_ne!(decided["event_id"], pending["event_id"]);

    let got = r.got.lock().unwrap().clone();
    assert_eq!(got.len(), 2, "one request per notice");
    for (headers, body) in &got {
        assert_signed(headers, body);
        assert_eq!(headers["content-type"], "application/json");
        let v: Value = serde_json::from_slice(body).unwrap();
        assert_eq!(headers["x-attenuo-event"].to_str().unwrap(), v["type"]);
        assert_eq!(
            headers["x-attenuo-event-id"].to_str().unwrap(),
            v["event_id"]
        );
        let text = String::from_utf8_lossy(body);
        assert!(!text.contains("secret-repo"), "no argument values: {text}");
        assert!(!text.contains(&token), "no token: {text}");
        assert!(!text.contains(SECRET));
    }
    assert_eq!(
        h.metric_reaches("attenuo_approval_notify_delivered_total", 2)
            .await,
        2
    );
}

#[tokio::test]
async fn an_approval_nobody_decides_gets_an_expired_notice() {
    let (r, hook) = receiver(0).await;
    let h = Harness::start(&hook.url("/hook"), "ATTENUO_TEST_NOTIFY_SECRET_2", |c| {
        c.approvals.ttl_seconds = 1;
    })
    .await;
    let token = h.root().await;
    let id = h.gated(&token, "alice/site").await;
    r.wait_for("approval.pending").await;
    h.advance_past_expiry(&id);
    let expired = r.wait_for("approval.expired").await;
    assert_eq!(expired["approval_id"], id);
    assert!(expired.get("decision").is_none());
    let (headers, body) = r.got.lock().unwrap().last().cloned().unwrap();
    assert_signed(&headers, &body);
    // A decided approval gets no expired notice. `id3`, left pending, expires after `id2`:
    // the watcher looks at approvals in expiry order and the queue delivers in order, so an
    // expired notice for `id2` would arrive before the one for `id3`.
    let id2 = h.gated(&token, "alice/other").await;
    h.admin_decide(&id2, "grant").await;
    r.wait_for("approval.decided").await;
    let id3 = h.gated(&token, "alice/third").await;
    h.advance_past_expiry(&id3);
    let expired3 = r.wait_for_approval("approval.expired", &id3).await;
    assert_eq!(expired3["approval_id"], id3);
    let notices = r.delivered();
    let for_id2: Vec<&str> = notices
        .iter()
        .filter(|v| v["approval_id"] == id2.as_str())
        .map(|v| v["type"].as_str().unwrap())
        .collect();
    assert_eq!(for_id2, ["approval.pending", "approval.decided"]);
    let expired_ids: Vec<&str> = notices
        .iter()
        .filter(|v| v["type"] == "approval.expired")
        .map(|v| v["approval_id"].as_str().unwrap())
        .collect();
    assert_eq!(expired_ids, [id.as_str(), id3.as_str()]);
}

#[tokio::test]
async fn a_receiver_answering_500_is_retried_with_the_same_event() {
    let (r, hook) = receiver(2).await;
    let h = Harness::start(&hook.url("/hook"), "ATTENUO_TEST_NOTIFY_SECRET_3", |_| {}).await;
    let token = h.root().await;
    let id = h.gated(&token, "alice/site").await;
    let pending = r.wait_for("approval.pending").await;
    assert_eq!(pending["approval_id"], id);
    let got = r.got.lock().unwrap().clone();
    assert_eq!(got.len(), 3, "two 500s, then delivered");
    let ids: Vec<&str> = got
        .iter()
        .map(|(h, _)| h["x-attenuo-event-id"].to_str().unwrap())
        .collect();
    assert!(ids.iter().all(|i| *i == ids[0]), "{ids:?}");
    assert!(
        got.iter().all(|(_, b)| b == &got[0].1),
        "same body each time"
    );
    for (headers, body) in &got {
        assert_signed(headers, body);
    }
    assert_eq!(
        h.metric_reaches("attenuo_approval_notify_delivered_total", 1)
            .await,
        1
    );
    assert_eq!(h.metric("attenuo_approval_notify_failures_total"), 2);
    assert_eq!(h.metric("attenuo_approval_notify_dropped_total"), 0);
}

#[tokio::test]
async fn a_dead_receiver_never_delays_a_gated_call_or_a_decision() {
    let (url, _dead) = dead_receiver().await;
    let h = Harness::start(&url, "ATTENUO_TEST_NOTIFY_SECRET_4", |c| {
        let n = c.approvals.notify.as_mut().unwrap();
        n.timeout_seconds = 30;
        n.queue_capacity = 1;
    })
    .await;
    let token = h.root().await;
    // Warm up the server path once (first connection, first policy evaluation).
    assert!(h
        .call(&token, "read_web", "x")
        .await
        .get("result")
        .is_some());
    let budget = Duration::from_secs(2);
    for repo in ["a/1", "a/2", "a/3"] {
        let started = Instant::now();
        let v = h.call(&token, "delete_repo", repo).await;
        let took = started.elapsed();
        assert_eq!(v["error"]["code"], -32008, "{v}");
        assert!(
            took < budget,
            "gated call took {took:?} with a receiver that never answers"
        );
        let id = v["error"]["data"]["approval_id"]
            .as_str()
            .unwrap()
            .to_string();
        let started = Instant::now();
        let decided = h.admin_decide(&id, "decline").await;
        let took = started.elapsed();
        assert_eq!(decided["state"], "declined");
        assert!(
            took < budget,
            "decision took {took:?} with a receiver that never answers"
        );
    }
    // Six notices into a queue of one, behind a request that hangs for 30 s: the overflow is
    // dropped and counted, and readiness stays 200.
    assert!(h.metric("attenuo_approval_notify_dropped_total") >= 4);
    assert_eq!(h.metric("attenuo_approval_notify_delivered_total"), 0);
    let resp = h.client.get(h.server.url("/readyz")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["ready"], true);
    assert_eq!(v["checks"]["approval_notifier"], "degraded", "{v}");
    assert_eq!(v["degraded"], true);
}

#[test]
fn startup_fails_without_the_signing_secret_and_names_only_the_variable() {
    let mut cfg = Config::default();
    let mut notify = NotifySection::new("https://hooks.example/attenuo");
    notify.secret_env = "ATTENUO_TEST_NOTIFY_SECRET_UNSET".into();
    cfg.approvals.notify = Some(notify.clone());
    let err = attenuo_server::build(&cfg)
        .err()
        .expect("refused")
        .to_string();
    assert!(err.contains("ATTENUO_TEST_NOTIFY_SECRET_UNSET"), "{err}");

    std::env::set_var("ATTENUO_TEST_NOTIFY_SECRET_SHORT", "short");
    notify.secret_env = "ATTENUO_TEST_NOTIFY_SECRET_SHORT".into();
    cfg.approvals.notify = Some(notify.clone());
    let err = attenuo_server::build(&cfg)
        .err()
        .expect("refused")
        .to_string();
    assert!(
        err.contains("shorter than 32 bytes") && !err.contains("short\""),
        "{err}"
    );

    std::env::set_var("ATTENUO_TEST_NOTIFY_SECRET_OK", SECRET);
    notify.secret_env = "ATTENUO_TEST_NOTIFY_SECRET_OK".into();
    notify.headers.insert(
        "authorization".into(),
        "ATTENUO_TEST_NOTIFY_AUTH_UNSET".into(),
    );
    cfg.approvals.notify = Some(notify);
    let err = attenuo_server::build(&cfg)
        .err()
        .expect("refused")
        .to_string();
    assert!(err.contains("ATTENUO_TEST_NOTIFY_AUTH_UNSET"), "{err}");
}

/// Settings for a server whose receiver never answers: short timeouts, many attempts.
fn hanging(c: &mut Config) {
    let n = c.approvals.notify.as_mut().unwrap();
    n.timeout_seconds = 1;
    n.max_attempts = 100;
}

/// Wait until the outbox has no open row.
async fn outbox_drains(h: &Harness) {
    let end = Instant::now() + Duration::from_secs(10);
    while !h.state.leases.outbox_open(10).unwrap().is_empty() {
        assert!(Instant::now() < end, "outbox rows still open");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A notice queued for a receiver that never answered is in the outbox when the server stops,
/// and a server started on the same database delivers it, once, signed, with the same id.
#[tokio::test]
async fn a_notice_queued_at_shutdown_is_delivered_after_a_restart() {
    const ENV: &str = "ATTENUO_TEST_NOTIFY_SECRET_5";
    let (url, dead) = dead_receiver().await;
    let h = Harness::start(&url, ENV, hanging).await;
    let token = h.root().await;
    let id = h.gated(&token, "alice/site").await;
    let open = h.state.leases.outbox_open(10).unwrap();
    assert_eq!(open.len(), 1, "{open:?}");
    assert_eq!(open[0].approval_id, id);
    assert_eq!(open[0].kind, "approval.pending");
    hang_up(dead).await;
    let clock = h.clock.clone();
    let dir = h.stop().await;

    let (r, hook) = receiver(0).await;
    let h = Harness::start_in(dir, clock, &hook.url("/hook"), ENV, |_| {}).await;
    let pending = r.wait_for("approval.pending").await;
    assert_eq!(pending["approval_id"], id);
    let event_id =
        attenuo_server::notify::event_id_for(attenuo_server::notify::NoticeKind::Pending, &id);
    assert_eq!(pending["event_id"], event_id);
    outbox_drains(&h).await;
    assert_eq!(
        h.metric_reaches("attenuo_approval_notify_delivered_total", 1)
            .await,
        1
    );
    // Nothing else arrives: the delivered row is not sent again. Stopping the delivery
    // thread delivers anything still queued first, so a second copy would show here.
    h.quiesce().await;
    let got = r.got.lock().unwrap().clone();
    assert_eq!(got.len(), 1, "delivered once");
    let (headers, body) = &got[0];
    assert_signed(headers, body);
    assert_eq!(headers["x-attenuo-event-id"].to_str().unwrap(), event_id);
    assert_eq!(h.metric("attenuo_approval_notify_outbox_rows"), 0);
}

/// An approval pending when the server stopped and expired while it was down gets its
/// `approval.expired` notice on start, after the pending one still in the outbox; a second
/// restart sends neither again.
#[tokio::test]
async fn an_approval_that_expired_while_down_gets_its_notice_on_start_once() {
    const ENV: &str = "ATTENUO_TEST_NOTIFY_SECRET_6";
    let (url, dead) = dead_receiver().await;
    let h = Harness::start(&url, ENV, |c| {
        c.approvals.ttl_seconds = 1;
        hanging(c);
    })
    .await;
    let token = h.root().await;
    let id = h.gated(&token, "alice/site").await;
    let expires_at = h.state.leases.approval(&id).unwrap().unwrap().expires_at;
    hang_up(dead).await;
    let clock = h.clock.clone();
    let dir = h.stop().await;
    // Down until after the expiry.
    let left = Duration::try_from(expires_at - clock.now_utc()).unwrap_or_default();
    clock.advance(left + Duration::from_secs(1));

    let (r, hook) = receiver(0).await;
    let h = Harness::start_in(dir, clock, &hook.url("/hook"), ENV, |_| {}).await;
    // Past the watcher's grace after an expiry too, so it looks now.
    h.advance(Duration::from_secs(1));
    let expired = r.wait_for("approval.expired").await;
    assert_eq!(expired["approval_id"], id);
    outbox_drains(&h).await;
    let types: Vec<String> = r
        .delivered()
        .iter()
        .map(|v| {
            assert_eq!(v["approval_id"], id.as_str());
            v["type"].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(types, ["approval.pending", "approval.expired"]);
    for (headers, body) in r.got.lock().unwrap().iter() {
        assert_signed(headers, body);
    }
    let clock = h.clock.clone();
    let dir = h.stop().await;

    let (r2, hook2) = receiver(0).await;
    let h = Harness::start_in(dir, clock, &hook2.url("/hook"), ENV, |_| {}).await;
    // A fresh approval, left to expire: the watcher looks at the old one first (it expired
    // earlier), and the queue delivers in order, so a second notice for the old one would
    // arrive before this one's `approval.expired`. Stopping then flushes anything queued.
    let token = h.root().await;
    let fresh = h.gated(&token, "alice/fresh").await;
    h.advance_past_expiry(&fresh);
    r2.wait_for_approval("approval.expired", &fresh).await;
    h.quiesce().await;
    let types: Vec<String> = r2
        .delivered()
        .iter()
        .map(|v| {
            assert_eq!(
                v["approval_id"],
                fresh.as_str(),
                "nothing is sent again after a second restart"
            );
            v["type"].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(types, ["approval.pending", "approval.expired"]);
    assert_eq!(h.metric("attenuo_approval_notify_outbox_rows"), 0);
}
