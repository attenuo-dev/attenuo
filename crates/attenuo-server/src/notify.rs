//! The approval notifier (`[approvals.notify]`): tells a webhook the deployment owns that an
//! approval is waiting, and again when it was decided or expired, so an operator does not have
//! to watch the console.
//!
//! Where: [`NotifierHandle::pending`] is called by the pipeline after a new pending approval
//! and its `approval_request` record were written, and [`NotifierHandle::decided`] by the
//! approval routes after the decision and its `approval_grant` record were. Both only build a
//! small JSON document and queue it; neither waits on the network. Delivery runs on the
//! `[audit.sink]` queue ([`crate::sink::Queue`], role [`QueueRole::ApprovalNotices`]): bounded,
//! oldest dropped when full, one background thread, jittered exponential backoff, and given
//! up after `max_attempts`. Expiry has no request to hang on, so a watcher thread keeps the
//! pending approvals by expiry time and, once one is due, reads it from the lease store and
//! queues `approval.expired` if it is still pending.
//!
//! Best effort: a notification can be late, dropped (counted in
//! `attenuo_approval_notify_dropped_total`) or, after a retry whose answer was lost, delivered
//! twice (the receiver deduplicates by `event_id`). Nothing here can change a decision, and a
//! receiver that is down or slow never holds up a request.
//!
//! The document carries no token and no arguments: only the call hash
//! (`ToolCall::call_hash`, SHA-256 over server, tool and arguments) stands for the call. Each
//! request is signed: `X-Attenuo-Signature: t=<unix seconds>,v1=<hex HMAC-SHA-256 of
//! "<t>.<body>">` under the secret in the environment variable `secret_env`
//! ([`signature`]).

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use attenuo_audit::{Approval, ApprovalState, LeaseStore};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::{NotifySection, NOTIFY_SECRET_MIN_LEN};
use crate::metrics::Metrics;
use crate::sink::{
    Backoff, Deliver, Queue, QueueHandle, QueueItem, QueueRole, SinkLimits, SinkStatus,
};

/// The signature header: `t=<unix seconds>,v1=<hex HMAC-SHA-256 of "<t>.<body>">`.
pub const SIGNATURE_HEADER: &str = "x-attenuo-signature";
/// The event type (`approval.pending`, `approval.decided`, `approval.expired`).
pub const EVENT_HEADER: &str = "x-attenuo-event";
/// The event id, the same on every retry of one notification.
pub const EVENT_ID_HEADER: &str = "x-attenuo-event-id";

/// Most pending approvals the expiry watcher keeps. Beyond this an approval gets no
/// `approval.expired` notice, and the miss is counted as a drop.
pub const MAX_WATCHED: usize = 10_000;

/// How long after `expires_at` the watcher looks, so the store agrees it has expired.
const EXPIRY_GRACE: Duration = Duration::from_millis(250);

/// What happened to the approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeKind {
    Pending,
    Decided,
    Expired,
}

impl NoticeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "approval.pending",
            Self::Decided => "approval.decided",
            Self::Expired => "approval.expired",
        }
    }
}

/// One notification, its body fixed when it was queued.
#[derive(Debug, Clone)]
pub struct Notice {
    pub kind: NoticeKind,
    pub approval_id: String,
    /// A UUID, the same on every attempt.
    pub event_id: String,
    /// The JSON document, exactly as sent and signed.
    pub body: Vec<u8>,
}

impl Notice {
    pub fn new(kind: NoticeKind, a: &Approval) -> Self {
        let event_id = uuid::Uuid::new_v4().to_string();
        let body = serde_json::to_vec(&notice_json(kind, &event_id, a)).unwrap_or_default();
        Self {
            kind,
            approval_id: a.id.clone(),
            event_id,
            body,
        }
    }
}

impl QueueItem for Notice {
    fn log_id(&self) -> String {
        format!("{} {}", self.kind.as_str(), self.approval_id)
    }
}

fn fmt(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

/// The JSON document for `a`. Only identifiers, names, times and the call hash: no token, no
/// argument values, no labels' content beyond the source tool names.
pub fn notice_json(kind: NoticeKind, event_id: &str, a: &Approval) -> Value {
    let user = &a.chain.originating_user;
    let mut v = json!({
        "type": kind.as_str(),
        "event_id": event_id,
        "approval_id": a.id,
        "decision_id": a.decision_id,
        "chain_id": a.chain_id,
        "server": a.server,
        "tool": a.tool,
        "call_hash": a.call_hash,
        "subject": user.subject,
        "issuer": user.issuer,
        "agent": a.chain.hops.last().map(|h| h.agent.0.as_str()),
        "chain_depth": a.chain.depth(),
        "requested_at": fmt(a.created_at),
        "expires_at": fmt(a.expires_at),
        "reason": reason_summary(a),
    });
    if kind == NoticeKind::Decided {
        let decision = match a.state {
            ApprovalState::Granted | ApprovalState::Consumed => "grant",
            _ => "decline",
        };
        v["decision"] = json!(decision);
        if let Some(p) = &a.approver {
            v["decided_by"] = json!({ "subject": p.subject, "by": p.method.by() });
        }
        if let Some(t) = a.decided_at {
            v["decided_at"] = json!(fmt(t));
        }
    }
    v
}

/// One line on why the call waits: the sources of the run's untrusted results, at most three
/// by name, and how many arguments matched one.
pub fn reason_summary(a: &Approval) -> String {
    let mut sources: Vec<&str> = Vec::new();
    for l in &a.labels {
        if !sources.contains(&l.source.as_str()) {
            sources.push(&l.source);
        }
    }
    let mut s = String::from("a policy asks for approval of this call");
    if !sources.is_empty() {
        let shown = sources
            .iter()
            .take(3)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str("; the run read untrusted results from ");
        s.push_str(&shown);
        if sources.len() > 3 {
            s.push_str(&format!(" and {} more", sources.len() - 3));
        }
    }
    match a.untrusted_args.len() {
        0 => {}
        1 => s.push_str("; 1 argument matches an untrusted result"),
        n => s.push_str(&format!("; {n} arguments match untrusted results")),
    }
    s
}

/// HMAC-SHA-256 of `msg` under `secret`, hex.
pub fn hmac_hex(secret: &[u8], msg: &[u8]) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    hex::encode(ring::hmac::sign(&key, msg).as_ref())
}

/// The [`SIGNATURE_HEADER`] value: `t=<timestamp>,v1=<hex HMAC-SHA-256 of "<timestamp>.<body>">`.
/// The timestamp is signed so that a receiver can refuse an old request replayed to it.
pub fn signature(secret: &[u8], timestamp: u64, body: &[u8]) -> String {
    let mut msg = format!("{timestamp}.").into_bytes();
    msg.extend_from_slice(body);
    format!("t={timestamp},v1={}", hmac_hex(secret, &msg))
}

/// `POST` each notice as JSON, signed.
pub struct WebhookNotify {
    client: reqwest::Client,
    url: String,
    /// For log lines: the URL's host only, since a path or query may carry a credential.
    host: String,
    headers: reqwest::header::HeaderMap,
    secret: Vec<u8>,
}

impl std::fmt::Debug for WebhookNotify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookNotify")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl WebhookNotify {
    /// `headers` are name and value pairs, already read from the environment.
    pub fn new(
        url: &str,
        headers: &[(String, String)],
        secret: Vec<u8>,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let parsed = reqwest::Url::parse(url)?;
        let host = parsed.host_str().unwrap_or_default().to_string();
        let mut map = reqwest::header::HeaderMap::new();
        for (name, value) in headers {
            let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())?;
            let mut value = reqwest::header::HeaderValue::from_str(value).map_err(|_| {
                anyhow::anyhow!(
                    "[approvals.notify] headers: the value for {name} is not a valid header value"
                )
            })?;
            value.set_sensitive(true);
            map.insert(name, value);
        }
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            url: url.to_string(),
            host,
            headers: map,
            secret,
        })
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[async_trait]
impl Deliver<Notice> for WebhookNotify {
    async fn deliver(&self, n: &Notice) -> Result<(), String> {
        let sig = signature(&self.secret, unix_now(), &n.body);
        let resp = self
            .client
            .post(&self.url)
            .headers(self.headers.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(EVENT_HEADER, n.kind.as_str())
            .header(EVENT_ID_HEADER, &n.event_id)
            .header(SIGNATURE_HEADER, sig)
            .body(n.body.clone())
            .send()
            .await
            // The URL is left out of the error: its path or query may hold a credential.
            .map_err(|e| format!("request to {} failed: {}", self.host, e.without_url()))?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(format!("{} answered {status}", self.host))
        }
    }
}

/// Pending approvals by when they expire.
#[derive(Debug, Default)]
struct WatchState {
    due: BTreeSet<(Instant, String)>,
    at: HashMap<String, Instant>,
    stop: bool,
}

#[derive(Debug, Default)]
struct Watch {
    st: Mutex<WatchState>,
    wake: Condvar,
}

impl Watch {
    /// Look at `id` again at `when`. `false` when the watcher is full.
    fn add(&self, id: &str, when: Instant) -> bool {
        let mut st = self.st.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(old) = st.at.remove(id) {
            st.due.remove(&(old, id.to_string()));
        } else if st.at.len() >= MAX_WATCHED {
            return false;
        }
        st.at.insert(id.to_string(), when);
        st.due.insert((when, id.to_string()));
        drop(st);
        self.wake.notify_all();
        true
    }

    fn remove(&self, id: &str) {
        let mut st = self.st.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(old) = st.at.remove(id) {
            st.due.remove(&(old, id.to_string()));
        }
    }

    fn stop(&self) {
        self.st.lock().unwrap_or_else(|e| e.into_inner()).stop = true;
        self.wake.notify_all();
    }

    /// Wait for the next due id; `None` once stopped.
    fn next_due(&self) -> Option<String> {
        let mut st = self.st.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if st.stop {
                return None;
            }
            let now = Instant::now();
            match st.due.first().cloned() {
                Some((when, id)) if when <= now => {
                    st.due.remove(&(when, id.clone()));
                    st.at.remove(&id);
                    return Some(id);
                }
                Some((when, _)) => {
                    st = self
                        .wake
                        .wait_timeout(st, when - now)
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                }
                None => st = self.wake.wait(st).unwrap_or_else(|e| e.into_inner()),
            }
        }
    }
}

/// When to look at an approval that expires at `expires_at`.
fn due_at(expires_at: OffsetDateTime) -> Instant {
    let left = expires_at - OffsetDateTime::now_utc();
    let left = Duration::try_from(left).unwrap_or(Duration::ZERO);
    Instant::now() + left + EXPIRY_GRACE
}

/// The producer end: what the pipeline and the approval routes call. Cheap to clone.
#[derive(Debug, Clone)]
pub struct NotifierHandle {
    queue: QueueHandle<Notice>,
    watch: Arc<Watch>,
    metrics: Arc<Metrics>,
}

impl NotifierHandle {
    /// `a` was just stored as pending: queue `approval.pending` and watch for its expiry.
    pub fn pending(&self, a: &Approval) {
        self.queue.push(Notice::new(NoticeKind::Pending, a));
        if !self.watch.add(&a.id, due_at(a.expires_at)) {
            self.metrics.approval_notify_dropped();
            tracing::warn!(
                approval = %a.id,
                max = MAX_WATCHED,
                "[approvals.notify] too many pending approvals watched: this one gets no \
                 approval.expired notice"
            );
        }
    }

    /// `a` was just granted or declined: queue `approval.decided`.
    pub fn decided(&self, a: &Approval) {
        self.watch.remove(&a.id);
        self.queue.push(Notice::new(NoticeKind::Decided, a));
    }
}

/// A running notifier: the queue, its delivery thread and the expiry watcher.
#[derive(Debug)]
pub struct ApprovalNotifier {
    queue: Queue<Notice>,
    watch: Arc<Watch>,
    watcher: Mutex<Option<std::thread::JoinHandle<()>>>,
    metrics: Arc<Metrics>,
}

impl ApprovalNotifier {
    /// Validate `cfg`, read its secret and headers from the environment, and start. The
    /// error names a missing variable, never a value.
    pub fn start(
        cfg: &NotifySection,
        metrics: Arc<Metrics>,
        leases: Arc<dyn LeaseStore>,
    ) -> anyhow::Result<Self> {
        cfg.validate()?;
        let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        let secret = env(&cfg.secret_env).ok_or_else(|| {
            anyhow::anyhow!(
                "[approvals.notify] the signing secret is not set: put at least \
                 {NOTIFY_SECRET_MIN_LEN} bytes in the environment variable {}",
                cfg.secret_env
            )
        })?;
        if secret.len() < NOTIFY_SECRET_MIN_LEN {
            anyhow::bail!(
                "[approvals.notify] the signing secret in {} is shorter than \
                 {NOTIFY_SECRET_MIN_LEN} bytes",
                cfg.secret_env
            );
        }
        let mut headers = Vec::new();
        for (name, var) in &cfg.headers {
            let value = env(var).ok_or_else(|| {
                anyhow::anyhow!(
                    "[approvals.notify] headers: {name} names the environment variable {var}, \
                     which is not set"
                )
            })?;
            headers.push((name.clone(), value));
        }
        let deliver = WebhookNotify::new(
            &cfg.url,
            &headers,
            secret.into_bytes(),
            Duration::from_secs(cfg.timeout_seconds),
        )?;
        let host = deliver.host.clone();
        if cfg.url.starts_with("http://")
            && !matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]")
        {
            tracing::warn!(
                host = %host,
                "[approvals.notify] url is plain http to a host other than loopback: \
                 notifications travel unencrypted"
            );
        }
        let limits = SinkLimits {
            capacity: cfg.queue_capacity,
            max_lag: Duration::from_secs(cfg.max_lag_seconds),
            backoff: Backoff {
                initial: Duration::from_millis(cfg.initial_backoff_ms),
                max: Duration::from_secs(cfg.max_backoff_seconds),
            },
        };
        let n = Self::with_deliver(Box::new(deliver), limits, cfg.max_attempts, metrics, leases)?;
        tracing::info!(host = %host, capacity = cfg.queue_capacity, "[approvals.notify] notifying a webhook of approvals");
        Ok(n)
    }

    /// Start with any deliverer (tests).
    pub fn with_deliver(
        deliver: Box<dyn Deliver<Notice>>,
        limits: SinkLimits,
        max_attempts: u32,
        metrics: Arc<Metrics>,
        leases: Arc<dyn LeaseStore>,
    ) -> anyhow::Result<Self> {
        let queue = Queue::start(
            deliver,
            limits,
            QueueRole::ApprovalNotices { max_attempts },
            metrics.clone(),
        )?;
        let watch = Arc::new(Watch::default());
        let (w, q, m) = (watch.clone(), queue.handle(), metrics.clone());
        let watcher = std::thread::Builder::new()
            .name("attenuo-approval-expiry".into())
            .spawn(move || watch_expiry(&w, leases.as_ref(), &q, &m))?;
        Ok(Self {
            queue,
            watch,
            watcher: Mutex::new(Some(watcher)),
            metrics,
        })
    }

    pub fn handle(&self) -> NotifierHandle {
        NotifierHandle {
            queue: self.queue.handle(),
            watch: self.watch.clone(),
            metrics: self.metrics.clone(),
        }
    }

    pub fn status(&self) -> SinkStatus {
        self.queue.status()
    }

    /// Stop watching, then deliver what is queued until `grace` has passed. Blocks.
    pub fn shutdown(&self, grace: Duration) {
        self.watch.stop();
        if let Some(t) = self.watcher.lock().ok().and_then(|mut t| t.take()) {
            let _ = t.join();
        }
        self.queue.shutdown(grace);
    }
}

impl Drop for ApprovalNotifier {
    fn drop(&mut self) {
        self.watch.stop();
    }
}

/// The expiry watcher: queue `approval.expired` for each watched approval still pending once
/// its expiry has passed.
fn watch_expiry(
    watch: &Watch,
    leases: &dyn LeaseStore,
    queue: &QueueHandle<Notice>,
    metrics: &Metrics,
) {
    while let Some(id) = watch.next_due() {
        match leases.approval(&id) {
            Ok(Some(a)) if a.state == ApprovalState::Pending => {
                if a.is_expired(OffsetDateTime::now_utc()) {
                    queue.push(Notice::new(NoticeKind::Expired, &a));
                } else {
                    // The clocks disagree by a little: look again.
                    watch.add(
                        &a.id,
                        due_at(a.expires_at).max(Instant::now() + EXPIRY_GRACE),
                    );
                }
            }
            // Decided, used, or gone (pruned, or dropped after a failed audit append).
            Ok(_) => {}
            Err(e) => {
                metrics.approval_notify_dropped();
                tracing::warn!(approval = %id, error = %e, "[approvals.notify] approval unreadable at its expiry: no approval.expired notice");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attenuo_audit::{ApprovalLabel, ApprovalMethod, Approver};
    use attenuo_core::{AgentId, Capability, DelegationChain, Hop, LeaseId, OriginatingUser};

    fn approval(state: ApprovalState) -> Approval {
        let t = OffsetDateTime::from_unix_timestamp(1_780_000_000).unwrap();
        let hop = |agent: &str, lease: &str| Hop {
            agent: AgentId::new(agent),
            capabilities: std::iter::once(Capability::new("github", "*")).collect(),
            lease: LeaseId::new(lease),
            expires_at: t + time::Duration::hours(1),
            issued_at: t,
        };
        let chain = DelegationChain {
            originating_user: OriginatingUser {
                subject: "alice".into(),
                issuer: "https://idp.example".into(),
                authenticated_at: t,
                attributes: Default::default(),
            },
            hops: vec![hop("planner", "l0"), hop("coder", "l1")],
        };
        Approval {
            id: "11111111-1111-4111-8111-111111111111".into(),
            chain_id: LeaseId::new("l0"),
            lease: LeaseId::new("l1"),
            call_hash: "ab".repeat(32),
            server: "github".into(),
            tool: "delete_repo".into(),
            arguments: json!({"repo": "alice/site", "token": "ghp_secret"}),
            labels: vec![
                ApprovalLabel {
                    source: "github/read_web".into(),
                    seq: 3,
                },
                ApprovalLabel {
                    source: "github/read_web".into(),
                    seq: 4,
                },
            ],
            untrusted_args: Vec::new(),
            decision_id: "22222222-2222-4222-8222-222222222222".into(),
            chain,
            created_at: t,
            expires_at: t + time::Duration::seconds(120),
            state,
            approver: None,
            decided_at: None,
            consumed_by: None,
            jkt: None,
        }
    }

    #[test]
    fn pending_notice_has_the_fields_and_no_arguments() {
        let a = approval(ApprovalState::Pending);
        let v = notice_json(NoticeKind::Pending, "e1", &a);
        assert_eq!(
            v,
            json!({
                "type": "approval.pending",
                "event_id": "e1",
                "approval_id": a.id,
                "decision_id": a.decision_id,
                "chain_id": "l0",
                "server": "github",
                "tool": "delete_repo",
                "call_hash": a.call_hash,
                "subject": "alice",
                "issuer": "https://idp.example",
                "agent": "coder",
                "chain_depth": 2,
                "requested_at": "2026-05-28T20:26:40Z",
                "expires_at": "2026-05-28T20:28:40Z",
                "reason": "a policy asks for approval of this call; the run read untrusted \
                           results from github/read_web",
            })
        );
        let body = String::from_utf8(Notice::new(NoticeKind::Pending, &a).body).unwrap();
        assert!(
            !body.contains("alice/site") && !body.contains("ghp_secret"),
            "{body}"
        );
        assert!(!body.contains("arguments"), "{body}");
    }

    #[test]
    fn decided_notice_names_the_decision_and_the_approver() {
        let mut a = approval(ApprovalState::Declined);
        a.approver = Some(Approver {
            subject: "urn:attenuo:admin".into(),
            method: ApprovalMethod::AdminToken,
        });
        a.decided_at = Some(a.created_at + time::Duration::seconds(5));
        let v = notice_json(NoticeKind::Decided, "e2", &a);
        assert_eq!(v["type"], "approval.decided");
        assert_eq!(v["decision"], "decline");
        assert_eq!(
            v["decided_by"],
            json!({"subject": "urn:attenuo:admin", "by": "operator"})
        );
        assert_eq!(v["decided_at"], "2026-05-28T20:26:45Z");
        a.state = ApprovalState::Granted;
        assert_eq!(
            notice_json(NoticeKind::Decided, "e3", &a)["decision"],
            "grant"
        );
        // Expired and pending notices carry no decision.
        let e = notice_json(NoticeKind::Expired, "e4", &a);
        assert_eq!(e["type"], "approval.expired");
        assert!(e.get("decision").is_none() && e.get("decided_by").is_none());
    }

    #[test]
    fn reason_lists_at_most_three_sources_and_counts_matched_arguments() {
        let mut a = approval(ApprovalState::Pending);
        a.labels.clear();
        assert_eq!(
            reason_summary(&a),
            "a policy asks for approval of this call"
        );
        a.labels = ["a/x", "b/y", "c/z", "d/w", "e/v"]
            .iter()
            .enumerate()
            .map(|(i, s)| ApprovalLabel {
                source: (*s).into(),
                seq: i as u64,
            })
            .collect();
        assert_eq!(
            reason_summary(&a),
            "a policy asks for approval of this call; the run read untrusted results from \
             a/x, b/y, c/z and 2 more"
        );
    }

    /// RFC 4231 test case 2, then the header built on it.
    #[test]
    fn signature_is_hmac_sha256_over_timestamp_dot_body() {
        assert_eq!(
            hmac_hex(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let body = br#"{"type":"approval.pending"}"#;
        let sig = signature(b"Jefe", 1_780_000_000, body);
        let mut msg = b"1780000000.".to_vec();
        msg.extend_from_slice(body);
        assert_eq!(sig, format!("t=1780000000,v1={}", hmac_hex(b"Jefe", &msg)));
        assert_ne!(
            sig,
            signature(b"Jefe", 1_780_000_001, body),
            "the time is signed"
        );
        assert_ne!(sig, signature(b"other", 1_780_000_000, body));
    }

    #[test]
    fn webhook_debug_shows_the_host_only() {
        let w = WebhookNotify::new(
            "https://hooks.example/p/very-secret-path?key=k",
            &[("authorization".into(), "Bearer s3cret".into())],
            b"x".repeat(32),
            Duration::from_secs(1),
        )
        .unwrap();
        let d = format!("{w:?}");
        assert!(d.contains("hooks.example"), "{d}");
        assert!(!d.contains("very-secret") && !d.contains("s3cret") && !d.contains("key=k"));
    }

    #[test]
    fn config_validation() {
        let mut c = NotifySection::new("https://hooks.example/attenuo");
        c.validate().unwrap();
        for bad in [
            "ftp://hooks.example/",
            "https://user:pw@hooks.example/",
            "https://hooks.example/#x",
            "not a url",
        ] {
            c.url = bad.into();
            assert!(c.validate().is_err(), "{bad}");
        }
        c.url = "https://hooks.example/".into();
        c.headers.insert("X-Attenuo-Signature".into(), "E".into());
        assert!(c.validate().is_err());
        c.headers.clear();
        c.headers.insert("content-type".into(), "E".into());
        assert!(c.validate().is_err());
        c.headers.clear();
        c.headers.insert("authorization".into(), String::new());
        assert!(c.validate().is_err());
        c.headers.clear();
        c.max_attempts = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn watch_returns_ids_in_expiry_order_and_forgets_removed_ones() {
        let w = Watch::default();
        let now = Instant::now();
        assert!(w.add("b", now + Duration::from_millis(20)));
        assert!(w.add("a", now));
        assert!(w.add("c", now + Duration::from_millis(10)));
        w.remove("c");
        assert_eq!(w.next_due().as_deref(), Some("a"));
        assert_eq!(w.next_due().as_deref(), Some("b"));
        w.stop();
        assert_eq!(w.next_due(), None);
    }
}
