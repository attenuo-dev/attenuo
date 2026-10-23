//! The checkpoint sink (`[audit.sink]`, SR-21): ships every signed audit checkpoint off the
//! host as soon as it is created.
//!
//! Why: a checkpoint is signed with the server's own issuer key. An attacker who holds the
//! host and that key can rewrite the SQLite log and sign new checkpoints over the rewritten
//! history; an export of it verifies against the JWKS. A copy that already left the host
//! cannot be rewritten, and `onbehalf audit verify --file <export> --checkpoints <shipped>`
//! reports any checkpoint signed again after it was shipped
//! ([`onbehalf_audit::cross_check`]).
//!
//! How: the log's `on_created` hook runs after the commit that wrote the checkpoint was synced
//! (SR-50) and calls [`SinkHandle::push`], which only queues. The queue is bounded
//! (`queue_capacity`); when it is full the oldest queued checkpoint is dropped, because every
//! later checkpoint covers the entries an earlier one does, and
//! `onbehalf_audit_sink_dropped_total` counts it. One background thread, with its own
//! single-threaded Tokio runtime, delivers the queue in order. A failed delivery is retried
//! with exponential backoff and full jitter between half and all of the delay (`initial_backoff_ms`
//! doubling up to `max_backoff_seconds`) until it succeeds; it is never skipped, so a sink
//! that keeps failing holds the queue until it fills. [`SinkHandle::status`] says the sink is
//! degraded (on `/readyz`) when the queue is full or the oldest undelivered checkpoint is older
//! than `max_lag_seconds`.
//!
//! Three deliverers: [`WebhookDeliver`] (`POST`, any 2xx), [`FileDeliver`] (append one JSON
//! line, `fsync`), and [`S3Deliver`] (`PUT` with AWS Signature Version 4, implemented here on
//! `ring` HMAC and `sha2`).

use std::collections::VecDeque;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;
use onbehalf_audit::{Checkpoint, ShippedCheckpoint};
use sha2::{Digest, Sha256};

use crate::config::{SinkKind, SinkSection, SINK_TOKEN_ENV};
use crate::metrics::Metrics;

/// Delivers one shipped checkpoint. `Err` is retried.
#[async_trait]
pub trait Deliver: Send + Sync {
    async fn deliver(&self, shipped: &ShippedCheckpoint) -> Result<(), String>;
}

/// Exponential backoff with jitter: attempt `n` (from 0) waits a uniformly random time
/// between half and all of `min(initial * 2^n, max)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    pub initial: Duration,
    pub max: Duration,
}

impl Backoff {
    /// The ceiling for attempt `n`, before jitter.
    pub fn ceiling(&self, attempt: u32) -> Duration {
        let factor = 1u32.checked_shl(attempt.min(31)).unwrap_or(u32::MAX);
        self.initial.saturating_mul(factor).min(self.max)
    }

    /// The delay for attempt `n`, with `unit` in `[0, 1)` choosing where in
    /// `[ceiling/2, ceiling]` it lands.
    pub fn delay(&self, attempt: u32, unit: f64) -> Duration {
        let c = self.ceiling(attempt);
        let half = c / 2;
        half + (c - half).mul_f64(unit.clamp(0.0, 1.0))
    }
}

/// A cheap source of jitter (splitmix64); not for anything secret.
#[derive(Debug)]
struct Jitter(u64);

impl Jitter {
    fn new() -> Self {
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        Self(seed ^ (std::process::id() as u64).rotate_left(32))
    }

    fn unit(&mut self) -> f64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        (z >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Queue limits and timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkLimits {
    pub capacity: usize,
    pub max_lag: Duration,
    pub backoff: Backoff,
}

impl SinkLimits {
    pub fn from_config(cfg: &SinkSection) -> Self {
        Self {
            capacity: cfg.queue_capacity,
            max_lag: Duration::from_secs(cfg.max_lag_seconds),
            backoff: Backoff {
                initial: Duration::from_millis(cfg.initial_backoff_ms),
                max: Duration::from_secs(cfg.max_backoff_seconds),
            },
        }
    }
}

#[derive(Debug)]
struct Queued {
    shipped: ShippedCheckpoint,
    since: Instant,
    since_wall: SystemTime,
}

#[derive(Debug, Default)]
struct State {
    queue: VecDeque<Queued>,
    /// The checkpoint being delivered, by when it was queued.
    in_flight: Option<(Instant, SystemTime)>,
    /// First failure of the current delivery; cleared on success.
    failing_since: Option<Instant>,
    last_error: Option<String>,
    /// Shutting down: deliver what is queued until this deadline, then stop.
    stop_at: Option<Instant>,
}

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
    wake: Condvar,
    limits: SinkLimits,
    metrics: Arc<Metrics>,
    public_url: Option<String>,
    /// Test hook: delivered checkpoints, by count.
    delivered: AtomicU64,
}

impl Shared {
    fn oldest(st: &State) -> Option<(Instant, SystemTime)> {
        st.in_flight
            .or_else(|| st.queue.front().map(|q| (q.since, q.since_wall)))
    }

    /// Refresh the depth and oldest-undelivered gauges. Call with the lock held.
    fn gauges(&self, st: &State) {
        self.metrics.audit_sink_queue(
            st.queue.len() as u64,
            Self::oldest(st).map(|(_, wall)| wall),
        );
    }
}

/// Whether the sink keeps up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkStatus {
    pub queued: usize,
    pub capacity: usize,
    /// Age of the oldest checkpoint not yet delivered (zero when none).
    pub lag: Duration,
    /// How long the current delivery has been failing.
    pub failing_for: Option<Duration>,
    pub last_error: Option<String>,
    /// The queue is full, or `lag` (or `failing_for`) exceeds `max_lag_seconds`.
    pub degraded: bool,
}

/// The queue end the log's hook pushes into. Cheap to clone.
#[derive(Debug, Clone)]
pub struct SinkHandle {
    shared: Arc<Shared>,
}

impl SinkHandle {
    /// Queue `cp` for delivery. Never blocks on the network or on disk.
    pub fn push(&self, cp: &Checkpoint) {
        let shipped = ShippedCheckpoint::new(cp, self.shared.public_url.clone());
        let Ok(mut st) = self.shared.state.lock() else {
            return;
        };
        if st.queue.len() >= self.shared.limits.capacity {
            if let Some(old) = st.queue.pop_front() {
                self.shared.metrics.audit_sink_dropped();
                tracing::error!(
                    dropped_seq = old.shipped.checkpoint.seq,
                    capacity = self.shared.limits.capacity,
                    "[audit.sink] queue full: dropped the oldest undelivered checkpoint"
                );
            }
        }
        st.queue.push_back(Queued {
            shipped,
            since: Instant::now(),
            since_wall: SystemTime::now(),
        });
        self.shared.gauges(&st);
        drop(st);
        self.shared.wake.notify_all();
    }

    pub fn status(&self) -> SinkStatus {
        self.status_at(Instant::now())
    }

    fn status_at(&self, now: Instant) -> SinkStatus {
        let st = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
        let limits = self.shared.limits;
        let lag =
            Shared::oldest(&st).map_or(Duration::ZERO, |(t, _)| now.saturating_duration_since(t));
        let failing_for = st.failing_since.map(|t| now.saturating_duration_since(t));
        let full = st.queue.len() >= limits.capacity;
        let degraded =
            full || lag > limits.max_lag || failing_for.is_some_and(|f| f > limits.max_lag);
        SinkStatus {
            queued: st.queue.len(),
            capacity: limits.capacity,
            lag,
            failing_for,
            last_error: st.last_error.clone(),
            degraded,
        }
    }

    /// Checkpoints delivered since start.
    pub fn delivered(&self) -> u64 {
        self.shared.delivered.load(Ordering::Relaxed)
    }
}

/// A running sink: the queue plus its delivery thread. Dropping it stops the thread without
/// waiting; [`shutdown`](Self::shutdown) gives queued checkpoints a grace period first.
#[derive(Debug)]
pub struct CheckpointSink {
    handle: SinkHandle,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    kind: SinkKind,
}

impl CheckpointSink {
    /// Validate `cfg` and start delivering.
    pub fn start(
        cfg: &SinkSection,
        public_url: Option<String>,
        metrics: Arc<Metrics>,
    ) -> anyhow::Result<Self> {
        cfg.validate()?;
        let timeout = Duration::from_secs(cfg.timeout_seconds);
        let deliver: Box<dyn Deliver> = match cfg.kind {
            SinkKind::Webhook => Box::new(WebhookDeliver::new(
                cfg.url.clone().unwrap_or_default(),
                cfg.bearer_token
                    .clone()
                    .or_else(|| std::env::var(SINK_TOKEN_ENV).ok().filter(|t| !t.is_empty())),
                timeout,
            )?),
            SinkKind::File => Box::new(FileDeliver::new(cfg.path.clone().unwrap_or_default())?),
            SinkKind::S3 => Box::new(S3Deliver::from_config(cfg, timeout)?),
        };
        let mut sink =
            Self::with_deliver(deliver, SinkLimits::from_config(cfg), public_url, metrics)?;
        sink.kind = cfg.kind;
        tracing::info!(kind = %cfg.kind, capacity = cfg.queue_capacity, "[audit.sink] shipping checkpoints off the host");
        Ok(sink)
    }

    /// Start with any deliverer (tests).
    pub fn with_deliver(
        deliver: Box<dyn Deliver>,
        limits: SinkLimits,
        public_url: Option<String>,
        metrics: Arc<Metrics>,
    ) -> anyhow::Result<Self> {
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            wake: Condvar::new(),
            limits,
            metrics,
            public_url,
            delivered: AtomicU64::new(0),
        });
        let worker = shared.clone();
        let thread = std::thread::Builder::new()
            .name("onbehalf-ckpt-sink".into())
            .spawn(move || run(worker, deliver))?;
        Ok(Self {
            handle: SinkHandle { shared },
            thread: Mutex::new(Some(thread)),
            kind: SinkKind::Webhook,
        })
    }

    pub fn handle(&self) -> SinkHandle {
        self.handle.clone()
    }

    pub fn kind(&self) -> SinkKind {
        self.kind
    }

    pub fn status(&self) -> SinkStatus {
        self.handle.status()
    }

    /// Stop after delivering what is queued, giving up at `grace`. Blocks (call it from a
    /// blocking context); a request already in flight can add its timeout.
    pub fn shutdown(&self, grace: Duration) {
        self.stop(Instant::now() + grace);
        let thread = self.thread.lock().ok().and_then(|mut t| t.take());
        if let Some(t) = thread {
            let _ = t.join();
        }
    }

    fn stop(&self, at: Instant) {
        if let Ok(mut st) = self.handle.shared.state.lock() {
            st.stop_at = Some(st.stop_at.map_or(at, |s| s.min(at)));
        }
        self.handle.shared.wake.notify_all();
    }
}

impl Drop for CheckpointSink {
    fn drop(&mut self) {
        self.stop(Instant::now());
    }
}

/// The delivery thread.
fn run(shared: Arc<Shared>, deliver: Box<dyn Deliver>) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "[audit.sink] cannot start its runtime; checkpoints will not be shipped");
            return;
        }
    };
    let mut jitter = Jitter::new();
    loop {
        // Next checkpoint, or stop.
        let item = {
            let mut st = shared.state.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                let stopping = st.stop_at.is_some_and(|t| Instant::now() >= t);
                if stopping {
                    if !st.queue.is_empty() {
                        tracing::error!(
                            undelivered = st.queue.len(),
                            "[audit.sink] stopping with checkpoints not shipped"
                        );
                    }
                    return;
                }
                if let Some(q) = st.queue.pop_front() {
                    st.in_flight = Some((q.since, q.since_wall));
                    break q;
                }
                if st.stop_at.is_some() {
                    return; // stopping and nothing left
                }
                st = shared.wake.wait(st).unwrap_or_else(|e| e.into_inner());
            }
        };
        let mut attempt = 0u32;
        loop {
            let result = rt.block_on(deliver.deliver(&item.shipped));
            let mut st = shared.state.lock().unwrap_or_else(|e| e.into_inner());
            match result {
                Ok(()) => {
                    st.in_flight = None;
                    st.failing_since = None;
                    st.last_error = None;
                    shared.gauges(&st);
                    shared.delivered.fetch_add(1, Ordering::Relaxed);
                    shared.metrics.audit_sink_delivered();
                    break;
                }
                Err(e) => {
                    shared.metrics.audit_sink_failure();
                    st.failing_since.get_or_insert_with(Instant::now);
                    tracing::warn!(
                        seq = item.shipped.checkpoint.seq,
                        attempt,
                        error = %e,
                        "[audit.sink] delivering a checkpoint failed; retrying"
                    );
                    st.last_error = Some(e);
                    let wait = shared.limits.backoff.delay(attempt, jitter.unit());
                    attempt = attempt.saturating_add(1);
                    let until = Instant::now() + wait;
                    // Sleep, but wake for a shutdown whose deadline has passed.
                    loop {
                        let now = Instant::now();
                        if st.stop_at.is_some_and(|t| now >= t) {
                            tracing::error!(
                                seq = item.shipped.checkpoint.seq,
                                undelivered = st.queue.len() + 1,
                                "[audit.sink] stopping with checkpoints not shipped"
                            );
                            return;
                        }
                        if now >= until {
                            break;
                        }
                        let mut d = until - now;
                        if let Some(t) = st.stop_at {
                            d = d.min(t.saturating_duration_since(now));
                        }
                        st = shared
                            .wake
                            .wait_timeout(st, d)
                            .unwrap_or_else(|e| e.into_inner())
                            .0;
                    }
                }
            }
        }
    }
}

/// `POST` the shipped checkpoint as JSON.
#[derive(Debug)]
pub struct WebhookDeliver {
    client: reqwest::Client,
    url: String,
    bearer: Option<String>,
}

impl WebhookDeliver {
    pub fn new(url: String, bearer: Option<String>, timeout: Duration) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            url,
            bearer,
        })
    }
}

#[async_trait]
impl Deliver for WebhookDeliver {
    async fn deliver(&self, s: &ShippedCheckpoint) -> Result<(), String> {
        let mut req = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("x-onbehalf-checkpoint-seq", s.checkpoint.seq.to_string())
            .header("x-onbehalf-checkpoint-sha256", &s.checkpoint_sha256)
            .body(s.to_canonical_json());
        if let Some(t) = &self.bearer {
            req = req.bearer_auth(t);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(format!("receiver answered {status}"))
        }
    }
}

/// Append one JSON line per checkpoint and sync it.
#[derive(Debug)]
pub struct FileDeliver {
    path: PathBuf,
}

impl FileDeliver {
    /// Checks at startup that `path` can be opened for appending.
    pub fn new(path: PathBuf) -> anyhow::Result<Self> {
        open_append(&path)
            .map_err(|e| anyhow::anyhow!("[audit.sink] path {}: {e}", path.display()))?;
        Ok(Self { path })
    }
}

fn open_append(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

#[async_trait]
impl Deliver for FileDeliver {
    async fn deliver(&self, s: &ShippedCheckpoint) -> Result<(), String> {
        // Opened per line, so an operator's rotation (rename, new file) is picked up.
        let write = || -> std::io::Result<()> {
            let mut f = open_append(&self.path)?;
            f.write_all(s.to_line().as_bytes())?;
            f.sync_data()
        };
        write().map_err(|e| format!("{}: {e}", self.path.display()))
    }
}

/// Credentials for [`S3Deliver`].
#[derive(Clone)]
pub struct S3Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

impl std::fmt::Debug for S3Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Credentials")
            .field("access_key_id", &self.access_key_id)
            .finish_non_exhaustive()
    }
}

/// `PUT` each checkpoint as `<endpoint>/<bucket>/<prefix><seq>-<sha16>.json`, signed with
/// AWS Signature Version 4.
#[derive(Debug)]
pub struct S3Deliver {
    client: reqwest::Client,
    endpoint: String,
    bucket: String,
    region: String,
    prefix: String,
    creds: S3Credentials,
}

impl S3Deliver {
    fn from_config(cfg: &SinkSection, timeout: Duration) -> anyhow::Result<Self> {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let access_key_id = cfg
            .access_key_id
            .clone()
            .or_else(|| env("AWS_ACCESS_KEY_ID"))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "[audit.sink] kind = \"s3\" needs access_key_id (or AWS_ACCESS_KEY_ID)"
                )
            })?;
        let secret_access_key = cfg
            .secret_access_key
            .clone()
            .or_else(|| env("AWS_SECRET_ACCESS_KEY"))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "[audit.sink] kind = \"s3\" needs secret_access_key (or AWS_SECRET_ACCESS_KEY)"
                )
            })?;
        Self::new(
            cfg.endpoint.clone().unwrap_or_default(),
            cfg.bucket.clone().unwrap_or_default(),
            cfg.region.clone().unwrap_or_else(|| "us-east-1".into()),
            cfg.prefix
                .clone()
                .unwrap_or_else(|| "onbehalf/checkpoints/".into()),
            S3Credentials {
                access_key_id,
                secret_access_key,
                session_token: cfg
                    .session_token
                    .clone()
                    .or_else(|| env("AWS_SESSION_TOKEN")),
            },
            timeout,
        )
    }

    pub fn new(
        endpoint: String,
        bucket: String,
        region: String,
        prefix: String,
        creds: S3Credentials,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            endpoint: endpoint.trim_end_matches('/').to_string(),
            bucket,
            region,
            prefix,
            creds,
        })
    }

    /// The object key for `s`.
    pub fn key(&self, s: &ShippedCheckpoint) -> String {
        format!(
            "{}{:020}-{}.json",
            self.prefix,
            s.checkpoint.seq,
            &s.checkpoint_sha256[..16.min(s.checkpoint_sha256.len())]
        )
    }
}

#[async_trait]
impl Deliver for S3Deliver {
    async fn deliver(&self, s: &ShippedCheckpoint) -> Result<(), String> {
        let body = s.to_canonical_json();
        let path = format!(
            "/{}/{}",
            uri_encode(&self.bucket, true),
            uri_encode(&self.key(s), false)
        );
        let url = format!("{}{}", self.endpoint, path);
        let host = self
            .endpoint
            .split_once("://")
            .map_or("", |(_, h)| h)
            .to_string();
        let payload_hash = hex::encode(Sha256::digest(&body));
        let amz_date = amz_date(SystemTime::now());
        let mut headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("host".to_string(), host),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-date".to_string(), amz_date.clone()),
        ];
        if let Some(t) = &self.creds.session_token {
            headers.push(("x-amz-security-token".to_string(), t.clone()));
        }
        let auth = sigv4_authorization(&SigV4Request {
            method: "PUT",
            canonical_uri: &path,
            canonical_query: "",
            headers: &headers,
            payload_sha256: &payload_hash,
            region: &self.region,
            service: "s3",
            amz_date: &amz_date,
            creds: &self.creds,
        });
        let mut req = self
            .client
            .put(&url)
            .body(body)
            .header("authorization", auth);
        for (k, v) in &headers {
            if k != "host" {
                req = req.header(k.as_str(), v.as_str());
            }
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(format!("S3 answered {status}"))
        }
    }
}

/// `YYYYMMDD'T'HHMMSS'Z'` in UTC.
pub fn amz_date(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let dt = time::OffsetDateTime::from_unix_timestamp(secs as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

/// RFC 3986 percent-encoding as SigV4 wants it: unreserved characters kept, everything else
/// `%XX` (uppercase); `/` kept unless `encode_slash`.
pub fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// What SigV4 signs.
pub struct SigV4Request<'a> {
    pub method: &'a str,
    /// Already encoded with [`uri_encode`].
    pub canonical_uri: &'a str,
    pub canonical_query: &'a str,
    /// Lowercase names; every header listed here is signed.
    pub headers: &'a [(String, String)],
    pub payload_sha256: &'a str,
    pub region: &'a str,
    pub service: &'a str,
    pub amz_date: &'a str,
    pub creds: &'a S3Credentials,
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    ring::hmac::sign(&k, data).as_ref().to_vec()
}

/// The `Authorization` header value for `r` (AWS Signature Version 4, header form).
pub fn sigv4_authorization(r: &SigV4Request<'_>) -> String {
    let mut headers: Vec<(String, String)> = r
        .headers
        .iter()
        .map(|(k, v)| {
            let v = v.split_whitespace().collect::<Vec<_>>().join(" ");
            (k.to_ascii_lowercase(), v)
        })
        .collect();
    headers.sort();
    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        r.method,
        r.canonical_uri,
        r.canonical_query,
        canonical_headers,
        signed_headers,
        r.payload_sha256
    );
    let date = &r.amz_date[..8];
    let scope = format!("{date}/{}/{}/aws4_request", r.region, r.service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        r.amz_date,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let k_date = hmac(
        format!("AWS4{}", r.creds.secret_access_key).as_bytes(),
        date.as_bytes(),
    );
    let k_region = hmac(&k_date, r.region.as_bytes());
    let k_service = hmac(&k_region, r.service.as_bytes());
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        r.creds.access_key_id
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn cp(seq: u64) -> Checkpoint {
        Checkpoint {
            seq,
            head_hash: format!("{seq:064x}"),
            at: "2026-10-23T00:00:00Z".into(),
            kid: "k1".into(),
            signature: "sig".into(),
        }
    }

    fn limits(capacity: usize, max_lag: Duration) -> SinkLimits {
        SinkLimits {
            capacity,
            max_lag,
            backoff: Backoff {
                initial: Duration::from_millis(1),
                max: Duration::from_millis(5),
            },
        }
    }

    /// Fails while `fail` is set; records what it delivered.
    #[derive(Default)]
    struct Fake {
        fail: std::sync::atomic::AtomicBool,
        attempts: AtomicUsize,
        got: Mutex<Vec<u64>>,
    }

    struct FakeRef(Arc<Fake>);

    #[async_trait]
    impl Deliver for FakeRef {
        async fn deliver(&self, s: &ShippedCheckpoint) -> Result<(), String> {
            self.0.attempts.fetch_add(1, Ordering::SeqCst);
            if self.0.fail.load(Ordering::SeqCst) {
                return Err("down".into());
            }
            self.0.got.lock().unwrap().push(s.checkpoint.seq);
            Ok(())
        }
    }

    fn wait_until(mut f: impl FnMut() -> bool) {
        let end = Instant::now() + Duration::from_secs(10);
        while !f() {
            assert!(Instant::now() < end, "timed out");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn backoff_doubles_caps_and_jitters_within_half_to_full() {
        let b = Backoff {
            initial: Duration::from_millis(500),
            max: Duration::from_secs(60),
        };
        assert_eq!(b.ceiling(0), Duration::from_millis(500));
        assert_eq!(b.ceiling(1), Duration::from_secs(1));
        assert_eq!(b.ceiling(3), Duration::from_secs(4));
        assert_eq!(b.ceiling(7), Duration::from_secs(60));
        assert_eq!(b.ceiling(u32::MAX), Duration::from_secs(60));
        assert_eq!(b.delay(1, 0.0), Duration::from_millis(500));
        assert_eq!(b.delay(1, 1.0), Duration::from_secs(1));
        let mut j = Jitter::new();
        let mut distinct = std::collections::BTreeSet::new();
        for _ in 0..200 {
            let u = j.unit();
            assert!((0.0..1.0).contains(&u));
            let d = b.delay(2, u);
            assert!(d >= Duration::from_secs(1) && d <= Duration::from_secs(2));
            distinct.insert(d);
        }
        assert!(distinct.len() > 100, "jitter spreads the delays");
    }

    #[test]
    fn delivers_in_order_and_retries_until_the_sink_recovers() {
        let fake = Arc::new(Fake::default());
        fake.fail.store(true, Ordering::SeqCst);
        let metrics = Metrics::new();
        let sink = CheckpointSink::with_deliver(
            Box::new(FakeRef(fake.clone())),
            limits(16, Duration::from_secs(60)),
            Some("https://ob.example".into()),
            metrics.clone(),
        )
        .unwrap();
        let h = sink.handle();
        for s in 1..=3 {
            h.push(&cp(s));
        }
        wait_until(|| fake.attempts.load(Ordering::SeqCst) >= 4);
        assert!(h.status().failing_for.is_some());
        assert_eq!(h.status().last_error.as_deref(), Some("down"));
        fake.fail.store(false, Ordering::SeqCst);
        wait_until(|| h.delivered() == 3);
        assert_eq!(*fake.got.lock().unwrap(), vec![1, 2, 3]);
        let st = h.status();
        assert_eq!(
            (st.queued, st.lag, st.failing_for, st.degraded),
            (0, Duration::ZERO, None, false)
        );
        let text = metrics.render();
        assert!(text.contains("onbehalf_audit_sink_delivered_total 3\n"));
        assert!(!text.contains("onbehalf_audit_sink_failures_total 0\n"));
        assert!(text.contains("onbehalf_audit_sink_queue_depth 0\n"));
        sink.shutdown(Duration::from_secs(1));
    }

    #[test]
    fn a_full_queue_drops_the_oldest_counts_it_and_degrades() {
        let fake = Arc::new(Fake::default());
        fake.fail.store(true, Ordering::SeqCst);
        let metrics = Metrics::new();
        let sink = CheckpointSink::with_deliver(
            Box::new(FakeRef(fake.clone())),
            limits(2, Duration::from_secs(3600)),
            None,
            metrics.clone(),
        )
        .unwrap();
        let h = sink.handle();
        h.push(&cp(1));
        // Seq 1 is in flight (failing); 2 and 3 fill the queue; 4 and 5 push out 2 and 3.
        wait_until(|| fake.attempts.load(Ordering::SeqCst) >= 1);
        for s in 2..=5 {
            h.push(&cp(s));
        }
        let st = h.status();
        assert_eq!((st.queued, st.capacity), (2, 2));
        assert!(st.degraded, "a full queue is degraded");
        assert!(metrics
            .render()
            .contains("onbehalf_audit_sink_dropped_total 2\n"));
        assert!(metrics
            .render()
            .contains("onbehalf_audit_sink_queue_depth 2\n"));
        fake.fail.store(false, Ordering::SeqCst);
        wait_until(|| h.delivered() == 3);
        assert_eq!(*fake.got.lock().unwrap(), vec![1, 4, 5]);
        assert!(!h.status().degraded);
        sink.shutdown(Duration::from_secs(1));
    }

    #[test]
    fn degraded_once_failing_or_lagging_longer_than_max_lag() {
        let fake = Arc::new(Fake::default());
        fake.fail.store(true, Ordering::SeqCst);
        let sink = CheckpointSink::with_deliver(
            Box::new(FakeRef(fake.clone())),
            limits(100, Duration::from_millis(50)),
            None,
            Metrics::new(),
        )
        .unwrap();
        let h = sink.handle();
        assert!(!h.status().degraded, "idle is healthy");
        h.push(&cp(1));
        wait_until(|| fake.attempts.load(Ordering::SeqCst) >= 1);
        let now = Instant::now();
        assert!(
            !h.status_at(now).degraded,
            "a fresh failure is not yet degraded"
        );
        let later = h.status_at(now + Duration::from_millis(200));
        assert!(later.degraded);
        assert!(later.lag >= Duration::from_millis(200));
        assert!(later.failing_for.unwrap() > Duration::from_millis(50));
        fake.fail.store(false, Ordering::SeqCst);
        wait_until(|| h.delivered() == 1);
        assert!(
            !h.status_at(Instant::now() + Duration::from_secs(10))
                .degraded
        );
        drop(sink);
    }

    #[test]
    fn shutdown_gives_up_after_the_grace_period() {
        let fake = Arc::new(Fake::default());
        fake.fail.store(true, Ordering::SeqCst);
        let sink = CheckpointSink::with_deliver(
            Box::new(FakeRef(fake.clone())),
            SinkLimits {
                capacity: 4,
                max_lag: Duration::from_secs(1),
                backoff: Backoff {
                    initial: Duration::from_secs(30),
                    max: Duration::from_secs(30),
                },
            },
            None,
            Metrics::new(),
        )
        .unwrap();
        sink.handle().push(&cp(1));
        wait_until(|| fake.attempts.load(Ordering::SeqCst) >= 1);
        let started = Instant::now();
        sink.shutdown(Duration::from_millis(50));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a 30 s backoff does not hold up shutdown"
        );
    }

    #[test]
    fn file_sink_appends_canonical_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ckpt.jsonl");
        let d = FileDeliver::new(path.clone()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        for s in [1, 2] {
            rt.block_on(d.deliver(&ShippedCheckpoint::new(&cp(s), None)))
                .unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines = onbehalf_audit::parse_shipped(&text).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1].checkpoint, cp(2));
        assert!(FileDeliver::new(dir.path().join("no/such/dir/x.jsonl")).is_err());
    }

    fn example_creds() -> S3Credentials {
        S3Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        }
    }

    /// AWS's published example "GET Object" (Signature Version 4, header form, S3 docs
    /// "Examples of signature calculations").
    #[test]
    fn sigv4_matches_the_aws_get_object_example() {
        let empty = hex::encode(Sha256::digest(b""));
        let headers = vec![
            (
                "host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            ),
            ("range".to_string(), "bytes=0-9".to_string()),
            ("x-amz-content-sha256".to_string(), empty.clone()),
            ("x-amz-date".to_string(), "20130524T000000Z".to_string()),
        ];
        let auth = sigv4_authorization(&SigV4Request {
            method: "GET",
            canonical_uri: "/test.txt",
            canonical_query: "",
            headers: &headers,
            payload_sha256: &empty,
            region: "us-east-1",
            service: "s3",
            amz_date: "20130524T000000Z",
            creds: &example_creds(),
        });
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    /// AWS's published example "PUT Object".
    #[test]
    fn sigv4_matches_the_aws_put_object_example() {
        let body_hash = hex::encode(Sha256::digest(b"Welcome to Amazon S3."));
        let headers = vec![
            (
                "date".to_string(),
                "Fri, 24 May 2013 00:00:00 GMT".to_string(),
            ),
            (
                "host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            ),
            ("x-amz-content-sha256".to_string(), body_hash.clone()),
            ("x-amz-date".to_string(), "20130524T000000Z".to_string()),
            (
                "x-amz-storage-class".to_string(),
                "REDUCED_REDUNDANCY".to_string(),
            ),
        ];
        let auth = sigv4_authorization(&SigV4Request {
            method: "PUT",
            canonical_uri: &format!("/{}", uri_encode("test$file.text", false)),
            canonical_query: "",
            headers: &headers,
            payload_sha256: &body_hash,
            region: "us-east-1",
            service: "s3",
            amz_date: "20130524T000000Z",
            creds: &example_creds(),
        });
        assert!(
            auth.ends_with(
                "Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
            ),
            "{auth}"
        );
    }

    #[test]
    fn amz_date_and_uri_encoding() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_369_353_600);
        assert_eq!(amz_date(t), "20130524T000000Z");
        assert_eq!(uri_encode("a b/c~d$", false), "a%20b/c~d%24");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
    }

    #[test]
    fn config_validation_names_missing_and_foreign_fields() {
        let mut c = SinkSection::new(SinkKind::Webhook);
        assert!(c
            .validate()
            .unwrap_err()
            .to_string()
            .contains("needs `url`"));
        c.url = Some("ftp://x".into());
        assert!(c.validate().is_err());
        c.url = Some("https://hooks.example/ckpt".into());
        c.validate().unwrap();
        c.path = Some("/x".into());
        assert!(c
            .validate()
            .unwrap_err()
            .to_string()
            .contains("does not use path"));
        let mut s3 = SinkSection::new(SinkKind::S3);
        s3.endpoint = Some("https://s3.example/extra".into());
        s3.bucket = Some("b".into());
        assert!(s3
            .validate()
            .unwrap_err()
            .to_string()
            .contains("without a path"));
        s3.endpoint = Some("http://127.0.0.1:9000".into());
        s3.validate().unwrap();
        let mut f = SinkSection::new(SinkKind::File);
        f.path = Some("/x".into());
        f.queue_capacity = 0;
        assert!(f.validate().is_err());
    }
}
