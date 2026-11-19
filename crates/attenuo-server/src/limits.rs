//! `[limits]`: the in-flight cap, the request body and handler deadlines, and the per-caller
//! rate limits of `POST /token`, `/mcp/{server}` (audit finding S-4) and AuthZEN action search
//! (SR-117).
//!
//! All of it is in-process and per server: with more than one replica each counts on its own
//! (one replica is the supported deployment, see the deploy guide). None of it is a security
//! property: it keeps one busy or misbehaving caller from taking the whole process down, and
//! it fails closed (a refused request is answered, never let through unchecked).
//!
//! **In-flight cap** ([`shed`]). A semaphore of `max_in_flight` permits; a request that finds
//! none is answered `503` at once (`overloaded`, `Retry-After: 1`), so a burst cannot build an
//! unbounded queue of tasks, blocked SQLite calls and buffered bodies. `/healthz` and `/readyz`
//! are not counted, so an orchestrator still sees a busy server as live and ready. A request
//! holds its permit until its answer starts; a streamed answer then runs without one.
//!
//! **Deadlines** ([`deadlines`]). Every request body must arrive within
//! `request_body_timeout_seconds` of its headers. Every route except `/mcp/{server}` and
//! `/admin/*` must answer within `request_timeout_seconds`; the proxy has its own upstream
//! deadlines and streams that must stay open, and an audit verify or export of a large log may
//! take longer than any sensible default. The header-read timeout is in [`crate::listen`].
//!
//! **Rate limits** ([`RateLimiter`]). A fixed window of one minute per key: a key admits `N`
//! requests in its window and refuses every further one until the window ends; a refused
//! request does not count. Over a window boundary a key can therefore send up to `2N` in less
//! than a minute, never more than `N` within one window. Memory is bounded by
//! `rate_limit_max_keys`: a key whose window has ended is dropped first, and a key inside its
//! window is never dropped, so dropping cannot reset a count. When every tracked key is inside
//! its window, a new key is refused until the oldest window ends (`table_full`), so a flood of
//! distinct callers cannot push out the count of the one being limited. The per-peer table of
//! `POST /token` is the exception: requests that authenticate an agent never enter it, so a
//! new address with client credentials is let through to authenticate, and refused only if it
//! does not ([`token_peer_limit`], SR-109). Action search has its own per-run table, apart from
//! the MCP one ([`Limits::admit_search`]). Keys are run ids (root lease ids), agent ids and
//! peer addresses, never a user subject.

use std::collections::HashMap;
use std::future::Future as _;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http_body::{Body as _, Frame, SizeHint};

use crate::config::LimitsSection;
use crate::error::ApiError;
use crate::metrics::{Metrics, RateLimitCause, RateLimitedBy, TimeoutKind};

/// The window of every rate limit.
pub(crate) const RATE_WINDOW: Duration = Duration::from_secs(60);

/// At most one log line about a full rate-limit table per this interval.
const FULL_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// `error_description` of a shed request.
pub(crate) const OVERLOADED: &str = "overloaded";
/// `error_description` of a request over a deadline.
pub(crate) const REQUEST_TIMEOUT: &str = "request_timeout";
/// `error` and `error_description` of a rate-limited request.
pub(crate) const RATE_LIMITED: &str = attenuo_proxy::auth::REASON_RATE_LIMITED;

/// The `[limits]` of one server.
pub(crate) struct Limits {
    in_flight: Option<Arc<tokio::sync::Semaphore>>,
    body_timeout: Duration,
    request_timeout: Duration,
    /// `POST /token`, per authenticated agent.
    pub(crate) token: Option<RateLimiter>,
    /// `POST /token` that authenticated no agent, per peer address.
    pub(crate) token_peer: Option<RateLimiter>,
    /// `/mcp/{server}`, per run.
    pub(crate) mcp: Option<RateLimiter>,
    /// `POST /access/v1/search/action`, per run; a table of its own, so searches and MCP
    /// requests do not use up each other's minute.
    pub(crate) authzen_search: Option<RateLimiter>,
    metrics: Arc<Metrics>,
    /// When a full table was last logged, so a flood of new callers logs once in a while.
    full_logged: Mutex<Option<Instant>>,
}

impl std::fmt::Debug for Limits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Limits")
            .field("in_flight", &self.in_flight.is_some())
            .field("body_timeout", &self.body_timeout)
            .field("request_timeout", &self.request_timeout)
            .finish_non_exhaustive()
    }
}

impl Limits {
    /// The limits of a checked section ([`LimitsSection::check`]).
    pub(crate) fn new(section: &LimitsSection, metrics: Arc<Metrics>) -> Self {
        let to_usize = |v: u64| usize::try_from(v).unwrap_or(usize::MAX);
        let max_keys = to_usize(section.rate_limit_max_keys);
        let limiter = |per_minute: u64| {
            (per_minute > 0).then(|| RateLimiter::new(per_minute, RATE_WINDOW, max_keys))
        };
        Self {
            in_flight: (section.max_in_flight > 0).then(|| {
                Arc::new(tokio::sync::Semaphore::new(
                    to_usize(section.max_in_flight).min(tokio::sync::Semaphore::MAX_PERMITS),
                ))
            }),
            body_timeout: Duration::from_secs(section.request_body_timeout_seconds),
            request_timeout: Duration::from_secs(section.request_timeout_seconds),
            token: limiter(section.token_requests_per_minute),
            token_peer: limiter(section.token_unauthenticated_requests_per_minute),
            mcp: limiter(section.mcp_requests_per_minute),
            authzen_search: limiter(section.authzen_search_requests_per_minute),
            metrics,
            full_logged: Mutex::new(None),
        }
    }

    /// Count one `/mcp/{server}` request of the run `chain_id`. `Err` carries the seconds until
    /// the run may retry.
    pub(crate) fn admit_mcp(&self, chain_id: &str) -> Result<(), u64> {
        let Some(limiter) = &self.mcp else {
            return Ok(());
        };
        match limiter.admit(chain_id, Instant::now()) {
            Verdict::Admit => Ok(()),
            refused => {
                let retry = self.refused(RateLimitedBy::Mcp, &refused);
                if refused.first() {
                    tracing::warn!(
                        limit = "mcp_requests_per_minute",
                        chain_id,
                        retry_after_seconds = retry,
                        "rate limit reached; further requests of this run are refused until \
                         the minute ends"
                    );
                }
                Err(retry)
            }
        }
    }

    /// Count one AuthZEN action search of the run `chain_id` (the chain's root lease), once the
    /// caller has authenticated and before any candidate is evaluated (SR-117).
    ///
    /// # Errors
    ///
    /// `429` `rate_limited` with `Retry-After` when the run is over
    /// `authzen_search_requests_per_minute`.
    pub(crate) fn admit_search(&self, chain_id: &str) -> Result<(), ApiError> {
        let Some(limiter) = &self.authzen_search else {
            return Ok(());
        };
        match limiter.admit(chain_id, Instant::now()) {
            Verdict::Admit => Ok(()),
            refused => {
                let retry = self.refused(RateLimitedBy::AuthzenSearch, &refused);
                if refused.first() {
                    tracing::warn!(
                        limit = "authzen_search_requests_per_minute",
                        chain_id,
                        retry_after_seconds = retry,
                        "rate limit reached; further action searches of this run are refused \
                         until the minute ends"
                    );
                }
                Err(rate_limited(
                    "too many action searches for this run; retry later",
                    retry,
                ))
            }
        }
    }

    /// Count one `POST /token` request of the authenticated agent `agent`, and mark the
    /// request as authenticated so the peer limit does not count it ([`token_peer_limit`]).
    ///
    /// # Errors
    ///
    /// `429` `rate_limited` with `Retry-After` when the agent is over
    /// `token_requests_per_minute`.
    pub(crate) fn admit_agent(
        &self,
        mark: Option<&CallerMark>,
        agent: &str,
    ) -> Result<(), ApiError> {
        if let Some(mark) = mark {
            mark.set_authenticated();
        }
        let Some(limiter) = &self.token else {
            return Ok(());
        };
        match limiter.admit(agent, Instant::now()) {
            Verdict::Admit => Ok(()),
            refused => Err(self.agent_refused(&refused, agent)),
        }
    }

    /// [`admit_agent`](Self::admit_agent) without counting: refuse the authenticated agent
    /// `agent` when it is over `token_requests_per_minute`, and mark the request as
    /// authenticated. For a request whose credential is used up when it is accepted (a client
    /// assertion): it runs before that credential is recorded, so an agent over its limit
    /// writes nothing to the replay store and can send the same assertion again after
    /// `Retry-After` (SR-108). The request is counted by `admit_agent` afterwards.
    ///
    /// # Errors
    ///
    /// As [`admit_agent`](Self::admit_agent).
    pub(crate) fn check_agent(
        &self,
        mark: Option<&CallerMark>,
        agent: &str,
    ) -> Result<(), ApiError> {
        if let Some(mark) = mark {
            mark.set_authenticated();
        }
        let Some(limiter) = &self.token else {
            return Ok(());
        };
        match limiter.check(agent, Instant::now()) {
            Verdict::Admit => Ok(()),
            refused => Err(self.agent_refused(&refused, agent)),
        }
    }

    /// The `429` of an agent over `token_requests_per_minute`, counted in the metrics and
    /// logged on its first refusal in the minute.
    fn agent_refused(&self, refused: &Verdict, agent: &str) -> ApiError {
        let retry = self.refused(RateLimitedBy::Token, refused);
        if refused.first() {
            tracing::warn!(
                limit = "token_requests_per_minute",
                agent,
                retry_after_seconds = retry,
                "rate limit reached; further token requests of this agent are refused until \
                 the minute ends"
            );
        }
        rate_limited("too many token requests for this agent; retry later", retry)
    }

    /// Count a refusal in the metrics; returns its `Retry-After` in seconds.
    fn refused(&self, by: RateLimitedBy, verdict: &Verdict) -> u64 {
        let (retry, cause) = match verdict {
            Verdict::Admit => (Duration::ZERO, RateLimitCause::Limit),
            Verdict::Limited { retry_after, .. } => (*retry_after, RateLimitCause::Limit),
            Verdict::Full { retry_after } => {
                let now = Instant::now();
                let mut last = self
                    .full_logged
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if last.is_none_or(|t| now.duration_since(t) >= FULL_LOG_INTERVAL) {
                    *last = Some(now);
                    tracing::warn!(
                        limit = by.label(),
                        "rate limit table full of callers inside their minute; new callers are \
                         refused until one ends (raise [limits] rate_limit_max_keys)"
                    );
                }
                (*retry_after, RateLimitCause::TableFull)
            }
        };
        self.metrics.rate_limited(by, cause);
        retry_seconds(retry)
    }
}

/// Whole seconds to wait, rounded up, at least 1.
fn retry_seconds(d: Duration) -> u64 {
    let secs = d.as_secs() + u64::from(d.subsec_nanos() > 0);
    secs.max(1)
}

/// The `429` of a rate-limited REST request.
fn rate_limited(detail: &str, retry: u64) -> ApiError {
    ApiError::new(StatusCode::TOO_MANY_REQUESTS, RATE_LIMITED, detail)
        .with_description(RATE_LIMITED)
        .with_retry_after(retry)
}

// ---------------------------------------------------------------------------------------------
// The rate limiter
// ---------------------------------------------------------------------------------------------

/// What [`RateLimiter::admit`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Counted and let through.
    Admit,
    /// The key is over its limit for `retry_after`. `first` is set on the first refusal of
    /// the key in its window, for a single log line.
    Limited { retry_after: Duration, first: bool },
    /// The key is new and every tracked key is inside its window: refused for `retry_after`,
    /// until the oldest window ends.
    Full { retry_after: Duration },
}

impl Verdict {
    fn first(&self) -> bool {
        matches!(self, Verdict::Limited { first: true, .. })
    }
}

/// A fixed-window counter per key, with at most `max_keys` keys (see the module docs).
pub(crate) struct RateLimiter {
    limit: u64,
    window: Duration,
    max_keys: usize,
    table: Mutex<Table>,
}

#[derive(Default)]
struct Table {
    slots: HashMap<String, Slot>,
    /// No slot's window ends before this (a lower bound; `None` when there are no slots).
    next_end: Option<Instant>,
}

struct Slot {
    start: Instant,
    count: u64,
    warned: bool,
}

impl RateLimiter {
    /// `limit` requests per `window` per key (both at least 1), at most `max_keys` keys.
    pub(crate) fn new(limit: u64, window: Duration, max_keys: usize) -> Self {
        Self {
            limit: limit.max(1),
            window: window.max(Duration::from_millis(1)),
            max_keys: max_keys.max(1),
            table: Mutex::new(Table::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Table> {
        // A panic while the table was held leaves counts that are still counts.
        self.table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Count one request of `key` at `now` if it is under its limit.
    pub(crate) fn admit(&self, key: &str, now: Instant) -> Verdict {
        let window = self.window;
        let mut t = self.lock();
        if let Some(slot) = t.slots.get_mut(key) {
            if now >= slot.start + window {
                *slot = Slot {
                    start: now,
                    count: 0,
                    warned: false,
                };
            }
            if slot.count < self.limit {
                slot.count += 1;
                return Verdict::Admit;
            }
            let first = !slot.warned;
            slot.warned = true;
            return Verdict::Limited {
                retry_after: (slot.start + window).saturating_duration_since(now),
                first,
            };
        }
        if t.slots.len() >= self.max_keys {
            t.drop_ended(now, window);
            if t.slots.len() >= self.max_keys {
                let end = t.next_end.unwrap_or(now + window);
                return Verdict::Full {
                    retry_after: end.saturating_duration_since(now),
                };
            }
        }
        t.slots.insert(
            key.to_owned(),
            Slot {
                start: now,
                count: 1,
                warned: false,
            },
        );
        let end = now + window;
        t.next_end = Some(t.next_end.map_or(end, |e| e.min(end)));
        // `limit` is at least 1, so a new key's first request is always under it.
        Verdict::Admit
    }

    /// What [`admit`](Self::admit) would answer for `key` at `now`, without counting:
    /// `Limited` (never `first`) when the key is over its limit, `Full` when it is new and
    /// the table is full of keys inside their window.
    pub(crate) fn peek(&self, key: &str, now: Instant) -> Verdict {
        let window = self.window;
        let mut t = self.lock();
        if let Some(slot) = t.slots.get(key) {
            let end = slot.start + window;
            if now < end && slot.count >= self.limit {
                return Verdict::Limited {
                    retry_after: end.saturating_duration_since(now),
                    first: false,
                };
            }
            return Verdict::Admit;
        }
        if t.slots.len() >= self.max_keys {
            t.drop_ended(now, window);
            if t.slots.len() >= self.max_keys {
                let end = t.next_end.unwrap_or(now + window);
                return Verdict::Full {
                    retry_after: end.saturating_duration_since(now),
                };
            }
        }
        Verdict::Admit
    }

    /// [`peek`](Self::peek), except that a refusal of a key over its limit is remembered as
    /// [`admit`](Self::admit) remembers it: `first` is set on the key's first refusal in its
    /// window, whichever of the two made it. Counts nothing.
    pub(crate) fn check(&self, key: &str, now: Instant) -> Verdict {
        let window = self.window;
        {
            let mut t = self.lock();
            if let Some(slot) = t.slots.get_mut(key) {
                let end = slot.start + window;
                if now < end && slot.count >= self.limit {
                    let first = !slot.warned;
                    slot.warned = true;
                    return Verdict::Limited {
                        retry_after: end.saturating_duration_since(now),
                        first,
                    };
                }
                return Verdict::Admit;
            }
        }
        self.peek(key, now)
    }

    /// How many keys are tracked.
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.lock().slots.len()
    }
}

impl Table {
    /// Drop every slot whose window has ended (they hold no count that still matters), when
    /// one may have; recompute `next_end`.
    fn drop_ended(&mut self, now: Instant, window: Duration) {
        if self.next_end.is_some_and(|end| now < end) {
            return;
        }
        self.slots.retain(|_, s| now < s.start + window);
        self.next_end = self.slots.values().map(|s| s.start + window).min();
    }
}

// ---------------------------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------------------------

/// Is this a proxy route? Its refusals use the JSON-RPC shape.
fn is_mcp(path: &str) -> bool {
    path.starts_with("/mcp/")
}

/// Liveness and readiness, which the in-flight cap never refuses.
fn is_probe(path: &str) -> bool {
    matches!(path, "/healthz" | "/readyz")
}

/// A `503` with `Retry-After: 1` in the route's shape: JSON-RPC `-32006` on `/mcp/{server}`,
/// the REST error shape elsewhere.
fn unavailable(mcp: bool, description: &'static str, detail: &str) -> Response {
    if mcp {
        let body = attenuo_proxy::jsonrpc::attenuo_error(
            serde_json::Value::Null,
            attenuo_proxy::jsonrpc::CODE_UNAVAILABLE,
            description,
            format!("attenuo: temporarily unavailable: {description}"),
            Some(serde_json::json!({ "reason": description })),
        );
        let mut resp = (StatusCode::SERVICE_UNAVAILABLE, axum::Json(body)).into_response();
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    }
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        detail,
    )
    .with_description(description)
    .with_retry_after(1)
    .into_response()
}

/// Middleware: the in-flight cap (`[limits] max_in_flight`, see the module docs).
pub(crate) async fn shed(State(limits): State<Arc<Limits>>, req: Request, next: Next) -> Response {
    let Some(permits) = &limits.in_flight else {
        return next.run(req).await;
    };
    if is_probe(req.uri().path()) {
        return next.run(req).await;
    }
    let Ok(_permit) = permits.clone().try_acquire_owned() else {
        limits.metrics.request_shed();
        tracing::debug!("request refused: max_in_flight requests already running");
        return unavailable(
            is_mcp(req.uri().path()),
            OVERLOADED,
            "the server is handling too many requests; retry later",
        );
    };
    next.run(req).await
}

/// Middleware: the request body deadline on every route, and the handler deadline on every
/// route but `/mcp/{server}` and `/admin/*` (see the module docs).
pub(crate) async fn deadlines(
    State(limits): State<Arc<Limits>>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path();
    let bounded = !is_mcp(path) && !path.starts_with("/admin/");
    let (parts, body) = req.into_parts();
    let body = if body.is_end_stream() {
        body
    } else {
        Body::new(Deadlined {
            inner: body,
            timer: Box::pin(tokio::time::sleep(limits.body_timeout)),
            metrics: limits.metrics.clone(),
            fired: false,
        })
    };
    let req = Request::from_parts(parts, body);
    if !bounded {
        return next.run(req).await;
    }
    match tokio::time::timeout(limits.request_timeout, next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => {
            limits.metrics.request_timed_out(TimeoutKind::Handler);
            tracing::warn!(
                timeout_seconds = limits.request_timeout.as_secs(),
                "request abandoned: no answer within [limits] request_timeout_seconds"
            );
            unavailable(
                false,
                REQUEST_TIMEOUT,
                "the request took too long to answer; retry later",
            )
        }
    }
}

/// The error a body past `request_body_timeout_seconds` fails with.
#[derive(Debug)]
pub(crate) struct BodyTimedOut;

impl std::fmt::Display for BodyTimedOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the request body did not arrive within [limits] request_body_timeout_seconds")
    }
}

impl std::error::Error for BodyTimedOut {}

/// Is `err`, or an error it wraps, [`BodyTimedOut`]?
pub(crate) fn is_body_timeout(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur = Some(err);
    while let Some(e) = cur {
        if e.is::<BodyTimedOut>() {
            return true;
        }
        cur = e.source();
    }
    false
}

/// A request body that fails with [`BodyTimedOut`] once its timer has fired.
struct Deadlined {
    inner: Body,
    timer: Pin<Box<tokio::time::Sleep>>,
    metrics: Arc<Metrics>,
    fired: bool,
}

impl http_body::Body for Deadlined {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        if self.fired || self.timer.as_mut().poll(cx).is_ready() {
            if !self.fired {
                self.fired = true;
                self.metrics.request_timed_out(TimeoutKind::Body);
                tracing::debug!("request body not read in time");
            }
            return Poll::Ready(Some(Err(axum::Error::new(BodyTimedOut))));
        }
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        !self.fired && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// What [`token_peer_limit`] and the `POST /token` handler tell each other about a request.
/// The handler sets it once it has authenticated an agent ([`Limits::admit_agent`],
/// [`Limits::check_agent`]), so that the request is not counted against its peer address, and
/// reads whether the request came in on a full peer table ([`Self::on_full_table`]).
#[derive(Debug, Clone, Default)]
pub(crate) struct CallerMark {
    authenticated: Arc<AtomicBool>,
    on_full_table: bool,
}

impl CallerMark {
    /// The request authenticated an agent.
    fn set_authenticated(&self) {
        self.authenticated.store(true, Ordering::Release);
    }

    fn authenticated(&self) -> bool {
        self.authenticated.load(Ordering::Acquire)
    }

    /// The peer is not in the per-peer table and the table is full (SR-109): the request runs
    /// only so that it may authenticate an agent, and is refused `429` afterwards if it does
    /// not. The handler refuses it at once, before any work, unless it carries client
    /// credentials and no actor token ([`refuse_on_full_table`]).
    pub(crate) fn on_full_table(&self) -> bool {
        self.on_full_table
    }
}

/// The `429` of a request refused by the per-peer limit, up front or after it authenticated no
/// agent: one answer for both, so a request on a full table learns nothing more than one
/// refused before it ran.
fn peer_refusal(retry: u64) -> ApiError {
    rate_limited(
        "too many unauthenticated token requests from this address; retry later",
        retry,
    )
}

/// For the `POST /token` handler, before any work: on a full peer table
/// ([`CallerMark::on_full_table`]) a request goes on only when it carries client credentials
/// (`has_client_credentials`: a secret or a client assertion) and no actor token
/// (`has_actor_token`). Client authentication costs a digest compare or one signature
/// verification against keys in the config; an actor token may need a JWKS fetch from its
/// issuer, and a request with no credential would go on to work that does not authenticate an
/// agent at all, so neither is opened (SR-109). The refusal returned here is replaced by
/// [`token_peer_limit`] with the counted one.
///
/// # Errors
///
/// `429` `rate_limited`.
pub(crate) fn refuse_on_full_table(
    mark: Option<&CallerMark>,
    has_client_credentials: bool,
    has_actor_token: bool,
) -> Result<(), ApiError> {
    if mark.is_some_and(CallerMark::on_full_table) && (!has_client_credentials || has_actor_token) {
        return Err(peer_refusal(1));
    }
    Ok(())
}

/// The key of a peer address: the address itself for IPv4 (and IPv4-mapped IPv6), the /64 for
/// IPv6, since one host commonly holds a whole /64. `unknown` when the request came without
/// one (a router driven without the server's accept loop).
pub(crate) fn peer_key(peer: Option<SocketAddr>) -> String {
    match peer.map(|p| p.ip()) {
        None => "unknown".to_string(),
        Some(IpAddr::V4(v4)) => v4.to_string(),
        Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

/// Route middleware of `POST /token`: the per-peer limit of requests that authenticate no
/// agent (`[limits] token_unauthenticated_requests_per_minute`). A peer that has used up its
/// minute is refused before any work; otherwise the request runs, and counts against the peer
/// only when the handler did not authenticate an agent ([`CallerMark`]). The peer address is
/// never logged.
///
/// A peer that is not in the table when the table is full is not refused up front (SR-109):
/// requests that authenticate an agent are never in the table, so that would refuse every
/// agent during a flood from many addresses. The request runs with
/// [`CallerMark::on_full_table`] set; the handler refuses at once one that carries no client
/// credential or an actor token ([`refuse_on_full_table`]), and lets one with client
/// credentials authenticate. If it authenticated an agent it is answered as usual and not
/// counted here; if not, its answer is replaced by the same `429` it would have got up front,
/// counted as `table_full`, so a failed authentication learns nothing past the refusal.
pub(crate) async fn token_peer_limit(
    State(limits): State<Arc<Limits>>,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(limiter) = &limits.token_peer else {
        req.extensions_mut().insert(CallerMark::default());
        return next.run(req).await;
    };
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let key = peer_key(peer);
    let verdict = limiter.peek(&key, Instant::now());
    let on_full_table = match verdict {
        Verdict::Admit => false,
        Verdict::Full { .. } => true,
        Verdict::Limited { .. } => {
            let retry = limits.refused(RateLimitedBy::TokenUnauthenticated, &verdict);
            tracing::debug!("token request refused: the peer is over its unauthenticated limit");
            return peer_refusal(retry).into_response();
        }
    };
    let mark = CallerMark {
        authenticated: Arc::default(),
        on_full_table,
    };
    req.extensions_mut().insert(mark.clone());
    let resp = next.run(req).await;
    if on_full_table && !mark.authenticated() {
        let retry = limits.refused(RateLimitedBy::TokenUnauthenticated, &verdict);
        tracing::debug!(
            "token request refused: the peer table is full and the request authenticated no agent"
        );
        return peer_refusal(retry).into_response();
    }
    if !mark.authenticated() {
        let now = Instant::now();
        // Not counted when the table filled up meanwhile: the request has run already, and
        // the next one from this peer is refused by the `peek` above.
        if limiter.admit(&key, now) == Verdict::Admit && limiter.peek(&key, now) != Verdict::Admit {
            tracing::warn!(
                limit = "token_unauthenticated_requests_per_minute",
                "a peer used up its unauthenticated token requests; its token requests are \
                 refused until the minute ends"
            );
        }
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: Duration = Duration::from_secs(60);

    /// A limit of N admits N in a window, refuses the N+1st (and every later one, uncounted),
    /// and admits N again once the window has ended.
    /// `check` counts nothing, refuses what `admit` would refuse, and shares the first-refusal
    /// flag with `admit`, so the warning is logged once a minute whichever of them refused
    /// first (SR-108).
    #[test]
    fn check_counts_nothing_and_shares_the_first_refusal() {
        let l = RateLimiter::new(2, W, 100);
        let t0 = Instant::now();
        for _ in 0..5 {
            assert_eq!(l.check("agent", t0), Verdict::Admit);
        }
        assert_eq!(l.tracked(), 0, "check adds no key");
        assert_eq!(l.admit("agent", t0), Verdict::Admit);
        assert_eq!(l.admit("agent", t0), Verdict::Admit);
        assert!(matches!(
            l.check("agent", t0),
            Verdict::Limited { first: true, .. }
        ));
        assert!(matches!(
            l.check("agent", t0),
            Verdict::Limited { first: false, .. }
        ));
        assert!(matches!(
            l.admit("agent", t0),
            Verdict::Limited { first: false, .. }
        ));
        assert_eq!(l.check("agent", t0 + W), Verdict::Admit);
        // A new key on a full table is refused as `admit` would refuse it.
        let full = RateLimiter::new(1, W, 1);
        assert_eq!(full.admit("a", t0), Verdict::Admit);
        assert!(matches!(full.check("b", t0), Verdict::Full { .. }));
    }

    #[test]
    fn admits_n_refuses_n_plus_one_and_recovers_after_the_window() {
        let l = RateLimiter::new(3, W, 100);
        let t0 = Instant::now();
        for i in 0..3 {
            assert_eq!(l.admit("run", t0 + Duration::from_secs(i)), Verdict::Admit);
        }
        let v = l.admit("run", t0 + Duration::from_secs(10));
        assert_eq!(
            v,
            Verdict::Limited {
                retry_after: Duration::from_secs(50),
                first: true
            }
        );
        // Still refused, and no longer the first refusal; refusals are not counted.
        assert!(matches!(
            l.admit("run", t0 + Duration::from_secs(59)),
            Verdict::Limited { first: false, .. }
        ));
        assert_eq!(
            l.peek("run", t0 + Duration::from_secs(59)),
            Verdict::Limited {
                retry_after: Duration::from_secs(1),
                first: false
            }
        );
        // The window ended: N again, then refused.
        let t1 = t0 + W;
        assert_eq!(l.peek("run", t1), Verdict::Admit);
        for _ in 0..3 {
            assert_eq!(l.admit("run", t1), Verdict::Admit);
        }
        assert!(matches!(
            l.admit("run", t1),
            Verdict::Limited { first: true, .. }
        ));
    }

    /// Keys are counted apart: one key over its limit does not touch another.
    #[test]
    fn keys_are_independent() {
        let l = RateLimiter::new(1, W, 100);
        let t = Instant::now();
        assert_eq!(l.admit("a", t), Verdict::Admit);
        assert!(matches!(l.admit("a", t), Verdict::Limited { .. }));
        assert_eq!(l.admit("b", t), Verdict::Admit);
        assert_eq!(l.peek("c", t), Verdict::Admit);
    }

    /// The table never holds more than `max_keys`. A key inside its window is never dropped,
    /// so a flood of new keys cannot reset its count: the new keys are refused instead, until
    /// a window ends; then ended keys make room.
    #[test]
    fn a_full_table_refuses_new_keys_and_never_resets_an_active_one() {
        let l = RateLimiter::new(2, W, 100);
        let t0 = Instant::now();
        assert_eq!(l.admit("victim", t0), Verdict::Admit);
        assert_eq!(l.admit("victim", t0), Verdict::Admit);
        for i in 0..99 {
            assert_eq!(
                l.admit(&format!("k{i}"), t0 + Duration::from_secs(1)),
                Verdict::Admit
            );
        }
        assert_eq!(l.tracked(), 100);
        assert_eq!(
            l.admit("new", t0 + Duration::from_secs(2)),
            Verdict::Full {
                retry_after: Duration::from_secs(58)
            }
        );
        assert_eq!(l.tracked(), 100);
        assert!(matches!(
            l.peek("other-new", t0 + Duration::from_secs(2)),
            Verdict::Full { .. }
        ));
        // The limited key is still limited: nothing was evicted.
        assert!(matches!(
            l.admit("victim", t0 + Duration::from_secs(2)),
            Verdict::Limited { .. }
        ));
        // Once "victim"'s window ends it is dropped to make room; the others are still in
        // theirs and stay.
        assert_eq!(l.admit("new", t0 + W), Verdict::Admit);
        assert_eq!(l.tracked(), 100);
        assert!(matches!(
            l.admit("k5", t0 + W),
            Verdict::Admit | Verdict::Limited { .. }
        ));
        // After every window has ended a burst of new keys fits again.
        let later = t0 + 3 * W;
        for i in 0..100 {
            assert_eq!(l.admit(&format!("n{i}"), later), Verdict::Admit);
        }
        assert_eq!(l.tracked(), 100);
    }

    /// No key gets more than its limit within one window, however keys come and go.
    #[test]
    fn no_key_exceeds_its_limit_in_a_window_under_churn() {
        let l = RateLimiter::new(5, W, 100);
        let t0 = Instant::now();
        let mut admitted = 0;
        for step in 0..1_000u64 {
            let now = t0 + Duration::from_millis(step * 50); // 50 s in all: one window
            if l.admit("target", now) == Verdict::Admit {
                admitted += 1;
            }
            let _ = l.admit(&format!("churn{step}"), now);
        }
        assert_eq!(admitted, 5);
    }

    /// `authzen_search_requests_per_minute` (SR-117): off by default; on, a run gets N
    /// searches, the next is `429` `rate_limited` with `Retry-After`, another run is not
    /// touched, and its table is not the MCP one in either direction.
    #[test]
    fn the_search_limit_is_per_run_and_apart_from_the_mcp_limit() {
        let (off, _) = limits(|_| {});
        for _ in 0..1_000 {
            off.admit_search("run-a").unwrap();
        }
        let (l, metrics) = limits(|s| {
            s.authzen_search_requests_per_minute = 2;
            s.mcp_requests_per_minute = 2;
        });
        // Two MCP requests of run-a spend none of its searches.
        l.admit_mcp("run-a").unwrap();
        l.admit_mcp("run-a").unwrap();
        l.admit_search("run-a").unwrap();
        l.admit_search("run-a").unwrap();
        let e = l.admit_search("run-a").unwrap_err();
        assert_eq!(e.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(e.stable_code(), RATE_LIMITED);
        l.admit_search("run-b").unwrap();
        // And the searches spent none of run-b's MCP requests.
        l.admit_mcp("run-b").unwrap();
        l.admit_mcp("run-b").unwrap();
        assert!(l.admit_mcp("run-b").is_err());
        let m = metrics.render();
        assert!(
            m.contains(
                "attenuo_requests_rate_limited_total{limit=\"authzen_search\",cause=\"limit\"} 1\n"
            ),
            "{m}"
        );
        assert!(
            m.contains("attenuo_requests_rate_limited_total{limit=\"mcp\",cause=\"limit\"} 1\n")
        );
    }

    fn limits(f: impl FnOnce(&mut LimitsSection)) -> (Arc<Limits>, Arc<Metrics>) {
        let mut section = LimitsSection::default();
        f(&mut section);
        section.check().unwrap();
        let metrics = Metrics::new();
        (Arc::new(Limits::new(&section, metrics.clone())), metrics)
    }

    /// A router with a handler that waits for `gate` (or sleeps `wait`) on every path the
    /// middleware treats differently, behind `deadlines` and `shed` as in `crate::router`.
    fn app(limits: &Arc<Limits>, gate: Arc<tokio::sync::Notify>, wait: Duration) -> axum::Router {
        use axum::routing::{get, post};
        let slow = move || {
            let gate = gate.clone();
            async move {
                tokio::select! {
                    () = gate.notified() => {}
                    () = tokio::time::sleep(wait) => {}
                }
                "done"
            }
        };
        axum::Router::new()
            .route("/token", get(slow.clone()))
            .route("/mcp/{server}", get(slow.clone()))
            .route("/admin/audit/verify", get(slow.clone()))
            .route("/healthz", get(|| async { "ok" }))
            .route(
                "/body",
                post(
                    |crate::routes::extract::Body(b): crate::routes::extract::Body| async move {
                        b.len().to_string()
                    },
                ),
            )
            .layer(axum::middleware::from_fn_with_state(
                limits.clone(),
                deadlines,
            ))
            .layer(axum::middleware::from_fn_with_state(limits.clone(), shed))
    }

    async fn send(app: &axum::Router, method: &str, path: &str) -> Response {
        use tower::ServiceExt as _;
        let req = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(req).await.unwrap()
    }

    async fn json_of(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// SR-109: a full peer table does not refuse agents. Requests that authenticate an agent
    /// are never counted against their peer address, so an agent's address is never in the
    /// table. Once `rate_limit_max_keys` other addresses each sent one unauthenticated request
    /// within their minute, a request from an address not in the table still runs if it
    /// carries client credentials: an agent that authenticates is served (and not counted), one
    /// that does not is refused with the same `429` as before, counted as `table_full`. A
    /// request with no client credential, or with an actor token, is refused before any work.
    /// A peer that is in the table and over its limit is still refused before the handler
    /// runs. Before the fix the agent was refused `429` too.
    #[tokio::test]
    async fn a_full_peer_table_still_serves_an_authenticated_agent_sr109() {
        use axum::extract::Extension;
        use axum::routing::post;
        use std::sync::atomic::AtomicUsize;
        use tower::ServiceExt as _;
        let (limits, metrics) = limits(|l| {
            l.token_unauthenticated_requests_per_minute = 2;
            l.rate_limit_max_keys = 100;
        });
        // How many requests the handler saw, and how many it tried to authenticate.
        let runs = Arc::new(AtomicUsize::new(0));
        let attempts = Arc::new(AtomicUsize::new(0));
        // A stand-in for `POST /token`: `x-agent` stands for credentials that authenticate,
        // `x-secret` for client credentials that do not, `x-actor` for an actor token.
        let handler = {
            let (runs, attempts) = (runs.clone(), attempts.clone());
            move |State(limits): State<Arc<Limits>>,
                  Extension(mark): Extension<CallerMark>,
                  headers: axum::http::HeaderMap| {
                let (runs, attempts) = (runs.clone(), attempts.clone());
                async move {
                    runs.fetch_add(1, Ordering::SeqCst);
                    let has = |h: &str| headers.contains_key(h);
                    if let Err(e) = refuse_on_full_table(
                        Some(&mark),
                        has("x-agent") || has("x-secret"),
                        has("x-actor"),
                    ) {
                        return e.into_response();
                    }
                    attempts.fetch_add(1, Ordering::SeqCst);
                    match headers.get("x-agent").and_then(|v| v.to_str().ok()) {
                        Some(agent) => match limits.admit_agent(Some(&mark), agent) {
                            Ok(()) => StatusCode::OK.into_response(),
                            Err(e) => e.into_response(),
                        },
                        None => StatusCode::UNAUTHORIZED.into_response(),
                    }
                }
            }
        };
        let app = axum::Router::new()
            .route(
                "/token",
                post(handler).layer(axum::middleware::from_fn_with_state(
                    limits.clone(),
                    token_peer_limit,
                )),
            )
            .with_state(limits.clone());
        let send = |peer: [u8; 4], header: Option<(&'static str, &'static str)>| {
            let app = app.clone();
            async move {
                let mut req = Request::builder().method("POST").uri("/token");
                if let Some((k, v)) = header {
                    req = req.header(k, v);
                }
                let mut req = req.body(Body::empty()).unwrap();
                req.extensions_mut()
                    .insert(ConnectInfo(SocketAddr::from((peer, 40000))));
                app.oneshot(req).await.unwrap()
            }
        };
        let agent = Some(("x-agent", "coder"));
        // The agent's own address, before the flood: authenticated, never counted.
        assert_eq!(send([192, 0, 2, 1], agent).await.status(), StatusCode::OK);
        // One unauthenticated request from each of 100 other addresses fills the table.
        for i in 0..100u8 {
            let status = send([198, 51, 100, i], None).await.status();
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        let full = || {
            metrics.render().lines().find_map(|l| {
                l.strip_prefix(
                    "attenuo_requests_rate_limited_total{limit=\"token_unauthenticated\",cause=\"table_full\"} ",
                )
                .map(|n| n.parse::<u64>().unwrap())
            })
            .unwrap_or(0)
        };
        assert_eq!(full(), 0);
        // The agent, from its address and from one never seen: served, and not counted.
        assert_eq!(send([192, 0, 2, 1], agent).await.status(), StatusCode::OK);
        assert_eq!(send([192, 0, 2, 2], agent).await.status(), StatusCode::OK);
        assert_eq!(limits.token_peer.as_ref().unwrap().tracked(), 100);
        // Client credentials that do not authenticate, from a new address: they are tried,
        // and the answer is the 429 a peer over its limit gets, not the handler's 401.
        let before = attempts.load(Ordering::SeqCst);
        let bad = send([203, 0, 113, 1], Some(("x-secret", "wrong"))).await;
        assert_eq!(attempts.load(Ordering::SeqCst), before + 1);
        assert_eq!(bad.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(bad.headers().contains_key(header::RETRY_AFTER));
        let bad = json_of(bad).await;
        // No client credential, or an actor token: refused before any authentication work.
        for header in [None, Some(("x-actor", "token"))] {
            let resp = send([203, 0, 113, 2], header).await;
            assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(json_of(resp).await, bad);
        }
        assert_eq!(attempts.load(Ordering::SeqCst), before + 1);
        assert_eq!(full(), 3);
        // A peer that is in the table and over its limit (2): refused before the handler runs,
        // with the same body, counted as `limit`.
        assert_eq!(
            send([198, 51, 100, 7], None).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let ran = runs.load(Ordering::SeqCst);
        let over = send([198, 51, 100, 7], agent).await;
        assert_eq!(over.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(runs.load(Ordering::SeqCst), ran);
        assert_eq!(json_of(over).await, bad);
        assert!(metrics.render().contains(
            "attenuo_requests_rate_limited_total{limit=\"token_unauthenticated\",cause=\"limit\"} 1\n"
        ));
        assert_eq!(full(), 3);
        assert_eq!(limits.token_peer.as_ref().unwrap().tracked(), 100);
    }

    /// With `max_in_flight` requests running, the next one is refused at once with `503`,
    /// `Retry-After` and the route's error shape, while `/healthz` is still answered; once a
    /// request ends its permit is free again.
    #[tokio::test]
    async fn the_in_flight_cap_sheds_and_spares_the_probes() {
        let (limits, metrics) = limits(|l| l.max_in_flight = 1);
        let gate = Arc::new(tokio::sync::Notify::new());
        let app = app(&limits, gate.clone(), Duration::from_secs(30));
        let held = tokio::spawn({
            let app = app.clone();
            async move { send(&app, "GET", "/token").await }
        });
        // Wait until the first request holds the only permit.
        while limits.in_flight.as_ref().unwrap().available_permits() > 0 {
            tokio::task::yield_now().await;
        }
        let rest = send(&app, "GET", "/token").await;
        assert_eq!(rest.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(rest.headers()[header::RETRY_AFTER], "1");
        let v = json_of(rest).await;
        assert_eq!(v["error"], "temporarily_unavailable");
        assert_eq!(v["error_description"], OVERLOADED);

        let mcp = send(&app, "GET", "/mcp/github").await;
        assert_eq!(mcp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(mcp.headers()[header::RETRY_AFTER], "1");
        let v = json_of(mcp).await;
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["error"]["code"], attenuo_proxy::jsonrpc::CODE_UNAVAILABLE);
        assert_eq!(v["error"]["data"]["reason"], OVERLOADED);

        assert_eq!(send(&app, "GET", "/healthz").await.status(), StatusCode::OK);
        assert!(metrics.render().contains("attenuo_requests_shed_total 2\n"));

        gate.notify_one();
        assert_eq!(held.await.unwrap().status(), StatusCode::OK);
        let again = tokio::spawn({
            let app = app.clone();
            async move { send(&app, "GET", "/token").await }
        });
        while limits.in_flight.as_ref().unwrap().available_permits() > 0 {
            tokio::task::yield_now().await;
        }
        gate.notify_one();
        assert_eq!(again.await.unwrap().status(), StatusCode::OK);
    }

    /// `max_in_flight = 0` is no cap at all.
    #[tokio::test]
    async fn zero_turns_the_cap_off() {
        let (limits, _) = limits(|l| l.max_in_flight = 0);
        assert!(limits.in_flight.is_none());
        let app = app(
            &limits,
            Arc::new(tokio::sync::Notify::new()),
            Duration::ZERO,
        );
        let all =
            futures_util::future::join_all((0..50).map(|_| send(&app, "GET", "/token"))).await;
        assert!(all.iter().all(|r| r.status() == StatusCode::OK));
    }

    /// A REST route past `request_timeout_seconds` is answered `503` `request_timeout`; the
    /// proxy and admin routes are not cut by it.
    #[tokio::test(start_paused = true)]
    async fn the_handler_deadline_spares_the_proxy_and_admin_routes() {
        let (limits, metrics) = limits(|l| l.request_timeout_seconds = 1);
        let app = app(
            &limits,
            Arc::new(tokio::sync::Notify::new()),
            Duration::from_secs(5),
        );
        let resp = send(&app, "GET", "/token").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp.headers()[header::RETRY_AFTER], "1");
        assert_eq!(json_of(resp).await["error_description"], REQUEST_TIMEOUT);
        assert!(metrics
            .render()
            .contains("attenuo_request_timeouts_total{kind=\"handler\"} 1\n"));
        for path in ["/mcp/github", "/admin/audit/verify"] {
            let resp = send(&app, "GET", path).await;
            assert_eq!(resp.status(), StatusCode::OK, "{path}");
        }
    }

    /// A body that does not arrive within `request_body_timeout_seconds` is `408`; one that
    /// does is read.
    #[tokio::test]
    async fn a_slow_body_is_refused_with_408() {
        use tower::ServiceExt as _;
        let (limits, _) = limits(|l| l.request_body_timeout_seconds = 1);
        let app = app(
            &limits,
            Arc::new(tokio::sync::Notify::new()),
            Duration::ZERO,
        );
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(1);
        tx.send(Ok(Bytes::from_static(b"abc"))).await.unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/body")
            .body(Body::from_stream(tokio_stream_from(rx)))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(json_of(resp).await["error"], REQUEST_TIMEOUT);
        drop(tx);
        let req = Request::builder()
            .method("POST")
            .uri("/body")
            .body(Body::from("abcd"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn retry_after_rounds_up_to_whole_seconds() {
        assert_eq!(retry_seconds(Duration::ZERO), 1);
        assert_eq!(retry_seconds(Duration::from_millis(1)), 1);
        assert_eq!(retry_seconds(Duration::from_millis(1_001)), 2);
        assert_eq!(retry_seconds(Duration::from_secs(60)), 60);
    }

    #[test]
    fn peer_keys_group_ipv6_by_64() {
        let a: SocketAddr = "[2001:db8:1:2:aaaa::1]:5000".parse().unwrap();
        let b: SocketAddr = "[2001:db8:1:2:bbbb::9]:6000".parse().unwrap();
        let c: SocketAddr = "[2001:db8:1:3::1]:6000".parse().unwrap();
        assert_eq!(peer_key(Some(a)), peer_key(Some(b)));
        assert_ne!(peer_key(Some(a)), peer_key(Some(c)));
        assert_eq!(peer_key(Some(a)), "2001:db8:1:2::/64");
        let v4: SocketAddr = "192.0.2.7:1".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:192.0.2.7]:1".parse().unwrap();
        assert_eq!(peer_key(Some(v4)), "192.0.2.7");
        assert_eq!(peer_key(Some(mapped)), "192.0.2.7");
        assert_eq!(peer_key(None), "unknown");
    }

    /// A body error from the deadline is recognised through the wrappers axum puts round it.
    #[tokio::test]
    async fn a_body_timeout_is_recognised_through_the_extractor() {
        use axum::extract::FromRequest;
        let metrics = Metrics::new();
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(1);
        tx.send(Ok(Bytes::from_static(b"{"))).await.unwrap();
        let slow = Body::from_stream(tokio_stream_from(rx));
        let body = Body::new(Deadlined {
            inner: slow,
            timer: Box::pin(tokio::time::sleep(Duration::from_millis(50))),
            metrics: metrics.clone(),
            fired: false,
        });
        let req = Request::builder().body(body).unwrap();
        let err = Bytes::from_request(req, &()).await.unwrap_err();
        assert!(is_body_timeout(&err));
        let api = crate::routes::extract::body_rejection(err);
        assert_eq!(api.status, StatusCode::REQUEST_TIMEOUT);
        assert!(metrics
            .render()
            .contains("attenuo_request_timeouts_total{kind=\"body\"} 1\n"));
        drop(tx);
    }

    /// A stream over an mpsc receiver, without a dependency on `tokio-stream`.
    fn tokio_stream_from(
        mut rx: tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>,
    ) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> {
        futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx))
    }
}
