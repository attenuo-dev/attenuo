//! Re-checking long-lived response streams (SR-28).
//!
//! A `GET` listen stream, or a `POST` whose upstream answers with a streamed body (SSE), can
//! stay open far longer than the request that opened it. The lease check made when it opened
//! says nothing about later: a revoked lease (P4) or an expired token must end the stream too.
//! [`guard_stream`] wraps the body sent to the client and, every [`StreamGuard::interval`],
//! checks the token's expiry (the earliest `expires_at` of the chain's hops) and calls
//! [`Authorizer::check_active`]. At the first failure it ends the stream: for SSE, after one
//! last `message` event carrying a JSON-RPC error `-32001` with `data.reason` set to
//! `token_expired`, `lease_revoked` or the authorizer's reason; for any other body, with a
//! transport error, so the client cannot mistake a truncated body for a complete one.
//!
//! When the stream is ended because the chain's lease is no longer live or its token expired,
//! and the guard knows where the stream goes ([`StreamGuard::recording`]), the end is recorded
//! through [`Authorizer::record_rejection`]: one `deny` record with the fixed tool name
//! [`STREAM_END_TOOL`], the reason, the proxied server and the session's hash tag, and its id
//! in the final event's `data.decision_id`. The token verified when the stream opened, so the
//! record names a principal attenuo issued a token to (SR-18). A stream that ends because the
//! upstream closed it or the client went away is not a decision and stays a log line (debug
//! and info), so long-lived listen streams that come and go add nothing to the audit log.
//!
//! On the `GET` listen stream ([`StreamGuard::listen`]) two more things happen:
//!
//! - every stream is counted once when it ends, by [`StreamEndCause`], through
//!   [`Authorizer::observe_stream_end`] (the server's `proxy_streams_ended_total{cause}`),
//!   however it ends: cut by the re-check, finished or broken by the upstream, or dropped by
//!   the client (the `Drop` of the stream state);
//! - its `stream.end` records are bounded by a [`RecordWindow`]: at most one per delegation
//!   chain and reason every [`STREAM_END_RECORD_WINDOW`]. The first end in a window is
//!   recorded; later ones in the same window still end their stream with the same final event
//!   (naming the first record's id), are logged, and are counted through
//!   [`Authorizer::observe_record_suppressed`] instead of recorded. The lease refusals of
//!   undecided requests are bounded the same way by their own window ([`crate::records`]);
//!   tool-call decisions and decided refusals (exchanges, renewals) never are.
//!
//! Dropping the wrapped stream drops the upstream response, which closes the upstream
//! connection.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use attenuo_core::{chain_id_of, DelegationChain, ToolCall};
use axum::body::Bytes;
use futures_util::{Stream, StreamExt};
use serde_json::{json, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::{AuthError, Authorizer};
use crate::jsonrpc::{error_response, CODE_UNAUTHORIZED};
use crate::records::{Admission, RecordWindow};
use crate::session::session_tag;

/// Reason given when a stream is ended because a hop of the token's chain expired.
pub use crate::auth::REASON_TOKEN_EXPIRED;

/// The tool name of the audit record written when the proxy ends a stream because the lease
/// is no longer live or the token expired. A fixed name, like `http.GET`, never request text.
pub const STREAM_END_TOOL: &str = "stream.end";

/// How long, after a `stream.end` record of a `GET` listen stream, further ends of listen
/// streams of the same delegation chain for the same reason are counted instead of recorded
/// ([`RecordWindow`]). A minute keeps the record of when the condition began, and one more
/// a minute later while it lasts, without one record per stream: a client holding several
/// listen streams (or several sessions) of one token sees them all end at the same expiry or
/// revocation. A constant, not configuration: the suppressed ends are in the metric
/// `audit_records_suppressed_total` and the proxy log.
pub const STREAM_END_RECORD_WINDOW: Duration = Duration::from_secs(60);

/// Why a guarded `GET` listen stream ended: the `cause` label of the server's
/// `proxy_streams_ended_total`. A fixed set, so the metric's cardinality stays bounded; the
/// lease reasons the server's authorizer gives map to their own value, any other to
/// [`StreamEndCause::LeaseOther`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamEndCause {
    /// The re-check found a hop of the token's chain expired (recorded).
    TokenExpired,
    /// The re-check found a lease of the chain revoked (recorded).
    LeaseRevoked,
    /// The re-check found a lease of the chain expired (recorded).
    LeaseExpired,
    /// The re-check found a lease of the chain unknown to the store (recorded).
    LeaseUnknown,
    /// The lease store could not answer; the chain counts as inactive (recorded).
    LeaseError,
    /// Any other lease reason from a custom authorizer (recorded).
    LeaseOther,
    /// The re-check could not run (a server-side limit); not recorded.
    RecheckUnavailable,
    /// The re-check failed for a reason that is not a lease or token judgement; not recorded.
    RecheckFailed,
    /// The client went away (or the server shut down) before the stream ended; not recorded.
    ClientDisconnect,
    /// The upstream finished the stream; not recorded.
    UpstreamEof,
    /// The upstream stream broke (a transport error, an event over the size limit); not
    /// recorded.
    UpstreamError,
}

impl StreamEndCause {
    /// Every cause, in label order.
    pub const ALL: [StreamEndCause; 11] = [
        StreamEndCause::TokenExpired,
        StreamEndCause::LeaseRevoked,
        StreamEndCause::LeaseExpired,
        StreamEndCause::LeaseUnknown,
        StreamEndCause::LeaseError,
        StreamEndCause::LeaseOther,
        StreamEndCause::RecheckUnavailable,
        StreamEndCause::RecheckFailed,
        StreamEndCause::ClientDisconnect,
        StreamEndCause::UpstreamEof,
        StreamEndCause::UpstreamError,
    ];

    /// The causes whose end is a `stream.end` record: the `reason` label values of the
    /// server's `audit_records_suppressed_total`. They lead [`StreamEndCause::ALL`], so their
    /// [`index`](StreamEndCause::index) is also their position here.
    pub const RECORDED: [StreamEndCause; 6] = [
        StreamEndCause::TokenExpired,
        StreamEndCause::LeaseRevoked,
        StreamEndCause::LeaseExpired,
        StreamEndCause::LeaseUnknown,
        StreamEndCause::LeaseError,
        StreamEndCause::LeaseOther,
    ];

    /// The label value. For a recorded cause other than [`StreamEndCause::LeaseOther`] it is
    /// also the record's reason code.
    pub fn as_str(self) -> &'static str {
        match self {
            StreamEndCause::TokenExpired => "token_expired",
            StreamEndCause::LeaseRevoked => "lease_revoked",
            StreamEndCause::LeaseExpired => "lease_expired",
            StreamEndCause::LeaseUnknown => "lease_unknown",
            StreamEndCause::LeaseError => "lease_error",
            StreamEndCause::LeaseOther => "lease_other",
            StreamEndCause::RecheckUnavailable => "recheck_unavailable",
            StreamEndCause::RecheckFailed => "recheck_failed",
            StreamEndCause::ClientDisconnect => "client_disconnect",
            StreamEndCause::UpstreamEof => "upstream_eof",
            StreamEndCause::UpstreamError => "upstream_error",
        }
    }

    /// Position in [`StreamEndCause::ALL`].
    pub fn index(self) -> usize {
        self as usize
    }

    /// The cause of a lease refusal with `reason` ([`AuthError::LeaseInactive`]). Also the
    /// `reason` label of a suppressed lease-refusal record ([`crate::records`]), so a custom
    /// authorizer's reason cannot widen the metric's label set.
    pub fn of_lease_reason(reason: &str) -> Self {
        match reason {
            "lease_revoked" => StreamEndCause::LeaseRevoked,
            "lease_expired" => StreamEndCause::LeaseExpired,
            "lease_unknown" => StreamEndCause::LeaseUnknown,
            "lease_error" => StreamEndCause::LeaseError,
            _ => StreamEndCause::LeaseOther,
        }
    }
}

/// What a stream is re-checked against, and how often.
#[derive(Clone)]
pub struct StreamGuard {
    pub authorizer: Arc<dyn Authorizer>,
    pub chain: DelegationChain,
    pub interval: Duration,
    /// Where the stream goes, for the audit record of its end; `None` records nothing.
    pub record: Option<StreamRecord>,
    /// Set for a `GET` listen stream ([`StreamGuard::listen`]): its end is counted, and its
    /// `stream.end` record bounded by this window.
    pub listen: Option<Arc<RecordWindow>>,
}

/// Where a guarded stream goes, for the audit record written when the proxy ends it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamRecord {
    /// The `/mcp/{server}` name.
    pub server: String,
    /// The hash tag of the stream's `Mcp-Session-Id` ([`session_tag`]), never the id itself.
    pub session: Option<String>,
    /// Whether the request that opened the stream proved possession of the token's key.
    pub dpop_bound: bool,
}

/// Why a check failed: the reason code, and whether it is a lease or token judgement (which
/// is recorded) rather than a server-side failure (which is not).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Failed {
    reason: String,
    recorded: bool,
    cause: StreamEndCause,
}

/// What became of the record of a stream end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndRecord {
    /// Nothing was recorded and nothing stands for it (a guard without `recording`).
    None,
    /// Recorded as this id.
    Written(Uuid),
    /// Not recorded: the first record of the window stands for it ([`RecordWindow`]).
    Suppressed(Option<Uuid>),
}

impl EndRecord {
    /// The id the final event names.
    fn id(self) -> Option<Uuid> {
        match self {
            EndRecord::None => None,
            EndRecord::Written(id) => Some(id),
            EndRecord::Suppressed(first) => first,
        }
    }
}

impl StreamGuard {
    pub fn new(
        authorizer: Arc<dyn Authorizer>,
        chain: DelegationChain,
        interval: Duration,
    ) -> Self {
        Self {
            authorizer,
            chain,
            interval: interval.max(Duration::from_millis(1)),
            record: None,
            listen: None,
        }
    }

    /// Mark the stream as a `GET` listen stream: count its end through
    /// [`Authorizer::observe_stream_end`], and bound its `stream.end` records by `records`.
    pub fn listen(mut self, records: Arc<RecordWindow>) -> Self {
        self.listen = Some(records);
        self
    }

    /// Record the end of the stream when the proxy cuts it for a lease or token reason: the
    /// stream serves `server`, in the session `session_id` (stored as its hash tag only).
    pub fn recording(mut self, server: &str, session_id: Option<&str>, dpop_bound: bool) -> Self {
        self.record = Some(StreamRecord {
            server: server.to_owned(),
            session: session_id.map(session_tag),
            dpop_bound,
        });
        self
    }

    /// Is the stream still allowed at `now`? `Err` carries a short reason code.
    pub async fn check(&self, now: OffsetDateTime) -> Result<(), String> {
        self.check_detail(now).await.map_err(|f| f.reason)
    }

    async fn check_detail(&self, now: OffsetDateTime) -> Result<(), Failed> {
        let fail = |reason: String, recorded: bool, cause: StreamEndCause| {
            Err(Failed {
                reason,
                recorded,
                cause,
            })
        };
        let expired = || {
            fail(
                REASON_TOKEN_EXPIRED.to_owned(),
                true,
                StreamEndCause::TokenExpired,
            )
        };
        if self.chain.hops.iter().any(|h| h.expires_at <= now) {
            return expired();
        }
        match self.authorizer.check_active(&self.chain, now).await {
            Ok(()) => Ok(()),
            Err(AuthError::LeaseInactive(reason)) => {
                let cause = StreamEndCause::of_lease_reason(&reason);
                fail(reason, true, cause)
            }
            Err(AuthError::TokenExpired) => expired(),
            Err(AuthError::Unavailable(reason)) => {
                fail(reason, false, StreamEndCause::RecheckUnavailable)
            }
            Err(
                AuthError::MissingToken
                | AuthError::InvalidToken(_)
                | AuthError::DpopRequired
                | AuthError::InvalidDpopProof(_)
                | AuthError::UseDpopNonce(_),
            ) => fail(
                "unauthorized".to_owned(),
                false,
                StreamEndCause::RecheckFailed,
            ),
        }
    }

    /// Record the end of the stream for `reason` ([`STREAM_END_TOOL`]), unless the guard
    /// records nothing, or the stream is a listen stream whose chain already has a record for
    /// `reason` in the current window ([`RecordWindow`]).
    async fn record_end(
        &self,
        reason: &str,
        cause: StreamEndCause,
        now: OffsetDateTime,
    ) -> EndRecord {
        let Some(record) = self.record.as_ref() else {
            return EndRecord::None;
        };
        let window = self
            .listen
            .as_ref()
            .map(|records| (records, self.chain.digest()));
        if let Some((records, key)) = &window {
            match records.admit(key, STREAM_END_TOOL, reason, Instant::now()) {
                Admission::Suppress { first } => {
                    self.authorizer
                        .observe_record_suppressed(STREAM_END_TOOL, cause);
                    return EndRecord::Suppressed(first);
                }
                Admission::Record { suppressed_before } if suppressed_before > 0 => {
                    tracing::info!(
                        reason = ?reason,
                        suppressed = suppressed_before,
                        chain_id = ?chain_id_of(&self.chain),
                        subject = ?self.chain.originating_user.subject,
                        "stream.end records suppressed in the previous window"
                    );
                }
                Admission::Record { .. } => {}
            }
        }
        let mut call = ToolCall::new(record.server.as_str(), STREAM_END_TOOL, json!({}))
            .with_dpop_bound(record.dpop_bound);
        if let Some(tag) = &record.session {
            call = call.with_session(tag.clone());
        }
        let id = self
            .authorizer
            .record_rejection(&self.chain, &call, reason, now)
            .await;
        if let Some((records, key)) = &window {
            records.recorded(key, STREAM_END_TOOL, reason, id);
        }
        EndRecord::Written(id)
    }
}

/// The SSE event sent before a stream is ended for `reason`.
pub fn end_event(reason: &str) -> Bytes {
    end_event_recorded(reason, None)
}

/// [`end_event`] for an end recorded as `decision_id`, which `data.decision_id` carries.
pub fn end_event_recorded(reason: &str, decision_id: Option<Uuid>) -> Bytes {
    let mut data = json!({ "reason": reason });
    if let Some(id) = decision_id {
        data["decision_id"] = Value::String(id.to_string());
    }
    let body: Value = error_response(
        Value::Null,
        CODE_UNAUTHORIZED,
        format!("attenuo: unauthorized: stream ended: {reason}"),
        Some(data),
    );
    Bytes::from(format!("event: message\ndata: {body}\n\n"))
}

type BoxStream = Pin<Box<dyn Stream<Item = Result<Bytes, io::Error>> + Send>>;

struct State {
    inner: BoxStream,
    guard: StreamGuard,
    ticker: tokio::time::Interval,
    sse: bool,
    /// The stream ended on its own: the upstream finished or broke it, or the guard cut it.
    done: bool,
    /// Why it ended, once it did; still `None` when the client went away.
    cause: Option<StreamEndCause>,
}

impl State {
    fn log_fields(&self) -> (&str, &str) {
        self.guard.record.as_ref().map_or(("", ""), |r| {
            (r.server.as_str(), r.session.as_deref().unwrap_or_default())
        })
    }
}

impl Drop for State {
    /// The state is dropped exactly once, however the stream ended, so a listen stream is
    /// counted here ([`Authorizer::observe_stream_end`]). Dropped before it ended: the client
    /// went away (or the server shut down). Not a decision, so a log line, not an audit
    /// record.
    fn drop(&mut self) {
        if !self.done {
            let (server, session) = self.log_fields();
            tracing::info!(
                server = ?server,
                session = %session,
                chain_id = ?chain_id_of(&self.guard.chain),
                subject = ?self.guard.chain.originating_user.subject,
                "response stream closed by the client"
            );
        }
        if self.guard.listen.is_some() {
            let cause = self.cause.unwrap_or(StreamEndCause::ClientDisconnect);
            self.guard.authorizer.observe_stream_end(cause);
        }
    }
}

/// Wrap `inner` so that it ends at the first failed [`StreamGuard::check`]. `sse` says the
/// body is an event stream whose chunks end on event boundaries (see
/// [`crate::sse::frame_stream`]), so a final event can be appended.
pub fn guard_stream<S>(
    inner: S,
    guard: StreamGuard,
    sse: bool,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static
where
    S: Stream<Item = Result<Bytes, io::Error>> + Send + 'static,
{
    let mut ticker =
        tokio::time::interval_at(tokio::time::Instant::now() + guard.interval, guard.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let state = State {
        inner: Box::pin(inner),
        guard,
        ticker,
        sse,
        done: false,
        cause: None,
    };
    futures_util::stream::unfold(state, |mut st| async move {
        if st.done {
            return None;
        }
        loop {
            tokio::select! {
                // A ready tick wins over a ready chunk, so a busy stream is checked on time too.
                biased;
                _ = st.ticker.tick() => {
                    let now = OffsetDateTime::now_utc();
                    let Err(failed) = st.guard.check_detail(now).await else {
                        continue;
                    };
                    let reason = failed.reason;
                    let end = if failed.recorded {
                        st.guard.record_end(&reason, failed.cause, now).await
                    } else {
                        EndRecord::None
                    };
                    let decision_id = end.id();
                    let (server, session) = st.log_fields();
                    tracing::warn!(
                        reason = ?reason,
                        server = ?server,
                        session = %session,
                        chain_id = ?chain_id_of(&st.guard.chain),
                        subject = ?st.guard.chain.originating_user.subject,
                        decision_id = ?decision_id,
                        record_suppressed = matches!(end, EndRecord::Suppressed(_)),
                        "ending response stream: re-check failed"
                    );
                    st.done = true;
                    st.cause = Some(failed.cause);
                    let last = if st.sse {
                        Ok(end_event_recorded(&reason, decision_id))
                    } else {
                        Err(io::Error::other(format!("attenuo: stream ended: {reason}")))
                    };
                    return Some((last, st));
                }
                item = st.inner.next() => {
                    let Some(chunk) = item else {
                        st.done = true;
                        st.cause = Some(StreamEndCause::UpstreamEof);
                        let (server, session) = st.log_fields();
                        tracing::debug!(
                            server = ?server,
                            session = %session,
                            chain_id = ?chain_id_of(&st.guard.chain),
                            "response stream ended by the upstream"
                        );
                        return None;
                    };
                    if let Err(e) = &chunk {
                        // The error ends the body: nothing after it is relayed.
                        st.done = true;
                        st.cause = Some(StreamEndCause::UpstreamError);
                        let (server, session) = st.log_fields();
                        tracing::debug!(
                            server = ?server,
                            session = %session,
                            chain_id = ?chain_id_of(&st.guard.chain),
                            error = ?e.to_string(),
                            "response stream broken by the upstream"
                        );
                    }
                    return Some((chunk, st));
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{test_chain, StaticAuthorizer};
    use attenuo_core::Capability;

    fn ticking() -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static {
        futures_util::stream::unfold(0u32, |i| async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            Some((Ok(Bytes::from(format!("data: {i}\n\n"))), i + 1))
        })
    }

    #[tokio::test]
    async fn revocation_ends_the_stream_with_a_final_event() {
        let chain = test_chain("user:a", "agent:a", [Capability::new("s", "*")]);
        let auth = Arc::new(StaticAuthorizer::new().with_chain("a", chain.clone()));
        let guard = StreamGuard::new(auth.clone(), chain, Duration::from_millis(20));
        let mut s = Box::pin(guard_stream(ticking(), guard, true));
        assert!(s.next().await.unwrap().is_ok());
        auth.revoke("a");
        let mut last = Bytes::new();
        while let Some(chunk) = tokio::time::timeout(Duration::from_secs(2), s.next())
            .await
            .expect("stream ends")
        {
            last = chunk.unwrap();
        }
        let text = String::from_utf8_lossy(&last);
        assert!(text.starts_with("event: message\ndata: "), "{text}");
        let payload: Value =
            serde_json::from_str(text.trim_start_matches("event: message\ndata: ").trim()).unwrap();
        assert_eq!(payload["error"]["code"], -32001);
        assert_eq!(payload["error"]["data"]["reason"], "lease_revoked");
        assert!(payload["id"].is_null());
        // A guard without `recording` writes no audit record.
        assert!(payload["error"]["data"].get("decision_id").is_none());
        assert!(auth.decisions().is_empty());
    }

    #[tokio::test]
    async fn a_non_sse_body_ends_with_an_error() {
        let chain = test_chain("user:a", "agent:a", [Capability::new("s", "*")]);
        let auth = Arc::new(StaticAuthorizer::new().with_chain("a", chain.clone()));
        auth.revoke("a");
        let guard = StreamGuard::new(auth, chain, Duration::from_millis(10));
        let mut s = Box::pin(guard_stream(ticking(), guard, false));
        let mut saw_error = false;
        while let Some(chunk) = tokio::time::timeout(Duration::from_secs(2), s.next())
            .await
            .expect("stream ends")
        {
            saw_error |= chunk.is_err();
        }
        assert!(saw_error);
    }

    #[tokio::test]
    async fn expiry_is_checked_before_the_lease() {
        let mut chain = test_chain("user:a", "agent:a", [Capability::new("s", "*")]);
        let auth = Arc::new(StaticAuthorizer::new().with_chain("a", chain.clone()));
        chain.hops[0].expires_at = OffsetDateTime::now_utc() - time::Duration::seconds(1);
        let guard = StreamGuard::new(auth, chain, Duration::from_millis(10));
        assert_eq!(
            guard.check(OffsetDateTime::now_utc()).await,
            Err(REASON_TOKEN_EXPIRED.to_owned())
        );
    }

    /// The JSON-RPC payload of the final event of a stream the guard ended.
    async fn final_event(guard: StreamGuard) -> Value {
        let mut s = Box::pin(guard_stream(ticking(), guard, true));
        let mut last = Bytes::new();
        while let Some(chunk) = tokio::time::timeout(Duration::from_secs(2), s.next())
            .await
            .expect("stream ends")
        {
            last = chunk.unwrap();
        }
        let text = String::from_utf8_lossy(&last);
        serde_json::from_str(text.trim_start_matches("event: message\ndata: ").trim()).unwrap()
    }

    #[tokio::test]
    async fn listen_stream_ends_are_recorded_once_per_chain_and_window() {
        let chain_a = test_chain("user:a", "agent:a", [Capability::new("s", "*")]);
        let chain_b = test_chain("user:b", "agent:b", [Capability::new("s", "*")]);
        let auth = Arc::new(
            StaticAuthorizer::new()
                .with_chain("a", chain_a.clone())
                .with_chain("b", chain_b.clone()),
        );
        auth.revoke("a");
        auth.revoke("b");
        let window = Duration::from_secs(1);
        let records = Arc::new(RecordWindow::with_max_keys(window, 16));
        let guard = |chain: &DelegationChain| {
            StreamGuard::new(auth.clone(), chain.clone(), Duration::from_millis(10))
                .recording("s", Some("sess"), false)
                .listen(records.clone())
        };
        let started = Instant::now();

        // First end: recorded, and the final event names the record.
        let first = final_event(guard(&chain_a)).await;
        let decisions = auth.decisions();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].tool, STREAM_END_TOOL);
        assert_eq!(decisions[0].reason, "lease_revoked");
        let id = decisions[0].id.to_string();
        assert_eq!(first["error"]["data"]["decision_id"], id);

        // Repeats in the window: ended the same way, not recorded, counted; their final event
        // names the record that stands for them.
        for _ in 0..2 {
            let again = final_event(guard(&chain_a)).await;
            assert_eq!(again["error"]["data"]["reason"], "lease_revoked");
            assert_eq!(again["error"]["data"]["decision_id"], id);
        }
        assert_eq!(auth.decisions().len(), 1);
        assert_eq!(
            auth.suppressed_records(),
            vec![(STREAM_END_TOOL.to_owned(), StreamEndCause::LeaseRevoked); 2]
        );

        // Another chain is not affected.
        let other = final_event(guard(&chain_b)).await;
        let decisions = auth.decisions();
        assert_eq!(decisions.len(), 2);
        assert_eq!(decisions[1].originating_subject, "user:b");
        assert_eq!(
            other["error"]["data"]["decision_id"],
            decisions[1].id.to_string()
        );
        assert!(
            started.elapsed() < window,
            "the test ran too slowly to mean anything"
        );

        // After the window: a new record.
        tokio::time::sleep(window).await;
        let later = final_event(guard(&chain_a)).await;
        let decisions = auth.decisions();
        assert_eq!(decisions.len(), 3);
        assert_eq!(decisions[2].originating_subject, "user:a");
        assert_ne!(decisions[2].id.to_string(), id);
        assert_eq!(
            later["error"]["data"]["decision_id"],
            decisions[2].id.to_string()
        );
        assert_eq!(auth.suppressed_records().len(), 2);
        assert_eq!(auth.stream_ends(), vec![StreamEndCause::LeaseRevoked; 5]);
    }

    #[tokio::test]
    async fn streams_that_are_not_listen_streams_are_neither_bounded_nor_counted() {
        let chain = test_chain("user:a", "agent:a", [Capability::new("s", "*")]);
        let auth = Arc::new(StaticAuthorizer::new().with_chain("a", chain.clone()));
        auth.revoke("a");
        for _ in 0..2 {
            let guard = StreamGuard::new(auth.clone(), chain.clone(), Duration::from_millis(10))
                .recording("s", None, false);
            final_event(guard).await;
        }
        assert_eq!(auth.decisions().len(), 2);
        assert!(auth.suppressed_records().is_empty());
        assert!(auth.stream_ends().is_empty());
    }

    fn listen_guard(auth: &Arc<StaticAuthorizer>, chain: &DelegationChain) -> StreamGuard {
        StreamGuard::new(auth.clone(), chain.clone(), Duration::from_millis(10))
            .recording("s", None, false)
            .listen(Arc::new(RecordWindow::new(STREAM_END_RECORD_WINDOW)))
    }

    #[tokio::test]
    async fn each_way_a_listen_stream_ends_is_counted_once() {
        let chain = test_chain("user:a", "agent:a", [Capability::new("s", "*")]);
        let auth = Arc::new(StaticAuthorizer::new().with_chain("a", chain.clone()));
        // The ends reported since the last call.
        let seen = std::cell::Cell::new(0);
        let take = |auth: &StaticAuthorizer| {
            let ends = auth.stream_ends();
            let new = ends[seen.get()..].to_vec();
            seen.set(ends.len());
            new
        };

        // The upstream finishes it.
        let finite = futures_util::stream::iter([Ok(Bytes::from("data: 1\n\n"))]);
        let s = guard_stream(finite, listen_guard(&auth, &chain), true);
        assert_eq!(s.collect::<Vec<_>>().await.len(), 1);
        assert_eq!(take(&auth), vec![StreamEndCause::UpstreamEof]);

        // The upstream breaks it: the error is relayed and nothing after it.
        let broken = futures_util::stream::iter([
            Ok(Bytes::from("data: 1\n\n")),
            Err(io::Error::other("connection reset")),
            Ok(Bytes::from("data: 2\n\n")),
        ]);
        let s = guard_stream(broken, listen_guard(&auth, &chain), true);
        let items = s.collect::<Vec<_>>().await;
        assert_eq!(items.len(), 2);
        assert!(items[1].is_err());
        assert_eq!(take(&auth), vec![StreamEndCause::UpstreamError]);

        // The client goes away after one event, or before the body was ever polled.
        let mut s = Box::pin(guard_stream(ticking(), listen_guard(&auth, &chain), true));
        assert!(s.next().await.unwrap().is_ok());
        drop(s);
        drop(guard_stream(ticking(), listen_guard(&auth, &chain), true));
        assert_eq!(take(&auth), vec![StreamEndCause::ClientDisconnect; 2]);

        // The re-check cuts it: the chain's token expired, or its lease expired.
        let mut expired = chain.clone();
        expired.hops[0].expires_at = OffsetDateTime::now_utc() - time::Duration::seconds(1);
        final_event(listen_guard(&auth, &expired)).await;
        assert_eq!(take(&auth), vec![StreamEndCause::TokenExpired]);
        auth.expire_lease("a");
        final_event(listen_guard(&auth, &chain)).await;
        assert_eq!(take(&auth), vec![StreamEndCause::LeaseExpired]);
    }

    #[test]
    fn cause_labels_are_fixed_and_recorded_causes_lead() {
        for (i, c) in StreamEndCause::ALL.iter().enumerate() {
            assert_eq!(c.index(), i, "{}", c.as_str());
        }
        for (i, c) in StreamEndCause::RECORDED.iter().enumerate() {
            assert_eq!(c.index(), i, "{}", c.as_str());
        }
        for reason in [
            "lease_revoked",
            "lease_expired",
            "lease_unknown",
            "lease_error",
        ] {
            assert_eq!(StreamEndCause::of_lease_reason(reason).as_str(), reason);
        }
        assert_eq!(
            StreamEndCause::of_lease_reason("anything else"),
            StreamEndCause::LeaseOther
        );
    }
}
