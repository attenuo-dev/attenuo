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
//! Dropping the wrapped stream drops the upstream response, which closes the upstream
//! connection.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use attenuo_core::{DelegationChain, ToolCall};
use axum::body::Bytes;
use futures_util::{Stream, StreamExt};
use serde_json::{json, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::{AuthError, Authorizer};
use crate::jsonrpc::{error_response, CODE_UNAUTHORIZED};
use crate::session::session_tag;

/// Reason given when a stream is ended because a hop of the token's chain expired.
pub use crate::auth::REASON_TOKEN_EXPIRED;

/// The tool name of the audit record written when the proxy ends a stream because the lease
/// is no longer live or the token expired. A fixed name, like `http.GET`, never request text.
pub const STREAM_END_TOOL: &str = "stream.end";

/// What a stream is re-checked against, and how often.
#[derive(Clone)]
pub struct StreamGuard {
    pub authorizer: Arc<dyn Authorizer>,
    pub chain: DelegationChain,
    pub interval: Duration,
    /// Where the stream goes, for the audit record of its end; `None` records nothing.
    pub record: Option<StreamRecord>,
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
        }
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
        let fail = |reason: String, recorded: bool| Err(Failed { reason, recorded });
        if self.chain.hops.iter().any(|h| h.expires_at <= now) {
            return fail(REASON_TOKEN_EXPIRED.to_owned(), true);
        }
        match self.authorizer.check_active(&self.chain, now).await {
            Ok(()) => Ok(()),
            Err(AuthError::LeaseInactive(reason)) => fail(reason, true),
            Err(AuthError::TokenExpired) => fail(REASON_TOKEN_EXPIRED.to_owned(), true),
            Err(AuthError::Unavailable(reason)) => fail(reason, false),
            Err(
                AuthError::MissingToken
                | AuthError::InvalidToken(_)
                | AuthError::DpopRequired
                | AuthError::InvalidDpopProof(_)
                | AuthError::UseDpopNonce(_),
            ) => fail("unauthorized".to_owned(), false),
        }
    }

    /// Record the end of the stream for `reason` ([`STREAM_END_TOOL`]); `None` when the guard
    /// records nothing.
    async fn record_end(&self, reason: &str, now: OffsetDateTime) -> Option<Uuid> {
        let record = self.record.as_ref()?;
        let mut call = ToolCall::new(record.server.as_str(), STREAM_END_TOOL, json!({}))
            .with_dpop_bound(record.dpop_bound);
        if let Some(tag) = &record.session {
            call = call.with_session(tag.clone());
        }
        Some(
            self.authorizer
                .record_rejection(&self.chain, &call, reason, now)
                .await,
        )
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
    /// The stream ended on its own: the upstream finished it, or the guard cut it.
    done: bool,
}

impl State {
    fn log_fields(&self) -> (&str, &str) {
        self.guard.record.as_ref().map_or(("", ""), |r| {
            (r.server.as_str(), r.session.as_deref().unwrap_or_default())
        })
    }
}

impl Drop for State {
    /// Dropped before it ended: the client went away (or the server shut down). Not a
    /// decision, so a log line, not an audit record.
    fn drop(&mut self) {
        if !self.done {
            let (server, session) = self.log_fields();
            tracing::info!(
                server = ?server,
                session = %session,
                subject = ?self.guard.chain.originating_user.subject,
                "response stream closed by the client"
            );
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
                    let decision_id = if failed.recorded {
                        st.guard.record_end(&reason, now).await
                    } else {
                        None
                    };
                    let (server, session) = st.log_fields();
                    tracing::warn!(
                        reason = ?reason,
                        server = ?server,
                        session = %session,
                        subject = ?st.guard.chain.originating_user.subject,
                        decision_id = ?decision_id,
                        "ending response stream: re-check failed"
                    );
                    st.done = true;
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
                        let (server, session) = st.log_fields();
                        tracing::debug!(
                            server = ?server,
                            session = %session,
                            "response stream ended by the upstream"
                        );
                        return None;
                    };
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
}
