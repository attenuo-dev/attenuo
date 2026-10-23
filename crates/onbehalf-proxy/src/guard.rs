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
//! Dropping the wrapped stream drops the upstream response, which closes the upstream
//! connection.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use futures_util::{Stream, StreamExt};
use onbehalf_core::DelegationChain;
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::auth::{AuthError, Authorizer};
use crate::jsonrpc::{error_response, CODE_UNAUTHORIZED};

/// Reason given when a stream is ended because a hop of the token's chain expired.
pub use crate::auth::REASON_TOKEN_EXPIRED;

/// What a stream is re-checked against, and how often.
#[derive(Clone)]
pub struct StreamGuard {
    pub authorizer: Arc<dyn Authorizer>,
    pub chain: DelegationChain,
    pub interval: Duration,
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
        }
    }

    /// Is the stream still allowed at `now`? `Err` carries a short reason code.
    pub async fn check(&self, now: OffsetDateTime) -> Result<(), String> {
        if self.chain.hops.iter().any(|h| h.expires_at <= now) {
            return Err(REASON_TOKEN_EXPIRED.to_owned());
        }
        match self.authorizer.check_active(&self.chain, now).await {
            Ok(()) => Ok(()),
            Err(AuthError::LeaseInactive(reason)) => Err(reason),
            Err(AuthError::TokenExpired) => Err(REASON_TOKEN_EXPIRED.to_owned()),
            Err(AuthError::Unavailable(reason)) => Err(reason),
            Err(
                AuthError::MissingToken
                | AuthError::InvalidToken(_)
                | AuthError::DpopRequired
                | AuthError::InvalidDpopProof(_),
            ) => Err("unauthorized".to_owned()),
        }
    }
}

/// The SSE event sent before a stream is ended for `reason`.
pub fn end_event(reason: &str) -> Bytes {
    let body: Value = error_response(
        Value::Null,
        CODE_UNAUTHORIZED,
        format!("onbehalf: unauthorized: stream ended: {reason}"),
        Some(json!({ "reason": reason })),
    );
    Bytes::from(format!("event: message\ndata: {body}\n\n"))
}

type BoxStream = Pin<Box<dyn Stream<Item = Result<Bytes, io::Error>> + Send>>;

struct State {
    inner: BoxStream,
    guard: StreamGuard,
    ticker: tokio::time::Interval,
    sse: bool,
    done: bool,
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
                    let Err(reason) = st.guard.check(OffsetDateTime::now_utc()).await else {
                        continue;
                    };
                    tracing::warn!(
                        reason = ?reason,
                        subject = ?st.guard.chain.originating_user.subject,
                        "ending response stream: re-check failed"
                    );
                    st.done = true;
                    let last = if st.sse {
                        Ok(end_event(&reason))
                    } else {
                        Err(io::Error::other(format!("onbehalf: stream ended: {reason}")))
                    };
                    return Some((last, st));
                }
                item = st.inner.next() => {
                    return item.map(|chunk| (chunk, st));
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{test_chain, StaticAuthorizer};
    use onbehalf_core::Capability;

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
