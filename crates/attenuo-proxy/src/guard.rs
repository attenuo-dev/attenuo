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
//!   chain and reason every [`crate::ProxyConfig::record_window`] (`[proxy]
//!   record_window_seconds`, default [`crate::records::DEFAULT_RECORD_WINDOW`], a minute).
//!   The first end in a window is
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
use crate::jsonrpc::{error_response, CODE_UNAUTHORIZED, CODE_UPSTREAM};
use crate::records::{Admission, RecordWindow};
use crate::session::session_tag;

/// Reason given when a stream is ended because a hop of the token's chain expired.
pub use crate::auth::REASON_TOKEN_EXPIRED;

/// The tool name of the audit record written when the proxy ends a stream because the lease
/// is no longer live or the token expired. A fixed name, like `http.GET`, never request text.
pub const STREAM_END_TOOL: &str = "stream.end";

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
        let written = self
            .authorizer
            .record_rejection_checked(&self.chain, &call, reason, now)
            .await;
        match (written, &window) {
            (Some(id), Some((records, key))) => records.recorded(key, STREAM_END_TOOL, reason, id),
            // Not in the log: open no window on it, so the next end is recorded (SR-81).
            (None, Some((records, key))) => records.forget(key, STREAM_END_TOOL, reason),
            (_, None) => {}
        }
        written.map_or(EndRecord::None, EndRecord::Written)
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

/// `data.reason` of an upstream error the proxy rewrote because it had the shape of the
/// proxy's own stream-end event ([`disown_stream_end`]).
pub const REASON_UPSTREAM_STREAM_END_SHAPE: &str = "upstream_stream_end_shape";

/// Does `msg` have the shape of the proxy's stream-end event ([`end_event_recorded`])? A
/// response (no `method` member) whose `id` is `null` or absent and whose `error.code` is
/// `-32001`. This is what the SDKs read as a cut (`stream_end_error`, `streamEndError`)
/// without their test of `data.reason`, so it catches everything they would read as one. The
/// code is compared by value, as the SDKs do: `-32001.0` matches too.
///
/// The proxy's other `-32001` answers (the HTTP 401 of a refused token) carry the request's
/// id when it has one; an upstream's `-32001` that answers a request by its id is left alone.
pub fn has_stream_end_shape(msg: &Value) -> bool {
    let Some(obj) = msg.as_object() else {
        return false;
    };
    let code = obj
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_f64);
    !obj.contains_key("method")
        && obj.get("id").is_none_or(Value::is_null)
        && code == Some(CODE_UNAUTHORIZED as f64)
}

/// Rewrite every message of an upstream `body` (one message or a batch) that has the
/// stream-end shape ([`has_stream_end_shape`]), so that no upstream can speak in the proxy's
/// voice: its `error` becomes `-32005` ([`CODE_UPSTREAM`]) with `data.reason`
/// [`REASON_UPSTREAM_STREAM_END_SHAPE`] and the upstream's error object, unchanged, in
/// `data.upstream_error`. The client still learns that the upstream failed, and why it said
/// it did, but nothing in it reads as a proxy cut or names a decision id at the top level.
/// Returns how many messages were rewritten; each rewrite is logged (without the upstream's
/// text).
pub fn disown_stream_end(body: &mut Value) -> usize {
    let messages: Vec<&mut Value> = match body {
        Value::Array(items) => items.iter_mut().collect(),
        other => vec![other],
    };
    let mut rewritten = 0;
    for msg in messages {
        if !has_stream_end_shape(msg) {
            continue;
        }
        let original = msg.get_mut("error").map(Value::take).unwrap_or_default();
        msg["error"] = json!({
            "code": CODE_UPSTREAM,
            "message": "attenuo: upstream sent an error in the shape of the proxy's stream end",
            "data": {
                "reason": REASON_UPSTREAM_STREAM_END_SHAPE,
                "upstream_error": original,
            },
        });
        rewritten += 1;
    }
    if rewritten > 0 {
        tracing::warn!(
            rewritten,
            "upstream sent an error in the shape of the proxy's stream-end event; rewritten"
        );
    }
    rewritten
}

/// Could the raw bytes of an SSE event hold a message with the stream-end shape
/// ([`has_stream_end_shape`])? A byte scan run before the event is parsed, so that the
/// unfiltered SSE path parses only the rare event that may be a look-alike; every message
/// `has_stream_end_shape` matches passes it, and a false positive only costs the parse.
///
/// `has_stream_end_shape` compares `error.code` by value, so the event must hold a JSON number
/// whose `f64` value is `-32001`. Its text cannot be escaped (JSON numbers have no escapes),
/// it starts with a literal `-`, and it is one unbroken run of the bytes `0-9 . e E + -`
/// (data lines are joined with `\n`, which cannot fall inside a number). The text is not
/// always `-32001`: `-32001.0`, `-32001e0`, `-3.2001e4`, `-3.2001E+4`, `-0.32001e5` and
/// `-320010e-1` all have that value, and so does any decimal close enough to round to it,
/// such as `-32000.99999999999999999` or `-32001.0000000000000001`. A search for `-32001`
/// would miss most of these (`-3.2001e4` does not contain it), and a search for `32001`
/// would miss the rounded ones. What every one of them shares is its significant digits:
/// take the digits and points after the `-`, drop the points and the leading zeros, and what
/// is left starts with `32001` or, for a value just under 32001 in magnitude, `320009` (a
/// double next to 32001 is within 4e-12 of it, so its decimal is `32001.000...` or
/// `32000.999...`). So the scan accepts an event when some `-` is followed by such a run whose
/// significant digits start with `32001` or `320009`. The exponent is not read: a wrong
/// magnitude (`-3.2001`, `-320010`) is a false positive that the parse then rejects.
pub(crate) fn may_hold_stream_end_code(event: &[u8]) -> bool {
    let mut rest = event;
    while let Some(i) = rest.iter().position(|&b| b == b'-') {
        rest = &rest[i + 1..];
        let mut head = [0u8; 6];
        let mut len = 0;
        for &b in rest
            .iter()
            .take_while(|b| b.is_ascii_digit() || **b == b'.')
            .filter(|b| **b != b'.')
            .skip_while(|b| **b == b'0')
            .take(head.len())
        {
            head[len] = b;
            len += 1;
        }
        let head = &head[..len];
        if head.starts_with(b"32001") || head.starts_with(b"320009") {
            return true;
        }
    }
    false
}

/// [`disown_stream_end`] over a chunk of whole SSE events (as [`crate::sse::frame_stream`]
/// and [`crate::sse::rewrite_stream`] emit them). An event with a message to rewrite is
/// emitted again with the new data and its other fields (`id:`, `event:`) kept; an event that
/// passes the scan but whose data does not parse is dropped (SR-79); every other event goes out
/// byte for byte. Only an event that passes [`may_hold_stream_end_code`] is
/// parsed (`docs/design/bench/2026-10-25-vm-sse-disown.md`).
pub(crate) fn disown_events(chunk: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(chunk.len());
    for event in crate::sse::split_events(chunk) {
        if !may_hold_stream_end_code(event) {
            out.extend_from_slice(event);
            continue;
        }
        let parsed = crate::sse::event_json(event);
        if parsed.is_none() && crate::sse::has_data(event) {
            // It may hold the code and the proxy cannot parse it, while a client whose JSON
            // parser differs may read it as a cut: not relayed (SR-79).
            tracing::warn!(
                bytes = event.len(),
                "upstream SSE event that may hold the stream-end code and does not parse; dropped"
            );
            continue;
        }
        let lookalike = parsed.is_some_and(|v| match &v {
            Value::Array(items) => items.iter().any(has_stream_end_shape),
            other => has_stream_end_shape(other),
        });
        if !lookalike
            || crate::sse::rewrite_event(
                event,
                &mut |v: &mut Value| {
                    disown_stream_end(v);
                },
                &mut out,
            )
            .is_err()
        {
            out.extend_from_slice(event);
        }
    }
    out
}

/// [`disown_events`] over one chunk of whole SSE events, returning the chunk itself, without
/// a copy, when no event in it passes [`may_hold_stream_end_code`] (the scan over the chunk
/// sees every event's bytes; a number never runs across the empty line that ends an event).
pub(crate) fn disown_chunk(chunk: Bytes) -> Bytes {
    if may_hold_stream_end_code(&chunk) {
        Bytes::from(disown_events(&chunk))
    } else {
        chunk
    }
}

/// Run every chunk of `inner` (whole SSE events) through [`disown_chunk`].
pub(crate) fn disown_stream<S>(inner: S) -> impl Stream<Item = Result<Bytes, io::Error>> + Send
where
    S: Stream<Item = Result<Bytes, io::Error>> + Send,
{
    inner.map(|chunk| chunk.map(disown_chunk))
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

    fn lookalike(id: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "error": {
            "code": -32001,
            "message": "attenuo: unauthorized: stream ended: lease_revoked",
            "data": {"reason": "lease_revoked", "decision_id": Uuid::nil().to_string()}}})
    }

    #[test]
    fn the_proxys_own_end_event_has_the_protected_shape() {
        for id in [None, Some(Uuid::new_v4())] {
            let event = end_event_recorded(REASON_TOKEN_EXPIRED, id);
            let msg = crate::sse::event_json(&event).unwrap();
            assert!(has_stream_end_shape(&msg), "{msg}");
        }
    }

    #[test]
    fn stream_end_shape_is_null_id_minus_32001_and_no_method() {
        assert!(has_stream_end_shape(&lookalike(Value::Null)));
        let mut absent = lookalike(Value::Null);
        absent.as_object_mut().unwrap().remove("id");
        assert!(has_stream_end_shape(&absent));
        // Compared by value, as the SDKs do; no `data.reason` needed.
        assert!(has_stream_end_shape(
            &json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32001.0, "message": "x"}})
        ));
        // Not the shape: an answer by id, another code, a request or notification, a result.
        assert!(!has_stream_end_shape(&lookalike(json!(7))));
        assert!(!has_stream_end_shape(&lookalike(json!("7"))));
        assert!(!has_stream_end_shape(
            &json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32000, "message": "x"}})
        ));
        let mut with_method = lookalike(Value::Null);
        with_method["method"] = json!("notifications/message");
        assert!(!has_stream_end_shape(&with_method));
        assert!(!has_stream_end_shape(
            &json!({"jsonrpc": "2.0", "id": null, "result": {}})
        ));
        assert!(!has_stream_end_shape(&json!([lookalike(Value::Null)])));
    }

    #[test]
    fn a_lookalike_plain_body_is_rewritten_and_an_answer_by_id_is_not() {
        let mut body = lookalike(Value::Null);
        assert_eq!(disown_stream_end(&mut body), 1);
        assert!(body["id"].is_null());
        assert_eq!(body["error"]["code"], CODE_UPSTREAM);
        assert_eq!(
            body["error"]["data"]["reason"],
            REASON_UPSTREAM_STREAM_END_SHAPE
        );
        assert_eq!(
            body["error"]["data"]["upstream_error"],
            lookalike(Value::Null)["error"]
        );
        assert!(body["error"]["data"].get("decision_id").is_none());
        assert!(!has_stream_end_shape(&body));
        // Rewriting is idempotent.
        assert_eq!(disown_stream_end(&mut body), 0);

        // A `-32001` that answers the request by its id is the upstream's own, left alone.
        let mut by_id = lookalike(json!(1));
        assert_eq!(disown_stream_end(&mut by_id), 0);
        assert_eq!(by_id, lookalike(json!(1)));

        // In a batch only the look-alike changes.
        let ok = json!({"jsonrpc": "2.0", "id": 2, "result": {"content": []}});
        let mut batch = json!([ok, lookalike(Value::Null), lookalike(json!(3))]);
        assert_eq!(disown_stream_end(&mut batch), 1);
        assert_eq!(batch[0], ok);
        assert_eq!(batch[1]["error"]["code"], CODE_UPSTREAM);
        assert_eq!(batch[2], lookalike(json!(3)));
    }

    #[test]
    fn a_lookalike_sse_event_is_rewritten_with_its_fields_and_others_pass_byte_for_byte() {
        let note =
            "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\n\n";
        let by_id = format!("data: {}\n\n", lookalike(json!(1)));
        let fake = format!(
            "id: 7\nevent: message\ndata: {}\n\n",
            lookalike(Value::Null)
        );
        let chunk = format!("{note}{by_id}{fake}");
        let out = String::from_utf8(disown_events(chunk.as_bytes())).unwrap();
        assert!(out.starts_with(&format!("{note}{by_id}")), "{out}");
        let rewritten = &out[note.len() + by_id.len()..];
        assert!(
            rewritten.starts_with("id: 7\nevent: message\ndata: "),
            "{rewritten}"
        );
        let msg = crate::sse::event_json(rewritten.as_bytes()).unwrap();
        assert_eq!(msg["error"]["code"], CODE_UPSTREAM);
        assert_eq!(
            msg["error"]["data"]["upstream_error"]["data"]["reason"],
            "lease_revoked"
        );
        assert!(!has_stream_end_shape(&msg));
        // A chunk with nothing to rewrite comes back unchanged.
        assert_eq!(disown_events(note.as_bytes()), note.as_bytes());
    }

    /// An SSE event whose one message is a look-alike with `code` written as `code`.
    fn lookalike_event(code: &str) -> String {
        format!(
            "id: 3\nevent: message\ndata: {{\"jsonrpc\":\"2.0\",\"id\":null,\
             \"error\":{{\"code\":{code},\"message\":\"x\"}}}}\n\n"
        )
    }

    /// Every spelling of a look-alike's code passes the byte scan, and the event is rewritten.
    fn assert_scanned_and_rewritten(code: &str) {
        let event = lookalike_event(code);
        let msg = crate::sse::event_json(event.as_bytes()).expect(code);
        assert!(has_stream_end_shape(&msg), "not a look-alike: {code}");
        assert!(may_hold_stream_end_code(event.as_bytes()), "missed: {code}");
        let out = disown_events(event.as_bytes());
        let msg = crate::sse::event_json(&out).unwrap();
        assert_eq!(msg["error"]["code"], CODE_UPSTREAM, "{code}");
    }

    #[test]
    fn every_encoding_serde_json_writes_for_the_code_passes_the_byte_scan() {
        for code in [
            json!(-32001i64),
            json!(-32001.0f64),
            json!(CODE_UNAUTHORIZED),
            json!(CODE_UNAUTHORIZED as f64),
        ] {
            let text = code.to_string();
            assert!(["-32001", "-32001.0"].contains(&text.as_str()), "{text}");
            assert_scanned_and_rewritten(&text);
        }
        assert_scanned_and_rewritten(&lookalike(Value::Null)["error"]["code"].to_string());
    }

    #[test]
    fn hand_written_spellings_of_the_code_pass_the_byte_scan() {
        for code in [
            "-32001",
            "-32001.0",
            "-32001.000",
            "-3.2001e4",
            "-3.2001E4",
            "-3.2001e+4",
            "-3.2001E+4",
            "-32001e0",
            "-32001E-0",
            "-0.32001e5",
            "-0.0032001e7",
            "-320010e-1",
            "-3200100e-2",
            "-320.01e2",
            "-3200.1e1",
            "-32001.0000000000000001",
            "-32000.99999999999999999",
            "-3.2000999999999999999e4",
            " -32001 ",
            "\t -3.2001E+4\t",
        ] {
            assert_scanned_and_rewritten(code);
        }
        // Every place for the point and every exponent that puts it back.
        let digits = "32001";
        for point in 1..=digits.len() {
            for zeros in 0..3 {
                let (int, frac) = digits.split_at(point);
                let frac = format!("{frac}{}", "0".repeat(zeros));
                let frac = if frac.is_empty() {
                    String::new()
                } else {
                    format!(".{frac}")
                };
                let exp = digits.len() - point;
                for e in ["e", "E", "e+", "E+"] {
                    assert_scanned_and_rewritten(&format!("-{int}{frac}{e}{exp}"));
                }
                assert_scanned_and_rewritten(&format!(
                    "-0.{}{digits}e{}",
                    "0".repeat(zeros),
                    5 + zeros
                ));
            }
        }
    }

    #[test]
    fn events_without_the_codes_digits_are_not_parsed() {
        for event in [
            "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\
             \"params\":{\"progressToken\":\"call-17\",\"progress\":-3,\"total\":100}}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32000,\"message\":\"x\"}}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":32001,\"message\":\"x\"}}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-3.2002e4,\"message\":\"x\"}}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32002,\"message\":\"-3200 or -32000.8\"}}\n\n",
        ] {
            assert!(!may_hold_stream_end_code(event.as_bytes()), "{event}");
            assert_eq!(disown_events(event.as_bytes()), event.as_bytes());
        }
        // A chunk that fails the scan is passed on as it is.
        let note = Bytes::from_static(b"data: {\"jsonrpc\":\"2.0\",\"method\":\"n\"}\n\n");
        assert_eq!(disown_chunk(note.clone()).as_ptr(), note.as_ptr());
        // A false positive is parsed and left alone.
        let near = "data: {\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-3.2001,\"message\":\"x\"}}\n\n";
        assert!(may_hold_stream_end_code(near.as_bytes()));
        assert_eq!(disown_events(near.as_bytes()), near.as_bytes());
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
            .listen(Arc::new(RecordWindow::new(
                crate::records::DEFAULT_RECORD_WINDOW,
            )))
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

    /// Security review pass 7: every spelling of a number whose `f64` value is -32001 that this
    /// generator can make (point anywhere, leading and trailing zeros, exponents, both cases,
    /// `serde_json`'s and Rust's own formatting, decimals that round to it) passes the byte
    /// scan whenever the parsed message has the stream-end shape.
    #[test]
    fn the_byte_scan_admits_every_spelling_of_the_code_pass7() {
        fn check(num: &str) {
            let text = format!(r#"data: {{"jsonrpc":"2.0","id":null,"error":{{"code":{num}}}}}"#);
            let Ok(v) = serde_json::from_str::<Value>(&text["data: ".len()..]) else {
                return;
            };
            if has_stream_end_shape(&v) {
                assert!(may_hold_stream_end_code(text.as_bytes()), "missed {num}");
            }
        }
        let mut seen = 0;
        for digits in ["32001", "320010", "3200100", "032001", "0032001"] {
            for point in 0..=digits.len() {
                let (a, b) = digits.split_at(point);
                let mantissa = match (a.is_empty(), b.is_empty()) {
                    (true, _) => format!("0.{b}"),
                    (_, true) => a.to_owned(),
                    _ => format!("{a}.{b}"),
                };
                for exp in -12i32..=12 {
                    for e in ["e", "E"] {
                        for sign in ["", "+"] {
                            let n = if exp < 0 {
                                format!("-{mantissa}{e}{exp}")
                            } else {
                                format!("-{mantissa}{e}{sign}{exp}")
                            };
                            check(&n);
                            seen += 1;
                        }
                    }
                }
                check(&format!("-{mantissa}"));
            }
        }
        // Rust's and serde_json's own spellings of the value and its neighbours.
        let x = -32001.0f64;
        for v in [
            x,
            f64::from_bits(x.to_bits() + 1),
            f64::from_bits(x.to_bits() - 1),
        ] {
            check(&format!("{v}"));
            check(&format!("{v:e}"));
            check(&format!("{v:E}"));
            check(&format!("{v:.20}"));
            check(&serde_json::to_string(&v).unwrap());
        }
        // Decimals close to 32001 on either side (a small LCG, fixed seed).
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..20_000 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let off = (state >> 11) as f64 / (1u64 << 53) as f64 * 8e-12 - 4e-12;
            for prec in [10usize, 12, 14, 16, 20] {
                check(&format!("{:.prec$}", -32001.0 + off));
            }
        }
        assert!(seen > 1000);
    }
}
