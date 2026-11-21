//! `attenuo stdio-bridge`: run a local STDIO MCP server as a child process and serve it as a
//! Streamable HTTP MCP endpoint, so the attenuo proxy can list it as an ordinary upstream.
//!
//! The STDIO transport is newline-delimited JSON-RPC: one message per line on the child's
//! stdin and stdout, logging on its stderr (which goes to the bridge's stderr). The bridge
//! is a transport, not a second proxy: it decides nothing about what a call may do.
//!
//! - A `POST` with a request is written to the child as one line, its `id` replaced by a
//!   bridge-unique number (two HTTP callers may use the same id), and answered with the
//!   child's response to that number, the caller's id put back, as `application/json`. No
//!   answer within `--timeout`: a JSON-RPC error with HTTP 504, as the proxy answers an
//!   upstream timeout.
//! - A `POST` with a notification is written to the child and answered `202` with no body.
//!   A `POST` with a response is answered `202` and dropped: the bridge never relays the
//!   child's own requests, so a response can only be unsolicited.
//! - A batch is refused (`400`): MCP 2025-06-18 removed JSON-RPC batching.
//! - `GET` (the listen stream) and `DELETE` (session end) are `405`: the child is one session
//!   and has no server-to-client stream here. The child's notifications are dropped and its
//!   requests (sampling, elicitation, roots, ping) answered with a JSON-RPC error at once, so
//!   it does not wait for an answer that cannot come; both are counted.
//! - `initialize` is forwarded once. A later `initialize` (a second client of the proxy, or
//!   the same one reconnecting) gets the child's first answer, with its own id, and is not
//!   forwarded, and only the first `notifications/initialized` reaches the child: a STDIO
//!   server expects exactly one handshake per process.
//! - A request carrying an `Origin` header is refused (`403`): the proxy sends none, and a
//!   browser always does, which closes DNS rebinding from a web page.
//!
//! Nothing of the child's arguments or environment is logged; only the program name is.

use std::collections::HashMap;
use std::ffi::OsString;
use std::future::IntoFuture;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use serde_json::{json, Map, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::oneshot;

use crate::cli::StdioBridgeArgs;

/// The endpoint path the bridge serves.
pub(crate) const PATH: &str = "/mcp";

/// JSON-RPC: invalid JSON.
const PARSE_ERROR: i64 = -32700;
/// JSON-RPC: not a valid request object.
const INVALID_REQUEST: i64 = -32600;
/// JSON-RPC: method not found (the answer to the child's own requests).
const METHOD_NOT_FOUND: i64 = -32601;
/// JSON-RPC: internal error (the bridge could not get an answer from the child).
const INTERNAL_ERROR: i64 = -32603;

/// How long the child gets to exit after its stdin is closed, before it is killed.
const STOP_GRACE: Duration = Duration::from_secs(2);

/// Prefix of the variables removed from the child's environment: attenuo's own credentials
/// and settings (the CLI's `ATTENUO_ADMIN_TOKEN`, `ATTENUO_TOKEN`, `ATTENUO_CLIENT_SECRET` and
/// `ATTENUO_DPOP_KEY`, the server's `ATTENUO_AUDIT_SINK_TOKEN`,
/// `ATTENUO_APPROVAL_NOTIFY_SECRET` and `ATTENUO__*` overrides such as
/// `ATTENUO__ADMIN__TOKEN`). The STDIO server is an upstream, and upstreams are not trusted
/// with them (SR-134).
const SECRET_ENV_PREFIX: &str = "ATTENUO_";

/// The variables of `vars` that the child must not get: every name that starts with
/// [`SECRET_ENV_PREFIX`].
pub(crate) fn scrubbed_env(vars: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    vars.into_iter()
        .filter(|name| {
            name.as_encoded_bytes()
                .starts_with(SECRET_ENV_PREFIX.as_bytes())
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Line framing
// ---------------------------------------------------------------------------------------------

/// One line of the child's stdout.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Line {
    /// A line within the bound, without its line ending (`\n` or `\r\n`).
    Message(Vec<u8>),
    /// A line over the bound: dropped as it was read, never held whole. `len` is its length.
    TooLong { len: usize },
}

/// Read one `\n`-terminated line of at most `max` bytes (line ending not counted). A longer
/// line is read to its end and dropped, holding no more than `max` bytes of it. A last line
/// without `\n` before end of file counts as a line. `None` at end of file.
pub(crate) async fn read_line_bounded<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max: usize,
) -> io::Result<Option<Line>> {
    let mut line = Vec::new();
    let mut too_long: Option<usize> = None;
    let mut started = false;
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            if !started {
                return Ok(None);
            }
            break;
        }
        started = true;
        let (chunk, used, done) = match buf.iter().position(|b| *b == b'\n') {
            Some(i) => (&buf[..i], i + 1, true),
            None => (buf, buf.len(), false),
        };
        match too_long.as_mut() {
            Some(len) => *len += chunk.len(),
            // `max + 1`: room for a `\r` that the line ending may still strip.
            None if line.len() + chunk.len() > max.saturating_add(1) => {
                too_long = Some(line.len() + chunk.len());
                line = Vec::new();
            }
            None => line.extend_from_slice(chunk),
        }
        reader.consume(used);
        if done {
            break;
        }
    }
    if let Some(len) = too_long {
        return Ok(Some(Line::TooLong { len }));
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    if line.len() > max {
        return Ok(Some(Line::TooLong { len: line.len() }));
    }
    Ok(Some(Line::Message(line)))
}

/// One message as the line written to the child: compact JSON, which never holds a raw
/// newline (serde_json escapes control characters in strings), then `\n`.
pub(crate) fn encode_line(msg: &Value) -> Vec<u8> {
    let mut out = serde_json::to_vec(msg).unwrap_or_default();
    debug_assert!(!out.contains(&b'\n'));
    out.push(b'\n');
    out
}

// ---------------------------------------------------------------------------------------------
// Message kinds and id rewriting
// ---------------------------------------------------------------------------------------------

/// What a message from an HTTP caller is.
#[derive(Debug, PartialEq)]
pub(crate) enum FromCaller {
    /// A request: `method` and an `id` that is a string or a number.
    Request { method: String, id: Value },
    /// A notification: `method` and no `id`.
    Notification { method: String },
    /// A response (`id` and `result` or `error`, no `method`).
    Response,
    /// Anything else, with the reason.
    Invalid(&'static str),
}

/// Classify one message (an object) from an HTTP caller.
pub(crate) fn classify_from_caller(msg: &Value) -> FromCaller {
    let Some(obj) = msg.as_object() else {
        return FromCaller::Invalid("expected a JSON-RPC object");
    };
    match obj.get("method") {
        Some(Value::String(method)) => match obj.get("id") {
            None => FromCaller::Notification {
                method: method.clone(),
            },
            Some(id @ (Value::String(_) | Value::Number(_))) => FromCaller::Request {
                method: method.clone(),
                id: id.clone(),
            },
            Some(_) => FromCaller::Invalid("a request id must be a string or a number"),
        },
        Some(_) => FromCaller::Invalid("method must be a string"),
        None if obj.contains_key("id")
            && (obj.contains_key("result") || obj.contains_key("error")) =>
        {
            FromCaller::Response
        }
        None => FromCaller::Invalid("neither a request, a notification nor a response"),
    }
}

/// What a message from the child is. A message with a `method` is never a response, so a
/// notification or a request of the child that reuses a pending id is not taken for the
/// answer.
#[derive(Debug, PartialEq)]
pub(crate) enum FromChild {
    /// A response, with its `id`.
    Response(Value),
    /// The child's own request (sampling, elicitation, roots, ping).
    Request { method: String, id: Value },
    /// A notification (progress, log message, list changed).
    Notification { method: String },
    /// Not a JSON-RPC message (a batch included: the bridge never sends one).
    Invalid,
}

/// Classify one message from the child.
pub(crate) fn classify_from_child(msg: &Value) -> FromChild {
    let Some(obj) = msg.as_object() else {
        return FromChild::Invalid;
    };
    match (obj.get("method"), obj.get("id")) {
        (Some(Value::String(m)), Some(id)) => FromChild::Request {
            method: m.clone(),
            id: id.clone(),
        },
        (Some(Value::String(m)), None) => FromChild::Notification { method: m.clone() },
        (Some(_), _) => FromChild::Invalid,
        (None, Some(id)) if obj.contains_key("result") || obj.contains_key("error") => {
            FromChild::Response(id.clone())
        }
        (None, _) => FromChild::Invalid,
    }
}

/// Give a caller's request the bridge-unique id `bridge_id`; returns the caller's id.
pub(crate) fn rewrite_id(msg: &mut Map<String, Value>, bridge_id: u64) -> Value {
    msg.insert("id".into(), Value::from(bridge_id))
        .unwrap_or(Value::Null)
}

/// Put the caller's id back on the child's response.
pub(crate) fn restore_id(response: &mut Value, caller_id: Value) {
    if let Some(obj) = response.as_object_mut() {
        obj.insert("id".into(), caller_id);
    }
}

/// The bridge id a child's response carries, if it is one the bridge could have sent.
fn bridge_id_of(id: &Value) -> Option<u64> {
    id.as_u64()
}

/// A JSON-RPC error object.
pub(crate) fn rpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message.into()}})
}

// ---------------------------------------------------------------------------------------------
// The bridge's state
// ---------------------------------------------------------------------------------------------

/// Messages of the child the bridge dropped or answered itself, counted.
#[derive(Debug, Default)]
pub(crate) struct Counts {
    pub notifications: AtomicU64,
    pub child_requests: AtomicU64,
    pub unmatched_responses: AtomicU64,
    pub invalid_lines: AtomicU64,
    pub long_lines: AtomicU64,
    pub caller_responses: AtomicU64,
}

impl Counts {
    fn bump(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    fn summary(&self) -> Option<String> {
        let parts: Vec<String> = [
            (&self.notifications, "notification(s) dropped"),
            (
                &self.child_requests,
                "request(s) of its own answered with an error",
            ),
            (
                &self.unmatched_responses,
                "response(s) nobody waited for dropped",
            ),
            (
                &self.invalid_lines,
                "line(s) that were not JSON-RPC dropped",
            ),
            (&self.long_lines, "line(s) over --max-line-bytes dropped"),
        ]
        .iter()
        .filter_map(|(c, what)| {
            let n = c.load(Ordering::Relaxed);
            (n > 0).then(|| format!("{n} {what}"))
        })
        .collect();
        (!parts.is_empty())
            .then(|| format!("stdio-bridge: from the STDIO server: {}", parts.join(", ")))
    }
}

type Writer = Box<dyn AsyncWrite + Send + Unpin>;

/// One line for the child's stdin, and where to say whether it was written.
type WriteJob = (Vec<u8>, oneshot::Sender<io::Result<()>>);

/// How many lines may wait for the writer.
const WRITE_QUEUE: usize = 256;

/// Write the queued lines to the child's stdin, each whole, in order, until the queue is
/// closed; then close stdin. Only this task writes, and nothing cancels it, so a caller that
/// gives up waiting never leaves half a line behind.
async fn write_child(mut stdin: Writer, mut jobs: tokio::sync::mpsc::Receiver<WriteJob>) {
    while let Some((line, done)) = jobs.recv().await {
        let r = match stdin.write_all(&line).await {
            Ok(()) => stdin.flush().await,
            Err(e) => Err(e),
        };
        let _ = done.send(r);
    }
    let _ = stdin.shutdown().await;
}

/// What the HTTP handlers and the stdout reader share.
pub(crate) struct Bridge {
    /// The queue to [`write_child`]; `None` once the child's stdin is to be closed.
    stdin: Mutex<Option<tokio::sync::mpsc::Sender<WriteJob>>>,
    /// Requests waiting for the child's answer, by bridge id.
    pending: Mutex<HashMap<u64, oneshot::Sender<Value>>>,
    next_id: AtomicU64,
    /// The child's answer to the first successful `initialize`. The lock is held while one
    /// is in flight, so concurrent ones wait for it.
    init: tokio::sync::Mutex<Option<Value>>,
    /// `notifications/initialized` was forwarded.
    initialized_sent: AtomicBool,
    timeout: Duration,
    max_request: usize,
    verbose: bool,
    pub(crate) counts: Counts,
}

/// Removes a pending entry when its request ends, whether it was answered, timed out or the
/// HTTP caller went away.
struct PendingGuard<'a> {
    bridge: &'a Bridge,
    id: u64,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut p) = self.bridge.pending.lock() {
            p.remove(&self.id);
        }
    }
}

impl Bridge {
    /// A bridge writing to `stdin`. Must be called on a Tokio runtime (it starts the writer).
    pub(crate) fn new(stdin: Writer, timeout: Duration, max_request: usize, verbose: bool) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(WRITE_QUEUE);
        tokio::spawn(write_child(stdin, rx));
        Self {
            stdin: Mutex::new(Some(tx)),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            init: tokio::sync::Mutex::new(None),
            initialized_sent: AtomicBool::new(false),
            timeout,
            max_request,
            verbose,
            counts: Counts::default(),
        }
    }

    fn debug(&self, line: impl FnOnce() -> String) {
        if self.verbose {
            errln!("stdio-bridge: {}", line());
        }
    }

    /// Write one message to the child as one line. Once queued the line is written whole
    /// even if this future is dropped (a timeout), so the child may still act on it.
    async fn write(&self, msg: &Value) -> io::Result<()> {
        let closed = || io::Error::new(io::ErrorKind::BrokenPipe, "stdin closed");
        let tx = self
            .stdin
            .lock()
            .ok()
            .and_then(|q| q.clone())
            .ok_or_else(closed)?;
        let (done, written) = oneshot::channel();
        tx.send((encode_line(msg), done))
            .await
            .map_err(|_| closed())?;
        written.await.map_err(|_| closed())?
    }

    /// Close the child's stdin once the queued lines are written (the STDIO way to ask a
    /// server to exit).
    fn close_stdin(&self) {
        if let Ok(mut q) = self.stdin.lock() {
            q.take();
        }
    }

    /// Send a caller's request to the child and wait for its answer: the HTTP status and the
    /// JSON-RPC message to answer with.
    pub(crate) async fn request(
        &self,
        mut msg: Map<String, Value>,
        caller_id: Value,
    ) -> (StatusCode, Value) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        rewrite_id(&mut msg, id);
        let (tx, rx) = oneshot::channel();
        match self.pending.lock() {
            Ok(mut p) => {
                p.insert(id, tx);
            }
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    rpc_error(caller_id, INTERNAL_ERROR, "stdio-bridge: internal error"),
                )
            }
        }
        let _guard = PendingGuard { bridge: self, id };
        let deadline = tokio::time::Instant::now() + self.timeout;
        let timed_out = || {
            (
                StatusCode::GATEWAY_TIMEOUT,
                rpc_error(
                    caller_id.clone(),
                    INTERNAL_ERROR,
                    format!(
                        "stdio-bridge: no answer from the STDIO server within {} s",
                        self.timeout.as_secs()
                    ),
                ),
            )
        };
        let gone = || {
            (
                StatusCode::BAD_GATEWAY,
                rpc_error(
                    caller_id.clone(),
                    INTERNAL_ERROR,
                    "stdio-bridge: the STDIO server is gone",
                ),
            )
        };
        match tokio::time::timeout_at(deadline, self.write(&Value::Object(msg))).await {
            Err(_) => return timed_out(),
            Ok(Err(_)) => return gone(),
            Ok(Ok(())) => {}
        }
        match tokio::time::timeout_at(deadline, rx).await {
            Ok(Ok(mut response)) => {
                restore_id(&mut response, caller_id.clone());
                (StatusCode::OK, response)
            }
            Ok(Err(_)) => gone(),
            Err(_) => timed_out(),
        }
    }

    /// Hand a child's response to the request waiting for it. `false` when none is.
    fn deliver(&self, id: &Value, response: Value) -> bool {
        let tx = bridge_id_of(id).and_then(|n| self.pending.lock().ok()?.remove(&n));
        match tx {
            Some(tx) => tx.send(response).is_ok(),
            None => false,
        }
    }

    /// The child's stdout ended: fail every waiting request now.
    fn fail_pending(&self) {
        if let Ok(mut p) = self.pending.lock() {
            p.clear();
        }
    }

    /// Answer one HTTP `POST`.
    async fn post(&self, headers: &HeaderMap, body: Body) -> Response {
        if let Some(ct) = headers.get(header::CONTENT_TYPE) {
            let ct = ct.to_str().unwrap_or_default().trim_start();
            if !ct.to_ascii_lowercase().starts_with("application/json") {
                return reply(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    rpc_error(
                        Value::Null,
                        INVALID_REQUEST,
                        "stdio-bridge: Content-Type must be application/json",
                    ),
                );
            }
        }
        let Ok(bytes) = to_bytes(body, self.max_request).await else {
            return reply(
                StatusCode::PAYLOAD_TOO_LARGE,
                rpc_error(
                    Value::Null,
                    INVALID_REQUEST,
                    format!(
                        "stdio-bridge: request body larger than {} bytes",
                        self.max_request
                    ),
                ),
            );
        };
        let msg: Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => {
                return reply(
                    StatusCode::BAD_REQUEST,
                    rpc_error(Value::Null, PARSE_ERROR, "stdio-bridge: parse error"),
                )
            }
        };
        if msg.is_array() {
            return reply(
                StatusCode::BAD_REQUEST,
                rpc_error(
                    Value::Null,
                    INVALID_REQUEST,
                    "stdio-bridge: JSON-RPC batches are not supported; send one message per request",
                ),
            );
        }
        match classify_from_caller(&msg) {
            FromCaller::Invalid(why) => reply(
                StatusCode::BAD_REQUEST,
                rpc_error(
                    msg.get("id").cloned().unwrap_or(Value::Null),
                    INVALID_REQUEST,
                    format!("stdio-bridge: invalid request: {why}"),
                ),
            ),
            FromCaller::Response => {
                Counts::bump(&self.counts.caller_responses);
                self.debug(|| "dropped a response from a caller: nothing asked for it".into());
                accepted()
            }
            FromCaller::Notification { method } => {
                if method == "notifications/initialized"
                    && self.initialized_sent.swap(true, Ordering::SeqCst)
                {
                    self.debug(|| "dropped a repeated notifications/initialized".into());
                    return accepted();
                }
                let deadline = tokio::time::Instant::now() + self.timeout;
                match tokio::time::timeout_at(deadline, self.write(&msg)).await {
                    Ok(Ok(())) => accepted(),
                    Ok(Err(_)) => reply(
                        StatusCode::BAD_GATEWAY,
                        rpc_error(
                            Value::Null,
                            INTERNAL_ERROR,
                            "stdio-bridge: the STDIO server is gone",
                        ),
                    ),
                    Err(_) => reply(
                        StatusCode::GATEWAY_TIMEOUT,
                        rpc_error(
                            Value::Null,
                            INTERNAL_ERROR,
                            "stdio-bridge: the STDIO server does not read its input",
                        ),
                    ),
                }
            }
            FromCaller::Request { method, id } => {
                let Value::Object(obj) = msg else {
                    unreachable!("classified as a request")
                };
                if method == "initialize" {
                    return self.initialize(obj, id).await;
                }
                let (status, body) = self.request(obj, id).await;
                reply(status, body)
            }
        }
    }

    /// `initialize`: forwarded the first time it succeeds, answered from that answer after.
    async fn initialize(&self, msg: Map<String, Value>, caller_id: Value) -> Response {
        let mut init = self.init.lock().await;
        if let Some(result) = init.as_ref() {
            self.debug(|| "answered a repeated initialize with the first handshake".into());
            return reply(
                StatusCode::OK,
                json!({"jsonrpc": "2.0", "id": caller_id, "result": result}),
            );
        }
        let (status, body) = self.request(msg, caller_id).await;
        if status == StatusCode::OK {
            if let Some(result) = body.get("result") {
                *init = Some(result.clone());
            }
        }
        reply(status, body)
    }

    /// Handle one line of the child's stdout.
    fn on_line(self: &Arc<Self>, line: Line) {
        let bytes = match line {
            Line::TooLong { len } => {
                Counts::bump(&self.counts.long_lines);
                errln!(
                    "stdio-bridge: dropped a {len}-byte line from the STDIO server (over \
                     --max-line-bytes)"
                );
                return;
            }
            Line::Message(b) => b,
        };
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return;
        }
        let Ok(msg) = serde_json::from_slice::<Value>(&bytes) else {
            Counts::bump(&self.counts.invalid_lines);
            errln!("stdio-bridge: dropped a line from the STDIO server that is not JSON");
            return;
        };
        match classify_from_child(&msg) {
            FromChild::Response(id) => {
                if !self.deliver(&id, msg) {
                    Counts::bump(&self.counts.unmatched_responses);
                    self.debug(|| format!("dropped a response to {id}: no request waits for it"));
                }
            }
            FromChild::Notification { method } => {
                Counts::bump(&self.counts.notifications);
                self.debug(|| format!("dropped a notification from the STDIO server: {method}"));
            }
            FromChild::Request { method, id } => {
                Counts::bump(&self.counts.child_requests);
                self.debug(|| {
                    format!("answered a request of the STDIO server with an error: {method}")
                });
                // Not on the reader: a child that does not read its stdin while its stdout
                // is unread would block both.
                let bridge = self.clone();
                tokio::spawn(async move {
                    let err = rpc_error(
                        id,
                        METHOD_NOT_FOUND,
                        "attenuo stdio-bridge does not relay server-to-client requests",
                    );
                    let _ = tokio::time::timeout(bridge.timeout, bridge.write(&err)).await;
                });
            }
            FromChild::Invalid => {
                Counts::bump(&self.counts.invalid_lines);
                errln!(
                    "stdio-bridge: dropped a line from the STDIO server that is not a JSON-RPC \
                     message"
                );
            }
        }
    }
}

/// Read the child's stdout until it ends.
pub(crate) async fn read_child<R: AsyncBufRead + Unpin>(
    bridge: Arc<Bridge>,
    mut reader: R,
    max_line: usize,
) {
    loop {
        match read_line_bounded(&mut reader, max_line).await {
            Ok(Some(line)) => bridge.on_line(line),
            Ok(None) => break,
            Err(e) => {
                errln!("stdio-bridge: reading the STDIO server's output failed: {e}");
                break;
            }
        }
    }
    bridge.fail_pending();
}

fn reply(status: StatusCode, body: Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn accepted() -> Response {
    StatusCode::ACCEPTED.into_response()
}

async fn handle_post(State(bridge): State<Arc<Bridge>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    if parts.headers.contains_key(header::ORIGIN) {
        return reply(
            StatusCode::FORBIDDEN,
            rpc_error(
                Value::Null,
                INVALID_REQUEST,
                "stdio-bridge: requests with an Origin header are refused",
            ),
        );
    }
    bridge.post(&parts.headers, body).await
}

/// The HTTP side: `POST /mcp`; any other method there is `405` (axum's answer, with `Allow`).
pub(crate) fn router(bridge: Arc<Bridge>) -> Router {
    Router::new()
        .route(PATH, post(handle_post))
        .with_state(bridge)
}

// ---------------------------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------------------------

/// Refuse a non-loopback address unless allowed.
pub(crate) fn check_listen(addr: SocketAddr, allow_non_loopback: bool) -> Result<()> {
    if !addr.ip().is_loopback() && !allow_non_loopback {
        bail!(
            "--listen {addr} is not a loopback address. The bridge does not authenticate its \
             callers, so anyone who can reach it calls the STDIO server without attenuo. Use \
             127.0.0.1 or [::1], or pass --allow-non-loopback if a firewall keeps everyone \
             but the attenuo proxy away from it"
        );
    }
    Ok(())
}

/// Resolve on SIGINT or SIGTERM.
pub(crate) async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).ok();
        let term = async {
            match term.as_mut() {
                Some(t) => {
                    t.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            () = term => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// `attenuo stdio-bridge`: `Ok` when stopped by a signal, an error when the child cannot be
/// started or ends.
pub(crate) async fn run(args: StdioBridgeArgs) -> Result<()> {
    check_listen(args.listen, args.allow_non_loopback)?;
    let (program, child_args): (&OsString, &[OsString]) = args
        .command
        .split_first()
        .context("stdio-bridge needs the STDIO server's command after --")?;
    let name = program.to_string_lossy().into_owned();
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("cannot listen on {}", args.listen))?;
    let addr = listener.local_addr()?;

    let mut cmd = tokio::process::Command::new(program);
    cmd.args(child_args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true);
    for var in scrubbed_env(std::env::vars_os().map(|(name, _)| name)) {
        cmd.env_remove(var);
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("cannot start the STDIO server `{name}`"))?;
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        bail!("the STDIO server `{name}` was started without pipes");
    };
    let max_request = usize::try_from(args.max_request_bytes).unwrap_or(usize::MAX);
    let max_line = usize::try_from(args.max_line_bytes).unwrap_or(usize::MAX);
    let bridge = Arc::new(Bridge::new(
        Box::new(stdin),
        Duration::from_secs(args.timeout),
        max_request,
        args.verbose,
    ));
    let mut reader = tokio::spawn(read_child(bridge.clone(), BufReader::new(stdout), max_line));
    let server = axum::serve(listener, router(bridge.clone()));

    outln!("listening on http://{addr}{PATH}")?;
    errln!(
        "stdio-bridge: serving the STDIO server `{name}` (pid {}) on http://{addr}{PATH}",
        child.id().map_or_else(|| "?".into(), |p| p.to_string())
    );

    let outcome = tokio::select! {
        r = server.into_future() => Err(match r {
            Ok(()) => anyhow::anyhow!("the HTTP listener stopped"),
            Err(e) => anyhow::anyhow!("the HTTP listener failed: {e}"),
        }),
        status = child.wait() => Err(match status {
            Ok(s) => anyhow::anyhow!("the STDIO server `{name}` exited ({s})"),
            Err(e) => anyhow::anyhow!("waiting for the STDIO server `{name}` failed: {e}"),
        }),
        _ = &mut reader => Err(anyhow::anyhow!(
            "the STDIO server `{name}` closed its standard output"
        )),
        () = stop_signal() => Ok(()),
    };
    stop_child(&bridge, &mut child).await;
    if let Some(line) = bridge.counts.summary() {
        errln!("{line}");
    }
    reader.abort();
    outcome
}

/// Stop the child: close its stdin, give it [`STOP_GRACE`] to exit, then kill it.
async fn stop_child(bridge: &Bridge, child: &mut tokio::process::Child) {
    bridge.close_stdin();
    if let Ok(Ok(_)) = tokio::time::timeout(STOP_GRACE, child.wait()).await {
        return;
    }
    let _ = child.kill().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn lines(input: &[u8], max: usize) -> Vec<Line> {
        // A tiny buffer, so lines cross `fill_buf` boundaries.
        let mut r = BufReader::with_capacity(3, input);
        let mut out = Vec::new();
        while let Some(l) = read_line_bounded(&mut r, max).await.unwrap() {
            out.push(l);
        }
        out
    }

    fn msg(s: &str) -> Line {
        Line::Message(s.as_bytes().to_vec())
    }

    #[tokio::test]
    async fn lines_are_split_on_newline_and_lose_their_line_ending() {
        let got = lines(b"{\"a\":1}\n{\"b\":2}\r\n\nlast", 64).await;
        assert_eq!(
            got,
            vec![msg("{\"a\":1}"), msg("{\"b\":2}"), msg(""), msg("last")]
        );
        assert!(lines(b"", 64).await.is_empty());
    }

    #[tokio::test]
    async fn a_line_over_the_bound_is_dropped_and_the_next_one_is_read() {
        let got = lines(b"0123456789\nok\n0123\n01234\r\n", 4).await;
        assert_eq!(
            got,
            vec![
                Line::TooLong { len: 10 },
                msg("ok"),
                msg("0123"),
                // The length counts the `\r` that a kept line would lose.
                Line::TooLong { len: 6 },
            ]
        );
        // Exactly at the bound with `\r\n`: kept.
        assert_eq!(lines(b"0123\r\n", 4).await, vec![msg("0123")]);
        // Over the bound without a final newline.
        assert_eq!(lines(b"0123456", 4).await, vec![Line::TooLong { len: 7 }]);
    }

    #[test]
    fn an_encoded_message_is_one_line_whatever_its_strings_hold() {
        let v = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"arguments": {"text": "a\nb\r\nc\u{2028}"}}});
        let line = encode_line(&v);
        assert_eq!(line.iter().filter(|b| **b == b'\n').count(), 1);
        assert_eq!(line.last(), Some(&b'\n'));
        let back: Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn ids_are_rewritten_and_restored() {
        let mut m = json!({"jsonrpc": "2.0", "id": "abc", "method": "ping"})
            .as_object()
            .cloned()
            .unwrap();
        let old = rewrite_id(&mut m, 42);
        assert_eq!(old, json!("abc"));
        assert_eq!(m["id"], json!(42));
        let mut resp = json!({"jsonrpc": "2.0", "id": 42, "result": {}});
        restore_id(&mut resp, old);
        assert_eq!(resp, json!({"jsonrpc": "2.0", "id": "abc", "result": {}}));
        assert_eq!(bridge_id_of(&json!(42)), Some(42));
        assert_eq!(bridge_id_of(&json!("42")), None);
        assert_eq!(bridge_id_of(&json!(-1)), None);
    }

    #[test]
    fn caller_messages_are_classified() {
        use FromCaller::*;
        let c = |v: Value| classify_from_caller(&v);
        assert_eq!(
            c(json!({"jsonrpc":"2.0","id":7,"method":"tools/list"})),
            Request {
                method: "tools/list".into(),
                id: json!(7)
            }
        );
        assert_eq!(
            c(json!({"jsonrpc":"2.0","method":"notifications/initialized"})),
            Notification {
                method: "notifications/initialized".into()
            }
        );
        assert_eq!(c(json!({"jsonrpc":"2.0","id":7,"result":{}})), Response);
        assert_eq!(c(json!({"jsonrpc":"2.0","id":7,"error":{}})), Response);
        assert!(matches!(
            c(json!({"jsonrpc":"2.0","id":null,"method":"x"})),
            Invalid(_)
        ));
        assert!(matches!(
            c(json!({"jsonrpc":"2.0","id":{},"method":"x"})),
            Invalid(_)
        ));
        assert!(matches!(c(json!({"jsonrpc":"2.0","method":1})), Invalid(_)));
        assert!(matches!(c(json!({"jsonrpc":"2.0","id":1})), Invalid(_)));
        assert!(matches!(c(json!("x")), Invalid(_)));
    }

    #[test]
    fn a_child_message_with_a_method_is_never_a_response() {
        use FromChild::*;
        let c = |v: Value| classify_from_child(&v);
        assert_eq!(
            c(json!({"jsonrpc":"2.0","id":1,"result":{}})),
            Response(json!(1))
        );
        // A notification that carries `result` and the pending id is still a notification.
        assert_eq!(
            c(json!({"jsonrpc":"2.0","method":"notifications/progress","result":{}})),
            Notification {
                method: "notifications/progress".into()
            }
        );
        // A request of the child that reuses a pending id is a request.
        assert_eq!(
            c(json!({"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","result":{}})),
            Request {
                method: "sampling/createMessage".into(),
                id: json!(1)
            }
        );
        assert_eq!(c(json!([{"jsonrpc":"2.0","id":1,"result":{}}])), Invalid);
        assert_eq!(c(json!({"jsonrpc":"2.0","id":1})), Invalid);
    }

    #[test]
    fn every_attenuo_variable_is_scrubbed_sr134() {
        let names = [
            "ATTENUO_ADMIN_TOKEN",
            "ATTENUO_TOKEN",
            "ATTENUO_CLIENT_SECRET",
            "ATTENUO_DPOP_KEY",
            "ATTENUO_AUDIT_SINK_TOKEN",
            "ATTENUO_APPROVAL_NOTIFY_SECRET",
            "ATTENUO__ADMIN__TOKEN",
            "ATTENUO__AUDIT__SINK__BEARER_TOKEN",
            "GITHUB_TOKEN",
            "PATH",
            "attenuo_token",
            "XATTENUO_TOKEN",
        ];
        let got = scrubbed_env(names.iter().map(OsString::from));
        assert_eq!(
            got,
            names[..8].iter().map(OsString::from).collect::<Vec<_>>()
        );
    }

    #[test]
    fn only_loopback_is_accepted_without_the_flag() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert!(check_listen(a("127.0.0.1:3001"), false).is_ok());
        assert!(check_listen(a("[::1]:3001"), false).is_ok());
        let err = check_listen(a("0.0.0.0:3001"), false).unwrap_err();
        assert!(err.to_string().contains("--allow-non-loopback"), "{err}");
        assert!(check_listen(a("0.0.0.0:3001"), true).is_ok());
    }

    /// A bridge whose "child" is in this process: what it writes to the child, and a way to
    /// answer as the child.
    fn in_process(
        timeout: Duration,
    ) -> (
        Arc<Bridge>,
        BufReader<tokio::io::DuplexStream>,
        tokio::io::DuplexStream,
    ) {
        let (to_child, child_in) = tokio::io::duplex(1 << 16);
        let (child_out, from_child) = tokio::io::duplex(1 << 16);
        let bridge = Arc::new(Bridge::new(Box::new(to_child), timeout, 1 << 20, false));
        tokio::spawn(read_child(bridge.clone(), BufReader::new(from_child), 1024));
        (bridge, BufReader::new(child_in), child_out)
    }

    async fn next_written(r: &mut BufReader<tokio::io::DuplexStream>) -> Value {
        match read_line_bounded(r, 1 << 20).await.unwrap().unwrap() {
            Line::Message(b) => serde_json::from_slice(&b).unwrap(),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn answers_reach_their_caller_whatever_the_order_and_a_notification_with_the_id_does_not()
    {
        let (bridge, mut child_in, mut child_out) = in_process(Duration::from_secs(5));
        let call = |n: u64| {
            let b = bridge.clone();
            tokio::spawn(async move {
                let m = json!({"jsonrpc":"2.0","id":1,"method":"echo","params":{"n":n}});
                b.request(m.as_object().cloned().unwrap(), json!(1)).await
            })
        };
        let first = call(10);
        let second = call(20);
        let a = next_written(&mut child_in).await;
        let b = next_written(&mut child_in).await;
        assert_ne!(
            a["id"], b["id"],
            "the same caller id becomes two bridge ids"
        );
        // The child sends a notification that looks like an answer and a request carrying a
        // pending id, then answers in reverse order.
        for line in [
            json!({"jsonrpc":"2.0","method":"notifications/progress",
                   "params":{"progressToken":a["id"]},"result":{"n":0}}),
            json!({"jsonrpc":"2.0","id":a["id"],"method":"ping"}),
            json!({"jsonrpc":"2.0","id":b["id"],"result":{"n":b["params"]["n"]}}),
            json!({"jsonrpc":"2.0","id":a["id"],"result":{"n":a["params"]["n"]}}),
        ] {
            child_out.write_all(&encode_line(&line)).await.unwrap();
        }
        let (s1, r1) = first.await.unwrap();
        let (s2, r2) = second.await.unwrap();
        assert_eq!(s1, StatusCode::OK);
        assert_eq!(s2, StatusCode::OK);
        assert_eq!(r1, json!({"jsonrpc":"2.0","id":1,"result":{"n":10}}));
        assert_eq!(r2, json!({"jsonrpc":"2.0","id":1,"result":{"n":20}}));
        // The child's request got an error answer of its own.
        let err = next_written(&mut child_in).await;
        assert_eq!(err["id"], a["id"]);
        assert_eq!(err["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(bridge.counts.notifications.load(Ordering::Relaxed), 1);
        assert_eq!(bridge.counts.child_requests.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn no_answer_in_time_is_a_504_and_a_late_answer_is_dropped() {
        let (bridge, mut child_in, mut child_out) = in_process(Duration::from_millis(200));
        let m = json!({"jsonrpc":"2.0","id":"x","method":"slow"});
        let (status, body) = bridge
            .request(m.as_object().cloned().unwrap(), json!("x"))
            .await;
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(body["id"], "x");
        assert_eq!(body["error"]["code"], INTERNAL_ERROR);
        assert!(bridge.pending.lock().unwrap().is_empty());
        let sent = next_written(&mut child_in).await;
        child_out
            .write_all(&encode_line(
                &json!({"jsonrpc":"2.0","id":sent["id"],"result":{}}),
            ))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(bridge.counts.unmatched_responses.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_write_given_up_on_still_leaves_whole_lines() {
        // A child that reads nothing yet: a pipe of 16 bytes fills at once.
        let (to_child, child_in) = tokio::io::duplex(16);
        let bridge = Bridge::new(Box::new(to_child), Duration::from_secs(5), 1 << 20, false);
        let big = json!({"jsonrpc":"2.0","method":"n","params":{"t":"x".repeat(100)}});
        let given_up = tokio::time::timeout(Duration::from_millis(50), bridge.write(&big)).await;
        assert!(
            given_up.is_err(),
            "the write cannot finish while nothing reads"
        );
        let small = json!({"jsonrpc":"2.0","method":"m"});
        let next = tokio::spawn(async move {
            bridge.write(&small).await.unwrap();
            bridge
        });
        let mut r = BufReader::new(child_in);
        assert_eq!(next_written(&mut r).await, big);
        assert_eq!(next_written(&mut r).await["method"], "m");
        next.await.unwrap();
    }

    #[tokio::test]
    async fn a_closed_stdout_fails_waiting_requests_at_once() {
        let (bridge, mut child_in, child_out) = in_process(Duration::from_secs(30));
        let b = bridge.clone();
        let call = tokio::spawn(async move {
            let m = json!({"jsonrpc":"2.0","id":3,"method":"x"});
            b.request(m.as_object().cloned().unwrap(), json!(3)).await
        });
        next_written(&mut child_in).await;
        drop(child_out);
        let (status, body) = tokio::time::timeout(Duration::from_secs(5), call)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["id"], 3);
    }
}
