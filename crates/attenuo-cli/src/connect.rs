//! `attenuo connect`: a STDIO front for desktop MCP clients.
//!
//! A desktop client (Claude Desktop, Claude Code, Cursor) starts this as a command and speaks
//! MCP to it over STDIO: newline-delimited JSON-RPC, one message per line. Each message is
//! sent to the proxy at `<--server>/mcp/<--upstream>` as a Streamable HTTP `POST`, with a
//! fresh delegation token as the bearer, and what comes back is written to stdout, one
//! message per line. The connector is a transport. It decides nothing, and it adds no
//! authority: it sends the token it was given, to `--server` only.
//!
//! - **stdout carries MCP messages only.** One writer task writes them, each line whole.
//!   Everything else (logs, warnings) goes to stderr.
//! - **Tokens.** From `--token-command` (run again whenever a new token is needed), from
//!   `--token-file` (read again), or from `ATTENUO_TOKEN` (used as it is). A new token is
//!   fetched when two thirds of the current one's lifetime have passed, and at once when the
//!   proxy answers 401; the request that got the 401 is sent once more with the new token,
//!   and never more than once. The token and the command's arguments are never logged.
//! - **Lease.** `POST /token/renew` once when a token is new, then at a third of the
//!   `expires_in` it answers. A renewal refused with `lease_revoked` is final: renewal
//!   stops, no new token is fetched, and calls fail as the proxy answers them.
//! - **Requests** may be in flight together, up to `--max-in-flight`; stdin is not held up
//!   by a slow call. `initialize` and notifications are sent in the order they are read.
//!   A request that gets no answer (the network, a timeout, an HTTP error without a JSON-RPC
//!   body, no token) is answered with a JSON-RPC error with its id. The proxy's own JSON-RPC
//!   errors are passed on as they came; when one has `"id": null` (the proxy refused the
//!   request before reading it), the request's id is put in, so the client can match it.
//! - **Listen stream.** After `notifications/initialized`, a `GET` opens the server-to-client
//!   stream. `405` (the upstream has none) ends it quietly. Its requests and notifications are
//!   written to stdout; it is opened again, with a growing pause, when it ends.
//! - **End.** At end of stdin, or SIGINT or SIGTERM: stop reading, give requests in flight
//!   [`STOP_GRACE`] to finish, end the MCP session with `DELETE`, exit 0.
//!
//! Nothing that comes from the proxy or the upstream is run, and none of it is logged.

use std::io::{BufRead, Read};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::JoinSet;

use crate::cli::ConnectArgs;
use crate::client::stable_code;
use crate::init_cmd::header_safe;
use crate::render::escape_controls;
use crate::sse::{event_end, parse_event};
use crate::stdio_bridge::{
    classify_from_caller, encode_line, rpc_error, stop_signal, FromCaller, Line,
};

/// JSON-RPC: invalid JSON.
const PARSE_ERROR: i64 = -32700;
/// JSON-RPC: not a valid request object.
const INVALID_REQUEST: i64 = -32600;
/// JSON-RPC: internal error (the connector could not get an answer).
const INTERNAL_ERROR: i64 = -32603;

/// How long requests in flight may still take once input has ended.
const STOP_GRACE: Duration = Duration::from_secs(5);
/// How long a notification (or a response to the server) may take to be accepted. They are
/// sent in order, so a slow one holds up the next lines.
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout of a lease renewal and of the `DELETE` at the end.
const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout of opening a TCP (and TLS) connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest pause between two tries of something that failed.
pub(crate) const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Longest token accepted, in bytes.
const MAX_TOKEN: usize = 16 * 1024;
/// Most bytes read from the token command or the token file.
const MAX_TOKEN_SOURCE: u64 = 64 * 1024;
/// Most bytes read from a renewal answer.
const MAX_RENEW_ANSWER: usize = 64 * 1024;
/// Lines that may wait for the stdout writer.
const OUT_QUEUE: usize = 32;

// ---------------------------------------------------------------------------------------------
// The token command, split into words
// ---------------------------------------------------------------------------------------------

/// Split `s` into words as a POSIX shell would, without expanding anything: whitespace
/// separates words, `'...'` keeps everything as it is, `"..."` keeps everything but a
/// backslash before `"`, `\`, `$` or a backtick, and a backslash outside quotes keeps the next
/// character. The error never repeats the text, which may hold a secret.
pub(crate) fn split_command(s: &str) -> Result<Vec<String>, &'static str> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => word.push(c),
                        None => return Err("a single quote is not closed"),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(c @ ('"' | '\\' | '$' | '`')) => word.push(c),
                            Some('\n') => {}
                            Some(c) => {
                                word.push('\\');
                                word.push(c);
                            }
                            None => return Err("a double quote is not closed"),
                        },
                        Some(c) => word.push(c),
                        None => return Err("a double quote is not closed"),
                    }
                }
            }
            '\\' => match chars.next() {
                Some('\n') => {}
                Some(c) => {
                    in_word = true;
                    word.push(c);
                }
                None => return Err("it ends with a backslash"),
            },
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }
    if in_word {
        words.push(word);
    }
    if words.is_empty() {
        return Err("it is empty");
    }
    Ok(words)
}

// ---------------------------------------------------------------------------------------------
// Where tokens come from
// ---------------------------------------------------------------------------------------------

/// Where the delegation token comes from.
#[derive(Debug)]
enum Source {
    /// `--token-command`: run it, take the first line of its stdout.
    Command {
        program: String,
        args: Vec<String>,
        timeout: Duration,
    },
    /// `--token-file`: the first line of the file.
    File(PathBuf),
    /// `ATTENUO_TOKEN`, as it is: never replaced.
    Env,
}

impl Source {
    fn from_args(args: &ConnectArgs) -> Result<Self> {
        if let Some(cmd) = &args.token_command {
            let mut words = split_command(cmd)
                .map_err(|why| anyhow!("--token-command cannot be split into words: {why}"))?;
            let program = words.remove(0);
            return Ok(Source::Command {
                program,
                args: words,
                timeout: Duration::from_secs(args.token_command_timeout),
            });
        }
        if let Some(path) = &args.token_file {
            return Ok(Source::File(path.clone()));
        }
        Ok(Source::Env)
    }

    /// Whether a new token can be had from it.
    fn refreshable(&self) -> bool {
        !matches!(self, Source::Env)
    }

    /// What to call it in messages: the program name or the path, never the arguments.
    fn describe(&self) -> String {
        match self {
            Source::Command { program, .. } => format!("the token command `{program}`"),
            Source::File(p) => format!("the token file {}", p.display()),
            Source::Env => crate::secrets::TOKEN_ENV.to_string(),
        }
    }

    /// Get a token. No error message holds the token or the command's arguments.
    async fn fetch(&self) -> Result<String> {
        let text = match self {
            Source::Command {
                program,
                args,
                timeout,
            } => run_token_command(program, args, *timeout).await?,
            Source::File(path) => {
                let f = std::fs::File::open(path)
                    .with_context(|| format!("cannot open the token file {}", path.display()))?;
                let mut text = String::new();
                f.take(MAX_TOKEN_SOURCE)
                    .read_to_string(&mut text)
                    .with_context(|| format!("cannot read the token file {}", path.display()))?;
                text
            }
            Source::Env => std::env::var(crate::secrets::TOKEN_ENV).unwrap_or_default(),
        };
        let token = text.lines().next().unwrap_or("").trim().to_string();
        check_token(&token)
            .map_err(|why| anyhow!("{} gave no usable token: {why}", self.describe()))?;
        Ok(token)
    }
}

/// Run the token command and return its stdout. Its stdin is empty (ours carries MCP), its
/// stderr is ours, its environment is ours.
async fn run_token_command(program: &str, args: &[String], timeout: Duration) -> Result<String> {
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| anyhow!("cannot start the token command `{program}`: {e}"))?;
    let Some(stdout) = child.stdout.take() else {
        bail!("the token command `{program}` was started without a pipe");
    };
    let work = async {
        let mut out = Vec::new();
        stdout.take(MAX_TOKEN_SOURCE).read_to_end(&mut out).await?;
        let status = child.wait().await?;
        Ok::<_, std::io::Error>((out, status))
    };
    match tokio::time::timeout(timeout, work).await {
        Err(_) => {
            let _ = child.kill().await;
            bail!(
                "the token command `{program}` did not finish within {} s (--token-command-timeout)",
                timeout.as_secs()
            )
        }
        Ok(Err(e)) => bail!("running the token command `{program}` failed: {e}"),
        Ok(Ok((_, status))) if !status.success() => {
            bail!("the token command `{program}` failed ({status})")
        }
        Ok(Ok((out, _))) => Ok(String::from_utf8_lossy(&out).into_owned()),
    }
}

/// A token can go in an `Authorization` header: visible ASCII, not empty, bounded.
fn check_token(token: &str) -> Result<(), String> {
    if token.is_empty() {
        return Err("the first line is empty".into());
    }
    if token.len() > MAX_TOKEN {
        return Err(format!("it is longer than {MAX_TOKEN} bytes"));
    }
    if !token.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err("it holds spaces or characters that cannot go in a header".into());
    }
    Ok(())
}

/// The token's `exp` (Unix seconds), read without checking the signature, and whether it is
/// bound to a DPoP key. `None` for a token that is not an attenuo JWT.
fn token_meta(token: &str) -> (Option<i64>, bool) {
    match crate::jwt::decode_unverified(token) {
        Ok(d) => (Some(d.claims.exp), d.claims.cnf.is_some()),
        Err(_) => (None, false),
    }
}

fn now_ms() -> i64 {
    i64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .unwrap_or(i64::MAX)
}

// ---------------------------------------------------------------------------------------------
// When to do what (pure, so it can be tested without waiting)
// ---------------------------------------------------------------------------------------------

/// The pause after `failures` failures in a row: 1 s, 2 s, 4 s, ... up to [`MAX_BACKOFF`].
pub(crate) fn backoff(failures: u32) -> Duration {
    let secs = 1u64 << failures.saturating_sub(1).min(5);
    Duration::from_secs(secs).min(MAX_BACKOFF)
}

/// When a token fetched at `fetched_ms` (Unix milliseconds) that expires at `exp` (Unix
/// seconds) should be replaced: after two thirds of its lifetime. A token that has already
/// expired is due now. `None` when its expiry is unknown.
pub(crate) fn refresh_time(fetched_ms: i64, exp: Option<i64>) -> Option<i64> {
    let exp_ms = exp?.saturating_mul(1000);
    let life = exp_ms.saturating_sub(fetched_ms);
    if life <= 0 {
        return Some(fetched_ms);
    }
    Some(fetched_ms.saturating_add(life / 3 * 2))
}

/// How long after a renewal that answered `expires_in` (seconds) to renew again: a third of
/// it, and at least a second.
pub(crate) fn renew_delay(expires_in: i64) -> Duration {
    let ms = u64::try_from(expires_in.saturating_mul(1000) / 3).unwrap_or(0);
    Duration::from_millis(ms).max(Duration::from_secs(1))
}

/// The two things the background task waits for, as Unix milliseconds.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Timers {
    /// When to get a new token; `None` when no new token is to be fetched.
    pub refresh_at: Option<i64>,
    /// When to renew the lease; `None` when renewal has stopped.
    pub renew_at: Option<i64>,
}

/// What the background task does next.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Next {
    /// Get a new token.
    Refresh,
    /// Renew the lease.
    Renew,
    /// Nothing is due: wait for a new token.
    Idle,
}

/// The next thing to do at `now` and how long to wait for it. When both are due, the new
/// token comes first: it has a new lease of its own.
pub(crate) fn next(now: i64, t: &Timers) -> (Next, Duration) {
    let wait = |at: i64| Duration::from_millis(u64::try_from(at.saturating_sub(now)).unwrap_or(0));
    match (t.refresh_at, t.renew_at) {
        (None, None) => (Next::Idle, Duration::ZERO),
        (Some(r), None) => (Next::Refresh, wait(r)),
        (None, Some(n)) => (Next::Renew, wait(n)),
        (Some(r), Some(n)) if r <= n => (Next::Refresh, wait(r)),
        (Some(_), Some(n)) => (Next::Renew, wait(n)),
    }
}

/// What a renewal's answer means.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Renewal {
    /// Renewed; renew again at a third of `expires_in` seconds.
    Renewed { expires_in: i64 },
    /// `lease_revoked`: final. Stop renewing and fetching tokens.
    Revoked,
    /// The lease has expired or is unknown: only a new token (with a new lease) helps.
    NeedToken,
    /// Anything else: try again later. The text says why, for the log.
    Retry(String),
}

/// Sort the answer to `POST /token/renew`.
pub(crate) fn classify_renewal(status: u16, body: &str) -> Renewal {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    if (200..300).contains(&status) {
        return match v.get("expires_in").and_then(Value::as_i64) {
            Some(n) => Renewal::Renewed { expires_in: n },
            None => Renewal::Retry(format!("HTTP {status} without expires_in")),
        };
    }
    match (status, stable_code(&v)) {
        (400, Some("lease_revoked")) => Renewal::Revoked,
        (400, Some("lease_expired" | "lease_unknown")) => Renewal::NeedToken,
        (_, Some(code)) => Renewal::Retry(format!("HTTP {status} ({})", escape_controls(code))),
        (_, None) => Renewal::Retry(format!("HTTP {status}")),
    }
}

// ---------------------------------------------------------------------------------------------
// The current token
// ---------------------------------------------------------------------------------------------

/// One token and what is known about it.
#[derive(Clone)]
struct Current {
    token: Arc<str>,
    /// Counts the tokens: 1 for the first.
    generation: u64,
    fetched_ms: i64,
    exp: Option<i64>,
}

/// The token in use, and the way to a new one.
struct Tokens {
    source: Source,
    current: Mutex<Current>,
    /// Held while a new token is fetched, so that requests that all got a 401 fetch one.
    refreshing: tokio::sync::Mutex<()>,
    /// The generation of the current token, for the background task.
    generation: watch::Sender<u64>,
    /// The lease was revoked: no new token is fetched any more.
    revoked: AtomicBool,
    /// The "token has expired" line was written.
    expired_said: AtomicBool,
}

impl Tokens {
    /// Get the first token. An error here ends the command before stdin is read.
    async fn start(source: Source) -> Result<Self> {
        if matches!(source, Source::Env) && std::env::var_os(crate::secrets::TOKEN_ENV).is_none() {
            bail!(
                "a delegation token is needed: pass --token-command CMD or --token-file PATH, or \
                 set {}",
                crate::secrets::TOKEN_ENV
            );
        }
        let token = source
            .fetch()
            .await
            .context("cannot get a delegation token; nothing was started")?;
        let current = Self::describe_new(&source, token, 1);
        if matches!(source, Source::Env) {
            if let Some(exp) = current.exp {
                if exp * 1000 <= now_ms() {
                    bail!(
                        "the token in {} has expired; set a fresh one, or use --token-command or \
                         --token-file so that attenuo connect can get new ones",
                        crate::secrets::TOKEN_ENV
                    );
                }
            }
        }
        let (generation, _) = watch::channel(1);
        Ok(Self {
            source,
            current: Mutex::new(current),
            refreshing: tokio::sync::Mutex::new(()),
            generation,
            revoked: AtomicBool::new(false),
            expired_said: AtomicBool::new(false),
        })
    }

    /// Wrap a new token, and say on stderr what matters about it.
    fn describe_new(source: &Source, token: String, generation: u64) -> Current {
        let (exp, bound) = token_meta(&token);
        let fetched_ms = now_ms();
        if bound {
            errln!(
                "attenuo connect: warning: the token is bound to a DPoP key (cnf.jkt), and \
                 attenuo connect sends no DPoP proofs, so the proxy will refuse it"
            );
        }
        match exp {
            Some(exp) => errln!(
                "attenuo connect: got a token from {} (expires in {} s)",
                source.describe(),
                exp - fetched_ms / 1000
            ),
            None => errln!(
                "attenuo connect: got a token from {}; its expiry cannot be read (it is not an \
                 attenuo token), so a new one is fetched only when the proxy refuses it",
                source.describe()
            ),
        }
        Current {
            token: Arc::from(token),
            generation,
            fetched_ms,
            exp,
        }
    }

    fn current(&self) -> Current {
        self.current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn can_refresh(&self) -> bool {
        self.source.refreshable() && !self.revoked.load(Ordering::SeqCst)
    }

    /// The token to send now and its generation. An expired token is replaced first when it
    /// can be; one that cannot is refused here, so nothing is sent with it.
    async fn for_request(&self) -> Result<(Arc<str>, u64), String> {
        let cur = self.current();
        let expired = cur
            .exp
            .is_some_and(|exp| exp.saturating_mul(1000) <= now_ms());
        if !expired {
            return Ok((cur.token, cur.generation));
        }
        if self.can_refresh() {
            return self
                .refresh(cur.generation)
                .await
                .map_err(|e| format!("attenuo connect: no valid token: {e:#}"));
        }
        if self.revoked.load(Ordering::SeqCst) {
            // The proxy says why, with the token as it is.
            return Ok((cur.token, cur.generation));
        }
        if !self.expired_said.swap(true, Ordering::SeqCst) {
            errln!(
                "attenuo connect: the token from {} has expired and cannot be replaced; every \
                 request is now answered with an error. Restart with a fresh token, or use \
                 --token-command or --token-file",
                crate::secrets::TOKEN_ENV
            );
        }
        Err(format!(
            "attenuo connect: the token from {} has expired",
            crate::secrets::TOKEN_ENV
        ))
    }

    /// Get a new token in place of generation `failed`. When another caller already replaced
    /// it, that newer token is the answer and nothing is fetched.
    async fn refresh(&self, failed: u64) -> Result<(Arc<str>, u64)> {
        let _one = self.refreshing.lock().await;
        let cur = self.current();
        if cur.generation != failed {
            return Ok((cur.token, cur.generation));
        }
        if !self.can_refresh() {
            bail!(
                "{} cannot give a new token{}",
                self.source.describe(),
                if self.revoked.load(Ordering::SeqCst) {
                    " (the lease was revoked)"
                } else {
                    ""
                }
            );
        }
        let token = self.source.fetch().await?;
        let new = Self::describe_new(&self.source, token, cur.generation + 1);
        let out = (new.token.clone(), new.generation);
        *self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = new;
        self.generation.send_replace(out.1);
        Ok(out)
    }

    /// The lease was revoked: from now on no new token is fetched.
    fn revoke(&self) {
        self.revoked.store(true, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------------------------
// Reading stdin, writing stdout
// ---------------------------------------------------------------------------------------------

/// [`crate::stdio_bridge::read_line_bounded`] for a blocking reader.
pub(crate) fn read_line_sync<R: BufRead>(
    reader: &mut R,
    max: usize,
) -> std::io::Result<Option<Line>> {
    let mut line = Vec::new();
    let mut too_long: Option<usize> = None;
    let mut started = false;
    loop {
        let buf = match reader.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
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

/// Read stdin on a thread of its own, one line at a time. A blocking read of stdin cannot be
/// cancelled, so it is kept off the runtime, which can then end while the read still waits.
fn read_stdin(max: usize) -> mpsc::Receiver<Line> {
    let (tx, rx) = mpsc::channel(16);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut reader = stdin.lock();
        loop {
            match read_line_sync(&mut reader, max) {
                Ok(Some(line)) => {
                    if tx.blocking_send(line).is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    errln!("attenuo connect: reading standard input failed: {e}");
                    break;
                }
            }
        }
    });
    rx
}

/// What the stdout writer is given.
enum ToStdout {
    /// One message, as one line.
    Line(Vec<u8>),
    /// Say when every line before this one is written.
    Flush(tokio::sync::oneshot::Sender<()>),
}

/// Write the queued lines to stdout, each whole, in order. The only writer of stdout.
async fn write_stdout(mut lines: mpsc::Receiver<ToStdout>) {
    let mut stdout = tokio::io::stdout();
    let mut open = true;
    while let Some(item) = lines.recv().await {
        match item {
            ToStdout::Line(line) if open => {
                if stdout.write_all(&line).await.is_err() || stdout.flush().await.is_err() {
                    errln!("attenuo connect: standard output is closed; messages are dropped");
                    open = false;
                }
            }
            ToStdout::Line(_) => {}
            ToStdout::Flush(done) => {
                let _ = done.send(());
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Forwarding
// ---------------------------------------------------------------------------------------------

/// Why a request got no answer: a short code (in `error.data.reason`) and the message. Neither
/// holds a secret.
#[derive(Debug)]
struct Failure {
    reason: &'static str,
    message: String,
}

fn fail(reason: &'static str, message: impl Into<String>) -> Failure {
    Failure {
        reason,
        message: message.into(),
    }
}

/// A message without its `attenuo connect: ` prefix, to follow one in a log line.
fn bare(message: &str) -> &str {
    message.strip_prefix("attenuo connect: ").unwrap_or(message)
}

/// The JSON-RPC error for a request that `f` left unanswered.
fn error_for(id: Value, f: &Failure) -> Value {
    let mut e = rpc_error(id, INTERNAL_ERROR, f.message.clone());
    e["error"]["data"] = json!({ "reason": f.reason });
    e
}

/// A JSON-RPC message: an object with `jsonrpc`.
fn is_jsonrpc(v: &Value) -> bool {
    v.as_object().is_some_and(|o| o.contains_key("jsonrpc"))
}

/// A response: no `method`, and a `result` or an `error`.
fn is_response(v: &Value) -> bool {
    v.get("method").is_none() && (v.get("result").is_some() || v.get("error").is_some())
}

/// Put `id` on an error response that has `"id": null`: the proxy answers some refusals (a bad
/// token, an unknown session) before it reads the request, so the client could not match them.
pub(crate) fn fill_null_id(v: &mut Value, id: &Value) {
    if is_response(v) && v.get("error").is_some() && v.get("id").is_none_or(Value::is_null) {
        v["id"] = id.clone();
    }
}

/// What the parts of the connector share.
struct Conn {
    http: reqwest::Client,
    /// `--server`, without a trailing `/`.
    base: String,
    /// `<base>/mcp/<upstream>`.
    url: String,
    tokens: Tokens,
    out: mpsc::Sender<ToStdout>,
    session: Mutex<Option<String>>,
    protocol: Mutex<Option<String>>,
    timeout: Duration,
    max_message: usize,
    max_stream: usize,
    session_gone_said: AtomicBool,
}

impl Conn {
    fn session(&self) -> Option<String> {
        self.session.lock().ok().and_then(|s| s.clone())
    }

    fn protocol(&self) -> Option<String> {
        self.protocol.lock().ok().and_then(|s| s.clone())
    }

    /// Write one message to stdout as one line.
    async fn emit(&self, msg: &Value) {
        let _ = self.out.send(ToStdout::Line(encode_line(msg))).await;
    }

    /// Wait until every message queued so far is written.
    async fn flush(&self) {
        let (done, written) = tokio::sync::oneshot::channel();
        if self.out.send(ToStdout::Flush(done)).await.is_ok() {
            let _ = written.await;
        }
    }

    fn transport(&self, e: &reqwest::Error) -> Failure {
        if e.is_timeout() {
            fail(
                "timeout",
                format!(
                    "attenuo connect: no answer from the attenuo server within {} s",
                    self.timeout.as_secs()
                ),
            )
        } else if e.is_connect() {
            fail(
                "unreachable",
                format!(
                    "attenuo connect: cannot connect to the attenuo server at {}",
                    self.base
                ),
            )
        } else {
            fail(
                "transport",
                format!(
                    "attenuo connect: the exchange with the attenuo server at {} failed",
                    self.base
                ),
            )
        }
    }

    fn say_session_gone(&self) {
        if !self.session_gone_said.swap(true, Ordering::SeqCst) {
            errln!(
                "attenuo connect: the proxy does not know the MCP session any more (it ended, or \
                 the proxy restarted); the client has to start a new one"
            );
        }
    }

    /// Read a whole (non-SSE) answer, at most `--max-message-bytes` of it.
    async fn read_bounded(
        &self,
        mut resp: reqwest::Response,
        max: usize,
    ) -> Result<Vec<u8>, Failure> {
        let mut bytes = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| self.transport(&e))? {
            if bytes.len() + chunk.len() > max {
                return Err(fail(
                    "too_large",
                    format!("attenuo connect: the answer is larger than {max} bytes (--max-message-bytes)"),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    /// Send one message from the client and write what comes back. For a request (`id`),
    /// `Ok(true)` when its answer was written.
    async fn forward(
        &self,
        msg: &Value,
        id: Option<&Value>,
        method: &str,
    ) -> Result<bool, Failure> {
        let body = serde_json::to_vec(msg).unwrap_or_default();
        let initialize = method == "initialize" && id.is_some();
        let mut retried = false;
        loop {
            let (token, generation) = self
                .tokens
                .for_request()
                .await
                .map_err(|m| fail("no_token", m))?;
            let mut req = self
                .http
                .post(&self.url)
                .bearer_auth(&*token)
                .header(ACCEPT, "application/json, text/event-stream")
                .header(CONTENT_TYPE, "application/json")
                .timeout(self.timeout)
                .body(body.clone());
            // `initialize` starts a session: it carries neither header.
            let sent_session = if initialize { None } else { self.session() };
            if let Some(s) = &sent_session {
                req = req.header("mcp-session-id", s);
            }
            if !initialize {
                if let Some(p) = self.protocol() {
                    req = req.header("mcp-protocol-version", p);
                }
            }
            let resp = req.send().await.map_err(|e| self.transport(&e))?;
            let status = resp.status();
            if status.is_redirection() {
                return Err(fail(
                    "redirect",
                    format!(
                        "attenuo connect: the attenuo server answered with a redirect (HTTP {status}), \
                         which is not followed; --server must be the URL that answers without one"
                    ),
                ));
            }
            if status == StatusCode::UNAUTHORIZED {
                let bytes = self.read_bounded(resp, self.max_message).await?;
                if retried {
                    errln!("attenuo connect: the proxy refused the new token too");
                } else if self.tokens.can_refresh() {
                    retried = true;
                    match self.tokens.refresh(generation).await {
                        Ok(_) => continue,
                        Err(e) => errln!(
                            "attenuo connect: the proxy refused the token and no new one could be \
                             had: {e:#}"
                        ),
                    }
                }
                return self.relay_json(status, &bytes, id, false, false).await;
            }
            let session_gone = status == StatusCode::NOT_FOUND && sent_session.is_some();
            if session_gone {
                self.say_session_gone();
            }
            if initialize && status.is_success() {
                if let Some(v) = resp.headers().get("mcp-session-id") {
                    match v.to_str().ok().filter(|s| header_safe(s)) {
                        Some(s) => {
                            if let Ok(mut slot) = self.session.lock() {
                                *slot = Some(s.to_string());
                            }
                        }
                        None => errln!(
                            "attenuo connect: the Mcp-Session-Id the proxy sent cannot be sent back \
                             (longer than 256 bytes or not visible ASCII); it is not used"
                        ),
                    }
                }
            }
            let sse = resp
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.to_ascii_lowercase().contains("text/event-stream"));
            if sse {
                return self.relay_sse(resp, id, initialize).await;
            }
            let bytes = self.read_bounded(resp, self.max_message).await?;
            return self
                .relay_json(status, &bytes, id, initialize, session_gone)
                .await;
        }
    }

    /// Write one message that came back for the request `id`. `true` when it is the request's
    /// answer.
    async fn relay_one(&self, mut v: Value, id: Option<&Value>, initialize: bool) -> bool {
        let answered = match id {
            Some(id) if is_response(&v) => {
                fill_null_id(&mut v, id);
                v.get("id") == Some(id)
            }
            _ => false,
        };
        if answered && initialize {
            if let Some(p) = v
                .pointer("/result/protocolVersion")
                .and_then(Value::as_str)
                .filter(|p| header_safe(p))
            {
                if let Ok(mut slot) = self.protocol.lock() {
                    *slot = Some(p.to_string());
                }
            }
        }
        self.emit(&v).await;
        answered
    }

    /// A JSON answer, or none (`202`).
    async fn relay_json(
        &self,
        status: StatusCode,
        bytes: &[u8],
        id: Option<&Value>,
        initialize: bool,
        session_gone: bool,
    ) -> Result<bool, Failure> {
        let http_failure = || {
            if session_gone {
                fail(
                    "session_ended",
                    "attenuo connect: the MCP session has ended (HTTP 404); start a new session",
                )
            } else {
                fail(
                    "http_status",
                    format!("attenuo connect: the attenuo server answered HTTP {status}"),
                )
            }
        };
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return if status.is_success() {
                Ok(false)
            } else {
                Err(http_failure())
            };
        }
        match serde_json::from_slice::<Value>(bytes) {
            Ok(v) if is_jsonrpc(&v) => Ok(self.relay_one(v, id, initialize).await),
            _ if status.is_success() => Err(fail(
                "not_jsonrpc",
                "attenuo connect: the answer is not a JSON-RPC message",
            )),
            _ => Err(http_failure()),
        }
    }

    /// An SSE answer: every JSON-RPC message in it, in order, up to the request's answer.
    async fn relay_sse(
        &self,
        mut resp: reqwest::Response,
        id: Option<&Value>,
        initialize: bool,
    ) -> Result<bool, Failure> {
        let mut buf: Vec<u8> = Vec::new();
        let mut scan_from = 0;
        let mut total = 0usize;
        loop {
            let chunk = match resp.chunk().await {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(e) => return Err(self.transport(&e)),
            };
            total += chunk.len();
            if total > self.max_stream {
                return Err(fail(
                    "too_large",
                    format!(
                        "attenuo connect: the streamed answer is larger than {} bytes \
                         (--max-stream-bytes)",
                        self.max_stream
                    ),
                ));
            }
            buf.extend_from_slice(&chunk);
            let mut start = 0;
            while let Some((end, next)) = event_end(&buf, scan_from) {
                let event = parse_event(&String::from_utf8_lossy(&buf[start..end]));
                start = next;
                scan_from = next;
                if let Some(v) = event
                    .data
                    .and_then(|d| serde_json::from_str::<Value>(&d).ok())
                    .filter(is_jsonrpc)
                {
                    if self.relay_one(v, id, initialize).await {
                        // The answer is the last message of the request's stream.
                        return Ok(true);
                    }
                }
            }
            buf.drain(..start);
            // No blank line up to here; one may still straddle the end of the buffer.
            scan_from = (scan_from - start).max(buf.len().saturating_sub(2));
            if buf.len() > self.max_message {
                return Err(fail(
                    "too_large",
                    format!(
                        "attenuo connect: one event of the streamed answer is larger than {} bytes \
                         (--max-message-bytes)",
                        self.max_message
                    ),
                ));
            }
        }
        // A last event that no blank line ended.
        let event = parse_event(&String::from_utf8_lossy(&buf));
        if let Some(v) = event
            .data
            .and_then(|d| serde_json::from_str::<Value>(&d).ok())
            .filter(is_jsonrpc)
        {
            return Ok(self.relay_one(v, id, initialize).await);
        }
        Ok(false)
    }

    /// `POST /token/renew` with the current token.
    async fn renew(&self) -> Renewal {
        let token = self.tokens.current().token;
        let resp = self
            .http
            .post(format!("{}/token/renew", self.base))
            .bearer_auth(&*token)
            .timeout(SHORT_TIMEOUT)
            .send()
            .await;
        let resp = match resp {
            Ok(r) => r,
            Err(e) => return Renewal::Retry(self.transport(&e).message),
        };
        let status = resp.status();
        if status.is_redirection() {
            return Renewal::Retry(format!("a redirect (HTTP {status}), which is not followed"));
        }
        match self.read_bounded(resp, MAX_RENEW_ANSWER).await {
            Ok(bytes) => classify_renewal(status.as_u16(), &String::from_utf8_lossy(&bytes)),
            Err(f) => Renewal::Retry(f.message),
        }
    }

    /// End the MCP session (`DELETE`). A server without sessions may answer `405`.
    async fn end_session(&self) {
        let Some(session) = self.session() else {
            return;
        };
        let token = self.tokens.current().token;
        let mut req = self
            .http
            .delete(&self.url)
            .bearer_auth(&*token)
            .header("mcp-session-id", session)
            .timeout(STOP_GRACE);
        if let Some(p) = self.protocol() {
            req = req.header("mcp-protocol-version", p);
        }
        match req.send().await {
            Ok(r) if r.status().is_success() || r.status() == StatusCode::METHOD_NOT_ALLOWED => {}
            Ok(r) => errln!(
                "attenuo connect: ending the MCP session: HTTP {}",
                r.status()
            ),
            Err(e) => errln!(
                "attenuo connect: ending the MCP session failed: {}",
                self.transport(&e).message
            ),
        }
    }
}

/// Send one request and write its answer, or an error with its id.
async fn answer(conn: &Conn, msg: &Value, id: &Value, method: &str) {
    let failure = match conn.forward(msg, Some(id), method).await {
        Ok(true) => return,
        Ok(false) => fail(
            "no_answer",
            "attenuo connect: the attenuo server sent no answer to the request",
        ),
        Err(f) => f,
    };
    errln!(
        "attenuo connect: {method:?} got no answer: {}",
        bare(&failure.message)
    );
    conn.emit(&error_for(id.clone(), &failure)).await;
}

// ---------------------------------------------------------------------------------------------
// The listen stream
// ---------------------------------------------------------------------------------------------

/// Keep the server-to-client stream open (`GET`) and write its requests and notifications to
/// stdout. Ends when the proxy answers `405` (the upstream has none) or `404` (the session
/// is gone).
async fn listen(conn: Arc<Conn>) {
    let mut failures = 0u32;
    let mut last_id: Option<String> = None;
    loop {
        if let Ok((token, generation)) = conn.tokens.for_request().await {
            let mut req = conn
                .http
                .get(&conn.url)
                .bearer_auth(&*token)
                .header(ACCEPT, "text/event-stream");
            if let Some(s) = conn.session() {
                req = req.header("mcp-session-id", s);
            }
            if let Some(p) = conn.protocol() {
                req = req.header("mcp-protocol-version", p);
            }
            if let Some(id) = &last_id {
                req = req.header("last-event-id", id);
            }
            match req.send().await {
                Ok(resp) if resp.status() == StatusCode::METHOD_NOT_ALLOWED => return,
                Ok(resp) if resp.status() == StatusCode::NOT_FOUND => {
                    conn.say_session_gone();
                    return;
                }
                Ok(resp) if resp.status() == StatusCode::UNAUTHORIZED => {
                    if conn.tokens.can_refresh() {
                        let _ = conn.tokens.refresh(generation).await;
                    }
                    failures += 1;
                }
                Ok(resp) if resp.status().is_success() => {
                    if relay_listen(&conn, resp, &mut last_id).await {
                        failures = 0;
                    }
                    failures += 1;
                }
                Ok(resp) => {
                    if failures == 0 {
                        errln!(
                            "attenuo connect: the listen stream was refused (HTTP {}); trying again",
                            resp.status()
                        );
                    }
                    failures += 1;
                }
                Err(_) => failures += 1,
            }
        } else {
            failures += 1;
        }
        tokio::time::sleep(backoff(failures)).await;
    }
}

/// Write the requests and notifications of one listen stream until it ends. `true` when it
/// carried at least one. A response on it (the proxy's end-of-stream error, for one) answers
/// nothing the client sent, so it is not written.
async fn relay_listen(
    conn: &Conn,
    mut resp: reqwest::Response,
    last_id: &mut Option<String>,
) -> bool {
    let mut buf: Vec<u8> = Vec::new();
    let mut scan_from = 0;
    let mut any = false;
    while let Ok(Some(chunk)) = resp.chunk().await {
        buf.extend_from_slice(&chunk);
        let mut start = 0;
        while let Some((end, next)) = event_end(&buf, scan_from) {
            let event = parse_event(&String::from_utf8_lossy(&buf[start..end]));
            start = next;
            scan_from = next;
            if let Some(id) = event.id.filter(|i| header_safe(i)) {
                *last_id = Some(id);
            }
            if let Some(v) = event
                .data
                .and_then(|d| serde_json::from_str::<Value>(&d).ok())
                .filter(|v| is_jsonrpc(v) && v.get("method").is_some_and(Value::is_string))
            {
                conn.emit(&v).await;
                any = true;
            }
        }
        buf.drain(..start);
        scan_from = (scan_from - start).max(buf.len().saturating_sub(2));
        if buf.len() > conn.max_message {
            errln!(
                "attenuo connect: an event of the listen stream is larger than {} bytes \
                 (--max-message-bytes); the stream is opened again",
                conn.max_message
            );
            break;
        }
    }
    any
}

// ---------------------------------------------------------------------------------------------
// Tokens and the lease, in the background
// ---------------------------------------------------------------------------------------------

/// Replace the token before it runs out and renew the lease, until the task is stopped.
async fn keep_fresh(conn: Arc<Conn>) {
    let mut generations = conn.tokens.generation.subscribe();
    let mut seen = 0u64;
    let mut timers = Timers::default();
    let mut refresh_failures = 0u32;
    let mut renew_failures = 0u32;
    let mut renewing = true;
    loop {
        let generation = *generations.borrow_and_update();
        if generation != seen {
            // A new token: it has a lease of its own, renewed once now to learn its window.
            seen = generation;
            let cur = conn.tokens.current();
            timers.refresh_at = if conn.tokens.can_refresh() {
                refresh_time(cur.fetched_ms, cur.exp)
            } else {
                None
            };
            timers.renew_at = renewing.then(now_ms);
            refresh_failures = 0;
            renew_failures = 0;
        }
        let (what, wait) = next(now_ms(), &timers);
        tokio::select! {
            changed = generations.changed() => {
                if changed.is_err() {
                    return;
                }
                continue;
            }
            () = tokio::time::sleep(wait), if what != Next::Idle => {}
        }
        match what {
            Next::Idle => {}
            Next::Refresh => {
                if let Err(e) = conn.tokens.refresh(seen).await {
                    refresh_failures += 1;
                    let pause = backoff(refresh_failures);
                    errln!(
                        "attenuo connect: getting a new token failed: {e:#}; trying again in {} s",
                        pause.as_secs()
                    );
                    timers.refresh_at = Some(now_ms() + pause.as_millis() as i64);
                }
            }
            Next::Renew => match conn.renew().await {
                Renewal::Renewed { expires_in } => {
                    renew_failures = 0;
                    timers.renew_at = Some(now_ms() + renew_delay(expires_in).as_millis() as i64);
                }
                Renewal::Revoked => {
                    errln!(
                        "attenuo connect: the lease was revoked (lease_revoked). This is final: \
                         renewal has stopped, no new token is fetched, and calls fail as the \
                         proxy answers them. Restart attenuo connect to start again"
                    );
                    conn.tokens.revoke();
                    renewing = false;
                    timers = Timers::default();
                }
                Renewal::NeedToken => {
                    timers.renew_at = None;
                    if conn.tokens.can_refresh() {
                        errln!("attenuo connect: the lease has run out; getting a new token");
                        timers.refresh_at = Some(now_ms());
                    } else {
                        errln!(
                            "attenuo connect: the lease has run out or is unknown, and the token \
                             from {} cannot be replaced; calls will be refused",
                            crate::secrets::TOKEN_ENV
                        );
                    }
                }
                Renewal::Retry(why) => {
                    renew_failures += 1;
                    let pause = backoff(renew_failures);
                    errln!(
                        "attenuo connect: renewing the lease failed: {why}; trying again in {} s",
                        pause.as_secs()
                    );
                    timers.renew_at = Some(now_ms() + pause.as_millis() as i64);
                }
            },
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------------------------

/// `--server`, checked: `http://` or `https://`, a host, no user name or password, no query or
/// fragment. Returned without a trailing `/`.
pub(crate) fn check_server(server: &str) -> Result<String> {
    let base = server.trim_end_matches('/');
    let url = reqwest::Url::parse(base).map_err(|_| {
        anyhow!("--server must be the attenuo server's base URL (http://host:port)")
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("--server must be the attenuo server's base URL (http://host:port)");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("--server must not carry a user name or password");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("--server must not have a query or a fragment");
    }
    Ok(base.to_string())
}

/// What to do with one line from the client.
struct Lines<'a> {
    conn: &'a Arc<Conn>,
    tasks: &'a mut JoinSet<()>,
    permits: &'a Arc<Semaphore>,
    listen: &'a mut Option<tokio::task::JoinHandle<()>>,
    max_in_flight: usize,
}

impl Lines<'_> {
    async fn on_line(&mut self, line: Line) {
        let conn = self.conn;
        let bytes = match line {
            Line::TooLong { len } => {
                errln!(
                    "attenuo connect: dropped a {len}-byte message from the client (over \
                     --max-message-bytes)"
                );
                conn.emit(&rpc_error(
                    Value::Null,
                    INVALID_REQUEST,
                    "attenuo connect: message larger than --max-message-bytes",
                ))
                .await;
                return;
            }
            Line::Message(b) => b,
        };
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return;
        }
        let Ok(msg) = serde_json::from_slice::<Value>(&bytes) else {
            conn.emit(&rpc_error(
                Value::Null,
                PARSE_ERROR,
                "attenuo connect: parse error: the line is not JSON",
            ))
            .await;
            return;
        };
        if msg.is_array() {
            conn.emit(&rpc_error(
                Value::Null,
                INVALID_REQUEST,
                "attenuo connect: JSON-RPC batches are not supported (MCP 2025-06-18 removed \
                 them); send one message per line",
            ))
            .await;
            return;
        }
        match classify_from_caller(&msg) {
            FromCaller::Invalid(why) => {
                let id = msg.get("id").cloned().unwrap_or(Value::Null);
                conn.emit(&rpc_error(
                    id,
                    INVALID_REQUEST,
                    format!("attenuo connect: invalid request: {why}"),
                ))
                .await;
            }
            FromCaller::Request { method, id } if method == "initialize" => {
                // In order: what the client sends next needs the session it opens.
                answer(conn, &msg, &id, &method).await;
            }
            FromCaller::Request { method, id } => {
                let Ok(permit) = self.permits.clone().try_acquire_owned() else {
                    let f = fail(
                        "too_many_in_flight",
                        format!(
                            "attenuo connect: {} requests are already waiting for an answer \
                             (--max-in-flight)",
                            self.max_in_flight
                        ),
                    );
                    conn.emit(&error_for(id, &f)).await;
                    return;
                };
                let conn = conn.clone();
                self.tasks.spawn(async move {
                    answer(&conn, &msg, &id, &method).await;
                    drop(permit);
                });
            }
            FromCaller::Notification { method } => {
                let ok = self.deliver(&msg, &method).await;
                if ok && method == "notifications/initialized" {
                    if let Some(old) = self.listen.take() {
                        old.abort();
                    }
                    *self.listen = Some(tokio::spawn(listen(conn.clone())));
                }
            }
            FromCaller::Response => {
                self.deliver(&msg, "a response").await;
            }
        }
    }

    /// Send a notification or a response; failures are only logged.
    async fn deliver(&self, msg: &Value, what: &str) -> bool {
        let r = tokio::time::timeout(NOTIFY_TIMEOUT, self.conn.forward(msg, None, what)).await;
        let why = match r {
            Ok(Ok(_)) => return true,
            Ok(Err(f)) => f.message,
            Err(_) => format!(
                "attenuo connect: not accepted within {} s",
                NOTIFY_TIMEOUT.as_secs()
            ),
        };
        errln!(
            "attenuo connect: {what:?} could not be delivered: {}",
            bare(&why)
        );
        false
    }
}

/// `attenuo connect`.
pub(crate) async fn run(server: &str, args: ConnectArgs) -> Result<()> {
    let base = check_server(server)?;
    attenuo_core::names::check_server_name(&args.upstream)
        .map_err(|e| anyhow!("--upstream is not a valid upstream name: {e}"))?;
    let source = Source::from_args(&args)?;
    let tokens = Tokens::start(source).await?;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .build()?;
    let (out, out_rx) = mpsc::channel(OUT_QUEUE);
    tokio::spawn(write_stdout(out_rx));
    let max_message = usize::try_from(args.max_message_bytes).unwrap_or(usize::MAX);
    let max_in_flight = usize::try_from(args.max_in_flight).unwrap_or(64);
    let url = format!("{base}/mcp/{}", args.upstream);
    let conn = Arc::new(Conn {
        http,
        base,
        url,
        tokens,
        out,
        session: Mutex::new(None),
        protocol: Mutex::new(None),
        timeout: Duration::from_secs(args.timeout),
        max_message,
        max_stream: usize::try_from(args.max_stream_bytes).unwrap_or(usize::MAX),
        session_gone_said: AtomicBool::new(false),
    });
    errln!(
        "attenuo connect: forwarding MCP messages from standard input to {}",
        conn.url
    );
    let fresh = tokio::spawn(keep_fresh(conn.clone()));
    let mut input = read_stdin(max_message);
    let mut tasks = JoinSet::new();
    let permits = Arc::new(Semaphore::new(max_in_flight));
    let mut listen_task = None;
    let signal = stop_signal();
    tokio::pin!(signal);
    {
        let mut lines = Lines {
            conn: &conn,
            tasks: &mut tasks,
            permits: &permits,
            listen: &mut listen_task,
            max_in_flight,
        };
        loop {
            tokio::select! {
                line = input.recv() => match line {
                    Some(line) => lines.on_line(line).await,
                    None => break,
                },
                () = &mut signal => {
                    errln!("attenuo connect: stopping on a signal");
                    break;
                }
                Some(_) = lines.tasks.join_next(), if !lines.tasks.is_empty() => {}
            }
        }
    }
    drop(input);
    let finished = tokio::time::timeout(STOP_GRACE, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    if finished.is_err() {
        errln!(
            "attenuo connect: {} request(s) still waiting after {} s were dropped",
            tasks.len(),
            STOP_GRACE.as_secs()
        );
        tasks.abort_all();
    }
    if let Some(l) = listen_task {
        l.abort();
    }
    fresh.abort();
    conn.end_session().await;
    let _ = tokio::time::timeout(STOP_GRACE, conn.flush()).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_are_split_like_a_shell_would_without_running_one() {
        let s = |c: &str| split_command(c).unwrap();
        assert_eq!(s("attenuo token root"), ["attenuo", "token", "root"]);
        assert_eq!(s("  a   b\tc\n"), ["a", "b", "c"]);
        assert_eq!(s("sh -c 'echo $HOME; x'"), ["sh", "-c", "echo $HOME; x"]);
        assert_eq!(s(r#"a "b c" d"#), ["a", "b c", "d"]);
        assert_eq!(s(r#""a\"b\\c\$d\n""#), [r#"a"b\c$d\n"#]);
        assert_eq!(s(r"a\ b c"), ["a b", "c"]);
        assert_eq!(s("x''y \"\"z"), ["xy", "z"]);
        assert_eq!(s("'' a"), ["", "a"]);
        assert_eq!(s("--cap github:* *"), ["--cap", "github:*", "*"]);
        for bad in ["", "   ", "'open", "\"open", "a\\", "\"a\\"] {
            let e = split_command(bad).unwrap_err();
            // The error never repeats the text.
            assert!(!e.contains("open"), "{e}");
        }
    }

    #[test]
    fn tokens_must_fit_in_a_header() {
        assert!(check_token("a.b.c").is_ok());
        assert!(check_token("").is_err());
        assert!(check_token("a b").is_err());
        assert!(check_token("a\u{7f}").is_err());
        assert!(check_token(&"x".repeat(MAX_TOKEN + 1)).is_err());
        let e = check_token("secret value").unwrap_err();
        assert!(!e.contains("secret"), "{e}");
    }

    #[test]
    fn a_token_is_replaced_after_two_thirds_of_its_life() {
        // Fetched at t = 1000 s, expires at 1900 s: due at 1600 s.
        assert_eq!(refresh_time(1_000_000, Some(1900)), Some(1_600_000));
        // Already expired: due at once.
        assert_eq!(refresh_time(1_000_000, Some(900)), Some(1_000_000));
        assert_eq!(refresh_time(1_000_000, Some(1000)), Some(1_000_000));
        // Unknown expiry: only a 401 replaces it.
        assert_eq!(refresh_time(1_000_000, None), None);
    }

    #[test]
    fn the_lease_is_renewed_at_a_third_of_its_window() {
        assert_eq!(renew_delay(300), Duration::from_secs(100));
        assert_eq!(renew_delay(299), Duration::from_millis(99_666));
        // Never more often than once a second.
        assert_eq!(renew_delay(1), Duration::from_secs(1));
        assert_eq!(renew_delay(0), Duration::from_secs(1));
        assert_eq!(renew_delay(-5), Duration::from_secs(1));
    }

    #[test]
    fn failures_back_off_up_to_thirty_seconds() {
        let got: Vec<u64> = (1..=8).map(|n| backoff(n).as_secs()).collect();
        assert_eq!(got, [1, 2, 4, 8, 16, 30, 30, 30]);
        assert_eq!(backoff(0), Duration::from_secs(1));
        assert_eq!(backoff(u32::MAX), MAX_BACKOFF);
    }

    #[test]
    fn the_next_action_is_the_earliest_one_due() {
        let t = |refresh_at, renew_at| Timers {
            refresh_at,
            renew_at,
        };
        assert_eq!(next(0, &t(None, None)), (Next::Idle, Duration::ZERO));
        assert_eq!(
            next(1_000, &t(Some(5_000), Some(2_000))),
            (Next::Renew, Duration::from_secs(1))
        );
        assert_eq!(
            next(1_000, &t(Some(2_000), Some(5_000))),
            (Next::Refresh, Duration::from_secs(1))
        );
        // A tie: the new token first, since it comes with a lease of its own.
        assert_eq!(
            next(1_000, &t(Some(2_000), Some(2_000))),
            (Next::Refresh, Duration::from_secs(1))
        );
        // Overdue: at once.
        assert_eq!(
            next(9_000, &t(None, Some(2_000))),
            (Next::Renew, Duration::ZERO)
        );
        assert_eq!(
            next(9_000, &t(Some(2_000), None)),
            (Next::Refresh, Duration::ZERO)
        );
    }

    /// A whole token's life, as the background task plans it: renew at once, then every
    /// third of the window, and the new token before the old one runs out.
    #[test]
    fn a_token_life_is_planned_without_waiting() {
        let fetched = 0;
        let mut timers = Timers {
            refresh_at: refresh_time(fetched, Some(900)),
            renew_at: Some(fetched),
        };
        let mut now = fetched;
        let mut log = Vec::new();
        for _ in 0..8 {
            let (what, wait) = next(now, &timers);
            now += wait.as_millis() as i64;
            log.push((what, now / 1000));
            match what {
                Next::Renew => {
                    timers.renew_at = Some(now + renew_delay(300).as_millis() as i64);
                }
                Next::Refresh => break,
                Next::Idle => unreachable!(),
            }
        }
        assert_eq!(
            log,
            [
                (Next::Renew, 0),
                (Next::Renew, 100),
                (Next::Renew, 200),
                (Next::Renew, 300),
                (Next::Renew, 400),
                (Next::Renew, 500),
                (Next::Refresh, 600),
            ]
        );
    }

    #[test]
    fn renewal_answers_are_sorted() {
        assert_eq!(
            classify_renewal(200, r#"{"lease":"l","expires_in":299}"#),
            Renewal::Renewed { expires_in: 299 }
        );
        assert!(matches!(classify_renewal(200, "{}"), Renewal::Retry(_)));
        assert_eq!(
            classify_renewal(
                400,
                r#"{"error":"invalid_grant","code":"lease_revoked","detail":"x"}"#
            ),
            Renewal::Revoked
        );
        for code in ["lease_expired", "lease_unknown"] {
            assert_eq!(
                classify_renewal(
                    400,
                    &format!(r#"{{"error":"invalid_grant","code":"{code}"}}"#)
                ),
                Renewal::NeedToken
            );
        }
        // A 401 (a bad or expired token) is retried: a new token comes from its own timer
        // or from a refused call.
        assert!(matches!(
            classify_renewal(401, r#"{"error":"unauthorized","code":"token_expired"}"#),
            Renewal::Retry(_)
        ));
        assert!(matches!(classify_renewal(503, "busy"), Renewal::Retry(_)));
        // A code with control characters is escaped before it is logged.
        let Renewal::Retry(why) = classify_renewal(500, r#"{"error":"x\u001b[2J"}"#) else {
            panic!()
        };
        assert!(!why.chars().any(char::is_control), "{why:?}");
    }

    #[test]
    fn a_null_id_on_an_error_becomes_the_request_id() {
        let mut v = json!({"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"m"}});
        fill_null_id(&mut v, &json!(7));
        assert_eq!(v["id"], 7);
        // An error with an id of its own, a result, and a notification are left alone.
        for orig in [
            json!({"jsonrpc":"2.0","id":3,"error":{"code":1,"message":"m"}}),
            json!({"jsonrpc":"2.0","id":null,"result":{}}),
            json!({"jsonrpc":"2.0","method":"notifications/message","error":{}}),
        ] {
            let mut v = orig.clone();
            fill_null_id(&mut v, &json!(7));
            assert_eq!(v, orig);
        }
    }

    #[test]
    fn the_server_url_is_checked() {
        assert_eq!(
            check_server("http://127.0.0.1:8080/").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            check_server("https://a.example/attenuo").unwrap(),
            "https://a.example/attenuo"
        );
        for bad in [
            "github",
            "ftp://x",
            "http://user:pw@x",
            "http://x/?a=1",
            "http://x/#f",
        ] {
            assert!(check_server(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn blocking_lines_are_bounded_like_the_async_ones() {
        let mut r = std::io::BufReader::with_capacity(3, &b"{\"a\":1}\r\n0123456789\nok"[..]);
        let mut got = Vec::new();
        while let Some(l) = read_line_sync(&mut r, 8).unwrap() {
            got.push(l);
        }
        assert_eq!(
            got,
            [
                Line::Message(b"{\"a\":1}".to_vec()),
                Line::TooLong { len: 10 },
                Line::Message(b"ok".to_vec()),
            ]
        );
    }

    #[test]
    fn an_unanswered_request_gets_an_error_with_its_id_and_a_reason() {
        let e = error_for(json!("r-1"), &fail("timeout", "attenuo connect: no answer"));
        assert_eq!(e["id"], "r-1");
        assert_eq!(e["error"]["code"], INTERNAL_ERROR);
        assert_eq!(e["error"]["data"]["reason"], "timeout");
        assert!(e["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("attenuo"));
    }
}
