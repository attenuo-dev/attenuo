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
//!   Everything else (logs, warnings) goes to stderr. A notification or a response from the
//!   client is never answered on stdout: when the proxy refuses one, that is logged.
//! - **Tokens.** From `--token-command` (run again whenever a new token is needed), from
//!   `--token-file` (read again), or from `ATTENUO_TOKEN` (used as it is). A new token is
//!   fetched when two thirds of the current one's lifetime have passed, and at once when the
//!   proxy answers 401; the request that got the 401 is sent once more with the new token,
//!   and never more than once. One fetch runs at a time. A fetch that fails, or that gives
//!   the same token again or one that has expired, is a failure: the next fetch waits 1, 2,
//!   4, ... s (at most [`MAX_BACKOFF`]), and callers in that window get the same failure. The
//!   token and the command's arguments are never logged.
//! - **Lease.** `POST /token/renew` once when a token is new, then at a third of the
//!   `expires_in` it answers. `lease_revoked`, from a renewal, a request or the listen
//!   stream, is final: requests in flight are answered with an error, nothing more is sent,
//!   no new token is fetched, and the process exits with status 3.
//! - **Requests** may be in flight together, up to `--max-in-flight`; stdin is not held up
//!   by a slow call. `initialize` and notifications are sent in the order they are read.
//!   A request that gets no answer (the network, a timeout, an HTTP error without a JSON-RPC
//!   body, no token) is answered with a JSON-RPC error with its id. The proxy's own JSON-RPC
//!   errors are passed on as they came; when one has `"id": null` (the proxy refused the
//!   request before reading it), the request's id is put in, so the client can match it.
//!   `notifications/cancelled` stops the local work for that request; it gets no answer.
//! - **Session.** The client's `initialize` and `notifications/initialized` are kept. When
//!   the proxy no longer knows the session (`404`), they are sent again once to open a new
//!   one (the answer is not written), and the request is sent once more.
//! - **Listen stream.** After `notifications/initialized`, a `GET` opens the server-to-client
//!   stream. `405` (the upstream has none) ends it quietly. Its requests and notifications are
//!   written to stdout; it is opened again, with a growing pause, when it ends.
//! - **End.** At end of stdin, or SIGINT, SIGTERM, SIGHUP or SIGQUIT: stop reading, give
//!   requests in flight [`STOP_GRACE`] to finish, end the MCP session with `DELETE`, exit 0.
//!   A signal is seen while a line is being handled too, and when stdout is not read the
//!   process exits without writing the rest.
//!
//! Nothing that comes from the proxy or the upstream is run, and none of it is logged.

use std::collections::HashMap;
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
use tokio::task::{AbortHandle, JoinSet};

use crate::cli::ConnectArgs;
use crate::client::stable_code;
use crate::init_cmd::header_safe;
use crate::render::escape_controls;
use crate::sse::{event_end, parse_event};
use crate::stdio_bridge::{
    classify_from_caller, encode_line, rpc_error, stop_signal, FromCaller, GroupGuard, Line,
};

/// JSON-RPC: invalid JSON.
const PARSE_ERROR: i64 = -32700;
/// JSON-RPC: not a valid request object.
const INVALID_REQUEST: i64 = -32600;
/// JSON-RPC: internal error (the connector could not get an answer).
const INTERNAL_ERROR: i64 = -32603;

/// How long requests in flight may still take once input has ended.
const STOP_GRACE: Duration = Duration::from_secs(5);
/// How long the last lines may take to be written at the end. Past it, stdout is not being
/// read, and the process exits without them.
const FLUSH_GRACE: Duration = Duration::from_secs(1);
/// How long a notification (or a response to the server) may take to be accepted. They are
/// sent in order, so a slow one holds up the next lines.
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout of a lease renewal, of the `DELETE` at the end, and of the headers of the listen
/// stream's `GET`.
const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout of opening a TCP (and TLS) connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest pause between two tries of something that failed.
pub(crate) const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Shortest pause before any planned token fetch or renewal, so that nothing can spin.
const MIN_DELAY_MS: i64 = 1_000;
/// A token that expires within this many milliseconds is no better than an expired one.
const EXPIRY_MARGIN_MS: i64 = 5_000;
/// Longest token accepted, in bytes.
const MAX_TOKEN: usize = 16 * 1024;
/// Most bytes read from the token command or the token file.
const MAX_TOKEN_SOURCE: u64 = 64 * 1024;
/// Most bytes read from a renewal answer, or from a refusal of the listen stream.
const MAX_RENEW_ANSWER: usize = 64 * 1024;
/// Lines that may wait for the stdout writer.
const OUT_QUEUE: usize = 32;
/// The exit status after `lease_revoked`.
pub(crate) const EXIT_REVOKED: u8 = 3;
/// The reason code that ends everything.
const LEASE_REVOKED: &str = "lease_revoked";

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

/// Whether `word` reads as a shell environment assignment, `NAME=value`.
pub(crate) fn is_env_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// ---------------------------------------------------------------------------------------------
// Where tokens come from
// ---------------------------------------------------------------------------------------------

/// Where the delegation token comes from.
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

/// The arguments may hold a secret: they are never shown, not even in a debug print.
impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::Command {
                program, timeout, ..
            } => f
                .debug_struct("Command")
                .field("program", program)
                .field("args", &"<redacted>")
                .field("timeout", timeout)
                .finish(),
            Source::File(p) => f.debug_tuple("File").field(p).finish(),
            Source::Env => f.write_str("Env"),
        }
    }
}

impl Source {
    fn from_args(args: &ConnectArgs) -> Result<Self> {
        if let Some(cmd) = &args.token_command {
            let mut words = split_command(cmd)
                .map_err(|why| anyhow!("--token-command cannot be split into words: {why}"))?;
            if is_env_assignment(&words[0]) {
                // The word is not repeated: the value may be a secret.
                bail!(
                    "--token-command starts with an environment assignment (NAME=value), which \
                     is not supported: no shell runs the command. Use `env NAME=value CMD ...`, \
                     a wrapper script, or the client's `env` setting"
                );
            }
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
/// stderr is ours, its environment is ours. It runs in a process group of its own, and the
/// whole group is killed on a timeout, or when the caller gives up (the future is dropped).
async fn run_token_command(program: &str, args: &[String], timeout: Duration) -> Result<String> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    #[cfg(unix)]
    cmd.process_group(0);
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("cannot start the token command `{program}`: {e}"))?;
    let mut group = GroupGuard(child.id());
    let Some(stdout) = child.stdout.take() else {
        bail!("the token command `{program}` was started without a pipe");
    };
    let work = async {
        let mut out = Vec::new();
        stdout.take(MAX_TOKEN_SOURCE).read_to_end(&mut out).await?;
        let status = child.wait().await?;
        Ok::<_, std::io::Error>((out, status))
    };
    let outcome = tokio::time::timeout(timeout, work).await;
    if outcome.is_err() {
        // The group first, while the child is not reaped: what it started goes too.
        drop(group);
        let _ = child.kill().await;
        bail!(
            "the token command `{program}` did not finish within {} s (--token-command-timeout)",
            timeout.as_secs()
        );
    }
    // It ended by itself: what it left running is not ours to stop.
    group.0 = None;
    match outcome {
        Err(_) => unreachable!("handled above"),
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

/// Whether a token that was just fetched is worth using: not the one in use (`previous`),
/// and not expired or about to expire at `now_ms`. The error says why, without the token.
pub(crate) fn judge_fetched(
    token: &str,
    previous: Option<&str>,
    exp: Option<i64>,
    now_ms: i64,
) -> Result<(), &'static str> {
    if previous == Some(token) {
        return Err("gave the same token again");
    }
    if let Some(exp) = exp {
        let exp_ms = exp.saturating_mul(1000);
        if exp_ms <= now_ms {
            return Err("gave a token that has already expired");
        }
        if exp_ms <= now_ms.saturating_add(EXPIRY_MARGIN_MS) {
            return Err("gave a token that expires in less than 5 s");
        }
    }
    Ok(())
}

/// Seconds from `now_ms` to `exp`, for the log. Never overflows.
pub(crate) fn seconds_left(exp: i64, now_ms: i64) -> i64 {
    exp.saturating_sub(now_ms / 1000)
}

fn now_ms() -> i64 {
    i64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .unwrap_or(i64::MAX)
}

fn ms(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
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
/// seconds) should be replaced: after two thirds of its lifetime, and never sooner than a
/// second after it was fetched. `None` when its expiry is unknown.
pub(crate) fn refresh_time(fetched_ms: i64, exp: Option<i64>) -> Option<i64> {
    let exp_ms = exp?.saturating_mul(1000);
    let life = exp_ms.saturating_sub(fetched_ms).max(0);
    Some(fetched_ms.saturating_add((life / 3 * 2).max(MIN_DELAY_MS)))
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

/// When to renew the lease of a new token: at once, unless renewals have been failing, then
/// not before the pause their failures earned since the last try.
pub(crate) fn first_renewal(now: i64, last_try: Option<i64>, failures: u32) -> i64 {
    match last_try {
        Some(t) if failures > 0 => now.max(t.saturating_add(ms(backoff(failures)))),
        Some(t) => now.max(t.saturating_add(MIN_DELAY_MS)),
        None => now,
    }
}

/// What a renewal's answer means.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Renewal {
    /// Renewed; renew again at a third of `expires_in` seconds.
    Renewed { expires_in: i64 },
    /// `lease_revoked`: final.
    Revoked,
    /// The lease has expired or is unknown, or the token was refused: only a new token (with
    /// a new lease) helps. The text says why, for the log.
    NeedToken(String),
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
    let code = stable_code(&v);
    match (status, code) {
        (400 | 401, Some(LEASE_REVOKED)) => Renewal::Revoked,
        (400, Some(c @ ("lease_expired" | "lease_unknown"))) => {
            Renewal::NeedToken(format!("HTTP 400 ({c})"))
        }
        (401, Some(c)) => Renewal::NeedToken(format!("HTTP 401 ({})", escape_controls(c))),
        (401, None) => Renewal::NeedToken("HTTP 401".into()),
        (_, Some(c)) => Renewal::Retry(format!("HTTP {status} ({})", escape_controls(c))),
        (_, None) => Renewal::Retry(format!("HTTP {status}")),
    }
}

/// Whether a message or an error body says the lease was revoked: `error.data.reason` of a
/// JSON-RPC error, or the `code` of an attenuo error body.
pub(crate) fn says_revoked(v: &Value) -> bool {
    v.pointer("/error/data/reason").and_then(Value::as_str) == Some(LEASE_REVOKED)
        || (v.get("method").is_none() && stable_code(v) == Some(LEASE_REVOKED))
}

/// `--server` is `http://` to a host that is not loopback: the bearer travels in cleartext.
pub(crate) fn cleartext_to_remote(base: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(base) else {
        return false;
    };
    if url.scheme() != "http" {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => !ip.is_loopback(),
        Err(_) => host != "localhost" && !host.ends_with(".localhost"),
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

/// The fetches that failed in a row, and the last one.
#[derive(Default)]
struct Failures {
    count: u32,
    /// When the last one ended, when the next may start, and why it failed.
    last: Option<(i64, i64, String)>,
}

/// The token in use, and the way to a new one.
struct Tokens {
    source: Source,
    current: Mutex<Current>,
    /// Held while a new token is fetched: one fetch at a time.
    refreshing: tokio::sync::Mutex<()>,
    failures: Mutex<Failures>,
    /// The generation of the current token, for the background task.
    generation: watch::Sender<u64>,
    /// The lease was revoked: nothing is sent and no new token is fetched any more.
    revoked: watch::Sender<bool>,
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
        let (exp, _) = token_meta(&token);
        if let Err(why) = judge_fetched(&token, None, exp, now_ms()) {
            if matches!(source, Source::Env) {
                bail!(
                    "{} holds a token that has expired or expires in less than 5 s; set a fresh \
                     one, or use --token-command or --token-file so that attenuo connect can get \
                     new ones",
                    crate::secrets::TOKEN_ENV
                );
            }
            bail!("{} {why}; nothing was started", source.describe());
        }
        let current = Self::describe_new(&source, token, 1);
        let (generation, _) = watch::channel(1);
        let (revoked, _) = watch::channel(false);
        Ok(Self {
            source,
            current: Mutex::new(current),
            refreshing: tokio::sync::Mutex::new(()),
            failures: Mutex::new(Failures::default()),
            generation,
            revoked,
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
                seconds_left(exp, fetched_ms)
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

    fn is_revoked(&self) -> bool {
        *self.revoked.borrow()
    }

    fn can_refresh(&self) -> bool {
        self.source.refreshable() && !self.is_revoked()
    }

    /// When the next fetch may start, after a failure.
    fn retry_at(&self) -> Option<i64> {
        self.failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .last
            .as_ref()
            .map(|(_, at, _)| *at)
    }

    /// The token to send now and its generation. An expired token is replaced first when it
    /// can be; one that cannot is refused here, so nothing is sent with it. After
    /// `lease_revoked` nothing is sent.
    async fn for_request(&self) -> Result<(Arc<str>, u64), Failure> {
        if self.is_revoked() {
            return Err(revoked_failure());
        }
        let cur = self.current();
        let expired = cur
            .exp
            .is_some_and(|exp| exp.saturating_mul(1000) <= now_ms());
        if !expired {
            return Ok((cur.token, cur.generation));
        }
        if self.source.refreshable() {
            return self
                .refresh(cur.generation)
                .await
                .map_err(|e| fail("no_token", format!("attenuo connect: no valid token: {e}")));
        }
        if !self.expired_said.swap(true, Ordering::SeqCst) {
            errln!(
                "attenuo connect: the token from {} has expired and cannot be replaced; every \
                 request is now answered with an error. Restart with a fresh token, or use \
                 --token-command or --token-file",
                crate::secrets::TOKEN_ENV
            );
        }
        Err(fail(
            "no_token",
            format!(
                "attenuo connect: the token from {} has expired",
                crate::secrets::TOKEN_ENV
            ),
        ))
    }

    /// Get a new token in place of generation `failed`. One fetch runs at a time. When
    /// another caller already replaced the token, that newer token is the answer. When a
    /// fetch failed while this caller waited, or the pause after the last failure has not
    /// passed, that failure is the answer and nothing is fetched. The error has no prefix.
    async fn refresh(&self, failed: u64) -> Result<(Arc<str>, u64), String> {
        let asked = now_ms();
        let _one = self.refreshing.lock().await;
        let cur = self.current();
        if cur.generation != failed {
            return Ok((cur.token, cur.generation));
        }
        if self.is_revoked() {
            return Err("no new token is fetched: the lease was revoked".into());
        }
        if !self.source.refreshable() {
            return Err(format!(
                "{} cannot give a new token",
                self.source.describe()
            ));
        }
        {
            let f = self
                .failures
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some((ended, next, why)) = &f.last {
                if *ended >= asked || now_ms() < *next {
                    return Err(why.clone());
                }
            }
        }
        let fetched = match self.source.fetch().await {
            Ok(token) => {
                let (exp, _) = token_meta(&token);
                judge_fetched(&token, Some(&cur.token), exp, now_ms())
                    .map(|()| token)
                    .map_err(|why| format!("{} {why}", self.source.describe()))
            }
            Err(e) => Err(format!("{e:#}")),
        };
        match fetched {
            Ok(token) => {
                *self
                    .failures
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Failures::default();
                let new = Self::describe_new(&self.source, token, cur.generation + 1);
                let out = (new.token.clone(), new.generation);
                *self
                    .current
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = new;
                self.generation.send_replace(out.1);
                Ok(out)
            }
            Err(why) => {
                let mut f = self
                    .failures
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                f.count = f.count.saturating_add(1);
                let pause = backoff(f.count);
                let ended = now_ms();
                f.last = Some((ended, ended.saturating_add(ms(pause)), why.clone()));
                errln!(
                    "attenuo connect: getting a new token failed: {why}; the next try is in {} s \
                     at the earliest",
                    pause.as_secs()
                );
                Err(why)
            }
        }
    }

    /// The lease was revoked: from now on nothing is sent and no new token is fetched.
    /// `true` the first time.
    fn revoke(&self) -> bool {
        !self.revoked.send_replace(true)
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
#[derive(Debug, Clone)]
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

fn revoked_failure() -> Failure {
    fail(
        LEASE_REVOKED,
        "attenuo connect: the lease was revoked (lease_revoked); attenuo connect stops",
    )
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
/// token, an unknown session) before it reads the request, so the client could not match it.
pub(crate) fn fill_null_id(v: &mut Value, id: &Value) {
    if is_response(v) && v.get("error").is_some() && v.get("id").is_none_or(Value::is_null) {
        v["id"] = id.clone();
    }
}

/// The key of a request id in the table of requests in flight.
fn id_key(id: &Value) -> String {
    id.to_string()
}

/// What one exchange relays, and how.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// A request, a notification or a response from the client.
    Plain,
    /// The client's `initialize`: its answer gives the protocol version.
    Initialize,
    /// `initialize` sent again for a lost session: nothing is written to stdout.
    Replay,
}

/// The request an exchange is for.
#[derive(Clone, Copy)]
struct Req<'a> {
    /// `None` for a notification or a response.
    id: Option<&'a Value>,
    mode: Mode,
    /// The request is in the table of requests in flight.
    tracked: bool,
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
    /// The client's last `initialize` and `notifications/initialized`, to open a new session.
    handshake: Mutex<(Option<Value>, Option<Value>)>,
    /// Held while a new session is opened; the time and the error of the last try that failed.
    resuming: tokio::sync::Mutex<Option<(i64, String)>>,
    /// The listen stream's task, once `notifications/initialized` was accepted.
    listen: Mutex<Option<AbortHandle>>,
    /// Requests in flight, by [`id_key`]. An entry leaves the table when its answer is
    /// queued, or when the request is cancelled or answered for at the end; its permit goes
    /// with it.
    in_flight: Mutex<HashMap<String, Flight>>,
}

impl Conn {
    fn session(&self) -> Option<String> {
        self.session.lock().ok().and_then(|s| s.clone())
    }

    fn set_session(&self, s: Option<String>) {
        if let Ok(mut slot) = self.session.lock() {
            *slot = s;
        }
    }

    fn protocol(&self) -> Option<String> {
        self.protocol.lock().ok().and_then(|s| s.clone())
    }

    /// Write one message to stdout as one line.
    async fn emit(&self, msg: &Value) {
        let _ = self.out.send(ToStdout::Line(encode_line(msg))).await;
    }

    /// Write the answer to request `id`. A tracked request is answered once: when its entry
    /// is no longer in the table (it was cancelled, or answered for at the end), nothing is
    /// written. The entry is taken only once there is room in the queue, with no pause
    /// between taking it and queueing the line, so an answer is never lost on the way.
    async fn emit_answer(&self, id: &Value, msg: &Value, tracked: bool) {
        let slot = self.out.reserve().await;
        if tracked {
            let entry = self
                .in_flight
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id_key(id));
            if entry.is_none() {
                return;
            }
        }
        if let Ok(slot) = slot {
            slot.send(ToStdout::Line(encode_line(msg)));
        }
    }

    /// Wait until every message queued so far is written.
    async fn flush(&self) {
        let (done, written) = tokio::sync::oneshot::channel();
        if self.out.send(ToStdout::Flush(done)).await.is_ok() {
            let _ = written.await;
        }
    }

    /// `lease_revoked` was seen: nothing more is sent, and the main loop ends.
    fn on_revoked(&self) {
        self.tokens.revoke();
    }

    /// Open (again) the listen stream.
    fn start_listen(self: &Arc<Self>) {
        let task = tokio::spawn(listen(self.clone()));
        let mut slot = self
            .listen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(old) = slot.replace(task.abort_handle()) {
            old.abort();
        }
    }

    fn stop_listen(&self) {
        if let Some(l) = self
            .listen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            l.abort();
        }
    }

    fn listening(&self) -> bool {
        self.listen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
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

    /// Read a whole (non-SSE) answer, at most `max` bytes of it.
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

    /// `POST` one message to the endpoint.
    async fn post(
        &self,
        body: &[u8],
        token: &str,
        session: Option<&str>,
        protocol: bool,
    ) -> Result<reqwest::Response, Failure> {
        let mut req = self
            .http
            .post(&self.url)
            .bearer_auth(token)
            .header(ACCEPT, "application/json, text/event-stream")
            .header(CONTENT_TYPE, "application/json")
            .timeout(self.timeout)
            .body(body.to_vec());
        if let Some(s) = session {
            req = req.header("mcp-session-id", s);
        }
        if protocol {
            if let Some(p) = self.protocol() {
                req = req.header("mcp-protocol-version", p);
            }
        }
        req.send().await.map_err(|e| self.transport(&e))
    }

    /// Keep the `Mcp-Session-Id` an `initialize` answer carries.
    fn session_from(resp: &reqwest::Response) -> Option<String> {
        let v = resp.headers().get("mcp-session-id")?;
        match v.to_str().ok().filter(|s| header_safe(s)) {
            Some(s) => Some(s.to_string()),
            None => {
                errln!(
                    "attenuo connect: the Mcp-Session-Id the proxy sent cannot be sent back \
                     (longer than 256 bytes or not visible ASCII); it is not used"
                );
                None
            }
        }
    }

    fn is_sse(resp: &reqwest::Response) -> bool {
        resp.headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("text/event-stream"))
    }

    /// Send one message from the client and write what comes back. For a request (`id`),
    /// `Ok(true)` when its answer was written.
    async fn forward(
        self: &Arc<Self>,
        msg: &Value,
        id: Option<&Value>,
        method: &str,
        tracked: bool,
    ) -> Result<bool, Failure> {
        let body = serde_json::to_vec(msg).unwrap_or_default();
        let initialize = method == "initialize" && id.is_some();
        if let Ok(mut h) = self.handshake.lock() {
            if initialize {
                *h = (Some(msg.clone()), None);
            } else if method == "notifications/initialized" && id.is_none() {
                h.1 = Some(msg.clone());
            }
        }
        let req = Req {
            id,
            mode: if initialize {
                Mode::Initialize
            } else {
                Mode::Plain
            },
            tracked,
        };
        let mut new_token = false;
        let mut new_session = false;
        loop {
            let (token, generation) = self.tokens.for_request().await?;
            // `initialize` starts a session: it carries neither header.
            let sent_session = if initialize { None } else { self.session() };
            let resp = self
                .post(&body, &token, sent_session.as_deref(), !initialize)
                .await?;
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
                let refusal: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                if says_revoked(&refusal) {
                    // Final: no new token. The client gets the proxy's answer, then the end.
                    let r = self.relay_json(status, &bytes, req, false).await;
                    self.on_revoked();
                    return r;
                }
                if new_token {
                    errln!("attenuo connect: the proxy refused the new token too");
                } else if self.tokens.can_refresh() {
                    new_token = true;
                    match self.tokens.refresh(generation).await {
                        Ok(_) => continue,
                        Err(e) => errln!(
                            "attenuo connect: the proxy refused the token and no new one could be \
                             had: {e}"
                        ),
                    }
                }
                return self.relay_json(status, &bytes, req, false).await;
            }
            let session_gone = status == StatusCode::NOT_FOUND && sent_session.is_some();
            if session_gone && !new_session && self.can_resume() {
                new_session = true;
                drop(resp);
                if let Some(lost) = &sent_session {
                    self.resume(lost).await?;
                }
                continue;
            }
            if initialize && status.is_success() {
                if let Some(s) = Self::session_from(&resp) {
                    self.set_session(Some(s));
                }
            }
            if Self::is_sse(&resp) {
                return self.relay_sse(resp, req).await;
            }
            let bytes = self.read_bounded(resp, self.max_message).await?;
            return self.relay_json(status, &bytes, req, session_gone).await;
        }
    }

    /// Whether a lost session can be opened again: the client's `initialize` is known.
    fn can_resume(&self) -> bool {
        self.handshake.lock().is_ok_and(|h| h.0.is_some())
    }

    /// The proxy no longer knows session `lost`: send the client's `initialize` and
    /// `notifications/initialized` again to open a new one, once for all the requests that
    /// found it lost. A try that failed while this caller waited is its answer too; the next
    /// request tries again.
    async fn resume(self: &Arc<Self>, lost: &str) -> Result<(), Failure> {
        let asked = now_ms();
        let mut last = self.resuming.lock().await;
        if self.session().as_deref() != Some(lost) {
            // Another request opened a new one already.
            return Ok(());
        }
        if let Some((ended, why)) = &*last {
            if *ended >= asked {
                return Err(fail("session_ended", why.clone()));
            }
        }
        match self.replay().await {
            Ok(()) => {
                *last = None;
                errln!(
                    "attenuo connect: the proxy did not know the MCP session any more (it ended, \
                     or the proxy restarted); a new one was opened with the client's initialize"
                );
                if self.listening() {
                    self.start_listen();
                }
                Ok(())
            }
            Err(f) => {
                let why = format!(
                    "attenuo connect: the MCP session has ended and a new one could not be \
                     opened: {}",
                    bare(&f.message)
                );
                errln!("{why}; the next request tries again");
                *last = Some((now_ms(), why.clone()));
                Err(fail("session_ended", why))
            }
        }
    }

    /// Send the kept `initialize` and `notifications/initialized` again. Nothing is written
    /// to stdout. The new session is used only once both were accepted.
    async fn replay(&self) -> Result<(), Failure> {
        let (init, initialized) = self.handshake.lock().map(|h| h.clone()).unwrap_or_default();
        let init =
            init.ok_or_else(|| fail("session_ended", "the client's initialize is not known"))?;
        let id = init.get("id").cloned();
        let (token, _) = self.tokens.for_request().await?;
        let body = serde_json::to_vec(&init).unwrap_or_default();
        let resp = self.post(&body, &token, None, false).await?;
        let status = resp.status();
        if !status.is_success() {
            if status == StatusCode::UNAUTHORIZED {
                let bytes = self.read_bounded(resp, MAX_RENEW_ANSWER).await?;
                if says_revoked(&serde_json::from_slice(&bytes).unwrap_or(Value::Null)) {
                    self.on_revoked();
                    return Err(revoked_failure());
                }
            }
            return Err(fail(
                "session_ended",
                format!("initialize was answered HTTP {status}"),
            ));
        }
        let session = Self::session_from(&resp);
        let req = Req {
            id: id.as_ref(),
            mode: Mode::Replay,
            tracked: false,
        };
        let answered = if Self::is_sse(&resp) {
            self.relay_sse(resp, req).await?
        } else {
            let bytes = self.read_bounded(resp, self.max_message).await?;
            self.relay_json(status, &bytes, req, false).await?
        };
        if !answered {
            return Err(fail("session_ended", "initialize got no result"));
        }
        if let Some(n) = initialized {
            let body = serde_json::to_vec(&n).unwrap_or_default();
            let resp = self.post(&body, &token, session.as_deref(), true).await?;
            if !resp.status().is_success() {
                return Err(fail(
                    "session_ended",
                    format!(
                        "notifications/initialized was answered HTTP {}",
                        resp.status()
                    ),
                ));
            }
        }
        self.set_session(session);
        Ok(())
    }

    /// Write one message that came back for `req`. `true` when it is the request's answer
    /// (with [`Mode::Replay`], a result).
    async fn relay_one(&self, mut v: Value, req: Req<'_>) -> bool {
        let response = is_response(&v);
        let answered = match req.id {
            Some(id) if response => {
                fill_null_id(&mut v, id);
                v.get("id") == Some(id)
            }
            _ => false,
        };
        if answered && req.mode != Mode::Plain {
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
        let revoked = response && says_revoked(&v);
        match (req.mode, req.id) {
            (Mode::Replay, _) => {}
            (_, Some(id)) if answered => self.emit_answer(id, &v, req.tracked).await,
            (_, Some(_)) => self.emit(&v).await,
            // The client sent a notification or a response: an answer to it is not one the
            // client can take, so it is only logged. What the server sends of its own goes on.
            (_, None) if response => {
                if let Some(code) = v.pointer("/error/code").and_then(Value::as_i64) {
                    errln!(
                        "attenuo connect: the proxy answered a message without an id with error \
                         {code}; it is not passed on"
                    );
                }
            }
            (_, None) => self.emit(&v).await,
        }
        if revoked {
            self.on_revoked();
        }
        answered && (req.mode != Mode::Replay || v.get("result").is_some())
    }

    /// A JSON answer, or none (`202`).
    async fn relay_json(
        &self,
        status: StatusCode,
        bytes: &[u8],
        req: Req<'_>,
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
            Ok(v) if is_jsonrpc(&v) => {
                let answered = self.relay_one(v, req).await;
                if req.id.is_none() && !status.is_success() {
                    // Not delivered; the caller logs it.
                    return Err(http_failure());
                }
                Ok(answered)
            }
            _ if status.is_success() => Err(fail(
                "not_jsonrpc",
                "attenuo connect: the answer is not a JSON-RPC message",
            )),
            _ => Err(http_failure()),
        }
    }

    /// An SSE answer: every JSON-RPC message in it, in order, up to the request's answer.
    async fn relay_sse(&self, mut resp: reqwest::Response, req: Req<'_>) -> Result<bool, Failure> {
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
                    if self.relay_one(v, req).await {
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
            return Ok(self.relay_one(v, req).await);
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
            Err(e) => return Renewal::Retry(bare(&self.transport(&e).message).to_string()),
        };
        let status = resp.status();
        if status.is_redirection() {
            return Renewal::Retry(format!("a redirect (HTTP {status}), which is not followed"));
        }
        match self.read_bounded(resp, MAX_RENEW_ANSWER).await {
            Ok(bytes) => classify_renewal(status.as_u16(), &String::from_utf8_lossy(&bytes)),
            Err(f) => Renewal::Retry(bare(&f.message).to_string()),
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
                bare(&self.transport(&e).message)
            ),
        }
    }
}

/// Send one request and write its answer, or an error with its id.
async fn answer(conn: &Arc<Conn>, msg: &Value, id: &Value, method: &str, tracked: bool) {
    let failure = match conn.forward(msg, Some(id), method, tracked).await {
        Ok(true) => return,
        Ok(false) => fail(
            "no_answer",
            "attenuo connect: the attenuo server sent no answer to the request",
        ),
        Err(f) => f,
    };
    if failure.reason != LEASE_REVOKED {
        errln!(
            "attenuo connect: {method:?} got no answer: {}",
            bare(&failure.message)
        );
    }
    conn.emit_answer(id, &error_for(id.clone(), &failure), tracked)
        .await;
}

// ---------------------------------------------------------------------------------------------
// The listen stream
// ---------------------------------------------------------------------------------------------

/// Keep the server-to-client stream open (`GET`) and write its requests and notifications to
/// stdout. Ends when the proxy answers `405` (the upstream has none), `404` (the session is
/// gone; the next request opens a new one and this stream again) or `lease_revoked`.
async fn listen(conn: Arc<Conn>) {
    let mut failures = 0u32;
    let mut last_id: Option<String> = None;
    loop {
        match conn.tokens.for_request().await {
            Ok((token, generation)) => {
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
                // A bound on the headers only: the stream itself may stay quiet for hours.
                match tokio::time::timeout(SHORT_TIMEOUT, req.send()).await {
                    Ok(Ok(resp)) if resp.status() == StatusCode::METHOD_NOT_ALLOWED => return,
                    Ok(Ok(resp)) if resp.status() == StatusCode::NOT_FOUND => return,
                    Ok(Ok(resp)) if resp.status() == StatusCode::UNAUTHORIZED => {
                        let bytes = conn
                            .read_bounded(resp, MAX_RENEW_ANSWER)
                            .await
                            .unwrap_or_default();
                        if says_revoked(&serde_json::from_slice(&bytes).unwrap_or(Value::Null)) {
                            conn.on_revoked();
                            return;
                        }
                        if conn.tokens.can_refresh() {
                            let _ = conn.tokens.refresh(generation).await;
                        }
                        failures += 1;
                    }
                    Ok(Ok(resp)) if resp.status().is_success() => {
                        if relay_listen(&conn, resp, &mut last_id).await {
                            failures = 0;
                        }
                        if conn.tokens.is_revoked() {
                            return;
                        }
                        failures += 1;
                    }
                    Ok(Ok(resp)) => {
                        if failures == 0 {
                            errln!(
                                "attenuo connect: the listen stream was refused (HTTP {}); trying again",
                                resp.status()
                            );
                        }
                        failures += 1;
                    }
                    Ok(Err(_)) | Err(_) => failures += 1,
                }
            }
            Err(f) if f.reason == LEASE_REVOKED => return,
            Err(_) => failures += 1,
        }
        tokio::time::sleep(backoff(failures)).await;
    }
}

/// Write the requests and notifications of one listen stream until it ends. `true` when it
/// carried at least one. A response on it (the proxy's end-of-stream error, for one) answers
/// nothing the client sent, so it is not written; one that says `lease_revoked` ends it all.
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
            let Some(v) = event
                .data
                .and_then(|d| serde_json::from_str::<Value>(&d).ok())
                .filter(is_jsonrpc)
            else {
                continue;
            };
            if v.get("method").is_some_and(Value::is_string) {
                conn.emit(&v).await;
                any = true;
            } else if says_revoked(&v) {
                conn.on_revoked();
                return any;
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

/// Replace the token before it runs out and renew the lease, until the task is stopped or
/// the lease is revoked.
async fn keep_fresh(conn: Arc<Conn>) {
    let mut generations = conn.tokens.generation.subscribe();
    let mut seen = 0u64;
    let mut timers = Timers::default();
    // Not reset by a new token: a lease that keeps failing keeps its pause.
    let mut renew_failures = 0u32;
    let mut last_renewal: Option<i64> = None;
    let mut renewing = true;
    loop {
        if conn.tokens.is_revoked() {
            return;
        }
        let generation = *generations.borrow_and_update();
        if generation != seen {
            // A new token: it has a lease of its own, renewed now to learn its window.
            seen = generation;
            let cur = conn.tokens.current();
            timers.refresh_at = if conn.tokens.can_refresh() {
                refresh_time(cur.fetched_ms, cur.exp)
            } else {
                None
            };
            timers.renew_at =
                renewing.then(|| first_renewal(now_ms(), last_renewal, renew_failures));
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
                if conn.tokens.refresh(seen).await.is_err() {
                    // The failure is logged where it happened.
                    let floor = now_ms().saturating_add(MIN_DELAY_MS);
                    timers.refresh_at =
                        Some(conn.tokens.retry_at().map_or(floor, |at| at.max(floor)));
                } else if *generations.borrow() == seen {
                    timers.refresh_at = Some(now_ms().saturating_add(MIN_DELAY_MS));
                }
            }
            Next::Renew => {
                last_renewal = Some(now_ms());
                match conn.renew().await {
                    Renewal::Renewed { expires_in } => {
                        renew_failures = 0;
                        timers.renew_at =
                            Some(now_ms().saturating_add(ms(renew_delay(expires_in))));
                    }
                    Renewal::Revoked => {
                        conn.on_revoked();
                        return;
                    }
                    Renewal::NeedToken(why) => {
                        renew_failures = renew_failures.saturating_add(1);
                        timers.renew_at = None;
                        if conn.tokens.can_refresh() {
                            let pause = backoff(renew_failures);
                            errln!(
                                "attenuo connect: renewing the lease failed: {why}; a new token \
                                 is fetched in {} s",
                                pause.as_secs()
                            );
                            let at = now_ms().saturating_add(ms(pause));
                            timers.refresh_at = Some(timers.refresh_at.map_or(at, |r| r.min(at)));
                        } else {
                            errln!(
                                "attenuo connect: renewing the lease failed: {why}, and the token \
                                 from {} cannot be replaced; renewal stops and calls will be \
                                 refused",
                                crate::secrets::TOKEN_ENV
                            );
                            renewing = false;
                        }
                    }
                    Renewal::Retry(why) => {
                        renew_failures = renew_failures.saturating_add(1);
                        let pause = backoff(renew_failures);
                        errln!(
                            "attenuo connect: renewing the lease failed: {why}; trying again in {} s",
                            pause.as_secs()
                        );
                        timers.renew_at = Some(now_ms().saturating_add(ms(pause)));
                    }
                }
            }
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

/// Why the main loop stopped before the end of stdin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    Signal,
    Revoked,
}

/// A request in flight: how to stop its task, and its share of `--max-in-flight`.
struct Flight {
    task: Option<AbortHandle>,
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

/// What the main loop keeps: the requests in flight in their own tasks.
struct Front {
    conn: Arc<Conn>,
    tasks: JoinSet<()>,
    permits: Arc<Semaphore>,
    max_in_flight: usize,
}

impl Front {
    async fn on_line(&mut self, line: Line) {
        let conn = &self.conn;
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
                // In order: what the client sends next needs the session it opens. In the
                // table too, so that it is answered if the lease is revoked meanwhile.
                let tracked = conn
                    .in_flight
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(
                        id_key(&id),
                        Flight {
                            task: None,
                            _permit: None,
                        },
                    )
                    .is_none();
                answer(conn, &msg, &id, &method, tracked).await;
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
                let key = id_key(&id);
                let busy = {
                    // The table is held while the task starts, so that its answer cannot be
                    // written before its entry is in.
                    let mut table = conn
                        .in_flight
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if table.contains_key(&key) {
                        Some(id)
                    } else {
                        let task_conn = conn.clone();
                        let handle = self.tasks.spawn(async move {
                            answer(&task_conn, &msg, &id, &method, true).await;
                        });
                        table.insert(
                            key,
                            Flight {
                                task: Some(handle),
                                _permit: Some(permit),
                            },
                        );
                        None
                    }
                };
                if let Some(id) = busy {
                    conn.emit(&rpc_error(
                        id,
                        INVALID_REQUEST,
                        "attenuo connect: a request with this id is already waiting for an answer",
                    ))
                    .await;
                }
            }
            FromCaller::Notification { method } => {
                if method == "notifications/cancelled" {
                    if let Some(rid) = msg.pointer("/params/requestId") {
                        self.cancel(rid);
                    }
                }
                let ok = self.deliver(&msg, &method).await;
                if ok && method == "notifications/initialized" {
                    conn.start_listen();
                }
            }
            FromCaller::Response => {
                self.deliver(&msg, "a response").await;
            }
        }
    }

    /// The client cancelled request `id`: stop its task and free its place. It gets no
    /// answer.
    fn cancel(&self, id: &Value) {
        let entry = self
            .conn
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id_key(id));
        if let Some(task) = entry.and_then(|f| f.task) {
            task.abort();
        }
    }

    /// Send a notification or a response; failures are only logged.
    async fn deliver(&self, msg: &Value, what: &str) -> bool {
        let r =
            tokio::time::timeout(NOTIFY_TIMEOUT, self.conn.forward(msg, None, what, false)).await;
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

    /// After `lease_revoked`: stop every request in flight and answer each with an error.
    async fn answer_all_revoked(&mut self) {
        let left: Vec<(String, Flight)> = self
            .conn
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain()
            .collect();
        for (_, flight) in &left {
            if let Some(task) = &flight.task {
                task.abort();
            }
        }
        self.tasks.abort_all();
        let failure = revoked_failure();
        for (key, _) in left {
            let id: Value = serde_json::from_str(&key).unwrap_or(Value::Null);
            self.conn.emit(&error_for(id, &failure)).await;
        }
        while self.tasks.join_next().await.is_some() {}
    }
}

/// `attenuo connect`. The exit status: 0, or [`EXIT_REVOKED`] after `lease_revoked`.
pub(crate) async fn run(server: &str, args: ConnectArgs, tls: &crate::tls::Tls) -> Result<u8> {
    let base = check_server(server)?;
    attenuo_core::names::check_server_name(&args.upstream)
        .map_err(|e| anyhow!("--upstream is not a valid upstream name: {e}"))?;
    let source = Source::from_args(&args)?;
    if cleartext_to_remote(&base) {
        errln!(
            "attenuo connect: warning: --server is http:// to a host that is not loopback, so \
             the delegation token travels in cleartext for as long as this runs; use https://"
        );
    }
    let tokens = Tokens::start(source).await?;
    // Every request goes to `--server`: its CA and the client certificate, when given.
    let http = tls.build(
        crate::tls::Target::Server,
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT),
    )?;
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
        handshake: Mutex::new((None, None)),
        resuming: tokio::sync::Mutex::new(None),
        listen: Mutex::new(None),
        in_flight: Mutex::new(HashMap::new()),
    });
    errln!(
        "attenuo connect: forwarding MCP messages from standard input to {}",
        conn.url
    );
    let fresh = tokio::spawn(keep_fresh(conn.clone()));
    let mut input = read_stdin(max_message);
    let mut front = Front {
        conn: conn.clone(),
        tasks: JoinSet::new(),
        permits: Arc::new(Semaphore::new(max_in_flight)),
        max_in_flight,
    };
    let mut revoked = conn.tokens.revoked.subscribe();
    let stop = async move {
        tokio::select! {
            () = stop_signal() => Stop::Signal,
            r = revoked.wait_for(|r| *r) => match r {
                Ok(_) => Stop::Revoked,
                Err(_) => std::future::pending().await,
            },
        }
    };
    tokio::pin!(stop);
    let mut stopped = None;
    loop {
        let line = tokio::select! {
            line = input.recv() => line,
            why = &mut stop => {
                stopped = Some(why);
                break;
            }
            Some(_) = front.tasks.join_next(), if !front.tasks.is_empty() => continue,
        };
        let Some(line) = line else { break };
        // A line may wait on the network or on stdout: a stop is seen meanwhile too.
        tokio::select! {
            () = front.on_line(line) => {}
            why = &mut stop => {
                stopped = Some(why);
                break;
            }
        }
    }
    drop(input);
    let revoked = stopped == Some(Stop::Revoked) || conn.tokens.is_revoked();
    if stopped == Some(Stop::Signal) {
        errln!("attenuo connect: stopping on a signal");
    }
    if revoked {
        conn.stop_listen();
        fresh.abort();
        let _ = tokio::time::timeout(STOP_GRACE, front.answer_all_revoked()).await;
        errln!(
            "attenuo connect: the lease was revoked (lease_revoked). This is final: requests in \
             flight were answered with an error, and attenuo connect exits. Restart it with a new \
             token to start again"
        );
    } else {
        let finished = tokio::time::timeout(STOP_GRACE, async {
            while front.tasks.join_next().await.is_some() {}
        })
        .await;
        if finished.is_err() {
            errln!(
                "attenuo connect: {} request(s) still waiting after {} s were dropped",
                front.tasks.len(),
                STOP_GRACE.as_secs()
            );
            front.tasks.abort_all();
        }
        conn.stop_listen();
        fresh.abort();
        conn.end_session().await;
    }
    let code = if revoked { EXIT_REVOKED } else { 0 };
    if tokio::time::timeout(FLUSH_GRACE, conn.flush())
        .await
        .is_err()
    {
        // A write to stdout is stuck (the client does not read it). The runtime would wait for
        // it at the end, so the process ends here.
        errln!("attenuo connect: standard output is not being read; exiting without the rest");
        std::process::exit(i32::from(code));
    }
    Ok(code)
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
        // Already expired, or about to: never sooner than a second after the fetch, so that
        // nothing spins.
        assert_eq!(refresh_time(1_000_000, Some(900)), Some(1_001_000));
        assert_eq!(refresh_time(1_000_000, Some(1000)), Some(1_001_000));
        assert_eq!(refresh_time(1_000_000, Some(1001)), Some(1_001_000));
        // Unknown expiry: only a 401 replaces it.
        assert_eq!(refresh_time(1_000_000, None), None);
        // An `exp` from an unverified token can be anything: no overflow.
        assert_eq!(
            refresh_time(1_000_000, Some(i64::MAX)),
            Some(1_000_000 + (i64::MAX - 1_000_000) / 3 * 2)
        );
        assert_eq!(refresh_time(i64::MAX, Some(i64::MAX)), Some(i64::MAX));
        assert_eq!(refresh_time(1_000_000, Some(i64::MIN)), Some(1_001_000));
        assert_eq!(seconds_left(i64::MAX, 1_000_000), i64::MAX - 1_000);
        assert_eq!(seconds_left(i64::MIN, 1_000_000), i64::MIN);
        assert_eq!(seconds_left(1_900, 1_000_000), 900);
    }

    #[test]
    fn a_fetched_token_must_be_new_and_not_about_to_expire() {
        let now = 1_000_000;
        assert_eq!(judge_fetched("b", Some("a"), Some(2_000), now), Ok(()));
        assert_eq!(judge_fetched("b", None, None, now), Ok(()));
        assert_eq!(judge_fetched("b", None, Some(i64::MAX), now), Ok(()));
        assert!(judge_fetched("a", Some("a"), Some(2_000), now)
            .unwrap_err()
            .contains("same token"));
        assert!(judge_fetched("a", Some("a"), None, now).is_err());
        assert!(judge_fetched("b", None, Some(999), now)
            .unwrap_err()
            .contains("expired"));
        assert!(judge_fetched("b", None, Some(1_000), now).is_err());
        assert!(judge_fetched("b", None, Some(1_004), now)
            .unwrap_err()
            .contains("less than 5 s"));
        assert_eq!(judge_fetched("b", None, Some(1_006), now), Ok(()));
        assert!(judge_fetched("b", None, Some(i64::MIN), now).is_err());
    }

    #[test]
    fn a_new_token_is_renewed_at_once_unless_renewals_were_failing() {
        assert_eq!(first_renewal(10_000, None, 0), 10_000);
        // The last renewal was fine: at most one a second.
        assert_eq!(first_renewal(10_000, Some(9_500), 0), 10_500);
        assert_eq!(first_renewal(10_000, Some(1_000), 0), 10_000);
        // Failing: the pause the failures earned, counted from the last try.
        assert_eq!(first_renewal(10_000, Some(9_000), 3), 13_000);
        assert_eq!(first_renewal(10_000, Some(9_000), 99), 39_000);
        assert_eq!(first_renewal(i64::MAX, Some(i64::MAX), 99), i64::MAX);
    }

    #[test]
    fn env_assignments_are_recognised_without_running_a_shell() {
        for yes in ["A=1", "TOKEN=secret", "_x=", "a_B9=c=d"] {
            assert!(is_env_assignment(yes), "{yes}");
        }
        for no in ["attenuo", "=x", "9A=1", "a-b=1", "/bin/x=y", "--cap=x", ""] {
            assert!(!is_env_assignment(no), "{no}");
        }
    }

    #[test]
    fn cleartext_to_a_remote_host_is_noticed() {
        for remote in [
            "http://attenuo.example",
            "http://10.0.0.5:8080",
            "http://[2001:db8::1]:8080",
        ] {
            assert!(cleartext_to_remote(remote), "{remote}");
        }
        for fine in [
            "https://attenuo.example",
            "http://127.0.0.1:8080",
            "http://127.1.2.3",
            "http://[::1]:8080",
            "http://localhost:8080",
            "http://LOCALHOST",
            "http://a.localhost",
        ] {
            assert!(!cleartext_to_remote(fine), "{fine}");
        }
    }

    #[test]
    fn lease_revoked_is_read_from_rpc_errors_and_error_bodies() {
        assert!(says_revoked(&json!({"jsonrpc":"2.0","id":null,
            "error":{"code":-32001,"message":"m","data":{"reason":"lease_revoked"}}})));
        assert!(says_revoked(
            &json!({"error":"invalid_grant","code":"lease_revoked"})
        ));
        assert!(!says_revoked(&json!({"jsonrpc":"2.0","id":1,
            "error":{"code":-32001,"message":"m","data":{"reason":"invalid_token"}}})));
        assert!(!says_revoked(&json!({"jsonrpc":"2.0","id":1,"result":{}})));
        // A notification from the server is not a refusal, whatever it carries.
        assert!(!says_revoked(
            &json!({"jsonrpc":"2.0","method":"x","code":"lease_revoked"})
        ));
    }

    #[test]
    fn debug_prints_hide_the_token_command_arguments() {
        let s = Source::Command {
            program: "get-token".into(),
            args: vec!["--secret".into(), "hunter2".into()],
            timeout: Duration::from_secs(1),
        };
        let printed = format!("{s:?}");
        assert!(printed.contains("get-token"), "{printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
        assert!(!printed.contains("hunter2"), "{printed}");
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
        assert_eq!(
            classify_renewal(401, r#"{"error":"unauthorized","code":"lease_revoked"}"#),
            Renewal::Revoked
        );
        for code in ["lease_expired", "lease_unknown"] {
            assert!(matches!(
                classify_renewal(
                    400,
                    &format!(r#"{{"error":"invalid_grant","code":"{code}"}}"#)
                ),
                Renewal::NeedToken(why) if why.contains(code)
            ));
        }
        // A 401 (a bad or expired token): the same token will not do better, so only a new
        // one helps.
        assert!(matches!(
            classify_renewal(401, r#"{"error":"unauthorized","code":"token_expired"}"#),
            Renewal::NeedToken(_)
        ));
        assert!(matches!(classify_renewal(401, ""), Renewal::NeedToken(_)));
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
