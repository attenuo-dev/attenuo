//! A thin HTTP client for the attenuo server.

use anyhow::{anyhow, bail, Context, Result};
use attenuo_token::dpop::{DPOP_NONCE_HEADER, USE_DPOP_NONCE};
use attenuo_token::DpopKey;
use reqwest::header::HeaderMap;
use reqwest::{RequestBuilder, StatusCode};
use serde_json::{json, Value};
use std::sync::Mutex;

use crate::render::escape_controls;
use crate::tls::{Target, Tls};

/// Present `token` with a DPoP proof by `key` for `method` and `url` (RFC 9449 §7.1:
/// `Authorization: DPoP <token>` and a `DPoP` header whose `ath` covers the token), or as a
/// plain bearer without a key.
fn present(
    req: RequestBuilder,
    token: &str,
    key: Option<&DpopKey>,
    method: &str,
    url: &str,
    nonce: Option<&str>,
) -> RequestBuilder {
    match key {
        Some(k) => req.header("authorization", format!("DPoP {token}")).header(
            "dpop",
            k.proof_with_nonce(
                method,
                url,
                Some(token),
                nonce,
                time::OffsetDateTime::now_utc(),
            ),
        ),
        None => req.bearer_auth(token),
    }
}

/// `url` without a trailing `/`, if it is an `http://` or `https://` URL.
fn base_url(url: &str) -> Result<String> {
    let base = url.trim_end_matches('/').to_string();
    if !(base.starts_with("http://") || base.starts_with("https://")) {
        bail!(
            "--server must be the attenuo server's base URL (http://host:port), got `{base}`. \
             To name an MCP upstream, use `--upstream <name>` after the subcommand."
        );
    }
    Ok(base)
}

/// A response read in full: status, headers and body text.
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    text: String,
    /// Whether a bare 404 to this request should carry [`ADMIN_LISTENER_HINT`].
    admin_hint: bool,
}

/// Added under a 404 without an error code (the server's answer to a route it does not have,
/// not its JSON `not_found` for a missing lease or record) to an `/admin/*` request sent to
/// `--server` because no `--admin-server` was given.
const ADMIN_LISTENER_HINT: &str = "hint: the server may serve its admin API on a separate \
     listener ([admin] listen); pass --admin-server URL (or set ATTENUO_ADMIN_SERVER)";

/// Added under a 404 without an error code to `POST /admin/root-token`: the server mounts that
/// route only with the development root mint on, so a server that runs its config as shipped
/// answers it like an unknown path.
const ROOT_MINT_HINT: &str = "hint: POST /admin/root-token exists only when the server's config \
     sets [dev] allow_root_mint = true (development only); for a root token from a user's \
     identity provider, use `attenuo token exchange --subject-token-type id-token`";

pub(crate) struct Client {
    /// Sends to the origin of `--server` only: `--tls-ca-cert` and the client certificate,
    /// when given. [`Client::client_for`] is the only place that hands it out.
    http: reqwest::Client,
    /// Sends to every other origin (`--admin-server`): `--tls-ca-cert`, never the client
    /// certificate. Requests are also built with it, so a request sent from its builder
    /// directly carries no certificate either.
    plain_http: reqwest::Client,
    base: String,
    /// Where `/admin/*` goes: `--admin-server` when given, else `base`.
    admin_base: String,
    /// Whether `admin_base` was given (`--admin-server` or `ATTENUO_ADMIN_SERVER`).
    admin_base_given: bool,
    admin_token: Option<String>,
    /// The latest `DPoP-Nonce` this server sent (RFC 9449 §8), for the next proof. Never
    /// printed or logged.
    nonce: Mutex<Option<String>>,
}

impl Client {
    /// A client for the server at `base`, sending `/admin/*` to `admin_base` instead when
    /// given (`--admin-server`, for a server with `[admin] listen`), with the `--tls-*`
    /// options in `tls`.
    pub(crate) fn new(
        base: &str,
        admin_base: Option<&str>,
        admin_token: Option<String>,
        tls: &Tls,
    ) -> Result<Self> {
        let base = base_url(base)?;
        let admin_base_given = admin_base.is_some();
        let admin_base = match admin_base {
            Some(a) => base_url(a).map_err(|_| {
                anyhow!(
                    "--admin-server must be the base URL of the server's admin listener \
                     (http://host:port), got `{}`",
                    a.trim_end_matches('/')
                )
            })?,
            None => base.clone(),
        };
        Ok(Self {
            http: tls.build(Target::Server, client_builder())?,
            plain_http: tls.build(Target::Admin, client_builder())?,
            base,
            admin_base,
            admin_base_given,
            admin_token,
            nonce: Mutex::new(None),
        })
    }

    /// Whether an admin token was given (flag, file, stdin or `ATTENUO_ADMIN_TOKEN`).
    pub(crate) fn has_admin_token(&self) -> bool {
        self.admin_token.is_some()
    }

    /// The nonce to put in the next proof, if the server has sent one.
    fn current_nonce(&self) -> Option<String> {
        self.nonce.lock().ok().and_then(|n| n.clone())
    }

    /// Send the request `build` makes (given the nonce for its proof) and read the reply.
    /// Keeps the response's `DPoP-Nonce`; when `dpop` is set and the server refused the proof
    /// with `use_dpop_nonce` and sent a nonce, builds and sends the request once more with it
    /// (RFC 9449 §8.2).
    /// `path` is the API path the request is for (`/token`, `/admin/...`), without any
    /// prefix of the base URL; it chooses the messages, not the client.
    async fn send_dpop(
        &self,
        path: &str,
        dpop: bool,
        mut build: impl FnMut(Option<&str>) -> Result<RequestBuilder>,
    ) -> Result<Reply> {
        let mut retried = false;
        let admin_hint = self.hints_admin_listener(path);
        loop {
            let req = build(self.current_nonce().as_deref())?;
            let resp = self.execute(path, req).await?;
            let status = resp.status();
            let headers = resp.headers().clone();
            let text = resp.text().await?;
            let fresh = headers
                .get(DPOP_NONCE_HEADER)
                .and_then(|v| v.to_str().ok())
                .filter(|v| !v.is_empty())
                .map(str::to_owned);
            let has_fresh = fresh.is_some();
            if let Some(n) = fresh {
                if let Ok(mut slot) = self.nonce.lock() {
                    *slot = Some(n);
                }
            }
            if dpop && !retried && has_fresh && is_use_dpop_nonce(status, &headers, &text) {
                retried = true;
                continue;
            }
            return Ok(Reply {
                status,
                headers,
                text,
                admin_hint,
            });
        }
    }

    /// The base URL that serves `path`: the admin listener's for `/admin` and everything
    /// under it, the main listener's for the rest. The only place that chooses between them.
    fn base_for(&self, path: &str) -> &str {
        if is_admin_path(path) {
            &self.admin_base
        } else {
            &self.base
        }
    }

    /// The HTTP client for a request to `url`, chosen by the URL the request goes to, never
    /// by the API path: the `--server` client (with the client certificate) only when `url`
    /// has the origin (scheme, host and port) of `--server`, the client without the
    /// certificate for every other URL. So `--admin-server` on another origin never gets the
    /// certificate, whatever prefix either base URL has. One on the same origin as
    /// `--server` is the same host, and does.
    fn client_for(&self, url: &reqwest::Url) -> &reqwest::Client {
        match (origin(url.as_str()), origin(&self.base)) {
            (Some(a), Some(b)) if a == b => &self.http,
            _ => &self.plain_http,
        }
    }

    /// The client for a full URL that is not built from `--server` or `--admin-server` (an
    /// `approval verify --jwks` URL): [`Client::client_for`]'s choice, so the certificate
    /// goes only to the origin of `--server`, and `--tls-ca-cert` applies either way.
    pub(crate) fn http_for_url(&self, url: &str) -> Result<reqwest::Client> {
        let url = reqwest::Url::parse(url).with_context(|| format!("`{url}` is not a URL"))?;
        Ok(self.client_for(&url).clone())
    }

    /// Send `req` (for the API path `path`) with [`Client::client_for`]'s client, and refuse
    /// a redirect.
    async fn execute(&self, path: &str, req: RequestBuilder) -> Result<reqwest::Response> {
        let req = req.build()?;
        let resp = self
            .client_for(req.url())
            .execute(req)
            .await
            .with_context(|| format!("could not reach the server at {}", self.base_for(path)))?;
        refuse_redirect(&resp, self.flag_for(path))?;
        Ok(resp)
    }

    /// The flag that sets the base URL serving `path`, for [`refuse_redirect`]'s message.
    fn flag_for(&self, path: &str) -> &'static str {
        if is_admin_path(path) && self.admin_base_given {
            "--admin-server"
        } else {
            "--server"
        }
    }

    /// Whether a bare 404 to `path` gets [`ADMIN_LISTENER_HINT`]: an `/admin/*` path sent to
    /// `--server` because no admin listener was named.
    fn hints_admin_listener(&self, path: &str) -> bool {
        !self.admin_base_given && is_admin_path(path)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_for(path), path)
    }

    fn admin(&self, req: RequestBuilder) -> Result<RequestBuilder> {
        let token = self.admin_token.as_deref().ok_or_else(|| {
            anyhow!(
                "this command needs the admin token: pass --admin-token or set ATTENUO_ADMIN_TOKEN"
            )
        })?;
        Ok(req.bearer_auth(token))
    }

    async fn send_json(&self, path: &str, req: RequestBuilder) -> Result<Value> {
        let mut req = Some(req);
        let reply = self
            .send_dpop(path, false, |_| Ok(req.take().expect("sent once")))
            .await?;
        json_reply(reply)
    }

    /// `GET` an unauthenticated path within `timeout` and hand back the status and body as
    /// they came, whatever the status (`attenuo health`).
    pub(crate) async fn probe(
        &self,
        path: &str,
        timeout: std::time::Duration,
    ) -> Result<(StatusCode, String)> {
        let req = self.plain_http.get(self.url(path)).timeout(timeout);
        let resp = self.execute(path, req).await?;
        let status = resp.status();
        Ok((status, resp.text().await?))
    }

    pub(crate) async fn get(&self, path: &str) -> Result<Value> {
        self.send_json(path, self.plain_http.get(self.url(path)))
            .await
    }

    pub(crate) async fn admin_get(&self, path: &str) -> Result<Value> {
        self.send_json(path, self.admin(self.plain_http.get(self.url(path)))?)
            .await
    }

    /// `GET` an admin path and hand back the response for the caller to read incrementally
    /// (the audit export). Non-success statuses become errors; the long timeout is for a big
    /// export, not for a hung server.
    pub(crate) async fn admin_get_stream(&self, path: &str) -> Result<reqwest::Response> {
        let req = self
            .admin(self.plain_http.get(self.url(path)))?
            .timeout(std::time::Duration::from_secs(3600));
        let resp = self.execute(path, req).await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let err = api_error(status, &resp.text().await?);
        Err(if self.hints_admin_listener(path) {
            with_admin_hint(err)
        } else {
            err
        })
    }

    pub(crate) async fn admin_post(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_json(
            path,
            self.admin(self.plain_http.post(self.url(path)).json(body))?,
        )
        .await
    }

    /// `POST /admin/root-token`, bound to `key` when given (a DPoP proof in the header).
    pub(crate) async fn root(&self, body: &Value, key: Option<&DpopKey>) -> Result<Value> {
        let path = "/admin/root-token";
        let url = self.url(path);
        let reply = self
            .send_dpop(path, key.is_some(), |nonce| {
                let mut req = self.admin(self.plain_http.post(&url).json(body))?;
                if let Some(k) = key {
                    req = req.header(
                        "dpop",
                        k.proof_with_nonce(
                            "POST",
                            &url,
                            None,
                            nonce,
                            time::OffsetDateTime::now_utc(),
                        ),
                    );
                }
                Ok(req)
            })
            .await?;
        json_reply(reply).map_err(|e| with_hint_on_bare_404(e, ROOT_MINT_HINT))
    }

    /// The URL of `POST /token`, which DPoP proofs for an exchange name.
    pub(crate) fn token_url(&self) -> String {
        self.url("/token")
    }

    /// `POST /token` with an RFC 8693 JSON body. `proof` makes the `DPoP` header for the
    /// nonce it is given (none without a DPoP key); it runs again if the server asks for its
    /// nonce.
    pub(crate) async fn exchange(
        &self,
        body: &Value,
        proof: impl Fn(Option<&str>) -> Result<Option<String>>,
    ) -> Result<Value> {
        let dpop = proof(None)?.is_some();
        let reply = self
            .send_dpop("/token", dpop, |nonce| {
                let mut req = self.plain_http.post(self.url("/token")).json(body);
                if let Some(p) = proof(nonce)? {
                    req = req.header("dpop", p);
                }
                Ok(req)
            })
            .await?;
        json_reply(reply)
    }

    /// `POST /access/v1/evaluation` with the delegation token as bearer.
    pub(crate) async fn authzen(
        &self,
        token: &str,
        body: &Value,
        key: Option<&DpopKey>,
    ) -> Result<Value> {
        self.post_as_agent("/access/v1/evaluation", token, body, key)
            .await
    }

    /// `POST /access/v1/search/action` with the delegation token as bearer.
    pub(crate) async fn authzen_search_action(
        &self,
        token: &str,
        body: &Value,
        key: Option<&DpopKey>,
    ) -> Result<Value> {
        self.post_as_agent("/access/v1/search/action", token, body, key)
            .await
    }

    /// `POST path` with the delegation token as bearer (and a DPoP proof for that URL).
    async fn post_as_agent(
        &self,
        path: &str,
        token: &str,
        body: &Value,
        key: Option<&DpopKey>,
    ) -> Result<Value> {
        let url = self.url(path);
        let reply = self
            .send_dpop(path, key.is_some(), |nonce| {
                Ok(present(self.plain_http.post(&url), token, key, "POST", &url, nonce).json(body))
            })
            .await?;
        json_reply(reply)
    }

    /// One JSON-RPC request to `/mcp/{server}`. Returns the JSON-RPC response whatever the
    /// HTTP status, since the proxy reports denials as JSON-RPC errors.
    pub(crate) async fn mcp(
        &self,
        token: &str,
        key: Option<&DpopKey>,
        server: &str,
        method: &str,
        params: Value,
    ) -> Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let path = format!("/mcp/{server}");
        let url = self.url(&path);
        let Reply {
            status,
            headers,
            text,
            ..
        } = self
            .send_dpop(&path, key.is_some(), |nonce| {
                Ok(
                    present(self.plain_http.post(&url), token, key, "POST", &url, nonce)
                        .header("accept", "application/json, text/event-stream")
                        .json(&body),
                )
            })
            .await?;
        let is_sse = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("event-stream"));
        // A refusal before the proxy (`{"error": code}`, not JSON-RPC) is an API error.
        match parse_rpc_body(&text, is_sse)
            .filter(|v| status.is_success() || v.get("jsonrpc").is_some())
        {
            Some(v) => Ok(v),
            None if status.is_success() => {
                bail!("no JSON-RPC response in body: {}", escape_controls(&text))
            }
            None => Err(api_error(status, &text)),
        }
    }
}

/// The JSON body of a success, or the server's error.
fn json_reply(reply: Reply) -> Result<Value> {
    let Reply {
        status,
        text,
        admin_hint,
        ..
    } = reply;
    if status.is_success() {
        return serde_json::from_str(&text).with_context(|| {
            format!(
                "server sent non-JSON ({status}): {}",
                escape_controls(&text)
            )
        });
    }
    let err = api_error(status, &text);
    Err(if admin_hint {
        with_admin_hint(err)
    } else {
        err
    })
}

/// The origin of `url` (scheme, host and port, the default port filled in), or `None` for a
/// string that is not a URL with a host.
fn origin(url: &str) -> Option<(String, String, Option<u16>)> {
    let u = reqwest::Url::parse(url).ok()?;
    Some((
        u.scheme().to_owned(),
        u.host_str()?.to_owned(),
        u.port_or_known_default(),
    ))
}

/// Whether `path` is `/admin` or under it, which `--admin-server` serves.
fn is_admin_path(path: &str) -> bool {
    let rest = path.strip_prefix("/admin").unwrap_or("x");
    rest.is_empty() || rest.starts_with(['/', '?'])
}

/// `err` with [`ADMIN_LISTENER_HINT`] on a line of its own when it is a 404 without an error
/// code: the answer to an unknown route. A JSON 404 (`not_found` for a lease, approval or
/// audit record that does not exist) comes from a route that does exist, so it stays as it is.
fn with_admin_hint(err: anyhow::Error) -> anyhow::Error {
    with_hint_on_bare_404(err, ADMIN_LISTENER_HINT)
}

/// `err` with `hint` on a line of its own when it is a 404 without an error code.
fn with_hint_on_bare_404(mut err: anyhow::Error, hint: &str) -> anyhow::Error {
    if let Some(api) = err.downcast_mut::<ApiError>() {
        if api.status == StatusCode::NOT_FOUND && api.code.is_none() {
            api.message.push('\n');
            api.message.push_str(hint);
        }
    }
    err
}

/// Did the server refuse a proof for want of its nonce (RFC 9449 §8)? A 401 with
/// `WWW-Authenticate: DPoP error="use_dpop_nonce"` (attenuo's own routes), or a 400 or 401
/// whose JSON `code` or `error` is `use_dpop_nonce`.
fn is_use_dpop_nonce(status: StatusCode, headers: &HeaderMap, body: &str) -> bool {
    if status != StatusCode::UNAUTHORIZED && status != StatusCode::BAD_REQUEST {
        return false;
    }
    let challenged = headers
        .get_all("www-authenticate")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.contains(USE_DPOP_NONCE));
    challenged
        || serde_json::from_str::<Value>(body)
            .is_ok_and(|v| stable_code(&v) == Some(USE_DPOP_NONCE))
}

/// A non-success answer from the server. Its text is `server answered <status>: <error>
/// (<code>): <detail>` (or the raw body), the ` (<code>)` left out when the stable code is the
/// error or the detail itself, and a second line `decision <id>` when the body names the
/// audit record of the refusal; a command that gives some statuses a meaning of its own (as
/// `budget refund` does for 404 and 409) finds it with `anyhow::Error::downcast_ref`.
#[derive(Debug)]
pub(crate) struct ApiError {
    pub status: StatusCode,
    /// The answer's stable code, when the body is `{"error": ..., ...}`: its `code`, or for a
    /// server that does not send one, its `error_description` sub-code or else its `error`
    /// (see [`stable_code`]).
    pub code: Option<String>,
    /// The JSON body's `detail`, when it has a string one.
    pub detail: Option<String>,
    message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ApiError {}

/// The stable code of a REST error body: `code`, or for a server that does not send one
/// (before audit K-8), the `error_description` sub-code, or else `error`. Only the first is a
/// documented machine field; the fallbacks keep the CLI working against an older server.
pub(crate) fn stable_code(body: &Value) -> Option<&str> {
    [&body["code"], &body["error_description"], &body["error"]]
        .into_iter()
        .find_map(|v| v.as_str().filter(|s| !s.is_empty()))
}

/// The HTTP client of every CLI request: a 30 s timeout and no redirects followed (SR-112).
/// A followed `307` or `308` sends the body again to wherever `Location` names, client
/// secret, client assertion and subject token included; [`refuse_redirect`] reports it
/// instead.
///
/// This one trusts the built-in roots and presents no client certificate: it is for `init`,
/// which talks to an MCP server, not to attenuo. [`Client`] and `approval verify --jwks` add
/// the `--tls-*` options to [`client_builder`] themselves.
pub(crate) fn http_client() -> Result<reqwest::Client> {
    Ok(client_builder().build()?)
}

/// The settings of [`http_client`], before it is built.
pub(crate) fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
}

/// An error for a 3xx answer, naming its status and `Location` (SR-112): the client follows
/// no redirect, so `flag` (`--server`, `--admin-server`, or the URL given) must be the URL
/// that answers without one.
pub(crate) fn refuse_redirect(resp: &reqwest::Response, flag: &str) -> Result<()> {
    let status = resp.status();
    if !status.is_redirection() {
        return Ok(());
    }
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map_or_else(|| "no Location".to_owned(), |l| format!("Location {l}"));
    Err(anyhow!(
        "{} answered {status} ({location}); attenuo does not follow redirects, so {flag} \
         must be the final URL, the one that answers without a redirect",
        resp.url()
    ))
}

/// A server error as `{"error": error, "code": code, "detail": text}`, or the raw body when it
/// is not that, with control characters escaped in the text (SR-118); [`ApiError`]'s `code`
/// and `detail` keep the values as sent.
pub(crate) fn api_error(status: StatusCode, body: &str) -> anyhow::Error {
    let mut detail = None;
    let (code, message) = match serde_json::from_str::<Value>(body) {
        Ok(v) if v["error"].is_string() => {
            detail = v["detail"].as_str().map(str::to_string);
            let error = v["error"].as_str().unwrap_or_default();
            let code = stable_code(&v).unwrap_or(error).to_string();
            // The stable code, after the error, when it says something the error and the
            // detail do not (`invalid_grant (replayed)`, not `not_found (not_found)`).
            let shown_code = if code == error || Some(code.as_str()) == v["detail"].as_str() {
                String::new()
            } else {
                format!(" ({})", escape_controls(&code))
            };
            // A refusal the server audited (a refused token exchange) names its record. Every
            // string of the body is the answerer's, and an upstream MCP server's when the
            // proxy relays its error body: escaped, so none can drive the terminal (SR-118).
            let message = format!(
                "server answered {status}: {}{shown_code}{}{}",
                escape_controls(error),
                v["detail"]
                    .as_str()
                    .map(|d| format!(": {}", escape_controls(d)))
                    .unwrap_or_default(),
                v["decision_id"]
                    .as_str()
                    .map(|id| format!("\ndecision {}", escape_controls(id)))
                    .unwrap_or_default()
            );
            (Some(code), message)
        }
        _ if body.trim().is_empty() => (None, format!("server answered {status}")),
        _ => (
            None,
            format!("server answered {status}: {}", escape_controls(body.trim())),
        ),
    };
    anyhow::Error::new(ApiError {
        status,
        code,
        detail,
        message,
    })
}

/// The JSON-RPC response in a plain JSON or `text/event-stream` body.
pub(crate) fn parse_rpc_body(text: &str, sse: bool) -> Option<Value> {
    if !sse {
        return serde_json::from_str(text).ok();
    }
    text.lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .filter_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
        .find(|v| v.get("result").is_some() || v.get("error").is_some())
}

/// Percent-encode a query value or a path segment (everything but unreserved characters).
pub(crate) fn query_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_and_json_bodies() {
        let v = parse_rpc_body("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}", false).unwrap();
        assert!(v.get("result").is_some());
        let sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"a\":1}}\n\n";
        assert_eq!(parse_rpc_body(sse, true).unwrap()["result"]["a"], 1);
        assert!(parse_rpc_body("event: ping\n\n", true).is_none());
        assert!(parse_rpc_body("<html>", false).is_none());
    }

    #[test]
    fn api_error_formats() {
        let e = api_error(
            StatusCode::FORBIDDEN,
            r#"{"error":"no_root_grant","detail":"no entry"}"#,
        );
        assert_eq!(
            e.to_string(),
            "server answered 403 Forbidden: no_root_grant: no entry"
        );
        assert_eq!(
            api_error(
                StatusCode::BAD_REQUEST,
                r#"{"error":"invalid_scope","detail":"wider","decision_id":"d-1"}"#,
            )
            .to_string(),
            "server answered 400 Bad Request: invalid_scope: wider\ndecision d-1"
        );
        assert_eq!(
            api_error(StatusCode::BAD_GATEWAY, "oops").to_string(),
            "server answered 502 Bad Gateway: oops"
        );
    }

    #[test]
    fn api_error_names_the_stable_code_when_it_adds_something() {
        let text = |status, body| api_error(status, body).to_string();
        // A code other than the error and the detail goes in parentheses after the error.
        assert_eq!(
            text(
                StatusCode::BAD_REQUEST,
                r#"{"error":"invalid_grant","code":"replayed","detail":"this credential was already used"}"#,
            ),
            "server answered 400 Bad Request: invalid_grant (replayed): this credential was \
             already used"
        );
        // With a decision line, and without a detail.
        assert_eq!(
            text(
                StatusCode::BAD_REQUEST,
                r#"{"error":"invalid_grant","code":"replayed","decision_id":"d-1"}"#,
            ),
            "server answered 400 Bad Request: invalid_grant (replayed)\ndecision d-1"
        );
        // A code equal to the error, or to the detail, is not said twice.
        assert_eq!(
            text(
                StatusCode::NOT_FOUND,
                r#"{"error":"not_found","code":"not_found","detail":"no such lease"}"#,
            ),
            "server answered 404 Not Found: not_found: no such lease"
        );
        assert_eq!(
            text(
                StatusCode::UNAUTHORIZED,
                r#"{"error":"unauthorized","code":"token_expired","detail":"token_expired"}"#,
            ),
            "server answered 401 Unauthorized: unauthorized: token_expired"
        );
        // No code: the error alone (the stable code falls back to it).
        assert_eq!(
            text(
                StatusCode::FORBIDDEN,
                r#"{"error":"no_root_grant","detail":"no entry"}"#
            ),
            "server answered 403 Forbidden: no_root_grant: no entry"
        );
        // A server before `code`: its `error_description` sub-code is the stable code.
        assert_eq!(
            text(
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"temporarily_unavailable","detail":"x","error_description":"overloaded"}"#,
            ),
            "server answered 503 Service Unavailable: temporarily_unavailable (overloaded): x"
        );
        // A body that is not an error object is printed as it came, with no code.
        assert_eq!(
            text(StatusCode::BAD_GATEWAY, r#"<html>bad gateway</html>"#),
            "server answered 502 Bad Gateway: <html>bad gateway</html>"
        );
        assert_eq!(
            text(StatusCode::BAD_REQUEST, r#"{"code":"replayed"}"#),
            r#"server answered 400 Bad Request: {"code":"replayed"}"#
        );
    }

    /// Whoever answers at the server URL (or an upstream MCP server whose error body the proxy
    /// relays with its status) chooses every string of a refusal: none of them reaches the
    /// terminal with a control character in it (SR-118). The CLI's own line break before
    /// `decision` is the only one left.
    #[test]
    fn api_error_escapes_control_characters_sr118() {
        let text = |status, body| api_error(status, body).to_string();
        let shown = text(
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_grant\u001b[2J","code":"replayed\u001b]52;c;aGk=\u0007",
                "detail":"used\nerror: FORGED\r\u009b31m","decision_id":"d-1\u001b[8m"}"#,
        );
        assert_eq!(
            shown,
            "server answered 400 Bad Request: invalid_grant\\u{1b}[2J \
             (replayed\\u{1b}]52;c;aGk=\\u{7}): used\\nerror: FORGED\\r\\u{9b}31m\n\
             decision d-1\\u{1b}[8m"
        );
        assert_eq!(shown.matches('\n').count(), 1, "{shown:?}");
        assert!(!shown.replace('\n', "").chars().any(char::is_control));
        // A body that is not an error object, printed as it came, is escaped too.
        let raw = text(StatusCode::BAD_GATEWAY, "\u{1b}[31mbad gateway\n\u{7}");
        assert_eq!(
            raw,
            "server answered 502 Bad Gateway: \\u{1b}[31mbad gateway\\n\\u{7}"
        );
        // The machine fields keep the server's values: a caller compares them, nothing prints them.
        let e = api_error(
            StatusCode::BAD_REQUEST,
            r#"{"error":"x","code":"a\u001bb"}"#,
        );
        let api = e.downcast_ref::<ApiError>().unwrap();
        assert_eq!(api.code.as_deref(), Some("a\u{1b}b"));
    }

    #[test]
    fn api_error_keeps_status_and_code_for_callers() {
        let e = api_error(
            StatusCode::CONFLICT,
            r#"{"error":"already_refunded","detail":"once"}"#,
        );
        let api = e.downcast_ref::<ApiError>().unwrap();
        assert_eq!(api.status, StatusCode::CONFLICT);
        assert_eq!(api.code.as_deref(), Some("already_refunded"));
        assert_eq!(api.detail.as_deref(), Some("once"));
        let e = api_error(StatusCode::NOT_FOUND, "");
        let api = e.downcast_ref::<ApiError>().unwrap();
        assert_eq!(
            (api.status, api.code.as_deref()),
            (StatusCode::NOT_FOUND, None)
        );
        assert_eq!(e.to_string(), "server answered 404 Not Found");
        // K-8: `code` is the stable code; the message still names `error`.
        let e = api_error(
            StatusCode::UNAUTHORIZED,
            r#"{"error":"unauthorized","code":"token_expired","detail":"token_expired","error_description":"token_expired"}"#,
        );
        let api = e.downcast_ref::<ApiError>().unwrap();
        assert_eq!(api.code.as_deref(), Some("token_expired"));
        assert_eq!(
            e.to_string(),
            "server answered 401 Unauthorized: unauthorized: token_expired"
        );
        // A server without `code`: the sub-code, else `error`.
        let sub =
            r#"{"error":"temporarily_unavailable","detail":"x","error_description":"overloaded"}"#;
        let e = api_error(StatusCode::SERVICE_UNAVAILABLE, sub);
        let api = e.downcast_ref::<ApiError>().unwrap();
        assert_eq!(api.code.as_deref(), Some("overloaded"));
        // `code` wins over the deprecated `error_description`.
        let both = r#"{"error":"invalid_grant","code":"replayed","error_description":"other"}"#;
        let e = api_error(StatusCode::BAD_REQUEST, both);
        let api = e.downcast_ref::<ApiError>().unwrap();
        assert_eq!(api.code.as_deref(), Some("replayed"));
    }

    #[test]
    fn use_dpop_nonce_is_recognised_by_challenge_or_error_code() {
        let mut challenge = HeaderMap::new();
        challenge.insert(
            "www-authenticate",
            "DPoP error=\"use_dpop_nonce\"".parse().unwrap(),
        );
        let none = HeaderMap::new();
        let unauthorized = StatusCode::UNAUTHORIZED;
        assert!(is_use_dpop_nonce(unauthorized, &challenge, ""));
        assert!(is_use_dpop_nonce(
            StatusCode::BAD_REQUEST,
            &none,
            r#"{"error":"use_dpop_nonce"}"#
        ));
        assert!(is_use_dpop_nonce(
            unauthorized,
            &none,
            r#"{"error":"use_dpop_nonce","detail":"x"}"#
        ));
        assert!(is_use_dpop_nonce(
            unauthorized,
            &none,
            r#"{"error":"use_dpop_nonce","code":"use_dpop_nonce","detail":"x"}"#
        ));
        // Other refusals, other statuses and non-JSON bodies are not nonce requests.
        assert!(!is_use_dpop_nonce(
            unauthorized,
            &none,
            r#"{"error":"invalid_dpop_proof"}"#
        ));
        assert!(!is_use_dpop_nonce(unauthorized, &none, "<html>"));
        assert!(!is_use_dpop_nonce(StatusCode::FORBIDDEN, &challenge, ""));
        assert!(!is_use_dpop_nonce(StatusCode::OK, &challenge, ""));
    }

    #[test]
    fn admin_listener_hint_only_for_a_bare_404_to_an_implicit_admin_base() {
        let one = Client::new("http://main:8080", None, None, &Tls::default()).unwrap();
        assert!(one.hints_admin_listener("/admin/audit/verify"));
        assert!(one.hints_admin_listener("/admin"));
        for path in ["/token", "/mcp/admin", "/administer", "/healthz"] {
            assert!(!one.hints_admin_listener(path), "{path}");
        }
        let split = Client::new(
            "http://main:8080",
            Some("http://adm:9102"),
            None,
            &Tls::default(),
        )
        .unwrap();
        assert!(!split.hints_admin_listener("/admin/audit/verify"));

        let bare = with_admin_hint(api_error(StatusCode::NOT_FOUND, "")).to_string();
        assert_eq!(
            bare,
            format!("server answered 404 Not Found\n{ADMIN_LISTENER_HINT}")
        );
        // Still an `ApiError` for callers that read the status.
        let e = with_admin_hint(api_error(StatusCode::NOT_FOUND, ""));
        assert_eq!(
            e.downcast_ref::<ApiError>().unwrap().status,
            StatusCode::NOT_FOUND
        );
        // A JSON `not_found` (a missing item on a route that exists) and other statuses stay.
        for (status, body) in [
            (
                StatusCode::NOT_FOUND,
                r#"{"error":"not_found","detail":"unknown lease `x`"}"#,
            ),
            (StatusCode::UNAUTHORIZED, ""),
            (StatusCode::BAD_GATEWAY, "oops"),
        ] {
            let e = with_admin_hint(api_error(status, body)).to_string();
            assert!(!e.contains("hint:"), "{e}");
        }
    }

    /// The client is chosen by the origin a request goes to, never by its path: an
    /// `--admin-server` with a path prefix (`/pfx/admin/...`) on another origin gets the
    /// client without the certificate, and a prefixed `--server` keeps its own.
    #[test]
    fn the_certificate_client_is_used_only_for_the_server_origin() {
        let is_server = |c: &Client, path: &str| {
            let url = reqwest::Url::parse(&c.url(path)).unwrap();
            std::ptr::eq(c.client_for(&url), &c.http)
        };
        for (server, admin) in [
            ("https://main.test", "https://adm.test"),
            ("https://main.test/pfx", "https://adm.test/pfx"),
            ("https://main.test", "https://main.test:9102"),
            ("https://main.test", "http://main.test"),
        ] {
            let c = Client::new(server, Some(admin), None, &Tls::default()).unwrap();
            for path in ["/admin/policies", "/admin", "/admin/root-token"] {
                assert!(!is_server(&c, path), "{server} {admin} {path}");
            }
            for path in ["/token", "/healthz", "/mcp/admin", "/administer"] {
                assert!(is_server(&c, path), "{server} {admin} {path}");
            }
        }
        // Without --admin-server, `/admin/*` goes to `--server`, the same host.
        let one = Client::new("https://main.test/pfx", None, None, &Tls::default()).unwrap();
        assert!(is_server(&one, "/admin/audit"));

        // Full URLs (`approval verify --jwks`): the server origin only.
        let c = Client::new("https://attenuo.test", None, None, &Tls::default()).unwrap();
        let picks_server = |u: &str| {
            let url = reqwest::Url::parse(u).unwrap();
            std::ptr::eq(c.client_for(&url), &c.http)
        };
        for same in [
            "https://attenuo.test/.well-known/jwks.json",
            "https://attenuo.test:443/jwks",
            "https://ATTENUO.test/jwks",
        ] {
            assert!(picks_server(same), "{same}");
        }
        for other in [
            "http://attenuo.test/jwks",
            "https://attenuo.test:8443/jwks",
            "https://attenuo.test.evil/jwks",
            "https://other.test/jwks",
            "https://evil@other.test/jwks",
        ] {
            assert!(!picks_server(other), "{other}");
        }
        assert!(c.http_for_url("not a url").is_err());
    }

    #[test]
    fn server_must_be_a_url() {
        assert!(Client::new("github", None, None, &Tls::default()).is_err());
        assert!(Client::new("http://127.0.0.1:8080/", None, None, &Tls::default()).is_ok());
        let err = Client::new(
            "http://127.0.0.1:8080",
            Some("admin"),
            None,
            &Tls::default(),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(err.starts_with("--admin-server must be"), "{err}");
    }

    #[test]
    fn admin_paths_go_to_the_admin_server_when_given() {
        let split = Client::new(
            "http://main:8080/",
            Some("http://adm:9102/"),
            None,
            &Tls::default(),
        )
        .unwrap();
        for path in [
            "/admin/audit?from=1",
            "/admin/root-token",
            "/admin",
            "/admin?x=1",
        ] {
            assert_eq!(split.url(path), format!("http://adm:9102{path}"));
        }
        for path in [
            "/token",
            "/.well-known/jwks.json",
            "/healthz",
            "/mcp/admin",
            "/administer",
        ] {
            assert_eq!(split.url(path), format!("http://main:8080{path}"));
        }
        let one = Client::new("http://main:8080", None, None, &Tls::default()).unwrap();
        assert_eq!(one.url("/admin/audit"), "http://main:8080/admin/audit");
        assert_eq!(one.url("/token"), "http://main:8080/token");
    }
}
