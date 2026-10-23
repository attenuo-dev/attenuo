//! A thin HTTP client for the attenuo server.

use anyhow::{anyhow, bail, Context, Result};
use attenuo_token::dpop::{DPOP_NONCE_HEADER, USE_DPOP_NONCE};
use attenuo_token::DpopKey;
use reqwest::header::HeaderMap;
use reqwest::{RequestBuilder, StatusCode};
use serde_json::{json, Value};
use std::sync::Mutex;

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

/// A response read in full: status, headers and body text.
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    text: String,
}

pub struct Client {
    http: reqwest::Client,
    base: String,
    admin_token: Option<String>,
    /// The latest `DPoP-Nonce` this server sent (RFC 9449 §8), for the next proof. Never
    /// printed or logged.
    nonce: Mutex<Option<String>>,
}

impl Client {
    pub fn new(base: &str, admin_token: Option<String>) -> Result<Self> {
        let base = base.trim_end_matches('/').to_string();
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            bail!(
                "--server must be the attenuo server's base URL (http://host:port), got `{base}`. \
                 To name an MCP upstream, put `--server <name>` after `call` or `tools`."
            );
        }
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
            base,
            admin_token,
            nonce: Mutex::new(None),
        })
    }

    /// The nonce to put in the next proof, if the server has sent one.
    fn current_nonce(&self) -> Option<String> {
        self.nonce.lock().ok().and_then(|n| n.clone())
    }

    /// Send the request `build` makes (given the nonce for its proof) and read the reply.
    /// Keeps the response's `DPoP-Nonce`; when `dpop` is set and the server refused the proof
    /// with `use_dpop_nonce` and sent a nonce, builds and sends the request once more with it
    /// (RFC 9449 §8.2).
    async fn send_dpop(
        &self,
        dpop: bool,
        mut build: impl FnMut(Option<&str>) -> Result<RequestBuilder>,
    ) -> Result<Reply> {
        let mut retried = false;
        loop {
            let resp = build(self.current_nonce().as_deref())?
                .send()
                .await
                .with_context(|| format!("could not reach the server at {}", self.base))?;
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
            });
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    fn admin(&self, req: RequestBuilder) -> Result<RequestBuilder> {
        let token = self.admin_token.as_deref().ok_or_else(|| {
            anyhow!(
                "this command needs the admin token: pass --admin-token or set ATTENUO_ADMIN_TOKEN"
            )
        })?;
        Ok(req.bearer_auth(token))
    }

    async fn send_json(&self, req: RequestBuilder) -> Result<Value> {
        let mut req = Some(req);
        let reply = self
            .send_dpop(false, |_| Ok(req.take().expect("sent once")))
            .await?;
        json_reply(reply)
    }

    pub async fn get(&self, path: &str) -> Result<Value> {
        self.send_json(self.http.get(self.url(path))).await
    }

    pub async fn admin_get(&self, path: &str) -> Result<Value> {
        self.send_json(self.admin(self.http.get(self.url(path)))?)
            .await
    }

    /// `GET` an admin path and hand back the response for the caller to read incrementally
    /// (the audit export). Non-success statuses become errors; the long timeout is for a big
    /// export, not for a hung server.
    pub async fn admin_get_stream(&self, path: &str) -> Result<reqwest::Response> {
        let resp = self
            .admin(self.http.get(self.url(path)))?
            .timeout(std::time::Duration::from_secs(3600))
            .send()
            .await
            .with_context(|| format!("could not reach the server at {}", self.base))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        Err(api_error(status, &resp.text().await?))
    }

    pub async fn admin_post(&self, path: &str, body: &Value) -> Result<Value> {
        self.send_json(self.admin(self.http.post(self.url(path)).json(body))?)
            .await
    }

    /// `POST /admin/root-token`, bound to `key` when given (a DPoP proof in the header).
    pub async fn root(&self, body: &Value, key: Option<&DpopKey>) -> Result<Value> {
        let url = self.url("/admin/root-token");
        let reply = self
            .send_dpop(key.is_some(), |nonce| {
                let mut req = self.admin(self.http.post(&url).json(body))?;
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
        json_reply(reply)
    }

    /// The URL of `POST /token`, which DPoP proofs for an exchange name.
    pub fn token_url(&self) -> String {
        self.url("/token")
    }

    /// `POST /token` with an RFC 8693 JSON body. `proof` makes the `DPoP` header for the
    /// nonce it is given (none without a DPoP key); it runs again if the server asks for its
    /// nonce.
    pub async fn exchange(
        &self,
        body: &Value,
        proof: impl Fn(Option<&str>) -> Result<Option<String>>,
    ) -> Result<Value> {
        let dpop = proof(None)?.is_some();
        let reply = self
            .send_dpop(dpop, |nonce| {
                let mut req = self.http.post(self.url("/token")).json(body);
                if let Some(p) = proof(nonce)? {
                    req = req.header("dpop", p);
                }
                Ok(req)
            })
            .await?;
        json_reply(reply)
    }

    /// `POST /access/v1/evaluation` with the delegation token as bearer.
    pub async fn authzen(&self, token: &str, body: &Value, key: Option<&DpopKey>) -> Result<Value> {
        let url = self.url("/access/v1/evaluation");
        let reply = self
            .send_dpop(key.is_some(), |nonce| {
                Ok(present(self.http.post(&url), token, key, "POST", &url, nonce).json(body))
            })
            .await?;
        json_reply(reply)
    }

    /// One JSON-RPC request to `/mcp/{server}`. Returns the JSON-RPC response whatever the
    /// HTTP status, since the proxy reports denials as JSON-RPC errors.
    pub async fn mcp(
        &self,
        token: &str,
        key: Option<&DpopKey>,
        server: &str,
        method: &str,
        params: Value,
    ) -> Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let url = self.url(&format!("/mcp/{server}"));
        let Reply {
            status,
            headers,
            text,
        } = self
            .send_dpop(key.is_some(), |nonce| {
                Ok(
                    present(self.http.post(&url), token, key, "POST", &url, nonce)
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
            None if status.is_success() => bail!("no JSON-RPC response in body: {text}"),
            None => Err(api_error(status, &text)),
        }
    }
}

/// The JSON body of a success, or the server's error.
fn json_reply(reply: Reply) -> Result<Value> {
    let Reply { status, text, .. } = reply;
    if status.is_success() {
        return serde_json::from_str(&text)
            .with_context(|| format!("server sent non-JSON ({status}): {text}"));
    }
    Err(api_error(status, &text))
}

/// Did the server refuse a proof for want of its nonce (RFC 9449 §8)? A 401 with
/// `WWW-Authenticate: DPoP error="use_dpop_nonce"` (attenuo's own routes), or a 400 or 401
/// whose JSON `error` is `use_dpop_nonce`.
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
            .is_ok_and(|v| v["error"].as_str() == Some(USE_DPOP_NONCE))
}

/// A server error as `{"error": code, "detail": text}`, or the raw body when it is not that.
fn api_error(status: StatusCode, body: &str) -> anyhow::Error {
    match serde_json::from_str::<Value>(body) {
        Ok(v) if v["error"].is_string() => anyhow!(
            "server answered {status}: {}{}",
            v["error"].as_str().unwrap_or_default(),
            v["detail"]
                .as_str()
                .map(|d| format!(": {d}"))
                .unwrap_or_default()
        ),
        _ if body.trim().is_empty() => anyhow!("server answered {status}"),
        _ => anyhow!("server answered {status}: {}", body.trim()),
    }
}

/// The JSON-RPC response in a plain JSON or `text/event-stream` body.
pub fn parse_rpc_body(text: &str, sse: bool) -> Option<Value> {
    if !sse {
        return serde_json::from_str(text).ok();
    }
    text.lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .filter_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
        .find(|v| v.get("result").is_some() || v.get("error").is_some())
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
            api_error(StatusCode::BAD_GATEWAY, "oops").to_string(),
            "server answered 502 Bad Gateway: oops"
        );
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
    fn server_must_be_a_url() {
        assert!(Client::new("github", None).is_err());
        assert!(Client::new("http://127.0.0.1:8080/", None).is_ok());
    }
}
