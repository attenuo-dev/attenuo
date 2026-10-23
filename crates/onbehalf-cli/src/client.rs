//! A thin HTTP client for the onbehalf server.

use anyhow::{anyhow, bail, Context, Result};
use onbehalf_token::DpopKey;
use reqwest::{RequestBuilder, StatusCode};
use serde_json::{json, Value};

/// Present `token` with a DPoP proof by `key` for `method` and `url` (RFC 9449 §7.1:
/// `Authorization: DPoP <token>` and a `DPoP` header whose `ath` covers the token), or as a
/// plain bearer without a key.
fn present(
    req: RequestBuilder,
    token: &str,
    key: Option<&DpopKey>,
    method: &str,
    url: &str,
) -> RequestBuilder {
    match key {
        Some(k) => req.header("authorization", format!("DPoP {token}")).header(
            "dpop",
            k.proof(method, url, Some(token), time::OffsetDateTime::now_utc()),
        ),
        None => req.bearer_auth(token),
    }
}

pub struct Client {
    http: reqwest::Client,
    base: String,
    admin_token: Option<String>,
}

impl Client {
    pub fn new(base: &str, admin_token: Option<String>) -> Result<Self> {
        let base = base.trim_end_matches('/').to_string();
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            bail!(
                "--server must be the onbehalf server's base URL (http://host:port), got `{base}`. \
                 To name an MCP upstream, put `--server <name>` after `call` or `tools`."
            );
        }
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
            base,
            admin_token,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    fn admin(&self, req: RequestBuilder) -> Result<RequestBuilder> {
        let token = self.admin_token.as_deref().ok_or_else(|| {
            anyhow!("this command needs the admin token: pass --admin-token or set ONBEHALF_ADMIN_TOKEN")
        })?;
        Ok(req.bearer_auth(token))
    }

    async fn send_json(&self, req: RequestBuilder) -> Result<Value> {
        let resp = req
            .send()
            .await
            .with_context(|| format!("could not reach the server at {}", self.base))?;
        let status = resp.status();
        let text = resp.text().await?;
        if status.is_success() {
            return serde_json::from_str(&text)
                .with_context(|| format!("server sent non-JSON ({status}): {text}"));
        }
        Err(api_error(status, &text))
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
        let mut req = self.admin(self.http.post(&url).json(body))?;
        if let Some(k) = key {
            req = req.header(
                "dpop",
                k.proof("POST", &url, None, time::OffsetDateTime::now_utc()),
            );
        }
        self.send_json(req).await
    }

    /// The URL of `POST /token`, which DPoP proofs for an exchange name.
    pub fn token_url(&self) -> String {
        self.url("/token")
    }

    /// `POST /token` with an RFC 8693 JSON body and, when given, a `DPoP` header.
    pub async fn exchange(&self, body: &Value, dpop: Option<String>) -> Result<Value> {
        let mut req = self.http.post(self.url("/token")).json(body);
        if let Some(proof) = dpop {
            req = req.header("dpop", proof);
        }
        self.send_json(req).await
    }

    /// `POST /access/v1/evaluation` with the delegation token as bearer.
    pub async fn authzen(&self, token: &str, body: &Value, key: Option<&DpopKey>) -> Result<Value> {
        let url = self.url("/access/v1/evaluation");
        self.send_json(present(self.http.post(&url), token, key, "POST", &url).json(body))
            .await
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
        let resp = present(self.http.post(&url), token, key, "POST", &url)
            .header("accept", "application/json, text/event-stream")
            .json(&body)
            .send()
            .await
            .with_context(|| format!("could not reach the server at {}", self.base))?;
        let status = resp.status();
        let is_sse = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("event-stream"));
        let text = resp.text().await?;
        match parse_rpc_body(&text, is_sse) {
            Some(v) => Ok(v),
            None if status.is_success() => bail!("no JSON-RPC response in body: {text}"),
            None => Err(api_error(status, &text)),
        }
    }
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
    fn server_must_be_a_url() {
        assert!(Client::new("github", None).is_err());
        assert!(Client::new("http://127.0.0.1:8080/", None).is_ok());
    }
}
