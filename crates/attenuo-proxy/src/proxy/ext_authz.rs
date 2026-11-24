//! `/ext-authz/v1/mcp/{server}`: the proxy's decision for a request an external gateway is
//! about to forward, for agentgateway's HTTP `extAuthz` mode
//! (`docs/design/agentgateway-ext-authz.md`).
//!
//! The gateway sends the agent's request here (its method, its `Authorization` and `DPoP`
//! headers, its body) and forwards it to the MCP server only on a 2xx answer; any other answer
//! goes back to the agent as the gateway's response. This module adds no decision logic: it
//! authenticates with [`Authorizer::authenticate_request`] and screens the one JSON-RPC message
//! with [`screen_message`], as `POST /mcp/{server}` does, and answers 200 exactly when the
//! proxy would have forwarded the message unchanged. What it adds is only what the gateway's
//! position requires:
//!
//! - the gateway authenticates with a secret of the `[[ext_authz]]` entry of `{server}`, so a
//!   route configured for one server cannot ask about another;
//! - the body must be whole (`x-envoy-auth-partial-body: false`) and unambiguous (no duplicate
//!   member, every number written as serde_json reads it), because the gateway forwards its
//!   own parse of the agent's bytes (agentgateway v1.7.0 re-encodes the message), not the
//!   proxy's re-encoding of what was decided;
//! - batches are refused: the gateway forwards all or nothing;
//! - a DPoP proof names the gateway's URL (`dpop_url`), not this server's;
//! - `Mcp-Session-Id` is ignored: the adapter never sees which principal a session belongs to.

use std::collections::HashSet;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use sha2::{Digest, Sha256};

use super::*;

/// Header that carries the gateway's secret.
pub const GATEWAY_SECRET_HEADER: &str = "x-attenuo-gateway-secret";

/// Header agentgateway (like Envoy) sets on the check request whenever it includes the body:
/// `true` when the body was cut at `maxRequestBytes`, `false` when it is whole.
pub const PARTIAL_BODY_HEADER: &str = "x-envoy-auth-partial-body";

/// Code (HTTP 403) for a request without the `[[ext_authz]]` entry's gateway secret.
pub const REASON_EXT_AUTHZ_UNAUTHENTICATED: &str = "ext_authz_unauthenticated";

/// Code (HTTP 403) for a request whose `x-envoy-auth-partial-body` is not `false`: the body
/// was cut, or the gateway was not configured to send it.
pub const REASON_EXT_AUTHZ_BODY_INCOMPLETE: &str = "ext_authz_body_incomplete";

/// Code (HTTP 400) for a body that parsers can read differently: a duplicate member, or a
/// number not written as serde_json reads it.
pub const REASON_EXT_AUTHZ_AMBIGUOUS_BODY: &str = "ext_authz_ambiguous_body";

/// Code (HTTP 400) for a JSON-RPC batch, which the adapter does not decide.
pub const REASON_EXT_AUTHZ_BATCH_UNSUPPORTED: &str = "ext_authz_batch_unsupported";

/// Code (HTTP 401) for a request with a `DPoP` header to an entry without `dpop_url`.
pub const REASON_EXT_AUTHZ_DPOP_URL_UNSET: &str = "ext_authz_dpop_url_unset";

/// One `[[ext_authz]]` entry, as the router keeps it.
pub(super) struct Entry {
    /// SHA-256 of the gateway secret; `None` when the configured digest is not 64 hex digits,
    /// so that no secret matches.
    secret_sha256: Option<[u8; 32]>,
    dpop_url: Option<String>,
}

impl Entry {
    pub(super) fn from_config(route: &crate::config::ExtAuthzRoute) -> Self {
        let secret_sha256 = hex::decode(route.secret_sha256.trim())
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok());
        if secret_sha256.is_none() {
            tracing::error!(server = ?route.server, "[[ext_authz]] secret_sha256 is not 64 hex digits; every request will be refused");
        }
        Self {
            secret_sha256,
            dpop_url: route.dpop_url.clone(),
        }
    }

    fn admits(&self, headers: &HeaderMap) -> bool {
        let Some(expected) = &self.secret_sha256 else {
            return false;
        };
        let mut values = headers.get_all(GATEWAY_SECRET_HEADER).iter();
        let (Some(v), None) = (values.next(), values.next()) else {
            return false;
        };
        let presented: [u8; 32] = Sha256::digest(v.as_bytes()).into();
        presented
            .iter()
            .zip(expected)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

fn refuse(status: StatusCode, number: i64, code: &str, message: &str) -> Response {
    tracing::warn!(code, "ext_authz request refused");
    let body = attenuo_error(
        Value::Null,
        number,
        code,
        format!("attenuo: {message}"),
        None,
    );
    json_response(status, &body)
}

/// The handler of `/ext-authz/v1/mcp/{server}` (`POST`, `GET`, `DELETE`; axum also routes
/// `HEAD` to it, as at `/mcp/{server}`).
pub(super) async fn handle(
    State(state): State<Arc<AppState>>,
    ServerName(server): ServerName,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(entry) = state.ext_authz.get(&server) else {
        return unknown_server(&server);
    };
    // First, before the token, the proof or the body is read: without the secret the route
    // decides nothing, charges nothing and records nothing.
    if !entry.admits(&headers) {
        return refuse(
            StatusCode::FORBIDDEN,
            CODE_UNAUTHORIZED,
            REASON_EXT_AUTHZ_UNAUTHENTICATED,
            "the gateway did not authenticate",
        );
    }
    let whole = headers
        .get_all(PARTIAL_BODY_HEADER)
        .iter()
        .map(|v| v.as_bytes())
        .eq([b"false".as_slice()]);
    if !whole {
        return refuse(
            StatusCode::FORBIDDEN,
            CODE_INVALID_REQUEST,
            REASON_EXT_AUTHZ_BODY_INCOMPLETE,
            "the gateway did not send the whole request body",
        );
    }
    if headers.contains_key("dpop") && entry.dpop_url.is_none() {
        return refuse(
            StatusCode::UNAUTHORIZED,
            CODE_UNAUTHORIZED,
            REASON_EXT_AUTHZ_DPOP_URL_UNSET,
            "DPoP proofs are not accepted through this gateway route (no dpop_url)",
        );
    }
    let now = state.clock.now_utc();
    let who = match authenticate_forwarded(&state, &method, &headers, entry, now).await {
        Ok(a) => a,
        Err(e) => return unauthorized(e),
    };
    if method != Method::POST {
        // As `GET`/`DELETE /mcp/{server}` before it is forwarded: a live lease, recorded when
        // it is not.
        if let Err(e) = state.authorizer.check_active(&who.chain, now).await {
            let tool = if method == Method::DELETE {
                "http.DELETE"
            } else {
                "http.GET"
            };
            let id = record_lease_refusal(&state, &who, &server, None, tool, &e, now).await;
            return unauthorized_recorded(e, id);
        }
        return StatusCode::OK.into_response();
    }
    let body = match read_request_body(&headers, body, state.max_request_body).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    if let Err(detail) = check_unambiguous(&body) {
        tracing::warn!(detail, "ext_authz request refused: ambiguous body");
        return refuse(
            StatusCode::BAD_REQUEST,
            CODE_INVALID_REQUEST,
            REASON_EXT_AUTHZ_AMBIGUOUS_BODY,
            &format!("the request body can be read in more than one way: {detail}"),
        );
    }
    decide_post(&state, &who, &server, &body, now).await
}

/// Authenticate as [`authenticate`] does, with the DPoP proof checked against the entry's
/// `dpop_url` and the forwarded method.
async fn authenticate_forwarded(
    state: &AppState,
    method: &Method,
    headers: &HeaderMap,
    entry: &Entry,
    now: OffsetDateTime,
) -> Result<Authenticated, AuthError> {
    let req = RequestAuth {
        token: bearer_of(headers)?,
        dpop: dpop_of(headers)?,
        method: method.as_str(),
        path: "",
        host: None,
        url: entry.dpop_url.as_deref(),
        dpop_scheme: super::dpop_scheme_of(headers),
        // The connection is the gateway's: any certificate on it is the gateway's, not the
        // agent's. A token bound to a certificate is refused on this route.
        client_cert: None,
    };
    state.authorizer.authenticate_request(&req, now).await
}

/// The parse and screening of [`handle_post_inner`] for one message, answered without an
/// upstream: 200 when the proxy would forward the message, else the answer the proxy would
/// give, with a JSON-RPC error that the proxy sends in a 200 sent as 403 instead.
async fn decide_post(
    state: &AppState,
    who: &Authenticated,
    server: &str,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = ?e.to_string(), "request body is not JSON");
            let body = attenuo_error(
                Value::Null,
                CODE_PARSE_ERROR,
                "parse_error",
                format!("attenuo: parse error: {e}"),
                None,
            );
            return json_response(StatusCode::BAD_REQUEST, &body);
        }
    };
    let msg = match parsed {
        Value::Object(_) => parsed,
        Value::Array(_) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                CODE_INVALID_REQUEST,
                REASON_EXT_AUTHZ_BATCH_UNSUPPORTED,
                "JSON-RPC batches are not decided through a gateway",
            )
        }
        _ => {
            let body = attenuo_error(
                Value::Null,
                CODE_INVALID_REQUEST,
                "invalid_request",
                "attenuo: invalid request: expected a JSON-RPC object",
                None,
            );
            return json_response(StatusCode::BAD_REQUEST, &body);
        }
    };
    let mut screened = Screened::default();
    // No session: the adapter cannot tell whose a session id is (module docs).
    screen_message(state, who, server, None, msg, now, &mut screened).await;
    if screened.forward.is_empty() && screened.decision_ids.is_empty() {
        if let Some(Err(e)) = screened.lease_check.take() {
            return unauthorized_recorded(e, screened.lease_refusal);
        }
    }
    let mut resp = if !screened.forward.is_empty() && screened.replies.is_empty() {
        StatusCode::OK.into_response()
    } else {
        // A denial, an approval request or invalid params: what the proxy answers itself.
        let reply = screened.replies.pop().unwrap_or(Value::Null);
        json_response(StatusCode::FORBIDDEN, &reply)
    };
    add_decision_header(&mut resp, &screened.decision_ids);
    resp
}

/// `Ok` when `body` is JSON that every parser reads the same way as serde_json: no object has
/// two members of one name (after unescaping), and every number is written exactly as
/// serde_json writes the value it reads (so no digits are lost and no form is open to
/// another reading). Text that is not JSON is `Ok` here and refused by the parse after it.
fn check_unambiguous(body: &[u8]) -> Result<(), &'static str> {
    let mut de = serde_json::Deserializer::from_slice(body);
    match NoDuplicates.deserialize(&mut de) {
        Ok(()) => {}
        Err(e) if e.to_string().starts_with(DUPLICATE) => return Err("duplicate member name"),
        Err(_) => return Ok(()),
    }
    check_numbers(body)?;
    // Member names that differ only in case are one member to a decoder that ignores case
    // (SR-133). The proxy refuses such a message too, as invalid_request; here it is refused
    // with the other ambiguous bodies, before any decision.
    match serde_json::from_slice::<Value>(body) {
        Ok(v) if jsonrpc::member_case_conflict(&v).is_some() => {
            Err("member names that differ only in case")
        }
        _ => Ok(()),
    }
}

const DUPLICATE: &str = "duplicate member";

/// Walks a JSON value and fails on an object with two members of one name.
struct NoDuplicates;

impl<'de> DeserializeSeed<'de> for NoDuplicates {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for NoDuplicates {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JSON")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(NoDuplicates)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(de::Error::custom(DUPLICATE));
            }
            map.next_value_seed(NoDuplicates)?;
        }
        Ok(())
    }
}

/// Every number token outside a string must be exactly serde_json's rendering of the number
/// it parses to.
fn check_numbers(body: &[u8]) -> Result<(), &'static str> {
    let mut i = 0;
    let mut in_string = false;
    while i < body.len() {
        let b = body[i];
        if in_string {
            match b {
                b'\\' => i += 1,
                b'"' => in_string = false,
                _ => {}
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
            i += 1;
            continue;
        }
        if b == b'-' || b.is_ascii_digit() {
            let start = i;
            while i < body.len()
                && matches!(body[i], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
            {
                i += 1;
            }
            let text = std::str::from_utf8(&body[start..i]).map_err(|_| "number")?;
            match serde_json::from_str::<serde_json::Number>(text) {
                Ok(n) if n.to_string() == text => {}
                _ => return Err("a number is not written as it is read"),
            }
            continue;
        }
        i += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_members_are_ambiguous_at_any_depth() {
        assert!(check_unambiguous(br#"{"a":1,"b":{"c":2}}"#).is_ok());
        assert!(check_unambiguous(br#"{"method":"ping","method":"tools/call"}"#).is_err());
        assert!(check_unambiguous(br#"{"p":{"x":1,"x":2}}"#).is_err());
        assert!(check_unambiguous(br#"{"p":[{"a":1},{"a":2,"a":3}]}"#).is_err());
        // Not JSON: left to the parse, which refuses it.
        assert!(check_unambiguous(b"{not json").is_ok());
    }

    #[test]
    fn member_names_that_differ_only_in_case_are_ambiguous_sr133() {
        for bad in [
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","Method":"tools/call"}"#,
            r#"{"jsonrpc":"2.0","id":1,"Method":"tools/call","params":{"name":"x"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","NAME":"b"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","arguments":{"repo":"x","Repo":"y"}}}"#,
        ] {
            assert_eq!(
                check_unambiguous(bad.as_bytes()),
                Err("member names that differ only in case"),
                "{bad}"
            );
        }
    }

    #[test]
    fn numbers_must_read_back_as_written() {
        for ok in [
            r#"{"n":0}"#,
            r#"{"n":-7}"#,
            r#"{"n":1.5}"#,
            r#"{"n":100.0}"#,
            r#"{"n":18446744073709551615}"#,
            r#"{"s":"1.50 and 1e3 in a string","t":"\"9.000\""}"#,
        ] {
            assert!(check_unambiguous(ok.as_bytes()).is_ok(), "{ok}");
        }
        for bad in [
            r#"{"n":0.10000000000000001}"#,
            r#"{"n":100000000000000000001}"#,
            r#"{"n":1e3}"#,
            r#"{"n":1.50}"#,
            r#"{"n":-0}"#,
            r#"{"a":[1,2,1000000000000.00001]}"#,
        ] {
            assert!(check_unambiguous(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_the_right_secret_is_admitted() {
        let route = crate::config::ExtAuthzRoute {
            server: "github".into(),
            secret_sha256: hex::encode(Sha256::digest(b"s3cret")),
            dpop_url: None,
        };
        let entry = Entry::from_config(&route);
        let mut h = HeaderMap::new();
        assert!(!entry.admits(&h));
        h.insert(GATEWAY_SECRET_HEADER, HeaderValue::from_static("wrong"));
        assert!(!entry.admits(&h));
        h.insert(GATEWAY_SECRET_HEADER, HeaderValue::from_static("s3cret"));
        assert!(entry.admits(&h));
        h.append(GATEWAY_SECRET_HEADER, HeaderValue::from_static("s3cret"));
        assert!(!entry.admits(&h), "two values are refused");
        let broken = Entry::from_config(&crate::config::ExtAuthzRoute {
            secret_sha256: "not hex".into(),
            ..route
        });
        h.remove(GATEWAY_SECRET_HEADER);
        h.insert(GATEWAY_SECRET_HEADER, HeaderValue::from_static("s3cret"));
        assert!(!broken.admits(&h));
    }
}
