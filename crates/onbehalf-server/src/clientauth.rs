//! Client authentication against a list of `{ id, secret_sha256 }` entries.
//!
//! Used for agents at `POST /token` (`[[agents]]`: IdP intake and, with
//! `[token] require_actor_auth`, every exchange) and for policy enforcement points at the
//! AuthZEN endpoint (`[[peps]]`, only when `[authzen] allow_unsigned_chain` is on).
//!
//! Credentials come either from HTTP Basic (RFC 6749 §2.3.1: id and secret form-encoded, then
//! base64) or from two body fields, never both. Secrets are stored as the lowercase hex SHA-256
//! of the secret and compared in constant time, against a dummy hash for unknown ids so timing
//! does not reveal which ids exist.

use axum::http::{header, HeaderMap, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::config::AgentConfig;
use crate::error::ApiError;
use crate::routes::admin::constant_time_eq;

/// Which list is being authenticated against; only changes error texts and sub-codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientKind {
    /// `[[agents]]`, body fields `client_id` / `client_secret`.
    Agent,
    /// `[[peps]]`, body fields `pep_id` / `pep_secret`.
    Pep,
}

impl ClientKind {
    fn section(self) -> &'static str {
        match self {
            ClientKind::Agent => "[[agents]]",
            ClientKind::Pep => "[[peps]]",
        }
    }

    fn fields(self) -> (&'static str, &'static str) {
        match self {
            ClientKind::Agent => ("client_id", "client_secret"),
            ClientKind::Pep => ("pep_id", "pep_secret"),
        }
    }

    fn none_configured(self) -> &'static str {
        match self {
            ClientKind::Agent => "no_agents_configured",
            ClientKind::Pep => "no_peps_configured",
        }
    }
}

pub(crate) fn invalid_request(description: &'static str, detail: impl Into<String>) -> ApiError {
    ApiError::bad_request("invalid_request", detail).with_description(description)
}

pub(crate) fn invalid_client(description: &'static str, detail: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "invalid_client", detail).with_description(description)
}

/// Client credentials from HTTP Basic (RFC 6749 §2.3.1, form-encoded id and secret).
/// `Ok(None)` when there is no `Authorization` header or it is not Basic.
pub fn basic_credentials(headers: &HeaderMap) -> Result<Option<(String, String)>, ApiError> {
    let Some(raw) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let raw = raw.to_str().unwrap_or_default();
    let Some((scheme, b64)) = raw.split_once(' ') else {
        return Ok(None);
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return Ok(None);
    }
    let bad = || invalid_client("malformed_client_auth", "malformed Basic credentials");
    let decoded = STANDARD.decode(b64.trim()).map_err(|_| bad())?;
    let decoded = String::from_utf8(decoded).map_err(|_| bad())?;
    let (id, secret) = decoded.split_once(':').ok_or_else(bad)?;
    let unescape = |s: &str| -> Result<String, ApiError> {
        let pairs: Vec<(String, String)> =
            serde_urlencoded::from_str(&format!("v={s}")).map_err(|_| bad())?;
        Ok(pairs.into_iter().next().map(|(_, v)| v).unwrap_or_default())
    };
    Ok(Some((unescape(id)?, unescape(secret)?)))
}

/// Authenticate a client against `clients`; returns its id.
///
/// `body_id` / `body_secret` are the body fields ([`ClientKind`] names them). Sub-codes:
/// `client_auth_missing`, `multiple_client_auth`, `malformed_client_auth`,
/// `client_authentication_failed`, `no_agents_configured` / `no_peps_configured`.
pub fn authenticate(
    kind: ClientKind,
    clients: &[AgentConfig],
    headers: &HeaderMap,
    body_id: Option<&str>,
    body_secret: Option<&str>,
) -> Result<String, ApiError> {
    let (id_field, secret_field) = kind.fields();
    let (id, secret) = match (basic_credentials(headers)?, body_secret) {
        (Some(_), Some(_)) => {
            return Err(invalid_request(
                "multiple_client_auth",
                format!("use either HTTP Basic or {secret_field} in the body, not both"),
            ))
        }
        (Some((id, secret)), None) => {
            if body_id.is_some_and(|c| c != id) {
                return Err(invalid_client(
                    "client_authentication_failed",
                    format!("{id_field} differs from the Basic credentials"),
                ));
            }
            (id, secret)
        }
        (None, Some(secret)) => match body_id {
            Some(id) => (id.to_owned(), secret.to_owned()),
            None => {
                return Err(invalid_client(
                    "client_auth_missing",
                    format!("{id_field} is required"),
                ))
            }
        },
        (None, None) => {
            return Err(invalid_client(
                "client_auth_missing",
                format!(
                    "client authentication is required (HTTP Basic, or {id_field} and \
                     {secret_field})"
                ),
            ))
        }
    };
    if clients.is_empty() {
        return Err(invalid_client(
            kind.none_configured(),
            format!("no {} are configured", kind.section()),
        ));
    }
    let presented = hex::encode(Sha256::digest(secret.as_bytes()));
    let known = clients.iter().find(|a| a.id == id);
    // Compare against something even for unknown ids, so timing does not reveal which exist.
    let expected = known
        .map(|a| a.secret_sha256.as_str())
        .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
    let ok = constant_time_eq(presented.as_bytes(), expected.as_bytes());
    match known {
        Some(a) if ok => Ok(a.id.clone()),
        _ => Err(invalid_client(
            "client_authentication_failed",
            "unknown client or wrong secret",
        )),
    }
}

/// Validate a `{ id, secret_sha256 }` list at startup; returns it with the hashes lowercased.
pub fn validate_clients(
    section: &str,
    clients: &[AgentConfig],
) -> anyhow::Result<Vec<AgentConfig>> {
    let mut out: Vec<AgentConfig> = Vec::with_capacity(clients.len());
    for a in clients {
        if a.id.is_empty() {
            anyhow::bail!("{section}: id must not be empty");
        }
        if out.iter().any(|b| b.id == a.id) {
            anyhow::bail!("{section}: id `{}` is listed twice", a.id);
        }
        let h = a.secret_sha256.to_ascii_lowercase();
        if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            anyhow::bail!(
                "{section} `{}`: secret_sha256 must be 64 hex characters",
                a.id
            );
        }
        out.push(AgentConfig {
            id: a.id.clone(),
            secret_sha256: h,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn peps() -> Vec<AgentConfig> {
        validate_clients(
            "[[peps]]",
            &[AgentConfig {
                id: "gateway".into(),
                secret_sha256: hex::encode(Sha256::digest(b"pep-s3cret")),
            }],
        )
        .unwrap()
    }

    fn code(r: Result<String, ApiError>) -> &'static str {
        r.unwrap_err().description.unwrap()
    }

    #[test]
    fn pep_credentials_from_body_or_basic() {
        let h = HeaderMap::new();
        let auth = |id, secret| authenticate(ClientKind::Pep, &peps(), &h, id, secret);
        assert_eq!(
            auth(Some("gateway"), Some("pep-s3cret")).unwrap(),
            "gateway"
        );
        assert_eq!(
            code(auth(Some("gateway"), Some("nope"))),
            "client_authentication_failed"
        );
        assert_eq!(code(auth(None, None)), "client_auth_missing");
        assert_eq!(
            code(authenticate(
                ClientKind::Pep,
                &[],
                &h,
                Some("gateway"),
                Some("pep-s3cret")
            )),
            "no_peps_configured"
        );
        let mut basic = HeaderMap::new();
        basic.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", STANDARD.encode("gateway:pep-s3cret")))
                .unwrap(),
        );
        assert_eq!(
            authenticate(ClientKind::Pep, &peps(), &basic, None, None).unwrap(),
            "gateway"
        );
        assert_eq!(
            code(authenticate(
                ClientKind::Pep,
                &peps(),
                &basic,
                Some("other"),
                None
            )),
            "client_authentication_failed"
        );
    }
}
