//! JSON error responses: `{"error": "<code>", "detail": "<human-readable text>"}`, plus a
//! stable machine-readable sub-code in `error_description` where one is defined (IdP intake at
//! `POST /token`, see [`crate::idp::IntakeError`]).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// 401 reason: no credential was sent.
pub const REASON_MISSING_TOKEN: &str = onbehalf_proxy::auth::REASON_MISSING_TOKEN;
/// 401 reason: the credential is malformed, not ours, or fails verification.
pub const REASON_INVALID_TOKEN: &str = onbehalf_proxy::auth::REASON_INVALID_TOKEN;
/// 401 reason: the delegation token verified but has expired.
pub const REASON_TOKEN_EXPIRED: &str = onbehalf_proxy::auth::REASON_TOKEN_EXPIRED;

/// Did verification fail only because the token (or a hop of its chain) has expired?
pub fn is_expiry(e: &onbehalf_token::TokenError) -> bool {
    matches!(
        e,
        onbehalf_token::TokenError::Expired
            | onbehalf_token::TokenError::Chain(onbehalf_core::ChainError::HopExpired { .. })
    )
}

/// An error a handler returns. `code` is short and machine-readable; `detail` is for humans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: String,
    pub detail: String,
    /// Stable sub-code, sent as `error_description` (RFC 6749 §5.2) when set.
    pub description: Option<&'static str>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            detail: detail.into(),
            description: None,
        }
    }

    /// Attach a stable `error_description` sub-code.
    pub fn with_description(mut self, description: &'static str) -> Self {
        self.description = Some(description);
        self
    }

    pub fn bad_request(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, detail)
    }

    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", detail)
    }

    /// A 401 whose body carries only the stable `reason` code, as both `detail` and
    /// `error_description` (`missing_token`, `invalid_token`, `token_expired`). `internal` (the
    /// verifier's complaint: wrong audience, unknown `kid` and so on) is logged at debug level
    /// and never returned (SR-17).
    pub fn unauthorized(reason: &'static str, internal: impl std::fmt::Display) -> Self {
        tracing::debug!(reason, detail = ?internal.to_string(), "authentication failed");
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", reason).with_description(reason)
    }

    /// A 401 for a delegation token that did not verify: `token_expired` when it verified but
    /// has expired, `invalid_token` otherwise.
    pub fn bad_token(e: &onbehalf_token::TokenError) -> Self {
        let reason = if is_expiry(e) {
            REASON_TOKEN_EXPIRED
        } else {
            REASON_INVALID_TOKEN
        };
        Self::unauthorized(reason, e)
    }

    pub fn internal(detail: impl std::fmt::Display) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            detail.to_string(),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            // `detail` can quote the request (SR-18): Debug-format it.
            tracing::error!(code = ?self.code, detail = ?self.detail, "request failed");
        } else {
            tracing::debug!(status = %self.status, code = ?self.code, detail = ?self.detail, "request rejected");
        }
        let mut body = json!({ "error": self.code, "detail": self.detail });
        if let Some(d) = self.description {
            body["error_description"] = d.into();
        }
        let mut resp = (self.status, Json(body)).into_response();
        resp.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
        if self.status == StatusCode::UNAUTHORIZED && self.code == "invalid_client" {
            // RFC 6749 §5.2: a 401 for client authentication names the scheme.
            resp.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Basic realm=\"onbehalf\""),
            );
        }
        if self.status == StatusCode::UNAUTHORIZED {
            // RFC 9449 §7.1: a DPoP failure names the DPoP scheme and the accepted algorithms.
            let err = match self.code.as_str() {
                crate::dpop::DPOP_REQUIRED => Some(onbehalf_proxy::AuthError::DpopRequired),
                crate::dpop::INVALID_DPOP_PROOF => {
                    Some(onbehalf_proxy::AuthError::InvalidDpopProof(String::new()))
                }
                _ => None,
            };
            if let Some(v) =
                err.and_then(|e| axum::http::HeaderValue::from_str(&e.challenge()).ok())
            {
                resp.headers_mut()
                    .insert(axum::http::header::WWW_AUTHENTICATE, v);
            }
        }
        resp
    }
}

impl From<onbehalf_audit::AuditError> for ApiError {
    fn from(e: onbehalf_audit::AuditError) -> Self {
        match e {
            onbehalf_audit::AuditError::UnknownLease(id) => {
                ApiError::not_found(format!("unknown lease `{id}`"))
            }
            other => ApiError::internal(other),
        }
    }
}

/// Map a token error to an OAuth-style error code and status.
///
/// Attenuation and depth violations are `invalid_scope` (the request asked for more than the
/// parent holds); every other verification failure of the subject token is `invalid_grant`;
/// key problems are server errors.
impl From<onbehalf_token::TokenError> for ApiError {
    fn from(e: onbehalf_token::TokenError) -> Self {
        use onbehalf_core::ChainError;
        use onbehalf_token::TokenError;
        let code = match &e {
            TokenError::Chain(ChainError::DuplicateAgent { .. }) => {
                return ApiError::bad_request("invalid_request", e.to_string())
                    .with_description("duplicate_actor")
            }
            TokenError::Chain(ChainError::AttenuationViolated { .. })
            | TokenError::Chain(ChainError::TooDeep { .. }) => "invalid_scope",
            TokenError::ActorNotPermitted(_) => {
                return ApiError::bad_request("invalid_request", e.to_string())
                    .with_description("actor_not_permitted")
            }
            TokenError::NoLifetimeLeft(_) => {
                return ApiError::bad_request("invalid_request", e.to_string())
                    .with_description("no_lifetime_left")
            }
            TokenError::Key(_) => return ApiError::internal(e),
            TokenError::BindingRequired => {
                return crate::dpop::DpopFailure::Required(e.to_string()).into()
            }
            _ => "invalid_grant",
        };
        ApiError::bad_request(code, e.to_string())
    }
}
