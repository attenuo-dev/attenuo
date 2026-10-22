//! JSON error responses: `{"error": "<code>", "detail": "<human-readable text>"}`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// An error a handler returns. `code` is short and machine-readable; `detail` is for humans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: String,
    pub detail: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            detail: detail.into(),
        }
    }

    pub fn bad_request(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, detail)
    }

    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", detail)
    }

    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", detail)
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
            tracing::error!(code = %self.code, detail = %self.detail, "request failed");
        } else {
            tracing::debug!(status = %self.status, code = %self.code, detail = %self.detail, "request rejected");
        }
        let body = Json(json!({ "error": self.code, "detail": self.detail }));
        let mut resp = (self.status, body).into_response();
        resp.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
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
            TokenError::Chain(ChainError::AttenuationViolated { .. })
            | TokenError::Chain(ChainError::TooDeep { .. }) => "invalid_scope",
            TokenError::Key(_) => return ApiError::internal(e),
            _ => "invalid_grant",
        };
        ApiError::bad_request(code, e.to_string())
    }
}
