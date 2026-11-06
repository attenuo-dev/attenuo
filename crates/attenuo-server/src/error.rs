//! JSON error responses: `{"error": "<code>", "detail": "<human-readable text>"}`, plus a
//! stable machine-readable sub-code in `error_description` where one is defined (IdP intake at
//! `POST /token`, see `crate::idp::IntakeError`).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// 401 reason: no credential was sent.
pub const REASON_MISSING_TOKEN: &str = attenuo_proxy::auth::REASON_MISSING_TOKEN;
/// 401 reason: the credential is malformed, not ours, or fails verification.
pub const REASON_INVALID_TOKEN: &str = attenuo_proxy::auth::REASON_INVALID_TOKEN;
/// 401 reason: the delegation token verified but has expired.
pub const REASON_TOKEN_EXPIRED: &str = attenuo_proxy::auth::REASON_TOKEN_EXPIRED;

/// Did verification fail only because the token (or a hop of its chain) has expired?
pub fn is_expiry(e: &attenuo_token::TokenError) -> bool {
    matches!(
        e,
        attenuo_token::TokenError::Expired
            | attenuo_token::TokenError::Chain(attenuo_core::ChainError::HopExpired { .. })
    )
}

/// `detail` of every 500: the cause is in the server log only (SR-43).
pub const INTERNAL_DETAIL: &str = "internal error; the details are in the server log";

/// An error a handler returns. `code` is short and machine-readable; `detail` is for humans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    /// HTTP status of the response.
    pub status: StatusCode,
    /// Machine-readable code, sent as `error` in the body.
    pub code: String,
    /// Human-readable explanation, sent as `detail`. [`Self::internal`] sends
    /// [`INTERNAL_DETAIL`] here and keeps the cause in the log.
    pub detail: String,
    /// Stable sub-code, sent as `error_description` (RFC 6749 §5.2) when set.
    pub description: Option<&'static str>,
    /// The id of the `deny` audit record this refusal wrote, when it wrote one (a refused
    /// token exchange whose subject token verified, or a refused renewal whose token
    /// verified). Sent as `decision_id` in the body and in
    /// the `X-Attenuo-Decision-Id` header.
    pub decision_id: Option<uuid::Uuid>,
}

impl ApiError {
    /// An error with no `error_description` and no decision id.
    pub fn new(status: StatusCode, code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            detail: detail.into(),
            description: None,
            decision_id: None,
        }
    }

    /// Attach a stable `error_description` sub-code.
    pub fn with_description(mut self, description: &'static str) -> Self {
        self.description = Some(description);
        self
    }

    /// Attach the id of the audit record that recorded this refusal.
    pub fn with_decision_id(mut self, id: uuid::Uuid) -> Self {
        self.decision_id = Some(id);
        self
    }

    /// A 400 with this `code`.
    pub fn bad_request(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, detail)
    }

    /// A 404 with code `not_found`.
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
    pub fn bad_token(e: &attenuo_token::TokenError) -> Self {
        let reason = if is_expiry(e) {
            REASON_TOKEN_EXPIRED
        } else {
            REASON_INVALID_TOKEN
        };
        Self::unauthorized(reason, e)
    }

    /// A 500. `internal` (a storage error, which can name a database file and its state; a
    /// path that could not be read) is logged and never returned: the body says
    /// [`INTERNAL_DETAIL`] (SR-43, completing SR-17).
    pub fn internal(internal: impl std::fmt::Display) -> Self {
        // Debug-formatted: the text can quote the request (SR-18).
        tracing::error!(detail = ?internal.to_string(), "internal error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            INTERNAL_DETAIL,
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
        if let Some(id) = self.decision_id {
            body["decision_id"] = id.to_string().into();
        }
        let mut resp = (self.status, Json(body)).into_response();
        if let Some(v) = self
            .decision_id
            .and_then(|id| axum::http::HeaderValue::from_str(&id.to_string()).ok())
        {
            resp.headers_mut().insert(
                axum::http::HeaderName::from_static(attenuo_proxy::DECISION_ID_HEADER),
                v,
            );
        }
        resp.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
        if self.status == StatusCode::UNAUTHORIZED && self.code == "invalid_client" {
            // RFC 6749 §5.2: a 401 for client authentication names the scheme.
            resp.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Basic realm=\"attenuo\""),
            );
        }
        if self.status == StatusCode::UNAUTHORIZED {
            // RFC 9449 §7.1: a DPoP failure names the DPoP scheme and the accepted algorithms.
            let err = match self.code.as_str() {
                crate::dpop::DPOP_REQUIRED => Some(attenuo_proxy::AuthError::DpopRequired),
                crate::dpop::INVALID_DPOP_PROOF => {
                    Some(attenuo_proxy::AuthError::InvalidDpopProof(String::new()))
                }
                crate::dpop::USE_NONCE => {
                    Some(attenuo_proxy::AuthError::UseDpopNonce(String::new()))
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

/// The one mapping of a store refusal to an HTTP answer, so a route that uses `?` on a domain
/// variant answers with its status rather than a 500.
///
/// | Variant | Status | `error` |
/// |---|---|---|
/// | `UnknownLease`, `UnknownApproval`, `UnknownCharge` | 404 | `not_found` |
/// | `ApprovalNotPending` | 409 | `approval_not_pending` |
/// | `ApprovalExpired` | 409 | `approval_expired` |
/// | `LeaseRevoked` | 409 | `lease_revoked` |
/// | `ChargeRefunded` | 409 | `already_refunded` |
/// | `TooManyPendingApprovals` | 429 | `too_many_pending_approvals` |
/// | storage, lock, encoding, `BindingConflict`, `NoCheckpointSigner`, `Export`, `Jwks` | 500 | `server_error`, no detail (SR-43) |
///
/// A route whose answer depends on more than the variant keeps its own arm before falling back
/// to this: `POST /token/renew` refuses a revoked or unknown own lease as `invalid_grant` with
/// an audited deny record, and `POST /admin/budgets/refund` reads the audit log to tell an
/// unknown decision from a pruned charge (410 `charge_pruned`). `BindingConflict` is a 500
/// because a lease is bound only once, at issuance, to a lease id the server just made: a
/// conflict there is a server fault. `Export` and `Jwks` come from offline verification, which
/// no route runs.
impl From<attenuo_audit::AuditError> for ApiError {
    fn from(e: attenuo_audit::AuditError) -> Self {
        use attenuo_audit::AuditError as E;
        match e {
            E::UnknownLease(id) => ApiError::not_found(format!("unknown lease `{id}`")),
            E::UnknownApproval(id) => ApiError::not_found(format!("unknown approval `{id}`")),
            E::UnknownCharge(id) => {
                ApiError::not_found(format!("no budget charge is recorded for decision `{id}`"))
            }
            E::ApprovalNotPending { state, .. } => ApiError::new(
                StatusCode::CONFLICT,
                "approval_not_pending",
                format!("the approval is already {state}"),
            ),
            E::ApprovalExpired(_) => ApiError::new(
                StatusCode::CONFLICT,
                "approval_expired",
                "the approval, or the lease it is bound to, has expired",
            ),
            // Only the approval routes reach this: renewal answers a revoked lease itself.
            E::LeaseRevoked(_) => ApiError::new(
                StatusCode::CONFLICT,
                "lease_revoked",
                "the lease the approval is bound to has been revoked",
            ),
            E::ChargeRefunded(id) => ApiError::new(
                StatusCode::CONFLICT,
                "already_refunded",
                format!("the charge of decision `{id}` was already refunded"),
            ),
            // Only the pipeline creates approvals, and it answers this itself (a gated call
            // with no approval to grant, SR-92); a route that ever reaches it says the same.
            E::TooManyPendingApprovals { max, .. } => ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_pending_approvals",
                format!("the run already has {max} pending approvals"),
            ),
            // Listed one by one so that a new variant needs a decision here.
            e @ (E::Sqlite(_)
            | E::Serde(_)
            | E::TimeFormat(_)
            | E::TimeParse(_)
            | E::Storage(_)
            | E::Poisoned
            | E::Corrupt { .. }
            | E::Export(_)
            | E::NoCheckpointSigner
            | E::Jwks(_)
            | E::BindingConflict(_)) => ApiError::internal(e),
        }
    }
}

/// Map a token error to an OAuth-style error code and status.
///
/// Attenuation and depth violations are `invalid_scope` (the request asked for more than the
/// parent holds); every other verification failure of the subject token is `invalid_grant`;
/// key problems are server errors.
impl From<attenuo_token::TokenError> for ApiError {
    fn from(e: attenuo_token::TokenError) -> Self {
        use attenuo_core::ChainError;
        use attenuo_token::TokenError;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// SR-43: a storage error (here as `AuditError` would carry it) never reaches the body.
    #[tokio::test]
    async fn internal_errors_keep_their_detail_in_the_log() {
        let e: ApiError = attenuo_audit::AuditError::Storage(
            "unable to open /var/lib/attenuo/audit.sqlite: disk I/O error".into(),
        )
        .into();
        assert_eq!(e.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(e.detail, INTERNAL_DETAIL);
        let body = axum::body::to_bytes(e.into_response().into_body(), 4096)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            !text.contains("/var/lib") && !text.contains("disk I/O"),
            "{text}"
        );
    }

    /// One value of every `AuditError` variant.
    fn one_of_each_audit_error() -> Vec<attenuo_audit::AuditError> {
        use attenuo_audit::AuditError as E;
        let parse = time::OffsetDateTime::parse(
            "not a time",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap_err();
        vec![
            E::Sqlite(rusqlite::Error::QueryReturnedNoRows),
            E::Serde(serde_json::from_str::<serde_json::Value>("{").unwrap_err()),
            E::TimeFormat(time::error::Format::InvalidComponent("offset")),
            E::TimeParse(parse),
            E::Storage("disk I/O error".into()),
            E::Poisoned,
            E::Corrupt {
                seq: 7,
                detail: "bad json".into(),
            },
            E::Export("line 3".into()),
            E::NoCheckpointSigner,
            E::Jwks("no keys".into()),
            E::UnknownLease("l1".into()),
            E::LeaseRevoked("l1".into()),
            E::BindingConflict("l1".into()),
            E::UnknownApproval("a1".into()),
            E::ApprovalNotPending {
                id: "a1".into(),
                state: "granted",
            },
            E::ApprovalExpired("a1".into()),
            E::UnknownCharge("d1".into()),
            E::ChargeRefunded("d1".into()),
            E::TooManyPendingApprovals {
                chain_id: "l1".into(),
                max: 32,
            },
        ]
    }

    /// Only a store fault answers 500: every domain refusal of the lease store has a 4xx, so a
    /// route's `?` on one cannot turn it into "internal error". The match below has no
    /// wildcard: a new variant does not compile here until it is classed as a fault or a
    /// refusal, and added to [`one_of_each_audit_error`] (the test checks that every
    /// variant appears there exactly once).
    #[test]
    fn only_store_faults_answer_500() {
        use attenuo_audit::AuditError as E;
        // (position in declaration order, is a store fault)
        fn class(e: &E) -> (usize, bool) {
            match e {
                E::Sqlite(_) => (0, true),
                E::Serde(_) => (1, true),
                E::TimeFormat(_) => (2, true),
                E::TimeParse(_) => (3, true),
                E::Storage(_) => (4, true),
                E::Poisoned => (5, true),
                E::Corrupt { .. } => (6, true),
                E::Export(_) => (7, true),
                E::NoCheckpointSigner => (8, true),
                E::Jwks(_) => (9, true),
                E::UnknownLease(_) => (10, false),
                E::LeaseRevoked(_) => (11, false),
                // Bound once, at issuance, to a lease id the server just made.
                E::BindingConflict(_) => (12, true),
                E::UnknownApproval(_) => (13, false),
                E::ApprovalNotPending { .. } => (14, false),
                E::ApprovalExpired(_) => (15, false),
                E::UnknownCharge(_) => (16, false),
                E::ChargeRefunded(_) => (17, false),
                E::TooManyPendingApprovals { .. } => (18, false),
            }
        }
        let all = one_of_each_audit_error();
        let positions: Vec<usize> = all.iter().map(|e| class(e).0).collect();
        assert_eq!(
            positions,
            (0..all.len()).collect::<Vec<_>>(),
            "one_of_each_audit_error must list every variant once, in declaration order"
        );
        for e in all {
            let (_, fault) = class(&e);
            let name = format!("{e:?}");
            let got = ApiError::from(e);
            if fault {
                assert_eq!(got.status, StatusCode::INTERNAL_SERVER_ERROR, "{name}");
                assert_eq!(got.code, "server_error", "{name}");
                assert_eq!(got.detail, INTERNAL_DETAIL, "{name}");
            } else {
                assert!(got.status.is_client_error(), "{name}: {}", got.status);
                assert_ne!(got.detail, INTERNAL_DETAIL, "{name}");
            }
        }
    }

    /// Every `AuditError` variant has one status, one `error` code and, for a 500, no detail
    /// of its own (SR-43). The route tests pin the same answers end to end.
    #[test]
    fn every_audit_error_has_one_answer() {
        use attenuo_audit::AuditError as E;
        use StatusCode as S;
        let parse = time::OffsetDateTime::parse(
            "not a time",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap_err();
        let serde = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
        let cases: Vec<(E, S, &str, Option<&str>)> = vec![
            (
                E::UnknownLease("l1".into()),
                S::NOT_FOUND,
                "not_found",
                Some("unknown lease `l1`"),
            ),
            (
                E::UnknownApproval("a1".into()),
                S::NOT_FOUND,
                "not_found",
                Some("unknown approval `a1`"),
            ),
            (
                E::UnknownCharge("d1".into()),
                S::NOT_FOUND,
                "not_found",
                Some("no budget charge is recorded for decision `d1`"),
            ),
            (
                E::ApprovalNotPending {
                    id: "a1".into(),
                    state: "granted",
                },
                S::CONFLICT,
                "approval_not_pending",
                Some("the approval is already granted"),
            ),
            (
                E::ApprovalExpired("a1".into()),
                S::CONFLICT,
                "approval_expired",
                Some("the approval, or the lease it is bound to, has expired"),
            ),
            (
                E::LeaseRevoked("l1".into()),
                S::CONFLICT,
                "lease_revoked",
                Some("the lease the approval is bound to has been revoked"),
            ),
            (
                E::ChargeRefunded("d1".into()),
                S::CONFLICT,
                "already_refunded",
                Some("the charge of decision `d1` was already refunded"),
            ),
            (
                E::TooManyPendingApprovals {
                    chain_id: "l1".into(),
                    max: 32,
                },
                S::TOO_MANY_REQUESTS,
                "too_many_pending_approvals",
                Some("the run already has 32 pending approvals"),
            ),
            (
                E::Sqlite(rusqlite::Error::QueryReturnedNoRows),
                S::INTERNAL_SERVER_ERROR,
                "server_error",
                None,
            ),
            (
                E::Serde(serde),
                S::INTERNAL_SERVER_ERROR,
                "server_error",
                None,
            ),
            (
                E::TimeFormat(time::error::Format::InvalidComponent("offset")),
                S::INTERNAL_SERVER_ERROR,
                "server_error",
                None,
            ),
            (
                E::TimeParse(parse),
                S::INTERNAL_SERVER_ERROR,
                "server_error",
                None,
            ),
            (
                E::Storage("/var/lib/attenuo/audit.db: disk I/O error".into()),
                S::INTERNAL_SERVER_ERROR,
                "server_error",
                None,
            ),
            (E::Poisoned, S::INTERNAL_SERVER_ERROR, "server_error", None),
            (
                E::Corrupt {
                    seq: 7,
                    detail: "bad json".into(),
                },
                S::INTERNAL_SERVER_ERROR,
                "server_error",
                None,
            ),
            (
                E::Export("line 3".into()),
                S::INTERNAL_SERVER_ERROR,
                "server_error",
                None,
            ),
            (
                E::NoCheckpointSigner,
                S::INTERNAL_SERVER_ERROR,
                "server_error",
                None,
            ),
            (
                E::Jwks("no keys".into()),
                S::INTERNAL_SERVER_ERROR,
                "server_error",
                None,
            ),
            (
                E::BindingConflict("l1".into()),
                S::INTERNAL_SERVER_ERROR,
                "server_error",
                None,
            ),
        ];
        // One case per variant (the `From` match lists them all, so a new one fails to compile
        // there first).
        assert_eq!(cases.len(), 19);
        for (e, status, code, detail) in cases {
            let name = format!("{e:?}");
            let got = ApiError::from(e);
            assert_eq!(got.status, status, "{name}");
            assert_eq!(got.code, code, "{name}");
            assert_eq!(got.detail, detail.unwrap_or(INTERNAL_DETAIL), "{name}");
            assert_eq!(got.description, None, "{name}");
        }
    }
}
