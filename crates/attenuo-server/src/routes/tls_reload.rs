//! `POST /admin/tls/reload`: put a renewed server certificate of `[server.tls]` in force without
//! a restart. What a reload reads, checks and changes is in the private `tls` module.

use std::sync::Arc;

use attenuo_core::Decision;
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde_json::{json, Value};

use super::{audit_admin, REASON_ADMIN_ACTION};
use crate::error::ApiError;
use crate::operators::AdminIdentity;
use crate::state::AppState;
use crate::tls::{LoadError, Problem};

/// The audit record's tool.
const TOOL: &str = "admin.tls.reload";

/// `POST /admin/tls/reload`: read `[server.tls] cert_pem_path` and `key_pem_path` again (the
/// paths read at startup; a reload never re-reads the config file), check them as startup
/// does and also check the first certificate's dates, then put the new certificate chain and
/// key in force for every connection accepted from then on. Connections that are already open
/// keep the certificate they were made with. TLS 1.3 only, ALPN `http/1.1`, no session
/// resumption and `client_certificates` stay as they were: they come from the code and the
/// startup settings, never from the files.
///
/// The request takes no body (one is ignored). Answers `changed` (whether the first
/// certificate differs from the one it replaces), `certificate_sha256` and
/// `previous_certificate_sha256` (SHA-256 of each first certificate's DER, hex), `not_before`
/// and `not_after` of the new one (RFC 3339), `chain_length`, and the id of the audit record.
/// Never a key, a file's content or a path.
///
/// # Errors
///
/// Nothing changes on any error: the certificate in force keeps serving. 409
/// `reload_unavailable` without `[server.tls]`; 422 `tls_file_unreadable` (a file cannot be
/// read, is not a regular file, is too large, or the key file's owner or mode is refused), 422
/// `tls_file_invalid` (empty, no certificate or key, not PEM, a key in the certificate file,
/// more than one key, a key or certificate that cannot be used, undated), 422
/// `tls_key_mismatch` (the key does not belong to the first certificate), 422
/// `tls_certificate_expired` and 422 `tls_certificate_not_yet_valid`. The message names the
/// setting and the problem, never the path or the content. The 422s are audited as a `deny`
/// and counted as `failed` in `tls_certificate_reloads_total`; the 409 is neither.
pub async fn reload_tls(
    State(state): State<Arc<AppState>>,
    Extension(who): Extension<AdminIdentity>,
) -> Result<Json<Value>, ApiError> {
    let Some(tls) = state.main_tls.clone() else {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "reload_unavailable",
            "[server.tls] is not configured: the main listener speaks plain HTTP, so there is \
             no certificate to reload",
        ));
    };
    // One reload at a time, from reading the files to the swap.
    let _reloading = tls.reloading.lock().await;
    let now = state.now();
    let section = tls.section().clone();
    let paths = json!({
        "cert_pem_path": section.cert_pem_path,
        "key_pem_path": section.key_pem_path,
    });
    let reader = Arc::clone(&tls);
    let read = state.blocking(move |_| reader.read_new(now)).await;
    let new = match read {
        Ok(new) => new,
        Err(e) => {
            state.metrics.tls_reload(false);
            let refusal = refusal(&e);
            let code = refusal.stable_code().to_string();
            tracing::warn!(code, detail = %e.reload_message(), "TLS certificate reload refused");
            let mut args = paths;
            args["previous_certificate_sha256"] = json!(tls.current().leaf_sha256_hex());
            let _ = state
                .blocking(move |state| {
                    audit_admin(
                        state,
                        &who,
                        TOOL,
                        Decision::Deny,
                        &code,
                        Vec::new(),
                        args,
                        now,
                    )
                })
                .await
                .inspect_err(
                    |e| tracing::error!(error = ?e.detail, "failed TLS reload was not audited"),
                );
            return Err(refusal);
        }
    };
    let certificate_sha256 = new.leaf_sha256_hex();
    let (not_before, not_after) = new
        .validity
        .map(|(b, a)| (crate::tls::rfc3339(b), crate::tls::rfc3339(a)))
        .unwrap_or_default();
    let chain_length = new.chain_len;
    let not_after_unix = new.not_after_unix();
    let old = tls.swap(new);
    state.metrics.tls_certificate_not_after(not_after_unix);
    state.metrics.tls_reload(true);
    let previous_certificate_sha256 = old.leaf_sha256_hex();
    let changed = certificate_sha256 != previous_certificate_sha256;
    tracing::info!(
        changed,
        certificate_sha256,
        previous_certificate_sha256,
        not_after,
        chain_length,
        "TLS certificate reloaded; new connections use it"
    );
    let summary = json!({
        "changed": changed,
        "certificate_sha256": certificate_sha256,
        "previous_certificate_sha256": previous_certificate_sha256,
        "not_before": not_before,
        "not_after": not_after,
        "chain_length": chain_length,
    });
    let mut args = paths;
    for (k, v) in summary.as_object().into_iter().flatten() {
        args[k] = v.clone();
    }
    let audit_id = state
        .blocking(move |state| {
            audit_admin(
                state,
                &who,
                TOOL,
                Decision::Allow,
                REASON_ADMIN_ACTION,
                Vec::new(),
                args,
                now,
            )
        })
        .await
        .inspect_err(|e| tracing::error!(error = ?e.detail, "TLS reload was not audited"))
        .ok();
    let mut body = summary;
    body["audit_id"] = json!(audit_id);
    Ok(Json(body))
}

/// The answer to a refused reload: 422 with the code of the problem, and a detail that names
/// the setting and the problem, never the path or a file's content.
fn refusal(e: &LoadError) -> ApiError {
    let detail = format!(
        "{}; the certificate in force is unchanged",
        e.reload_message()
    );
    match e.problem {
        Problem::Unreadable => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "tls_file_unreadable",
            detail,
        ),
        Problem::Invalid => {
            ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "tls_file_invalid", detail)
        }
        Problem::KeyMismatch => {
            ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "tls_key_mismatch", detail)
        }
        Problem::Expired => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "tls_certificate_expired",
            detail,
        ),
        Problem::NotYetValid => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "tls_certificate_not_yet_valid",
            detail,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::Setting;

    /// Every problem has its own code, registered as a 422.
    #[test]
    fn problems_have_distinct_registered_codes() {
        let all = [
            Problem::Unreadable,
            Problem::Invalid,
            Problem::KeyMismatch,
            Problem::Expired,
            Problem::NotYetValid,
        ];
        let mut codes = std::collections::BTreeSet::new();
        for problem in all {
            let e = LoadError {
                problem,
                setting: Setting::Cert,
                why: "why".into(),
            };
            let r = refusal(&e);
            let code = r.stable_code().to_string();
            let entry = attenuo_core::error_codes::lookup(&code)
                .unwrap_or_else(|| panic!("{code} is not in ERROR_CODES"));
            assert_eq!(entry.rest.len(), 1, "{code}");
            assert_eq!(entry.rest[0].status, 422, "{code}");
            assert_eq!(entry.rest[0].error, code, "{code}");
            codes.insert(code);
        }
        assert_eq!(codes.len(), all.len());
    }
}
