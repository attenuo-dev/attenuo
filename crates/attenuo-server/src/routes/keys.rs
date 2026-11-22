//! `POST /admin/keys/reload`: rotate the issuer's signing key, and change the retired keys that
//! still verify, without a restart. What follows the reload and what does not is in
//! [`crate::issuer_keys`].

use std::collections::BTreeSet;
use std::sync::Arc;

use attenuo_core::Decision;
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use super::admin::{audited_refusal, audited_refusal_with, IDENTITY_SECTIONS};
use super::extract::Body;
use super::{audit_admin, REASON_ADMIN_ACTION};
use crate::error::ApiError;
use crate::issuer_keys::{IssuerKeys, KeyFileError, KeyPaths};
use crate::operators::AdminIdentity;
use crate::state::AppState;

/// The audit record's tool.
const TOOL: &str = "admin.keys.reload";

/// The body of `POST /admin/keys/reload`: empty, or overrides of three refusals.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysReloadBody {
    /// Accept a new signing key while the current one is not among the new verifying keys:
    /// every token it signed stops verifying at once. Without it that is refused
    /// (`keys_reload_drops_current`).
    #[serde(default)]
    pub allow_drop_current: bool,
    /// Accept new verifying keys that leave out a key that signed an audit checkpoint or prune
    /// anchor the log still holds (or the key that signs them now): `audit verify` then
    /// reports them as signed by an unknown key. Without it that is refused
    /// (`keys_reload_drops_audit_key`).
    #[serde(default)]
    pub allow_drop_audit_key: bool,
    /// Accept a file whose `[issuer]` (but its key files) or `[audit]` differs from the config
    /// in force: without it that is refused (`config_file_mismatch`), since it is most likely
    /// another server's file.
    #[serde(default)]
    pub allow_mismatch: bool,
}

/// `POST /admin/keys/reload`: re-read `[issuer] private_key_pem_path` and
/// `previous_key_paths` from the config file the server was started with (the paths as the
/// file on disk gives them now), read those key files, and put the new signing key and the new
/// verifying keys in force in one step. Tokens signed by a key that is still among the
/// verifying keys keep verifying; new tokens, approval tokens, audit checkpoints and prune
/// anchors are signed with the new key; the JWKS lists the new set. The other settings of
/// `[issuer]` (`issuer`, `audience`, the lifetimes) stay as they are; a section of the file that
/// differs from the one in force is named in `restart_needed` and is not applied.
///
/// Answers the `kid`s only, never a key or a file's content: `signing_kid` and
/// `previous_signing_kid`, `changed` (whether the signing key or the verifying set differs),
/// `verifying_kids` (the signing key first), the kids `added` to and `removed` from the
/// verifying set, `audit_signing_kid`, `kept_until_restart` (what stays keyed by the startup
/// key: DPoP nonces, subject digests), `restart_needed`, `warnings`, and the id of the audit
/// record.
///
/// # Errors
///
/// Nothing changes on any error. 409 `reload_unavailable` when the server was not started
/// from a config file; 500 `config_unreadable` when the file cannot be read (the cause is in
/// the log); 400 `invalid_request` for a body that is not the expected JSON; 422
/// `keys_config_invalid` when the file does not parse as the server's config or sets no
/// `[issuer] private_key_pem_path` (a reload never generates a key); 422
/// `config_file_mismatch` without `allow_mismatch`; 422 `key_file_unreadable`,
/// `key_file_invalid` or `key_duplicate` for a key file that cannot be read, holds no Ed25519
/// key of the kind wanted, or holds the same key as another; 422 `keys_reload_drops_current`
/// without `allow_drop_current`; 422 `keys_reload_drops_audit_key` without
/// `allow_drop_audit_key`; 500 `server_error` when the file cannot be compared with the config
/// in force (not expected). The 422s are audited as a `deny`; the 400, 409 and 500s are not.
pub async fn reload_keys(
    State(state): State<Arc<AppState>>,
    Extension(who): Extension<AdminIdentity>,
    Body(body): Body,
) -> Result<Json<Value>, ApiError> {
    let opts: KeysReloadBody = if body.is_empty() {
        KeysReloadBody::default()
    } else {
        super::parse_json(&body)?
    };
    let path = state.config_path.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "reload_unavailable",
            "the server was not started from a config file; there is nothing to reload",
        )
    })?;
    // One reload at a time, from reading the file to the swap.
    let _reloading = state.keys_reload.lock().await;
    let text = tokio::fs::read_to_string(&path).await.map_err(|e| {
        ApiError::internal(format!("reading {}: {e}", path.display()))
            .with_code("config_unreadable")
    })?;
    let now = state.now();
    let unchanged = "the signing key and the verifying keys in force are unchanged";
    let (file, env_set) =
        match crate::config::Config::reparse_with_overrides(&text, std::env::vars_os()) {
            Ok(parsed) => parsed,
            Err(e) => {
                let refusal = ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "keys_config_invalid",
                    format!("{e:#}; {unchanged}"),
                );
                return Err(audited_refusal(&state, who, TOOL, &path, refusal, now).await);
            }
        };
    let Some(signing_path) = file.issuer.private_key_pem_path.clone() else {
        let refusal = ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys_config_invalid",
            format!(
                "the file sets no [issuer] private_key_pem_path: a reload reads the signing key \
                 from a file and never generates one; {unchanged}"
            ),
        );
        return Err(audited_refusal(&state, who, TOOL, &path, refusal, now).await);
    };
    // Not expected to fail: the config serialized at startup. Without the comparison the
    // mismatch check cannot be made, so nothing is applied.
    let sections = file.section_digests().map_err(|e| {
        ApiError::internal(format!(
            "the file could not be compared with the config in force ({e:#}); {unchanged}"
        ))
    })?;
    let restart_needed = state.config_sections.differing(&sections);
    let foreign: Vec<&str> = IDENTITY_SECTIONS
        .into_iter()
        .filter(|s| restart_needed.iter().any(|r| r == s))
        .collect();
    if !foreign.is_empty() && !opts.allow_mismatch {
        let refusal = ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "config_file_mismatch",
            format!(
                "the file's {} differs from the running config: it may be another server's \
                 file. Send {{\"allow_mismatch\": true}} (attenuo admin key reload \
                 --allow-mismatch) to reload its keys anyway; {unchanged}",
                foreign.join(" and ")
            ),
        );
        return Err(audited_refusal(&state, who, TOOL, &path, refusal, now).await);
    }

    let current = state.keys();
    // The `iss`, `aud` and lifetimes in force: only the keys change.
    let issuer = match crate::issuer_keys::read_key_files(
        current.issuer.config().clone(),
        &signing_path,
        &file.issuer.previous_key_paths,
    )
    .await
    {
        Ok(issuer) => issuer,
        Err(e) => {
            let detail = format!("{e}; {unchanged}");
            let refusal = match e {
                KeyFileError::Unreadable { .. } => ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "key_file_unreadable",
                    detail,
                ),
                KeyFileError::Invalid { .. } => {
                    ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "key_file_invalid", detail)
                }
                KeyFileError::Duplicate { .. } => {
                    ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "key_duplicate", detail)
                }
            };
            return Err(audited_refusal(&state, who, TOOL, &path, refusal, now).await);
        }
    };
    let new = IssuerKeys::new(issuer)
        .map_err(|e| ApiError::internal(format!("{e:#}")))?
        .with_paths(KeyPaths::of(&file.issuer));
    let (old_signing, new_signing) = (current.issuer.key_id(), new.issuer.key_id());
    let (old_kids, new_kids) = (current.kids(), new.kids());
    let kid_args = || {
        json!({
            "signing_kid": new_signing,
            "previous_signing_kid": old_signing,
            "verifying_kids": new_kids,
        })
    };

    // Every live token signed by the current key would stop verifying at once.
    if new_signing != old_signing && !new_kids.contains(&old_signing) && !opts.allow_drop_current {
        let refusal = ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys_reload_drops_current",
            format!(
                "the new signing key is kid `{new_signing}` and the current one, kid \
                 `{old_signing}`, is not in [issuer] previous_key_paths: every token it signed \
                 would stop verifying at once. List the current key file in previous_key_paths \
                 for an overlap, or send {{\"allow_drop_current\": true}} (attenuo admin key \
                 reload --allow-drop-current) to drop it; {unchanged}"
            ),
        );
        return Err(audited_refusal_with(&state, who, TOOL, &path, kid_args(), refusal, now).await);
    }

    // Keys that signed what the audit log holds, and the key that signs it now.
    let audit_kids = state
        .blocking(|s| {
            let mut kids = s.audit.signing_kids()?;
            kids.extend(s.audit.checkpoint_signer_kid());
            Ok::<_, attenuo_audit::AuditError>(kids)
        })
        .await?;
    let dropped_audit: Vec<String> = audit_kids
        .into_iter()
        .filter(|k| !new_kids.contains(k))
        .collect();
    if !dropped_audit.is_empty() && !opts.allow_drop_audit_key {
        let mut args = kid_args();
        args["dropped_audit_kids"] = json!(dropped_audit);
        let refusal = ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys_reload_drops_audit_key",
            format!(
                "the new verifying keys leave out kid {}, which signed audit checkpoints or \
                 anchors the log holds (or signs them now): `audit verify` would report them as \
                 signed by an unknown key. Keep its file in [issuer] previous_key_paths, or send \
                 {{\"allow_drop_audit_key\": true}} (attenuo admin key reload \
                 --allow-drop-audit-key) to drop it; {unchanged}",
                backquoted(&dropped_audit)
            ),
        );
        return Err(audited_refusal_with(&state, who, TOOL, &path, args, refusal, now).await);
    }

    let changed = new_kids != old_kids;
    let added: Vec<&String> = new_kids.iter().filter(|k| !old_kids.contains(k)).collect();
    let removed: Vec<&String> = old_kids.iter().filter(|k| !new_kids.contains(k)).collect();
    let mut warnings: Vec<String> = removed
        .iter()
        .map(|kid| {
            // A child token's `ou_sig` is checked under the key its `ou_kid` names, so a
            // token signed by a kept key but rooted under this one stops verifying too.
            if **kid == old_signing {
                format!(
                    "tokens signed by kid `{kid}`, or rooted under it (ou_kid), no longer \
                     verify: their agents must get new ones"
                )
            } else {
                format!(
                    "tokens signed by the retired kid `{kid}`, or rooted under it (ou_kid), no \
                     longer verify"
                )
            }
        })
        .collect();
    // A key path set by the environment wins over the file at a reload as at startup, so an
    // edit of that line in the file does nothing.
    for o in env_set
        .iter()
        .filter(|o| KEY_PATH_KEYS.contains(&o.key.as_str()))
    {
        warnings.push(format!(
            "{} comes from the environment ({}), not from the file: an edit of that line in \
             the file has no effect while the variable is set",
            o.key, o.variable
        ));
    }
    if !dropped_audit.is_empty() {
        warnings.push(format!(
            "audit checkpoints and anchors signed by kid {} no longer verify against the JWKS",
            backquoted(&dropped_audit)
        ));
    }
    if !changed && new.paths() != current.paths() {
        // The same keys from other files: only what an agents reload compares changes.
        state.keys.swap(new);
    } else if changed {
        // The verifying set first, then the audit signer: a checkpoint signed with the new key
        // is never checked against a set without it. A request in flight finishes with the
        // snapshot it took.
        let signer = new.issuer.detached_signer();
        state.keys.swap(new);
        if let Err(e) = state.audit.set_checkpoint_signer(signer) {
            // Not expected: the server always signs checkpoints.
            tracing::error!(error = %e, "the audit checkpoint signer was not swapped");
        }
    }
    let audit_signing_kid = state.audit.checkpoint_signer_kid();
    // What stays keyed by the startup key, once the signing key is another.
    let kept_until_restart: &[&str] = if new_signing == state.startup_kid {
        &[]
    } else {
        &state.startup_key_uses
    };
    for w in &warnings {
        tracing::warn!(warning = ?w, "keys reload");
    }
    tracing::info!(
        signing_kid = %new_signing,
        previous_signing_kid = %old_signing,
        changed,
        added = ?added,
        removed = ?removed,
        restart_needed = ?restart_needed,
        "issuer keys reloaded"
    );
    let args = json!({
        "path": path,
        "signing_kid": new_signing,
        "previous_signing_kid": old_signing,
        "changed": changed,
        "verifying_kids": new_kids,
        "added": added,
        "removed": removed,
        "restart_needed": restart_needed,
    });
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
        .inspect_err(|e| tracing::error!(error = ?e.detail, "keys reload was not audited"))
        .ok();
    Ok(Json(json!({
        "signing_kid": new_signing,
        "previous_signing_kid": old_signing,
        "changed": changed,
        "verifying_kids": new_kids,
        "added": added,
        "removed": removed,
        "audit_signing_kid": audit_signing_kid,
        "kept_until_restart": kept_until_restart,
        "restart_needed": restart_needed,
        "warnings": warnings,
        "audit_id": audit_id,
    })))
}

/// The `[issuer]` keys that name key files, as an [`crate::config::EnvOverride`] names them.
const KEY_PATH_KEYS: [&str; 2] = [
    "[issuer] private_key_pem_path",
    "[issuer] previous_key_paths",
];

/// `` `a`, `b` `` for a refusal's text.
fn backquoted(kids: &[String]) -> String {
    let set: BTreeSet<&String> = kids.iter().collect();
    set.into_iter()
        .map(|k| format!("`{k}`"))
        .collect::<Vec<_>>()
        .join(", ")
}
