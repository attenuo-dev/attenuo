//! The audit retention routes (ADR-0015, `docs/design/audit-retention.md`): the prune plan,
//! the prune itself and the list of anchors. Admin role only.
//!
//! A prune writes, in one transaction, the checkpoint of the head, the prune record (an
//! `admin` record, tool `admin.audit.prune`), a signed anchor naming the last pruned seq and
//! its hash, and the checkpoint of the prune record. The rows at or below the boundary are
//! then deleted in batches by the maintenance task (`crate::maintenance_ticks`), so the
//! request never waits for them. With `[audit.sink]` the two checkpoints and the anchor are
//! queued for shipping as the transaction commits.

use std::sync::Arc;

use attenuo_audit::{
    AuditError, PlanBound, PruneGuard, PruneLimits, SinkProgress, StoredAnchor, PRUNE_TOOL,
};
use attenuo_core::Decision;
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::extract::{Body, Query};
use super::page;
use super::{admin_record, REASON_ADMIN_ACTION};
use crate::config::PruneMode;
use crate::error::ApiError;
use crate::operators::AdminIdentity;
use crate::state::AppState;

/// Default page of `GET /admin/audit/anchors`.
const DEFAULT_ANCHOR_PAGE: usize = 50;
/// Largest page of `GET /admin/audit/anchors`.
const MAX_ANCHOR_PAGE: usize = 500;

/// 409 `prune_disabled` unless `[audit.retention] prune` allows a prune.
fn require_enabled(state: &AppState) -> Result<(), ApiError> {
    match state.retention.prune {
        PruneMode::Off => Err(ApiError::new(
            StatusCode::CONFLICT,
            "prune_disabled",
            "the audit log is not pruned: [audit.retention] prune is \"off\"",
        )),
        PruneMode::Manual => Ok(()),
    }
}

/// The guards' inputs now: the age floor, the sink's progress and the clock.
fn limits(state: &AppState) -> PruneLimits {
    PruneLimits {
        min_age: state.retention.min_age(),
        sink: state.checkpoint_sink.as_ref().map(|s| SinkProgress {
            degraded: s.status().degraded,
            delivered_through: s.delivered_through(),
        }),
        now: state.now(),
    }
}

/// Query string of `GET /admin/audit/prune/plan`: at most one of the two.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanQuery {
    /// Prune at most through this seq.
    pub through: Option<u64>,
    /// Prune only entries older than this RFC 3339 time.
    pub before: Option<String>,
}

/// `GET /admin/audit/prune/plan?through=` or `?before=`: the largest boundary the guards
/// allow at or below the request (the head when neither is given), as `{from, through,
/// entries, checkpoint, at, guards, anchor}`. `through` is null when nothing can be pruned;
/// `guards` gives the bound each guard sets and `limited_by` the code of the one that set
/// `through` below the request. Reads only. The archive of a prune through `through` is the
/// export `from..=through`.
///
/// # Errors
///
/// 409 `prune_disabled` when `[audit.retention] prune` is `"off"`; 400 `invalid_request`
/// when both `through` and `before` are given or `before` is not RFC 3339; 500 `server_error`
/// when the audit log fails.
pub async fn prune_plan(
    State(state): State<Arc<AppState>>,
    Query(q): Query<PlanQuery>,
) -> Result<Json<Value>, ApiError> {
    require_enabled(&state)?;
    let bound = match (q.through, q.before.as_deref()) {
        (Some(_), Some(_)) => {
            return Err(ApiError::bad_request(
                "invalid_request",
                "give `through` or `before`, not both",
            ))
        }
        (Some(t), None) => PlanBound::Through(t),
        (None, Some(b)) => PlanBound::Before(OffsetDateTime::parse(b, &Rfc3339).map_err(|_| {
            ApiError::bad_request("invalid_request", "`before` must be an RFC 3339 time")
        })?),
        (None, None) => PlanBound::Through(u64::MAX),
    };
    let limits = limits(&state);
    let plan = state
        .blocking(move |s| s.audit.prune_plan(bound, &limits))
        .await?;
    Ok(Json(
        serde_json::to_value(plan).map_err(ApiError::internal)?,
    ))
}

/// Body of `POST /admin/audit/prune`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PruneBody {
    /// The last seq to prune: a checkpoint seq the plan allows.
    pub through: u64,
    /// Hex SHA-256 of the archive of `from..=through` the operator kept, signed into the
    /// anchor. The server never sees the archive and cannot check it.
    #[serde(default)]
    pub archive_sha256: Option<String>,
    /// The archive's first seq. When given, the prune is refused (409
    /// `prune_archive_mismatch`) unless it is the log's first retained seq, so the archive
    /// covers every entry the prune removes. Optional for older clients; send it.
    #[serde(default)]
    pub from: Option<u64>,
    /// The archive's last entry hash. When given, the prune is refused (409
    /// `prune_archive_mismatch`) unless it is the entry hash at `through`. Optional for older
    /// clients; send it.
    #[serde(default)]
    pub through_hash: Option<String>,
}

/// `POST /admin/audit/prune` with `{"through": B, "archive_sha256": "...", "from": F,
/// "through_hash": "..."}`: prune the log
/// through seq B. Answers `{prune_seq, anchor, checkpoint_before, checkpoint_after,
/// pruned_through, deleting, shipped, already}` once the prune is committed; the rows are
/// deleted afterwards, in batches of `[audit.retention] batch_rows`, by the maintenance task
/// (`deleting` is true until they are gone). `shipped` is null without `[audit.sink]`, else
/// `{queued, delivered_through, anchor_shipped_at, anchor_pending}`: whether the anchor (and,
/// for a new prune, the two checkpoints) were queued by this call, the highest checkpoint seq
/// the sink has delivered, when the sink delivered the anchor (null until it has), and
/// whether the anchor is queued and not yet delivered.
///
/// `from` (the archive's first seq) and `through_hash` (its last entry hash) are optional;
/// when given, the transaction refuses unless they are the first retained seq and the entry
/// hash at B, so the archive covers what is pruned. A repeat compares them with the stored
/// anchor.
///
/// Repeating a request that succeeded answers 200 with the stored anchor and
/// `"already": true`, and writes nothing.
///
/// # Errors
///
/// 400 `invalid_request` for a body that is not the expected JSON, a `through` of 0 or an
/// `archive_sha256` that is not 64 lower-case hex digits; 409 `prune_disabled`,
/// `prune_not_at_checkpoint`, `prune_too_recent`, `prune_live_run`, `sink_behind`,
/// `prune_in_progress`, `prune_conflict` (the same `through` was pruned with another
/// digest) or `prune_archive_mismatch` (`from` or `through_hash` do not match); 410 `audit_pruned` when `through` is below the current boundary; 500
/// `server_error` when the audit log fails (nothing is written).
pub async fn prune(
    State(state): State<Arc<AppState>>,
    Extension(who): Extension<AdminIdentity>,
    Body(body): Body,
) -> Result<Json<Value>, ApiError> {
    require_enabled(&state)?;
    let body: PruneBody = super::parse_json(&body)?;
    if body.through == 0 {
        return Err(ApiError::bad_request(
            "invalid_request",
            "`through` must be at least 1",
        ));
    }
    if let Some(d) = &body.archive_sha256 {
        if d.len() != 64 || !d.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(ApiError::bad_request(
                "invalid_request",
                "`archive_sha256` must be 64 lower-case hex digits",
            ));
        }
    }
    if let Some(h) = &body.through_hash {
        if h.len() != 64 || !h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(ApiError::bad_request(
                "invalid_request",
                "`through_hash` must be 64 lower-case hex digits",
            ));
        }
    }
    if body.from == Some(0) {
        return Err(ApiError::bad_request(
            "invalid_request",
            "`from` must be at least 1",
        ));
    }
    let expect = attenuo_audit::PruneExpect {
        from: body.from,
        through_hash: body.through_hash.clone(),
    };
    let limits = limits(&state);
    let now = limits.now;
    let out = state
        .blocking(move |s| {
            let done = s.audit.prune_through_expecting(
                body.through,
                body.archive_sha256,
                &expect,
                &limits,
                |args| {
                    admin_record(
                        &who,
                        PRUNE_TOOL,
                        Decision::Allow,
                        REASON_ADMIN_ACTION,
                        Vec::new(),
                        args.clone(),
                        now,
                    )
                },
            );
            // Below the boundary: answer with it, as every other 410 `audit_pruned` does.
            Ok::<_, AuditError>(match done {
                Err(AuditError::PruneRefused {
                    guard: PruneGuard::AlreadyPruned,
                    detail,
                }) => Err((detail, s.audit.newest_anchor()?)),
                other => Ok(other?),
            })
        })
        .await?
        .map_err(|(detail, anchor)| match anchor {
            Some(a) => ApiError::audit_pruned(detail, &a.anchor),
            None => ApiError::new(StatusCode::GONE, "audit_pruned", detail),
        })?;
    let a = &out.anchor.anchor;
    if !out.already {
        tracing::warn!(
            through = a.through_seq,
            prune_seq = a.prune_seq,
            previous_through_seq = ?a.previous_through_seq,
            archive_sha256 = ?a.archive_sha256,
            "audit log pruned; the rows are deleted in the background"
        );
    }
    // A repeat finds the anchor queued, or queues it again if it is neither delivered nor
    // queued (it was queued before a restart that lost it, and the restart queued it, but a
    // repeat costs nothing). The anchor is never dropped from the queue.
    let shipped = state.checkpoint_sink.as_ref().map(|s| {
        let queued = if out.already && out.anchor.shipped_at.is_none() {
            s.handle().push_anchor(a)
        } else {
            !out.already
        };
        json!({
            "queued": queued,
            "delivered_through": s.delivered_through(),
            "anchor_shipped_at": out.anchor.shipped_at,
            "anchor_pending": out.anchor.shipped_at.is_none() && s.anchor_pending(a.through_seq),
        })
    });
    Ok(Json(json!({
        "prune_seq": a.prune_seq,
        "pruned_through": a.through_seq,
        "anchor": out.anchor.anchor,
        "checkpoint_before": out.checkpoint_before,
        "checkpoint_after": out.checkpoint_after,
        "deleting": out.anchor.state == attenuo_audit::AnchorState::Deleting,
        "shipped": shipped,
        "already": out.already,
    })))
}

/// Query string of `GET /admin/audit/anchors`.
#[derive(Debug, Default, Deserialize)]
pub struct AnchorsQuery {
    /// The `next_cursor` of the previous page ([`super::page`]).
    pub cursor: Option<String>,
    /// Page size (default 50, at most 500).
    pub limit: Option<usize>,
}

/// `GET /admin/audit/anchors?cursor=&limit=`: the anchors of every prune, newest first, as
/// `{anchors, next_cursor}`, each the signed anchor with its `state` (`deleting` or `done`)
/// and `shipped_at`, when `[audit.sink]` delivered it (null until then).
/// Paged like `GET /admin/audit/checkpoints`. Answers an empty list for a log never pruned,
/// whatever `[audit.retention] prune` is.
///
/// # Errors
///
/// 400 `invalid_cursor` for a cursor that is malformed or of another route, 400
/// `invalid_request` for a `limit` of 0 or above 500, and 500 `server_error` when the audit
/// log fails.
pub async fn anchors(
    State(state): State<Arc<AppState>>,
    Query(q): Query<AnchorsQuery>,
) -> Result<Json<Value>, ApiError> {
    let dir = page::Direction::Descending;
    let limit = page::limit(q.limit, DEFAULT_ANCHOR_PAGE, MAX_ANCHOR_PAGE)?;
    let before = page::decode(q.cursor.as_deref(), page::List::Anchors, dir)?;
    let mut anchors: Vec<StoredAnchor> = state
        .blocking(move |s| {
            s.audit
                .anchors_before(before.unwrap_or(u64::MAX), limit + 1)
        })
        .await?;
    let next = (anchors.len() > limit).then(|| anchors[limit - 1].anchor.through_seq);
    anchors.truncate(limit);
    Ok(Json(json!({
        "anchors": anchors,
        "next_cursor": next.map(|p| page::encode(page::List::Anchors, dir, p)),
    })))
}
