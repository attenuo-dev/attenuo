//! The automatic prune of the audit log (`[audit.retention] prune = "auto"`, ADR-0015 phase
//! 2): every `interval_seconds` the server prunes what is older than `keep_seconds`, through
//! the same plan and the same prune as `POST /admin/audit/prune`.
//!
//! One run ([`auto_prune_once`]):
//!
//! 0. Look at the clocks: when the wall clock moved more than [`CLOCK_JUMP_SLACK`] away from
//!    the monotonic clock since the last run (or since start), the run is `skipped`
//!    (`clock_jump`) with a warning. The next run, with the clocks in step again, goes on.
//! 1. Plan, as `GET /admin/audit/prune/plan` does with no bound, but with `keep_seconds` as the
//!    age floor ([`attenuo_audit::SqliteAudit::prune_plan`]), measured back from the time of
//!    the newest entry when that is earlier than now, so that a clock that jumps ahead with no
//!    new entries makes nothing old enough. Every guard of a manual prune
//!    applies: a signed checkpoint at the boundary, no live run below it, and `[audit.sink]`
//!    caught up (not degraded, a checkpoint at or past the boundary delivered since start, the
//!    anchor of the prune before delivered). Nothing allowed: the run is `skipped`, with the
//!    guard that stopped it as the reason. A plan of more than `max_entries_per_run` entries
//!    is planned again with that limit, so a large old log is pruned in several runs; when no
//!    checkpoint falls inside the limit, the smallest allowed checkpoint above it is the
//!    boundary. With `archive_dir`, an archive file a run left there for a smaller boundary
//!    from the same first seq (a crash before its commit) sets the boundary, so that the file
//!    is used and not left beside a second one.
//! 2. Verify the prefix the prune would remove, on the reader
//!    ([`attenuo_audit::SqliteAudit::verify_retained_through`]): the chain from the newest
//!    anchor (or genesis), every checkpoint, and the anchors. It must pass, and a checkpoint at
//!    or past the boundary must verify. A failure is `failed` (`verify_failed`) and nothing is
//!    pruned: a broken prefix is evidence, and the server keeps it.
//! 3. With `archive_dir`: write the prefix there as an export file (the format of
//!    `attenuo audit export`, [`archive_file_name`]), through a temporary file that is flushed
//!    to disk and then linked into place, with the directory flushed after. The file is then
//!    read back and verified: from genesis or from the newest anchor, to the boundary's hash,
//!    every entry signed, the same bytes in both passes. A file of that name is never
//!    replaced: one that passes the same check is used as it is (its own digest is signed),
//!    any other fails the run (`archive_exists`). Any failure fails the run
//!    (`archive_write_failed`, `archive_exists`, `archive_verify_failed`), or skips it
//!    (`concurrent_prune`) when another prune moved the boundary meanwhile, and nothing is
//!    pruned. A file this run wrote and no prune used is removed again.
//! 4. Prune ([`attenuo_audit::SqliteAudit::prune_through_expecting`]), with the plan's first
//!    seq and the boundary's hash as the expected archive, so a prune that something else made
//!    in between refuses this one. The guards are checked again inside the transaction. The
//!    prune record names [`AUTO_PRUNE_SUBJECT`] as its subject. With `archive_dir` the
//!    archive's SHA-256 is signed into the anchor (`archive_sha256`), as for a manual prune
//!    with an archive; without it `archive_sha256` is null and no copy is kept.
//!
//! The rows are then deleted by the maintenance task, as for a manual prune. A manual prune
//! and an automatic one cannot both commit: the store checks the guards (a prune still
//! deleting, the boundary already pruned, the archive's first seq) inside the prune's write
//! transaction, under the write gate, so whichever commits second is refused and a refused
//! automatic run counts as `skipped`.
//!
//! The timer (`auto_prune_ticks`, started by [`crate::run`]) runs one run at a time, the
//! first one interval after start. A run that fails or panics is logged and counted, and the
//! next tick tries again; the server never stops for it. Shutdown is seen between runs, so a
//! run in progress finishes first (a verify walk or an archive of a large prefix can take some
//! seconds). `/readyz` does not look at any of it.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use attenuo_audit::{
    Anchor, AuditError, AuditSink, Checkpoint, PlanBound, PruneExpect, PruneLimits, PrunePlan,
    VerifyOptions, PRUNE_TOOL,
};
use attenuo_core::Decision;
use futures_util::FutureExt;
use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::operators::AdminIdentity;
use crate::routes::{admin_record, REASON_ADMIN_ACTION};
use crate::state::AppState;

/// The `originating_subject` of the record of an automatic prune. Under the reserved
/// `urn:attenuo:` prefix, and not under `urn:attenuo:admin`, so it cannot be an operator's.
pub const AUTO_PRUNE_SUBJECT: &str = "urn:attenuo:retention";

/// A run pruned the log.
pub const OUTCOME_PRUNED: &str = "pruned";
/// A run found nothing it may prune (a guard, nothing old enough, a clock jump).
pub const OUTCOME_SKIPPED: &str = "skipped";
/// A run could not finish (the store failed, the prefix did not verify, or the archive could
/// not be written or checked).
pub const OUTCOME_FAILED: &str = "failed";

/// The reason of a run that pruned.
pub const RUN_OK: &str = "ok";
/// A run skipped because the log has nothing past its boundary at a checkpoint (an empty or
/// fully pruned log) and no guard said why.
pub const RUN_NOTHING_TO_PRUNE: &str = "nothing_to_prune";
/// A run skipped because another prune changed the log between its plan and its prune.
pub const RUN_CONCURRENT_PRUNE: &str = "concurrent_prune";
/// A run skipped because the wall clock moved more than [`CLOCK_JUMP_SLACK`] away from the
/// monotonic clock since the run before (or since start).
pub const RUN_CLOCK_JUMP: &str = "clock_jump";
/// A run failed because the prefix it would prune does not verify.
pub const RUN_VERIFY_FAILED: &str = "verify_failed";
/// A run failed because the store failed.
pub const RUN_ERROR: &str = "error";
/// A run failed because it panicked.
pub const RUN_PANIC: &str = "panic";
/// A run failed because the archive file could not be written (`archive_dir` missing or not
/// writable, the disk full, the store failed while reading the prefix).
pub const RUN_ARCHIVE_WRITE_FAILED: &str = "archive_write_failed";
/// A run failed because `archive_dir` already holds a file of the archive's name that is not
/// this prefix's archive. The server never replaces it.
pub const RUN_ARCHIVE_EXISTS: &str = "archive_exists";
/// A run failed because the archive file it wrote, read back, does not verify as the prefix.
pub const RUN_ARCHIVE_VERIFY_FAILED: &str = "archive_verify_failed";

/// How far the wall clock may move away from the monotonic clock between two runs before the
/// run is skipped as a clock jump (forward or back): an hour.
pub const CLOCK_JUMP_SLACK: time::Duration = time::Duration::hours(1);

/// The name of the archive file of `from..=through` in `archive_dir`:
/// `audit-<from>-<through>.jsonl`, each number zero-padded to 20 digits so the names sort in
/// seq order.
pub fn archive_file_name(from: u64, through: u64) -> String {
    format!("audit-{from:020}-{through:020}.jsonl")
}

/// The range of an archive file name, if `name` is one.
fn archive_range(name: &str) -> Option<(u64, u64)> {
    let rest = name.strip_prefix("audit-")?.strip_suffix(".jsonl")?;
    let (from, through) = rest.split_once('-')?;
    let num = |d: &str| {
        (d.len() == 20 && d.bytes().all(|b| b.is_ascii_digit()))
            .then(|| d.parse::<u64>().ok())
            .flatten()
    };
    Some((num(from)?, num(through)?))
}

/// What one run did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutoPruneRun {
    /// When the run started (RFC 3339 UTC).
    pub at: String,
    /// [`OUTCOME_PRUNED`], [`OUTCOME_SKIPPED`] or [`OUTCOME_FAILED`].
    pub outcome: &'static str,
    /// Why: [`RUN_OK`] for a prune, the code of the guard that stopped a skipped run
    /// (`prune_too_recent`, `sink_behind`, `prune_live_run`, `prune_in_progress`,
    /// `prune_not_at_checkpoint`, ...), [`RUN_NOTHING_TO_PRUNE`], [`RUN_CONCURRENT_PRUNE`] or
    /// [`RUN_CLOCK_JUMP`], or [`RUN_VERIFY_FAILED`], [`RUN_ARCHIVE_WRITE_FAILED`],
    /// [`RUN_ARCHIVE_EXISTS`], [`RUN_ARCHIVE_VERIFY_FAILED`], [`RUN_ERROR`] or [`RUN_PANIC`]
    /// for a failure.
    pub reason: &'static str,
    /// The boundary: pruned through it, or the one the run tried.
    pub through: Option<u64>,
    /// The prune record's seq, for a run that pruned.
    pub prune_seq: Option<u64>,
    /// More words for a skip or a failure (a guard's message, the error).
    pub detail: Option<String>,
    /// The name of the archive file in `archive_dir` the run wrote (or found already
    /// written), when it got that far.
    pub archive: Option<String>,
}

/// The last run, kept for `GET /admin/audit/prune/plan`. Lost at a restart. Also: the lock
/// that keeps two runs of this process apart (the timer never overlaps its own runs, but a
/// direct call of [`auto_prune_once`] could), so that two runs never write in `archive_dir` at
/// once; the clock readings of the last run, for the clock-jump check; and the files of
/// `archive_dir` already warned about.
#[derive(Debug, Default)]
pub struct AutoPruneStatus {
    last: Mutex<Option<AutoPruneRun>>,
    running: Arc<tokio::sync::Mutex<()>>,
    clocks: Mutex<Option<(Instant, OffsetDateTime)>>,
    warned: Mutex<HashSet<String>>,
}

impl AutoPruneStatus {
    /// A status whose clock-jump check starts from `wall`, read now.
    pub fn starting_at(wall: OffsetDateTime) -> Self {
        Self {
            clocks: Mutex::new(Some((Instant::now(), wall))),
            ..Self::default()
        }
    }

    /// The last run this process made, if any.
    pub fn last(&self) -> Option<AutoPruneRun> {
        self.last.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set(&self, run: AutoPruneRun) {
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Some(run);
    }

    /// Take the readings of this run (`mono`, `wall`) as the next baseline, and say how the
    /// clocks disagree when they moved apart by more than [`CLOCK_JUMP_SLACK`] since the last
    /// baseline.
    fn clock_jump(&self, mono: Instant, wall: OffsetDateTime) -> Option<String> {
        let prev = self
            .clocks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace((mono, wall));
        let (m0, w0) = prev?;
        let passed = mono.saturating_duration_since(m0);
        let moved = wall - w0;
        let step = moved - time::Duration::try_from(passed).unwrap_or(time::Duration::MAX);
        (step.abs() > CLOCK_JUMP_SLACK).then(|| {
            format!(
                "the wall clock moved {moved} while {passed:?} passed on the monotonic clock (a \
                 step of {step}); this run prunes nothing, and the next one, with the clocks in \
                 step, may"
            )
        })
    }

    /// Whether `key` is warned about for the first time in this process.
    fn first_warning(&self, key: String) -> bool {
        self.warned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key)
    }
}

/// Tests: hold the lock runs take, so that a run waits for it (a run that lasts longer than
/// the interval).
#[doc(hidden)]
pub async fn hold_auto_prune_runs(state: &AppState) -> tokio::sync::OwnedMutexGuard<()> {
    state.auto_prune.running.clone().lock_owned().await
}

fn rfc3339(t: OffsetDateTime) -> String {
    t.to_offset(time::UtcOffset::UTC)
        .replace_nanosecond(0)
        .unwrap_or(t)
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// Run one automatic prune now (see the module docs), record it in the metrics, the log and
/// [`AppState::auto_prune`], and return what it did. Never panics on a store failure; with
/// `prune` other than `"auto"` it does nothing and answers `skipped` / `prune_disabled`.
pub async fn auto_prune_once(state: &Arc<AppState>) -> AutoPruneRun {
    let _one = state.auto_prune.running.lock().await;
    let started = state.now();
    if let Some(detail) = state.auto_prune.clock_jump(Instant::now(), started) {
        let run = run_of(started, OUTCOME_SKIPPED, RUN_CLOCK_JUMP, None, Some(detail));
        return finish(state, run);
    }
    let run = attempt(state, started).await;
    finish(state, run)
}

/// Count, log and keep `run`.
fn finish(state: &AppState, run: AutoPruneRun) -> AutoPruneRun {
    let at = OffsetDateTime::parse(&run.at, &Rfc3339).map_or(0, |t| t.unix_timestamp());
    state
        .metrics
        .audit_auto_prune_run(run.outcome, run.reason, u64::try_from(at).unwrap_or(0));
    match (run.outcome, run.reason) {
        (OUTCOME_PRUNED, _) => tracing::warn!(
            through = ?run.through,
            prune_seq = ?run.prune_seq,
            archive = run.archive.as_deref().unwrap_or("none"),
            "audit log pruned automatically ([audit.retention] prune = \"auto\"); the rows are \
             deleted in the background"
        ),
        (OUTCOME_FAILED, _) => tracing::error!(
            reason = run.reason,
            through = ?run.through,
            archive = run.archive.as_deref().unwrap_or("none"),
            detail = run.detail.as_deref().unwrap_or(""),
            "automatic audit prune failed; nothing was pruned, the next run tries again"
        ),
        (_, RUN_CLOCK_JUMP) => tracing::warn!(
            detail = run.detail.as_deref().unwrap_or(""),
            "automatic audit prune skipped: the system clock jumped. Check NTP and the host's \
             clock; nothing was pruned"
        ),
        _ => tracing::debug!(
            reason = run.reason,
            through = ?run.through,
            detail = run.detail.as_deref().unwrap_or(""),
            "automatic audit prune: nothing pruned"
        ),
    }
    state.auto_prune.set(run.clone());
    run
}

/// What steps 1 to 3 of a run settled on: the prune to make.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct Prepared {
    /// The first seq the prune removes.
    pub from: u64,
    /// The boundary.
    pub through: u64,
    /// The entry hash at the boundary (the checkpoint's `head_hash`).
    pub through_hash: String,
    /// The archive file, with `archive_dir`.
    pub archive: Option<Archive>,
}

/// An archive file in `archive_dir`, verified as the prefix.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Archive {
    /// Its name ([`archive_file_name`]).
    pub name: String,
    /// Its path.
    pub path: PathBuf,
    /// SHA-256 of its bytes, lower-case hex.
    pub sha256: String,
    /// The file was there already, passed the check, and was used as it is.
    pub reused: bool,
}

/// Steps 1 to 3 of a run, without the prune: plan, verify the prefix and, with
/// `archive_dir`, write and verify the archive. For tests (a crash between the archive and
/// the prune); the timer runs [`auto_prune_once`].
#[doc(hidden)]
pub async fn auto_prune_prepare(state: &Arc<AppState>) -> Result<Prepared, Box<AutoPruneRun>> {
    let _one = state.auto_prune.running.lock().await;
    prepare(state, state.now()).await
}

fn run_of(
    started: OffsetDateTime,
    outcome: &'static str,
    reason: &'static str,
    through: Option<u64>,
    detail: Option<String>,
) -> AutoPruneRun {
    AutoPruneRun {
        at: rfc3339(started),
        outcome,
        reason,
        through,
        prune_seq: None,
        detail,
        archive: None,
    }
}

/// The limits of an automatic prune: those of a manual one with `keep` as the age, measured
/// back from the time of the newest entry when that is before now. A wall clock that jumps
/// ahead with no new entries then makes nothing older than it was.
fn auto_limits(s: &AppState, keep: time::Duration) -> Result<PruneLimits, AuditError> {
    let mut limits = crate::routes::retention::limits(s, keep);
    if let Some(newest) = s.audit.head()? {
        let behind = limits.now - newest.record.at;
        if behind.is_positive() {
            limits.min_age = keep.saturating_add(behind);
        }
    }
    Ok(limits)
}

async fn plan_at(
    state: &Arc<AppState>,
    keep: time::Duration,
    bound: u64,
) -> Result<PrunePlan, AuditError> {
    state
        .blocking(move |s| {
            let limits = auto_limits(s, keep)?;
            s.audit.prune_plan(PlanBound::Through(bound), &limits)
        })
        .await
}

/// The plan of a run that may remove at most `max` entries: `plan` when it is small enough;
/// else the largest allowed checkpoint inside the limit; else, when none falls inside it, the
/// smallest allowed checkpoint above it (looking at a few); else `plan`.
async fn capped(
    state: &Arc<AppState>,
    keep: time::Duration,
    plan: PrunePlan,
    max: u64,
) -> Result<PrunePlan, AuditError> {
    let Some(through) = plan.through else {
        return Ok(plan);
    };
    if plan.entries <= max {
        return Ok(plan);
    }
    let bound = plan.from.saturating_sub(1).saturating_add(max);
    let inside = plan_at(state, keep, bound).await?;
    if inside.through.is_some_and(|t| t >= plan.from) && inside.from == plan.from {
        return Ok(inside);
    }
    let mut after = bound;
    for _ in 0..8 {
        let next = state
            .blocking(move |s| s.audit.checkpoint_covering(after.saturating_add(1)))
            .await?;
        let Some(c) = next.filter(|c| c.seq < through) else {
            break;
        };
        let p = plan_at(state, keep, c.seq).await?;
        if p.through == Some(c.seq) && p.from == plan.from {
            return Ok(p);
        }
        after = c.seq;
    }
    Ok(plan)
}

async fn prepare(
    state: &Arc<AppState>,
    started: OffsetDateTime,
) -> Result<Prepared, Box<AutoPruneRun>> {
    let run = |outcome, reason, through, detail| {
        Box::new(run_of(started, outcome, reason, through, detail))
    };
    let Some(keep) = state.retention.keep() else {
        return Err(run(OUTCOME_SKIPPED, "prune_disabled", None, None));
    };
    let failed = |e: AuditError| run(OUTCOME_FAILED, RUN_ERROR, None, Some(e.to_string()));
    // 1. The plan, with the keep window as the age floor, at most `max_entries_per_run`.
    let plan = plan_at(state, keep, u64::MAX).await.map_err(failed)?;
    if plan.through.is_none() {
        let reason = plan.guards.limited_by.unwrap_or(RUN_NOTHING_TO_PRUNE);
        return Err(run(OUTCOME_SKIPPED, reason, None, None));
    }
    let mut plan = capped(state, keep, plan, state.retention.max_entries_per_run())
        .await
        .map_err(failed)?;
    let mut through = plan.through.unwrap_or(0);
    // An archive a run left for a smaller boundary from the same first seq: use it.
    if let Some(dir) = state.retention.archive_dir.clone() {
        let from = plan.from;
        let left = state.blocking(move |_| leftover_archives(&dir, from)).await;
        for &x in left.iter().filter(|&&x| x < through) {
            let again = plan_at(state, keep, x).await.map_err(failed)?;
            if again.through == Some(x) && again.from == from {
                through = x;
                plan = again;
                break;
            }
        }
    }
    let Some(cp) = plan.checkpoint.clone() else {
        return Err(run(OUTCOME_SKIPPED, RUN_NOTHING_TO_PRUNE, None, None));
    };
    let floor = plan.from.checked_sub(1).filter(|&b| b > 0);

    // 2. The prefix verifies, from the same boundary the plan saw.
    let verified = state
        .blocking(move |s| {
            let keys = s.keys();
            let report = s
                .audit
                .verify_retained_through(through, &keys.checkpoint_keys)?;
            // A key reload meanwhile: check once more with the keys in force, as
            // `GET /admin/audit/verify` does.
            let now = s.keys();
            let report = if report.ok || now.generation() == keys.generation() {
                report
            } else {
                s.audit
                    .verify_retained_through(through, &now.checkpoint_keys)?
            };
            let boundary = s.audit.pruned_through()?;
            Ok::<_, AuditError>((report, boundary))
        })
        .await;
    let (report, boundary) = verified.map_err(|e| {
        run(
            OUTCOME_FAILED,
            RUN_ERROR,
            Some(through),
            Some(e.to_string()),
        )
    })?;
    if boundary != floor {
        // Another prune committed after the plan; the next run plans again.
        return Err(run(
            OUTCOME_SKIPPED,
            RUN_CONCURRENT_PRUNE,
            Some(through),
            Some(format!(
                "the log was pruned through {boundary:?} while this run planned from {floor:?}"
            )),
        ));
    }
    let signed = report.last_signed_seq.is_some_and(|s| s >= through);
    if !report.ok || !signed || report.pruned_through != floor {
        return Err(run(
            OUTCOME_FAILED,
            RUN_VERIFY_FAILED,
            Some(through),
            Some(format!(
                "the entries up to seq {through} do not verify: first_bad_seq {:?}, \
                 last_signed_seq {:?}, {} bad checkpoints, {} bad anchors, pruned_through {:?}; \
                 run `attenuo audit verify`",
                report.first_bad_seq,
                report.last_signed_seq,
                report.bad_checkpoints.len(),
                report.bad_anchors.len(),
                report.pruned_through
            )),
        ));
    }

    // 3. The archive, with `archive_dir`.
    let archive = match state.retention.archive_dir.clone() {
        None => None,
        Some(dir) => {
            let job = ArchiveJob {
                dir,
                from: plan.from,
                cp: cp.clone(),
                anchor: plan.anchor.clone().map(|a| a.anchor),
            };
            let written = state
                .blocking(move |s| {
                    let out = job.run(s);
                    // A prune that landed meanwhile: not this run's failure.
                    let moved = out.is_err() && s.audit.pruned_through().ok() != Some(floor);
                    (out, moved)
                })
                .await;
            match written {
                (Ok(a), _) => Some(a),
                (Err((_, name, detail)), true) => {
                    return Err(Box::new(AutoPruneRun {
                        archive: name,
                        ..*run(
                            OUTCOME_SKIPPED,
                            RUN_CONCURRENT_PRUNE,
                            Some(through),
                            Some(format!(
                                "the log was pruned by another prune while the archive was \
                                 written ({detail})"
                            )),
                        )
                    }))
                }
                (Err((reason, name, detail)), false) => {
                    return Err(Box::new(AutoPruneRun {
                        archive: name,
                        ..*run(OUTCOME_FAILED, reason, Some(through), Some(detail))
                    }))
                }
            }
        }
    };
    Ok(Prepared {
        from: plan.from,
        through,
        through_hash: cp.head_hash,
        archive,
    })
}

async fn attempt(state: &Arc<AppState>, started: OffsetDateTime) -> AutoPruneRun {
    let prepared = match prepare(state, started).await {
        Ok(p) => p,
        Err(run) => return *run,
    };
    let Some(keep) = state.retention.keep() else {
        return run_of(started, OUTCOME_SKIPPED, "prune_disabled", None, None);
    };
    let through = prepared.through;
    let name = prepared.archive.as_ref().map(|a| a.name.clone());
    let run = |outcome, reason, detail| AutoPruneRun {
        archive: name.clone(),
        ..run_of(started, outcome, reason, Some(through), detail)
    };

    // 4. The prune, as `POST /admin/audit/prune` makes it. The guards are checked again in
    // its transaction with the sink's progress and the time now.
    let expect = PruneExpect {
        from: Some(prepared.from),
        through_hash: Some(prepared.through_hash.clone()),
    };
    let digest = prepared.archive.as_ref().map(|a| a.sha256.clone());
    let done = state
        .blocking(move |s| {
            let limits = auto_limits(s, keep)?;
            let now = limits.now;
            s.audit
                .prune_through_expecting(through, digest, &expect, &limits, |args| {
                    let mut r = admin_record(
                        &AdminIdentity::legacy(),
                        PRUNE_TOOL,
                        Decision::Allow,
                        REASON_ADMIN_ACTION,
                        Vec::new(),
                        args.clone(),
                        now,
                    );
                    // Made by the server, not by an operator.
                    r.originating_subject = AUTO_PRUNE_SUBJECT.to_string();
                    r
                })
        })
        .await;
    let out = match done {
        Ok(out) if !out.already => {
            let a = &out.anchor.anchor;
            if let Ok(t) = OffsetDateTime::parse(&a.at, &Rfc3339) {
                state
                    .metrics
                    .audit_pruned_at(u64::try_from(t.unix_timestamp()).unwrap_or(0));
            }
            return AutoPruneRun {
                prune_seq: Some(a.prune_seq),
                ..run(OUTCOME_PRUNED, RUN_OK, None)
            };
        }
        // The same prune was made already (by a run that raced this one).
        Ok(_) => run(OUTCOME_SKIPPED, RUN_CONCURRENT_PRUNE, None),
        Err(AuditError::PruneRefused { guard, detail }) => {
            run(OUTCOME_SKIPPED, guard.code(), Some(detail))
        }
        Err(e) => run(OUTCOME_FAILED, RUN_ERROR, Some(e.to_string())),
    };
    // No prune used the archive: a file this run wrote goes again, unless an anchor names it.
    if let Some(a) = prepared.archive.filter(|a| !a.reused) {
        state.blocking(move |s| a.remove_unused(s)).await;
    }
    out
}

impl Archive {
    /// Remove this file, which this run wrote and no prune used, unless the newest anchor
    /// names its digest after all.
    fn remove_unused(&self, s: &AppState) {
        let named = s
            .audit
            .newest_anchor()
            .ok()
            .flatten()
            .is_some_and(|a| a.anchor.archive_sha256.as_deref() == Some(self.sha256.as_str()));
        if named {
            return;
        }
        match std::fs::remove_file(&self.path) {
            Ok(()) => {
                if let Some(dir) = self.path.parent() {
                    let _ = sync_dir(dir);
                }
                tracing::info!(
                    file = %self.path.display(),
                    "automatic audit prune: removed the archive file this run wrote, since no \
                     prune used it"
                );
            }
            Err(e) => tracing::warn!(
                file = %self.path.display(),
                error = %e,
                "automatic audit prune: could not remove the archive file this run wrote and \
                 no prune used; it is not part of the log"
            ),
        }
    }
}

/// The boundaries of the archive files in `dir` that start at `from`, smallest first. An
/// unreadable directory gives none (the write fails later, with the reason).
fn leftover_archives(dir: &Path, from: u64) -> Vec<u64> {
    let mut out: Vec<u64> = archive_files(dir)
        .into_iter()
        .filter(|&(f, _)| f == from)
        .map(|(_, t)| t)
        .collect();
    out.sort_unstable();
    out
}

/// The ranges of the archive files in `dir`.
fn archive_files(dir: &Path) -> Vec<(u64, u64)> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| archive_range(&e.file_name().to_string_lossy()))
        .collect()
}

/// Step 3 of a run, on the blocking pool.
struct ArchiveJob {
    dir: PathBuf,
    from: u64,
    /// The checkpoint at the boundary.
    cp: Checkpoint,
    /// The newest anchor, which the file's header must carry when `from` is above 1.
    anchor: Option<Anchor>,
}

/// Why step 3 failed: the reason, the file name when known, and the detail.
type ArchiveFailure = (&'static str, Option<String>, String);

/// Writes to `inner` and takes the SHA-256 of what passes.
struct Hashing<W> {
    inner: W,
    hasher: sha2::Sha256,
}

impl<W: std::io::Write> std::io::Write for Hashing<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use sha2::Digest;
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl ArchiveJob {
    fn run(self, s: &AppState) -> Result<Archive, ArchiveFailure> {
        let through = self.cp.seq;
        let name = archive_file_name(self.from, through);
        self.remove_temporaries();
        self.warn_strays(s, through);
        let target = self.dir.join(&name);
        if std::fs::symlink_metadata(&target).is_ok() {
            return self.use_existing(s, &target, &name);
        }
        let tmp = self.dir.join(format!(".{name}.{}.tmp", std::process::id()));
        let written = self.write_and_place(s, &tmp, &target, &name);
        let _ = std::fs::remove_file(&tmp);
        let sha256 = match written {
            Ok(Some(sha)) => sha,
            // Someone put a file of that name there meanwhile.
            Ok(None) => return self.use_existing(s, &target, &name),
            Err(e) => return Err(e),
        };
        match self.check(s, &target, Some(&sha256)) {
            Ok(_) => Ok(Archive {
                name,
                path: target,
                sha256,
                reused: false,
            }),
            Err(problems) => {
                // This run's own file, and it is not the prefix: it goes.
                let _ = std::fs::remove_file(&target);
                let _ = sync_dir(&self.dir);
                Err((
                    RUN_ARCHIVE_VERIFY_FAILED,
                    Some(name),
                    format!("{}: {problems}", target.display()),
                ))
            }
        }
    }

    /// A file of the archive's name is there: use it if it passes the archive check (its
    /// digest is what the prune signs), else fail and leave it alone.
    fn use_existing(
        &self,
        s: &AppState,
        target: &Path,
        name: &str,
    ) -> Result<Archive, ArchiveFailure> {
        let refuse = |why: String| {
            (
                RUN_ARCHIVE_EXISTS,
                Some(name.to_string()),
                format!(
                    "{} exists and is not this prefix's archive ({why}); it is never replaced: \
                     move it away if it is not needed, and the next run writes the archive",
                    target.display()
                ),
            )
        };
        let meta = std::fs::symlink_metadata(target).map_err(|e| refuse(e.to_string()))?;
        if !meta.file_type().is_file() {
            return Err(refuse("not a regular file".to_string()));
        }
        let sha256 = self.check(s, target, None).map_err(refuse)?;
        std::fs::File::open(target)
            .and_then(|f| f.sync_all())
            .and_then(|()| sync_dir(&self.dir))
            .map_err(|e| {
                (
                    RUN_ARCHIVE_WRITE_FAILED,
                    Some(name.to_string()),
                    format!("flushing {}: {e}", target.display()),
                )
            })?;
        Ok(Archive {
            name: name.to_string(),
            path: target.to_path_buf(),
            sha256,
            reused: true,
        })
    }

    /// Remove the temporary files of earlier runs (a crash while one was written).
    fn remove_temporaries(&self) {
        let Ok(list) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for e in list.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with(".audit-") && n.ends_with(".tmp") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }

    /// Warn, once per file in this process, about archive files no prune used: from this
    /// run's first seq but for another boundary, or for a range at or below the boundary of
    /// the log that no anchor names. They are not part of the log and are never deleted here.
    fn warn_strays(&self, s: &AppState, through: u64) {
        let floor = self.from.saturating_sub(1);
        for (f, t) in archive_files(&self.dir) {
            let name = archive_file_name(f, t);
            let stray = if f == self.from {
                t != through
            } else if t <= floor {
                // The anchor with the largest boundary at or below `t`.
                !s.audit
                    .anchors_before(t.saturating_add(1), 1)
                    .ok()
                    .and_then(|a| a.into_iter().next())
                    .is_some_and(|a| {
                        a.anchor.through_seq == t
                            && a.anchor.previous_through_seq.map_or(1, |p| p + 1) == f
                    })
            } else {
                false
            };
            if stray && s.auto_prune.first_warning(name.clone()) {
                tracing::warn!(
                    file = %self.dir.join(&name).display(),
                    "[audit.retention] archive_dir holds an archive file that no prune used: it \
                     matches no anchor and is not part of the log. It is left as it is; the \
                     shipped anchors name the real archives"
                );
            }
        }
    }

    /// Write the export into a new file at `tmp`, flush it to disk, and put it at `target`
    /// without replacing anything. Answers the digest, or `None` when a file of that name
    /// appeared meanwhile.
    fn write_and_place(
        &self,
        s: &AppState,
        tmp: &Path,
        target: &Path,
        name: &str,
    ) -> Result<Option<String>, ArchiveFailure> {
        use sha2::Digest;
        use std::io::Write;

        let fail = |detail: String| (RUN_ARCHIVE_WRITE_FAILED, Some(name.to_string()), detail);
        let io = |e: std::io::Error, what: &str| fail(format!("{what} {}: {e}", tmp.display()));
        let file = create_private(tmp).map_err(|e| io(e, "creating"))?;
        let mut out = Hashing {
            inner: std::io::BufWriter::new(file),
            hasher: sha2::Sha256::new(),
        };
        let exported_at = rfc3339(s.now());
        s.audit
            .write_export(self.from, self.cp.seq, exported_at, &mut out)
            .map_err(|e| fail(e.to_string()))?;
        out.flush().map_err(|e| io(e, "writing"))?;
        let sha256 = hex::encode(out.hasher.finalize());
        let file = out
            .inner
            .into_inner()
            .map_err(|e| io(e.into_error(), "writing"))?;
        file.sync_all().map_err(|e| io(e, "flushing"))?;
        drop(file);
        match attenuo_audit::fsutil::place_no_replace(tmp, target) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(None),
            Err(e) => {
                return Err(fail(format!(
                    "placing {} at {}: {e}",
                    tmp.display(),
                    target.display()
                )))
            }
        }
        sync_dir(&self.dir).map_err(|e| io(e, "flushing the directory of"))?;
        Ok(Some(sha256))
    }

    /// Read the file at `target` and check that it is this prefix's archive: it verifies
    /// strictly, from genesis or from the newest anchor (the header's anchor equal to it),
    /// holds exactly `from..=through`, ends at the boundary's checkpoint and hash, and, when
    /// `written` is given, has that digest. Answers its digest, or what is wrong.
    fn check(&self, s: &AppState, target: &Path, written: Option<&str>) -> Result<String, String> {
        let through = self.cp.seq;
        let keys = s.keys();
        let got = attenuo_audit::verify_export_file(
            target,
            &keys.checkpoint_keys,
            VerifyOptions::default(),
        )
        .map_err(|e| e.to_string())?;
        let r = &got.report;
        let mut problems = Vec::new();
        if !r.report.ok {
            problems.push(format!(
                "it does not verify (first_bad_seq {:?}, {} bad checkpoints, {} bad anchors, \
                 truncated {})",
                r.report.first_bad_seq,
                r.report.bad_checkpoints.len(),
                r.report.bad_anchors.len(),
                r.truncated
            ));
        }
        if (got.header.from, got.header.to) != (self.from, through)
            || (r.first_seq, r.last_seq) != (Some(self.from), Some(through))
        {
            problems.push(format!(
                "it holds seq {:?}..{:?}, not {}..{through}",
                r.first_seq, r.last_seq, self.from
            ));
        }
        if r.report.last_signed_seq != Some(through) {
            problems.push("it does not end at the boundary's checkpoint".to_string());
        }
        if got.last_entry_hash.as_deref() != Some(self.cp.head_hash.as_str()) {
            problems.push("its last entry is not the one the boundary's checkpoint signs".into());
        }
        let starts = if self.from == 1 {
            r.from_genesis
        } else {
            r.from_anchor && got.header.anchor == self.anchor
        };
        if !starts {
            problems.push(if self.from == 1 {
                "it does not start at genesis".to_string()
            } else {
                "it does not start at the newest anchor".to_string()
            });
        }
        if let Some(w) = written.filter(|w| *w != got.sha256) {
            problems.push(format!(
                "its sha256 is {}, not the {w} that was written",
                got.sha256
            ));
        }
        if problems.is_empty() {
            Ok(got.sha256)
        } else {
            Err(problems.join("; "))
        }
    }
}

/// Create `path` for writing, failing if it exists; readable and writable by the owner only
/// on Unix (mode 0600), as the archives of `attenuo audit prune` are.
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// Flush the directory `dir`, so a link or rename into it survives a crash. Nothing to do
/// where a directory cannot be opened (Windows).
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// The timer of the automatic prune, until `stop` resolves: one [`auto_prune_once`] every
/// `[audit.retention] interval_seconds`, the first one interval after start. `stop` is looked
/// at between runs, first: once it has resolved, no run starts, even with a tick due. A run
/// runs in a task of its own, so that a panic in it is counted as a failed run and the timer
/// goes on.
pub(crate) async fn auto_prune_ticks(
    state: Arc<AppState>,
    stop: impl std::future::Future<Output = ()>,
) {
    tokio::pin!(stop);
    let mut tick = tokio::time::interval(state.retention.interval());
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await; // the first tick is immediate
    loop {
        tokio::select! {
            biased;
            () = &mut stop => return,
            _ = tick.tick() => {}
        }
        if stop.as_mut().now_or_never().is_some() {
            return;
        }
        let s = state.clone();
        let started = state.now();
        if let Err(e) = tokio::spawn(async move { auto_prune_once(&s).await }).await {
            finish(
                &state,
                AutoPruneRun {
                    at: rfc3339(started),
                    outcome: OUTCOME_FAILED,
                    reason: RUN_PANIC,
                    through: None,
                    prune_seq: None,
                    detail: Some(e.to_string()),
                    archive: None,
                },
            );
        }
    }
}
