//! The automatic prune of the audit log (`[audit.retention] prune = "auto"`, ADR-0015 phase
//! 2): every `interval_seconds` the server prunes what is older than `keep_seconds`, through
//! the same plan and the same prune as `POST /admin/audit/prune`.
//!
//! One run ([`auto_prune_once`]):
//!
//! 1. Plan, as `GET /admin/audit/prune/plan` does with no bound, but with `keep_seconds` as the
//!    age floor ([`attenuo_audit::SqliteAudit::prune_plan`]). Every guard of a manual prune
//!    applies: a signed checkpoint at the boundary, no live run below it, and `[audit.sink]`
//!    caught up (not degraded, a checkpoint at or past the boundary delivered since start, the
//!    anchor of the prune before delivered). Nothing allowed: the run is `skipped`, with the
//!    guard that stopped it as the reason. A plan of more than `max_entries_per_run` entries
//!    is planned again with that limit, so a large old log is pruned in several runs (unless
//!    no checkpoint falls inside the limit). With `archive_dir`, an archive file a run left
//!    there for a smaller boundary from the same first seq (a crash before its commit) sets
//!    the boundary, so that the file is used and not left beside a second one.
//! 2. Verify the prefix the prune would remove, on the reader
//!    ([`attenuo_audit::SqliteAudit::verify_retained_through`]): the chain from the newest
//!    anchor (or genesis), every checkpoint, and the anchors. It must pass, and a checkpoint at
//!    or past the boundary must verify. A failure is `failed` (`verify_failed`) and nothing is
//!    pruned: a broken prefix is evidence, and the server keeps it.
//! 3. With `archive_dir`: write the prefix there as an export file (the format of
//!    `attenuo audit export`, [`archive_file_name`]), through a temporary file that is flushed
//!    to disk and then linked into place, with the directory flushed after. A file of that
//!    name is never replaced: one with the same bytes (the same SHA-256) is used as it is, any
//!    other fails the run (`archive_exists`). The file is then read back and verified: from
//!    genesis or from the newest anchor, to the boundary's hash, every entry signed. Any
//!    failure fails the run (`archive_write_failed`, `archive_exists`,
//!    `archive_verify_failed`) and nothing is pruned.
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

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use attenuo_audit::{
    Anchor, AuditError, Checkpoint, PlanBound, PruneExpect, PrunePlan, VerifyOptions, PRUNE_TOOL,
};
use attenuo_core::Decision;
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
/// A run found nothing it may prune (a guard, or nothing old enough).
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
/// A run failed because the prefix it would prune does not verify.
pub const RUN_VERIFY_FAILED: &str = "verify_failed";
/// A run failed because the store failed.
pub const RUN_ERROR: &str = "error";
/// A run failed because it panicked.
pub const RUN_PANIC: &str = "panic";
/// A run failed because the archive file could not be written (`archive_dir` missing or not
/// writable, the disk full, the store failed while reading the prefix).
pub const RUN_ARCHIVE_WRITE_FAILED: &str = "archive_write_failed";
/// A run failed because `archive_dir` already holds a file of the archive's name with other
/// bytes. The server never replaces it.
pub const RUN_ARCHIVE_EXISTS: &str = "archive_exists";
/// A run failed because the archive file, read back, does not verify as the prefix.
pub const RUN_ARCHIVE_VERIFY_FAILED: &str = "archive_verify_failed";

/// The name of the archive file of `from..=through` in `archive_dir`:
/// `audit-<from>-<through>.jsonl`, each number zero-padded to 20 digits so the names sort in
/// seq order.
pub fn archive_file_name(from: u64, through: u64) -> String {
    format!("audit-{from:020}-{through:020}.jsonl")
}

/// The boundary of an archive file name from `from`, if `name` is one.
fn archive_through(name: &str, from: u64) -> Option<u64> {
    let rest = name.strip_prefix(&format!("audit-{from:020}-"))?;
    let digits = rest.strip_suffix(".jsonl")?;
    (digits.len() == 20 && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
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
    /// `prune_not_at_checkpoint`, ...), [`RUN_NOTHING_TO_PRUNE`] or [`RUN_CONCURRENT_PRUNE`], or
    /// [`RUN_VERIFY_FAILED`], [`RUN_ARCHIVE_WRITE_FAILED`], [`RUN_ARCHIVE_EXISTS`],
    /// [`RUN_ARCHIVE_VERIFY_FAILED`], [`RUN_ERROR`] or [`RUN_PANIC`] for a failure.
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

/// The last run, kept for `GET /admin/audit/prune/plan`. Lost at a restart. Also the lock
/// that keeps two runs of this process apart (the timer never overlaps its own runs, but a
/// direct call of [`auto_prune_once`] could), so that two runs never write in `archive_dir` at
/// once.
#[derive(Debug, Default)]
pub struct AutoPruneStatus {
    last: Mutex<Option<AutoPruneRun>>,
    running: tokio::sync::Mutex<()>,
}

impl AutoPruneStatus {
    /// The last run this process made, if any.
    pub fn last(&self) -> Option<AutoPruneRun> {
        self.last.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set(&self, run: AutoPruneRun) {
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Some(run);
    }
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
    let run = attempt(state, started).await;
    finish(state, run)
}

/// Count, log and keep `run`.
fn finish(state: &AppState, run: AutoPruneRun) -> AutoPruneRun {
    state.metrics.audit_auto_prune_run(run.outcome, run.reason);
    match run.outcome {
        OUTCOME_PRUNED => tracing::warn!(
            through = ?run.through,
            prune_seq = ?run.prune_seq,
            archive = run.archive.as_deref().unwrap_or("none"),
            "audit log pruned automatically ([audit.retention] prune = \"auto\"); the rows are \
             deleted in the background"
        ),
        OUTCOME_FAILED => tracing::error!(
            reason = run.reason,
            through = ?run.through,
            archive = run.archive.as_deref().unwrap_or("none"),
            detail = run.detail.as_deref().unwrap_or(""),
            "automatic audit prune failed; nothing was pruned, the next run tries again"
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

/// An archive file in `archive_dir`, written and verified.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Archive {
    /// Its name ([`archive_file_name`]).
    pub name: String,
    /// Its path.
    pub path: PathBuf,
    /// SHA-256 of its bytes, lower-case hex.
    pub sha256: String,
    /// The file was there already, with these bytes, and was used as it is.
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

async fn plan_at(
    state: &Arc<AppState>,
    keep: time::Duration,
    bound: u64,
) -> Result<PrunePlan, AuditError> {
    let limits = crate::routes::retention::limits(state, keep);
    state
        .blocking(move |s| s.audit.prune_plan(PlanBound::Through(bound), &limits))
        .await
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
    // 1. The plan, with the keep window as the age floor.
    let mut plan = plan_at(state, keep, u64::MAX).await.map_err(failed)?;
    let Some(mut through) = plan.through else {
        let reason = plan.guards.limited_by.unwrap_or(RUN_NOTHING_TO_PRUNE);
        return Err(run(OUTCOME_SKIPPED, reason, None, None));
    };
    // At most `max_entries_per_run`, when a checkpoint falls inside the limit.
    let max = state.retention.max_entries_per_run();
    if plan.entries > max {
        let bound = plan.from.saturating_sub(1).saturating_add(max);
        let capped = plan_at(state, keep, bound).await.map_err(failed)?;
        if let Some(t) = capped.through.filter(|t| *t >= plan.from) {
            through = t;
            plan = capped;
        }
    }
    // An archive a run left for a smaller boundary from the same first seq: use it.
    if let Some(dir) = state.retention.archive_dir.clone() {
        let from = plan.from;
        let left = state.blocking(move |_| leftover_archives(&dir, from)).await;
        if let Some(&x) = left.iter().find(|&&x| x < through) {
            let again = plan_at(state, keep, x).await.map_err(failed)?;
            if again.through == Some(x) && again.from == from {
                through = x;
                plan = again;
            }
        }
        for x in left.iter().filter(|&&x| x > through) {
            tracing::warn!(
                file = archive_file_name(from, *x),
                through,
                "[audit.retention] archive_dir holds an archive file no prune used, past this \
                 run's boundary; it is left as it is"
            );
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
            let written = state.blocking(move |s| job.run(s)).await;
            match written {
                Ok(a) => Some(a),
                Err((reason, name, detail)) => {
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
    let limits = crate::routes::retention::limits(state, keep);
    let now = limits.now;
    let expect = PruneExpect {
        from: Some(prepared.from),
        through_hash: Some(prepared.through_hash.clone()),
    };
    let digest = prepared.archive.as_ref().map(|a| a.sha256.clone());
    let done = state
        .blocking(move |s| {
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
    match done {
        Ok(out) if !out.already => {
            let a = &out.anchor.anchor;
            if let Ok(t) = OffsetDateTime::parse(&a.at, &Rfc3339) {
                state
                    .metrics
                    .audit_pruned_at(u64::try_from(t.unix_timestamp()).unwrap_or(0));
            }
            AutoPruneRun {
                prune_seq: Some(a.prune_seq),
                ..run(OUTCOME_PRUNED, RUN_OK, None)
            }
        }
        // The same prune was made already (by a run that raced this one).
        Ok(_) => run(OUTCOME_SKIPPED, RUN_CONCURRENT_PRUNE, None),
        Err(AuditError::PruneRefused { guard, detail }) => {
            run(OUTCOME_SKIPPED, guard.code(), Some(detail))
        }
        Err(e) => run(OUTCOME_FAILED, RUN_ERROR, Some(e.to_string())),
    }
}

/// The boundaries of the archive files in `dir` that start at `from`, smallest first. An
/// unreadable directory gives none (the write fails later, with the reason).
fn leftover_archives(dir: &Path, from: u64) -> Vec<u64> {
    let mut out: Vec<u64> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| archive_through(&e.file_name().to_string_lossy(), from))
        .collect();
    out.sort_unstable();
    out
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

/// SHA-256 of the file at `path`, read in pieces.
fn sha256_of(path: &Path) -> std::io::Result<String> {
    use sha2::Digest;
    let mut h = Hashing {
        inner: std::io::sink(),
        hasher: sha2::Sha256::new(),
    };
    std::io::copy(&mut std::fs::File::open(path)?, &mut h)?;
    Ok(hex::encode(h.hasher.finalize()))
}

impl ArchiveJob {
    fn run(self, s: &AppState) -> Result<Archive, ArchiveFailure> {
        let through = self.cp.seq;
        let name = archive_file_name(self.from, through);
        let fail = |reason, detail: String| (reason, Some(name.clone()), detail);
        let write_failed = |e: std::io::Error, what: &str| {
            fail(
                RUN_ARCHIVE_WRITE_FAILED,
                format!("{what} in {}: {e}", self.dir.display()),
            )
        };
        self.remove_temporaries();
        let target = self.dir.join(&name);
        let tmp = self.dir.join(format!(".{name}.{}.tmp", std::process::id()));
        let file =
            create_private(&tmp).map_err(|e| write_failed(e, "creating a temporary file"))?;
        // From here on the temporary file goes, whatever happens.
        let result = self.write_and_place(s, file, &tmp, &target, &name);
        let _ = std::fs::remove_file(&tmp);
        let (sha256, reused) = result?;
        self.check(s, &target, &name, &sha256)?;
        Ok(Archive {
            name,
            path: target,
            sha256,
            reused,
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

    /// Write the export into `file` (at `tmp`), flush it to disk, and put it at `target`
    /// unless a file is there: the same bytes are used as they are, other bytes fail.
    /// Answers the digest and whether the file was there already.
    fn write_and_place(
        &self,
        s: &AppState,
        file: std::fs::File,
        tmp: &Path,
        target: &Path,
        name: &str,
    ) -> Result<(String, bool), ArchiveFailure> {
        use sha2::Digest;
        use std::io::Write;

        let fail = |reason, detail: String| (reason, Some(name.to_string()), detail);
        let io = |e: std::io::Error, what: &str| {
            fail(
                RUN_ARCHIVE_WRITE_FAILED,
                format!("{what} {}: {e}", tmp.display()),
            )
        };
        let mut out = Hashing {
            inner: std::io::BufWriter::new(file),
            hasher: sha2::Sha256::new(),
        };
        // The checkpoint's time, not the time now, so that writing the same range again
        // gives the same bytes.
        s.audit
            .write_export(self.from, self.cp.seq, self.cp.at.clone(), &mut out)
            .map_err(|e| fail(RUN_ARCHIVE_WRITE_FAILED, e.to_string()))?;
        out.flush().map_err(|e| io(e, "writing"))?;
        let sha256 = hex::encode(out.hasher.finalize());
        let file = out
            .inner
            .into_inner()
            .map_err(|e| io(e.into_error(), "writing"))?;
        file.sync_all().map_err(|e| io(e, "flushing"))?;
        drop(file);
        let placed = match std::fs::hard_link(tmp, target) {
            Ok(()) => Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(true),
            // A file system without hard links: rename, after looking that no file is there
            // (runs never overlap, so nothing of this server can put one there meanwhile).
            Err(_) if std::fs::symlink_metadata(target).is_err() => std::fs::rename(tmp, target)
                .map(|()| false)
                .map_err(|e| io(e, "renaming")),
            Err(_) => Ok(true),
        }?;
        if placed {
            // A file of that name is there: use it only if it holds these very bytes.
            let meta = std::fs::symlink_metadata(target).map_err(|e| io(e, "reading"))?;
            let theirs = if meta.file_type().is_file() {
                sha256_of(target).map_err(|e| io(e, "reading"))?
            } else {
                "not a regular file".to_string()
            };
            if theirs != sha256 {
                return Err(fail(
                    RUN_ARCHIVE_EXISTS,
                    format!(
                        "{} exists with other content (sha256 {theirs}, expected {sha256}); it is \
                         never replaced: move it away if it is not needed, and the next run \
                         writes the archive again",
                        target.display()
                    ),
                ));
            }
            std::fs::File::open(target)
                .and_then(|f| f.sync_all())
                .map_err(|e| io(e, "flushing"))?;
        }
        sync_dir(&self.dir).map_err(|e| io(e, "flushing the directory of"))?;
        Ok((sha256, placed))
    }

    /// Read the file at `target` back and check that it is the prefix: it verifies, from
    /// genesis or from the newest anchor, every entry signed, it holds exactly
    /// `from..=through`, ends at the boundary's hash, and has the digest that was written.
    fn check(
        &self,
        s: &AppState,
        target: &Path,
        name: &str,
        sha256: &str,
    ) -> Result<(), ArchiveFailure> {
        let through = self.cp.seq;
        let bad = |detail: String| {
            (
                RUN_ARCHIVE_VERIFY_FAILED,
                Some(name.to_string()),
                format!("{}: {detail}", target.display()),
            )
        };
        let keys = s.keys();
        let got = attenuo_audit::verify_export_file(
            target,
            &keys.checkpoint_keys,
            VerifyOptions::default(),
        )
        .map_err(|e| bad(e.to_string()))?;
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
        if got.sha256 != sha256 {
            problems.push(format!(
                "its sha256 is {}, not the {sha256} that was written",
                got.sha256
            ));
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(bad(problems.join("; ")))
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
/// `[audit.retention] interval_seconds`, the first one interval after start. `stop` is only
/// looked at between runs. A run runs in a task of its own, so that a panic in it is counted
/// as a failed run and the timer goes on.
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
            () = &mut stop => return,
            _ = tick.tick() => {}
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
