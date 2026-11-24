//! `attenuo audit compact`: shrink the server's SQLite file offline after a prune, with the
//! server stopped (`attenuo_audit::compact`, design note `docs/design/audit-retention.md`).
//!
//! Exit status: 0 when the file was compacted (or the dry run passed its checks), 2 when a
//! check refused and the file was not changed, 3 when `VACUUM` rewrote the file and the check
//! after it found a difference or could not run (restore the backup), 1 on any other error.

use std::path::Path;

use anyhow::Result;
use attenuo_audit::{CompactError, CompactOptions, CompactReport};
use serde_json::{json, Value};

use crate::{print_json, render, Outcome};

/// The exit status of a compaction whose check after `VACUUM` failed.
pub(crate) const POST_CHECK_FAILED: u8 = 3;

/// `audit compact --db PATH [--dry-run]`.
pub(crate) fn audit_compact(db: &Path, dry_run: bool, json: bool) -> Result<Outcome> {
    match attenuo_audit::compact(db, CompactOptions::default().dry_run(dry_run)) {
        Ok(report) => {
            if json {
                print_json(&report_json(&report))?;
            } else {
                for line in report_lines(&report) {
                    outln!("{line}")?;
                }
            }
            Ok(Outcome::Ok)
        }
        Err(CompactError::Refused { code, detail }) => {
            let detail = render::escape_controls(&detail);
            if json {
                print_json(&json!({"ok": false, "refused": {"code": code, "detail": detail}}))?;
            } else {
                errln!("compact refused: {code}: {detail}");
                errln!("the file was not changed");
            }
            Ok(Outcome::No)
        }
        Err(CompactError::PostCheck { mismatches }) => {
            let mismatches: Vec<String> = mismatches
                .iter()
                .map(|m| render::escape_controls(m))
                .collect();
            if json {
                print_json(&json!({"ok": false, "post_check_failed": mismatches}))?;
            } else {
                errln!("COMPACTED, BUT THE CHECK AFTER VACUUM FAILED:");
                for m in &mismatches {
                    errln!("  {m}");
                }
                errln!(
                    "Do not start the server on this file. Restore the backup you took before \
                     compacting."
                );
            }
            Ok(Outcome::Exit(POST_CHECK_FAILED))
        }
        Err(e @ CompactError::Unverified { .. }) => {
            let detail = render::escape_controls(&e.to_string());
            if json {
                print_json(&json!({"ok": false, "unverified": detail}))?;
            } else {
                errln!("COMPACTED, BUT THE FILE COULD NOT BE CHECKED: {detail}");
            }
            Ok(Outcome::Exit(POST_CHECK_FAILED))
        }
        Err(CompactError::Failed(e)) => {
            Err(anyhow::Error::new(e).context(format!("compacting {}", db.display())))
        }
    }
}

fn report_json(r: &CompactReport) -> Value {
    let b = &r.before;
    json!({
        "ok": true,
        "dry_run": r.dry_run,
        "path": r.path,
        "size_before": r.disk_bytes_before,
        "size_after": r.disk_bytes_after,
        "wal_bytes_before": r.wal_bytes_before,
        "bytes_returned": r.bytes_returned(),
        "free_bytes_before": b.free_bytes,
        "free_bytes_after": r.after.as_ref().map(|a| a.free_bytes),
        "entries": b.entries,
        "head_seq": b.head_seq,
        "head_hash": b.head_hash,
        "pruned_through": b.pruned_through,
        "schema_version": b.schema_version,
        "space": r.space.places,
    })
}

fn report_lines(r: &CompactReport) -> Vec<String> {
    let b = &r.before;
    let head = b
        .head_seq
        .map_or_else(|| "empty log".to_string(), |s| format!("head seq {s}"));
    let mut lines = Vec::new();
    if r.dry_run {
        lines.push(format!("dry run: {} was not changed", r.path.display()));
        lines.push(format!(
            "size:          {} bytes, {} of them free pages",
            r.disk_bytes_before, b.free_bytes
        ));
        lines.push(format!(
            "would return:  at least {} bytes (the free pages), plus the -wal file's {} bytes",
            b.free_bytes, r.wal_bytes_before
        ));
    } else {
        lines.push(format!("compacted {}", r.path.display()));
        lines.push(format!("size before:   {} bytes", r.disk_bytes_before));
        lines.push(format!("size after:    {} bytes", r.disk_bytes_after));
        lines.push(format!("returned:      {} bytes", r.bytes_returned()));
    }
    lines.push(format!("entries:       {} ({head})", b.entries));
    for p in &r.space.places {
        lines.push(format!(
            "free space:    {} ({}): {} bytes needed, {} available",
            p.dir.display(),
            p.what.join(" and "),
            p.needed,
            p.available
        ));
    }
    if !r.dry_run {
        lines.push(
            "checked:       integrity before and after; schema version, entry count, chain \
             head, prune marker, newest anchor, every table's rows and the schema text are \
             unchanged"
                .to_string(),
        );
    }
    lines
}
