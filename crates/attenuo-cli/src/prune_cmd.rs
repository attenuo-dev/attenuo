//! `attenuo audit prune`: archive the start of the audit log, verify the archive, then ask the
//! server to prune it (design note `docs/design/audit-retention.md`, section 6.1).
//!
//! Nothing on the server changes before the last step, the `POST`: a failure or a crash while
//! planning, exporting, verifying or hashing leaves the log as it was.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::client::{self, query_escape, Client};
use crate::{
    create_partial, export_lines, issuer_keys, partial_path, print_json, render, sync_parent,
    write_export, ExportFormat, Outcome,
};

/// The arguments of `audit prune`.
pub(crate) struct PruneArgs {
    pub before: Option<String>,
    pub through: Option<u64>,
    pub archive: Option<PathBuf>,
    pub jwks: Option<PathBuf>,
    pub dry_run: bool,
    pub reuse_archive: bool,
}

/// The codes with which the server refuses a plan or a prune: the guards (409), and 410
/// `audit_pruned` for a boundary already below the log's start.
const REFUSALS: &[&str] = &[
    "prune_disabled",
    "prune_not_at_checkpoint",
    "prune_too_recent",
    "prune_live_run",
    "sink_behind",
    "prune_in_progress",
    "prune_conflict",
    "audit_pruned",
];

/// The server's refusal in `e`, as `(code, detail)`, when it is one of [`REFUSALS`].
fn refusal(e: &anyhow::Error) -> Option<(String, String)> {
    let api = e.downcast_ref::<client::ApiError>()?;
    let code = api.code.as_deref().filter(|c| REFUSALS.contains(c))?;
    Some((
        code.to_string(),
        render::escape_controls(api.detail.as_deref().unwrap_or_default()),
    ))
}

/// `audit prune`.
pub(crate) async fn audit_prune(client: &Client, args: &PruneArgs, json: bool) -> Result<Outcome> {
    if args.reuse_archive {
        let archive = args.archive.as_deref().expect("clap requires --archive");
        return prune_with_archive(client, archive, args, None, json).await;
    }
    let query = match (&args.before, args.through) {
        (Some(b), _) => format!("before={}", query_escape(b)),
        (None, Some(t)) => format!("through={t}"),
        (None, None) => unreachable!("clap requires --before or --through"),
    };
    let plan = match client
        .admin_get(&format!("/admin/audit/prune/plan?{query}"))
        .await
    {
        Ok(plan) => plan,
        Err(e) => {
            if let Some((code, detail)) = refusal(&e) {
                errln!("prune refused: {code}: {detail}");
                return Ok(Outcome::No);
            }
            return Err(e);
        }
    };
    let Some(through) = plan["through"].as_u64() else {
        if json {
            print_json(&json!({"plan": plan}))?;
        } else {
            for line in plan_lines(&plan) {
                outln!("{line}")?;
            }
        }
        return Ok(Outcome::No);
    };
    if args.dry_run {
        if json {
            print_json(&json!({"plan": plan}))?;
        } else {
            for line in plan_lines(&plan) {
                outln!("{line}")?;
            }
            outln!("dry run: nothing was exported or pruned")?;
        }
        return Ok(Outcome::Ok);
    }
    let archive = args.archive.as_deref().expect("clap requires --archive");
    if std::fs::symlink_metadata(archive).is_ok() {
        anyhow::bail!(
            "{} exists; refusing to overwrite it (if an earlier prune wrote it and its request \
             failed, repeat with `attenuo audit prune --archive {} --reuse-archive`)",
            archive.display(),
            archive.display()
        );
    }
    // The keys first: a JWKS that cannot be read stops the prune before any export.
    let keys = issuer_keys(Ok(client), args.jwks.as_deref()).await?;
    let from = plan["from"].as_u64().context("the plan has no `from`")?;

    // Step 2: export `from..=through` to a temporary file, flushed to disk.
    let tmp = partial_path(archive);
    if let Err(e) = export_archive(client, from, through, &tmp).await {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.context("the archive was not written; the server was not changed"));
    }
    // Step 3: verify it strictly, and check that it is the range the plan named.
    let checked = std::fs::read(&tmp)
        .with_context(|| format!("reading {}", tmp.display()))
        .and_then(|bytes| check_archive(&bytes, &keys, Some((from, &plan))).map(|r| (bytes, r)));
    let (bytes, report) = match checked {
        Ok((bytes, Ok(report))) => (bytes, report),
        Ok((_, Err(lines))) => {
            let _ = std::fs::remove_file(&tmp);
            for line in lines {
                errln!("{line}");
            }
            errln!("the archive did not verify; it was removed and the server was not changed");
            return Ok(Outcome::No);
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.context("the server was not changed"));
        }
    };
    // Step 4: the digest of the file's bytes.
    let digest = hex::encode(Sha256::digest(&bytes));
    // Into place, never over a file that appeared meanwhile.
    if let Err(e) = place(&tmp, archive) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.context("the server was not changed"));
    }
    if !json {
        outln!(
            "archive {}: seq {from}..{through}, {} entries, verified, sha256 {digest}",
            render::escape_controls(&archive.display().to_string()),
            report["entries"]
        )?;
    }
    post_prune(
        client,
        archive,
        through,
        &digest,
        Some(&plan),
        &report,
        json,
    )
    .await
}

/// `audit prune --reuse-archive`: verify the archive an earlier run wrote, and send the prune
/// for its last seq with its digest again.
async fn prune_with_archive(
    client: &Client,
    archive: &Path,
    args: &PruneArgs,
    plan: Option<&Value>,
    json: bool,
) -> Result<Outcome> {
    let keys = issuer_keys(Ok(client), args.jwks.as_deref()).await?;
    let bytes = std::fs::read(archive).with_context(|| format!("reading {}", archive.display()))?;
    let report = match check_archive(&bytes, &keys, None)? {
        Ok(report) => report,
        Err(lines) => {
            for line in lines {
                errln!("{line}");
            }
            errln!("the archive did not verify; nothing was sent to the server");
            return Ok(Outcome::No);
        }
    };
    let through = report["last_seq"]
        .as_u64()
        .context("the archive holds no entries")?;
    if let Some(t) = args.through.filter(|t| *t != through) {
        anyhow::bail!(
            "the archive ends at seq {through}, not at --through {t}; nothing was sent to the \
             server"
        );
    }
    let digest = hex::encode(Sha256::digest(&bytes));
    if !json {
        outln!(
            "archive {}: seq {}..{through}, {} entries, verified, sha256 {digest}",
            render::escape_controls(&archive.display().to_string()),
            report["first_seq"],
            report["entries"]
        )?;
    }
    post_prune(client, archive, through, &digest, plan, &report, json).await
}

/// Stream the export `from..=through` into `tmp` (created new) and flush it to disk.
async fn export_archive(client: &Client, from: u64, through: u64, tmp: &Path) -> Result<()> {
    use std::io::Write;

    let file = create_partial(tmp)?;
    let path = crate::export_path(
        Some(from),
        Some(through),
        &attenuo_audit::RecordFilter::default(),
    );
    let resp = client.admin_get_stream(&path).await?;
    let mut sink = std::io::BufWriter::new(file);
    write_export(resp, ExportFormat::Jsonl, &mut sink).await?;
    sink.flush()?;
    let file = sink.into_inner().map_err(|e| e.into_error())?;
    file.sync_all()?;
    Ok(())
}

/// Verify an archive's bytes strictly and check that it is a whole prefix ending at a
/// checkpoint: entries from its header's `from` to its `to`, every one signed, the last at a
/// checkpoint. With `plan`, also that it is `from..=through` of that plan and ends at the
/// plan's checkpoint hash. `Ok(Err(lines))` says why it does not pass.
fn check_archive(
    bytes: &[u8],
    keys: &attenuo_audit::CheckpointKeys,
    plan: Option<(u64, &Value)>,
) -> Result<std::result::Result<Value, Vec<String>>> {
    let text = std::str::from_utf8(bytes).context("the archive is not UTF-8")?;
    let export = attenuo_audit::parse_export(text).context("parsing the archive")?;
    let report = attenuo_audit::verify_export(&export, keys)?;
    let v = serde_json::to_value(&report)?;
    let mut problems = Vec::new();
    if !report.report.ok {
        problems.extend(export_lines(&v));
    }
    let header = export
        .header
        .as_ref()
        .context("the archive has no header")?;
    let last = export.entries.last();
    if report.first_seq != Some(header.from) || report.last_seq != Some(header.to) {
        problems.push(format!(
            "the archive does not hold every entry of seq {}..{}",
            header.from, header.to
        ));
    }
    if report.report.last_signed_seq != report.last_seq {
        problems.push("the archive does not end at a checkpoint".to_string());
    }
    if let Some((from, plan)) = plan {
        let through = plan["through"].as_u64();
        if header.from != from || Some(header.to) != through {
            problems.push(format!(
                "the server exported seq {}..{}, not the plan's {from}..{}",
                header.from,
                header.to,
                through.map_or_else(|| "?".to_string(), |t| t.to_string())
            ));
        }
        if let Some(h) = plan["checkpoint"]["head_hash"].as_str() {
            if last.map(|e| e.entry_hash.as_str()) != Some(h) {
                problems.push(
                    "the archive's last entry is not the one the plan's checkpoint signs"
                        .to_string(),
                );
            }
        }
    }
    Ok(if problems.is_empty() {
        Ok(v)
    } else {
        Err(problems)
    })
}

/// Move the verified `tmp` to `archive`, refusing if `archive` exists by now: a hard link,
/// which fails on an existing name, then the temporary name is removed. On a file system
/// without hard links, a rename after one more check.
fn place(tmp: &Path, archive: &Path) -> Result<()> {
    match std::fs::hard_link(tmp, archive) {
        Ok(()) => {
            let _ = std::fs::remove_file(tmp);
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            anyhow::bail!(
                "{} appeared while the archive was written; refusing to overwrite it",
                archive.display()
            );
        }
        Err(_) => {
            if std::fs::symlink_metadata(archive).is_ok() {
                anyhow::bail!(
                    "{} appeared while the archive was written; refusing to overwrite it",
                    archive.display()
                );
            }
            std::fs::rename(tmp, archive)
                .with_context(|| format!("moving the archive to {}", archive.display()))?;
        }
    }
    sync_parent(archive);
    Ok(())
}

/// Step 5 and 6: send the prune and print what the server committed. The archive is kept
/// whatever the answer.
async fn post_prune(
    client: &Client,
    archive: &Path,
    through: u64,
    digest: &str,
    plan: Option<&Value>,
    report: &Value,
    json: bool,
) -> Result<Outcome> {
    let repeat = format!(
        "the archive {} is kept; once the cause is fixed, repeat with `attenuo audit prune \
         --archive {} --reuse-archive` (the same digest makes the request safe to repeat)",
        archive.display(),
        archive.display()
    );
    let body = json!({"through": through, "archive_sha256": digest});
    let resp = match client.admin_post("/admin/audit/prune", &body).await {
        Ok(resp) => resp,
        Err(e) => {
            if let Some((code, detail)) = refusal(&e) {
                errln!("prune refused: {code}: {detail}");
                errln!("{}", render::escape_controls(&repeat));
                return Ok(Outcome::No);
            }
            errln!("{}", render::escape_controls(&repeat));
            return Err(e.context("the prune request failed"));
        }
    };
    if json {
        print_json(&json!({
            "plan": plan,
            "archive": {
                "path": archive.display().to_string(),
                "sha256": digest,
                "entries": report["entries"],
                "from": report["first_seq"],
                "through": report["last_seq"],
            },
            "prune": resp,
        }))?;
    } else {
        for line in prune_lines(&resp) {
            outln!("{line}")?;
        }
    }
    Ok(Outcome::Ok)
}

/// Text for a prune plan.
fn plan_lines(plan: &Value) -> Vec<String> {
    let g = &plan["guards"];
    let mut out = Vec::new();
    match plan["through"].as_u64() {
        Some(t) => out.push(format!(
            "plan: prune seq {}..{t} ({} entries); the entry at seq {t} was written at {} and \
             the checkpoint there signs it",
            plan["from"],
            plan["entries"],
            plan["at"].as_str().unwrap_or("?")
        )),
        None => out.push(format!(
            "plan: nothing can be pruned (the log starts at seq {})",
            plan["from"]
        )),
    }
    if let Some(by) = g["limited_by"].as_str() {
        out.push(format!("limited by: {by}"));
    }
    if let Some(c) = g["min_age_cutoff"].as_str() {
        out.push(format!("only entries written before {c} are old enough"));
    }
    if let Some(s) = g["live_run_seq"].as_u64() {
        out.push(format!("a live delegation chain has a record at seq {s}"));
    }
    if g["sink_degraded"] == true {
        out.push("the checkpoint sink is degraded".to_string());
    }
    if let Some(s) = g["sink_delivered_through"].as_u64() {
        out.push(format!("the checkpoint sink has delivered through seq {s}"));
    }
    if g["in_progress"] == true {
        out.push("the rows of the previous prune are still being deleted".to_string());
    }
    if g["anchor_undelivered"] == true {
        out.push("the previous prune's anchor is not delivered by the sink yet".to_string());
    }
    if let Some(b) = plan["anchor"]["through_seq"].as_u64() {
        out.push(format!("the log was pruned before, through seq {b}"));
    }
    out
}

/// Text for the answer to `POST /admin/audit/prune`.
fn prune_lines(resp: &Value) -> Vec<String> {
    let a = &resp["anchor"];
    let mut out = vec![if resp["already"] == true {
        format!(
            "already pruned through seq {} with this archive (prune record at seq {}); nothing \
             new was written",
            resp["pruned_through"], resp["prune_seq"]
        )
    } else {
        format!(
            "pruned through seq {} (prune record at seq {})",
            resp["pruned_through"], resp["prune_seq"]
        )
    }];
    out.push(format!(
        "anchor: through seq {} hash {}, prune record hash {}, previous boundary {}, archive \
         sha256 {}, signed {} by {}",
        a["through_seq"],
        a["through_hash"].as_str().unwrap_or("?"),
        a["prune_entry_hash"].as_str().unwrap_or("?"),
        a["previous_through_seq"]
            .as_u64()
            .map_or_else(|| "none".to_string(), |s| format!("seq {s}")),
        a["archive_sha256"].as_str().unwrap_or("none"),
        a["at"].as_str().unwrap_or("?"),
        a["kid"].as_str().unwrap_or("?"),
    ));
    for (name, cp) in [
        ("before", &resp["checkpoint_before"]),
        ("after", &resp["checkpoint_after"]),
    ] {
        if let Some(seq) = cp["seq"].as_u64() {
            out.push(format!(
                "checkpoint {name}: seq {seq} hash {}",
                cp["head_hash"].as_str().unwrap_or("?")
            ));
        }
    }
    let s = &resp["shipped"];
    if s.is_null() {
        out.push("sink: none configured".to_string());
    } else if let Some(at) = s["anchor_shipped_at"].as_str() {
        out.push(format!("sink: the anchor was delivered at {at}"));
    } else {
        out.push(format!(
            "sink: the anchor and checkpoints are queued, not delivered yet (delivered through \
             seq {}); the next prune waits for them",
            s["delivered_through"]
        ));
    }
    if resp["deleting"] == true {
        out.push(format!(
            "the pruned rows are being deleted in the background; reads already start at seq {}",
            resp["pruned_through"].as_u64().unwrap_or(0) + 1
        ));
    } else {
        out.push("the pruned rows are deleted".to_string());
    }
    out.push(
        "keep the archive off this host: it is the only copy of the pruned entries".to_string(),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_partial_file_sits_next_to_the_archive() {
        let p = partial_path(Path::new("/mnt/archive/a.jsonl"));
        assert_eq!(p.parent(), Some(Path::new("/mnt/archive")));
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with(".a.jsonl.partial-"), "{name}");
    }

    #[test]
    fn place_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path().join(".a.partial");
        let out = dir.path().join("a.jsonl");
        std::fs::write(&tmp, b"new").unwrap();
        std::fs::write(&out, b"old").unwrap();
        assert!(place(&tmp, &out).is_err());
        assert_eq!(std::fs::read(&out).unwrap(), b"old");
        std::fs::remove_file(&out).unwrap();
        place(&tmp, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"new");
        assert!(!tmp.exists());
    }

    #[test]
    fn prune_text_names_the_record_anchor_checkpoints_and_sink() {
        let resp = json!({
            "prune_seq": 41, "pruned_through": 20, "deleting": true, "already": false,
            "anchor": {"through_seq": 20, "through_hash": "aa", "prune_entry_hash": "bb",
                       "previous_through_seq": null, "archive_sha256": "cc",
                       "at": "2026-01-01T00:00:00Z", "kid": "k1"},
            "checkpoint_before": {"seq": 40, "head_hash": "dd"},
            "checkpoint_after": {"seq": 41, "head_hash": "ee"},
            "shipped": {"queued": true, "delivered_through": 40, "anchor_shipped_at": null,
                        "anchor_pending": true},
        });
        let text = prune_lines(&resp).join("\n");
        for want in [
            "pruned through seq 20 (prune record at seq 41)",
            "archive sha256 cc",
            "checkpoint before: seq 40",
            "checkpoint after: seq 41",
            "not delivered yet",
            "reads already start at seq 21",
        ] {
            assert!(text.contains(want), "{want} not in {text}");
        }
    }
}
