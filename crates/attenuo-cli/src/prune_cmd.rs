//! `attenuo audit prune`: archive the start of the audit log, verify the archive, then ask the
//! server to prune it (design note `docs/design/audit-retention.md`, section 6.1).
//!
//! Nothing on the server changes before the last step, the `POST`: a failure or a crash while
//! planning, exporting, verifying or hashing leaves the log as it was. The `POST` names the
//! archive's first seq and last entry hash, so the server refuses a prune the archive does not
//! cover, and the anchor it answers is checked against the archive before success is printed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use attenuo_audit::{Anchor, CheckpointKeys, Export};
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
    "prune_archive_mismatch",
    "audit_pruned",
];

/// Refusals that repeating the same request with the same archive can never get past.
const FINAL: &[&str] = &["prune_conflict", "prune_archive_mismatch", "audit_pruned"];

/// The server's refusal in `e`, as `(code, detail)`, when it is one of [`REFUSALS`].
fn refusal(e: &anyhow::Error) -> Option<(String, String)> {
    let api = e.downcast_ref::<client::ApiError>()?;
    let code = api.code.as_deref().filter(|c| REFUSALS.contains(c))?;
    Some((
        code.to_string(),
        render::escape_controls(api.detail.as_deref().unwrap_or_default()),
    ))
}

/// A "no" answer: the text on stderr, or with `--json` an object on stdout that says why.
fn no(json: bool, body: Value, lines: &[String]) -> Result<Outcome> {
    if json {
        let mut v = json!({"ok": false});
        if let (Some(v), Some(b)) = (v.as_object_mut(), body.as_object()) {
            v.extend(b.clone());
        }
        print_json(&v)?;
    } else {
        for line in lines {
            errln!("{line}");
        }
    }
    Ok(Outcome::No)
}

/// `audit prune`.
pub(crate) async fn audit_prune(client: &Client, args: &PruneArgs, json: bool) -> Result<Outcome> {
    if args.reuse_archive {
        let archive = args.archive.as_deref().expect("clap requires --archive");
        return prune_with_archive(client, archive, args, json).await;
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
                return no(
                    json,
                    json!({"refused": {"code": code, "detail": detail}}),
                    &[format!("prune refused: {code}: {detail}")],
                );
            }
            return Err(e);
        }
    };
    let Some(through) = plan["through"].as_u64() else {
        if json {
            print_json(&json!({"ok": false, "plan": plan}))?;
        } else {
            for line in plan_lines(&plan) {
                outln!("{line}")?;
            }
        }
        return Ok(Outcome::No);
    };
    if args.dry_run {
        if json {
            print_json(&json!({"ok": true, "plan": plan}))?;
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
    let Some(through_hash) = plan["checkpoint"]["head_hash"].as_str() else {
        anyhow::bail!(
            "the plan names no checkpoint hash at seq {through}; nothing was exported and the \
             server was not changed"
        );
    };
    let server_anchor = stored_anchor(&plan["anchor"])?;
    let expect = Expect {
        from,
        through: Some(through),
        through_hash: Some(through_hash.to_string()),
        anchor: server_anchor,
        anchor_boundary_only: false,
    };

    // Step 2: export `from..=through` to a temporary file, flushed to disk.
    let tmp = partial_path(archive);
    if let Err(e) = export_archive(client, from, through, &tmp).await {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.context("the archive was not written; the server was not changed"));
    }
    // Step 3: verify it strictly, and check that it is the range the plan named.
    let checked = read_archive(&tmp).and_then(|(export, digest)| {
        check_archive(&export, &keys, &expect).map(|r| (export, digest, r))
    });
    let (export, digest, report) = match checked {
        Ok((export, digest, Ok(report))) => (export, digest, report),
        Ok((_, _, Err(lines))) => {
            let _ = std::fs::remove_file(&tmp);
            let mut text = lines.clone();
            text.push(
                "the archive did not verify; it was removed and the server was not changed".into(),
            );
            return no(
                json,
                json!({"archive_problems": lines, "plan": plan}),
                &text,
            );
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.context("the server was not changed"));
        }
    };
    // Into place, never over a file that appeared meanwhile, and the directory flushed.
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
        &export,
        &digest,
        &keys,
        Some(&plan),
        &report,
        json,
    )
    .await
}

/// What the archive must be: its first seq, its last seq and hash when known, and the anchor
/// its header must carry (the server's newest, for an archive that does not start at 1).
struct Expect {
    from: u64,
    through: Option<u64>,
    through_hash: Option<String>,
    anchor: Option<Anchor>,
    /// Compare only the header anchor's boundary (`from - 1`), not the whole anchor: for the
    /// repeat of a prune, whose archive starts after an older prune.
    anchor_boundary_only: bool,
}

/// The signed anchor of a stored anchor (`{...anchor, state, shipped_at}`), or `None` for null.
fn stored_anchor(v: &Value) -> Result<Option<Anchor>> {
    if v.is_null() {
        return Ok(None);
    }
    Ok(Some(
        serde_json::from_value(v.clone()).context("the server's anchor is malformed")?,
    ))
}

/// `audit prune --reuse-archive`: verify the archive an earlier run wrote against the log as
/// it is now, and send the prune for its last seq with its digest again.
async fn prune_with_archive(
    client: &Client,
    archive: &Path,
    args: &PruneArgs,
    json: bool,
) -> Result<Outcome> {
    let keys = issuer_keys(Ok(client), args.jwks.as_deref()).await?;
    let (export, digest) = read_archive(archive)?;
    let (Some(first), Some(last)) = (export.entries.first(), export.entries.last()) else {
        anyhow::bail!("the archive holds no entries; nothing was sent to the server");
    };
    let _ = first;
    let (through, last_hash) = (last.seq, last.entry_hash.clone());
    if let Some(t) = args.through.filter(|t| *t != through) {
        anyhow::bail!(
            "the archive ends at seq {through}, not at --through {t}; nothing was sent to the \
             server"
        );
    }
    // The log as it is now: its newest anchor says where it starts.
    let page = client.admin_get("/admin/audit/anchors?limit=1").await?;
    let newest = stored_anchor(&page["anchors"][0])?;
    let already = newest.as_ref().filter(|a| a.through_seq == through);
    let expect = match already {
        // A repeat of a prune that succeeded: the anchor must be this archive's.
        Some(a) => {
            let mut problems = Vec::new();
            if a.through_hash != last_hash {
                problems.push(format!(
                    "the log was pruned through seq {through} with another hash there ({}), not \
                     this archive's last entry hash",
                    a.through_hash
                ));
            }
            if a.archive_sha256.as_deref() != Some(digest.as_str()) {
                problems.push(format!(
                    "the log was pruned through seq {through} with another archive digest ({})",
                    a.archive_sha256.as_deref().unwrap_or("none")
                ));
            }
            if !problems.is_empty() {
                problems.push("nothing was sent to the server".into());
                return no(json, json!({"archive_problems": problems}), &problems);
            }
            Expect {
                from: a.previous_through_seq.map_or(1, |p| p + 1),
                through: Some(through),
                through_hash: Some(last_hash.clone()),
                anchor: None,
                anchor_boundary_only: true,
            }
        }
        None if newest.as_ref().is_some_and(|a| a.through_seq > through) => {
            let lines = vec![
                format!(
                    "the log is already pruned through seq {}, past this archive's end at seq {through}; nothing was sent to the server",
                    newest.as_ref().map_or(0, |a| a.through_seq)
                ),
            ];
            return no(json, json!({"archive_problems": lines}), &lines);
        }
        _ => Expect {
            from: newest.as_ref().map_or(1, |a| a.through_seq + 1),
            through: Some(through),
            through_hash: None,
            anchor: newest.clone(),
            anchor_boundary_only: false,
        },
    };
    // For the repeat the header anchor is the previous prune's, which the store keeps; the
    // signature and the `from` it implies are what can be checked here.
    let report = match check_archive(&export, &keys, &expect)? {
        Ok(report) => report,
        Err(mut lines) => {
            lines.push("the archive does not match the log; nothing was sent to the server".into());
            return no(json, json!({"archive_problems": lines}), &lines);
        }
    };
    if !json {
        outln!(
            "archive {}: seq {}..{through}, {} entries, verified, sha256 {digest}",
            render::escape_controls(&archive.display().to_string()),
            report["first_seq"],
            report["entries"]
        )?;
    }
    post_prune(
        client, archive, &export, &digest, &keys, None, &report, json,
    )
    .await
}

/// Stream the export `from..=through` into `tmp` (created new, mode 0600 on Unix) and flush
/// it to disk.
async fn export_archive(client: &Client, from: u64, through: u64, tmp: &Path) -> Result<()> {
    use std::io::Write;

    let file = create_partial(tmp, true)?;
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

/// Parse the archive at `path` and take the SHA-256 of its bytes, read in pieces (the text is
/// dropped once parsed).
fn read_archive(path: &Path) -> Result<(Export, String)> {
    use std::io::Read;

    let mut f = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hex::encode(hasher.finalize());
    let export = {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        attenuo_audit::parse_export(&text).context("parsing the archive")?
    };
    Ok((export, digest))
}

/// Verify an archive strictly and check that it is the whole prefix `expect` names: entries
/// from `expect.from` to its last seq, every one signed, the last at a checkpoint; that last
/// entry is `expect.through` with hash `expect.through_hash` when known; and an archive that
/// does not start at 1 carries `expect.anchor` in its header. `Ok(Err(lines))` says why it
/// does not pass.
fn check_archive(
    export: &Export,
    keys: &CheckpointKeys,
    expect: &Expect,
) -> Result<std::result::Result<Value, Vec<String>>> {
    let report = attenuo_audit::verify_export(export, keys)?;
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
    if header.from != expect.from {
        problems.push(format!(
            "the archive starts at seq {}, but the log starts at seq {}: the entries before \
             seq {} would be pruned without being archived",
            header.from, expect.from, header.from
        ));
    }
    if let Some(t) = expect.through.filter(|t| Some(*t) != report.last_seq) {
        problems.push(format!(
            "the archive ends at seq {}, not at seq {t}",
            report
                .last_seq
                .map_or_else(|| "?".to_string(), |s| s.to_string())
        ));
    }
    if let Some(h) = &expect.through_hash {
        if last.map(|e| &e.entry_hash) != Some(h) {
            problems.push(
                "the archive's last entry is not the one the server's checkpoint signs".to_string(),
            );
        }
    }
    if header.from > 1 {
        match (&header.anchor, &expect.anchor) {
            (Some(a), _) if expect.anchor_boundary_only && a.through_seq + 1 == header.from => {}
            (Some(a), Some(b)) if a == b => {}
            (None, _) => problems.push(
                "the archive does not start at seq 1 and its header carries no anchor".into(),
            ),
            (Some(a), _) => problems.push(format!(
                "the archive's header anchor (through seq {}) is not the log's newest anchor",
                a.through_seq
            )),
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
/// without hard links, a rename that refuses to replace (Linux `RENAME_NOREPLACE`), or else
/// an error. Then the directory is flushed; a failure there is an error too, before anything
/// is sent.
fn place(tmp: &Path, archive: &Path) -> Result<()> {
    let exists = || {
        anyhow::anyhow!(
            "{} appeared while the archive was written; refusing to overwrite it",
            archive.display()
        )
    };
    match std::fs::hard_link(tmp, archive) {
        Ok(()) => {
            let _ = std::fs::remove_file(tmp);
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(exists()),
        Err(link_err) => attenuo_audit::fsutil::rename_noreplace(tmp, archive).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                exists()
            } else {
                anyhow::anyhow!(
                    "could not move the archive to {} without risking an overwrite (hard link: \
                     {link_err}; rename without replace: {e}); the verified file is kept at {}",
                    archive.display(),
                    tmp.display()
                )
            }
        })?,
    }
    sync_parent(archive)
        .with_context(|| format!("flushing the directory of {} to disk", archive.display()))?;
    Ok(())
}

/// Check the anchor the server answered against the archive: its signature, its boundary and
/// hash (the archive's last entry), its digest (the archive's), and its previous boundary (the
/// archive header's anchor, or none for an archive from seq 1).
fn anchor_problems(
    resp: &Value,
    export: &Export,
    digest: &str,
    keys: &CheckpointKeys,
) -> Vec<String> {
    let a: Anchor = match serde_json::from_value(resp["anchor"].clone()) {
        Ok(a) => a,
        Err(e) => return vec![format!("the answer's anchor is malformed: {e}")],
    };
    let mut out = Vec::new();
    if let Err(why) = keys.verify_anchor(&a) {
        out.push(format!("the anchor's signature: {why}"));
    }
    let last = export.entries.last();
    if Some(a.through_seq) != last.map(|e| e.seq) {
        out.push(format!(
            "the anchor is through seq {}, the archive ends at seq {}",
            a.through_seq,
            last.map_or(0, |e| e.seq)
        ));
    }
    if Some(&a.through_hash) != last.map(|e| &e.entry_hash) {
        out.push("the anchor's through_hash is not the archive's last entry hash".into());
    }
    if a.archive_sha256.as_deref() != Some(digest) {
        out.push(format!(
            "the anchor's archive_sha256 is {}, not the archive's {digest}",
            a.archive_sha256.as_deref().unwrap_or("none")
        ));
    }
    let header = export.header.as_ref();
    let want_prev = header
        .filter(|h| h.from > 1)
        .and_then(|h| h.anchor.as_ref())
        .map(|p| p.through_seq);
    if a.previous_through_seq != want_prev {
        out.push(format!(
            "the anchor's previous boundary is {:?}, the archive says {:?}",
            a.previous_through_seq, want_prev
        ));
    }
    out
}

/// Step 5 and 6: send the prune (with the archive's first seq and last hash, so the server
/// refuses one the archive does not cover), check the anchor it answers, and print what the
/// server committed. The archive is kept whatever the answer.
#[allow(clippy::too_many_arguments)]
async fn post_prune(
    client: &Client,
    archive: &Path,
    export: &Export,
    digest: &str,
    keys: &CheckpointKeys,
    plan: Option<&Value>,
    report: &Value,
    json: bool,
) -> Result<Outcome> {
    let (Some(first), Some(last)) = (export.entries.first(), export.entries.last()) else {
        anyhow::bail!("the archive holds no entries");
    };
    let repeat = format!(
        "the archive {} is kept; once the cause is fixed, repeat with `attenuo audit prune \
         --archive {} --reuse-archive` (the same digest makes the request safe to repeat)",
        archive.display(),
        archive.display()
    );
    let body = json!({
        "through": last.seq,
        "archive_sha256": digest,
        "from": first.seq,
        "through_hash": last.entry_hash,
    });
    let resp = match client.admin_post("/admin/audit/prune", &body).await {
        Ok(resp) => resp,
        Err(e) => {
            if let Some((code, detail)) = refusal(&e) {
                let mut lines = vec![format!("prune refused: {code}: {detail}")];
                if FINAL.contains(&code.as_str()) {
                    lines.push(format!(
                        "the archive {} is kept; the same request would be refused again",
                        archive.display()
                    ));
                } else {
                    lines.push(repeat.clone());
                }
                let lines: Vec<String> = lines.iter().map(|l| render::escape_controls(l)).collect();
                return no(
                    json,
                    json!({"refused": {"code": code, "detail": detail}}),
                    &lines,
                );
            }
            errln!("{}", render::escape_controls(&repeat));
            return Err(e.context("the prune request failed"));
        }
    };
    let problems = anchor_problems(&resp, export, digest, keys);
    let archive_json = json!({
        "path": archive.display().to_string(),
        "sha256": digest,
        "entries": report["entries"],
        "from": report["first_seq"],
        "through": report["last_seq"],
    });
    if !problems.is_empty() {
        let mut lines =
            vec!["PRUNE COMMITTED, BUT THE ANCHOR DOES NOT MATCH THE ARCHIVE".to_string()];
        lines.extend(problems.iter().cloned());
        lines.push(format!(
            "the server pruned through seq {}; keep the archive {} and the server's answer, and \
             check the log with `attenuo audit verify` and `audit verify --file`",
            resp["pruned_through"],
            archive.display()
        ));
        return no(
            json,
            json!({"committed": true, "anchor_problems": problems, "archive": archive_json,
                   "prune": resp}),
            &lines,
        );
    }
    if json {
        print_json(&json!({
            "ok": true,
            "plan": plan,
            "archive": archive_json,
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
    out.extend(auto_lines(&plan["auto"]));
    out
}

/// The plan's `auto` member (`[audit.retention] prune = "auto"`) in one or two lines;
/// nothing when it is null.
fn auto_lines(auto: &Value) -> Vec<String> {
    if !auto.is_object() {
        return Vec::new();
    }
    let archive = match auto["archive_dir"].as_str() {
        Some(d) => format!("archives in {}", render::escape_controls(d)),
        None => "no archive is kept".to_string(),
    };
    let mut out = vec![format!(
        "automatic prune: on, of entries older than {} seconds, every {} seconds, at most {} \
         entries a run; {archive}",
        auto["keep_seconds"], auto["interval_seconds"], auto["max_entries_per_run"]
    )];
    let last = &auto["last_run"];
    if last.is_object() {
        let mut line = format!(
            "last automatic run: {} at {} ({})",
            render::escape_controls(last["outcome"].as_str().unwrap_or("?")),
            render::escape_controls(last["at"].as_str().unwrap_or("?")),
            render::escape_controls(last["reason"].as_str().unwrap_or("?"))
        );
        if let Some(t) = last["through"].as_u64() {
            line.push_str(&format!(", through seq {t}"));
        }
        if let Some(a) = last["archive"].as_str() {
            line.push_str(&format!(", archive {}", render::escape_controls(a)));
        }
        out.push(line);
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
    fn plan_text_names_the_automatic_prune() {
        let mut plan = json!({"from": 1, "through": null, "entries": 0, "guards": {},
                              "anchor": null, "auto": null});
        assert!(!plan_lines(&plan).join("\n").contains("automatic"));
        plan["auto"] = json!({"keep_seconds": 7776000, "interval_seconds": 3600,
                              "max_entries_per_run": 1000000, "archive_dir": "/var/a",
                              "last_run": null});
        let text = plan_lines(&plan).join("\n");
        assert!(
            text.contains(
                "automatic prune: on, of entries older than 7776000 seconds, every \
                           3600 seconds, at most 1000000 entries a run; archives in /var/a"
            ),
            "{text}"
        );
        assert!(!text.contains("last automatic run"), "{text}");
        plan["auto"]["archive_dir"] = Value::Null;
        plan["auto"]["last_run"] = json!({"at": "2026-01-01T00:00:00Z", "outcome": "pruned",
                                          "reason": "ok", "through": 20, "prune_seq": 26,
                                          "detail": null, "archive": "audit-00000000000000000001-00000000000000000020.jsonl"});
        let text = plan_lines(&plan).join("\n");
        for want in [
            "no archive is kept",
            "last automatic run: pruned at 2026-01-01T00:00:00Z (ok), through seq 20, archive \
             audit-00000000000000000001-00000000000000000020.jsonl",
        ] {
            assert!(text.contains(want), "{want} not in {text}");
        }
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
