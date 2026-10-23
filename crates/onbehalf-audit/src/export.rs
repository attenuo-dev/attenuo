//! Audit export: a self-contained slice of the log that can be verified offline.
//!
//! The export is JSON Lines, one object per line, each tagged by `type`:
//!
//! ```text
//! {"type":"header","format":"onbehalf-audit-export-v1","from":1,"to":120,"exported_at":"..."}
//! {"type":"entry","seq":1,"prev_hash":"..","record":{..},"entry_hash":".."}
//! ...
//! {"type":"checkpoint","seq":100,"head_hash":"..","at":"..","kid":"..","signature":".."}
//! ```
//!
//! Entries come first, in order, then the checkpoints whose seq falls inside the range. The
//! same content is also accepted as one JSON object, `{"header":..,"entries":[..],
//! "checkpoints":[..]}` (the CLI's `--format json`). [`verify_export`] needs nothing but the
//! JWKS: it re-hashes every entry, checks the links, verifies each checkpoint signature and
//! that its `head_hash` equals the entry hash at its seq.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::checkpoint::{
    verify_with_checkpoints, Checkpoint, CheckpointKeys, SignedVerifyReport, Start,
};
use crate::error::AuditError;
use crate::log::AuditEntry;

/// Value of the header's `format` field.
pub const EXPORT_FORMAT: &str = "onbehalf-audit-export-v1";

/// First line of an export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportHeader {
    pub format: String,
    pub from: u64,
    pub to: u64,
    pub exported_at: String,
}

impl ExportHeader {
    pub fn new(from: u64, to: u64, exported_at: String) -> Self {
        Self {
            format: EXPORT_FORMAT.to_string(),
            from,
            to,
            exported_at,
        }
    }
}

/// A parsed export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub header: Option<ExportHeader>,
    pub entries: Vec<AuditEntry>,
    pub checkpoints: Vec<Checkpoint>,
}

/// One JSONL line for the header.
pub fn header_line(h: &ExportHeader) -> String {
    tagged("header", serde_json::to_value(h))
}

/// One JSONL line for an entry.
pub fn entry_line(e: &AuditEntry) -> String {
    tagged("entry", serde_json::to_value(e))
}

/// One JSONL line for a checkpoint.
pub fn checkpoint_line(c: &Checkpoint) -> String {
    tagged("checkpoint", serde_json::to_value(c))
}

fn tagged(kind: &str, v: serde_json::Result<Value>) -> String {
    let mut v = v.expect("export types serialize");
    v["type"] = Value::String(kind.to_string());
    let mut s = v.to_string();
    s.push('\n');
    s
}

fn bad(detail: impl Into<String>) -> AuditError {
    AuditError::Export(detail.into())
}

/// Parse an export in either shape (JSONL, or the single-object JSON form).
pub fn parse_export(text: &str) -> Result<Export, AuditError> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        // A single object without a `type` tag is the JSON form; a JSONL file is a sequence
        // of tagged objects, which does not parse as one value unless it has a single line.
        if let Ok(v @ Value::Object(_)) = serde_json::from_str::<Value>(text) {
            if v.get("type").is_none() {
                return parse_json_form(v);
            }
        }
    }
    let mut export = Export {
        header: None,
        entries: Vec::new(),
        checkpoints: Vec::new(),
    };
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let at = |e: serde_json::Error| bad(format!("line {}: {e}", n + 1));
        let v: Value = serde_json::from_str(line).map_err(at)?;
        match v.get("type").and_then(Value::as_str) {
            Some("header") if export.header.is_none() => {
                export.header = Some(serde_json::from_value(v).map_err(at)?)
            }
            Some("header") => return Err(bad(format!("line {}: second header", n + 1))),
            Some("entry") => export.entries.push(serde_json::from_value(v).map_err(at)?),
            Some("checkpoint") => export
                .checkpoints
                .push(serde_json::from_value(v).map_err(at)?),
            other => return Err(bad(format!("line {}: unknown line type {other:?}", n + 1))),
        }
    }
    check_header(&export)?;
    Ok(export)
}

fn parse_json_form(v: Value) -> Result<Export, AuditError> {
    let get = |k: &str| v.get(k).cloned();
    let list = |k: &str| match get(k) {
        Some(Value::Array(a)) => Ok(a),
        None => Ok(Vec::new()),
        _ => Err(bad(format!("`{k}` must be an array"))),
    };
    let conv = |e: serde_json::Error| bad(e.to_string());
    let export = Export {
        header: get("header")
            .map(serde_json::from_value)
            .transpose()
            .map_err(conv)?,
        entries: list("entries")?
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<_, _>>()
            .map_err(conv)?,
        checkpoints: list("checkpoints")?
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<_, _>>()
            .map_err(conv)?,
    };
    check_header(&export)?;
    Ok(export)
}

fn check_header(export: &Export) -> Result<(), AuditError> {
    match &export.header {
        Some(h) if h.format != EXPORT_FORMAT => Err(bad(format!(
            "unsupported export format `{}` (expected `{EXPORT_FORMAT}`)",
            h.format
        ))),
        _ => Ok(()),
    }
}

/// The JSON form of an export (`--format json`).
pub fn to_json_form(export: &Export) -> Value {
    json!({
        "header": export.header,
        "entries": export.entries,
        "checkpoints": export.checkpoints,
    })
}

/// Result of verifying an export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportReport {
    #[serde(flatten)]
    pub report: SignedVerifyReport,
    /// Seq of the first and last entry in the file, if any.
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    /// The file starts at seq 1 and its first `prev_hash` is the genesis value. When `false`
    /// the entries before `first_seq` are not covered by this file.
    pub from_genesis: bool,
    /// Entries of the header's range are missing from the start or end of the file.
    pub truncated: bool,
}

/// Verify an export against the JWKS keys, offline.
///
/// Beyond [`verify_with_checkpoints`]: a file whose last entry stops short of the header's
/// `to` is flagged `truncated` and not ok, and a checkpoint outside the file's entry range is
/// ignored by the chain check but still has its signature verified.
pub fn verify_export(export: &Export, keys: &CheckpointKeys) -> Result<ExportReport, AuditError> {
    let first_seq = export.entries.first().map(|e| e.seq);
    let last_seq = export.entries.last().map(|e| e.seq);
    let from_genesis = first_seq == Some(1) && export.entries[0].prev_hash == crate::GENESIS_HASH;
    let start = if first_seq == Some(1) {
        Start::Genesis
    } else {
        Start::Window
    };
    // Checkpoints beyond the window cannot be matched to an entry; only those inside count.
    let (lo, hi) = (first_seq.unwrap_or(0), last_seq.unwrap_or(0));
    let inside: Vec<Checkpoint> = export
        .checkpoints
        .iter()
        .filter(|c| c.seq >= lo && c.seq <= hi)
        .cloned()
        .collect();
    let mut report =
        verify_with_checkpoints(export.entries.iter().cloned().map(Ok), &inside, keys, start)?;
    // Outside the window: still check the signature so a forged one is not silently dropped.
    for cp in export
        .checkpoints
        .iter()
        .filter(|c| c.seq < lo || c.seq > hi)
    {
        if let Err(reason) = keys.verify(cp) {
            report
                .bad_checkpoints
                .push(crate::checkpoint::BadCheckpoint {
                    seq: cp.seq,
                    reason,
                });
            report.ok = false;
        }
    }
    report.checkpoints = export.checkpoints.len() as u64;
    // The header says which range was asked for; a file that starts later or ends earlier has
    // had entries cut off.
    let truncated = match (&export.header, first_seq, last_seq) {
        (Some(h), Some(f), Some(l)) => f != h.from || l < h.to,
        (Some(h), _, _) => h.to >= h.from && h.to > 0,
        _ => false,
    };
    if truncated {
        report.ok = false;
    }
    Ok(ExportReport {
        report,
        first_seq,
        last_seq,
        from_genesis,
        truncated,
    })
}
