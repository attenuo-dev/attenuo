//! Audit export: a self-contained slice of the log that can be verified offline.
//!
//! The export is JSON Lines, one object per line, each tagged by `type` and written as RFC 8785
//! canonical JSON (members sorted, so `type` is not first):
//!
//! ```text
//! {"exported_at":"...","format":"attenuo-audit-export-v2","from":1,"to":120,"type":"header"}
//! {"entry_hash":"..","prev_hash":"..","record":{..},"seq":1,"type":"entry"}
//! ...
//! {"at":"..","head_hash":"..","kid":"..","seq":100,"signature":"..","type":"checkpoint"}
//! ```
//!
//! The header comes first and is required: it declares the range `from..=to` the file holds.
//! Entries follow, in order, then the checkpoints whose seq falls inside the range. The same
//! content is also accepted as one JSON object, `{"header":..,"entries":[..],
//! "checkpoints":[..]}` (the CLI's `--format json`). [`verify_export`] needs nothing but the
//! JWKS: it re-hashes every entry, checks the links, verifies each checkpoint signature and
//! that its `head_hash` equals the entry hash at its seq, and checks that the entries are
//! exactly the declared range and are all countersigned (see [`VerifyOptions`]).
//!
//! A header may carry `filter` (`{"kind":..,"chain_id":..,"tool":..,"decision":..}`, each member
//! optional) when the export holds only the matching entries; [`verify_export_with`] refuses
//! such a file. `tool` and `decision` were added after `kind` and `chain_id` without a format
//! bump: a member that is absent means "not filtered on this", so a header written before
//! they existed reads exactly as it did, and a verifier that predates them still refuses a
//! file filtered on them because it refuses any header that has a `filter` at all.
//!
//! Format `attenuo-audit-export-v2` goes with entry hash construction
//! [`ENTRY_HASH_VERSION`](crate::ENTRY_HASH_VERSION) (RFC 8785, SR-20). A `v1` export, hashed
//! the earlier way, is refused when parsed.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::checkpoint::{
    verify_with_checkpoints, Checkpoint, CheckpointKeys, SignedVerifyReport, Start,
};
use crate::error::AuditError;
use crate::log::AuditEntry;
use attenuo_core::{Decision, RecordKind};

/// Value of the header's `format` field.
pub const EXPORT_FORMAT: &str = "attenuo-audit-export-v2";

/// Which entries of the range an export holds, when it is not all of them. Set as the
/// header's `filter` member. Absent from an unfiltered export.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordFilter {
    /// Only records of this kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<RecordKind>,
    /// Only records of this delegation chain (`chain_id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    /// Only records for this tool (`tool`, for example `token.exchange`). Absent in headers
    /// written before this member existed, which means unfiltered on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Only records with this decision. Absent in headers written before this member
    /// existed, which means unfiltered on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
}

impl RecordFilter {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Does `record` pass?
    pub fn matches(&self, record: &attenuo_core::DecisionRecord) -> bool {
        self.kind.is_none_or(|k| k == record.kind)
            && self
                .chain_id
                .as_ref()
                .is_none_or(|c| record.chain_id.as_ref() == Some(c))
            && self.tool.as_ref().is_none_or(|t| *t == record.tool)
            && self.decision.as_ref().is_none_or(|d| *d == record.decision)
    }
}

/// First line of an export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportHeader {
    pub format: String,
    pub from: u64,
    pub to: u64,
    pub exported_at: String,
    /// Present when the export holds only the entries that match. Such a file has gaps in its
    /// hash chain by construction, so [`verify_export_with`] refuses it: verify an unfiltered
    /// export, then filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<RecordFilter>,
}

impl ExportHeader {
    pub fn new(from: u64, to: u64, exported_at: String) -> Self {
        Self {
            format: EXPORT_FORMAT.to_string(),
            from,
            to,
            exported_at,
            filter: None,
        }
    }

    /// The same header for a filtered export (an empty filter is no filter).
    pub fn with_filter(mut self, filter: RecordFilter) -> Self {
        self.filter = (!filter.is_empty()).then_some(filter);
        self
    }
}

/// A parsed export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    /// Always present in a parsed export; [`verify_export`] refuses an `Export` built without
    /// one, since nothing would say which range the file claims to hold.
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
    let mut s = attenuo_core::jcs::to_string(&v).expect("export lines have a canonical form");
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
        Some(h) if h.format == "attenuo-audit-export-v1" => Err(bad(format!(
            "export format `attenuo-audit-export-v1` was written by an earlier attenuo whose \
             entry hashes were not RFC 8785 canonical; this version verifies only \
             `{EXPORT_FORMAT}` (export the log again with this version)"
        ))),
        Some(h) if h.format != EXPORT_FORMAT => Err(bad(format!(
            "unsupported export format `{}` (expected `{EXPORT_FORMAT}`)",
            h.format
        ))),
        Some(_) => Ok(()),
        None => Err(missing_header()),
    }
}

fn missing_header() -> AuditError {
    bad("the export has no header line; the header declares the range of entries the file holds")
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
    /// Entries whose seq lies outside the header's `from..=to`. Any makes the export fail:
    /// the file holds more than it declares (fuzzing F5).
    pub outside_range: u64,
    /// The export failed because entries after its last valid checkpoint
    /// ([`SignedVerifyReport::unsigned_tail`]) are not countersigned and
    /// [`VerifyOptions::allow_unsigned_tail`] was not set.
    pub unsigned_tail_rejected: bool,
}

/// How strict [`verify_export_with`] is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerifyOptions {
    /// Accept entries after the last valid checkpoint, which only the hash chain covers (an
    /// export taken while the log was ahead of its newest checkpoint). Off by default: such
    /// entries could have been appended by anyone who can write the file, and an export that
    /// verifies should vouch for every entry in it. The CLI's `--allow-unsigned-tail`.
    pub allow_unsigned_tail: bool,
}

/// Verify an export against the JWKS keys, offline, strictly: [`verify_export_with`] with the
/// default [`VerifyOptions`], so every entry must be countersigned.
pub fn verify_export(export: &Export, keys: &CheckpointKeys) -> Result<ExportReport, AuditError> {
    verify_export_with(export, keys, VerifyOptions::default())
}

/// Verify an export against the JWKS keys, offline.
///
/// Beyond [`verify_with_checkpoints`], the export is not ok when:
///
/// - it has no header (an error, not a report);
/// - its entries do not start at the header's `from` or stop short of its `to` (`truncated`);
/// - it holds an entry outside `from..=to` (`outside_range`);
/// - entries follow its last valid checkpoint (`unsigned_tail`) and
///   `options.allow_unsigned_tail` is not set (`unsigned_tail_rejected`).
///
/// A checkpoint outside the file's entry range is ignored by the chain check but still has
/// its signature verified.
pub fn verify_export_with(
    export: &Export,
    keys: &CheckpointKeys,
    options: VerifyOptions,
) -> Result<ExportReport, AuditError> {
    let header = export.header.as_ref().ok_or_else(missing_header)?;
    if header.filter.is_some() {
        return Err(bad(
            "the export is filtered (its header has a `filter`), so its hash chain has gaps \
             and nothing proves it is complete; verify an export taken without --kind, \
             --chain-id, --tool or --decision, then filter that",
        ));
    }
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
    // had entries cut off, and one with entries outside it holds more than it declares.
    let truncated = match (first_seq, last_seq) {
        (Some(f), Some(l)) => f != header.from || l < header.to,
        _ => header.to >= header.from && header.to > 0,
    };
    let outside_range = export
        .entries
        .iter()
        .filter(|e| e.seq < header.from || e.seq > header.to)
        .count() as u64;
    let unsigned_tail_rejected = report.unsigned_tail > 0 && !options.allow_unsigned_tail;
    if truncated || outside_range > 0 || unsigned_tail_rejected {
        report.ok = false;
    }
    Ok(ExportReport {
        report,
        first_seq,
        last_seq,
        from_genesis,
        truncated,
        outside_range,
        unsigned_tail_rejected,
    })
}
