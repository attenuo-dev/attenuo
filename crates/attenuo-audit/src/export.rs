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
//! A header may carry `anchor` (an [`Anchor`], audit retention) when the export starts right
//! after a prune of the log: `from` is the anchor's `through_seq + 1`. [`verify_export_with`]
//! then checks the anchor's signature and that the first entry is `through_seq + 1` with
//! `prev_hash` equal to `through_hash`, and reports `from_anchor: true`. A verifier that does
//! not know the member ignores it and verifies the file as a window, as before. Added without
//! a format bump, as `filter`'s members were.
//!
//! Format `attenuo-audit-export-v2` goes with entry hash construction
//! [`ENTRY_HASH_VERSION`](crate::ENTRY_HASH_VERSION) (RFC 8785, SR-20). A `v1` export, hashed
//! the earlier way, is refused when parsed.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::checkpoint::{
    verify_with_checkpoints, Anchor, BadAnchor, Checkpoint, CheckpointKeys, SignedVerifyReport,
    Start,
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
    /// Whether no member is set, so the filter matches every record.
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
    /// The export format version, [`EXPORT_FORMAT`] for a file this crate writes.
    pub format: String,
    /// First seq of the declared range `from..=to`.
    pub from: u64,
    /// Last seq of the declared range.
    pub to: u64,
    /// When the export was taken, RFC 3339 UTC.
    pub exported_at: String,
    /// Present when the export holds only the entries that match. Such a file has gaps in its
    /// hash chain by construction, so [`verify_export_with`] refuses it: verify an unfiltered
    /// export, then filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<RecordFilter>,
    /// The signed anchor of the prune the export starts after (`from` is its
    /// `through_seq + 1`), when the log was pruned and the export starts at its first
    /// retained entry. Absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<Anchor>,
}

impl ExportHeader {
    /// An unfiltered header for the range `from..=to`, in the current [`EXPORT_FORMAT`].
    pub fn new(from: u64, to: u64, exported_at: String) -> Self {
        Self {
            format: EXPORT_FORMAT.to_string(),
            from,
            to,
            exported_at,
            filter: None,
            anchor: None,
        }
    }

    /// The same header for an export that starts right after the prune `anchor` names.
    pub fn with_anchor(mut self, anchor: Option<Anchor>) -> Self {
        self.anchor = anchor;
        self
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
    /// The entries, in file order.
    pub entries: Vec<AuditEntry>,
    /// The checkpoints, in file order.
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
///
/// # Errors
///
/// [`AuditError::Export`] when a line (or the single JSON object) is not valid JSON or not a
/// header, entry or checkpoint, when a JSONL file has a second header or a line of unknown `type`,
/// when the JSON form's `entries` or `checkpoints` is not an array, when there is no header, or
/// when the header's `format` is not [`EXPORT_FORMAT`] (including the earlier
/// `attenuo-audit-export-v1`).
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
    /// Chain and checkpoint verification of the file's entries, flattened into the report.
    #[serde(flatten)]
    pub report: SignedVerifyReport,
    /// Seq of the first and last entry in the file, if any.
    pub first_seq: Option<u64>,
    /// Seq of the last entry in the file, if any.
    pub last_seq: Option<u64>,
    /// The file starts at seq 1 and its first `prev_hash` is the genesis value. When `false`
    /// the entries before `first_seq` are not covered by this file.
    pub from_genesis: bool,
    /// The header carries a prune anchor whose signature verifies, and the file starts right
    /// after it: its first entry is the anchor's `through_seq + 1` with `prev_hash` equal to
    /// its `through_hash`. The entries before were pruned from the log through the server.
    #[serde(default)]
    pub from_anchor: bool,
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
///
/// # Errors
///
/// As [`verify_export_with`].
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
///
/// # Errors
///
/// [`AuditError::Export`] when the export has no header, or when its header carries a `filter` (a
/// filtered export has gaps, so its chain cannot be verified). Everything else that is wrong with
/// the export is reported in the [`ExportReport`], not as an error.
pub fn verify_export_with(
    export: &Export,
    keys: &CheckpointKeys,
    options: VerifyOptions,
) -> Result<ExportReport, AuditError> {
    let header = export.header.as_ref().ok_or_else(missing_header)?;
    refuse_filtered(header)?;
    let mut facts = EntryFacts::default();
    for e in &export.entries {
        facts.observe(header, e);
    }
    verify_parts(
        header,
        facts,
        export.entries.iter().cloned().map(Ok),
        &export.checkpoints,
        keys,
        options,
    )
}

fn refuse_filtered(header: &ExportHeader) -> Result<(), AuditError> {
    if header.filter.is_some() {
        return Err(bad(
            "the export is filtered (its header has a `filter`), so its hash chain has gaps \
             and nothing proves it is complete; verify an export taken without --kind, \
             --chain-id, --tool or --decision, then filter that",
        ));
    }
    Ok(())
}

/// What [`verify_parts`] needs to know about the entries before it walks them: gathered in
/// one pass, so that a file can be checked without holding its entries in memory.
#[derive(Default)]
struct EntryFacts {
    /// Seq and `prev_hash` of the first entry.
    first: Option<(u64, String)>,
    /// Seq and entry hash of the last entry.
    last: Option<(u64, String)>,
    /// Entries outside the header's range.
    outside_range: u64,
    /// The first entry at the header anchor's `prune_seq`, if any.
    prune_entry: Option<AuditEntry>,
    /// Entries seen.
    count: u64,
}

impl EntryFacts {
    fn observe(&mut self, header: &ExportHeader, e: &AuditEntry) {
        if self.first.is_none() {
            self.first = Some((e.seq, e.prev_hash.clone()));
        }
        self.last = Some((e.seq, e.entry_hash.clone()));
        if e.seq < header.from || e.seq > header.to {
            self.outside_range += 1;
        }
        if self.prune_entry.is_none()
            && header.anchor.as_ref().is_some_and(|a| a.prune_seq == e.seq)
        {
            self.prune_entry = Some(e.clone());
        }
        self.count += 1;
    }
}

/// The checks of [`verify_export_with`], on a header, the facts of a first pass over the
/// entries, the entries again (in file order) and the checkpoints.
fn verify_parts<I>(
    header: &ExportHeader,
    facts: EntryFacts,
    entries: I,
    checkpoints: &[Checkpoint],
    keys: &CheckpointKeys,
    options: VerifyOptions,
) -> Result<ExportReport, AuditError>
where
    I: IntoIterator<Item = Result<AuditEntry, AuditError>>,
{
    let first_seq = facts.first.as_ref().map(|(s, _)| *s);
    let last_seq = facts.last.as_ref().map(|(s, _)| *s);
    let from_genesis = facts
        .first
        .as_ref()
        .is_some_and(|(s, prev)| *s == 1 && prev == crate::GENESIS_HASH);
    // An anchor in the header: checked here, and the walk starts where it says.
    let mut bad_anchors = Vec::new();
    let anchor = header.anchor.as_ref();
    if let Some(a) = anchor {
        let fail = |reason: String| BadAnchor {
            through_seq: a.through_seq,
            reason,
        };
        if let Err(reason) = keys.verify_anchor(a) {
            bad_anchors.push(fail(reason));
        } else if a.through_seq.checked_add(1) != Some(header.from) {
            bad_anchors.push(fail(format!(
                "the header's anchor is through seq {}, but the export starts at {}",
                a.through_seq, header.from
            )));
        } else if let Some(p) = &facts.prune_entry {
            if let Err(reason) = a.check_prune_record(p) {
                bad_anchors.push(fail(reason));
            }
        }
    }
    let anchored = anchor.filter(|_| bad_anchors.is_empty());
    let start = match anchored {
        Some(a) => Start::Anchored {
            seq: a.through_seq,
            hash: a.through_hash.clone(),
        },
        None if first_seq == Some(1) => Start::Genesis,
        None => Start::Window,
    };
    let from_anchor = anchored.is_some_and(|a| {
        facts.first.as_ref().is_some_and(|(s, prev)| {
            Some(*s) == a.through_seq.checked_add(1) && *prev == a.through_hash
        })
    });
    // Checkpoints beyond the window cannot be matched to an entry; only those inside count.
    let (lo, hi) = (first_seq.unwrap_or(0), last_seq.unwrap_or(0));
    let inside: Vec<Checkpoint> = checkpoints
        .iter()
        .filter(|c| c.seq >= lo && c.seq <= hi)
        .cloned()
        .collect();
    let mut report = verify_with_checkpoints(entries, &inside, keys, start)?;
    // Outside the window: still check the signature so a forged one is not silently dropped.
    for cp in checkpoints.iter().filter(|c| c.seq < lo || c.seq > hi) {
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
    report.checkpoints = checkpoints.len() as u64;
    report.anchors = u64::from(anchor.is_some());
    if !bad_anchors.is_empty() {
        report.ok = false;
    }
    report.bad_anchors = bad_anchors;
    // The header says which range was asked for; a file that starts later or ends earlier has
    // had entries cut off, and one with entries outside it holds more than it declares.
    let truncated = match (first_seq, last_seq) {
        (Some(f), Some(l)) => f != header.from || l < header.to,
        _ => header.to >= header.from && header.to > 0,
    };
    let outside_range = facts.outside_range;
    let unsigned_tail_rejected = report.unsigned_tail > 0 && !options.allow_unsigned_tail;
    if truncated || outside_range > 0 || unsigned_tail_rejected {
        report.ok = false;
    }
    Ok(ExportReport {
        report,
        first_seq,
        last_seq,
        from_genesis,
        from_anchor,
        truncated,
        outside_range,
        unsigned_tail_rejected,
    })
}

/// What [`verify_export_file`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportFileReport {
    /// The report [`verify_export_with`] gives for the same file.
    pub report: ExportReport,
    /// The file's header.
    pub header: ExportHeader,
    /// SHA-256 of the file's bytes, lower-case hex.
    pub sha256: String,
    /// Entry hash of the file's last entry, if any.
    pub last_entry_hash: Option<String>,
    /// Entries in the file.
    pub entries: u64,
}

/// [`verify_export_with`] on a JSON Lines export file, without loading its entries into
/// memory: one pass reads the header and the checkpoints, takes the SHA-256 of the bytes and
/// notes what the checks need of the entries, and a second pass walks the entries. Only the
/// checkpoints are held. The header must be the first line (as every export this crate and
/// the server write has it); the single-object JSON form is not read here.
///
/// # Errors
///
/// [`AuditError::Storage`] when the file cannot be read; [`AuditError::Export`] when a line
/// does not parse (as for [`parse_export`]), the first line is not a header, or the header
/// carries a `filter`.
pub fn verify_export_file(
    path: &std::path::Path,
    keys: &CheckpointKeys,
    options: VerifyOptions,
) -> Result<ExportFileReport, AuditError> {
    use sha2::{Digest, Sha256};
    use std::io::BufRead;

    let io = |e: std::io::Error| AuditError::Storage(format!("reading {}: {e}", path.display()));
    let open = || {
        std::fs::File::open(path)
            .map(|f| std::io::BufReader::with_capacity(1 << 16, f))
            .map_err(io)
    };
    // Pass 1: the header, the checkpoints, the digest and the facts.
    let mut reader = open()?;
    let mut hasher = Sha256::new();
    let mut line = String::new();
    let mut n = 0usize;
    let mut header: Option<ExportHeader> = None;
    let mut checkpoints = Vec::new();
    let mut facts = EntryFacts::default();
    loop {
        line.clear();
        if reader.read_line(&mut line).map_err(io)? == 0 {
            break;
        }
        n += 1;
        hasher.update(line.as_bytes());
        if line.trim().is_empty() {
            continue;
        }
        let at = |e: serde_json::Error| bad(format!("line {n}: {e}"));
        let v: Value = serde_json::from_str(&line).map_err(at)?;
        match (v.get("type").and_then(Value::as_str), &header) {
            (Some("header"), None) => header = Some(serde_json::from_value(v).map_err(at)?),
            (Some("header"), Some(_)) => return Err(bad(format!("line {n}: second header"))),
            (_, None) => {
                return Err(bad(format!(
                    "line {n}: the first line of the file is not its header"
                )))
            }
            (Some("entry"), Some(h)) => {
                let e: AuditEntry = serde_json::from_value(v).map_err(at)?;
                facts.observe(h, &e);
            }
            (Some("checkpoint"), Some(_)) => {
                checkpoints.push(serde_json::from_value(v).map_err(at)?);
            }
            (other, Some(_)) => return Err(bad(format!("line {n}: unknown line type {other:?}"))),
        }
    }
    let export = Export {
        header,
        entries: Vec::new(),
        checkpoints: Vec::new(),
    };
    check_header(&export)?;
    let header = export.header.ok_or_else(missing_header)?;
    refuse_filtered(&header)?;
    let sha256 = hex::encode(hasher.finalize());
    let last_entry_hash = facts.last.as_ref().map(|(_, h)| h.clone());
    let entries = facts.count;
    // Pass 2: the entries, one at a time.
    let mut reader = open()?;
    let mut n = 0usize;
    let walk = std::iter::from_fn(move || loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => return None,
            Ok(_) => {}
            Err(e) => return Some(Err(io(e))),
        }
        n += 1;
        if line.trim().is_empty() {
            continue;
        }
        // Pass 1 parsed every line; the header and the checkpoints are passed over.
        let v: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => return Some(Err(bad(format!("line {n}: {e}")))),
        };
        if v.get("type").and_then(Value::as_str) == Some("entry") {
            return Some(serde_json::from_value(v).map_err(|e| bad(format!("line {n}: {e}"))));
        }
    });
    let report = verify_parts(&header, facts, walk, &checkpoints, keys, options)?;
    Ok(ExportFileReport {
        report,
        header,
        sha256,
        last_entry_hash,
        entries,
    })
}

/// Why two files given in a row do not form one log ([`link_exports`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkProblem {
    /// Index of the earlier file, from 0, in the order given.
    pub earlier: usize,
    /// Index of the later file (`earlier + 1`).
    pub later: usize,
    /// What does not link.
    pub reason: String,
}

/// Check that `exports`, in the order given (oldest first: the archives of the prunes, then
/// the retained export), form one log: for each file and the next,
///
/// - both hold entries;
/// - the later file's first seq is one above the earlier file's last;
/// - the later file's first `prev_hash` is the earlier file's last entry hash;
/// - the earlier file has a checkpoint at its last seq that names that hash (an archive ends
///   at the checkpoint its prune was made at);
/// - an anchor in the later file's header names the earlier file's end (`through_seq` and
///   `through_hash`).
///
/// It checks only how the files join. Verify each one with [`verify_export_with`] as well: a
/// file whose own chain or checkpoints fail is reported there, at its seq.
pub fn link_exports(exports: &[&Export]) -> Vec<LinkProblem> {
    let mut out = Vec::new();
    for (i, pair) in exports.windows(2).enumerate() {
        let (a, b) = (pair[0], pair[1]);
        let mut fail = |reason: String| {
            out.push(LinkProblem {
                earlier: i,
                later: i + 1,
                reason,
            });
        };
        let (Some(last), Some(first)) = (a.entries.last(), b.entries.first()) else {
            fail(if a.entries.is_empty() {
                "the earlier file holds no entries".to_string()
            } else {
                "the later file holds no entries".to_string()
            });
            continue;
        };
        if last.seq.checked_add(1) != Some(first.seq) {
            fail(format!(
                "the seqs are not contiguous: the earlier file ends at seq {}, the later one \
                 starts at seq {}",
                last.seq, first.seq
            ));
        } else if first.prev_hash != last.entry_hash {
            fail(format!(
                "the later file's first entry (seq {}) does not link to the earlier file's last \
                 (its prev_hash is not the entry hash at seq {})",
                first.seq, last.seq
            ));
        }
        match a.checkpoints.iter().find(|c| c.seq == last.seq) {
            Some(c) if c.head_hash == last.entry_hash => {}
            Some(_) => fail(format!(
                "the earlier file's checkpoint at its last seq {} names another hash than its \
                 entry",
                last.seq
            )),
            None => fail(format!(
                "the earlier file does not end at a checkpoint: none at its last seq {}",
                last.seq
            )),
        }
        if let Some(an) = b.header.as_ref().and_then(|h| h.anchor.as_ref()) {
            if an.through_seq != last.seq || an.through_hash != last.entry_hash {
                fail(format!(
                    "the later file's header anchor is through seq {}, not the earlier file's \
                     end at seq {} and its hash",
                    an.through_seq, last.seq
                ));
            }
        }
    }
    out
}
