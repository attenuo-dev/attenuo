//! Checkpoints shipped off the host (SR-21), and the cross-check of an export against them.
//!
//! A signed checkpoint proves the log prefix `1..=seq` hashed to `head_hash`, but it is signed
//! with the server's own key. An attacker who holds the host and that key can rewrite the
//! SQLite log and sign fresh checkpoints over the rewritten history; the export then verifies
//! against the JWKS. What they cannot change is a copy of the original checkpoint that already
//! left the host. The server's checkpoint sink (`[audit.sink]`) sends every checkpoint it
//! creates to a webhook, an append-only file or an S3 bucket as a [`ShippedCheckpoint`], and
//! [`cross_check`] compares an export with those copies: a checkpoint with the same `seq` but
//! a different `head_hash`, `at`, `kid` or `signature` was signed again after it was shipped.
//!
//! A shipped line is RFC 8785 canonical JSON:
//!
//! ```text
//! {"checkpoint":{"at":"..","head_hash":"..","kid":"..","seq":100,"signature":".."},
//!  "checkpoint_sha256":"..","format":"onbehalf-shipped-checkpoint-v1","kid":"..",
//!  "public_url":"https://onbehalf.example","signature":".."}
//! ```
//!
//! (one line in the file; wrapped here). `checkpoint_sha256` is the hex SHA-256 of the
//! canonical JSON of `checkpoint`, so a receiver can index and deduplicate on it; `kid` and
//! `signature` repeat the checkpoint's own fields for receivers that do not parse it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::checkpoint::{Checkpoint, CheckpointKeys};
use crate::error::AuditError;
use crate::export::Export;

/// Value of a shipped checkpoint's `format` field.
pub const SHIPPED_FORMAT: &str = "onbehalf-shipped-checkpoint-v1";

/// One checkpoint as the sink sends it: the webhook body, one line of the file sink, one S3
/// object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShippedCheckpoint {
    pub format: String,
    pub checkpoint: Checkpoint,
    /// The checkpoint's `kid`, repeated.
    pub kid: String,
    /// The checkpoint's `signature`, repeated.
    pub signature: String,
    /// `[server] public_url` of the server that signed it, when set: which log this is.
    #[serde(default)]
    pub public_url: Option<String>,
    /// Hex SHA-256 of the RFC 8785 canonical JSON of `checkpoint`.
    pub checkpoint_sha256: String,
}

/// Hex SHA-256 of the canonical JSON of `cp` (all five fields).
pub fn checkpoint_sha256(cp: &Checkpoint) -> String {
    let bytes = onbehalf_core::jcs::to_vec(cp).expect("checkpoints have a canonical form");
    hex::encode(Sha256::digest(bytes))
}

impl ShippedCheckpoint {
    pub fn new(cp: &Checkpoint, public_url: Option<String>) -> Self {
        Self {
            format: SHIPPED_FORMAT.to_string(),
            kid: cp.kid.clone(),
            signature: cp.signature.clone(),
            public_url,
            checkpoint_sha256: checkpoint_sha256(cp),
            checkpoint: cp.clone(),
        }
    }

    /// The canonical JSON bytes (the webhook body, the S3 object).
    pub fn to_canonical_json(&self) -> Vec<u8> {
        onbehalf_core::jcs::to_vec(self).expect("shipped checkpoints have a canonical form")
    }

    /// One JSONL line, newline included (the file sink).
    pub fn to_line(&self) -> String {
        let mut s = String::from_utf8(self.to_canonical_json()).expect("JSON is UTF-8");
        s.push('\n');
        s
    }

    /// Why the envelope disagrees with its own checkpoint, if it does.
    pub fn inconsistency(&self) -> Option<String> {
        if self.format != SHIPPED_FORMAT {
            return Some(format!("unsupported format `{}`", self.format));
        }
        if self.kid != self.checkpoint.kid || self.signature != self.checkpoint.signature {
            return Some("`kid` or `signature` differs from the checkpoint's own".into());
        }
        if self.checkpoint_sha256 != checkpoint_sha256(&self.checkpoint) {
            return Some("`checkpoint_sha256` does not match the checkpoint".into());
        }
        None
    }
}

/// One line of a shipped-checkpoint file: the sink's envelope, or a bare checkpoint (an export's
/// `checkpoint` line, or `GET /admin/audit/checkpoint` saved by an operator's own job).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShippedLine {
    /// 1-based line number in the file.
    pub line: usize,
    pub checkpoint: Checkpoint,
    /// Set when the line was an envelope that does not match its own checkpoint.
    pub inconsistency: Option<String>,
}

/// Parse a JSONL file of shipped checkpoints. Blank lines are skipped; anything that is
/// neither an envelope nor a checkpoint is an error.
pub fn parse_shipped(text: &str) -> Result<Vec<ShippedLine>, AuditError> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let at =
            |e: String| AuditError::Export(format!("shipped checkpoints, line {}: {e}", n + 1));
        let mut v: Value = serde_json::from_str(line).map_err(|e| at(e.to_string()))?;
        let parsed = if v.get("checkpoint").is_some() {
            let s: ShippedCheckpoint = serde_json::from_value(v).map_err(|e| at(e.to_string()))?;
            ShippedLine {
                line: n + 1,
                inconsistency: s.inconsistency(),
                checkpoint: s.checkpoint,
            }
        } else {
            if let Some(obj) = v.as_object_mut() {
                match obj.remove("type") {
                    None => {}
                    Some(Value::String(t)) if t == "checkpoint" => {}
                    Some(t) => return Err(at(format!("not a checkpoint line (type {t})"))),
                }
            }
            ShippedLine {
                line: n + 1,
                checkpoint: serde_json::from_value(v).map_err(|e| at(e.to_string()))?,
                inconsistency: None,
            }
        };
        out.push(parsed);
    }
    Ok(out)
}

/// A shipped checkpoint the export disagrees with, or one that is unusable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShippedMismatch {
    pub seq: u64,
    /// Line of the shipped file.
    pub line: usize,
    pub reason: String,
}

/// Result of [`cross_check`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossCheckReport {
    /// Lines in the shipped file.
    pub shipped: u64,
    /// Shipped checkpoints whose seq lies in the export header's `from..=to` (checked).
    pub in_range: u64,
    /// Of those, the ones the export agrees with.
    pub matched: u64,
    /// Shipped checkpoints past the export's range: not checked. If the export was taken up
    /// to the head of the log, these say the log is shorter than what was shipped.
    pub beyond_range: u64,
    /// Highest seq in the shipped file.
    pub last_shipped_seq: Option<u64>,
    pub mismatches: Vec<ShippedMismatch>,
    /// No mismatches.
    pub ok: bool,
}

/// Compare `export` with checkpoints shipped off the host.
///
/// For each shipped checkpoint whose seq is inside the export's declared range:
///
/// - it must verify against `keys` (a shipped copy that does not verify is reported, since the
///   check below would otherwise trust a forgery);
/// - the export must hold a checkpoint at that seq, identical in every field: a different one
///   was **signed again after shipping**; none at all means it was deleted;
/// - the export's entry at that seq must hash to the shipped `head_hash`.
///
/// Two different shipped checkpoints for the same seq are reported too (the server signed
/// that seq twice, which it never does on its own), as is an envelope whose `kid`,
/// `signature` or `checkpoint_sha256` disagree with its checkpoint. This does not replace
/// [`verify_export_with`](crate::verify_export_with): run both.
pub fn cross_check(
    export: &Export,
    shipped: &[ShippedLine],
    keys: &CheckpointKeys,
) -> CrossCheckReport {
    let (from, to) = export.header.as_ref().map_or((1, 0), |h| (h.from, h.to));
    let exported: BTreeMap<u64, &Checkpoint> =
        export.checkpoints.iter().map(|c| (c.seq, c)).collect();
    let entry_hash: BTreeMap<u64, &str> = export
        .entries
        .iter()
        .map(|e| (e.seq, e.entry_hash.as_str()))
        .collect();
    let mut first_by_seq: BTreeMap<u64, &ShippedLine> = BTreeMap::new();
    let mut mismatches = Vec::new();
    let (mut in_range, mut matched, mut beyond) = (0u64, 0u64, 0u64);
    for s in shipped {
        let cp = &s.checkpoint;
        let mut fail = |reason: String| {
            mismatches.push(ShippedMismatch {
                seq: cp.seq,
                line: s.line,
                reason,
            })
        };
        if let Some(why) = &s.inconsistency {
            fail(format!("shipped envelope is inconsistent: {why}"));
            continue;
        }
        match first_by_seq.get(&cp.seq) {
            Some(prev) if prev.checkpoint != *cp => {
                fail(format!(
                    "the sink holds two different checkpoints for this seq (lines {} and {}): \
                     the seq was signed again after the first was shipped",
                    prev.line, s.line
                ));
                continue;
            }
            Some(_) => {} // a retried delivery: same content
            None => {
                first_by_seq.insert(cp.seq, s);
            }
        }
        if cp.seq > to {
            beyond += 1;
            continue;
        }
        if cp.seq < from && !(cp.seq == 0 && from <= 1) {
            continue;
        }
        in_range += 1;
        if let Err(reason) = keys.verify(cp) {
            fail(format!("shipped checkpoint does not verify: {reason}"));
            continue;
        }
        let mut problems = Vec::new();
        match exported.get(&cp.seq) {
            None => problems.push(
                "the export has no checkpoint at this seq (deleted after shipping)".to_string(),
            ),
            Some(e) if *e != cp => {
                let mut diff = Vec::new();
                if e.head_hash != cp.head_hash {
                    diff.push("head_hash");
                }
                if e.signature != cp.signature {
                    diff.push("signature");
                }
                if e.at != cp.at {
                    diff.push("at");
                }
                if e.kid != cp.kid {
                    diff.push("kid");
                }
                problems.push(format!(
                    "RE-SIGNED after shipping: the export's checkpoint at this seq differs in {}",
                    diff.join(", ")
                ));
            }
            Some(_) => {}
        }
        if cp.seq > 0 {
            match entry_hash.get(&cp.seq) {
                Some(h) if *h != cp.head_hash => problems.push(
                    "the export's entry at this seq does not hash to the shipped head_hash \
                     (history rewritten after shipping)"
                        .to_string(),
                ),
                Some(_) => {}
                None => problems.push("the export has no entry at this seq".to_string()),
            }
        }
        if problems.is_empty() {
            matched += 1;
        } else {
            fail(problems.join("; "));
        }
    }
    CrossCheckReport {
        shipped: shipped.len() as u64,
        in_range,
        matched,
        beyond_range: beyond,
        last_shipped_seq: shipped.iter().map(|s| s.checkpoint.seq).max(),
        ok: mismatches.is_empty(),
        mismatches,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp(seq: u64) -> Checkpoint {
        Checkpoint {
            seq,
            head_hash: format!("h{seq}"),
            at: "2026-10-23T00:00:00Z".into(),
            kid: "k1".into(),
            signature: "sig".into(),
        }
    }

    #[test]
    fn envelope_round_trips_and_is_canonical() {
        let s = ShippedCheckpoint::new(&cp(7), Some("https://ob.example".into()));
        let line = s.to_line();
        assert!(line.starts_with("{\"checkpoint\":{\"at\":"));
        assert!(line.ends_with("}\n"));
        let parsed = parse_shipped(&line).unwrap();
        assert_eq!(parsed[0].checkpoint, cp(7));
        assert_eq!(parsed[0].inconsistency, None);
        assert_eq!(s.checkpoint_sha256.len(), 64);
    }

    #[test]
    fn tampered_envelope_and_bare_lines() {
        let mut s = ShippedCheckpoint::new(&cp(7), None);
        s.checkpoint.head_hash = "other".into();
        let parsed = parse_shipped(&s.to_line()).unwrap();
        assert!(parsed[0]
            .inconsistency
            .as_deref()
            .unwrap()
            .contains("checkpoint_sha256"));

        let bare = "{\"at\":\"2026-10-23T00:00:00Z\",\"head_hash\":\"h1\",\"kid\":\"k1\",\"seq\":1,\"signature\":\"sig\",\"type\":\"checkpoint\"}\n\n";
        assert_eq!(parse_shipped(bare).unwrap()[0].checkpoint, cp(1));
        assert!(parse_shipped("{\"type\":\"entry\",\"seq\":1}").is_err());
        assert!(parse_shipped("not json").is_err());
    }
}
