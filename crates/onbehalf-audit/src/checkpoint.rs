//! Signed checkpoints: the issuer countersigns `(seq, head_hash)` so truncation or a rewritten
//! history can be detected by anyone holding the JWKS, without trusting the host that stores
//! the log.
//!
//! A checkpoint is `{seq, head_hash, at, kid, signature}`. The signature is Ed25519 by the
//! issuer key `kid`, over the JSON array `[seq, head_hash, at, kid]` framed with the context
//! string [`CHECKPOINT_CONTEXT`] (see `onbehalf_token::detached`), so it cannot be replayed as
//! a token or any other signed object.
//!
//! What a valid checkpoint proves: the chain prefix `1..=seq` hashed to `head_hash` when the
//! issuer signed it. Rewriting any entry at or before `seq`, even with every later hash
//! recomputed, changes the hash at `seq` and no longer matches. Entries after the last
//! checkpoint are covered by the hash chain only until the next one is written
//! ([`SignedVerifyReport::unsigned_tail`] says how many).

use std::collections::{BTreeMap, HashMap};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use onbehalf_token::verify_detached;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::AuditError;
use crate::log::{walk_entries, AuditEntry, VerifyReport, GENESIS_HASH};

/// Domain-separation string for checkpoint signatures.
pub const CHECKPOINT_CONTEXT: &str = "onbehalf-checkpoint-v1";

/// A signed `(seq, head_hash)` pair. An empty log checkpoints as `(0, GENESIS_HASH)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub seq: u64,
    pub head_hash: String,
    /// RFC 3339 UTC, whole seconds.
    pub at: String,
    /// Key id (JWKS `kid`) of the signing key.
    pub kid: String,
    /// base64url Ed25519 signature.
    pub signature: String,
}

impl Checkpoint {
    /// The exact bytes the signature covers (before context framing).
    pub fn signing_payload(&self) -> Vec<u8> {
        serde_json::to_vec(&(self.seq, &self.head_hash, &self.at, &self.kid))
            .expect("checkpoint fields serialize")
    }

    /// Sign `(seq, head_hash)` at `now` with `signer`.
    pub fn sign(
        signer: &onbehalf_token::DetachedSigner,
        seq: u64,
        head_hash: &str,
        now: OffsetDateTime,
    ) -> Result<Self, AuditError> {
        let at = now
            .to_offset(time::UtcOffset::UTC)
            .replace_nanosecond(0)
            .unwrap_or(now)
            .format(&Rfc3339)?;
        let mut cp = Self {
            seq,
            head_hash: head_hash.to_string(),
            at,
            kid: signer.kid(),
            signature: String::new(),
        };
        cp.signature = signer.sign(CHECKPOINT_CONTEXT, &cp.signing_payload());
        Ok(cp)
    }
}

/// Public keys that may have signed checkpoints, by `kid`: the JWKS the server publishes, so
/// keys retired in a rotation keep verifying old checkpoints for as long as they are listed.
#[derive(Debug, Clone, Default)]
pub struct CheckpointKeys {
    keys: BTreeMap<String, Vec<u8>>,
}

impl CheckpointKeys {
    /// From a JWKS document (`{"keys": [{"kty":"OKP","crv":"Ed25519","kid":..,"x":..}]}`).
    /// Entries that are not Ed25519 OKP keys are skipped.
    pub fn from_jwks(jwks: &Value) -> Result<Self, AuditError> {
        let list = jwks
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| AuditError::Jwks("missing `keys` array".into()))?;
        let mut keys = BTreeMap::new();
        for k in list {
            let field = |n: &str| k.get(n).and_then(Value::as_str);
            if field("kty") != Some("OKP") || field("crv") != Some("Ed25519") {
                continue;
            }
            let (Some(kid), Some(x)) = (field("kid"), field("x")) else {
                continue;
            };
            let raw = URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|e| AuditError::Jwks(format!("key `{kid}`: bad `x`: {e}")))?;
            if raw.len() != 32 {
                return Err(AuditError::Jwks(format!(
                    "key `{kid}`: Ed25519 key must be 32 bytes, got {}",
                    raw.len()
                )));
            }
            keys.insert(kid.to_string(), raw);
        }
        Ok(Self { keys })
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// `Ok` when `cp` carries a valid signature by a known key.
    pub fn verify(&self, cp: &Checkpoint) -> Result<(), String> {
        let key = self
            .keys
            .get(&cp.kid)
            .ok_or_else(|| format!("unknown signing key `{}`", cp.kid))?;
        if verify_detached(
            key,
            CHECKPOINT_CONTEXT,
            &cp.signing_payload(),
            &cp.signature,
        ) {
            Ok(())
        } else {
            Err("signature does not verify".to_string())
        }
    }
}

/// A checkpoint that failed verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BadCheckpoint {
    pub seq: u64,
    pub reason: String,
}

/// Chain verification plus checkpoint verification. The first three fields are those of
/// [`VerifyReport`], so existing consumers of `/admin/audit/verify` keep working.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedVerifyReport {
    /// Entries examined.
    pub entries: u64,
    /// The chain is intact and every checkpoint verified.
    pub ok: bool,
    pub first_bad_seq: Option<u64>,
    /// Checkpoints examined.
    pub checkpoints: u64,
    /// Highest seq covered by a checkpoint whose signature and head hash both check out.
    pub last_signed_seq: Option<u64>,
    /// Entries after `last_signed_seq` (all of them when there is none): covered by the hash
    /// chain only, not yet countersigned.
    pub unsigned_tail: u64,
    pub bad_checkpoints: Vec<BadCheckpoint>,
}

impl SignedVerifyReport {
    /// The plain chain result, without checkpoint fields.
    pub fn chain(&self) -> VerifyReport {
        VerifyReport {
            entries: self.entries,
            ok: self.first_bad_seq.is_none(),
            first_bad_seq: self.first_bad_seq,
        }
    }
}

/// Where a verified run of entries starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Start {
    /// The run must begin at seq 1 with the genesis `prev_hash` (a whole log).
    Genesis,
    /// The run may begin anywhere (an export of `from..=to`); the first entry's `prev_hash`
    /// is taken as given and contiguity is checked from there.
    Window,
}

/// Walk `entries` and check each checkpoint in `checkpoints` against them.
///
/// Only checkpoints inside the walked range are meaningful; callers exporting a window pass
/// just those. A checkpoint beyond the last entry is reported as `bad` (truncation) when the
/// chain itself is intact.
pub fn verify_with_checkpoints<I>(
    entries: I,
    checkpoints: &[Checkpoint],
    keys: &CheckpointKeys,
    start: Start,
) -> Result<SignedVerifyReport, AuditError>
where
    I: IntoIterator<Item = Result<AuditEntry, AuditError>>,
{
    let wanted: HashMap<u64, ()> = checkpoints.iter().map(|c| (c.seq, ())).collect();
    let mut hashes: HashMap<u64, String> = HashMap::new();
    let mut last_seq = None;
    let mut ok_count = 0u64;
    let chain = walk_entries(entries, start == Start::Genesis, |e| {
        last_seq = Some(e.seq);
        ok_count += 1;
        if wanted.contains_key(&e.seq) {
            hashes.insert(e.seq, e.entry_hash.clone());
        }
    })?;

    let mut ordered: Vec<&Checkpoint> = checkpoints.iter().collect();
    ordered.sort_by_key(|c| c.seq);
    let mut bad = Vec::new();
    let mut last_signed: Option<u64> = None;
    for cp in &ordered {
        let mut fail = |reason: String| {
            bad.push(BadCheckpoint {
                seq: cp.seq,
                reason,
            })
        };
        if let Err(reason) = keys.verify(cp) {
            fail(reason);
            continue;
        }
        let actual = if cp.seq == 0 {
            (start == Start::Genesis).then(|| GENESIS_HASH.to_string())
        } else {
            hashes.get(&cp.seq).cloned()
        };
        match actual {
            Some(h) if h == cp.head_hash => {
                last_signed = Some(last_signed.map_or(cp.seq, |s| s.max(cp.seq)));
            }
            Some(_) => fail("head hash differs from the log at that seq".into()),
            // Past the break the entry cannot be trusted, and the chain failure is already
            // reported; only a clean chain that is shorter than the checkpoint is truncation.
            None if chain.ok && last_seq.is_none_or(|l| cp.seq > l) => {
                fail("log ends before this checkpoint (truncated)".into())
            }
            None => {}
        }
    }
    let unsigned_tail = match (last_seq, last_signed) {
        (Some(l), Some(s)) => l.saturating_sub(s),
        (Some(_), None) => ok_count,
        (None, _) => 0,
    };
    Ok(SignedVerifyReport {
        entries: chain.entries,
        ok: chain.ok && bad.is_empty(),
        first_bad_seq: chain.first_bad_seq,
        checkpoints: checkpoints.len() as u64,
        last_signed_seq: last_signed,
        unsigned_tail,
        bad_checkpoints: bad,
    })
}
