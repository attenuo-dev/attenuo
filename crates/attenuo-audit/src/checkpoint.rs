//! Signed checkpoints: the issuer countersigns `(seq, head_hash)` so truncation or a rewritten
//! history can be detected by anyone holding the JWKS, without trusting the host that stores
//! the log.
//!
//! A checkpoint is `{seq, head_hash, at, kid, signature}`. The signature is Ed25519 by the
//! issuer key `kid`, over the RFC 8785 canonical JSON array `[seq, head_hash, at, kid]`
//! ([`Checkpoint::signing_payload`]) framed with the context
//! string [`CHECKPOINT_CONTEXT`] (see `attenuo_token::detached`), so it cannot be replayed as
//! a token or any other signed object.
//!
//! What a valid checkpoint proves: the chain prefix `1..=seq` hashed to `head_hash` when the
//! issuer signed it. Rewriting any entry at or before `seq`, even with every later hash
//! recomputed, changes the hash at `seq` and no longer matches. Entries after the last
//! checkpoint are covered by the hash chain only until the next one is written
//! ([`SignedVerifyReport::unsigned_tail`] says how many).

use std::collections::{BTreeMap, HashMap};

use attenuo_token::verify_detached;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::AuditError;
use crate::log::{walk_entries, AuditEntry, VerifyReport, GENESIS_HASH};

/// Domain-separation string for checkpoint signatures.
pub const CHECKPOINT_CONTEXT: &str = "attenuo-checkpoint-v1";

/// A signed `(seq, head_hash)` pair. An empty log checkpoints as `(0, GENESIS_HASH)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Sequence number of the last entry the checkpoint covers.
    pub seq: u64,
    /// `entry_hash` of the entry at `seq` (the genesis hash for an empty log).
    pub head_hash: String,
    /// RFC 3339 UTC, whole seconds.
    pub at: String,
    /// Key id (JWKS `kid`) of the signing key.
    pub kid: String,
    /// base64url Ed25519 signature.
    pub signature: String,
}

impl Checkpoint {
    /// The exact bytes the signature covers (before context framing): the RFC 8785 canonical
    /// JSON of `[seq, head_hash, at, kid]`.
    ///
    /// For an integer and three strings that is the same text `serde_json` wrote before SR-20
    /// (both escape exactly `"`, `\` and the control characters, the same way), so the
    /// signature construction, and [`CHECKPOINT_CONTEXT`], did not change; what changed is the
    /// entry hash a checkpoint's `head_hash` names
    /// ([`ENTRY_HASH_VERSION`](crate::ENTRY_HASH_VERSION)).
    pub fn signing_payload(&self) -> Vec<u8> {
        attenuo_core::jcs::to_vec(&(self.seq, &self.head_hash, &self.at, &self.kid))
            .expect("checkpoint fields have a canonical JSON form")
    }

    /// Sign `(seq, head_hash)` at `now` with `signer`.
    ///
    /// # Errors
    ///
    /// [`AuditError::TimeFormat`] when `now` cannot be written as RFC 3339 (a year outside
    /// 0000..=9999).
    pub fn sign(
        signer: &attenuo_token::DetachedSigner,
        seq: u64,
        head_hash: &str,
        now: OffsetDateTime,
    ) -> Result<Self, AuditError> {
        let mut cp = Self {
            seq,
            head_hash: head_hash.to_string(),
            at: whole_seconds_utc(now)?,
            kid: signer.kid(),
            signature: String::new(),
        };
        cp.signature = signer.sign(CHECKPOINT_CONTEXT, &cp.signing_payload());
        Ok(cp)
    }
}

/// Domain-separation string for audit anchor signatures ([`Anchor`]).
pub const ANCHOR_CONTEXT: &str = "attenuo-audit-anchor-v1";

/// The `tool` of the audit record a prune appends (kind `admin`, server `attenuo`).
pub const PRUNE_TOOL: &str = "admin.audit.prune";

/// A signed statement that the log now starts at `through_seq + 1`: the entries up to
/// `through_seq` were pruned through the server, by the record at `prune_seq`.
///
/// The signature is Ed25519 by the issuer key `kid` over the RFC 8785 canonical JSON array
/// `[through_seq, through_hash, prune_seq, prune_entry_hash, previous_through_seq,
/// archive_sha256, at, kid]` ([`Anchor::signing_payload`]) framed with [`ANCHOR_CONTEXT`], so
/// it can be neither replayed as a checkpoint nor made from one. A checkpoint at `through_seq`
/// is already in the file for anyone to copy; only the anchor's signature tells a prune made
/// through the server from a prefix deleted by someone who can write the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    /// The last seq pruned (B). A signed checkpoint at this seq names `through_hash`.
    pub through_seq: u64,
    /// The entry hash at `through_seq`: the `prev_hash` of the first retained entry.
    pub through_hash: String,
    /// The seq of the prune's own audit record (tool [`PRUNE_TOOL`]).
    pub prune_seq: u64,
    /// The entry hash of that record, which binds the anchor to it.
    pub prune_entry_hash: String,
    /// `through_seq` of the prune before this one, if any: a series of prunes links.
    pub previous_through_seq: Option<u64>,
    /// The operator's statement of the archive's SHA-256 (hex), if given. The server never
    /// sees the archive.
    pub archive_sha256: Option<String>,
    /// RFC 3339 UTC, whole seconds.
    pub at: String,
    /// Key id (JWKS `kid`) of the signing key.
    pub kid: String,
    /// base64url Ed25519 signature.
    pub signature: String,
}

impl Anchor {
    /// The exact bytes the signature covers (before context framing): the RFC 8785 canonical
    /// JSON of `[through_seq, through_hash, prune_seq, prune_entry_hash, previous_through_seq,
    /// archive_sha256, at, kid]`, a missing value as `null`.
    pub fn signing_payload(&self) -> Vec<u8> {
        attenuo_core::jcs::to_vec(&(
            self.through_seq,
            &self.through_hash,
            self.prune_seq,
            &self.prune_entry_hash,
            self.previous_through_seq,
            &self.archive_sha256,
            &self.at,
            &self.kid,
        ))
        .expect("anchor fields have a canonical JSON form")
    }

    /// The arguments the prune record holds the digest of (its `arguments_digest` is
    /// `sha256_json` of this): `{through_seq, through_hash, previous_through_seq,
    /// archive_sha256}`.
    pub fn prune_arguments(
        through_seq: u64,
        through_hash: &str,
        previous_through_seq: Option<u64>,
        archive_sha256: Option<&str>,
    ) -> Value {
        serde_json::json!({
            "through_seq": through_seq,
            "through_hash": through_hash,
            "previous_through_seq": previous_through_seq,
            "archive_sha256": archive_sha256,
        })
    }

    /// The `arguments_digest` a genuine prune record of this anchor carries.
    pub fn prune_arguments_digest(&self) -> String {
        attenuo_core::digest::sha256_json(&Self::prune_arguments(
            self.through_seq,
            &self.through_hash,
            self.previous_through_seq,
            self.archive_sha256.as_deref(),
        ))
    }

    /// Sign an anchor at `now` with `signer`.
    ///
    /// # Errors
    ///
    /// [`AuditError::TimeFormat`] when `now` cannot be written as RFC 3339 (a year outside
    /// 0000..=9999).
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        signer: &attenuo_token::DetachedSigner,
        through_seq: u64,
        through_hash: &str,
        prune_seq: u64,
        prune_entry_hash: &str,
        previous_through_seq: Option<u64>,
        archive_sha256: Option<String>,
        now: OffsetDateTime,
    ) -> Result<Self, AuditError> {
        let mut a = Self {
            through_seq,
            through_hash: through_hash.to_string(),
            prune_seq,
            prune_entry_hash: prune_entry_hash.to_string(),
            previous_through_seq,
            archive_sha256,
            at: whole_seconds_utc(now)?,
            kid: signer.kid(),
            signature: String::new(),
        };
        a.signature = signer.sign(ANCHOR_CONTEXT, &a.signing_payload());
        Ok(a)
    }

    /// Check an entry that claims to be this anchor's prune record: at `prune_seq`, hashing
    /// to `prune_entry_hash`, an `admin` record of [`PRUNE_TOOL`] by the server, allowed, whose
    /// `arguments_digest` is that of the anchor's values.
    ///
    /// # Errors
    ///
    /// What does not match, as text for [`BadAnchor::reason`].
    pub fn check_prune_record(&self, e: &AuditEntry) -> Result<(), String> {
        let r = &e.record;
        if e.seq != self.prune_seq || e.entry_hash != self.prune_entry_hash {
            return Err("the entry at prune_seq does not hash to prune_entry_hash".into());
        }
        if r.kind != attenuo_core::RecordKind::Admin
            || r.tool != PRUNE_TOOL
            || r.server != "attenuo"
            || !r.decision.is_allow()
        {
            return Err(format!(
                "the entry at prune_seq is not an allowed `{PRUNE_TOOL}` admin record"
            ));
        }
        if r.arguments_digest != self.prune_arguments_digest() {
            return Err("the prune record's arguments digest does not match the anchor".into());
        }
        Ok(())
    }
}

/// `now` as RFC 3339 UTC, whole seconds: the `at` of checkpoints and anchors.
fn whole_seconds_utc(now: OffsetDateTime) -> Result<String, AuditError> {
    Ok(now
        .to_offset(time::UtcOffset::UTC)
        .replace_nanosecond(0)
        .unwrap_or(now)
        .format(&Rfc3339)?)
}

/// An anchor that failed verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BadAnchor {
    /// The `through_seq` the anchor claims.
    pub through_seq: u64,
    /// Why it failed: an unknown key, a bad signature, a checkpoint at `through_seq` that is
    /// missing or differs, a prune record that does not match, or a broken series.
    pub reason: String,
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
    ///
    /// # Errors
    ///
    /// [`AuditError::Jwks`] when the document has no `keys` array, or when an Ed25519 OKP entry's
    /// `x` is not base64url or does not decode to 32 bytes.
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

    /// Whether the JWKS held no usable Ed25519 key.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// `Ok` when `cp` carries a valid signature by a known key.
    ///
    /// # Errors
    ///
    /// The reason as text, for [`BadCheckpoint::reason`]: `cp.kid` names no key in the set, or the
    /// signature does not verify against that key.
    pub fn verify(&self, cp: &Checkpoint) -> Result<(), String> {
        self.verify_signed(
            &cp.kid,
            CHECKPOINT_CONTEXT,
            &cp.signing_payload(),
            &cp.signature,
        )
    }

    /// `Ok` when `anchor` carries a valid signature by a known key, under [`ANCHOR_CONTEXT`].
    ///
    /// # Errors
    ///
    /// The reason as text, for [`BadAnchor::reason`]: `anchor.kid` names no key in the set, or
    /// the signature does not verify against that key.
    pub fn verify_anchor(&self, anchor: &Anchor) -> Result<(), String> {
        self.verify_signed(
            &anchor.kid,
            ANCHOR_CONTEXT,
            &anchor.signing_payload(),
            &anchor.signature,
        )
    }

    fn verify_signed(
        &self,
        kid: &str,
        context: &str,
        payload: &[u8],
        signature: &str,
    ) -> Result<(), String> {
        let key = self
            .keys
            .get(kid)
            .ok_or_else(|| format!("unknown signing key `{kid}`"))?;
        if verify_detached(key, context, payload, signature) {
            Ok(())
        } else {
            Err("signature does not verify".to_string())
        }
    }
}

/// A checkpoint that failed verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BadCheckpoint {
    /// The `seq` the checkpoint claims to cover.
    pub seq: u64,
    /// Why it failed: an unknown key, a bad signature, a head hash that differs from the log,
    /// or a log that ends before it.
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
    /// Sequence number of the first entry that breaks the hash chain, as in [`VerifyReport`].
    pub first_bad_seq: Option<u64>,
    /// Checkpoints examined.
    pub checkpoints: u64,
    /// Highest seq covered by a checkpoint whose signature and head hash both check out.
    pub last_signed_seq: Option<u64>,
    /// Entries after `last_signed_seq` (all of them when there is none): covered by the hash
    /// chain only, not yet countersigned.
    pub unsigned_tail: u64,
    /// Every checkpoint that failed verification, with the reason.
    pub bad_checkpoints: Vec<BadCheckpoint>,
    /// The last seq pruned, when a valid anchor says the run starts after it (a pruned log,
    /// or an export that starts right after a prune); `null` otherwise. `entries` then counts
    /// the retained entries only.
    #[serde(default)]
    pub pruned_through: Option<u64>,
    /// Anchors examined.
    #[serde(default)]
    pub anchors: u64,
    /// Every anchor that failed verification, with the reason. Any makes the report fail.
    #[serde(default)]
    pub bad_anchors: Vec<BadAnchor>,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Start {
    /// The run must begin at seq 1 with the genesis `prev_hash` (a whole log).
    Genesis,
    /// The run may begin anywhere (an export of `from..=to`); the first entry's `prev_hash`
    /// is taken as given and contiguity is checked from there.
    Window,
    /// The run must begin at `seq + 1` with `prev_hash` equal to `hash`: a log pruned through
    /// `seq`, whose [`Anchor`] (checked by the caller) names `seq` and `hash`. A checkpoint at
    /// `seq` is matched against `hash`.
    Anchored {
        /// The last seq pruned ([`Anchor::through_seq`]).
        seq: u64,
        /// The entry hash at `seq` ([`Anchor::through_hash`]).
        hash: String,
    },
}

impl Start {
    /// The seq and `prev_hash` the first entry must have; `None` for [`Start::Window`].
    fn expected_first(&self) -> Option<(u64, String)> {
        match self {
            Start::Genesis => Some((1, GENESIS_HASH.to_string())),
            Start::Window => None,
            Start::Anchored { seq, hash } => Some((seq.saturating_add(1), hash.clone())),
        }
    }
}

/// Walk `entries` and check each checkpoint in `checkpoints` against them.
///
/// Only checkpoints inside the walked range are meaningful; callers exporting a window pass
/// just those. A checkpoint beyond the last entry is reported as `bad` (truncation) when the
/// chain itself is intact.
///
/// # Errors
///
/// Whatever error an item of `entries` carries other than [`AuditError::Corrupt`] (a store fault
/// while reading the log), which is propagated. A corrupt entry, a broken chain and a bad
/// checkpoint are not errors: they are reported in the [`SignedVerifyReport`].
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
    let chain = walk_entries(entries, start.expected_first(), |e| {
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
        let actual = match &start {
            Start::Genesis if cp.seq == 0 => Some(GENESIS_HASH.to_string()),
            Start::Anchored { seq, hash } if cp.seq == *seq => Some(hash.clone()),
            _ if cp.seq == 0 => None,
            _ => hashes.get(&cp.seq).cloned(),
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
        pruned_through: match start {
            Start::Anchored { seq, .. } => Some(seq),
            _ => None,
        },
        anchors: 0,
        bad_anchors: Vec::new(),
    })
}
