//! Certificate revocation lists (CRL files, RFC 5280 §5) for RFC 8705 `tls_client_auth`
//! ([ADR-0023](../../docs/decisions/0023-client-certificate-crls.md)).
//!
//! An `[[agents]]` or `[[peps]]` entry with `tls_client_ca_pem_path` may list CRL files in
//! `tls_client_crl_paths`. They are read at start and by an agents reload, never fetched.
//!
//! # At load
//!
//! Each file holds one CRL, PEM (`X509 CRL`) or DER, of at most [`MAX_CRL_FILE_BYTES`]. It
//! must:
//!
//! - parse as a version 2 CRL with `nextUpdate` (rustls-webpki's parser, which refuses delta
//!   CRLs, indirect CRLs and CRLs partitioned by reason), have no
//!   `issuingDistributionPoint` extension at all (a CRL scoped to some certificates of its
//!   CA would look complete here, so scoped and partitioned CRLs are refused), and list at
//!   most [`MAX_CRL_ENTRIES`] certificates;
//! - be signed by an acceptable issuer: a CA certificate of the entry's
//!   `tls_client_ca_pem_path` (a trust anchor), or a CA certificate of the entry's
//!   `tls_client_crl_issuer_pem_path`. Each certificate of that file must have started
//!   (`notBefore`) at load and be signed by a trust anchor or by another accepted
//!   certificate of the file whose `keyUsage`, if any, allows `keyCertSign`. The CRL's issuer
//!   name must equal the signer's subject, byte for byte, and the signature must verify with
//!   the signer's key (the algorithms of the listener's `ring` provider; checked once per file
//!   and key over a load). A signer with a `keyUsage` extension must have `cRLSign`. A CRL
//!   signed by any other key is refused. A CRL whose signer (name and key) a CRL of the entry
//!   revokes, or has no certificate in the files valid now, is loaded but ignored: every
//!   certificate that CA issues is [`Status::Ignored`], and the start or reload goes on;
//! - have `nextUpdate` after `thisUpdate`, and `thisUpdate` at most
//!   [`MAX_FUTURE_THIS_UPDATE_SECS`] ahead of the server clock;
//! - with `tls_client_crl_stale = "refuse"` (the default), not be stale: `nextUpdate` must
//!   be after the server clock;
//! - be the only CRL of its CA (issuer name and key) in the entry, and across all entries
//!   the same file content for one CA ([`check_consistent`]).
//!
//! Also at load, for each trust anchor that is not self-issued, the certificates of the two
//! files that issued it (by name, and by a signature checked here, once per pair of files in a
//! load) and those above them, so
//! that the anchor can be checked as an intermediate is ([`CrlSet::anchor_status`]); and the
//! names behind the warnings of [`log_in_force`].
//!
//! # At authentication
//!
//! [`crate::client_pki::verify`] checks each path rustls-webpki builds: every certificate
//! below the trust anchor is looked up, by the name and key of the CA that issued it in that
//! path, then by serial number without leading zero bytes ([`CrlSet::status`]); then the
//! anchor, by the checks found at load. Hash map lookups per certificate: no signature check,
//! no scan, no parsing.
//!
//! # Reload
//!
//! An agents reload reads every file again into new values, so caches keyed by them never
//! answer from an old CRL. A reload is refused when a CRL of a CA in force would be replaced
//! by an older one ([`check_not_older`]). Only the CRLs in force are compared: not across a
//! restart, and not after a reload that dropped the CA's CRL.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::pem::{PemObject, SectionKind};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::client_pki::{element, expect, time_of, CaFile, SEQUENCE};
use crate::config::ClientCrlRule;

/// Largest CRL file, in bytes.
pub(crate) const MAX_CRL_FILE_BYTES: u64 = 4 * 1024 * 1024;
/// Most certificates one CRL may list.
pub(crate) const MAX_CRL_ENTRIES: usize = 100_000;
/// Most files one entry's `tls_client_crl_paths` may list.
pub(crate) const MAX_CRLS_PER_ENTRY: usize = 16;
/// Most distinct CRL files one start or reload reads, over all entries.
pub(crate) const MAX_CRL_FILES: usize = 32;
/// Most bytes of CRL files one start or reload reads, over all entries.
pub(crate) const MAX_TOTAL_CRL_BYTES: u64 = 16 * 1024 * 1024;
/// Most listed certificates over the CRL files of one start or reload.
pub(crate) const MAX_TOTAL_CRL_ENTRIES: usize = 250_000;
/// How far ahead of the server clock a CRL's `thisUpdate` may be, for clock skew.
pub(crate) const MAX_FUTURE_THIS_UPDATE_SECS: i64 = 300;

/// `id-ce-cRLNumber` (2.5.29.20).
const CRL_NUMBER: [u8; 3] = [0x55, 0x1d, 0x14];
/// `id-ce-issuingDistributionPoint` (2.5.29.28).
const ISSUING_DISTRIBUTION_POINT: [u8; 3] = [0x55, 0x1d, 0x1c];
/// `id-ce-keyUsage` (2.5.29.15).
const KEY_USAGE: [u8; 3] = [0x55, 0x1d, 0x0f];

/// One CRL, read and checked on its own (its signature is checked per entry, against the
/// entry's acceptable issuers).
pub(crate) struct CrlFile {
    /// The path it was first read from, for messages.
    path: PathBuf,
    /// The lowercase hex SHA-256 of the file's bytes.
    sha256: String,
    /// The contents of the CRL's issuer name.
    issuer: Vec<u8>,
    this_update: i64,
    next_update: i64,
    /// `cRLNumber`, without leading zero bytes; `None` when the CRL has none.
    number: Option<Vec<u8>>,
    /// How many certificates it lists.
    entries: usize,
    /// The listed serial numbers, each without its leading zero bytes ([`serial_key`]).
    serials: HashSet<Box<[u8]>>,
}

#[cfg(feature = "fuzzing")]
impl CrlFile {
    /// For `crate::fuzzing`: the issuer name contents, `thisUpdate`, `nextUpdate`, the
    /// `cRLNumber` and the number of listed certificates.
    #[allow(clippy::type_complexity)]
    pub(crate) fn summary(self) -> (Vec<u8>, i64, i64, Option<Vec<u8>>, usize) {
        (
            self.issuer,
            self.this_update,
            self.next_update,
            self.number,
            self.entries,
        )
    }
}

impl std::fmt::Debug for CrlFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrlFile")
            .field("path", &self.path)
            .field("entries", &self.entries)
            .field("this_update", &self.this_update)
            .field("next_update", &self.next_update)
            .finish_non_exhaustive()
    }
}

impl CrlFile {
    fn number_text(&self) -> String {
        self.number
            .as_deref()
            .map_or_else(|| "none".to_owned(), hex::encode)
    }
}

/// The CRL status of one certificate in a path, worst last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Status {
    /// Not listed, or no CRL for its issuer and `tls_client_crl_missing = "allow"`.
    Good,
    /// No CRL for its issuer, and `tls_client_crl_missing = "refuse"`.
    Missing,
    /// The CRL of its issuer is stale, and `tls_client_crl_stale = "refuse"`.
    Stale,
    /// Its issuer signed a CRL that was ignored at load: a CRL of the entry revokes the
    /// issuer (or a CA above it), or none of the issuer's certificates in the files is valid
    /// now; and that CRL does not list it (a listed one is [`Status::Revoked`]). Whatever
    /// `tls_client_crl_missing` says.
    Ignored,
    /// Listed by the CRL of its issuer.
    Revoked,
}

impl Status {
    /// The worse of two.
    pub(crate) fn worst(self, other: Self) -> Self {
        self.max(other)
    }

    /// The refusal reason, for the debug log and the answer.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Status::Good => "not_refused",
            Status::Missing => MISSING_LOG_REASON,
            Status::Stale => STALE_LOG_REASON,
            Status::Ignored => IGNORED_LOG_REASON,
            Status::Revoked => REVOKED_LOG_REASON,
        }
    }
}

/// [`Status::Revoked`]'s reason.
pub(crate) const REVOKED_LOG_REASON: &str = "certificate_revoked";
/// [`Status::Stale`]'s reason.
pub(crate) const STALE_LOG_REASON: &str = "crl_stale";
/// [`Status::Missing`]'s reason.
pub(crate) const MISSING_LOG_REASON: &str = "crl_missing";
/// [`Status::Ignored`]'s reason.
pub(crate) const IGNORED_LOG_REASON: &str = "crl_ignored";

/// CRLs by the contents of their CA's subject name, then by the CA's key.
type ByIssuer = HashMap<Vec<u8>, Vec<(Vec<u8>, Arc<CrlFile>)>>;

/// The CRLs of one entry, as put in force by a start or a reload: one per CA, by the CA's
/// name and key.
pub(crate) struct CrlSet {
    /// By the contents of the CA's subject name: each CA key with that name and its CRL.
    by_issuer: ByIssuer,
    /// `tls_client_crl_paths` as written, each with the SHA-256 of the file read.
    files: Vec<(PathBuf, String)>,
    /// `tls_client_crl_issuer_pem_path` as written, with the SHA-256 of the file read.
    issuers: Option<(PathBuf, String)>,
    pub(crate) stale: ClientCrlRule,
    pub(crate) missing: ClientCrlRule,
    /// The earliest `nextUpdate` of the set's CRLs in force (not ignored).
    earliest_next_update: i64,
    /// By the contents of a trust anchor's subject name: each anchor key with that name that
    /// is not self-issued and whose issuer the entry's files hold, and the certificates to
    /// check above it ([`CrlSet::anchor_status`]).
    anchors: ByAnchor,
    /// The subject names, as text, of the CA file's anchors that a CRL of the set lists as
    /// revoked, for the warning of [`log_in_force`].
    revoked_anchors: Vec<String>,
    /// With `tls_client_crl_missing = "allow"`: the subject names, as text, of the CA
    /// certificates of the entry that may issue certificates and have no CRL in the set, for
    /// the warning of [`log_in_force`].
    uncovered: Vec<String>,
    /// The CAs (subject name contents, `subjectPublicKeyInfo` contents) whose CRL was
    /// ignored at load: every certificate they issue is [`Status::Ignored`].
    ignored: Vec<(Vec<u8>, Vec<u8>)>,
    /// The CRLs ignored at load, for the warning of [`log_in_force`]: the signer's subject
    /// name as text, and why.
    ignored_crls: Vec<(String, Ignored)>,
}

/// Why a CRL was ignored at load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Ignored {
    /// A CRL of the entry revokes the CA that signed it, or a CA above it.
    Revoked,
    /// No certificate of the files with the signer's name and key is valid now (through
    /// certificates valid now, up to a trust anchor).
    Expired,
}

/// One check above a trust anchor: the certificate with serial number `serial` (without its
/// leading zero bytes), issued by the CA with subject name contents `issuer` and
/// `subjectPublicKeyInfo` contents `spki`, looked up as [`CrlSet::status`] does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Step {
    pub(crate) issuer: Vec<u8>,
    pub(crate) spki: Vec<u8>,
    pub(crate) serial: Vec<u8>,
}

/// Trust anchors by the contents of their subject name, then by key, with their [`Step`]s.
type ByAnchor = HashMap<Vec<u8>, Vec<(Vec<u8>, Vec<Step>)>>;

/// A serial number (the contents of a DER `INTEGER`) without its leading zero bytes, so that
/// `00 01` and `01` are one serial number: non-negative serial numbers compare as numbers.
/// Only those are meaningful: RFC 5280 §4.1.2.2 forbids a negative one. A negative encoding
/// compares as its bytes would unsigned (`FF`, which is -1, equals `00 FF`, which is 255), so
/// the comparison can only list more certificates as revoked, never fewer.
pub(crate) fn serial_key(serial: &[u8]) -> &[u8] {
    let skip = serial.iter().take_while(|b| **b == 0).count();
    &serial[skip..]
}

impl std::fmt::Debug for CrlSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrlSet")
            .field("files", &self.files.len())
            .field("stale", &self.stale)
            .field("missing", &self.missing)
            .finish_non_exhaustive()
    }
}

impl CrlSet {
    /// The status of the certificate with DER serial number contents `serial`, issued by the
    /// CA with subject name contents `issuer` and `subjectPublicKeyInfo` contents `spki`, at
    /// `now` (Unix seconds). A listed certificate is [`Status::Revoked`] even when the CRL is
    /// stale: a revocation is never taken back.
    pub(crate) fn status(&self, issuer: &[u8], spki: &[u8], serial: &[u8], now: i64) -> Status {
        let crl = self
            .by_issuer
            .get(issuer)
            .and_then(|keys| keys.iter().find(|(k, _)| k.as_slice() == spki))
            .map(|(_, crl)| crl);
        // A certificate an ignored CRL lists is still revoked: a listing only adds refusals.
        if crl.is_some_and(|crl| crl.serials.contains(serial_key(serial))) {
            return Status::Revoked;
        }
        if self.is_ignored(issuer, spki) {
            return Status::Ignored;
        }
        let Some(crl) = crl else {
            return match self.missing {
                ClientCrlRule::Allow => Status::Good,
                ClientCrlRule::Refuse => Status::Missing,
            };
        };
        if now >= crl.next_update && self.stale == ClientCrlRule::Refuse {
            return Status::Stale;
        }
        Status::Good
    }

    /// The worst [`status`](Self::status) of `steps`.
    pub(crate) fn steps_status(&self, steps: &[Step], now: i64) -> Status {
        steps.iter().fold(Status::Good, |worst, s| {
            worst.worst(self.status(&s.issuer, &s.spki, &s.serial, now))
        })
    }

    /// The status of the trust anchor with subject name contents `subject` and
    /// `subjectPublicKeyInfo` contents `spki` at the end of a path: [`Status::Good`] for a
    /// self-issued CA, or one whose issuer the entry's files do not hold; otherwise the worst
    /// status of each certificate between it and a self-issued CA, through every issuer the
    /// files hold, each checked as an intermediate is ([`Step`]). Precomputed at load: hash
    /// lookups only, no signature check.
    pub(crate) fn anchor_status(&self, subject: &[u8], spki: &[u8], now: i64) -> Status {
        self.anchors
            .get(subject)
            .and_then(|keys| keys.iter().find(|(k, _)| k.as_slice() == spki))
            .map_or(Status::Good, |(_, steps)| self.steps_status(steps, now))
    }

    /// The last second an accepted path may be answered from a cache: one second before the
    /// earliest `nextUpdate`, when stale CRLs refuse. `None` when they do not.
    pub(crate) fn cache_until(&self) -> Option<i64> {
        (self.stale == ClientCrlRule::Refuse).then(|| self.earliest_next_update.saturating_sub(1))
    }

    /// Whether the CRL of the CA with this name and key was ignored at load.
    fn is_ignored(&self, issuer: &[u8], spki: &[u8]) -> bool {
        self.ignored
            .iter()
            .any(|(n, k)| n.as_slice() == issuer && k.as_slice() == spki)
    }

    /// [`crls`](Self::crls) without those ignored at load: the CRLs in force.
    fn crls_in_force(&self) -> impl Iterator<Item = (&[u8], &[u8], &Arc<CrlFile>)> {
        self.crls()
            .filter(|(name, spki, _)| !self.is_ignored(name, spki))
    }

    /// Each CRL of the set with its CA's name and key.
    fn crls(&self) -> impl Iterator<Item = (&[u8], &[u8], &Arc<CrlFile>)> {
        self.by_issuer.iter().flat_map(|(name, keys)| {
            keys.iter()
                .map(move |(spki, crl)| (name.as_slice(), spki.as_slice(), crl))
        })
    }

    /// The entry's member of the list digest and of a reload's changes:
    /// `tls_client_crl_paths` as written, the SHA-256 of each file read (in the same order),
    /// `tls_client_crl_issuer_pem_path` and its SHA-256 when set, and the two rules in force.
    pub(crate) fn row(&self) -> serde_json::Value {
        let mut row = serde_json::Map::new();
        row.insert(
            "tls_client_crl_paths".into(),
            self.files
                .iter()
                .map(|(p, _)| serde_json::Value::from(p.display().to_string()))
                .collect(),
        );
        row.insert(
            "tls_client_crl_sha256".into(),
            self.files
                .iter()
                .map(|(_, d)| serde_json::Value::from(d.clone()))
                .collect(),
        );
        if let Some((p, d)) = &self.issuers {
            row.insert(
                "tls_client_crl_issuer_pem_path".into(),
                p.display().to_string().into(),
            );
            row.insert("tls_client_crl_issuer_pem_sha256".into(), d.clone().into());
        }
        row.insert("tls_client_crl_stale".into(), rule_name(self.stale).into());
        row.insert(
            "tls_client_crl_missing".into(),
            rule_name(self.missing).into(),
        );
        serde_json::Value::Object(row)
    }
}

fn rule_name(r: ClientCrlRule) -> &'static str {
    match r {
        ClientCrlRule::Allow => "allow",
        ClientCrlRule::Refuse => "refuse",
    }
}

/// The CRL files read so far by one start or reload, by path, so each is read once, and the
/// totals that bound them. Also the intermediate CA files of `tls_client_crl_issuer_pem_path`.
pub(crate) struct Loading {
    /// The server clock, in Unix seconds.
    now: i64,
    /// Each file read: the CRL and its DER bytes (kept only while loading, for the signature
    /// check of each entry that names it).
    files: Vec<(PathBuf, Arc<CrlFile>, Vec<u8>)>,
    issuer_files: Vec<(PathBuf, Arc<CaFile>)>,
    total_bytes: u64,
    total_entries: usize,
    /// Each CRL signature checked so far, by file (its index in `files`) and key
    /// (`subjectPublicKeyInfo` contents): whether it verified. Entries that share a CA and a
    /// CRL file check it once.
    signatures: HashMap<(usize, Vec<u8>), bool>,
    /// How many CRL signatures were checked, for the tests.
    signature_checks: usize,
    /// The issuers found by [`nodes`] for each CA certificate, by the SHA-256 of the CA file
    /// and of the issuer file: entries that share both check their signatures once.
    graphs: HashMap<(String, Option<String>), Vec<Vec<usize>>>,
    /// How many times [`nodes`] checked the signatures between CA certificates, for the
    /// tests.
    graph_builds: usize,
}

impl Loading {
    /// A start or reload at `now`.
    pub(crate) fn new(now: OffsetDateTime) -> Self {
        Self {
            now: now.unix_timestamp(),
            files: Vec::new(),
            issuer_files: Vec::new(),
            total_bytes: 0,
            total_entries: 0,
            signatures: HashMap::new(),
            signature_checks: 0,
            graphs: HashMap::new(),
            graph_builds: 0,
        }
    }

    fn crl(&mut self, path: &Path) -> Result<(Arc<CrlFile>, usize), String> {
        if let Some(i) = self.files.iter().position(|(p, _, _)| p == path) {
            return Ok((self.files[i].1.clone(), i));
        }
        if self.files.len() >= MAX_CRL_FILES {
            return Err(format!(
                "more than {MAX_CRL_FILES} different CRL files over all entries"
            ));
        }
        let bytes = crate::tls::read_file(path, MAX_CRL_FILE_BYTES, false)?;
        self.add(path, &bytes)
    }

    /// [`crl`](Self::crl) of a file whose bytes were read.
    pub(crate) fn add(
        &mut self,
        path: &Path,
        bytes: &[u8],
    ) -> Result<(Arc<CrlFile>, usize), String> {
        self.total_bytes += bytes.len() as u64;
        if self.total_bytes > MAX_TOTAL_CRL_BYTES {
            return Err(format!(
                "the CRL files of all entries hold more than {} MiB together",
                MAX_TOTAL_CRL_BYTES / (1024 * 1024)
            ));
        }
        let (crl, der) = parse(path, bytes)?;
        self.total_entries += crl.entries;
        if self.total_entries > MAX_TOTAL_CRL_ENTRIES {
            return Err(format!(
                "the CRL files of all entries list more than {MAX_TOTAL_CRL_ENTRIES} \
                 certificates together"
            ));
        }
        let crl = Arc::new(crl);
        self.files.push((path.to_owned(), crl.clone(), der));
        Ok((crl, self.files.len() - 1))
    }

    fn issuer_file(&mut self, path: &Path) -> Result<Arc<CaFile>, String> {
        if let Some((_, f)) = self.issuer_files.iter().find(|(p, _)| p == path) {
            return Ok(f.clone());
        }
        let f = Arc::new(crate::client_pki::read_ca_file(path)?);
        self.issuer_files.push((path.to_owned(), f.clone()));
        Ok(f)
    }

    /// [`issuer_file`](Self::issuer_file) of a file that was read, for `crate::fuzzing`.
    #[cfg(feature = "fuzzing")]
    pub(crate) fn add_issuer_file(&mut self, path: &Path, file: CaFile) {
        self.issuer_files.push((path.to_owned(), Arc::new(file)));
    }
}

/// The settings of one entry, as written.
pub(crate) struct Settings<'a> {
    pub(crate) paths: &'a [PathBuf],
    pub(crate) issuers: Option<&'a Path>,
    pub(crate) stale: Option<ClientCrlRule>,
    pub(crate) missing: Option<ClientCrlRule>,
}

/// A CA certificate of an entry: of its CA file (a trust anchor) or of its
/// `tls_client_crl_issuer_pem_path`.
struct Node<'a> {
    /// The contents of its subject name, as its trust anchor holds them.
    subject: &'a [u8],
    /// The contents of its issuer name.
    issuer: &'a [u8],
    /// The contents of its `subjectPublicKeyInfo`.
    spki: &'a [u8],
    /// Its serial number, without leading zero bytes ([`serial_key`]).
    serial: &'a [u8],
    not_before: i64,
    not_after: i64,
    der: &'a [u8],
    /// From the CA file.
    anchor: bool,
    /// Its position in its file, from 1, for messages.
    n: usize,
    /// The other certificates of the two files that issued it: their subject is its issuer
    /// name and their key verifies its signature. Empty for a self-issued trust anchor
    /// (subject = issuer), which is a root here.
    issuers: Vec<usize>,
}

/// The CA certificates of an entry, CA file first, and who issued each: every signature
/// between them checked once per load and pair of files ([`Loading`] keeps the answer).
fn nodes<'a>(
    ca: &'a CaFile,
    issuers: Option<&'a CaFile>,
    loading: &mut Loading,
) -> Result<Vec<Node<'a>>, String> {
    let files = std::iter::once((true, ca)).chain(issuers.map(|f| (false, f)));
    let mut out = Vec::new();
    let mut signed = Vec::new();
    for (anchor, file) in files {
        for (i, (a, der)) in file.anchors().enumerate() {
            let n = i + 1;
            let read = || {
                let t = crate::client_pki::tbs(der)?;
                let (not_before, not_after) = crate::client_pki::validity(der)?;
                Some((t, not_before, not_after, signed_data(der)?))
            };
            let Some((t, not_before, not_after, s)) = read() else {
                let key = if anchor {
                    "tls_client_ca_pem_path"
                } else {
                    "tls_client_crl_issuer_pem_path"
                };
                return Err(format!("{key}: certificate {n} of the file cannot be read"));
            };
            out.push(Node {
                subject: a.subject.as_ref(),
                issuer: t.issuer,
                spki: a.subject_public_key_info.as_ref(),
                serial: serial_key(t.serial),
                not_before,
                not_after,
                der,
                anchor,
                n,
                issuers: Vec::new(),
            });
            signed.push(s);
        }
    }
    let key = (
        ca.sha256().to_owned(),
        issuers.map(|f| f.sha256().to_owned()),
    );
    let edges = match loading.graphs.get(&key) {
        Some(edges) => edges.clone(),
        None => {
            loading.graph_builds += 1;
            let edges: Vec<Vec<usize>> = (0..out.len())
                .map(|i| {
                    if out[i].anchor && out[i].subject == out[i].issuer {
                        return Vec::new();
                    }
                    (0..out.len())
                        .filter(|&j| {
                            j != i
                                && out[j].subject == out[i].issuer
                                && verify_signature(out[j].spki, &signed[i])
                        })
                        .collect()
                })
                .collect();
            loading.graphs.insert(key, edges.clone());
            edges
        }
    };
    for (node, found) in out.iter_mut().zip(edges) {
        node.issuers = found;
    }
    Ok(out)
}

/// The certificates of `nodes` reached from the trust anchors through issuers whose
/// `keyUsage`, if any, allows `keyCertSign`, taking only certificates `usable` says yes to (a
/// chain of intermediates works in any order). Trust anchors are always reached.
fn reached(nodes: &[Node<'_>], usable: impl Fn(&Node<'_>) -> bool) -> Vec<bool> {
    let mut ok: Vec<bool> = nodes.iter().map(|n| n.anchor).collect();
    loop {
        let mut changed = false;
        for i in 0..nodes.len() {
            if !ok[i]
                && usable(&nodes[i])
                && nodes[i]
                    .issuers
                    .iter()
                    .any(|&j| ok[j] && may_sign_certs(nodes[j].der))
            {
                ok[i] = true;
                changed = true;
            }
        }
        if !changed {
            return ok;
        }
    }
}

/// Each certificate of the issuer file must be valid already at `now` (`notBefore`), and
/// issued by a trust anchor or by another accepted certificate of that file whose `keyUsage`,
/// if any, allows `keyCertSign`. One that has expired is accepted here: the CRL it signed is
/// ignored instead (see [`load`]), so that a reload carrying other revocations is not held
/// back.
fn accept_issuer_file(nodes: &[Node<'_>], now: i64) -> Result<(), String> {
    let started = |n: &Node<'_>| n.not_before <= now;
    let ok = reached(nodes, started);
    let Some(i) = ok.iter().position(|ok| !ok) else {
        return Ok(());
    };
    let node = &nodes[i];
    let n = node.n;
    Err(if !started(node) {
        format!(
            "certificate {n} of the file is not valid yet (notBefore {})",
            date(node.not_before)
        )
    } else if node.issuers.is_empty() {
        format!(
            "certificate {n} of the file is not issued by a CA of tls_client_ca_pem_path, nor \
             by another certificate of this file"
        )
    } else if !node.issuers.iter().any(|&j| may_sign_certs(nodes[j].der)) {
        format!(
            "certificate {n} of the file is issued by a CA certificate whose keyUsage leaves \
             keyCertSign out"
        )
    } else {
        format!(
            "certificate {n} of the file is issued only by certificates of this file that are \
             refused"
        )
    })
}

/// The checks above certificate `from` of `nodes`: for each certificate on the way up through
/// every issuer the files hold, its serial number in the CRL of the CA that issued it, until
/// self-issued CAs. Each certificate is walked once.
fn steps(nodes: &[Node<'_>], from: usize) -> Vec<Step> {
    let mut out: Vec<Step> = Vec::new();
    let mut seen = vec![false; nodes.len()];
    seen[from] = true;
    let mut todo = vec![from];
    while let Some(i) = todo.pop() {
        for &j in &nodes[i].issuers {
            let step = Step {
                issuer: nodes[j].subject.to_vec(),
                spki: nodes[j].spki.to_vec(),
                serial: nodes[i].serial.to_vec(),
            };
            if !out.contains(&step) {
                out.push(step);
            }
            if !seen[j] {
                seen[j] = true;
                todo.push(j);
            }
        }
    }
    out
}

/// The CRLs of an entry whose CA file is `ca`, as the module docs say. A message names the
/// key and the file, never a part of a file.
pub(crate) fn load(s: &Settings<'_>, ca: &CaFile, loading: &mut Loading) -> Result<CrlSet, String> {
    if s.paths.is_empty() || s.paths.len() > MAX_CRLS_PER_ENTRY {
        return Err(format!(
            "tls_client_crl_paths must list 1 to {MAX_CRLS_PER_ENTRY} files"
        ));
    }
    for (i, p) in s.paths.iter().enumerate() {
        if s.paths[..i].contains(p) {
            return Err(format!(
                "tls_client_crl_paths lists {:?} twice",
                p.display().to_string()
            ));
        }
    }
    let stale = s.stale.unwrap_or(ClientCrlRule::Refuse);
    let missing = s.missing.unwrap_or(ClientCrlRule::Allow);
    let issuer_file = match s.issuers {
        None => None,
        Some(p) => Some((
            p,
            loading
                .issuer_file(p)
                .map_err(|e| format!("tls_client_crl_issuer_pem_path {:?}: {e}", shown(p)))?,
        )),
    };
    let issuers_fail = |e: String| {
        format!(
            "tls_client_crl_issuer_pem_path {:?}: {e}",
            issuer_file
                .as_ref()
                .map(|(p, _)| shown(p))
                .unwrap_or_default()
        )
    };
    let nodes = nodes(ca, issuer_file.as_ref().map(|(_, f)| &**f), loading)?;
    accept_issuer_file(&nodes, loading.now).map_err(issuers_fail)?;
    let mut by_issuer = ByIssuer::new();
    let mut files = Vec::with_capacity(s.paths.len());
    let mut signers = Vec::with_capacity(s.paths.len());
    for path in s.paths {
        let fail = |e: String| format!("tls_client_crl_paths {:?}: {e}", shown(path));
        let (crl, i) = loading.crl(path).map_err(fail)?;
        let signer = signed_by(&crl, i, &nodes, loading).map_err(fail)?;
        let spki = nodes[signer].spki;
        let keys = by_issuer.entry(crl.issuer.clone()).or_default();
        if keys.iter().any(|(k, _)| k.as_slice() == spki) {
            return Err(fail(
                "a CRL of the same CA (issuer name and key) is listed before it; list one CRL \
                 per CA"
                    .into(),
            ));
        }
        keys.push((spki.to_vec(), crl.clone()));
        files.push((path.clone(), crl.sha256.clone()));
        signers.push((path, crl, signer));
    }
    let mut set = CrlSet {
        by_issuer,
        files,
        issuers: issuer_file
            .as_ref()
            .map(|(p, f)| (p.to_path_buf(), f.sha256().to_owned())),
        stale,
        missing,
        earliest_next_update: i64::MAX,
        anchors: ByAnchor::new(),
        revoked_anchors: Vec::new(),
        uncovered: Vec::new(),
        ignored: Vec::new(),
        ignored_crls: Vec::new(),
    };
    let now = loading.now;
    // Listed: whatever the rules and the dates say.
    let revoked = |set: &CrlSet, steps: &[Step]| {
        steps
            .iter()
            .any(|s| set.status(&s.issuer, &s.spki, &s.serial, now) == Status::Revoked)
    };
    // A CRL is ignored when the CA that signed it (by name and key) is revoked by a CRL of
    // the entry, through any certificate of the files with that name and key or a CA above
    // one, or when no certificate with that name and key is valid now through certificates
    // valid now up to a trust anchor (trust anchors are not dated here). Every certificate
    // that CA issues is then refused as unknown ([`Status::Ignored`]), never accepted: with
    // cross-signing, its certificates might still chain another way. Revocations are counted
    // from every CRL listed, ignored ones too: they can only add refusals.
    let current = reached(&nodes, |n| n.not_before <= now && now < n.not_after);
    let mut ignored = Vec::new();
    for (_, _, signer) in &signers {
        let (name, spki) = (nodes[*signer].subject, nodes[*signer].spki);
        let same: Vec<usize> = (0..nodes.len())
            .filter(|&i| nodes[i].subject == name && nodes[i].spki == spki)
            .collect();
        let why = if same.iter().any(|&i| revoked(&set, &steps(&nodes, i))) {
            Ignored::Revoked
        } else if !same.iter().any(|&i| current[i]) {
            Ignored::Expired
        } else {
            continue;
        };
        ignored.push((name.to_vec(), spki.to_vec()));
        set.ignored_crls.push((name_text(name), why));
    }
    set.ignored = ignored;
    // The dates, once the ignored CRLs are known: an ignored CRL is not stale-checked (nor
    // compared by a reload, see [`check_not_older`]), so that its own age never holds back the
    // revocation that made it ignored; its other date checks stay.
    for (path, crl, signer) in &signers {
        let fail = |e: String| format!("tls_client_crl_paths {:?}: {e}", shown(path));
        if set.is_ignored(nodes[*signer].subject, nodes[*signer].spki) {
            check_dates(crl, ClientCrlRule::Allow, now).map_err(fail)?;
        } else {
            check_dates(crl, stale, now).map_err(fail)?;
            set.earliest_next_update = set.earliest_next_update.min(crl.next_update);
        }
    }
    // Trust anchors that are not self-issued and whose issuer the files hold: checked as an
    // intermediate is, at the end of each path ([`CrlSet::anchor_status`]).
    let mut anchors = ByAnchor::new();
    for (i, node) in nodes.iter().enumerate() {
        if !node.anchor || node.issuers.is_empty() {
            continue;
        }
        let keys = anchors.entry(node.subject.to_vec()).or_default();
        let steps = steps(&nodes, i);
        match keys.iter_mut().find(|(k, _)| k.as_slice() == node.spki) {
            Some((_, have)) => {
                for s in steps {
                    if !have.contains(&s) {
                        have.push(s);
                    }
                }
            }
            None => keys.push((node.spki.to_vec(), steps)),
        }
    }
    for (subject, keys) in &anchors {
        for (_, steps) in keys {
            if revoked(&set, steps) {
                set.revoked_anchors.push(name_text(subject));
            }
        }
    }
    set.anchors = anchors;
    if missing == ClientCrlRule::Allow {
        let mut seen: Vec<(&[u8], &[u8])> = Vec::new();
        for node in &nodes {
            let key = (node.subject, node.spki);
            let covered = set
                .by_issuer
                .get(node.subject)
                .is_some_and(|keys| keys.iter().any(|(k, _)| k.as_slice() == node.spki));
            if !covered && !seen.contains(&key) && may_sign_certs(node.der) {
                seen.push(key);
                set.uncovered.push(name_text(node.subject));
            }
        }
    }
    Ok(set)
}

fn shown(p: &Path) -> String {
    p.display().to_string()
}

/// The certificate of `nodes` that signed `crl` (file `file` of `loading`): its subject is the
/// CRL's issuer name and its key verifies the signature (checked once per file and key over a
/// whole load), and the `keyUsage` of every certificate of the files with that name and key,
/// if any, allows `cRLSign`.
fn signed_by(
    crl: &CrlFile,
    file: usize,
    nodes: &[Node<'_>],
    loading: &mut Loading,
) -> Result<usize, String> {
    let Loading {
        files,
        signatures,
        signature_checks,
        ..
    } = loading;
    let signed =
        signed_data(&files[file].2).ok_or_else(|| "cannot be read as an X.509 CRL".to_owned())?;
    let named: Vec<usize> = (0..nodes.len())
        .filter(|&i| nodes[i].subject == crl.issuer)
        .collect();
    if named.is_empty() {
        return Err(
            "its issuer is not a CA certificate of tls_client_ca_pem_path or \
             tls_client_crl_issuer_pem_path"
                .into(),
        );
    }
    let signer = named
        .iter()
        .copied()
        .find(|&i| {
            *signatures
                .entry((file, nodes[i].spki.to_vec()))
                .or_insert_with(|| {
                    *signature_checks += 1;
                    verify_signature(nodes[i].spki, &signed)
                })
        })
        .ok_or_else(|| {
            "its signature does not verify with the key of the CA it names as its issuer: it \
             was signed by another key"
                .to_owned()
        })?;
    let spki = nodes[signer].spki;
    if !named
        .iter()
        .filter(|&&i| nodes[i].spki == spki)
        .all(|&i| may_sign_crls(nodes[i].der))
    {
        return Err(
            "the CA certificate that signed it has a keyUsage extension without cRLSign".into(),
        );
    }
    Ok(signer)
}

fn check_dates(crl: &CrlFile, stale: ClientCrlRule, now: i64) -> Result<(), String> {
    if crl.next_update <= crl.this_update {
        return Err("its nextUpdate is not after its thisUpdate".into());
    }
    if crl.this_update > now.saturating_add(MAX_FUTURE_THIS_UPDATE_SECS) {
        return Err(format!(
            "its thisUpdate ({}) is more than {MAX_FUTURE_THIS_UPDATE_SECS} seconds ahead of \
             the server clock",
            date(crl.this_update)
        ));
    }
    if stale == ClientCrlRule::Refuse && now >= crl.next_update {
        return Err(format!(
            "it is stale: its nextUpdate ({}) has passed. Get a new CRL from the CA, or set \
             tls_client_crl_stale = \"allow\" to use it anyway",
            date(crl.next_update)
        ));
    }
    Ok(())
}

/// A Unix time as RFC 3339, for messages.
pub(crate) fn date(secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| secs.to_string())
}

/// Whether a certificate's `keyUsage`, if it has one, allows `cRLSign` (bit 6). A malformed
/// extension does not.
pub(crate) fn may_sign_crls(cert: &[u8]) -> bool {
    key_usage_allows(cert, 0x02)
}

/// Whether a certificate's `keyUsage`, if it has one, allows `keyCertSign` (bit 5). A
/// malformed extension does not.
pub(crate) fn may_sign_certs(cert: &[u8]) -> bool {
    key_usage_allows(cert, 0x04)
}

/// Whether a certificate's `keyUsage`, if it has one, has the bit `mask` of its first byte.
fn key_usage_allows(cert: &[u8], mask: u8) -> bool {
    let Some(ku) = crate::client_pki::extension(cert, &KEY_USAGE) else {
        return false;
    };
    let Some(value) = ku else {
        return true;
    };
    let Some((bits, rest)) = expect(value, 0x03) else {
        return false;
    };
    let Some((&unused, bytes)) = bits.split_first() else {
        return false;
    };
    rest.is_empty() && unused < 8 && bytes.first().is_some_and(|b| b & mask != 0)
}

/// Most characters of one attribute value in [`name_text`].
const NAME_VALUE_CHARS: usize = 64;
/// Most characters of [`name_text`].
const NAME_CHARS: usize = 256;

/// A name's contents as text for the log, as `CN=root, O=Example`: the common attribute
/// types by their short names, others as `?`; each value escaped (`char::escape_debug`) and
/// cut short, since a certificate's names are anyone's text. `(unreadable name)` for a name
/// that does not read.
pub(crate) fn name_text(name: &[u8]) -> String {
    let read = || -> Option<String> {
        let mut parts = Vec::new();
        let mut rest = name;
        while !rest.is_empty() {
            let (mut set, after) = expect(rest, 0x31)?;
            rest = after;
            while !set.is_empty() {
                let (atv, after) = expect(set, SEQUENCE)?;
                set = after;
                let (oid, atv) = expect(atv, 0x06)?;
                let (tag, value, _) = element(atv)?;
                let label = match oid {
                    [0x55, 0x04, 0x03] => "CN",
                    [0x55, 0x04, 0x05] => "serialNumber",
                    [0x55, 0x04, 0x06] => "C",
                    [0x55, 0x04, 0x07] => "L",
                    [0x55, 0x04, 0x08] => "ST",
                    [0x55, 0x04, 0x0a] => "O",
                    [0x55, 0x04, 0x0b] => "OU",
                    _ => "?",
                };
                let text = match tag {
                    0x0c | 0x13 | 0x14 | 0x16 => String::from_utf8_lossy(value).into_owned(),
                    0x1e => String::from_utf16_lossy(
                        &value
                            .chunks(2)
                            .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                            .collect::<Vec<u16>>(),
                    ),
                    _ => format!("#{}", hex::encode(value)),
                };
                let text: String = text
                    .chars()
                    .take(NAME_VALUE_CHARS)
                    .flat_map(char::escape_debug)
                    .collect();
                parts.push(format!("{label}={text}"));
            }
        }
        Some(parts.join(", "))
    };
    match read() {
        Some(t) if t.chars().count() > NAME_CHARS => {
            t.chars().take(NAME_CHARS).chain("...".chars()).collect()
        }
        Some(t) => t,
        None => "(unreadable name)".into(),
    }
}

/// The parts of a signed X.509 object (certificate or CRL): the to-be-signed element as
/// encoded, the contents of the signature algorithm identifier, and the signature bytes.
pub(crate) struct Signed<'a> {
    pub(crate) tbs: &'a [u8],
    pub(crate) alg: &'a [u8],
    pub(crate) signature: &'a [u8],
}

/// `SEQUENCE { tbs, AlgorithmIdentifier, BIT STRING }` and nothing after it.
pub(crate) fn signed_data(der: &[u8]) -> Option<Signed<'_>> {
    let (outer, rest) = expect(der, SEQUENCE)?;
    if !rest.is_empty() {
        return None;
    }
    let (tag, _, after) = element(outer)?;
    if tag != SEQUENCE {
        return None;
    }
    let tbs = &outer[..outer.len() - after.len()];
    let (alg, after) = expect(after, SEQUENCE)?;
    let (bits, after) = expect(after, 0x03)?;
    let (&unused, signature) = bits.split_first()?;
    (after.is_empty() && unused == 0).then_some(Signed {
        tbs,
        alg,
        signature,
    })
}

/// Whether `signed` verifies with the key whose `subjectPublicKeyInfo` contents are `spki`,
/// with an algorithm of the listener's provider that matches both the signature algorithm and
/// the key's algorithm, as rustls-webpki chooses one.
pub(crate) fn verify_signature(spki: &[u8], signed: &Signed<'_>) -> bool {
    let Some((key_alg, rest)) = expect(spki, SEQUENCE) else {
        return false;
    };
    let Some((bits, rest)) = expect(rest, 0x03) else {
        return false;
    };
    let Some((0, key)) = bits.split_first().map(|(u, k)| (*u, k)) else {
        return false;
    };
    if !rest.is_empty() {
        return false;
    }
    crate::client_cert::provider()
        .signature_verification_algorithms
        .all
        .iter()
        .filter(|a| {
            a.signature_alg_id().as_ref() == signed.alg && a.public_key_alg_id().as_ref() == key_alg
        })
        .any(|a| {
            a.verify_signature(key, signed.tbs, signed.signature)
                .is_ok()
        })
}

/// What [`facts`] reads from a CRL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Facts<'a> {
    pub(crate) issuer: &'a [u8],
    pub(crate) this_update: i64,
    pub(crate) next_update: i64,
    /// The `cRLNumber` contents, as encoded.
    pub(crate) number: Option<&'a [u8]>,
    /// Whether it has an `issuingDistributionPoint` extension.
    pub(crate) distribution_point: bool,
}

/// The fields of a CRL's `tbsCertList` used here (RFC 5280 §5.1): the issuer name contents,
/// `thisUpdate`, `nextUpdate` (required here), `cRLNumber` and whether an
/// `issuingDistributionPoint` is present. `None` on anything unexpected. Only on bytes
/// rustls-webpki has already parsed as a CRL; it decides nothing alone.
pub(crate) fn facts(der: &[u8]) -> Option<Facts<'_>> {
    let signed = signed_data(der)?;
    let (tbs, _) = expect(signed.tbs, SEQUENCE)?;
    let (_, tbs) = expect(tbs, 0x02)?; // version
    let (_, tbs) = expect(tbs, SEQUENCE)?; // signature
    let (issuer, tbs) = expect(tbs, SEQUENCE)?;
    let (this_update, tbs) = time_of(tbs)?;
    let (next_update, mut tbs) = time_of(tbs)?;
    if tbs.first() == Some(&SEQUENCE) {
        tbs = element(tbs)?.2; // revokedCertificates
    }
    let mut out = Facts {
        issuer,
        this_update,
        next_update,
        number: None,
        distribution_point: false,
    };
    if tbs.is_empty() {
        return Some(out);
    }
    let (exts, rest) = expect(tbs, 0xa0)?; // crlExtensions [0] EXPLICIT
    if !rest.is_empty() {
        return None;
    }
    let (mut exts, rest) = expect(exts, SEQUENCE)?;
    if !rest.is_empty() {
        return None;
    }
    while !exts.is_empty() {
        let (ext, rest) = expect(exts, SEQUENCE)?;
        exts = rest;
        let (id, mut ext) = expect(ext, 0x06)?;
        if ext.first() == Some(&0x01) {
            ext = expect(ext, 0x01)?.1; // critical
        }
        let (value, _) = expect(ext, 0x04)?;
        if id == CRL_NUMBER {
            let (n, rest) = expect(value, 0x02)?;
            if !rest.is_empty() || n.first().is_none_or(|b| b & 0x80 != 0) {
                return None;
            }
            out.number = Some(n);
        } else if id == ISSUING_DISTRIBUTION_POINT {
            out.distribution_point = true;
        }
    }
    Some(out)
}

/// The DER of a CRL file: one PEM `X509 CRL` block and nothing else, or DER.
fn file_der(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let start = bytes.iter().position(|b| !b.is_ascii_whitespace());
    match start.map(|i| bytes[i]) {
        None => Err("the file is empty; it must hold one CRL, PEM or DER".into()),
        Some(SEQUENCE) => Ok(bytes.to_vec()),
        Some(b'-') => {
            if crate::tls::mentions_private_key(bytes) {
                return Err("the file holds a private key; it must hold one CRL only".into());
            }
            // The parser's error is never shown: some of its variants quote a line.
            let sections = <(SectionKind, Vec<u8>)>::pem_slice_iter(bytes)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "not a valid PEM file".to_owned())?;
            let begins = bytes.windows(11).filter(|w| w == b"-----BEGIN ").count();
            let ends = bytes.windows(9).filter(|w| w == b"-----END ").count();
            // Nothing before the block, after it, or between blocks: the parser skips text
            // outside blocks.
            let trimmed = bytes.trim_ascii();
            let alone = trimmed.starts_with(b"-----BEGIN X509 CRL-----")
                && trimmed.ends_with(b"-----END X509 CRL-----");
            match sections.as_slice() {
                [(SectionKind::Crl, der)] if begins == 1 && ends == 1 && alone => Ok(der.clone()),
                _ => Err(
                    "the file must hold exactly one PEM block, -----BEGIN X509 CRL-----, and \
                     nothing else"
                        .into(),
                ),
            }
        }
        Some(_) => Err("the file is neither a PEM CRL (-----BEGIN X509 CRL-----) nor DER".into()),
    }
}

/// Read one CRL file's bytes, as the module docs say, up to its signature (checked per
/// entry). Returns the CRL and its DER.
pub(crate) fn parse(path: &Path, bytes: &[u8]) -> Result<(CrlFile, Vec<u8>), String> {
    let der = file_der(bytes)?;
    let borrowed = webpki::BorrowedCertRevocationList::from_der(&der).map_err(parse_error)?;
    // Counted before anything is kept for them.
    let mut entries = 0usize;
    for entry in &borrowed {
        entry.map_err(|_| "a listed certificate of the CRL cannot be read".to_owned())?;
        entries += 1;
        if entries > MAX_CRL_ENTRIES {
            return Err(format!(
                "the CRL lists more than {MAX_CRL_ENTRIES} certificates"
            ));
        }
    }
    let mut serials = HashSet::with_capacity(entries);
    for entry in &borrowed {
        let entry =
            entry.map_err(|_| "a listed certificate of the CRL cannot be read".to_owned())?;
        serials.insert(Box::from(serial_key(entry.serial_number)));
    }
    let f = facts(&der).ok_or_else(|| "cannot read the CRL's dates or extensions".to_owned())?;
    if f.distribution_point {
        return Err(
            "the CRL has an issuingDistributionPoint extension: CRLs scoped to some of a CA's \
             certificates, or partitioned, are not supported; use the CA's full CRL"
                .into(),
        );
    }
    if webpki::CertRevocationList::from(borrowed).issuer() != f.issuer {
        return Err("cannot read the CRL's issuer".into());
    }
    let number = f.number.map(|n| {
        let skip = n.iter().take_while(|b| **b == 0).count();
        n[skip..].to_vec()
    });
    let crl = CrlFile {
        path: path.to_owned(),
        sha256: hex::encode(Sha256::digest(bytes)),
        issuer: f.issuer.to_vec(),
        this_update: f.this_update,
        next_update: f.next_update,
        number,
        entries,
        serials,
    };
    Ok((crl, der))
}

/// A fixed message for a CRL rustls-webpki refused.
fn parse_error(e: webpki::Error) -> String {
    use webpki::Error as E;
    match e {
        E::UnsupportedDeltaCrl => "the CRL is a delta CRL; delta CRLs are not supported".into(),
        E::UnsupportedIndirectCrl => {
            "the CRL is an indirect CRL; indirect CRLs are not supported".into()
        }
        E::UnsupportedRevocationReasonsPartitioning | E::UnsupportedCrlIssuingDistributionPoint => {
            "the CRL is partitioned or scoped (issuingDistributionPoint); not supported".into()
        }
        E::UnsupportedCrlVersion => "the CRL is not a version 2 CRL".into(),
        E::UnsupportedCriticalExtension => {
            "the CRL, or one of its entries, has a critical extension that is not supported".into()
        }
        _ => "cannot be read as an X.509 CRL (version 2, with nextUpdate)".into(),
    }
}

/// CRLs by the name and key of their CA.
type ByCa<'a> = HashMap<(&'a [u8], &'a [u8]), Vec<&'a Arc<CrlFile>>>;

/// Every CRL in `sets`, by the name and key of its CA.
fn by_ca<'a>(sets: impl Iterator<Item = &'a CrlSet>) -> ByCa<'a> {
    let mut out = ByCa::new();
    for set in sets {
        for (name, spki, crl) in set.crls() {
            out.entry((name, spki)).or_default().push(crl);
        }
    }
    out
}

/// [`by_ca`] of the CRLs in force: those ignored at load left out.
fn in_force_by_ca<'a>(sets: impl Iterator<Item = &'a CrlSet>) -> ByCa<'a> {
    let mut out = ByCa::new();
    for set in sets {
        for (name, spki, crl) in set.crls_in_force() {
            out.entry((name, spki)).or_default().push(crl);
        }
    }
    out
}

/// Across all entries of a start or reload, one CA has one CRL content: two entries that list
/// different CRLs of the same CA (issuer name and key) are refused, since one of them would
/// check against an older list.
pub(crate) fn check_consistent<'a>(sets: impl Iterator<Item = &'a CrlSet>) -> Result<(), String> {
    for crls in by_ca(sets).values() {
        if let Some(other) = crls.iter().find(|c| c.sha256 != crls[0].sha256) {
            return Err(format!(
                "the CRL files {:?} and {:?} are both CRLs of one CA, with different contents; \
                 list the same file for that CA in every entry",
                shown(&crls[0].path),
                shown(&other.path)
            ));
        }
    }
    Ok(())
}

/// A reload must not put an older CRL of a CA in force: for every CA (issuer name and key)
/// with a CRL in force (`old`) and in the reload (`new`), the new one's `thisUpdate` must not
/// be earlier, and when the CRL in force has a `cRLNumber` the new one must have one that is
/// not smaller. The same content is always accepted. A CA whose CRL the reload no longer lists
/// is not checked: the operator removed it from the config. Nor is a CRL ignored at load, in
/// force or in the reload: it is not in force.
pub(crate) fn check_not_older<'a>(
    old: impl Iterator<Item = &'a CrlSet>,
    new: impl Iterator<Item = &'a CrlSet>,
) -> Result<(), String> {
    let old = in_force_by_ca(old);
    for (ca, crls) in in_force_by_ca(new) {
        let (Some(was), Some(now)) = (old.get(&ca).and_then(|v| v.first()), crls.first()) else {
            continue;
        };
        if was.sha256 == now.sha256 {
            continue;
        }
        let older_number = match (&was.number, &now.number) {
            (Some(w), Some(n)) => (n.len(), n.as_slice()) < (w.len(), w.as_slice()),
            (Some(_), None) => true,
            (None, _) => false,
        };
        if now.this_update < was.this_update || older_number {
            return Err(format!(
                "the CRL file {:?} is older than the CRL of the same CA in force (thisUpdate \
                 {} and cRLNumber {}, against {} and {} in force): a reload never puts an older \
                 CRL in force",
                shown(&now.path),
                date(now.this_update),
                now.number_text(),
                date(was.this_update),
                was.number_text()
            ));
        }
    }
    Ok(())
}

/// Log, at info level, each CRL in force in `sets`: its path, digest, number, dates and
/// size.
///
/// Then, at warning level, once per name: each trust anchor of a CA file that a CRL of its
/// entry lists as revoked (client certificates whose path ends at it are refused), and, for
/// entries with `tls_client_crl_missing = "allow"`, each CA certificate that may issue
/// certificates and has no CRL in its entry (certificates it issues are accepted with no
/// revocation check); and each CA whose CRL was ignored (certificates it issues are refused).
/// By subject name, never by path.
pub(crate) fn log_in_force<'a>(sets: impl Iterator<Item = &'a CrlSet> + Clone) {
    let mut revoked = HashSet::new();
    let mut uncovered = HashSet::new();
    let mut ignored = HashSet::new();
    for set in sets.clone() {
        for (name, why) in &set.ignored_crls {
            if !ignored.insert((name.as_str(), *why)) {
                continue;
            }
            match why {
                Ignored::Revoked => tracing::warn!(
                    subject = %name,
                    "a CRL of tls_client_crl_paths is ignored: a CRL of its entry revokes the CA \
                     that signed it, or a CA above it. Every certificate that CA issued is \
                     refused as client_certificate_revocation_unknown; remove its CRL from \
                     tls_client_crl_paths"
                ),
                Ignored::Expired => tracing::warn!(
                    subject = %name,
                    "a CRL of tls_client_crl_paths is ignored: no certificate of the CA that \
                     signed it in tls_client_crl_issuer_pem_path is valid now. Every \
                     certificate that CA issued is refused as \
                     client_certificate_revocation_unknown; list its current certificate"
                ),
            }
        }
        for name in &set.revoked_anchors {
            if revoked.insert(name.as_str()) {
                tracing::warn!(
                    subject = %name,
                    "a CA certificate of tls_client_ca_pem_path is revoked by a CRL of its entry: \
                     client certificates whose path ends at it are refused"
                );
            }
        }
        for name in &set.uncovered {
            if uncovered.insert(name.as_str()) {
                tracing::warn!(
                    subject = %name,
                    "a client certificate CA has no CRL in tls_client_crl_paths: with \
                     tls_client_crl_missing = \"allow\", certificates it issues are accepted \
                     with no revocation check"
                );
            }
        }
    }
    for crls in in_force_by_ca(sets).values() {
        let c = crls[0];
        tracing::info!(
            path = %c.path.display(),
            sha256 = %c.sha256,
            crl_number = %c.number_text(),
            this_update = %date(c.this_update),
            next_update = %date(c.next_update),
            entries = c.entries,
            "client certificate CRL in force"
        );
    }
}

/// Whether a refusal reason of [`crate::client_pki::verify`] is one of the CRL check.
pub(crate) fn revocation_reason(reason: &str) -> bool {
    [
        REVOKED_LOG_REASON,
        STALE_LOG_REASON,
        MISSING_LOG_REASON,
        IGNORED_LOG_REASON,
    ]
    .contains(&reason)
}

/// The test CA and files of the unit tests below, for the CRL tests of `client_pki`.
#[cfg(test)]
pub(crate) use tests::{Ca as TestCa, Dir as TestDir, NOW as TEST_NOW};

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::CertificateDer;

    pub(crate) const NOW: i64 = 1_800_000_000;

    pub(crate) fn at(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(secs).unwrap()
    }

    /// A CA (a root, or an intermediate another one issued) for CRL tests, valid around
    /// [`NOW`], with `keyCertSign` and `cRLSign`.
    pub(crate) struct Ca {
        pub(crate) params: rcgen::CertificateParams,
        pub(crate) key: rcgen::KeyPair,
        pub(crate) cert: rcgen::Certificate,
    }

    impl Ca {
        pub(crate) fn new(name: &str, issuer: Option<&Ca>) -> Self {
            Self::with_usages(
                name,
                issuer,
                vec![
                    rcgen::KeyUsagePurpose::KeyCertSign,
                    rcgen::KeyUsagePurpose::CrlSign,
                ],
            )
        }

        pub(crate) fn with_usages(
            name: &str,
            issuer: Option<&Ca>,
            usages: Vec<rcgen::KeyUsagePurpose>,
        ) -> Self {
            Self::with_serial(name, issuer, usages, None)
        }

        /// An intermediate with serial number `serial`, so that a CRL can list it.
        pub(crate) fn numbered(name: &str, issuer: &Ca, serial: u64) -> Self {
            Self::with_serial(
                name,
                Some(issuer),
                vec![
                    rcgen::KeyUsagePurpose::KeyCertSign,
                    rcgen::KeyUsagePurpose::CrlSign,
                ],
                Some(serial),
            )
        }

        /// A root with serial number `serial`.
        pub(crate) fn root_numbered(name: &str, serial: u64) -> Self {
            Self::with_serial(
                name,
                None,
                vec![
                    rcgen::KeyUsagePurpose::KeyCertSign,
                    rcgen::KeyUsagePurpose::CrlSign,
                ],
                Some(serial),
            )
        }

        /// A root whose key is of algorithm `alg`.
        pub(crate) fn with_alg(name: &str, alg: &'static rcgen::SignatureAlgorithm) -> Self {
            let key = rcgen::KeyPair::generate_for(alg).unwrap();
            Self::made(name, None, Self::usages(), None, key)
        }

        /// The same CA (name and key) issued by `issuer` with serial number `serial`: a
        /// cross-signed certificate of it.
        pub(crate) fn cross(&self, issuer: &Ca, serial: u64) -> Self {
            let key = rcgen::KeyPair::from_pem(&self.key.serialize_pem()).unwrap();
            let mut params = self.params.clone();
            params.serial_number = Some(rcgen::SerialNumber::from(serial));
            let cert = params
                .signed_by(
                    &key,
                    &rcgen::Issuer::from_params(&issuer.params, &issuer.key),
                )
                .unwrap();
            Self { params, key, cert }
        }

        fn usages() -> Vec<rcgen::KeyUsagePurpose> {
            vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::CrlSign,
            ]
        }

        fn with_serial(
            name: &str,
            issuer: Option<&Ca>,
            usages: Vec<rcgen::KeyUsagePurpose>,
            serial: Option<u64>,
        ) -> Self {
            let key = rcgen::KeyPair::generate().unwrap();
            Self::made(name, issuer, usages, serial, key)
        }

        fn made(
            name: &str,
            issuer: Option<&Ca>,
            usages: Vec<rcgen::KeyUsagePurpose>,
            serial: Option<u64>,
            key: rcgen::KeyPair,
        ) -> Self {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.serial_number = serial.map(rcgen::SerialNumber::from);
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, name);
            params.key_usages = usages;
            params.not_before = at(NOW - 86_400);
            params.not_after = at(NOW + 86_400);
            let cert = match issuer {
                None => params.self_signed(&key).unwrap(),
                Some(i) => params
                    .signed_by(&key, &rcgen::Issuer::from_params(&i.params, &i.key))
                    .unwrap(),
            };
            Self { params, key, cert }
        }

        /// A client certificate with serial number `serial`, for `name` (a URI name).
        pub(crate) fn leaf(&self, serial: u64, name: &str) -> CertificateDer<'static> {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.serial_number = Some(rcgen::SerialNumber::from(serial));
            params.not_before = at(NOW - 3600);
            params.not_after = at(NOW + 3600);
            params.is_ca = rcgen::IsCa::ExplicitNoCa;
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
            params.subject_alt_names = vec![rcgen::SanType::URI(name.try_into().unwrap())];
            params
                .signed_by(&key, &rcgen::Issuer::from_params(&self.params, &self.key))
                .unwrap()
                .der()
                .clone()
        }

        /// A CRL of this CA listing `serials`, valid from `this` to `next`, with number `n`.
        pub(crate) fn crl(&self, serials: &[u64], this: i64, next: i64, n: u64) -> Vec<u8> {
            self.crl_with(serials, this, next, n, |_| {})
        }

        pub(crate) fn crl_with(
            &self,
            serials: &[u64],
            this: i64,
            next: i64,
            n: u64,
            edit: impl FnOnce(&mut rcgen::CertificateRevocationListParams),
        ) -> Vec<u8> {
            let mut params = rcgen::CertificateRevocationListParams {
                this_update: at(this),
                next_update: at(next),
                crl_number: rcgen::SerialNumber::from(n),
                issuing_distribution_point: None,
                revoked_certs: serials
                    .iter()
                    .map(|s| rcgen::RevokedCertParams {
                        serial_number: rcgen::SerialNumber::from(*s),
                        revocation_time: at(this),
                        reason_code: Some(rcgen::RevocationReason::KeyCompromise),
                        invalidity_date: None,
                    })
                    .collect(),
                key_identifier_method: rcgen::KeyIdMethod::Sha256,
            };
            edit(&mut params);
            params
                .signed_by(&rcgen::Issuer::from_params(&self.params, &self.key))
                .unwrap()
                .der()
                .to_vec()
        }

        /// The same name with another key: what an attacker who does not hold the CA's key
        /// can make.
        pub(crate) fn impostor(&self, name: &str) -> Self {
            Self::new(name, None)
        }
    }

    pub(crate) fn pem(label: &str, der: &[u8]) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        format!("-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n")
    }

    /// A temporary directory with files written into it.
    pub(crate) struct Dir(pub(crate) tempfile::TempDir);

    impl Dir {
        pub(crate) fn new() -> Self {
            Self(tempfile::tempdir().unwrap())
        }

        pub(crate) fn write(&self, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
            let p = self.0.path().join(name);
            std::fs::write(&p, bytes).unwrap();
            p
        }

        pub(crate) fn ca_file(&self, name: &str, cas: &[&Ca]) -> CaFile {
            let text: String = cas.iter().map(|c| c.cert.pem()).collect();
            crate::client_pki::read_ca_file(&self.write(name, text)).unwrap()
        }
    }

    pub(crate) fn settings(paths: &[PathBuf]) -> Settings<'_> {
        Settings {
            paths,
            issuers: None,
            stale: None,
            missing: None,
        }
    }

    fn load_at(s: &Settings<'_>, ca: &CaFile, now: i64) -> Result<CrlSet, String> {
        load(s, ca, &mut Loading::new(at(now)))
    }

    fn spki(c: &Ca) -> Vec<u8> {
        let der = c.cert.der();
        let ee = webpki::EndEntityCert::try_from(der).unwrap();
        let spki = ee.subject_public_key_info();
        expect(spki.as_ref(), SEQUENCE).unwrap().0.to_vec()
    }

    fn subject(c: &Ca) -> Vec<u8> {
        crate::client_pki::tbs(c.cert.der())
            .unwrap()
            .subject
            .to_vec()
    }

    fn serial(der: &[u8]) -> Vec<u8> {
        let der = CertificateDer::from(der);
        let ee = webpki::EndEntityCert::try_from(&der).unwrap();
        ee.serial().to_vec()
    }

    #[test]
    fn a_crl_is_read_in_pem_or_der() {
        let root = Ca::new("root", None);
        let der = root.crl(&[5, 7], NOW - 60, NOW + 3600, 42);
        let dir = Dir::new();
        for bytes in [der.clone(), pem("X509 CRL", &der).into_bytes()] {
            let (crl, back) = parse(&dir.write("c", &bytes), &bytes).unwrap();
            assert_eq!(back, der);
            assert_eq!(crl.entries, 2);
            assert_eq!(crl.this_update, NOW - 60);
            assert_eq!(crl.next_update, NOW + 3600);
            assert_eq!(crl.number.as_deref(), Some(&[42u8][..]));
            assert_eq!(crl.issuer, subject(&root));
            assert_eq!(crl.sha256, hex::encode(Sha256::digest(&bytes)));
        }
    }

    #[test]
    fn files_that_are_not_one_crl_are_refused() {
        let root = Ca::new("root", None);
        let der = root.crl(&[], NOW - 60, NOW + 3600, 1);
        let one = pem("X509 CRL", &der);
        let key = rcgen::KeyPair::generate().unwrap().serialize_pem();
        let scoped = root.crl_with(&[], NOW - 60, NOW + 3600, 1, |p| {
            p.issuing_distribution_point = Some(rcgen::CrlIssuingDistributionPoint {
                distribution_point: rcgen::CrlDistributionPoint {
                    uris: vec!["http://crl.example/root.crl".into()],
                },
                scope: Some(rcgen::CrlScope::UserCertsOnly),
            });
        });
        let full_dp = root.crl_with(&[], NOW - 60, NOW + 3600, 1, |p| {
            p.issuing_distribution_point = Some(rcgen::CrlIssuingDistributionPoint {
                distribution_point: rcgen::CrlDistributionPoint {
                    uris: vec!["http://crl.example/root.crl".into()],
                },
                scope: None,
            });
        });
        let mut bad_sig = der.clone();
        let last = bad_sig.len() - 1;
        bad_sig[last] ^= 1;
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (Vec::new(), "the file is empty"),
            (b" \n".to_vec(), "the file is empty"),
            (b"hello".to_vec(), "neither a PEM CRL"),
            (format!("{one}{one}").into_bytes(), "exactly one PEM block"),
            // Text after the block, or between two.
            (
                format!("{one}trailing text\n").into_bytes(),
                "exactly one PEM block",
            ),
            (format!("{one}#\n").into_bytes(), "exactly one PEM block"),
            (
                format!("{one}text\n{}", pem("CERTIFICATE", root.cert.der())).into_bytes(),
                "exactly one PEM block",
            ),
            (
                format!("{one}-----END X509 CRL-----\n").into_bytes(),
                "exactly one PEM block",
            ),
            (root.cert.pem().into_bytes(), "exactly one PEM block"),
            (format!("{one}{key}").into_bytes(), "holds a private key"),
            (
                format!("{one}{}", pem("CERTIFICATE", root.cert.der())).into_bytes(),
                "exactly one PEM block",
            ),
            (
                pem("X509 CRL", b"\x30\x00").into_bytes(),
                "cannot be read as an X.509 CRL",
            ),
            (root.cert.der().to_vec(), "cannot be read as an X.509 CRL"),
            (
                der[..der.len() - 3].to_vec(),
                "cannot be read as an X.509 CRL",
            ),
            (scoped, "issuingDistributionPoint"),
            (full_dp, "issuingDistributionPoint"),
        ];
        for (bytes, want) in cases {
            let e = parse(Path::new("x"), &bytes).err().unwrap();
            assert!(e.contains(want), "{want}: {e}");
            assert!(!e.contains("MII"), "{e}");
        }
        // A broken signature parses: the signature is checked against the entry's CAs.
        assert!(parse(Path::new("x"), &bad_sig).is_ok());
        // Blank lines and CRLF line ends around the one block are fine.
        let spaced = format!("\r\n\n{}\r\n\n", one.replace('\n', "\r\n"));
        assert_eq!(parse(Path::new("x"), spaced.as_bytes()).unwrap().1, der);
    }

    #[test]
    fn the_number_of_entries_is_bounded() {
        let root = Ca::new("root", None);
        let serials: Vec<u64> = (1..=MAX_CRL_ENTRIES as u64 + 1).collect();
        let big = root.crl(&serials, NOW - 60, NOW + 3600, 1);
        let e = parse(Path::new("x"), &big).err().unwrap();
        assert!(e.contains("more than 100000 certificates"), "{e}");
        let ok = root.crl(&serials[..MAX_CRL_ENTRIES], NOW - 60, NOW + 3600, 1);
        assert_eq!(
            parse(Path::new("x"), &ok).unwrap().0.entries,
            MAX_CRL_ENTRIES
        );
    }

    #[test]
    fn a_crl_must_be_signed_by_a_ca_of_the_entry() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let other = Ca::new("other", None);
        let ca = dir.ca_file("ca.pem", &[&root]);
        let good = [dir.write("good.crl", root.crl(&[1], NOW - 60, NOW + 3600, 1))];
        let set = load_at(&settings(&good), &ca, NOW).unwrap();
        assert_eq!(set.files.len(), 1);
        assert_eq!(set.stale, ClientCrlRule::Refuse);
        assert_eq!(set.missing, ClientCrlRule::Allow);

        // Another CA's CRL: its issuer is not in the file.
        let p = [dir.write("other.crl", other.crl(&[1], NOW - 60, NOW + 3600, 1))];
        let e = load_at(&settings(&p), &ca, NOW).err().unwrap();
        assert!(e.contains("its issuer is not a CA certificate"), "{e}");
        // The CA's name with another key.
        let fake = root.impostor("root");
        let p = [dir.write("fake.crl", fake.crl(&[1], NOW - 60, NOW + 3600, 1))];
        let e = load_at(&settings(&p), &ca, NOW).err().unwrap();
        assert!(e.contains("signed by another key"), "{e}");
        assert!(e.contains("fake.crl"), "{e}");
        // A broken signature.
        let mut der = root.crl(&[1], NOW - 60, NOW + 3600, 1);
        let last = der.len() - 1;
        der[last] ^= 1;
        let p = [dir.write("broken.crl", der)];
        let e = load_at(&settings(&p), &ca, NOW).err().unwrap();
        assert!(e.contains("signed by another key"), "{e}");
        // A CA whose key usage leaves cRLSign out. rcgen refuses to sign with it, so the
        // CRL is signed with the same name and key through parameters without key usages.
        let mut no_crl = Ca::with_usages("nocrl", None, vec![rcgen::KeyUsagePurpose::KeyCertSign]);
        let ca2 = dir.ca_file("ca2.pem", &[&no_crl]);
        no_crl.params.key_usages.clear();
        let p = [dir.write("nocrl.crl", no_crl.crl(&[1], NOW - 60, NOW + 3600, 1))];
        let e = load_at(&settings(&p), &ca2, NOW).err().unwrap();
        assert!(e.contains("without cRLSign"), "{e}");
        // An intermediate's CRL needs the intermediate in tls_client_crl_issuer_pem_path.
        let mid = Ca::new("mid", Some(&root));
        let p = [dir.write("mid.crl", mid.crl(&[1], NOW - 60, NOW + 3600, 1))];
        let e = load_at(&settings(&p), &ca, NOW).err().unwrap();
        assert!(e.contains("its issuer is not a CA certificate"), "{e}");
        let issuers = dir.write("issuers.pem", mid.cert.pem());
        let s = Settings {
            issuers: Some(&issuers),
            ..settings(&p)
        };
        let set = load_at(&s, &ca, NOW).unwrap();
        assert!(set.row()["tls_client_crl_issuer_pem_sha256"].is_string());
        // An intermediate under another CA is not one of the entry's.
        let stray = Ca::new("mid", Some(&other));
        let issuers = dir.write("stray.pem", stray.cert.pem());
        let s = Settings {
            issuers: Some(&issuers),
            ..settings(&p)
        };
        let e = load_at(&s, &ca, NOW).err().unwrap();
        assert!(
            e.contains("not issued by a CA of tls_client_ca_pem_path"),
            "{e}"
        );
        // Two levels, listed bottom first: each is accepted once the one above it is.
        let low = Ca::new("low", Some(&mid));
        let issuers = dir.write("two.pem", format!("{}{}", low.cert.pem(), mid.cert.pem()));
        let p = [dir.write("low.crl", low.crl(&[1], NOW - 60, NOW + 3600, 1))];
        let s = Settings {
            issuers: Some(&issuers),
            ..settings(&p)
        };
        assert!(load_at(&s, &ca, NOW).is_ok());
    }

    #[test]
    fn the_dates_are_checked() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let ca = dir.ca_file("ca.pem", &[&root]);
        let p = [dir.write("c.crl", root.crl(&[], NOW - 3600, NOW - 1, 1))];
        let e = load_at(&settings(&p), &ca, NOW).err().unwrap();
        assert!(e.contains("it is stale"), "{e}");
        let allow = Settings {
            stale: Some(ClientCrlRule::Allow),
            ..settings(&p)
        };
        assert!(load_at(&allow, &ca, NOW).is_ok());
        // Exactly at nextUpdate is stale.
        assert!(load_at(&settings(&p), &ca, NOW - 1).is_err());
        assert!(load_at(&settings(&p), &ca, NOW - 2).is_ok());
        // thisUpdate ahead of the clock by more than the skew.
        let p = [dir.write("f.crl", root.crl(&[], NOW + 301, NOW + 3600, 1))];
        let e = load_at(&settings(&p), &ca, NOW).err().unwrap();
        assert!(e.contains("ahead of the server clock"), "{e}");
        let p = [dir.write("g.crl", root.crl(&[], NOW + 300, NOW + 3600, 1))];
        assert!(load_at(&settings(&p), &ca, NOW).is_ok());
    }

    #[test]
    fn the_lists_and_totals_are_bounded() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let ca = dir.ca_file("ca.pem", &[&root]);
        let one = dir.write("c.crl", root.crl(&[], NOW - 60, NOW + 3600, 1));
        let e = load_at(&settings(&[]), &ca, NOW).err().unwrap();
        assert!(e.contains("1 to 16 files"), "{e}");
        let e = load_at(&settings(&[one.clone(), one.clone()]), &ca, NOW)
            .err()
            .unwrap();
        assert!(e.contains("twice"), "{e}");
        let many: Vec<PathBuf> = (0..=MAX_CRLS_PER_ENTRY)
            .map(|i| dir.write(&format!("m{i}.crl"), b"x"))
            .collect();
        assert!(load_at(&settings(&many), &ca, NOW)
            .err()
            .unwrap()
            .contains("1 to 16"));
        // Two CRLs of one CA in one entry.
        let two = dir.write("d.crl", root.crl(&[], NOW - 60, NOW + 3600, 2));
        let e = load_at(&settings(&[one.clone(), two]), &ca, NOW)
            .err()
            .unwrap();
        assert!(e.contains("one CRL per CA"), "{e}");
        // Distinct files over a whole load.
        let mut loading = Loading::new(at(NOW));
        for i in 0..MAX_CRL_FILES {
            let cai = Ca::new(&format!("ca{i}"), None);
            let ca = dir.ca_file(&format!("ca{i}.pem"), &[&cai]);
            let p = [dir.write(&format!("n{i}.crl"), cai.crl(&[], NOW - 60, NOW + 3600, 1))];
            load(&settings(&p), &ca, &mut loading).unwrap();
        }
        // A file already read does not count again; a new one is refused.
        let p = [dir.write("last.crl", root.crl(&[], NOW - 60, NOW + 3600, 1))];
        let e = load(&settings(&p), &ca, &mut loading).err().unwrap();
        assert!(e.contains("more than 32 different CRL files"), "{e}");
        // Bytes over a whole load: a file of the largest size is fine, five are not.
        let mut loading = Loading::new(at(NOW));
        let big = vec![b' '; usize::try_from(MAX_CRL_FILE_BYTES).unwrap()];
        for i in 0..4 {
            let p = [dir.write(&format!("big{i}.crl"), &big)];
            let e = load(&settings(&p), &ca, &mut loading).err().unwrap();
            assert!(e.contains("the file is empty"), "{e}");
        }
        let p = [dir.write("big4.crl", &big)];
        let e = load(&settings(&p), &ca, &mut loading).err().unwrap();
        assert!(e.contains("more than 16 MiB together"), "{e}");
        let mut too_big = big.clone();
        too_big.push(b' ');
        let p = [dir.write("huge.crl", too_big)];
        let e = load_at(&settings(&p), &ca, NOW).err().unwrap();
        assert!(e.contains("larger than"), "{e}");
    }

    #[test]
    fn status_is_by_issuer_name_key_and_serial() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let ca = dir.ca_file("ca.pem", &[&root]);
        let leaf = root.leaf(7, "urn:a");
        let p = [dir.write("c.crl", root.crl(&[7], NOW - 60, NOW + 3600, 1))];
        let set = load_at(&settings(&p), &ca, NOW).unwrap();
        let (name, key) = (subject(&root), spki(&root));
        assert_eq!(
            set.status(&name, &key, &serial(&leaf), NOW),
            Status::Revoked
        );
        let other_leaf = root.leaf(8, "urn:a");
        assert_eq!(
            set.status(&name, &key, &serial(&other_leaf), NOW),
            Status::Good
        );
        // Revoked stays revoked once the CRL is stale; a good one is then unknown.
        assert_eq!(
            set.status(&name, &key, &serial(&leaf), NOW + 3600),
            Status::Revoked
        );
        assert_eq!(
            set.status(&name, &key, &serial(&other_leaf), NOW + 3600),
            Status::Stale
        );
        assert_eq!(
            set.status(&name, &key, &serial(&other_leaf), NOW + 3599),
            Status::Good
        );
        assert_eq!(set.cache_until(), Some(NOW + 3599));
        // Another key with the same name has no CRL here: as for a CA without one.
        let fake = root.impostor("root");
        assert_eq!(
            set.status(&name, &spki(&fake), &serial(&leaf), NOW),
            Status::Good
        );
        let strict = load_at(
            &Settings {
                missing: Some(ClientCrlRule::Refuse),
                stale: Some(ClientCrlRule::Allow),
                ..settings(&p)
            },
            &ca,
            NOW,
        )
        .unwrap();
        assert_eq!(
            strict.status(&name, &spki(&fake), &serial(&leaf), NOW),
            Status::Missing
        );
        assert_eq!(
            strict.status(&name, &key, &serial(&other_leaf), NOW + 7200),
            Status::Good
        );
        assert_eq!(strict.cache_until(), None);
        assert!(Status::Revoked.worst(Status::Good) == Status::Revoked);
        assert!(Status::Missing.worst(Status::Stale) == Status::Stale);
    }

    #[test]
    fn a_reload_never_puts_an_older_crl_in_force() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let ca = dir.ca_file("ca.pem", &[&root]);
        let set = |name: &str, der: Vec<u8>| {
            let p = [dir.write(name, der)];
            load_at(&settings(&p), &ca, NOW).unwrap()
        };
        let old = set("old.crl", root.crl(&[1], NOW - 600, NOW + 3600, 5));
        let check = |new: &CrlSet| check_not_older([&old].into_iter(), [new].into_iter());
        assert!(check(&set("same.crl", root.crl(&[1], NOW - 600, NOW + 3600, 5))).is_ok());
        assert!(check(&set(
            "newer.crl",
            root.crl(&[1, 2], NOW - 60, NOW + 3600, 6)
        ))
        .is_ok());
        let e = check(&set("earlier.crl", root.crl(&[], NOW - 900, NOW + 3600, 6)))
            .err()
            .unwrap();
        assert!(e.contains("earlier.crl") && e.contains("older"), "{e}");
        let e = check(&set("smaller.crl", root.crl(&[], NOW - 60, NOW + 3600, 4)))
            .err()
            .unwrap();
        assert!(e.contains("cRLNumber 04"), "{e}");
        // Numbers compare as numbers: 256 is more than 5.
        assert!(check(&set("big.crl", root.crl(&[], NOW - 60, NOW + 3600, 256))).is_ok());
        // Another CA's CRL, or none at all, is not a rollback.
        let other = Ca::new("other", None);
        let ca2 = dir.ca_file("ca2.pem", &[&other]);
        let p = [dir.write("o.crl", other.crl(&[], NOW - 9000, NOW + 3600, 1))];
        let o = load_at(&settings(&p), &ca2, NOW).unwrap();
        assert!(check(&o).is_ok());
        assert!(check_not_older([&old].into_iter(), std::iter::empty()).is_ok());
    }

    #[test]
    fn one_ca_has_one_crl_over_all_entries() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let ca = dir.ca_file("ca.pem", &[&root]);
        let a = [dir.write("a.crl", root.crl(&[1], NOW - 600, NOW + 3600, 5))];
        let b = [dir.write("b.crl", root.crl(&[1], NOW - 60, NOW + 3600, 6))];
        let mut loading = Loading::new(at(NOW));
        let x = load(&settings(&a), &ca, &mut loading).unwrap();
        let y = load(&settings(&a), &ca, &mut loading).unwrap();
        let z = load(&settings(&b), &ca, &mut loading).unwrap();
        assert!(check_consistent([&x, &y].into_iter()).is_ok());
        let e = check_consistent([&x, &y, &z].into_iter()).err().unwrap();
        assert!(e.contains("a.crl") && e.contains("b.crl"), "{e}");
        // Read once: both entries hold the same CRL.
        assert!(Arc::ptr_eq(
            x.crls().next().unwrap().2,
            y.crls().next().unwrap().2
        ));
    }

    #[test]
    fn the_der_reads() {
        assert!(facts(b"").is_none());
        assert!(signed_data(b"\x30\x00").is_none());
        assert!(signed_data(b"\x30\x06\x30\x00\x30\x00\x03\x00").is_none());
        let s = signed_data(b"\x30\x07\x30\x00\x30\x00\x03\x01\x00").unwrap();
        assert_eq!(
            (s.tbs, s.alg, s.signature),
            (&b"\x30\x00"[..], &b""[..], &b""[..])
        );
        // Unused bits in the signature, or bytes after it, are refused.
        assert!(signed_data(b"\x30\x07\x30\x00\x30\x00\x03\x01\x01").is_none());
        assert!(signed_data(b"\x30\x07\x30\x00\x30\x00\x03\x01\x00\x00").is_none());
        assert!(!verify_signature(b"", &s));
        let root = Ca::new("root", None);
        assert!(may_sign_crls(root.cert.der()));
        let no = Ca::with_usages("n", None, vec![rcgen::KeyUsagePurpose::KeyCertSign]);
        assert!(!may_sign_crls(no.cert.der()));
        let none = Ca::with_usages("n", None, vec![]);
        assert!(may_sign_crls(none.cert.der()));
        assert_eq!(date(0), "1970-01-01T00:00:00Z");
    }

    // --- DER made by hand, for encodings rcgen does not write -------------------------------

    fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = contents.len();
        if len < 0x80 {
            out.push(u8::try_from(len).unwrap());
        } else {
            let bytes: Vec<u8> = len
                .to_be_bytes()
                .into_iter()
                .skip_while(|b| *b == 0)
                .collect();
            out.push(0x80 | u8::try_from(bytes.len()).unwrap());
            out.extend(bytes);
        }
        out.extend_from_slice(contents);
        out
    }

    fn utc(secs: i64) -> Vec<u8> {
        let t = at(secs);
        let text = format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            t.year() % 100,
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        );
        tlv(0x17, text.as_bytes())
    }

    /// A CRL of `ca` (an ECDSA P-256 key) listing the serial numbers `serials` and with the
    /// `cRLNumber` `number`, as encoded here: leading zero bytes are kept.
    fn crl_by_hand(ca: &Ca, serials: &[&[u8]], number: &[u8], this: i64, next: i64) -> Vec<u8> {
        use rcgen::SigningKey as _;
        let alg = tlv(
            SEQUENCE,
            &tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]),
        );
        let mut tbs = tlv(0x02, &[1]);
        tbs.extend(&alg);
        tbs.extend(tlv(SEQUENCE, &subject(ca)));
        tbs.extend(utc(this));
        tbs.extend(utc(next));
        let entries: Vec<u8> = serials
            .iter()
            .flat_map(|s| tlv(SEQUENCE, &[tlv(0x02, s), utc(this)].concat()))
            .collect();
        if !entries.is_empty() {
            tbs.extend(tlv(SEQUENCE, &entries));
        }
        let mut ext = tlv(0x06, &CRL_NUMBER);
        ext.extend(tlv(0x04, &tlv(0x02, number)));
        tbs.extend(tlv(0xa0, &tlv(SEQUENCE, &tlv(SEQUENCE, &ext))));
        let tbs = tlv(SEQUENCE, &tbs);
        let signature = ca.key.sign(&tbs).unwrap();
        let mut bits = vec![0];
        bits.extend(signature);
        tlv(SEQUENCE, &[tbs, alg, tlv(0x03, &bits)].concat())
    }

    /// Serial numbers compare as numbers, with leading zero bytes stripped from the CRL's and
    /// the certificate's: `00 01` is `01`; two different numbers never compare equal.
    #[test]
    fn serial_numbers_compare_without_leading_zeros() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let ca = dir.ca_file("ca.pem", &[&root]);
        let der = crl_by_hand(
            &root,
            &[&[0x00, 0x01], &[0x05], &[0x00, 0x00, 0x80], &[0x00]],
            &[1],
            NOW - 60,
            NOW + 3600,
        );
        let p = [dir.write("c.crl", der)];
        let set = load_at(&settings(&p), &ca, NOW).unwrap();
        let (name, key) = (subject(&root), spki(&root));
        let status = |serial: &[u8]| set.status(&name, &key, serial, NOW);
        for listed in [
            &[0x01][..],
            &[0x00, 0x01],
            &[0x00, 0x00, 0x01],
            &[0x05],
            &[0x00, 0x05],
            &[0x80],
            &[0x00, 0x80],
            &[],
            &[0x00, 0x00],
        ] {
            assert_eq!(status(listed), Status::Revoked, "{listed:02x?}");
        }
        for other in [
            &[0x02][..],
            &[0x01, 0x00],
            &[0x01, 0x01],
            &[0x00, 0x01, 0x00],
            &[0x05, 0x00],
            &[0x81],
            &[0x80, 0x00],
        ] {
            assert_eq!(status(other), Status::Good, "{other:02x?}");
        }
        // A certificate rcgen writes with the shortest encoding.
        assert_eq!(
            set.status(&name, &key, &serial(&root.leaf(1, "urn:a")), NOW),
            Status::Revoked
        );
        assert_eq!(
            set.status(&name, &key, &serial(&root.leaf(256, "urn:a")), NOW),
            Status::Good
        );
    }

    /// `cRLNumber`s compare as numbers: the leading zero byte DER needs before a first byte
    /// of 0x80 or more does not count, and a large number in force is not passed by a smaller
    /// one. A number with leading zero bytes DER does not need is refused at load, as
    /// rustls-webpki's parser refuses it.
    #[test]
    fn crl_numbers_compare_as_numbers() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let ca = dir.ca_file("ca.pem", &[&root]);
        let read = |name: &str, number: &[u8], this: i64| {
            let p = [dir.write(name, crl_by_hand(&root, &[], number, this, NOW + 3600))];
            load_at(&settings(&p), &ca, NOW)
        };
        let set = |name: &str, number: &[u8], this: i64| read(name, number, this).unwrap();
        for padded in [&[0x00, 0x05][..], &[0x00, 0x00, 0x80], &[0x00, 0x01, 0x00]] {
            let e = read("padded.crl", padded, NOW - 60).err().unwrap();
            assert!(
                e.contains("cannot be read as an X.509 CRL"),
                "{padded:02x?}: {e}"
            );
        }
        // 2^72, in force.
        let big = [0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let old = set("big.crl", &big, NOW - 600);
        assert_eq!(
            old.crls().next().unwrap().2.number.as_deref(),
            Some(&big[..])
        );
        let check = |new: &CrlSet| check_not_older([&old].into_iter(), [new].into_iter());
        // 255, with its needed leading zero byte: smaller.
        let small = set("small.crl", &[0x00, 0xff], NOW - 60);
        assert_eq!(
            small.crls().next().unwrap().2.number.as_deref(),
            Some(&[0xffu8][..])
        );
        let e = check(&small).err().unwrap();
        assert!(
            e.contains("cRLNumber ff") && e.contains("01000000000000000000"),
            "{e}"
        );
        // 2^87, with its leading zero byte: larger, though its first byte is smaller.
        let larger = set(
            "larger.crl",
            &[0x00, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            NOW - 60,
        );
        assert!(check(&larger).is_ok());
        let one_more = set("more.crl", &[0x01, 0, 0, 0, 0, 0, 0, 0, 0, 1], NOW - 60);
        assert!(check(&one_more).is_ok());
        let same_number = set("same.crl", &big, NOW - 60);
        assert!(check(&same_number).is_ok());
        let one_less = set(
            "less.crl",
            &[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            NOW - 60,
        );
        assert!(check(&one_less).is_err());
        // A larger number with an earlier thisUpdate is still older.
        let earlier = set("earlier.crl", &[0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0], NOW - 900);
        assert!(check(&earlier).is_err());
    }

    /// CRLs signed with ECDSA P-256 and P-384, Ed25519 and RSA keys load, and their lists are
    /// used; one changed byte of the signature is refused.
    #[test]
    fn signers_of_each_algorithm() {
        let dir = Dir::new();
        for alg in [
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P384_SHA384,
            &rcgen::PKCS_ED25519,
        ] {
            let root = Ca::with_alg("root", alg);
            let ca = dir.ca_file("ca.pem", &[&root]);
            let der = root.crl(&[9], NOW - 60, NOW + 3600, 1);
            let p = [dir.write("c.crl", &der)];
            let set = load_at(&settings(&p), &ca, NOW).unwrap();
            let (name, key) = (subject(&root), spki(&root));
            assert_eq!(
                set.status(&name, &key, &[9], NOW),
                Status::Revoked,
                "{alg:?}"
            );
            assert_eq!(set.status(&name, &key, &[8], NOW), Status::Good, "{alg:?}");
            let mut bad = der.clone();
            let last = bad.len() - 1;
            bad[last] ^= 1;
            let p = [dir.write("bad.crl", bad)];
            let e = load_at(&settings(&p), &ca, NOW).err().unwrap();
            assert!(e.contains("signed by another key"), "{alg:?}: {e}");
        }
        // RSA (sha256WithRSAEncryption): a CA and a CRL made with openssl, kept here as the
        // public files only (rcgen cannot make RSA keys).
        let ca = crate::client_pki::ca_file(RSA_CA.as_bytes()).unwrap();
        let p = [dir.write("rsa.crl", RSA_CRL)];
        // Within the CRL's dates (2026-11-25 to 2035-02-11).
        let t = 1_811_808_000;
        let set = load_at(&settings(&p), &ca, t).unwrap();
        let (a, der) = ca.anchors().next().unwrap();
        let (name, key) = (a.subject.as_ref(), a.subject_public_key_info.as_ref());
        assert_eq!(set.status(name, key, &[0x2a], t), Status::Revoked);
        assert_eq!(set.status(name, key, &[0x2b], t), Status::Good);
        assert!(may_sign_crls(der));
        let crl = parse(Path::new("x"), RSA_CRL.as_bytes()).unwrap().0;
        assert_eq!(crl.number.as_deref(), Some(&[7u8][..]));
        let mut bad = file_der(RSA_CRL.as_bytes()).unwrap();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        let p = [dir.write("rsa-bad.crl", bad)];
        let e = load_at(&settings(&p), &ca, t).err().unwrap();
        assert!(e.contains("signed by another key"), "{e}");
    }

    /// A CA made with `openssl req -x509` (RSA 2048, `CA:TRUE`, `keyCertSign` and `cRLSign`).
    const RSA_CA: &str = "-----BEGIN CERTIFICATE-----
MIIC8jCCAdqgAwIBAgICEjQwDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAwwPY3Js
IHRlc3QgUlNBIENBMB4XDTI2MTEyNTIzMjg0NloXDTM2MTEyMjIzMjg0NlowGjEY
MBYGA1UEAwwPY3JsIHRlc3QgUlNBIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAoZbGeQLFyNe3VS/ZxcJCjO7OOt4HMRTNG/T2dZZ1HRA938+VqBIw
tR8PGYalEMo6sVQ/FoxwL2+MTdRtIofveoCmM4S/Pmu6S5Z/shnSbDUTiVXa/mxm
WGwM7krT/aY80GVW8t/XDANv778cT7rbSkfqeMIwM4YOT06oMZ3HbG3tbOcvEA3Q
hISbTJ+qj3UusKua4SwGxka0MShLXX4G9IqBn7W84wyKeYTAkYfIzY+VSD4E7yhw
3zJXMc7130ZS6c9CJ9BaSQvFZjyJQCF7OjNZ29aLmLvuHDc3pc8gqixodogHnKCs
BPk6yAC/nf9kpiu3BPjMkNn07Jyt108hXQIDAQABo0IwQDAPBgNVHRMBAf8EBTAD
AQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUd6KJAw119sYMswTIss6Gmh1Y
r8IwDQYJKoZIhvcNAQELBQADggEBAI2ZHRiQzWQH6VWtMMBxdN1Aexdk7uaqQUHM
7vDEUqWcdYunHB3I5FyPtE010SDDHfNZVv/NLbPeeg24n3+qwkt9DvuiBpIepKVX
WphokODsm4jhpDsl60UWyOlVDBLR4nQnsjreNPGj00YvotE/lmjl7Ot87zukFqml
TnhUbl+MUjPvUoDRHWmXf1WE3gbW8b19T23p+l2XSuUVJEQMyoIU4rwV32rndMU6
q/UNEMT1BcLf/MzdjtbbuZLhxx3uOb4Px2srkOJTDJ3itqryQJBExvmucpfvrhPo
rDm5igZv4Wk6esYAugB3/ayvCez4QCEgLR9rtX1XT569rdmhr8M=
-----END CERTIFICATE-----
";

    /// That CA's CRL from `openssl ca -gencrl`: serial number `2a` revoked, `cRLNumber` 7.
    const RSA_CRL: &str = "-----BEGIN X509 CRL-----
MIIBqjCBkwIBATANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDDA9jcmwgdGVzdCBS
U0EgQ0EXDTI2MTEyNTIzMjg0NloXDTM1MDIxMTIzMjg0NlowFDASAgEqFw0yNjAx
MDEwMDAwMDBaoC8wLTAfBgNVHSMEGDAWgBR3ookDDXX2xgyzBMiyzoaaHVivwjAK
BgNVHRQEAwIBBzANBgkqhkiG9w0BAQsFAAOCAQEADrBhd77RtZIcYveWuXgc6aQd
/0GE0nWtjiMtwXH2Q30xbSjTijpe4VkiAe827iL+jRYmlEbhKAA+p2OgAwYrByju
6rVaETDjGcH7wibCYAmHLRP+9dLzXeXoLV1xcoOWDtQgTPg6VDBixN9Pde+CBdim
iAFtXDGXVM841bsndn6RzUNgHuxDICEYMnD/2WvQTyB1zaxatlUUQPPhyT4iG9yd
FUf681lvm/SY8PiGiAc8cEZOOFLjLQAUEEQipJ03GNO6fs9AsQyxwBnH6oGLA5kO
9HVWiTxCnq7KHCX9F1Ma+fczsWbkJq2rr9rju3LwTvSt0Z/l3Jt0DRxuRNrFrg==
-----END X509 CRL-----
";

    /// One CRL file checked against one CA key once per load, whatever the number of entries
    /// that list it.
    #[test]
    fn a_crl_signature_is_checked_once_per_load() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let ca = dir.ca_file("ca.pem", &[&root]);
        let other_ca = dir.ca_file("other.pem", &[&root.impostor("root")]);
        let p = [dir.write("c.crl", root.crl(&[], NOW - 60, NOW + 3600, 1))];
        let mut loading = Loading::new(at(NOW));
        for _ in 0..3 {
            load(&settings(&p), &ca, &mut loading).unwrap();
        }
        assert_eq!(loading.signature_checks, 1);
        // The same name with another key: checked once more, and refused each time.
        for _ in 0..2 {
            let e = load(&settings(&p), &other_ca, &mut loading).err().unwrap();
            assert!(e.contains("signed by another key"), "{e}");
        }
        assert_eq!(loading.signature_checks, 2);
    }

    /// The signatures between the CA certificates of an entry are checked once per load for
    /// each pair of CA file and issuer file, however many entries share the pair.
    #[test]
    fn the_issuer_graph_is_built_once_per_pair_of_files() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let mid = Ca::numbered("mid", &root, 42);
        let ca = dir.ca_file("ca.pem", &[&root, &mid]);
        let issuers = dir.write("issuers.pem", mid.cert.pem());
        let p = [dir.write("root.crl", root.crl(&[], NOW - 60, NOW + 3600, 1))];
        let with_issuers = Settings {
            issuers: Some(&issuers),
            ..settings(&p)
        };
        let mut loading = Loading::new(at(NOW));
        for _ in 0..3 {
            load(&settings(&p), &ca, &mut loading).unwrap();
            load(&with_issuers, &ca, &mut loading).unwrap();
        }
        assert_eq!(loading.graph_builds, 2);
        // The same file content at another path is the same pair.
        let again = dir.ca_file("again.pem", &[&root, &mid]);
        load(&settings(&p), &again, &mut loading).unwrap();
        assert_eq!(loading.graph_builds, 2);
        // A new load checks again.
        let mut loading = Loading::new(at(NOW));
        load(&settings(&p), &ca, &mut loading).unwrap();
        assert_eq!(loading.graph_builds, 1);
    }

    /// A certificate of `tls_client_crl_issuer_pem_path` must have started and be issued by a
    /// CA allowed to sign certificates. One that has expired, or that a CRL of the entry
    /// revokes, has the CRL it signs ignored: what it issued is refused as unknown.
    #[test]
    fn issuer_file_certificates_are_checked() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let mid = Ca::numbered("mid", &root, 42);
        let ca = dir.ca_file("ca.pem", &[&root]);
        let issuers = dir.write("issuers.pem", mid.cert.pem());
        let with = |paths: &[PathBuf], t: i64| {
            load_at(
                &Settings {
                    issuers: Some(&issuers),
                    ..settings(paths)
                },
                &ca,
                t,
            )
        };
        // Valid from NOW - 1 day to NOW + 1 day. Not valid yet: refused.
        let t = NOW - 86_401;
        let p = [dir.write("mid.crl", mid.crl(&[], t - 60, t + 3600, 1))];
        let e = with(&p, t).err().unwrap();
        assert!(
            e.contains("certificate 1 of the file is not valid yet"),
            "{e}"
        );
        assert!(e.contains("tls_client_crl_issuer_pem_path"), "{e}");
        // Expired: loaded, its CRL ignored, and what it issued refused as unknown although
        // tls_client_crl_missing is "allow"; the root's certificates are unaffected.
        let t = NOW + 86_400;
        let p = [
            dir.write("mid.crl", mid.crl(&[], t - 60, t + 3600, 1)),
            dir.write("root.crl", root.crl(&[], t - 60, t + 3600, 1)),
        ];
        let set = with(&p, t).unwrap();
        assert_eq!(
            set.status(&subject(&mid), &spki(&mid), &[5], t),
            Status::Ignored
        );
        assert_eq!(
            set.status(&subject(&root), &spki(&root), &[5], t),
            Status::Good
        );
        assert_eq!(set.ignored_crls, [("CN=mid".to_owned(), Ignored::Expired)]);
        let mid_crl = dir.write("mid.crl", mid.crl(&[], NOW - 60, NOW + 3600, 1));
        let set = with(std::slice::from_ref(&mid_crl), NOW).unwrap();
        assert_eq!(
            set.status(&subject(&mid), &spki(&mid), &[5], NOW),
            Status::Good
        );
        assert!(set.ignored_crls.is_empty());
        // The root's CRL revokes the intermediate: loaded, the intermediate's CRL ignored,
        // and every certificate it issued refused as unknown, under either missing rule.
        let root_crl = dir.write("root.crl", root.crl(&[42], NOW - 60, NOW + 3600, 1));
        let set = with(&[root_crl.clone(), mid_crl.clone()], NOW).unwrap();
        assert_eq!(
            set.status(&subject(&mid), &spki(&mid), &[5], NOW),
            Status::Ignored
        );
        assert_eq!(
            set.status(&subject(&root), &spki(&root), &[42], NOW),
            Status::Revoked
        );
        assert_eq!(
            set.status(&subject(&root), &spki(&root), &[43], NOW),
            Status::Good
        );
        assert_eq!(set.ignored_crls, [("CN=mid".to_owned(), Ignored::Revoked)]);
        // Without the intermediate's own CRL, nothing is ignored: its certificates follow
        // tls_client_crl_missing, and the path through it is revoked at the intermediate.
        let set = with(std::slice::from_ref(&root_crl), NOW).unwrap();
        assert!(set.ignored_crls.is_empty());
        assert_eq!(
            set.status(&subject(&mid), &spki(&mid), &[5], NOW),
            Status::Good
        );
        // An ignored CRL is neither stale-checked nor compared by a reload: the intermediate's
        // last CRL, past its nextUpdate and older than the one in force, does not hold back the
        // root's revocation. A certificate it lists is still revoked; the rest is unknown.
        let in_force = with(
            &[
                dir.write("root.crl", root.crl(&[], NOW - 60, NOW + 3600, 1)),
                dir.write("mid.crl", mid.crl(&[7], NOW - 60, NOW + 3600, 5)),
            ],
            NOW,
        )
        .unwrap();
        let stale_mid = dir.write("mid.crl", mid.crl(&[7], NOW - 7200, NOW - 3600, 4));
        let root_crl = dir.write("root.crl", root.crl(&[42], NOW - 60, NOW + 3600, 2));
        let set = with(&[root_crl.clone(), stale_mid.clone()], NOW).unwrap();
        assert_eq!(set.ignored_crls, [("CN=mid".to_owned(), Ignored::Revoked)]);
        assert_eq!(
            set.status(&subject(&mid), &spki(&mid), &[7], NOW),
            Status::Revoked
        );
        assert_eq!(
            set.status(&subject(&mid), &spki(&mid), &[0, 7], NOW),
            Status::Revoked
        );
        assert_eq!(
            set.status(&subject(&mid), &spki(&mid), &[8], NOW),
            Status::Ignored
        );
        assert_eq!(set.cache_until(), Some(NOW + 3599));
        check_not_older(std::iter::once(&in_force), std::iter::once(&set)).unwrap();
        // Not ignored, the same stale CRL refuses the load.
        let e = with(std::slice::from_ref(&stale_mid), NOW).err().unwrap();
        assert!(e.contains("mid.crl"), "{e}");
        // Its other date checks stay: a thisUpdate far ahead is refused.
        let bad = dir.write("mid.crl", mid.crl(&[], NOW + 3600, NOW + 7200, 6));
        let e = with(&[root_crl, bad], NOW).err().unwrap();
        assert!(e.contains("mid.crl") && e.contains("thisUpdate"), "{e}");
        // An intermediate issued by a CA whose keyUsage leaves keyCertSign out. rcgen
        // refuses to sign with it, so it signs through parameters without key usages.
        let mut no_certs = Ca::with_usages("nocerts", None, vec![rcgen::KeyUsagePurpose::CrlSign]);
        let ca2 = dir.ca_file("ca2.pem", &[&no_certs]);
        no_certs.params.key_usages.clear();
        let under = Ca::new("under", Some(&no_certs));
        let issuers2 = dir.write("issuers2.pem", under.cert.pem());
        let p = [dir.write("under.crl", under.crl(&[], NOW - 60, NOW + 3600, 1))];
        let e = load_at(
            &Settings {
                issuers: Some(&issuers2),
                ..settings(&p)
            },
            &ca2,
            NOW,
        )
        .err()
        .unwrap();
        assert!(e.contains("leaves keyCertSign out"), "{e}");
    }

    /// The anchors a CRL of the entry revokes, and the CAs without a CRL under
    /// `tls_client_crl_missing = "allow"`, are kept by name for the warnings of
    /// [`log_in_force`]; none under "refuse", which refuses their certificates instead.
    #[test]
    fn revoked_anchors_and_cas_without_a_crl_are_named() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let mid = Ca::numbered("mid", &root, 99);
        let leafless = Ca::with_usages("crl only", None, vec![rcgen::KeyUsagePurpose::CrlSign]);
        let ca = dir.ca_file("ca.pem", &[&root, &mid, &leafless]);
        let p = [dir.write("root.crl", root.crl(&[99], NOW - 60, NOW + 3600, 1))];
        let set = load_at(&settings(&p), &ca, NOW).unwrap();
        assert_eq!(set.revoked_anchors, ["CN=mid"]);
        // The root has its CRL; a CA that may not sign certificates issues no client's.
        assert_eq!(set.uncovered, ["CN=mid"]);
        assert_eq!(
            set.anchor_status(&subject(&mid), &spki(&mid), NOW),
            Status::Revoked
        );
        assert_eq!(
            set.anchor_status(&subject(&root), &spki(&root), NOW),
            Status::Good
        );
        let strict = load_at(
            &Settings {
                missing: Some(ClientCrlRule::Refuse),
                ..settings(&p)
            },
            &ca,
            NOW,
        )
        .unwrap();
        assert!(strict.uncovered.is_empty());
        assert_eq!(strict.revoked_anchors, ["CN=mid"]);
        // Not revoked: no warning for it.
        let p = [dir.write("root2.crl", root.crl(&[], NOW - 60, NOW + 3600, 1))];
        let set = load_at(&settings(&p), &ca, NOW).unwrap();
        assert!(set.revoked_anchors.is_empty());
        log_in_force([&set, &strict].into_iter());
    }

    #[test]
    fn names_read_as_text() {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "a\nb\u{202e}");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Example");
        params.distinguished_name.push(
            rcgen::DnType::CustomDnType(vec![1, 2, 3]),
            rcgen::DnValue::PrintableString("x".try_into().unwrap()),
        );
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let name = crate::client_pki::tbs(cert.der()).unwrap().subject.to_vec();
        assert_eq!(name_text(&name), "CN=a\\nb\\u{202e}, O=Example, ?=x");
        assert_eq!(name_text(b"\x31"), "(unreadable name)");
        let long = "x".repeat(100);
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        for t in [
            rcgen::DnType::CommonName,
            rcgen::DnType::OrganizationName,
            rcgen::DnType::OrganizationalUnitName,
            rcgen::DnType::LocalityName,
            rcgen::DnType::StateOrProvinceName,
        ] {
            params.distinguished_name.push(t, &long);
        }
        let cert = params.self_signed(&key).unwrap();
        let name = crate::client_pki::tbs(cert.der()).unwrap().subject.to_vec();
        let text = name_text(&name);
        assert!(
            text.ends_with("...") && text.chars().count() == NAME_CHARS + 3,
            "{text}"
        );
        assert!(text.starts_with(&format!("CN={}, ", "x".repeat(NAME_VALUE_CHARS))));
    }
}
