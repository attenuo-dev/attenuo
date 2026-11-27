//! RFC 8705 §2.1 `tls_client_auth`: a TLS client certificate issued by a CA, matched by one
//! subject alternative name.
//!
//! An `[[agents]]` or `[[peps]]` entry names a PEM file of CA certificates
//! (`tls_client_ca_pem_path`) and exactly one name the client's certificate must carry: a URI
//! (`tls_client_auth_san_uri`) or a DNS name (`tls_client_auth_san_dns`). The TLS layer
//! proved that the client holds the certificate's key ([`crate::client_cert_verifier`]) and
//! kept the intermediates the client sent ([`ClientCertificate`]). Here, per request:
//!
//! 1. rustls-webpki builds a path from the certificate, through those intermediates, to one of
//!    the entry's CA certificates, for client use (`verify_for_usage` with
//!    [`webpki::KeyUsage::client_auth`]) at the request's time. That checks every
//!    signature in the path with the algorithms of the listener's `ring` provider, the dates
//!    of every certificate in the path, `basicConstraints` (the client's certificate must not
//!    be a CA, every issuer must be one, path lengths), the extended key usage (`clientAuth`
//!    when the certificate lists any), unknown critical extensions, and the name constraints
//!    of the CAs (URI name constraints are not supported by rustls-webpki and refuse the
//!    certificate). With `tls_client_crl_paths`, each path rustls-webpki finds is also
//!    checked against the entry's CRLs ([`crate::client_crl`]): a path in which the client's
//!    certificate or an intermediate is listed by the CRL of its issuer (or, by the settings,
//!    whose issuer's CRL is stale or missing) is refused, and the next path is tried. The
//!    lookups are by issuer name and key, then serial number, in maps: no signature check and
//!    no scan per request. No OCSP, nothing fetched.
//! 2. The name. A URI is compared exactly, byte for byte. A `spiffe://` value also needs the
//!    certificate to carry exactly one URI name, as an X.509-SVID does. A DNS name is
//!    compared without regard to ASCII case; a wildcard name in the certificate
//!    (`*.example.org`) never matches, since the configured name cannot be a wildcard. The
//!    subject DN, IP addresses and e-mail addresses are never matched.
//!
//! The CA file is read at start and by an agents reload, with the size and file-type rules of
//! the other CA files. No error shows a part of the file: every message is a fixed text.
//!
//! ## Cost before authentication
//!
//! The path check runs before the client is authenticated, on certificates the client chose.
//! What bounds it:
//!
//! - At most [`MAX_INTERMEDIATES`](crate::client_cert::MAX_INTERMEDIATES) certificates after
//!   the client's own; a chain with more is refused without a path check.
//! - [`useful_intermediates`], once per connection, drops the intermediates that cannot help
//!   a path: unreadable ones, a copy of the client's certificate, self-issued ones (subject =
//!   issuer; a path ends at a CA of the file, never at one the client sent) and every one after
//!   the first with a given subject. With one intermediate per subject, each step of path
//!   building has at most one intermediate to try, so the work is linear in the four, not the
//!   number of paths through them.
//! - rustls-webpki's own limits: at most six CA certificates between the client's and the
//!   trust anchor, and at most 100 signature checks per verification.
//! - A per-connection cache ([`PerConnection`]): a request on a connection whose certificate
//!   already passed (or failed on its names) for the same CA file and name is answered from
//!   it, while the answer still holds.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};

use rustls::pki_types::pem::{PemObject, SectionKind};
use rustls::pki_types::{CertificateDer, TrustAnchor, UnixTime};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::client_cert::ClientCertificate;
use crate::client_crl::{CrlSet, Status};

/// Most CA certificates one `tls_client_ca_pem_path` file may hold. A trust domain has one
/// or a few; more room is for a rotation.
pub(crate) const MAX_CA_CERTS: usize = 16;
/// Longest `tls_client_auth_san_uri`, in bytes.
const MAX_SAN_URI_BYTES: usize = 2048;
/// Longest `tls_client_auth_san_dns`, in bytes (RFC 1035).
const MAX_SAN_DNS_BYTES: usize = 253;
/// Most names of a refused certificate written to the debug log, and the longest one.
const LOGGED_NAMES: usize = 8;
const LOGGED_NAME_CHARS: usize = 256;
/// Most answers one connection keeps ([`PerConnection`]): one per CA file and name it was
/// checked against, the oldest dropped first.
const CACHED_ANSWERS: usize = 8;
/// Most certificates whose state the forwarding listener keeps ([`SharedStates`]), the oldest
/// dropped first.
const SHARED_STATES: usize = 256;
/// The refusals that depend on nothing but the certificate's names, once its path was
/// accepted: true at any later time, so kept for the connection.
const NAME_REFUSALS: [&str; 2] = ["uri_san_count", "san_mismatch"];

/// The CA certificates of one `tls_client_ca_pem_path` file, as trust anchors.
pub(crate) struct CaFile {
    anchors: Vec<TrustAnchor<'static>>,
    /// The certificates the anchors were made from, in the same order: the CRL check reads
    /// their key usage ([`crate::client_crl`]).
    certs: Vec<CertificateDer<'static>>,
    /// The lowercase hex SHA-256 of the file's bytes as they were read, for the list digest
    /// and the changes of a reload.
    sha256: String,
}

impl std::fmt::Debug for CaFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaFile")
            .field("certificates", &self.anchors.len())
            .finish_non_exhaustive()
    }
}

impl CaFile {
    /// The lowercase hex SHA-256 of the file's bytes.
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    /// How many CA certificates the file holds.
    pub(crate) fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Each CA certificate as a trust anchor, with the certificate it was made from.
    pub(crate) fn anchors(&self) -> impl Iterator<Item = (&TrustAnchor<'static>, &[u8])> {
        self.anchors
            .iter()
            .zip(self.certs.iter().map(|c| c.as_ref()))
    }
}

/// The CA files read for one start or reload, by path, so that each is read once and the
/// agents and the PEPs that name one see the same bytes.
pub(crate) type CaFiles = Vec<(PathBuf, Arc<CaFile>)>;

/// The name a client's certificate must carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SanName {
    /// `tls_client_auth_san_uri`, as written; `spiffe` when it is a SPIFFE ID.
    Uri { value: String, spiffe: bool },
    /// `tls_client_auth_san_dns`, in lowercase.
    Dns(String),
}

impl SanName {
    /// The config key the name came from.
    pub(crate) fn key(&self) -> &'static str {
        match self {
            SanName::Uri { .. } => "tls_client_auth_san_uri",
            SanName::Dns(_) => "tls_client_auth_san_dns",
        }
    }

    /// The value compared with the certificate's names (a DNS name in lowercase).
    pub(crate) fn value(&self) -> &str {
        match self {
            SanName::Uri { value, .. } | SanName::Dns(value) => value,
        }
    }
}

/// The `tls_client_auth` settings of one entry.
pub(crate) struct Pki {
    pub(crate) ca_path: PathBuf,
    pub(crate) ca: Arc<CaFile>,
    pub(crate) name: SanName,
    /// The entry's CRLs (`tls_client_crl_paths`), read when the list was built.
    pub(crate) crls: Option<Arc<CrlSet>>,
}

impl std::fmt::Debug for Pki {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pki")
            .field("ca_path", &self.ca_path)
            .field("ca_certificates", &self.ca.len())
            .field("name", &self.name.key())
            .field("crls", &self.crls)
            .finish()
    }
}

/// Check `tls_client_auth_san_uri`: an absolute URI of printable ASCII, at most
/// [`MAX_SAN_URI_BYTES`]; a `spiffe:` one (in any case) must be a valid SPIFFE ID
/// ([`crate::actor::parse_spiffe_id`]). The message never quotes the value.
pub(crate) fn san_uri(value: &str) -> Result<SanName, String> {
    if value.is_empty() || value.len() > MAX_SAN_URI_BYTES {
        return Err(format!("must be 1 to {MAX_SAN_URI_BYTES} characters"));
    }
    if !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("must be printable ASCII, with no spaces".into());
    }
    let scheme = value.split_once(':').map(|(s, _)| s).unwrap_or_default();
    let scheme_ok = scheme
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic())
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b));
    if !scheme_ok || value.len() == scheme.len() + 1 {
        return Err("must be an absolute URI (scheme:rest)".into());
    }
    let spiffe = scheme.eq_ignore_ascii_case("spiffe");
    if spiffe && crate::actor::parse_spiffe_id(value).is_none() {
        return Err(
            "is not a valid SPIFFE ID: spiffe://<trust domain>/<path>, with a lowercase trust \
             domain, a non-empty path, and no port, query or fragment"
                .into(),
        );
    }
    Ok(SanName::Uri {
        value: value.to_owned(),
        spiffe,
    })
}

/// Check `tls_client_auth_san_dns`: one DNS name, not a wildcard, not an IP address, no
/// trailing dot. Kept in lowercase. The message never quotes the value.
pub(crate) fn san_dns(value: &str) -> Result<SanName, String> {
    if value.contains('*') {
        return Err("must name one host; a wildcard is not allowed".into());
    }
    if value.parse::<std::net::IpAddr>().is_ok() {
        return Err("is an IP address; only DNS names are matched".into());
    }
    if value.is_empty()
        || value.len() > MAX_SAN_DNS_BYTES
        || value.ends_with('.')
        || rustls::pki_types::DnsName::try_from(value).is_err()
    {
        return Err(
            "is not a valid DNS name (letters, digits and hyphens in dot-separated labels, no \
             trailing dot)"
                .into(),
        );
    }
    Ok(SanName::Dns(value.to_ascii_lowercase()))
}

/// Read a `tls_client_ca_pem_path` file: a regular file of at most
/// [`crate::idp::jwks::MAX_CA_FILE_BYTES`], with only `CERTIFICATE` blocks, 1 to
/// [`MAX_CA_CERTS`] of them, each an X.509 certificate with `basicConstraints` `CA:TRUE`.
///
/// # Errors
///
/// A fixed message, without the path (callers name it) and without any part of the file.
pub(crate) fn read_ca_file(path: &Path) -> Result<CaFile, String> {
    let pem = crate::tls::read_file(path, crate::idp::jwks::MAX_CA_FILE_BYTES, false)?;
    ca_file(&pem)
}

/// [`read_ca_file`] of the bytes of the file.
pub(crate) fn ca_file(pem: &[u8]) -> Result<CaFile, String> {
    if pem.iter().all(u8::is_ascii_whitespace) {
        return Err("the file is empty; it must hold PEM CA certificates".into());
    }
    // Any mention counts, an encrypted or malformed key included. Nothing is decoded first.
    if crate::tls::mentions_private_key(pem) {
        return Err(
            "the file holds a private key; it must hold CA certificates only, and the CA's key \
             never belongs on this server"
                .into(),
        );
    }
    // The parser's error is never shown: some of its variants quote a line of the file.
    let sections = <(SectionKind, Vec<u8>)>::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "not a valid PEM file".to_owned())?;
    // The parser skips blocks with a label it does not know: count the block starts, so that
    // those are refused too.
    let begins = pem.windows(11).filter(|w| w == b"-----BEGIN ").count();
    if sections.len() != begins || sections.iter().any(|(k, _)| *k != SectionKind::Certificate) {
        return Err(
            "the file holds a PEM block other than CERTIFICATE; it must hold CA certificates \
             only"
                .into(),
        );
    }
    if sections.is_empty() {
        return Err("no PEM certificate (-----BEGIN CERTIFICATE-----) in the file".into());
    }
    if sections.len() > MAX_CA_CERTS {
        return Err(format!(
            "the file holds {} certificates; at most {MAX_CA_CERTS} are allowed",
            sections.len()
        ));
    }
    let mut anchors = Vec::with_capacity(sections.len());
    let mut certs = Vec::with_capacity(sections.len());
    for (i, (_, der)) in sections.into_iter().enumerate() {
        let n = i + 1;
        let der = CertificateDer::from(der);
        if webpki::EndEntityCert::try_from(&der).is_err() {
            return Err(format!(
                "certificate {n} of the file cannot be read as an X.509 certificate"
            ));
        }
        if !is_ca(der.as_ref()) {
            return Err(format!(
                "certificate {n} of the file is not a CA certificate (basicConstraints CA:TRUE); \
                 list the CA that issues the client certificates, not a client certificate"
            ));
        }
        let anchor = webpki::anchor_from_trusted_cert(&der)
            .map_err(|_| format!("certificate {n} of the file cannot be used as a trust anchor"))?;
        anchors.push(anchor.to_owned());
        certs.push(der);
    }
    Ok(CaFile {
        anchors,
        certs,
        sha256: hex::encode(Sha256::digest(pem)),
    })
}

/// Why a certificate does not authenticate an entry with `tls_client_auth`, for the debug log
/// only: every refusal is answered as any other failed client authentication (SR-110).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refused {
    pub(crate) reason: &'static str,
    /// The certificate's names of the matched kind, for a name that did not match: written to
    /// the debug log escaped, a few and cut short, since the client chose them.
    pub(crate) names: Vec<String>,
}

impl Refused {
    fn because(reason: &'static str) -> Self {
        Self {
            reason,
            names: Vec::new(),
        }
    }
}

/// The per-connection state of the CA check, kept with a [`ClientCertificate`] and shared by
/// the requests of its connection.
///
/// The cache holds, per CA file and name, the last answer that is still known to hold:
///
/// - The key is the identity of the CA file in force (the `Arc` the entry holds; a reload
///   reads the file again into a new one, so its old answers never match again), the identity
///   of the entry's CRLs in force (the same way: every start and reload reads the CRL files
///   into a new [`CrlSet`], so an answer from before a CRL change never matches again) and the
///   configured name. Two entries with different names never share an answer. The cache holds
///   the old file and CRLs only weakly, so their addresses are not reused while an answer
///   names them.
/// - An accepted path is kept with the time it was checked and the earliest `notAfter` of the
///   client's certificate and the intermediates kept: it is used only from that time (a clock
///   set back checks again) up to that `notAfter`, and, with CRLs whose staleness refuses
///   (`tls_client_crl_stale = "refuse"`), up to one second before the earliest `nextUpdate`
///   of the entry's CRLs ([`CrlSet::cache_until`]). An expired certificate is checked again,
///   and refused; so is one whose CRL went stale, with no reload.
/// - A revocation refusal is never kept: it is checked again on the next request.
/// - A refusal of the name ([`NAME_REFUSALS`]) holds at any time, since it came after an
///   accepted path. Every other refusal (dates, path, usage) is checked again on the next
///   request: a certificate that is not yet valid may become valid.
/// - At most [`CACHED_ANSWERS`] answers.
pub(crate) struct PerConnection {
    /// The earliest `notAfter` of the client's certificate and the intermediates kept, in
    /// Unix seconds; `None` when one cannot be read, and then nothing is cached.
    not_after: Option<i64>,
    names: OnceLock<CertNames>,
    cache: Mutex<Vec<Cached>>,
}

impl std::fmt::Debug for PerConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerConnection").finish_non_exhaustive()
    }
}

struct Cached {
    ca: Weak<CaFile>,
    crls: Option<Weak<CrlSet>>,
    name: SanName,
    answer: Answer,
}

impl Cached {
    /// Whether this answer is for `pki`: the same CA file, the same CRLs (or none for both)
    /// and the same name.
    fn is_for(&self, pki: &Pki) -> bool {
        let same_crls = match (&self.crls, &pki.crls) {
            (None, None) => true,
            (Some(a), Some(b)) => std::ptr::eq(a.as_ptr(), Arc::as_ptr(b)),
            _ => false,
        };
        std::ptr::eq(self.ca.as_ptr(), Arc::as_ptr(&pki.ca)) && same_crls && self.name == pki.name
    }

    /// Whether what this answer names is still held by someone.
    fn alive(&self) -> bool {
        self.ca.strong_count() > 0 && self.crls.as_ref().is_none_or(|c| c.strong_count() > 0)
    }
}

enum Answer {
    /// A path checked at `from`, good until `until` (Unix seconds).
    Accepted { from: i64, until: i64 },
    /// A refusal of the name.
    Refused(Refused),
}

impl PerConnection {
    /// The state for a client certificate `leaf` and the intermediates kept of it (`None`
    /// when the client sent too many).
    pub(crate) fn new(leaf: &[u8], intermediates: Option<&[CertificateDer<'_>]>) -> Self {
        let not_after = intermediates.and_then(|kept| {
            kept.iter()
                .map(|c| not_after(c.as_ref()))
                .chain(std::iter::once(not_after(leaf)))
                .try_fold(i64::MAX, |min, t| t.map(|t| min.min(t)))
        });
        Self {
            not_after,
            names: OnceLock::new(),
            cache: Mutex::new(Vec::new()),
        }
    }

    fn cached(&self, pki: &Pki, now: i64) -> Option<Result<(), Refused>> {
        let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        let hit = cache.iter().find(|c| c.is_for(pki))?;
        match &hit.answer {
            Answer::Accepted { from, until } => (*from <= now && now <= *until).then_some(Ok(())),
            Answer::Refused(r) => Some(Err(r.clone())),
        }
    }

    fn remember(&self, pki: &Pki, now: i64, outcome: &Result<(), Refused>) {
        let answer = match outcome {
            Ok(()) => {
                let crl_until = pki.crls.as_ref().and_then(|c| c.cache_until());
                match (self.not_after, crl_until) {
                    (Some(until), crl) => {
                        let until = crl.map_or(until, |c| until.min(c));
                        if now > until {
                            return;
                        }
                        Answer::Accepted { from: now, until }
                    }
                    (None, _) => return,
                }
            }
            Err(r) if NAME_REFUSALS.contains(&r.reason) => Answer::Refused(r.clone()),
            Err(_) => return,
        };
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        cache.retain(|c| !c.is_for(pki) && c.alive());
        if cache.len() >= CACHED_ANSWERS {
            cache.remove(0);
        }
        cache.push(Cached {
            ca: Arc::downgrade(&pki.ca),
            crls: pki.crls.as_ref().map(Arc::downgrade),
            name: pki.name.clone(),
            answer,
        });
    }

    #[cfg(test)]
    fn cached_answers(&self) -> usize {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// The [`PerConnection`] states of the forwarding listener (`[server.forwarded_client_cert]`),
/// where every request carries its certificate anew and one proxy connection carries many
/// clients' requests.
///
/// A request gets the state kept for exactly its certificate and the intermediates kept of it
/// (the key is a SHA-256 over their DER bytes, each with its length), or a new one. So the
/// cache holds the answers a native connection keeps, under the same rules
/// ([`PerConnection`]: per CA file `Arc` and name, an accepted path only within its dates and
/// from the time it was checked, a name refusal kept, no other refusal kept), shared only by
/// requests whose certificates are byte for byte the same. A certificate with more than
/// [`MAX_INTERMEDIATES`](crate::client_cert::MAX_INTERMEDIATES) intermediates gets a state of
/// its own, which caches nothing. At most [`SHARED_STATES`] states, the oldest dropped first:
/// a flood of new certificates only makes the check run again.
pub(crate) struct SharedStates {
    inner: Mutex<SharedInner>,
}

#[derive(Default)]
struct SharedInner {
    states: HashMap<[u8; 32], Arc<PerConnection>>,
    /// The keys of `states`, oldest first.
    order: VecDeque<[u8; 32]>,
}

impl std::fmt::Debug for SharedStates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedStates").finish_non_exhaustive()
    }
}

impl SharedStates {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(SharedInner::default()),
        }
    }

    /// The state for the certificate `leaf` with the intermediates kept of it (`None` when it
    /// came with too many).
    pub(crate) fn state(
        &self,
        leaf: &[u8],
        intermediates: Option<&[CertificateDer<'_>]>,
    ) -> Arc<PerConnection> {
        let Some(kept) = intermediates else {
            return Arc::new(PerConnection::new(leaf, None));
        };
        let mut h = Sha256::new();
        for der in std::iter::once(leaf).chain(kept.iter().map(|c| c.as_ref())) {
            h.update((der.len() as u64).to_be_bytes());
            h.update(der);
        }
        let key: [u8; 32] = h.finalize().into();
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(state) = inner.states.get(&key) {
            return state.clone();
        }
        let state = Arc::new(PerConnection::new(leaf, Some(kept)));
        if inner.states.len() >= SHARED_STATES {
            if let Some(oldest) = inner.order.pop_front() {
                inner.states.remove(&oldest);
            }
        }
        inner.states.insert(key, state.clone());
        inner.order.push_back(key);
        state
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .states
            .len()
    }
}

/// The URI and DNS names of a client certificate, as rustls-webpki reads them; DNS names in
/// lowercase. Wildcard DNS names are kept: no configured name equals one.
#[derive(Debug, Default)]
pub(crate) struct CertNames {
    pub(crate) uris: Vec<String>,
    pub(crate) dns: Vec<String>,
}

/// The names of `cert`, read once per connection. Empty when the certificate cannot be read.
pub(crate) fn names(cert: &ClientCertificate) -> &CertNames {
    cert.pki_state().names.get_or_init(|| {
        let Ok(ee) = webpki::EndEntityCert::try_from(cert.der()) else {
            return CertNames::default();
        };
        CertNames {
            uris: ee.valid_uri_names().map(str::to_owned).collect(),
            dns: ee
                .valid_dns_names()
                .map(|n| n.to_ascii_lowercase())
                .collect(),
        }
    })
}

/// Whether `cert` carries the name an entry with these settings requires: a URI name equal
/// to `tls_client_auth_san_uri`, or a DNS name equal to `tls_client_auth_san_dns` without
/// regard to case. The name test of [`verify`] without its count of URI names: a certificate
/// it is false for is refused by [`verify`] as `san_mismatch`. Reads the certificate's names
/// only (once per connection), no path or signature.
pub(crate) fn carries_name(pki: &Pki, cert: &ClientCertificate) -> bool {
    let names = names(cert);
    match &pki.name {
        SanName::Uri { value, .. } => names.uris.iter().any(|n| n == value),
        SanName::Dns(value) => names.dns.iter().any(|n| n == value),
    }
}

/// The intermediates of `sent` worth giving to path building for the client certificate
/// `leaf`, in the order sent: each one readable, not a copy of `leaf`, not self-issued
/// (subject = issuer), and the first one sent with its subject. See the module docs for why.
pub(crate) fn useful_intermediates(
    leaf: &[u8],
    sent: &[CertificateDer<'_>],
) -> Vec<CertificateDer<'static>> {
    let mut subjects: Vec<&[u8]> = Vec::with_capacity(sent.len());
    let mut kept = Vec::with_capacity(sent.len());
    for c in sent {
        let Some(t) = tbs(c.as_ref()) else { continue };
        if c.as_ref() == leaf || t.subject == t.issuer || subjects.contains(&t.subject) {
            continue;
        }
        subjects.push(t.subject);
        kept.push(c.clone().into_owned());
    }
    kept
}

/// Whether `cert` authenticates an entry with these settings at `now`: the path to one of its
/// CAs (see the module docs), then the name. Answered from the connection's cache when it
/// holds an answer still true at `now` ([`PerConnection`]).
pub(crate) fn verify(
    pki: &Pki,
    cert: &ClientCertificate,
    now: OffsetDateTime,
) -> Result<(), Refused> {
    let secs = now.unix_timestamp();
    tracing::trace!(
        x5t_s256 = %cert.x5t_s256(),
        ca_path = %pki.ca_path.display(),
        "client certificate checked against an entry's CA file"
    );
    let state = cert.pki_state();
    if let Some(answer) = state.cached(pki, secs) {
        return answer;
    }
    let outcome = verify_now(pki, cert, now);
    state.remember(pki, secs, &outcome);
    outcome
}

/// The check rustls-webpki runs on each path it builds.
type PathCheck<'c> = dyn Fn(&webpki::VerifiedPath<'_>) -> Result<(), webpki::Error> + 'c;

/// [`verify`] without the cache.
fn verify_now(pki: &Pki, cert: &ClientCertificate, now: OffsetDateTime) -> Result<(), Refused> {
    let Some(intermediates) = cert.intermediates() else {
        return Err(Refused::because("too_many_intermediates"));
    };
    let ee = webpki::EndEntityCert::try_from(cert.der())
        .map_err(|_| Refused::because("certificate_not_usable"))?;
    let secs = u64::try_from(now.unix_timestamp()).unwrap_or(0);
    let at = UnixTime::since_unix_epoch(std::time::Duration::from_secs(secs));
    // The CRL check runs on each path rustls-webpki has verified up to a CA of the file: a
    // refusal makes it try the next path, so a certificate is refused for revocation only when
    // no path avoids it. The worst refusal seen is kept for the answer.
    let revocation: std::cell::Cell<Option<Status>> = std::cell::Cell::new(None);
    let crl_check = |path: &webpki::VerifiedPath<'_>| -> Result<(), webpki::Error> {
        let Some(crls) = &pki.crls else {
            return Ok(());
        };
        match path_status(crls, path, now.unix_timestamp()) {
            Status::Good => Ok(()),
            bad => {
                revocation.set(Some(revocation.get().map_or(bad, |seen| seen.worst(bad))));
                Err(if bad == Status::Revoked {
                    webpki::Error::CertRevoked
                } else {
                    webpki::Error::UnknownRevocationStatus
                })
            }
        }
    };
    let callback: Option<&PathCheck<'_>> = pki.crls.as_ref().map(|_| &crl_check as _);
    let path = ee.verify_for_usage(
        crate::client_cert::provider()
            .signature_verification_algorithms
            .all,
        &pki.ca.anchors,
        intermediates,
        at,
        webpki::KeyUsage::client_auth(),
        None,
        callback,
    );
    if let Err(e) = path {
        return Err(match revocation.get() {
            // A revocation refusal is told apart only for a certificate that carries the
            // entry's name: one that names another client gets that client's answer.
            Some(status) => match check_name(pki, cert, &ee) {
                Ok(()) => Refused::because(status.reason()),
                Err(r) => r,
            },
            None => Refused::because(path_error(&e)),
        });
    }
    check_name(pki, cert, &ee)
}

/// The CRL status of a verified path: each certificate below the trust anchor (the client's,
/// then each intermediate) is looked up in the CRL of the CA that issued it in this path, by
/// that CA's name and key ([`CrlSet::status`]); then the trust anchor itself, when it is not
/// self-issued and the entry's files hold its issuer, as an intermediate is
/// ([`CrlSet::anchor_status`], precomputed at load). The worst status of the path.
fn path_status(crls: &CrlSet, path: &webpki::VerifiedPath<'_>, now: i64) -> Status {
    let mids: Vec<&webpki::Cert<'_>> = path.intermediate_certificates().collect();
    let anchor = path.anchor();
    let mut worst = Status::Good;
    let serials =
        std::iter::once(path.end_entity().serial()).chain(mids.iter().map(|c| c.serial()));
    for (i, serial) in serials.enumerate() {
        let status = match mids.get(i) {
            Some(issuer) => {
                let spki = issuer.subject_public_key_info();
                let Some((spki, _)) = expect(spki.as_ref(), SEQUENCE) else {
                    return Status::Missing.worst(worst);
                };
                crls.status(issuer.subject(), spki, serial, now)
            }
            None => crls.status(
                anchor.subject.as_ref(),
                anchor.subject_public_key_info.as_ref(),
                serial,
                now,
            ),
        };
        worst = worst.worst(status);
    }
    worst.worst(crls.anchor_status(
        anchor.subject.as_ref(),
        anchor.subject_public_key_info.as_ref(),
        now,
    ))
}

/// The name check of [`verify`], once the path is accepted.
fn check_name(
    pki: &Pki,
    cert: &ClientCertificate,
    ee: &webpki::EndEntityCert<'_>,
) -> Result<(), Refused> {
    match &pki.name {
        SanName::Uri { value, spiffe } => {
            let names: Vec<&str> = ee.valid_uri_names().collect();
            // An X.509-SVID carries exactly one URI name. Count them in the DER too, so that
            // a URI name rustls-webpki could not read still counts.
            if *spiffe && (names.len() != 1 || uri_name_count(cert.der().as_ref()) != Some(1)) {
                return Err(refused_names("uri_san_count", &names));
            }
            if names.iter().any(|n| n == value) {
                Ok(())
            } else {
                Err(refused_names("san_mismatch", &names))
            }
        }
        SanName::Dns(value) => {
            let names: Vec<&str> = ee.valid_dns_names().collect();
            // The configured name has no `*`, so a wildcard name never equals it.
            if names.iter().any(|n| n.eq_ignore_ascii_case(value)) {
                Ok(())
            } else {
                Err(refused_names("san_mismatch", &names))
            }
        }
    }
}

fn refused_names(reason: &'static str, names: &[&str]) -> Refused {
    Refused {
        reason,
        names: names
            .iter()
            .take(LOGGED_NAMES)
            .map(|n| n.chars().take(LOGGED_NAME_CHARS).collect())
            .collect(),
    }
}

/// The debug-log reason for a path rustls-webpki refused.
fn path_error(e: &webpki::Error) -> &'static str {
    use webpki::Error as E;
    match e {
        E::CertExpired { .. } => "certificate_expired",
        E::CertNotValidYet { .. } => "certificate_not_yet_valid",
        E::CaUsedAsEndEntity
        | E::RequiredEkuNotFoundContext(_)
        | E::EmptyEkuExtension
        | E::UnsupportedCriticalExtension => "certificate_not_usable",
        _ => "chain_invalid",
    }
}

// --- a few DER reads that rustls-webpki does not expose -------------------------------------
//
// Here, on bytes rustls-webpki has already parsed as a certificate. `crate::tls` also runs
// `validity` and `is_ca` on the raw DER of a `[server.tls] cert_pem_path` file, before any
// parser has seen it: the bytes are the operator's, not a peer's, but they may be anything.
// Every read is bounds checked and returns `None` on anything unexpected (a test runs them on
// every truncation and on corrupted dates); nothing here decides trust alone: it only refuses
// more (a CA file entry that is not a CA, a second URI name, a server certificate whose dates
// cannot be read or that is a CA).

/// One DER element of `input`: (tag, contents, the rest). Low tag numbers and definite
/// lengths of up to four bytes only.
pub(crate) fn element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

/// [`element`] with tag `want`: (contents, the rest).
pub(crate) fn expect(input: &[u8], want: u8) -> Option<(&[u8], &[u8])> {
    let (tag, contents, rest) = element(input)?;
    (tag == want).then_some((contents, rest))
}

pub(crate) const SEQUENCE: u8 = 0x30;

/// The parts of a certificate's `tbsCertificate` used here: the serial number contents, the
/// contents of the issuer and subject names and of the validity.
pub(crate) struct Tbs<'a> {
    pub(crate) serial: &'a [u8],
    pub(crate) issuer: &'a [u8],
    pub(crate) validity: &'a [u8],
    pub(crate) subject: &'a [u8],
}

pub(crate) fn tbs(cert: &[u8]) -> Option<Tbs<'_>> {
    let (cert, _) = expect(cert, SEQUENCE)?;
    let (mut tbs, _) = expect(cert, SEQUENCE)?;
    if tbs.first() == Some(&0xa0) {
        tbs = element(tbs)?.2; // version [0] EXPLICIT
    }
    let (serial, tbs) = expect(tbs, 0x02)?; // serialNumber
    let (_, tbs) = expect(tbs, SEQUENCE)?; // signature
    let (issuer, tbs) = expect(tbs, SEQUENCE)?;
    let (validity, tbs) = expect(tbs, SEQUENCE)?;
    let (subject, _) = expect(tbs, SEQUENCE)?;
    Some(Tbs {
        serial,
        issuer,
        validity,
        subject,
    })
}

/// A certificate's `notAfter`, in Unix seconds.
pub(crate) fn not_after(cert: &[u8]) -> Option<i64> {
    validity(cert).map(|(_, not_after)| not_after)
}

/// A certificate's `notBefore` and `notAfter`, in Unix seconds.
pub(crate) fn validity(cert: &[u8]) -> Option<(i64, i64)> {
    let validity = tbs(cert)?.validity;
    let (not_before, rest) = time_of(validity)?;
    let (not_after, rest) = time_of(rest)?;
    rest.is_empty().then_some((not_before, not_after))
}

/// One DER `Time` (RFC 5280 §4.1.2.5): `UTCTime` `YYMMDDHHMMSSZ` (years 1950 to 2049) or
/// `GeneralizedTime` `YYYYMMDDHHMMSSZ`, in Unix seconds, and the rest of the input.
pub(crate) fn time_of(input: &[u8]) -> Option<(i64, &[u8])> {
    let (tag, value, rest) = element(input)?;
    let digits = |b: &[u8]| -> Option<u16> {
        b.iter().try_fold(0u16, |acc, &d| {
            d.is_ascii_digit().then(|| acc * 10 + u16::from(d - b'0'))
        })
    };
    let (year, value) = match (tag, value.len()) {
        (0x17, 13) => {
            let yy = digits(&value[..2])?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, &value[2..])
        }
        (0x18, 15) => (digits(&value[..4])?, &value[4..]),
        _ => return None,
    };
    if value[10] != b'Z' {
        return None;
    }
    let two = |i: usize| digits(&value[i..i + 2]).and_then(|v| u8::try_from(v).ok());
    let date = time::Date::from_calendar_date(
        i32::from(year),
        time::Month::try_from(two(0)?).ok()?,
        two(2)?,
    )
    .ok()?;
    let at = time::Time::from_hms(two(4)?, two(6)?, two(8)?).ok()?;
    Some((
        time::PrimitiveDateTime::new(date, at)
            .assume_utc()
            .unix_timestamp(),
        rest,
    ))
}

/// The `extnValue` contents of the extension `oid` of a certificate: `Some(None)` when the
/// certificate has no such extension.
pub(crate) fn extension<'a>(cert: &'a [u8], oid: &[u8]) -> Option<Option<&'a [u8]>> {
    let (cert, _) = expect(cert, SEQUENCE)?;
    let (mut tbs, _) = expect(cert, SEQUENCE)?;
    while !tbs.is_empty() {
        let (tag, contents, rest) = element(tbs)?;
        tbs = rest;
        // extensions [3] EXPLICIT Extensions
        if tag != 0xa3 {
            continue;
        }
        let (mut exts, _) = expect(contents, SEQUENCE)?;
        while !exts.is_empty() {
            let (ext, rest) = expect(exts, SEQUENCE)?;
            exts = rest;
            let (id, mut ext) = expect(ext, 0x06)?;
            if ext.first() == Some(&0x01) {
                ext = expect(ext, 0x01)?.1; // critical BOOLEAN
            }
            let (value, _) = expect(ext, 0x04)?;
            if id == oid {
                return Some(Some(value));
            }
        }
    }
    Some(None)
}

/// Whether a certificate's `basicConstraints` (2.5.29.19) says `cA` TRUE, in DER: one
/// `SEQUENCE` and nothing after it, holding the `BOOLEAN` `0xff`, then at most one `INTEGER`
/// (`pathLenConstraint`, not negative) and nothing else. Anything else, a malformed extension
/// included, is "not a CA", so the file is refused.
pub(crate) fn is_ca(cert: &[u8]) -> bool {
    let ca = || -> Option<()> {
        let value = extension(cert, &[0x55, 0x1d, 0x13])??;
        let (bc, after) = expect(value, SEQUENCE)?;
        let (flag, rest) = expect(bc, 0x01)?;
        if !after.is_empty() || flag != [0xff] {
            return None;
        }
        if rest.is_empty() {
            return Some(());
        }
        let (len, rest) = expect(rest, 0x02)?;
        // A path length is never negative: the first content byte has its top bit clear.
        (len.first().is_some_and(|&b| b < 0x80) && rest.is_empty()).then_some(())
    };
    ca().is_some()
}

/// How many `uniformResourceIdentifier` names (`[6]`, primitive or constructed) a
/// certificate's `subjectAltName` (2.5.29.17) holds; `None` when it cannot be read.
pub(crate) fn uri_name_count(cert: &[u8]) -> Option<usize> {
    let Some(value) = extension(cert, &[0x55, 0x1d, 0x11])? else {
        return Some(0);
    };
    let (mut names, _) = expect(value, SEQUENCE)?;
    let mut count = 0;
    while !names.is_empty() {
        let (tag, _, rest) = element(names)?;
        names = rest;
        // The class and number bits: a constructed [6] (0xa6) counts as well, so that an
        // encoding rustls-webpki skips still makes a SPIFFE matcher refuse.
        if tag & 0xdf == 0x86 {
            count += 1;
        }
    }
    Some(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(secs).unwrap()
    }

    const NOW: i64 = 1_500_000_000;

    /// A CA (or an intermediate, when `issuer` is given) valid around [`NOW`].
    struct Authority {
        params: rcgen::CertificateParams,
        key: rcgen::KeyPair,
        cert: rcgen::Certificate,
    }

    impl Authority {
        fn new(name: &str, issuer: Option<&Authority>) -> Self {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, name);
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

        fn issue(
            &self,
            edit: impl FnOnce(&mut rcgen::CertificateParams),
        ) -> CertificateDer<'static> {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.not_before = at(NOW - 3600);
            params.not_after = at(NOW + 3600);
            params.is_ca = rcgen::IsCa::ExplicitNoCa;
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
            edit(&mut params);
            params
                .signed_by(&key, &rcgen::Issuer::from_params(&self.params, &self.key))
                .unwrap()
                .der()
                .clone()
        }

        fn pki(&self, name: SanName) -> Pki {
            Pki {
                ca_path: "ca.pem".into(),
                ca: Arc::new(ca_file(self.cert.pem().as_bytes()).unwrap()),
                name,
                crls: None,
            }
        }
    }

    fn uri(s: &str) -> rcgen::SanType {
        rcgen::SanType::URI(s.try_into().unwrap())
    }

    fn dns(s: &str) -> rcgen::SanType {
        rcgen::SanType::DnsName(s.try_into().unwrap())
    }

    const CODER: &str = "spiffe://example.org/ns/agents/sa/coder";

    fn check(
        pki: &Pki,
        leaf: CertificateDer<'static>,
        chain: &[CertificateDer<'static>],
    ) -> Result<(), &'static str> {
        let mut all = vec![leaf];
        all.extend_from_slice(chain);
        let cert = ClientCertificate::from_handshake(&all).unwrap();
        let answer = verify(pki, &cert, at(NOW)).map_err(|r| r.reason);
        // The name test of the bound-token check agrees with the check's: an accepted
        // certificate carries the entry's name, and one refused for its names does not
        // (`uri_san_count` aside, which may carry it among several).
        match answer {
            Ok(()) => assert!(carries_name(pki, &cert)),
            Err("san_mismatch") => assert!(!carries_name(pki, &cert)),
            Err(_) => {}
        }
        answer
    }

    #[test]
    fn san_uri_values_are_checked() {
        assert_eq!(
            san_uri(CODER).unwrap(),
            SanName::Uri {
                value: CODER.into(),
                spiffe: true
            }
        );
        assert_eq!(
            san_uri("https://agents.example/coder").unwrap(),
            SanName::Uri {
                value: "https://agents.example/coder".into(),
                spiffe: false
            }
        );
        for bad in [
            "",
            "coder",
            ":x",
            "1x:y",
            "https:",
            "https://agents.example/a b",
            "https://agents.example/\u{e9}",
            "spiffe://example.org",
            "spiffe://Example.org/a",
            "spiffe://example.org/a/../b",
            "SPIFFE://example.org/a",
            "Spiffe://example.org/a",
            "spiffe://example.org:443/a",
            "spiffe://example.org/a?x=1",
        ] {
            let e = san_uri(bad).unwrap_err();
            assert!(bad.is_empty() || !e.contains(bad), "{bad}: {e}");
        }
        assert!(san_uri(&format!("urn:{}", "a".repeat(MAX_SAN_URI_BYTES))).is_err());
    }

    #[test]
    fn san_dns_values_are_checked() {
        assert_eq!(
            san_dns("Coder.Agents.Internal").unwrap(),
            SanName::Dns("coder.agents.internal".into())
        );
        assert_eq!(san_dns("coder").unwrap(), SanName::Dns("coder".into()));
        for bad in [
            "",
            "*.agents.internal",
            "coder.*.internal",
            "*",
            "coder.agents.internal.",
            "127.0.0.1",
            "::1",
            "coder agents",
            "coder_.agents..internal",
            "https://coder",
        ] {
            let e = san_dns(bad).unwrap_err();
            assert!(bad.is_empty() || !e.contains(bad), "{bad}: {e}");
        }
        assert!(san_dns(&"a.".repeat(127)).is_err());
    }

    #[test]
    fn the_ca_file_holds_ca_certificates_only() {
        let root = Authority::new("root", None);
        let other = Authority::new("other", None);
        let both = format!("{}{}", root.cert.pem(), other.cert.pem());
        let f = ca_file(both.as_bytes()).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(f.sha256(), hex::encode(Sha256::digest(both.as_bytes())));
        // An intermediate CA is a CA too.
        let mid = Authority::new("mid", Some(&root));
        assert_eq!(ca_file(mid.cert.pem().as_bytes()).unwrap().len(), 1);

        let leaf = root.issue(|p| p.subject_alt_names = vec![uri(CODER)]);
        let leaf_pem = pem("CERTIFICATE", &leaf);
        let key = rcgen::KeyPair::generate().unwrap().serialize_pem();
        let secret_line = key.lines().nth(1).unwrap().to_owned();
        let cases: Vec<(String, &str)> = vec![
            (String::new(), "the file is empty"),
            (" \n\t".into(), "the file is empty"),
            ("hello".into(), "no PEM certificate"),
            (leaf_pem.clone(), "certificate 1 of the file is not a CA certificate"),
            (
                format!("{}{leaf_pem}", root.cert.pem()),
                "certificate 2 of the file is not a CA certificate",
            ),
            (format!("{}{key}", root.cert.pem()), "the file holds a private key"),
            (
                format!("{}-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n", root.cert.pem()),
                "the file holds a private key",
            ),
            (
                format!("{}{}", root.cert.pem(), pem("PUBLIC KEY", b"\x30\x00")),
                "a PEM block other than CERTIFICATE",
            ),
            (
                format!("{}{}", root.cert.pem(), pem("TRUSTED CERTIFICATE", b"\x30\x00")),
                "a PEM block other than CERTIFICATE",
            ),
            (
                format!("{}{}", root.cert.pem(), pem("X509 CRL", b"\x30\x00")),
                "a PEM block other than CERTIFICATE",
            ),
            (pem("CERTIFICATE", b"junk"), "certificate 1 of the file cannot be read"),
            (
                format!("-----BEGIN CERTIFICATE-----\n{secret_line}!!\n-----END CERTIFICATE-----\n"),
                "not a valid PEM file",
            ),
            (
                format!("-----BEGIN CERTIFICATE----\n{secret_line}\n"),
                "not a valid PEM file",
            ),
            (
                root.cert.pem().repeat(MAX_CA_CERTS + 1),
                "the file holds 17 certificates; at most 16",
            ),
        ];
        for (text, want) in cases {
            let e = ca_file(text.as_bytes()).err().unwrap();
            assert!(e.contains(want), "{want}: {e}");
            assert!(!e.contains(&secret_line), "{e}");
        }
        assert_eq!(
            ca_file(root.cert.pem().repeat(MAX_CA_CERTS).as_bytes())
                .unwrap()
                .len(),
            16
        );
    }

    #[test]
    fn the_ca_file_is_read_with_the_file_rules() {
        let dir = tempfile::tempdir().unwrap();
        let root = Authority::new("root", None);
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, root.cert.pem()).unwrap();
        assert_eq!(read_ca_file(&path).unwrap().len(), 1);
        assert!(read_ca_file(dir.path())
            .unwrap_err()
            .contains("not a regular file"));
        assert!(read_ca_file(&dir.path().join("missing.pem"))
            .unwrap_err()
            .contains("cannot read the file"));
        let big = dir.path().join("big.pem");
        std::fs::write(
            &big,
            vec![b' '; usize::try_from(crate::idp::jwks::MAX_CA_FILE_BYTES).unwrap() + 1],
        )
        .unwrap();
        assert!(read_ca_file(&big).unwrap_err().contains("larger than"));
    }

    fn pem(label: &str, der: &[u8]) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        format!("-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n")
    }

    #[test]
    fn a_certificate_from_the_ca_with_the_name_authenticates() {
        let root = Authority::new("root", None);
        let pki = root.pki(san_uri(CODER).unwrap());
        assert_eq!(
            check(
                &pki,
                root.issue(|p| p.subject_alt_names = vec![uri(CODER)]),
                &[]
            ),
            Ok(())
        );
        // Through an intermediate the client sends.
        let mid = Authority::new("mid", Some(&root));
        let leaf = mid.issue(|p| p.subject_alt_names = vec![uri(CODER)]);
        assert_eq!(check(&pki, leaf.clone(), &[mid.cert.der().clone()]), Ok(()));
        // Not without it.
        assert_eq!(check(&pki, leaf.clone(), &[]), Err("chain_invalid"));
        // Junk among the intermediates is skipped by path building.
        assert_eq!(
            check(
                &pki,
                leaf.clone(),
                &[
                    CertificateDer::from(b"junk".to_vec()),
                    mid.cert.der().clone()
                ]
            ),
            Ok(())
        );
        // Too many intermediates: refused before anything else.
        let many = vec![mid.cert.der().clone(); crate::client_cert::MAX_INTERMEDIATES + 1];
        assert_eq!(check(&pki, leaf, &many), Err("too_many_intermediates"));
    }

    /// A CA certificate with the name `subject`, signed by a new key under the name `issuer`:
    /// self-issued when they are equal.
    fn crafted(subject: &str, issuer: &str) -> CertificateDer<'static> {
        let issuer = Authority::new(issuer, None);
        Authority::new(subject, Some(&issuer)).cert.der().clone()
    }

    /// Chains built to make path building try many paths are cut down before it runs: each
    /// step then has at most one intermediate to try. The bound is checked on what is kept,
    /// not by timing.
    #[test]
    fn crafted_chains_are_cut_down_before_path_building() {
        use crate::client_cert::MAX_INTERMEDIATES;
        let root = Authority::new("root", None);
        let pki = root.pki(san_uri(CODER).unwrap());
        let named = |p: &mut rcgen::CertificateParams| p.subject_alt_names = vec![uri(CODER)];
        // Self-issued "X" certificates, each with its own key, and a client certificate
        // issued by "X": every one could issue every other.
        let x = Authority::new("X", None);
        let leaf = x.issue(named);
        let self_issued: Vec<_> = (0..MAX_INTERMEDIATES).map(|_| crafted("X", "X")).collect();
        assert!(useful_intermediates(&leaf, &self_issued).is_empty());
        assert_eq!(
            check(&pki, leaf.clone(), &self_issued),
            Err("chain_invalid")
        );
        let mut five = self_issued.clone();
        five.push(crafted("X", "X"));
        assert_eq!(
            check(&pki, leaf.clone(), &five),
            Err("too_many_intermediates")
        );

        // "X" by "Y" and "Y" by "X", twice each: one of each subject is kept.
        let crossed = vec![
            crafted("X", "Y"),
            crafted("Y", "X"),
            crafted("X", "Y"),
            crafted("Y", "X"),
        ];
        let kept = useful_intermediates(&leaf, &crossed);
        assert_eq!(kept, vec![crossed[0].clone(), crossed[1].clone()]);
        assert_eq!(check(&pki, leaf.clone(), &crossed), Err("chain_invalid"));

        // Copies of one intermediate, the client's own certificate and unreadable bytes are
        // dropped; the path still builds.
        let mid = Authority::new("mid", Some(&root));
        let good = mid.issue(named);
        let sent = vec![
            good.clone(),
            mid.cert.der().clone(),
            CertificateDer::from(b"junk".to_vec()),
            mid.cert.der().clone(),
        ];
        assert_eq!(
            useful_intermediates(&good, &sent),
            vec![mid.cert.der().clone()]
        );
        assert_eq!(check(&pki, good.clone(), &sent), Ok(()));
        // A second intermediate with the subject of one sent before it is dropped: the client
        // sends the one its path needs first.
        let decoy = crafted("mid", "elsewhere");
        let first = vec![mid.cert.der().clone(), decoy.clone()];
        assert_eq!(check(&pki, good.clone(), &first), Ok(()));
        let second = vec![decoy, mid.cert.der().clone()];
        assert_eq!(check(&pki, good, &second), Err("chain_invalid"));
    }

    /// A cached answer holds only while it is true: an accepted path until the earliest
    /// `notAfter` of the certificates kept, and from the time it was checked; a refusal for
    /// the dates is never kept.
    #[test]
    fn the_cache_answers_only_while_true() {
        let root = Authority::new("root", None);
        let pki = root.pki(san_uri(CODER).unwrap());
        let leaf = root.issue(|p| p.subject_alt_names = vec![uri(CODER)]);
        let cert = ClientCertificate::from_handshake(&[leaf]).unwrap();
        let state = cert.pki_state();
        assert_eq!(verify(&pki, &cert, at(NOW)), Ok(()));
        assert_eq!(state.cached_answers(), 1);
        assert_eq!(verify(&pki, &cert, at(NOW + 3600)), Ok(()));
        let r = verify(&pki, &cert, at(NOW + 3601)).unwrap_err();
        assert_eq!(r.reason, "certificate_expired");
        // A clock set back before the certificate is valid checks again.
        let r = verify(&pki, &cert, at(NOW - 3601)).unwrap_err();
        assert_eq!(r.reason, "certificate_not_yet_valid");
        assert_eq!(verify(&pki, &cert, at(NOW)), Ok(()));

        // Not yet valid is not a lasting refusal.
        let early = root.issue(|p| {
            p.subject_alt_names = vec![uri(CODER)];
            p.not_before = at(NOW + 10);
        });
        let early = ClientCertificate::from_handshake(&[early]).unwrap();
        let r = verify(&pki, &early, at(NOW)).unwrap_err();
        assert_eq!(r.reason, "certificate_not_yet_valid");
        assert_eq!(early.pki_state().cached_answers(), 0);
        assert_eq!(verify(&pki, &early, at(NOW + 10)), Ok(()));

        // An intermediate that expires before the client's certificate ends the answer.
        let mid = Authority::new("mid", Some(&root));
        let long = mid.issue(|p| {
            p.subject_alt_names = vec![uri(CODER)];
            p.not_after = at(NOW + 3 * 86_400);
        });
        let long = ClientCertificate::from_handshake(&[long, mid.cert.der().clone()]).unwrap();
        assert_eq!(verify(&pki, &long, at(NOW)), Ok(()));
        assert_eq!(verify(&pki, &long, at(NOW + 86_400)), Ok(()));
        let r = verify(&pki, &long, at(NOW + 86_401)).unwrap_err();
        assert_eq!(r.reason, "certificate_expired");
    }

    /// A cached answer is for one CA file and one name: a CA file read again (a reload), a
    /// CA that is gone, another name and another entry are checked afresh.
    #[test]
    fn the_cache_never_carries_an_answer_to_another_ca_or_name() {
        let root = Authority::new("root", None);
        let other = Authority::new("other", None);
        let a = root.pki(san_uri(CODER).unwrap());
        let leaf = root.issue(|p| p.subject_alt_names = vec![uri(CODER)]);
        let cert = ClientCertificate::from_handshake(&[leaf]).unwrap();
        assert_eq!(verify(&a, &cert, at(NOW)), Ok(()));

        // Entry B, the same CA file (the same `Arc`) and another name.
        let b = Pki {
            ca_path: a.ca_path.clone(),
            ca: a.ca.clone(),
            name: san_uri("spiffe://example.org/ns/agents/sa/reviewer").unwrap(),
            crls: None,
        };
        assert_eq!(
            verify(&b, &cert, at(NOW)).unwrap_err().reason,
            "san_mismatch"
        );
        // Its refusal is kept, and does not change A's answer.
        assert_eq!(
            verify(&b, &cert, at(NOW)).unwrap_err().reason,
            "san_mismatch"
        );
        assert_eq!(verify(&a, &cert, at(NOW)), Ok(()));

        // A reload that keeps the name and puts another CA in the file.
        let reloaded = Pki {
            ca_path: a.ca_path.clone(),
            ca: other.pki(san_uri(CODER).unwrap()).ca,
            name: a.name.clone(),
            crls: None,
        };
        assert_eq!(
            verify(&reloaded, &cert, at(NOW)).unwrap_err().reason,
            "chain_invalid"
        );
        // A reload that changes only the name.
        let renamed = Pki {
            ca_path: a.ca_path.clone(),
            ca: a.ca.clone(),
            name: san_dns("coder.agents").unwrap(),
            crls: None,
        };
        assert_eq!(
            verify(&renamed, &cert, at(NOW)).unwrap_err().reason,
            "san_mismatch"
        );
        // The same file read again: a new `Arc`, checked again, and accepted again.
        let same = root.pki(san_uri(CODER).unwrap());
        assert!(!Arc::ptr_eq(&same.ca, &a.ca));
        assert_eq!(verify(&same, &cert, at(NOW)), Ok(()));

        // Bounded, and answers for a CA file no one holds any more are dropped.
        drop(reloaded);
        for i in 0..20 {
            let name = san_uri(&format!("spiffe://example.org/n{i}")).unwrap();
            let pki = Pki {
                ca_path: a.ca_path.clone(),
                ca: a.ca.clone(),
                name,
                crls: None,
            };
            assert!(verify(&pki, &cert, at(NOW)).is_err());
        }
        assert!(cert.pki_state().cached_answers() <= CACHED_ANSWERS);
    }

    /// The forwarding listener's shared states answer only while true, as a connection's
    /// cache does, with a new certificate (as a new request makes) each time.
    #[test]
    fn shared_states_answer_only_while_true() {
        let root = Authority::new("root", None);
        let pki = root.pki(san_uri(CODER).unwrap());
        let leaf = root.issue(|p| p.subject_alt_names = vec![uri(CODER)]);
        let shared = SharedStates::new();
        let req = |leaf: &CertificateDer<'static>, chain: &[CertificateDer<'static>]| {
            ClientCertificate::forwarded(leaf.clone(), chain, &shared)
        };
        assert_eq!(verify(&pki, &req(&leaf, &[]), at(NOW)), Ok(()));
        assert_eq!(req(&leaf, &[]).pki_state().cached_answers(), 1);
        assert_eq!(verify(&pki, &req(&leaf, &[]), at(NOW + 3600)), Ok(()));
        let r = verify(&pki, &req(&leaf, &[]), at(NOW + 3601)).unwrap_err();
        assert_eq!(r.reason, "certificate_expired");
        let r = verify(&pki, &req(&leaf, &[]), at(NOW - 3601)).unwrap_err();
        assert_eq!(r.reason, "certificate_not_yet_valid");
        assert_eq!(verify(&pki, &req(&leaf, &[]), at(NOW)), Ok(()));

        // Not yet valid is not a lasting refusal.
        let early = root.issue(|p| {
            p.subject_alt_names = vec![uri(CODER)];
            p.not_before = at(NOW + 10);
        });
        let r = verify(&pki, &req(&early, &[]), at(NOW)).unwrap_err();
        assert_eq!(r.reason, "certificate_not_yet_valid");
        assert_eq!(req(&early, &[]).pki_state().cached_answers(), 0);
        assert_eq!(verify(&pki, &req(&early, &[]), at(NOW + 10)), Ok(()));

        // An intermediate that expires before the client's certificate ends the answer.
        let mid = Authority::new("mid", Some(&root));
        let long = mid.issue(|p| {
            p.subject_alt_names = vec![uri(CODER)];
            p.not_after = at(NOW + 3 * 86_400);
        });
        let chain = [mid.cert.der().clone()];
        assert_eq!(verify(&pki, &req(&long, &chain), at(NOW)), Ok(()));
        assert_eq!(verify(&pki, &req(&long, &chain), at(NOW + 86_400)), Ok(()));
        let r = verify(&pki, &req(&long, &chain), at(NOW + 86_401)).unwrap_err();
        assert_eq!(r.reason, "certificate_expired");
        // The same certificate without its intermediate has a state of its own: the accepted
        // path of the chain is not its answer.
        let alone = req(&long, &[]);
        assert!(!std::ptr::eq(
            alone.pki_state(),
            req(&long, &chain).pki_state()
        ));
        assert_eq!(
            verify(&pki, &alone, at(NOW)).unwrap_err().reason,
            "chain_invalid"
        );
        assert_eq!(verify(&pki, &req(&long, &chain), at(NOW)), Ok(()));
    }

    /// A shared answer is for one CA file and one name, as a connection's is.
    #[test]
    fn shared_states_never_carry_an_answer_to_another_ca_or_name() {
        let root = Authority::new("root", None);
        let other = Authority::new("other", None);
        let a = root.pki(san_uri(CODER).unwrap());
        let leaf = root.issue(|p| p.subject_alt_names = vec![uri(CODER)]);
        let shared = SharedStates::new();
        let req = || ClientCertificate::forwarded(leaf.clone(), &[], &shared);
        assert_eq!(verify(&a, &req(), at(NOW)), Ok(()));
        let b = Pki {
            ca_path: a.ca_path.clone(),
            ca: a.ca.clone(),
            name: san_uri("spiffe://example.org/ns/agents/sa/reviewer").unwrap(),
            crls: None,
        };
        assert_eq!(
            verify(&b, &req(), at(NOW)).unwrap_err().reason,
            "san_mismatch"
        );
        assert_eq!(
            verify(&b, &req(), at(NOW)).unwrap_err().reason,
            "san_mismatch"
        );
        assert_eq!(verify(&a, &req(), at(NOW)), Ok(()));
        // A reload that puts another CA in the file, and one that changes only the name.
        let reloaded = Pki {
            ca_path: a.ca_path.clone(),
            ca: other.pki(san_uri(CODER).unwrap()).ca,
            name: a.name.clone(),
            crls: None,
        };
        assert_eq!(
            verify(&reloaded, &req(), at(NOW)).unwrap_err().reason,
            "chain_invalid"
        );
        let renamed = Pki {
            ca_path: a.ca_path.clone(),
            ca: a.ca.clone(),
            name: san_dns("coder.agents").unwrap(),
            crls: None,
        };
        assert_eq!(
            verify(&renamed, &req(), at(NOW)).unwrap_err().reason,
            "san_mismatch"
        );
        // The same file read again: a new `Arc`, checked again, accepted again.
        let same = root.pki(san_uri(CODER).unwrap());
        assert!(!Arc::ptr_eq(&same.ca, &a.ca));
        assert_eq!(verify(&same, &req(), at(NOW)), Ok(()));
        assert!(req().pki_state().cached_answers() <= CACHED_ANSWERS);
    }

    /// At most [`SHARED_STATES`] states, the oldest dropped first; a certificate with too many
    /// intermediates is never kept; many requests at once for one certificate share one state.
    #[test]
    fn shared_states_are_bounded_and_shared_safely() {
        let shared = SharedStates::new();
        let first = shared.state(b"cert 0", Some(&[]));
        assert!(Arc::ptr_eq(&first, &shared.state(b"cert 0", Some(&[]))));
        for i in 1..SHARED_STATES + 10 {
            shared.state(format!("cert {i}").as_bytes(), Some(&[]));
        }
        assert_eq!(shared.len(), SHARED_STATES);
        assert!(!Arc::ptr_eq(&first, &shared.state(b"cert 0", Some(&[]))));
        // The key holds every certificate's length: moving bytes between the leaf and an
        // intermediate is another key.
        let ab = shared.state(b"ab", Some(&[CertificateDer::from(&b"c"[..])]));
        let a_bc = shared.state(b"a", Some(&[CertificateDer::from(&b"bc"[..])]));
        assert!(!Arc::ptr_eq(&ab, &a_bc));
        let before = shared.len();
        let too_many = shared.state(b"cert 0", None);
        assert!(!Arc::ptr_eq(&too_many, &shared.state(b"cert 0", None)));
        assert_eq!(shared.len(), before);

        let root = Authority::new("root", None);
        let pki = Arc::new(root.pki(san_uri(CODER).unwrap()));
        let leaf = root.issue(|p| p.subject_alt_names = vec![uri(CODER)]);
        let shared = Arc::new(SharedStates::new());
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (shared, pki, leaf) = (shared.clone(), pki.clone(), leaf.clone());
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        let cert = ClientCertificate::forwarded(leaf.clone(), &[], &shared);
                        assert_eq!(verify(&pki, &cert, at(NOW)), Ok(()));
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let cert = ClientCertificate::forwarded(leaf, &[], &shared);
        assert_eq!(cert.pki_state().cached_answers(), 1);
        assert_eq!(shared.len(), 1);
    }

    /// rustls-webpki does not read the client certificate's `keyUsage`: one without
    /// `digitalSignature` is accepted (ADR-0020 lists this as a known limit). The TLS
    /// handshake has already checked a signature made with the key.
    #[test]
    fn key_usage_is_not_checked() {
        let root = Authority::new("root", None);
        let pki = root.pki(san_uri(CODER).unwrap());
        let no_signing = root.issue(|p| {
            p.subject_alt_names = vec![uri(CODER)];
            p.key_usages = vec![rcgen::KeyUsagePurpose::KeyEncipherment];
        });
        assert_eq!(check(&pki, no_signing, &[]), Ok(()));
    }

    #[test]
    fn the_path_rules_hold() {
        let root = Authority::new("root", None);
        let other = Authority::new("other", None);
        let pki = root.pki(san_uri(CODER).unwrap());
        let named = |p: &mut rcgen::CertificateParams| p.subject_alt_names = vec![uri(CODER)];
        // Another CA.
        assert_eq!(check(&pki, other.issue(named), &[]), Err("chain_invalid"));
        // Dates.
        let expired = root.issue(|p| {
            named(p);
            p.not_after = at(NOW - 1);
        });
        assert_eq!(check(&pki, expired, &[]), Err("certificate_expired"));
        let early = root.issue(|p| {
            named(p);
            p.not_before = at(NOW + 1);
        });
        assert_eq!(check(&pki, early, &[]), Err("certificate_not_yet_valid"));
        // A CA certificate as the client's.
        let ca_leaf = root.issue(|p| {
            named(p);
            p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        });
        assert_eq!(check(&pki, ca_leaf, &[]), Err("certificate_not_usable"));
        // The CA's own certificate.
        assert_eq!(
            check(&pki, root.cert.der().clone(), &[]),
            Err("certificate_not_usable")
        );
        // Server use only; no extended key usage at all is fine.
        let server = root.issue(|p| {
            named(p);
            p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        });
        assert_eq!(check(&pki, server, &[]), Err("certificate_not_usable"));
        let no_eku = root.issue(|p| {
            named(p);
            p.extended_key_usages = vec![];
            p.is_ca = rcgen::IsCa::NoCa;
        });
        assert_eq!(check(&pki, no_eku, &[]), Ok(()));
        // Self-signed with the right name.
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        named(&mut params);
        params.not_before = at(NOW - 60);
        params.not_after = at(NOW + 60);
        let selfie = params.self_signed(&key).unwrap().der().clone();
        assert_eq!(check(&pki, selfie, &[]), Err("chain_invalid"));
        // An intermediate that is not a CA cannot issue.
        let fake_mid_key = rcgen::KeyPair::generate().unwrap();
        let mut fake_mid = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        fake_mid.is_ca = rcgen::IsCa::ExplicitNoCa;
        fake_mid.not_before = at(NOW - 60);
        fake_mid.not_after = at(NOW + 60);
        fake_mid
            .distinguished_name
            .push(rcgen::DnType::CommonName, "not a ca");
        let fake_mid_cert = fake_mid
            .signed_by(
                &fake_mid_key,
                &rcgen::Issuer::from_params(&root.params, &root.key),
            )
            .unwrap();
        let mut leaf_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        named(&mut leaf_params);
        leaf_params.not_before = at(NOW - 60);
        leaf_params.not_after = at(NOW + 60);
        let leaf = leaf_params
            .signed_by(
                &rcgen::KeyPair::generate().unwrap(),
                &rcgen::Issuer::from_params(&fake_mid, &fake_mid_key),
            )
            .unwrap();
        assert_eq!(
            check(&pki, leaf.der().clone(), &[fake_mid_cert.der().clone()]),
            Err("chain_invalid")
        );
        // A path length of 0 on an intermediate: no other intermediate below it. (A path
        // length on a CA of the file itself is not applied: rustls-webpki keeps only a trust
        // anchor's name and key, and its name constraints.)
        let mut strict = Authority::new("strict", Some(&root));
        strict.params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        strict.cert = strict
            .params
            .signed_by(
                &strict.key,
                &rcgen::Issuer::from_params(&root.params, &root.key),
            )
            .unwrap();
        let chain = [strict.cert.der().clone()];
        assert_eq!(check(&pki, strict.issue(named), &chain), Ok(()));
        let below = Authority::new("below", Some(&strict));
        let chain = [below.cert.der().clone(), strict.cert.der().clone()];
        assert_eq!(
            check(&pki, below.issue(named), &chain),
            Err("chain_invalid")
        );
    }

    #[test]
    fn uri_names_are_matched_exactly() {
        let root = Authority::new("root", None);
        let pki = root.pki(san_uri(CODER).unwrap());
        let with = |names: Vec<rcgen::SanType>| root.issue(|p| p.subject_alt_names = names);
        assert_eq!(
            check(
                &pki,
                with(vec![uri("spiffe://example.org/ns/agents/sa/reviewer")]),
                &[]
            ),
            Err("san_mismatch")
        );
        assert_eq!(
            check(
                &pki,
                with(vec![uri("spiffe://example.org/ns/agents/sa/Coder")]),
                &[]
            ),
            Err("san_mismatch")
        );
        assert_eq!(
            check(&pki, with(vec![uri(&format!("{CODER}/x"))]), &[]),
            Err("san_mismatch")
        );
        assert_eq!(
            check(&pki, with(vec![dns("coder")]), &[]),
            Err("uri_san_count")
        );
        // Two URI names, one of them right: not an X.509-SVID.
        assert_eq!(
            check(
                &pki,
                with(vec![uri(CODER), uri("spiffe://example.org/other")]),
                &[]
            ),
            Err("uri_san_count")
        );
        // A DNS name next to the one URI is fine.
        assert_eq!(
            check(&pki, with(vec![dns("coder"), uri(CODER)]), &[]),
            Ok(())
        );
        // A URI that is not a SPIFFE ID: any of the names may match here. (When another name
        // is the configured name of another entry of the list, client authentication refuses
        // the certificate after this check: see `clientauth`'s
        // `one_certificate_never_authenticates_two_clients_of_a_list`.)
        let plain = root.pki(san_uri("https://agents.example/coder").unwrap());
        assert_eq!(
            check(
                &plain,
                with(vec![
                    uri("https://agents.example/other"),
                    uri("https://agents.example/coder")
                ]),
                &[]
            ),
            Ok(())
        );
        assert_eq!(
            check(&plain, with(vec![uri("HTTPS://agents.example/coder")]), &[]),
            Err("san_mismatch")
        );
        // The refusal lists the certificate's names for the log.
        let leaf = with(vec![uri("spiffe://example.org/a\nb")]);
        let cert = ClientCertificate::from_handshake(&[leaf]).unwrap();
        let r = verify(&pki, &cert, at(NOW)).unwrap_err();
        assert_eq!(r.names, vec!["spiffe://example.org/a\nb".to_string()]);
    }

    #[test]
    fn dns_names_are_matched_as_dns_names() {
        let root = Authority::new("root", None);
        let pki = root.pki(san_dns("coder.agents.internal").unwrap());
        let with = |names: Vec<rcgen::SanType>| root.issue(|p| p.subject_alt_names = names);
        assert_eq!(
            check(&pki, with(vec![dns("coder.agents.internal")]), &[]),
            Ok(())
        );
        assert_eq!(
            check(&pki, with(vec![dns("CODER.Agents.Internal")]), &[]),
            Ok(())
        );
        assert_eq!(
            check(
                &pki,
                with(vec![
                    dns("other.agents.internal"),
                    dns("coder.agents.internal")
                ]),
                &[]
            ),
            Ok(())
        );
        for wrong in [
            "*.agents.internal",
            "agents.internal",
            "coder.agents.internal.evil",
            "coder",
        ] {
            assert_eq!(
                check(&pki, with(vec![dns(wrong)]), &[]),
                Err("san_mismatch"),
                "{wrong}"
            );
        }
        // A URI that spells the name is not a DNS name.
        assert_eq!(
            check(&pki, with(vec![uri("dns:coder.agents.internal")]), &[]),
            Err("san_mismatch")
        );
        // Neither is the subject's common name.
        let cn = root.issue(|p| {
            p.distinguished_name
                .push(rcgen::DnType::CommonName, "coder.agents.internal");
        });
        assert_eq!(check(&pki, cn, &[]), Err("san_mismatch"));
    }

    #[test]
    fn the_der_reads() {
        let root = Authority::new("root", None);
        assert!(is_ca(root.cert.der()));
        let leaf = root.issue(|p| p.subject_alt_names = vec![uri(CODER), dns("x"), uri("urn:a")]);
        assert!(!is_ca(&leaf));
        assert_eq!(uri_name_count(&leaf), Some(2));
        assert_eq!(not_after(&leaf), Some(NOW + 3600));
        assert_eq!(not_after(root.cert.der()), Some(NOW + 86_400));
        let t = tbs(&leaf).unwrap();
        assert_ne!(t.issuer, t.subject);
        let far = root.issue(|p| p.not_after = at(4_102_444_800)); // 2100, GeneralizedTime
        assert_eq!(not_after(&far), Some(4_102_444_800));
        let bare = root.issue(|p| p.is_ca = rcgen::IsCa::NoCa);
        assert!(!is_ca(&bare));
        assert_eq!(uri_name_count(&bare), Some(0));
        for junk in [
            &b""[..],
            b"\x30",
            b"\x30\x80",
            b"\x30\x05\x30\x03",
            b"\x1f\x00",
        ] {
            assert!(!is_ca(junk));
            assert_eq!(uri_name_count(junk), None);
        }
        // A constructed [6] counts as a URI name too.
        let san = |content: Vec<u8>| {
            root.issue(|p| {
                p.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
                    &[2, 5, 29, 17],
                    content,
                )];
            })
        };
        let constructed = san(b"\x30\x08\xa6\x03\x16\x01a\x86\x01b".to_vec());
        assert_eq!(uri_name_count(&constructed), Some(2));
        let empty = san(b"\x30\x00".to_vec());
        assert_eq!(uri_name_count(&empty), Some(0));
        assert_eq!(uri_name_count(&san(b"\x30\x03\x86\x05a".to_vec())), None);
        // A malformed basicConstraints is never a CA.
        let bc = |content: &[u8]| {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = rcgen::IsCa::NoCa;
            params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
                &[2, 5, 29, 19],
                content.to_vec(),
            )];
            params.self_signed(&key).unwrap().der().clone()
        };
        assert!(is_ca(&bc(b"\x30\x03\x01\x01\xff")));
        assert!(is_ca(&bc(b"\x30\x06\x01\x01\xff\x02\x01\x00")));
        for bad in [
            &b"\x30\x00"[..],
            b"\x30\x03\x01\x01\x01",
            b"\x30\x03\x01\x01\x00",
            b"\x30\x04\x01\x02\xff\xff",
            b"\x30\x03\x01\x01\xff\x00",
            b"\x30\x05\x01\x01\xff\x02\x00",
            b"\x30\x08\x01\x01\xff\x02\x01\x00\x05\x00",
            b"\x30\x06\x01\x01\xff\x02\x01\x80",
            b"\x30\x06\x01\x01\xff\x02\x01\xff",
            b"\x30\x04\x01\x01\xff",
            b"\x31\x03\x01\x01\xff",
            b"\x01\x01\xff",
            b"",
        ] {
            assert!(!is_ca(&bc(bad)), "{bad:02x?}");
        }
        assert_eq!(element(b"\x04\x84\xff\xff\xff\xff"), None);
        assert_eq!(
            element(b"\x04\x82\x00\x01\xaa"),
            Some((4, &b"\xaa"[..], &b""[..]))
        );
    }

    /// `validity` and `is_ca` also read raw DER from a `[server.tls]` file (`crate::tls`):
    /// on a certificate cut short at any byte, any byte changed, or dates that are not valid
    /// times, they answer `None` / "not a CA" or a value, and never panic.
    #[test]
    fn date_and_ca_reads_hold_on_malformed_der() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.not_before = at(NOW);
        params.not_after = at(NOW + 86_400);
        let der = params.self_signed(&key).unwrap().der().to_vec();
        assert_eq!(validity(&der), Some((NOW, NOW + 86_400)));
        assert!(!is_ca(&der));

        for n in 0..der.len() {
            assert_eq!(validity(&der[..n]), None, "cut at {n}");
            assert!(!is_ca(&der[..n]), "cut at {n}");
        }
        for i in 0..der.len() {
            for flip in [0x01u8, 0x80, 0xff] {
                let mut bad = der.clone();
                bad[i] ^= flip;
                let _ = validity(&bad);
                let _ = is_ca(&bad);
            }
        }

        // The two UTCTime values of the validity: `0x17 0x0d` then 13 bytes.
        let times: Vec<usize> = (0..der.len() - 15)
            .filter(|&i| der[i] == 0x17 && der[i + 1] == 13)
            .collect();
        assert_eq!(times.len(), 2, "{times:?}");
        let with = |at: usize, edit: &dyn Fn(&mut [u8])| {
            let mut bad = der.clone();
            edit(&mut bad[at..at + 15]);
            validity(&bad)
        };
        for &t in &times {
            // A letter for a digit, month 13, day 32, hour 24, no `Z`, the GeneralizedTime tag
            // on a UTCTime's length, an unknown tag.
            assert_eq!(with(t, &|b| b[2] = b'A'), None);
            assert_eq!(with(t, &|b| b[4..6].copy_from_slice(b"13")), None);
            assert_eq!(with(t, &|b| b[6..8].copy_from_slice(b"32")), None);
            assert_eq!(with(t, &|b| b[8..10].copy_from_slice(b"24")), None);
            assert_eq!(with(t, &|b| b[14] = b'X'), None);
            assert_eq!(with(t, &|b| b[0] = 0x18), None);
            assert_eq!(with(t, &|b| b[0] = 0x13), None);
        }
    }

    // --- CRLs (`tls_client_crl_paths`) ---------------------------------------------------

    use crate::client_crl::{TestCa as Ca, TestDir as Dir, TEST_NOW as CRL_NOW};

    fn crl_pki(ca: &Arc<CaFile>, name: &str, crls: &[PathBuf], strict: bool) -> Pki {
        let s = crate::client_crl::Settings {
            paths: crls,
            issuers: None,
            stale: None,
            missing: strict.then_some(crate::config::ClientCrlRule::Refuse),
        };
        let set =
            crate::client_crl::load(&s, ca, &mut crate::client_crl::Loading::new(at(CRL_NOW)))
                .unwrap();
        Pki {
            ca_path: "ca.pem".into(),
            ca: ca.clone(),
            name: san_uri(name).unwrap(),
            crls: Some(Arc::new(set)),
        }
    }

    fn crl_check(pki: &Pki, chain: &[CertificateDer<'static>], t: i64) -> Result<(), &'static str> {
        let cert = ClientCertificate::from_handshake(chain).unwrap();
        verify(pki, &cert, at(t)).map_err(|r| r.reason)
    }

    const A: &str = "spiffe://example.org/a";

    #[test]
    fn a_revoked_certificate_is_refused_and_others_from_its_ca_are_not() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let other = Ca::new("other", None);
        let ca = Arc::new(dir.ca_file("ca.pem", &[&root, &other]));
        let revoked = root.leaf(7, A);
        let fine = root.leaf(8, A);
        // The other CA's CRL lists serial 8 too: it is not the issuer of `fine`.
        let crls = [
            dir.write("root.crl", root.crl(&[7], CRL_NOW - 60, CRL_NOW + 3600, 1)),
            dir.write(
                "other.crl",
                other.crl(&[8], CRL_NOW - 60, CRL_NOW + 3600, 1),
            ),
        ];
        let pki = crl_pki(&ca, A, &crls, false);
        assert_eq!(
            crl_check(&pki, std::slice::from_ref(&revoked), CRL_NOW),
            Err("certificate_revoked")
        );
        assert_eq!(
            crl_check(&pki, std::slice::from_ref(&fine), CRL_NOW),
            Ok(())
        );
        let from_other = other.leaf(7, A);
        assert_eq!(crl_check(&pki, &[from_other], CRL_NOW), Ok(()));
        // A revoked certificate with another name gets the answer of a wrong name.
        let renamed = Pki {
            name: san_uri("spiffe://example.org/b").unwrap(),
            ..crl_pki(&ca, A, &crls, false)
        };
        assert_eq!(
            crl_check(&renamed, std::slice::from_ref(&revoked), CRL_NOW),
            Err("san_mismatch")
        );
        // Without CRLs the same certificate passes: nothing else changed.
        let none = Pki {
            crls: None,
            ..crl_pki(&ca, A, &crls, false)
        };
        assert_eq!(crl_check(&none, &[revoked], CRL_NOW), Ok(()));
        // Expired is still expired, not revoked.
        assert_eq!(
            crl_check(&pki, &[root.leaf(7, A)], CRL_NOW + 7200),
            Err("certificate_expired")
        );
    }

    #[test]
    fn a_revoked_intermediate_refuses_its_certificates() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let mid = Ca::numbered("mid", &root, 99);
        let good_mid = Ca::numbered("good-mid", &root, 100);
        let ca = Arc::new(dir.ca_file("ca.pem", &[&root]));
        let crls = [dir.write("root.crl", root.crl(&[99], CRL_NOW - 60, CRL_NOW + 3600, 1))];
        let pki = crl_pki(&ca, A, &crls, false);
        let leaf = mid.leaf(1, A);
        assert_eq!(
            crl_check(&pki, &[leaf, mid.cert.der().clone()], CRL_NOW),
            Err("certificate_revoked")
        );
        let leaf = good_mid.leaf(1, A);
        assert_eq!(
            crl_check(&pki, &[leaf.clone(), good_mid.cert.der().clone()], CRL_NOW),
            Ok(())
        );
        // `tls_client_crl_missing = "refuse"`: the intermediate has no CRL of its own.
        let strict = crl_pki(&ca, A, &crls, true);
        assert_eq!(
            crl_check(
                &strict,
                &[leaf.clone(), good_mid.cert.der().clone()],
                CRL_NOW
            ),
            Err("crl_missing")
        );
        // With the intermediate's CRL (its key from tls_client_crl_issuer_pem_path).
        let issuers = dir.write("issuers.pem", good_mid.cert.pem());
        let both = [
            crls[0].clone(),
            dir.write(
                "mid.crl",
                good_mid.crl(&[2], CRL_NOW - 60, CRL_NOW + 3600, 1),
            ),
        ];
        let s = crate::client_crl::Settings {
            paths: &both,
            issuers: Some(&issuers),
            stale: None,
            missing: Some(crate::config::ClientCrlRule::Refuse),
        };
        let set =
            crate::client_crl::load(&s, &ca, &mut crate::client_crl::Loading::new(at(CRL_NOW)))
                .unwrap();
        let strict = Pki {
            crls: Some(Arc::new(set)),
            ..crl_pki(&ca, A, &crls, true)
        };
        let chain = |l| vec![l, good_mid.cert.der().clone()];
        assert_eq!(crl_check(&strict, &chain(leaf), CRL_NOW), Ok(()));
        assert_eq!(
            crl_check(&strict, &chain(good_mid.leaf(2, A)), CRL_NOW),
            Err("certificate_revoked")
        );
    }

    /// A stale CRL refuses once the clock passes its `nextUpdate`, with no reload: the cached
    /// answer ends a second before.
    #[test]
    fn a_crl_that_goes_stale_refuses_without_a_reload() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let ca = Arc::new(dir.ca_file("ca.pem", &[&root]));
        let crls = [dir.write("root.crl", root.crl(&[], CRL_NOW - 60, CRL_NOW + 100, 1))];
        let pki = crl_pki(&ca, A, &crls, false);
        let cert = ClientCertificate::from_handshake(&[root.leaf(1, A)]).unwrap();
        assert_eq!(verify(&pki, &cert, at(CRL_NOW)), Ok(()));
        assert_eq!(cert.pki_state().cached_answers(), 1);
        assert_eq!(verify(&pki, &cert, at(CRL_NOW + 99)), Ok(()));
        assert_eq!(
            verify(&pki, &cert, at(CRL_NOW + 100)).unwrap_err().reason,
            "crl_stale"
        );
        // `tls_client_crl_stale = "allow"`: still accepted, and cached to the certificate's
        // own end.
        let s = crate::client_crl::Settings {
            paths: &crls,
            issuers: None,
            stale: Some(crate::config::ClientCrlRule::Allow),
            missing: None,
        };
        let set =
            crate::client_crl::load(&s, &ca, &mut crate::client_crl::Loading::new(at(CRL_NOW)))
                .unwrap();
        let allow = Pki {
            crls: Some(Arc::new(set)),
            ..crl_pki(&ca, A, &crls, false)
        };
        assert_eq!(verify(&allow, &cert, at(CRL_NOW + 200)), Ok(()));
        assert_eq!(verify(&allow, &cert, at(CRL_NOW + 3600)), Ok(()));
    }

    /// An answer cached under one set of CRLs is never used under another, on a connection or
    /// in the forwarding listener's shared states: a reload that adds a revocation refuses the
    /// certificate on the next request.
    #[test]
    fn a_new_crl_is_never_answered_from_the_cache() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let ca = Arc::new(dir.ca_file("ca.pem", &[&root]));
        let before = [dir.write("1.crl", root.crl(&[], CRL_NOW - 60, CRL_NOW + 3600, 1))];
        let after = [dir.write("2.crl", root.crl(&[5], CRL_NOW - 30, CRL_NOW + 3600, 2))];
        let leaf = root.leaf(5, A);
        let old = crl_pki(&ca, A, &before, false);
        let new = crl_pki(&ca, A, &after, false);
        let cert = ClientCertificate::from_handshake(std::slice::from_ref(&leaf)).unwrap();
        assert_eq!(verify(&old, &cert, at(CRL_NOW)), Ok(()));
        assert_eq!(verify(&old, &cert, at(CRL_NOW)), Ok(()));
        assert_eq!(
            verify(&new, &cert, at(CRL_NOW)).unwrap_err().reason,
            "certificate_revoked"
        );
        // The refusal is not cached, and the old answer is not reused.
        assert_eq!(
            verify(&new, &cert, at(CRL_NOW)).unwrap_err().reason,
            "certificate_revoked"
        );
        // The same file read again is a new set: checked again.
        let again = crl_pki(&ca, A, &before, false);
        assert!(!Arc::ptr_eq(
            again.crls.as_ref().unwrap(),
            old.crls.as_ref().unwrap()
        ));
        assert_eq!(verify(&again, &cert, at(CRL_NOW)), Ok(()));
        // Forwarded certificates: the same rules through the shared states.
        let shared = SharedStates::new();
        let req = || ClientCertificate::forwarded(leaf.clone(), &[], &shared);
        assert_eq!(verify(&old, &req(), at(CRL_NOW)), Ok(()));
        assert_eq!(req().pki_state().cached_answers(), 1);
        assert_eq!(
            verify(&new, &req(), at(CRL_NOW)).unwrap_err().reason,
            "certificate_revoked"
        );
        assert_eq!(verify(&old, &req(), at(CRL_NOW)), Ok(()));
        // A set no one holds any more is dropped from the cache.
        drop(old);
        drop(again);
        for i in 0..CACHED_ANSWERS {
            let n = format!("spiffe://example.org/n{i}");
            let p = Pki {
                name: san_uri(&n).unwrap(),
                ..crl_pki(&ca, A, &before, false)
            };
            let _ = verify(&p, &cert, at(CRL_NOW));
        }
        assert!(cert.pki_state().cached_answers() <= CACHED_ANSWERS);
    }

    fn crl_pki_with(
        ca: &Arc<CaFile>,
        crls: &[PathBuf],
        issuers: Option<&Path>,
        strict: bool,
    ) -> Pki {
        let s = crate::client_crl::Settings {
            paths: crls,
            issuers,
            stale: None,
            missing: strict.then_some(crate::config::ClientCrlRule::Refuse),
        };
        let set =
            crate::client_crl::load(&s, ca, &mut crate::client_crl::Loading::new(at(CRL_NOW)))
                .unwrap();
        Pki {
            ca_path: "ca.pem".into(),
            ca: ca.clone(),
            name: san_uri(A).unwrap(),
            crls: Some(Arc::new(set)),
        }
    }

    /// The review's case: an intermediate the root's CRL revokes is also in the CA file, so
    /// rustls-webpki ends the path at it (anchors first). It is checked as an intermediate is.
    #[test]
    fn review_revoked_intermediate_also_in_ca_file() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let mid = Ca::numbered("mid", &root, 99);
        let ca = Arc::new(dir.ca_file("ca.pem", &[&root, &mid]));
        let crls = [dir.write("root.crl", root.crl(&[99], CRL_NOW - 60, CRL_NOW + 3600, 1))];
        let pki = crl_pki(&ca, A, &crls, false);
        let leaf = mid.leaf(1, A);
        assert_eq!(
            crl_check(&pki, &[leaf.clone(), mid.cert.der().clone()], CRL_NOW),
            Err("certificate_revoked")
        );
        // With no intermediate sent too, and with the CA file in the other order.
        assert_eq!(
            crl_check(&pki, std::slice::from_ref(&leaf), CRL_NOW),
            Err("certificate_revoked")
        );
        let ca = Arc::new(dir.ca_file("ca2.pem", &[&mid, &root]));
        let pki = crl_pki(&ca, A, &crls, false);
        assert_eq!(
            crl_check(&pki, std::slice::from_ref(&leaf), CRL_NOW),
            Err("certificate_revoked")
        );
        // The root's other certificates, and an intermediate it does not revoke.
        let fine = Ca::numbered("fine", &root, 100);
        let ca = Arc::new(dir.ca_file("ca3.pem", &[&root, &mid, &fine]));
        let pki = crl_pki(&ca, A, &crls, false);
        assert_eq!(crl_check(&pki, &[root.leaf(5, A)], CRL_NOW), Ok(()));
        assert_eq!(crl_check(&pki, &[fine.leaf(5, A)], CRL_NOW), Ok(()));
    }

    /// `tls_client_crl_missing = "refuse"` with an intermediate in the CA file: the root that
    /// issued it needs its CRL, as for an intermediate sent by the client.
    #[test]
    fn an_anchor_below_another_needs_that_ones_crl_under_refuse() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let mid = Ca::numbered("mid", &root, 99);
        let ca = Arc::new(dir.ca_file("ca.pem", &[&root, &mid]));
        let mid_crl = dir.write("mid.crl", mid.crl(&[], CRL_NOW - 60, CRL_NOW + 3600, 1));
        let root_crl = dir.write("root.crl", root.crl(&[], CRL_NOW - 60, CRL_NOW + 3600, 1));
        let leaf = mid.leaf(1, A);
        let only_mid = crl_pki(&ca, A, std::slice::from_ref(&mid_crl), true);
        assert_eq!(
            crl_check(&only_mid, std::slice::from_ref(&leaf), CRL_NOW),
            Err("crl_missing")
        );
        // Allowed by default.
        let allow = crl_pki(&ca, A, std::slice::from_ref(&mid_crl), false);
        assert_eq!(
            crl_check(&allow, std::slice::from_ref(&leaf), CRL_NOW),
            Ok(())
        );
        let both = crl_pki(&ca, A, &[root_crl.clone(), mid_crl.clone()], true);
        assert_eq!(
            crl_check(&both, std::slice::from_ref(&leaf), CRL_NOW),
            Ok(())
        );
        // The root's CRL goes stale: the anchor's check is stale too.
        assert_eq!(
            crl_check(&both, std::slice::from_ref(&leaf), CRL_NOW + 3600),
            Err("crl_stale")
        );
        // An anchor whose issuer neither file holds is a root here: not checked above.
        let ca = Arc::new(dir.ca_file("mid-only.pem", &[&mid]));
        let pki = crl_pki(&ca, A, std::slice::from_ref(&mid_crl), true);
        assert_eq!(
            crl_check(&pki, std::slice::from_ref(&leaf), CRL_NOW),
            Ok(())
        );
    }

    /// A self-signed root is never looked up in a CRL, its own included: a CRL that lists the
    /// root's serial number does not refuse it.
    #[test]
    fn a_self_signed_root_is_unaffected() {
        let dir = Dir::new();
        let root = Ca::root_numbered("root", 77);
        let ca = Arc::new(dir.ca_file("ca.pem", &[&root]));
        let crls = [dir.write("root.crl", root.crl(&[77], CRL_NOW - 60, CRL_NOW + 3600, 1))];
        for strict in [false, true] {
            let pki = crl_pki(&ca, A, &crls, strict);
            assert_eq!(crl_check(&pki, &[root.leaf(5, A)], CRL_NOW), Ok(()));
            assert_eq!(
                crl_check(&pki, &[root.leaf(77, A)], CRL_NOW),
                Err("certificate_revoked")
            );
        }
    }

    /// An anchor issued by a certificate of `tls_client_crl_issuer_pem_path`: checked in that
    /// certificate's CRL, and that certificate in the root's.
    #[test]
    fn an_anchor_issued_by_an_issuer_file_certificate() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let mid = Ca::numbered("mid", &root, 10);
        let low = Ca::numbered("low", &mid, 20);
        let ca = Arc::new(dir.ca_file("ca.pem", &[&root, &low]));
        let issuers = dir.write("issuers.pem", mid.cert.pem());
        let leaf = low.leaf(1, A);
        let crl = |name: &str, ca: &Ca, serials: &[u64]| {
            dir.write(name, ca.crl(serials, CRL_NOW - 60, CRL_NOW + 3600, 1))
        };
        let good = crl_pki_with(
            &ca,
            &[
                crl("r0.crl", &root, &[]),
                crl("m0.crl", &mid, &[]),
                crl("l0.crl", &low, &[]),
            ],
            Some(&issuers),
            true,
        );
        assert_eq!(
            crl_check(&good, std::slice::from_ref(&leaf), CRL_NOW),
            Ok(())
        );
        // The intermediate's CRL revokes the anchor.
        let pki = crl_pki_with(
            &ca,
            &[crl("r1.crl", &root, &[]), crl("m1.crl", &mid, &[20])],
            Some(&issuers),
            false,
        );
        assert_eq!(
            crl_check(&pki, std::slice::from_ref(&leaf), CRL_NOW),
            Err("certificate_revoked")
        );
        // The root's CRL revokes the intermediate above the anchor.
        let pki = crl_pki_with(&ca, &[crl("r2.crl", &root, &[10])], Some(&issuers), false);
        assert_eq!(
            crl_check(&pki, std::slice::from_ref(&leaf), CRL_NOW),
            Err("certificate_revoked")
        );
        // Without the intermediate's CRL under "refuse": unknown.
        let pki = crl_pki_with(
            &ca,
            &[crl("r3.crl", &root, &[]), crl("l3.crl", &low, &[])],
            Some(&issuers),
            true,
        );
        assert_eq!(
            crl_check(&pki, std::slice::from_ref(&leaf), CRL_NOW),
            Err("crl_missing")
        );
    }

    /// Two CAs with one name and different keys in the CA file: each certificate is looked up
    /// in the CRL of the key that signed it, never in the other's.
    #[test]
    fn same_name_different_keys_at_request_time() {
        let dir = Dir::new();
        let root = Ca::new("root", None);
        let twin = root.impostor("root");
        let ca = Arc::new(dir.ca_file("ca.pem", &[&root, &twin]));
        let crls = [dir.write("root.crl", root.crl(&[7], CRL_NOW - 60, CRL_NOW + 3600, 1))];
        let pki = crl_pki(&ca, A, &crls, false);
        assert_eq!(
            crl_check(&pki, &[root.leaf(7, A)], CRL_NOW),
            Err("certificate_revoked")
        );
        assert_eq!(crl_check(&pki, &[twin.leaf(7, A)], CRL_NOW), Ok(()));
        let strict = crl_pki(&ca, A, &crls, true);
        assert_eq!(
            crl_check(&strict, &[twin.leaf(8, A)], CRL_NOW),
            Err("crl_missing")
        );
        assert_eq!(crl_check(&strict, &[root.leaf(8, A)], CRL_NOW), Ok(()));
    }

    /// A cross-signed intermediate (one name and key, a certificate from each of two roots),
    /// where only the first root has a CRL, which revokes its certificate of the intermediate.
    /// Revocation is of a certificate: the path through the other root's certificate is not
    /// revoked, so it is accepted while that root's missing CRL is allowed, and refused as
    /// unknown under "refuse". The same with the intermediate in the CA file (no chain sent):
    /// the worst over its issuers' CRLs, so revoked.
    #[test]
    fn a_cross_signed_intermediate_with_one_crl() {
        let dir = Dir::new();
        let one = Ca::new("one", None);
        let two = Ca::new("two", None);
        let mid = Ca::numbered("mid", &one, 50);
        let mid_by_two = mid.cross(&two, 51);
        let ca = Arc::new(dir.ca_file("ca.pem", &[&one, &two]));
        let crls = [dir.write("one.crl", one.crl(&[50], CRL_NOW - 60, CRL_NOW + 3600, 1))];
        let leaf = mid.leaf(1, A);
        let allow = crl_pki(&ca, A, &crls, false);
        let strict = crl_pki(&ca, A, &crls, true);
        let via_one = [leaf.clone(), mid.cert.der().clone()];
        let via_two = [leaf.clone(), mid_by_two.cert.der().clone()];
        assert_eq!(
            crl_check(&allow, &via_one, CRL_NOW),
            Err("certificate_revoked")
        );
        assert_eq!(crl_check(&allow, &via_two, CRL_NOW), Ok(()));
        assert_eq!(
            crl_check(&strict, &via_one, CRL_NOW),
            Err("certificate_revoked")
        );
        assert_eq!(crl_check(&strict, &via_two, CRL_NOW), Err("crl_missing"));
        // Both certificates of the intermediate in the CA file.
        let ca = Arc::new(dir.ca_file("ca2.pem", &[&one, &two, &mid, &mid_by_two]));
        let pki = crl_pki(&ca, A, &crls, false);
        assert_eq!(
            crl_check(&pki, std::slice::from_ref(&leaf), CRL_NOW),
            Err("certificate_revoked")
        );
        // Only the second root's certificate of it in the CA file: not revoked.
        let ca = Arc::new(dir.ca_file("ca3.pem", &[&one, &two, &mid_by_two]));
        let pki = crl_pki(&ca, A, &crls, false);
        assert_eq!(
            crl_check(&pki, std::slice::from_ref(&leaf), CRL_NOW),
            Ok(())
        );
    }
}
