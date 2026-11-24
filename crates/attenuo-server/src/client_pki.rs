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
//!    certificate). No revocation check: no CRL, no OCSP.
//! 2. The name. A URI is compared exactly, byte for byte. A `spiffe://` value also needs the
//!    certificate to carry exactly one URI name, as an X.509-SVID does. A DNS name is
//!    compared without regard to ASCII case; a wildcard name in the certificate
//!    (`*.example.org`) never matches, since the configured name cannot be a wildcard. The
//!    subject DN, IP addresses and e-mail addresses are never matched.
//!
//! The CA file is read at start and by an agents reload, with the size and file-type rules of
//! the other CA files. No error shows a part of the file: every message is a fixed text.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::pem::{PemObject, SectionKind};
use rustls::pki_types::{CertificateDer, TrustAnchor, UnixTime};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::client_cert::ClientCertificate;

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

/// The CA certificates of one `tls_client_ca_pem_path` file, as trust anchors.
pub(crate) struct CaFile {
    anchors: Vec<TrustAnchor<'static>>,
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
}

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
}

impl std::fmt::Debug for Pki {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pki")
            .field("ca_path", &self.ca_path)
            .field("ca_certificates", &self.ca.len())
            .field("name", &self.name.key())
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
fn ca_file(pem: &[u8]) -> Result<CaFile, String> {
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
    }
    Ok(CaFile {
        anchors,
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

/// Whether `cert` authenticates an entry with these settings at `now`: the path to one of its
/// CAs (see the module docs), then the name.
pub(crate) fn verify(
    pki: &Pki,
    cert: &ClientCertificate,
    now: OffsetDateTime,
) -> Result<(), Refused> {
    let Some(intermediates) = cert.intermediates() else {
        return Err(Refused::because("too_many_intermediates"));
    };
    let ee = webpki::EndEntityCert::try_from(cert.der())
        .map_err(|_| Refused::because("certificate_not_usable"))?;
    let secs = u64::try_from(now.unix_timestamp()).unwrap_or(0);
    let at = UnixTime::since_unix_epoch(std::time::Duration::from_secs(secs));
    ee.verify_for_usage(
        crate::client_cert::provider()
            .signature_verification_algorithms
            .all,
        &pki.ca.anchors,
        intermediates,
        at,
        webpki::KeyUsage::client_auth(),
        None,
        None,
    )
    .map_err(|e| Refused::because(path_error(&e)))?;
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
// Only on bytes rustls-webpki has already parsed as a certificate. Every read is bounds
// checked and returns `None` on anything unexpected; nothing here decides trust alone: it
// only refuses more (a CA file entry that is not a CA, a second URI name).

/// One DER element of `input`: (tag, contents, the rest). Low tag numbers and definite
/// lengths of up to four bytes only.
fn element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
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
fn expect(input: &[u8], want: u8) -> Option<(&[u8], &[u8])> {
    let (tag, contents, rest) = element(input)?;
    (tag == want).then_some((contents, rest))
}

const SEQUENCE: u8 = 0x30;

/// The `extnValue` contents of the extension `oid` of a certificate: `Some(None)` when the
/// certificate has no such extension.
fn extension<'a>(cert: &'a [u8], oid: &[u8]) -> Option<Option<&'a [u8]>> {
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

/// Whether a certificate's `basicConstraints` (2.5.29.19) says `cA` TRUE.
fn is_ca(cert: &[u8]) -> bool {
    let ca = || -> Option<bool> {
        let Some(value) = extension(cert, &[0x55, 0x1d, 0x13])? else {
            return Some(false);
        };
        let (bc, _) = expect(value, SEQUENCE)?;
        match expect(bc, 0x01) {
            Some((flag, _)) => Some(flag == [0xff]),
            None => Some(false),
        }
    };
    ca().unwrap_or(false)
}

/// How many `uniformResourceIdentifier` names (tag `[6]`) a certificate's
/// `subjectAltName` (2.5.29.17) holds; `None` when it cannot be read.
fn uri_name_count(cert: &[u8]) -> Option<usize> {
    let Some(value) = extension(cert, &[0x55, 0x1d, 0x11])? else {
        return Some(0);
    };
    let (mut names, _) = expect(value, SEQUENCE)?;
    let mut count = 0;
    while !names.is_empty() {
        let (tag, _, rest) = element(names)?;
        names = rest;
        if tag == 0x86 {
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
        verify(pki, &cert, at(NOW)).map_err(|r| r.reason)
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
        // A URI that is not a SPIFFE ID: any of the names may match.
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
        assert_eq!(element(b"\x04\x84\xff\xff\xff\xff"), None);
        assert_eq!(
            element(b"\x04\x82\x00\x01\xaa"),
            Some((4, &b"\xaa"[..], &b""[..]))
        );
    }
}
