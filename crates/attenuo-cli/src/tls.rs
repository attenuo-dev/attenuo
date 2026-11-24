//! `--tls-ca-cert`, `--tls-client-cert` and `--tls-client-key`: the CA the CLI trusts for the
//! attenuo server's certificate, and the TLS client certificate it presents to it (RFC 8705
//! `self_signed_tls_client_auth`).
//!
//! The rules:
//!
//! - Each option comes from its flag, else from its environment variable
//!   (`ATTENUO_TLS_CA_CERT`, `ATTENUO_TLS_CLIENT_CERT`, `ATTENUO_TLS_CLIENT_KEY`). An empty
//!   environment variable is unset; an empty flag value is a usage error.
//! - With `--tls-ca-cert`, the certificates in that file are the only roots trusted for
//!   `--server`, `--admin-server` and an `approval verify --jwks` URL: the public web PKI roots
//!   built into the CLI are not trusted next to them. Without it, the built-in roots are used,
//!   as before.
//! - `--tls-client-cert` and `--tls-client-key` go together, and need an `https://`
//!   `--server`. The certificate is presented on connections to the origin of `--server`
//!   only (`Client::client_for`): never to an `--admin-server` or a `--jwks` URL on another
//!   origin. The clients follow no redirect (SR-112), so it cannot be carried to a host named
//!   in a `Location` either. One exception: with an `https://` proxy in `HTTPS_PROXY`, reqwest
//!   uses these settings for the TLS connection to the proxy too, so the proxy's certificate
//!   must chain to `--tls-ca-cert`, and the client certificate is offered to the proxy if it
//!   asks for one. An `http://` proxy (a CONNECT tunnel) sees neither.
//! - Every file is read once, before any request is sent. Anything but a regular file (a
//!   FIFO, a directory) is refused before it is read. A file that cannot be read, is empty,
//!   or does not hold what its flag needs is an error that names the flag and the path, and
//!   nothing else: no parser message, which could quote the file (a key file's line, for
//!   instance), goes into it.
//! - The CLI's own buffers for the key file are sized from the file's length, so reading does
//!   not reallocate them, and are zeroed when dropped. reqwest and rustls keep their own copy
//!   of the key in memory for as long as the process runs; that copy is not zeroed by the
//!   CLI. No `Debug` output shows key bytes.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use reqwest::{Certificate, ClientBuilder, Identity};
use rustls_pki_types::pem::{PemObject, SectionKind};
use zeroize::Zeroizing;

/// The largest CA bundle read (a system bundle is a few hundred KiB).
const MAX_CA_BYTES: u64 = 4 << 20;
/// The largest client certificate or key file read.
const MAX_CLIENT_BYTES: u64 = 1 << 20;

/// What `--tls-ca-cert`, `--tls-client-cert` and `--tls-client-key` set, read and checked.
/// The default trusts the built-in roots and presents no certificate: the CLI as it was.
#[derive(Clone, Default)]
pub(crate) struct Tls {
    /// `--tls-ca-cert`: its path and its certificates, the only roots trusted when set.
    roots: Option<(PathBuf, Vec<Certificate>)>,
    /// `--tls-client-cert` and `--tls-client-key`: their paths and the identity they make.
    client: Option<(PathBuf, PathBuf, Identity)>,
}

/// Paths and counts only: never a byte of a certificate or a key.
impl std::fmt::Debug for Tls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls")
            .field("ca_cert", &self.roots.as_ref().map(|(p, c)| (p, c.len())))
            .field(
                "client_cert",
                &self
                    .client
                    .as_ref()
                    .map(|(c, k, _)| (c, k, "<key not shown>")),
            )
            .finish()
    }
}

/// Which listener a client is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Target {
    /// `--server`: the CA, and the client certificate when one is given.
    Server,
    /// `--admin-server`: the CA only.
    Admin,
}

impl Tls {
    /// Read and check the three options, each from its flag or else its environment
    /// variable ([`resolve`]).
    pub(crate) fn from_flags(
        ca_cert: Option<&Path>,
        client_cert: Option<&Path>,
        client_key: Option<&Path>,
    ) -> Result<Self> {
        let env = |name: &str| std::env::var_os(name);
        let ca = resolve(ca_cert, CA_FLAG, CA_ENV, env(CA_ENV));
        let cert = resolve(client_cert, CERT_FLAG, CERT_ENV, env(CERT_ENV));
        let key = resolve(client_key, KEY_FLAG, KEY_ENV, env(KEY_ENV));
        fn given<'a>(g: &'a Option<(PathBuf, &'static str)>) -> Option<Given<'a>> {
            g.as_ref().map(|(path, name)| Given { path, name })
        }
        Self::load_from(given(&ca), given(&cert), given(&key))
    }

    /// [`Tls::load_from`] with paths given by the flags.
    #[cfg(test)]
    pub(crate) fn load(
        ca_cert: Option<&Path>,
        client_cert: Option<&Path>,
        client_key: Option<&Path>,
    ) -> Result<Self> {
        fn flag<'a>(path: Option<&'a Path>, name: &'static str) -> Option<Given<'a>> {
            path.map(|path| Given { path, name })
        }
        Self::load_from(
            flag(ca_cert, CA_FLAG),
            flag(client_cert, CERT_FLAG),
            flag(client_key, KEY_FLAG),
        )
    }

    /// Read and check the three options. `None` is unset. Each error names the flag or the
    /// environment variable the path came from.
    pub(crate) fn load_from(
        ca_cert: Option<Given<'_>>,
        client_cert: Option<Given<'_>>,
        client_key: Option<Given<'_>>,
    ) -> Result<Self> {
        // The pairing is checked before any file is read.
        let pair = match (client_cert, client_key) {
            (Some(c), Some(k)) => Some((c, k)),
            (None, None) => None,
            (Some(c), None) => bail!(
                "{} needs --tls-client-key (or {KEY_ENV}): the private key of the certificate",
                c.name
            ),
            (None, Some(k)) => bail!(
                "{} needs --tls-client-cert (or {CERT_ENV}): the certificate of the key",
                k.name
            ),
        };
        let mut tls = Tls::default();
        if let Some(ca) = ca_cert {
            tls.roots = Some((ca.path.to_path_buf(), read_ca(ca.name, ca.path)?));
            // A certificate that rustls cannot take as a trust anchor fails here, not on the
            // first request.
            tls.build(Target::Admin, ClientBuilder::new())
                .map_err(|_| {
                    anyhow!(
                        "{} {}: a certificate in it cannot be used as a CA certificate",
                        ca.name,
                        ca.path.display()
                    )
                })?;
        }
        if let Some((cert, key)) = pair {
            let identity = read_identity(cert, key)?;
            tls.client = Some((cert.path.to_path_buf(), key.path.to_path_buf(), identity));
            // A key that is not the certificate's, or of a type rustls cannot sign with,
            // fails here. The error from rustls is not shown.
            tls.build(Target::Server, ClientBuilder::new())
                .map_err(|_| {
                    anyhow!(
                        "{} {} is not the private key of the certificate in {} {}, or its key \
                         type is not supported (Ed25519, ECDSA P-256 or P-384, RSA)",
                        key.name,
                        key.path.display(),
                        cert.name,
                        cert.path.display()
                    )
                })?;
        }
        Ok(tls)
    }

    /// Check the options against the URLs they are for: a client certificate needs an
    /// `https://` `--server` (an error, before any request). A CA with no `https://` URL to
    /// apply to does nothing, which the returned warning says.
    pub(crate) fn check_targets(
        &self,
        server: &str,
        admin: Option<&str>,
    ) -> Result<Option<String>> {
        let https = |u: &str| u.trim_start().to_ascii_lowercase().starts_with("https://");
        if self.client.is_some() && !https(server) {
            bail!(
                "--tls-client-cert and --tls-client-key (or ATTENUO_TLS_CLIENT_CERT and \
                 ATTENUO_TLS_CLIENT_KEY) need an https:// --server; a client certificate cannot \
                 be sent over plain HTTP"
            );
        }
        if self.roots.is_some() && !https(server) && !admin.is_some_and(https) {
            return Ok(Some(
                "warning: --tls-ca-cert (or ATTENUO_TLS_CA_CERT) is set, but neither --server \
                 nor --admin-server is https://, so it is not used"
                    .to_owned(),
            ));
        }
        Ok(None)
    }

    /// Whether a client certificate is presented to `--server`.
    pub(crate) fn has_client_cert(&self) -> bool {
        self.client.is_some()
    }

    /// `builder` with the roots and, for [`Target::Server`], the client certificate.
    pub(crate) fn apply(&self, target: Target, mut builder: ClientBuilder) -> ClientBuilder {
        if let Some((_, roots)) = &self.roots {
            builder = builder.tls_built_in_root_certs(false);
            for root in roots {
                builder = builder.add_root_certificate(root.clone());
            }
        }
        if let Some(identity) = self.identity_for(target) {
            builder = builder.identity(identity.clone());
        }
        builder
    }

    /// The client certificate to present to `target`: only ever to `--server`.
    fn identity_for(&self, target: Target) -> Option<&Identity> {
        match target {
            Target::Server => self.client.as_ref().map(|(_, _, id)| id),
            Target::Admin => None,
        }
    }

    /// Build `builder` with [`Tls::apply`]. A failure names no rustls detail.
    pub(crate) fn build(&self, target: Target, builder: ClientBuilder) -> Result<reqwest::Client> {
        let configured = self.roots.is_some() || self.client.is_some();
        self.apply(target, builder).build().map_err(|e| {
            if configured {
                anyhow!("cannot set up TLS with the --tls-* options")
            } else {
                anyhow::Error::new(e)
            }
        })
    }
}

/// The environment variables of the three options.
const CA_ENV: &str = "ATTENUO_TLS_CA_CERT";
const CA_FLAG: &str = "--tls-ca-cert";
const CERT_FLAG: &str = "--tls-client-cert";
const KEY_FLAG: &str = "--tls-client-key";
const CERT_ENV: &str = "ATTENUO_TLS_CLIENT_CERT";
const KEY_ENV: &str = "ATTENUO_TLS_CLIENT_KEY";

/// A path and where it came from: the flag's name, or the environment variable's, which
/// every error about it names.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Given<'a> {
    pub(crate) path: &'a Path,
    pub(crate) name: &'static str,
}

/// The flag's path (named `flag`), else the environment variable `var`'s when it is not
/// empty (a compose file's `${VAR:-}` gives an empty one). An empty flag value never gets
/// here: clap refuses it.
fn resolve(
    path: Option<&Path>,
    flag: &'static str,
    var: &'static str,
    env: Option<std::ffi::OsString>,
) -> Option<(PathBuf, &'static str)> {
    match path {
        Some(p) => Some((p.to_path_buf(), flag)),
        None => env
            .filter(|v| !v.is_empty())
            .map(|v| (PathBuf::from(v), var)),
    }
}

/// Open `path` for reading without blocking on a FIFO or a device: on Unix with
/// `O_NONBLOCK`, which a regular file ignores.
fn open(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // `O_NONBLOCK` is a small positive flag; the cast cannot change it.
        #[allow(clippy::cast_possible_wrap)]
        options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
    }
    options.open(path)
}

/// Read at most `max` bytes of `path` for `flag`. Anything but a regular file is refused
/// before it is read, as checked on the open handle; a larger file is an error, and so is
/// one with nothing but white space. The buffer is sized from the file's length, so it is not
/// reallocated (and an old copy left behind) while it is read.
fn read_file(flag: &str, path: &Path, max: u64) -> Result<Zeroizing<Vec<u8>>> {
    let cannot = |e: std::io::Error| anyhow!("cannot read {flag} {}: {e}", path.display());
    let file = open(path).map_err(cannot)?;
    let meta = file.metadata().map_err(cannot)?;
    if !meta.is_file() {
        bail!("{flag} {} is not a regular file", path.display());
    }
    if meta.len() > max {
        bail!("{flag} {} is larger than {max} bytes", path.display());
    }
    let len = usize::try_from(meta.len()).unwrap_or(0);
    let mut buf = Zeroizing::new(Vec::with_capacity(len));
    file.take(max + 1).read_to_end(&mut buf).map_err(cannot)?;
    if buf.len() as u64 > max {
        bail!("{flag} {} is larger than {max} bytes", path.display());
    }
    if buf.iter().all(u8::is_ascii_whitespace) {
        bail!("{flag} {} is empty", path.display());
    }
    Ok(buf)
}

/// The PEM sections of `bytes`, or an error naming only `flag` and `path`. Sections with a
/// label rustls does not know (`TRUSTED CERTIFICATE`, `EC PARAMETERS`) are skipped; each
/// section's DER is zeroed when dropped.
fn sections(
    flag: &str,
    path: &Path,
    bytes: &[u8],
) -> Result<Vec<(SectionKind, Zeroizing<Vec<u8>>)>> {
    let mut out = Vec::new();
    for item in <(SectionKind, Vec<u8>)>::pem_slice_iter(bytes) {
        // The parser's error can quote a line of the file: it is dropped, not shown.
        let Ok((kind, der)) = item else {
            bail!("{flag} {} is not a readable PEM file", path.display());
        };
        out.push((kind, Zeroizing::new(der)));
    }
    Ok(out)
}

/// The labels of the PEM `BEGIN` lines of `bytes` (`CERTIFICATE`, `PRIVATE KEY`, ...),
/// whether or not rustls knows them. Only compared, never shown: they come from the file.
fn begin_labels(bytes: &[u8]) -> Vec<&[u8]> {
    bytes
        .split(|b| *b == b'\n')
        .filter_map(|line| {
            let line = line.trim_ascii();
            line.strip_prefix(b"-----BEGIN ")?.strip_suffix(b"-----")
        })
        .collect()
}

/// Whether any `BEGIN` line of `bytes` starts a private key of any kind, including those
/// rustls does not read (`ENCRYPTED PRIVATE KEY`, `OPENSSH PRIVATE KEY`, `DSA PRIVATE KEY`).
fn has_any_private_key(bytes: &[u8]) -> bool {
    begin_labels(bytes)
        .iter()
        .any(|l| l.ends_with(b"PRIVATE KEY"))
}

fn is_private_key(kind: SectionKind) -> bool {
    matches!(
        kind,
        SectionKind::PrivateKey | SectionKind::RsaPrivateKey | SectionKind::EcPrivateKey
    )
}

/// The certificates of the `--tls-ca-cert` bundle: at least one, and no private key.
fn read_ca(flag: &str, path: &Path) -> Result<Vec<Certificate>> {
    let bytes = read_file(flag, path, MAX_CA_BYTES)?;
    if has_any_private_key(&bytes) {
        bail!(
            "{flag} {} holds a private key; it must hold only the CA certificates",
            path.display()
        );
    }
    let sections = sections(flag, path, &bytes)?;
    if sections.iter().any(|(k, _)| is_private_key(*k)) {
        bail!(
            "{flag} {} holds a private key; it must hold only the CA certificates",
            path.display()
        );
    }
    let roots = sections
        .iter()
        .filter(|(k, _)| *k == SectionKind::Certificate)
        .map(|(_, der)| Certificate::from_der(der))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            anyhow!(
                "{flag} {}: a certificate in it cannot be read",
                path.display()
            )
        })?;
    if roots.is_empty() {
        bail!("{flag} {} holds no PEM certificate", path.display());
    }
    Ok(roots)
}

/// The identity of `--tls-client-cert` (one or more certificates, the client's first, and no
/// private key) and `--tls-client-key` (exactly one unencrypted private key, and nothing
/// else). The key file is read once.
fn read_identity(cert: Given<'_>, key: Given<'_>) -> Result<Identity> {
    let (cert_name, cert) = (cert.name, cert.path);
    let (key_name, key) = (key.name, key.path);
    let cert_bytes = read_file(cert_name, cert, MAX_CLIENT_BYTES)?;
    if has_any_private_key(&cert_bytes) {
        bail!(
            "{cert_name} {} holds a private key; give the key in {key_name} and only the \
             certificate here",
            cert.display()
        );
    }
    let cert_sections = sections(cert_name, cert, &cert_bytes)?;
    if cert_sections.iter().any(|(k, _)| is_private_key(*k)) {
        bail!(
            "{cert_name} {} holds a private key; give the key in {key_name} and only the \
             certificate here",
            cert.display()
        );
    }
    if !cert_sections
        .iter()
        .all(|(k, _)| *k == SectionKind::Certificate)
        || cert_sections.is_empty()
    {
        bail!(
            "{cert_name} {} must hold the client certificate in PEM (`BEGIN CERTIFICATE`) and \
             nothing else",
            cert.display()
        );
    }
    let key_bytes = read_file(key_name, key, MAX_CLIENT_BYTES)?;
    let labels = begin_labels(&key_bytes);
    if labels.iter().any(|l| l.starts_with(b"ENCRYPTED")) {
        bail!(
            "{key_name} {} is an encrypted private key; the CLI needs it unencrypted (for \
             example `openssl pkey -in <key> -out <plain key>`, then chmod 600)",
            key.display()
        );
    }
    let supported: [&[u8]; 3] = [b"PRIVATE KEY", b"EC PRIVATE KEY", b"RSA PRIVATE KEY"];
    if labels
        .iter()
        .any(|l| l.ends_with(b"PRIVATE KEY") && !supported.contains(l))
    {
        bail!(
            "{key_name} {} holds a kind of private key the CLI cannot read; it needs PEM `BEGIN \
             PRIVATE KEY` (PKCS#8), `BEGIN EC PRIVATE KEY` or `BEGIN RSA PRIVATE KEY`",
            key.display()
        );
    }
    let key_sections = sections(key_name, key, &key_bytes)?;
    let keys = key_sections
        .iter()
        .filter(|(k, _)| is_private_key(*k))
        .count();
    if keys != 1 || key_sections.len() != 1 {
        bail!(
            "{key_name} {} must hold exactly one unencrypted private key in PEM (`BEGIN PRIVATE \
             KEY`, `BEGIN EC PRIVATE KEY` or `BEGIN RSA PRIVATE KEY`) and nothing else",
            key.display()
        );
    }
    // reqwest takes the certificate and the key as one PEM buffer.
    let mut pem = Zeroizing::new(Vec::with_capacity(cert_bytes.len() + key_bytes.len() + 1));
    pem.extend_from_slice(&cert_bytes);
    pem.push(b'\n');
    pem.extend_from_slice(&key_bytes);
    Identity::from_pem(&pem).map_err(|_| {
        anyhow!(
            "{cert_name} {} and {key_name} {} cannot be used together as a client certificate",
            cert.display(),
            key.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed client certificate and its key, as PEM.
    fn client_pair() -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["planner".to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn ca_pem() -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.self_signed(&key).unwrap().pem()
    }

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    fn err(r: Result<Tls>) -> String {
        format!("{:#}", r.expect_err("an error"))
    }

    #[test]
    fn nothing_given_is_the_default() {
        let tls = Tls::load(None, None, None).unwrap();
        assert!(tls.roots.is_none() && !tls.has_client_cert());
    }

    #[test]
    fn the_flag_wins_and_an_empty_environment_variable_is_unset() {
        let flag = Path::new("/flag.pem");
        let env = |v: &str| Some(std::ffi::OsString::from(v));
        let r = |p: Option<&Path>, e| resolve(p, CA_FLAG, CA_ENV, e);
        assert_eq!(
            r(Some(flag), env("/env.pem")),
            Some((flag.to_path_buf(), CA_FLAG))
        );
        assert_eq!(
            r(None, env("/env.pem")),
            Some((PathBuf::from("/env.pem"), CA_ENV))
        );
        // A compose file's `${VAR:-}`.
        assert_eq!(r(None, env("")), None);
        assert_eq!(r(None, None), None);
    }

    #[test]
    fn errors_name_the_environment_variable_a_path_came_from() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, _) = client_pair();
        let c = write(dir.path(), "c.pem", &cert);
        let missing = dir.path().join("missing.pem");
        fn env<'a>(path: &'a Path, name: &'static str) -> Option<Given<'a>> {
            Some(Given { path, name })
        }
        let e = err(Tls::load_from(env(&missing, CA_ENV), None, None));
        assert!(e.starts_with("cannot read ATTENUO_TLS_CA_CERT "), "{e}");
        let e = err(Tls::load_from(None, env(&c, CERT_ENV), None));
        assert!(
            e.starts_with("ATTENUO_TLS_CLIENT_CERT needs --tls-client-key"),
            "{e}"
        );
        let e = err(Tls::load_from(
            None,
            env(&c, CERT_FLAG),
            env(&missing, KEY_ENV),
        ));
        assert!(e.starts_with("cannot read ATTENUO_TLS_CLIENT_KEY "), "{e}");
        let e = err(Tls::load_from(
            None,
            env(&missing, CERT_ENV),
            env(&c, KEY_FLAG),
        ));
        assert!(e.starts_with("cannot read ATTENUO_TLS_CLIENT_CERT "), "{e}");
    }

    #[test]
    fn a_client_certificate_needs_an_https_server() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = client_pair();
        let c = write(dir.path(), "c.pem", &cert);
        let k = write(dir.path(), "k.pem", &key);
        let ca = write(dir.path(), "ca.pem", &ca_pem());
        let tls = Tls::load(None, Some(&c), Some(&k)).unwrap();
        for http in ["http://attenuo.test", "HTTP://attenuo.test"] {
            let e = format!("{:#}", tls.check_targets(http, None).unwrap_err());
            assert!(
                e.starts_with("--tls-client-cert and --tls-client-key"),
                "{e}"
            );
        }
        // An https admin server does not make an http --server fine: the certificate goes
        // to --server only.
        assert!(tls
            .check_targets("http://a.test", Some("https://adm.test"))
            .is_err());
        assert_eq!(tls.check_targets("https://a.test", None).unwrap(), None);
        assert_eq!(
            tls.check_targets("HTTPS://a.test", Some("http://adm.test"))
                .unwrap(),
            None
        );

        // A CA alone with no https:// URL: a warning, not an error.
        let tls = Tls::load(Some(&ca), None, None).unwrap();
        let w = tls.check_targets("http://a.test", None).unwrap().unwrap();
        assert!(w.starts_with("warning: --tls-ca-cert"), "{w}");
        assert!(tls
            .check_targets("http://a.test", Some("http://adm.test"))
            .unwrap()
            .is_some());
        for (server, admin) in [
            ("https://a.test", None),
            ("http://a.test", Some("https://adm.test")),
        ] {
            assert_eq!(tls.check_targets(server, admin).unwrap(), None);
        }
        // Nothing set: nothing to say.
        assert_eq!(
            Tls::default().check_targets("http://a.test", None).unwrap(),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_or_a_directory_is_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo.pem");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .unwrap();
        let (cert, _) = client_pair();
        let c = write(dir.path(), "c.pem", &cert);
        // Nothing ever writes to the FIFO: a blocking open would hang the test.
        let e = err(Tls::load(Some(&fifo), None, None));
        assert!(e.ends_with("is not a regular file"), "{e}");
        let e = err(Tls::load(None, Some(&c), Some(&fifo)));
        assert!(
            e.starts_with("--tls-client-key ") && e.ends_with("is not a regular file"),
            "{e}"
        );
        let e = err(Tls::load(Some(dir.path()), None, None));
        assert!(
            e.ends_with("is not a regular file") || e.starts_with("cannot read"),
            "{e}"
        );
    }

    #[test]
    fn cert_and_key_go_together_and_are_checked_before_reading() {
        // The paths do not exist: the pairing error comes first.
        let e = err(Tls::load(None, Some(Path::new("/nonexistent/c.pem")), None));
        assert!(
            e.starts_with("--tls-client-cert needs --tls-client-key"),
            "{e}"
        );
        let e = err(Tls::load(None, None, Some(Path::new("/nonexistent/k.pem"))));
        assert!(
            e.starts_with("--tls-client-key needs --tls-client-cert"),
            "{e}"
        );
    }

    #[test]
    fn a_good_pair_and_a_good_ca_load() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = client_pair();
        let c = write(dir.path(), "c.pem", &cert);
        let k = write(dir.path(), "k.pem", &key);
        let ca = write(dir.path(), "ca.pem", &format!("{}{}", ca_pem(), ca_pem()));
        let tls = Tls::load(Some(&ca), Some(&c), Some(&k)).unwrap();
        assert!(tls.has_client_cert());
        assert_eq!(tls.roots.as_ref().unwrap().1.len(), 2);
        tls.build(Target::Server, ClientBuilder::new()).unwrap();
        tls.build(Target::Admin, ClientBuilder::new()).unwrap();
        // No key bytes in the debug output.
        let debug = format!("{tls:?}");
        assert!(
            debug.contains("k.pem") && debug.contains("<key not shown>"),
            "{debug}"
        );
        let body: String = key.lines().filter(|l| !l.starts_with("-----")).collect();
        for chunk in body.as_bytes().chunks(16) {
            assert!(
                !debug.contains(std::str::from_utf8(chunk).unwrap()),
                "{debug}"
            );
        }
    }

    #[test]
    fn unreadable_empty_and_unparsable_files_name_the_flag_and_path_only() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = client_pair();
        let c = write(dir.path(), "c.pem", &cert);
        let k = write(dir.path(), "k.pem", &key);
        let missing = dir.path().join("missing.pem");
        let empty = write(dir.path(), "empty.pem", " \n\n");
        // A key file whose PEM is broken, with a secret-looking line the parser would quote.
        let secret_line = "-----BEGIN PRIVATE KEY-----SECRETSECRETSECRET";
        let broken = write(dir.path(), "broken.pem", &format!("{secret_line}\nAAAA\n"));
        let bad_b64 = write(
            dir.path(),
            "b64.pem",
            "-----BEGIN PRIVATE KEY-----\nS3CR3T!!!***\n-----END PRIVATE KEY-----\n",
        );

        let e = err(Tls::load(Some(&missing), None, None));
        assert!(
            e.starts_with("cannot read --tls-ca-cert ") && e.contains("missing.pem"),
            "{e}"
        );
        let e = err(Tls::load(Some(&empty), None, None));
        assert!(
            e.starts_with("--tls-ca-cert ") && e.ends_with(" is empty"),
            "{e}"
        );
        let e = err(Tls::load(None, Some(&c), Some(&missing)));
        assert!(e.starts_with("cannot read --tls-client-key "), "{e}");
        let e = err(Tls::load(None, Some(&empty), Some(&k)));
        assert!(
            e.starts_with("--tls-client-cert ") && e.ends_with(" is empty"),
            "{e}"
        );
        let e = err(Tls::load(None, Some(&c), Some(&empty)));
        assert!(
            e.starts_with("--tls-client-key ") && e.ends_with(" is empty"),
            "{e}"
        );
        for bad in [&broken, &bad_b64] {
            let e = err(Tls::load(None, Some(&c), Some(bad)));
            assert!(e.starts_with("--tls-client-key "), "{e}");
            assert!(!e.contains("SECRET") && !e.contains("S3CR3T"), "{e}");
            let e = err(Tls::load(Some(bad), None, None));
            assert!(e.starts_with("--tls-ca-cert "), "{e}");
            assert!(!e.contains("SECRET") && !e.contains("S3CR3T"), "{e}");
        }
        // Text that is not PEM at all.
        let text = write(dir.path(), "text.pem", "hello\n");
        let e = err(Tls::load(Some(&text), None, None));
        assert!(e.contains("holds no PEM certificate"), "{e}");
        let e = err(Tls::load(None, Some(&c), Some(&text)));
        assert!(e.contains("exactly one unencrypted private key"), "{e}");
        let e = err(Tls::load(None, Some(&text), Some(&k)));
        assert!(e.contains("must hold the client certificate"), "{e}");
    }

    #[test]
    fn files_must_hold_what_their_flag_needs() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = client_pair();
        let (_, other_key) = client_pair();
        let c = write(dir.path(), "c.pem", &cert);
        let k = write(dir.path(), "k.pem", &key);
        let both = write(dir.path(), "both.pem", &format!("{cert}{key}"));
        let two_keys = write(dir.path(), "two.pem", &format!("{key}{other_key}"));
        let other = write(dir.path(), "other.pem", &other_key);
        let encrypted = write(
            dir.path(),
            "enc.pem",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
        );

        // A key in the certificate file or the CA file is refused.
        let e = err(Tls::load(None, Some(&both), Some(&k)));
        assert!(e.contains("holds a private key"), "{e}");
        let e = err(Tls::load(Some(&both), None, None));
        assert!(e.contains("holds a private key"), "{e}");
        // The key file holds one key and nothing else.
        for bad in [&both, &two_keys, &c] {
            let e = err(Tls::load(None, Some(&c), Some(bad)));
            assert!(
                e.contains("exactly one unencrypted private key"),
                "{bad:?}: {e}"
            );
        }
        let e = err(Tls::load(None, Some(&c), Some(&encrypted)));
        assert!(e.contains("is an encrypted private key"), "{e}");

        // A key rustls does not read, in any file: never accepted, never quoted.
        for label in [
            "ENCRYPTED PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
            "DSA PRIVATE KEY",
        ] {
            let pem = format!("-----BEGIN {label}-----\nU0VDUkVUS0VZ\n-----END {label}-----\n");
            let f = write(dir.path(), "odd.pem", &format!("{cert}{pem}"));
            let e = err(Tls::load(Some(&f), None, None));
            assert!(e.contains("holds a private key"), "{label}: {e}");
            let e = err(Tls::load(None, Some(&f), Some(&k)));
            assert!(e.contains("holds a private key"), "{label}: {e}");
            let f = write(dir.path(), "odd.key", &pem);
            let e = err(Tls::load(None, Some(&c), Some(&f)));
            assert!(
                e.contains("encrypted private key") || e.contains("kind of private key"),
                "{label}: {e}"
            );
            assert!(!e.contains("U0VDUkVUS0VZ") && !e.contains(label), "{e}");
        }

        // A key that is not the certificate's.
        let e = err(Tls::load(None, Some(&c), Some(&other)));
        assert!(
            e.contains("is not the private key of the certificate"),
            "{e}"
        );
        assert!(
            !e.to_lowercase().contains("mismatch"),
            "no rustls text: {e}"
        );
    }

    #[test]
    fn the_admin_target_never_gets_the_client_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = client_pair();
        let c = write(dir.path(), "c.pem", &cert);
        let k = write(dir.path(), "k.pem", &key);
        let tls = Tls::load(None, Some(&c), Some(&k)).unwrap();
        assert!(tls.identity_for(Target::Server).is_some());
        assert!(tls.identity_for(Target::Admin).is_none());
        assert!(Tls::default().identity_for(Target::Server).is_none());
    }
}
