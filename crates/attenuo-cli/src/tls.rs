//! `--tls-ca-cert`, `--tls-client-cert` and `--tls-client-key`: the CA the CLI trusts for the
//! attenuo server's certificate, and the TLS client certificate it presents to it (RFC 8705
//! `self_signed_tls_client_auth`).
//!
//! The rules:
//!
//! - With `--tls-ca-cert`, the certificates in that file are the only roots trusted for
//!   `--server` and `--admin-server`: the public web PKI roots built into the CLI are not
//!   trusted next to them. Without it, the built-in roots are used, as before.
//! - `--tls-client-cert` and `--tls-client-key` go together. The certificate is presented
//!   on connections to `--server` only: never to `--admin-server` (a listener that does not
//!   read it) and never to any other URL (an `approval verify --jwks` URL on another host).
//!   The clients follow no redirect (SR-112), so a certificate cannot be carried to a host
//!   named in a `Location` either.
//! - Every file is read once, before any request is sent. A file that cannot be read, is
//!   empty, or does not hold what its flag needs is an error that names the flag and the
//!   path, and nothing else: no parser message, which could quote the file (a key file's
//!   line, for instance), goes into it.
//! - The private key's bytes are held in buffers that are zeroed when dropped, and no
//!   `Debug` output shows them.

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
    /// Read and check the three options. `None` (or an empty value, as a compose file's
    /// `${VAR:-}` gives) is unset.
    pub(crate) fn load(
        ca_cert: Option<&Path>,
        client_cert: Option<&Path>,
        client_key: Option<&Path>,
    ) -> Result<Self> {
        fn given(p: Option<&Path>) -> Option<&Path> {
            p.filter(|p| !p.as_os_str().is_empty())
        }
        let (ca_cert, client_cert, client_key) =
            (given(ca_cert), given(client_cert), given(client_key));
        // The pairing is checked before any file is read.
        let pair = match (client_cert, client_key) {
            (Some(c), Some(k)) => Some((c, k)),
            (None, None) => None,
            (Some(_), None) => bail!(
                "--tls-client-cert needs --tls-client-key (or ATTENUO_TLS_CLIENT_KEY): the \
                 private key of the certificate"
            ),
            (None, Some(_)) => bail!(
                "--tls-client-key needs --tls-client-cert (or ATTENUO_TLS_CLIENT_CERT): the \
                 certificate of the key"
            ),
        };
        let mut tls = Tls::default();
        if let Some(path) = ca_cert {
            tls.roots = Some((path.to_path_buf(), read_ca(path)?));
            // A certificate that rustls cannot take as a trust anchor fails here, not on the
            // first request.
            tls.build(Target::Admin, ClientBuilder::new())
                .map_err(|_| {
                    anyhow!(
                        "--tls-ca-cert {}: a certificate in it cannot be used as a CA \
                         certificate",
                        path.display()
                    )
                })?;
        }
        if let Some((cert, key)) = pair {
            let identity = read_identity(cert, key)?;
            tls.client = Some((cert.to_path_buf(), key.to_path_buf(), identity));
            // A key that is not the certificate's, or of a type rustls cannot sign with,
            // fails here. The error from rustls is not shown.
            tls.build(Target::Server, ClientBuilder::new())
                .map_err(|_| {
                    anyhow!(
                        "--tls-client-key {} is not the private key of the certificate in \
                         --tls-client-cert {}, or its key type is not supported (Ed25519, \
                         ECDSA P-256 or P-384, RSA)",
                        key.display(),
                        cert.display()
                    )
                })?;
        }
        Ok(tls)
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

/// Read at most `max` bytes of `path` for `flag`; more is an error, and so is a file with
/// nothing but white space.
fn read_file(flag: &str, path: &Path, max: u64) -> Result<Zeroizing<Vec<u8>>> {
    let file = std::fs::File::open(path)
        .map_err(|e| anyhow!("cannot read {flag} {}: {}", path.display(), e))?;
    let mut buf = Zeroizing::new(Vec::new());
    file.take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|e| anyhow!("cannot read {flag} {}: {}", path.display(), e))?;
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

fn is_private_key(kind: SectionKind) -> bool {
    matches!(
        kind,
        SectionKind::PrivateKey | SectionKind::RsaPrivateKey | SectionKind::EcPrivateKey
    )
}

/// The certificates of the `--tls-ca-cert` bundle: at least one, and no private key.
fn read_ca(path: &Path) -> Result<Vec<Certificate>> {
    const FLAG: &str = "--tls-ca-cert";
    let bytes = read_file(FLAG, path, MAX_CA_BYTES)?;
    let sections = sections(FLAG, path, &bytes)?;
    if sections.iter().any(|(k, _)| is_private_key(*k)) {
        bail!(
            "{FLAG} {} holds a private key; it must hold only the CA certificates",
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
                "{FLAG} {}: a certificate in it cannot be read",
                path.display()
            )
        })?;
    if roots.is_empty() {
        bail!("{FLAG} {} holds no PEM certificate", path.display());
    }
    Ok(roots)
}

/// The identity of `--tls-client-cert` (one or more certificates, the client's first, and no
/// private key) and `--tls-client-key` (exactly one unencrypted private key, and nothing
/// else). The key file is read once.
fn read_identity(cert: &Path, key: &Path) -> Result<Identity> {
    const CERT: &str = "--tls-client-cert";
    const KEY: &str = "--tls-client-key";
    let cert_bytes = read_file(CERT, cert, MAX_CLIENT_BYTES)?;
    let cert_sections = sections(CERT, cert, &cert_bytes)?;
    if cert_sections.iter().any(|(k, _)| is_private_key(*k)) {
        bail!(
            "{CERT} {} holds a private key; give the key in {KEY} and only the certificate here",
            cert.display()
        );
    }
    if !cert_sections
        .iter()
        .all(|(k, _)| *k == SectionKind::Certificate)
        || cert_sections.is_empty()
    {
        bail!(
            "{CERT} {} must hold the client certificate in PEM (`BEGIN CERTIFICATE`) and \
             nothing else",
            cert.display()
        );
    }
    let key_bytes = read_file(KEY, key, MAX_CLIENT_BYTES)?;
    let key_sections = sections(KEY, key, &key_bytes)?;
    let keys = key_sections
        .iter()
        .filter(|(k, _)| is_private_key(*k))
        .count();
    if keys != 1 || key_sections.len() != 1 {
        bail!(
            "{KEY} {} must hold exactly one unencrypted private key in PEM (`BEGIN PRIVATE \
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
            "{CERT} {} and {KEY} {} cannot be used together as a client certificate",
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
        // Empty values (`${VAR:-}`) count as unset.
        let empty = Path::new("");
        let tls = Tls::load(Some(empty), Some(empty), Some(empty)).unwrap();
        assert!(tls.roots.is_none() && !tls.has_client_cert());
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
        let e = err(Tls::load(
            None,
            Some(Path::new("/nonexistent/c.pem")),
            Some(Path::new("")),
        ));
        assert!(
            e.starts_with("--tls-client-cert needs --tls-client-key"),
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
        for bad in [&both, &two_keys, &encrypted, &c] {
            let e = err(Tls::load(None, Some(&c), Some(bad)));
            assert!(
                e.contains("exactly one unencrypted private key"),
                "{bad:?}: {e}"
            );
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
