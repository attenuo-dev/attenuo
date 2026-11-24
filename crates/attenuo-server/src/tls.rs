//! `[server.tls]`: the TLS configuration of the main listener.
//!
//! [`server_config`] reads the certificate chain and the private key once, at startup, and
//! refuses anything it cannot use as it is (fail closed): a file that cannot be read, is not
//! a regular file, is empty or too large; a certificate file with no certificate, or with a
//! private key in it; a key file with no private key or more than one; a key file whose
//! owner and mode break PostgreSQL's `ssl_key_file` rule ([`key_mode_ok`], Unix: owned by
//! the server's effective user or root, no access for others); a key that does not belong to
//! the first certificate.
//!
//! The configuration it builds:
//!
//! - the `ring` provider, the one reqwest already uses, given to the builder explicitly: no
//!   process-wide default provider is installed;
//! - TLS 1.3 only;
//! - ALPN `http/1.1` only (the listener serves HTTP/1, [`crate::listen`]);
//! - no session resumption: no session cache, no tickets, no early data, so every connection
//!   makes a full handshake, and every client certificate a request carries was proven on its
//!   own connection;
//! - no client certificate is asked for, unless `client_certificates = "optional"`: then one
//!   is asked for and never required, and any certificate whose handshake signature verifies
//!   is accepted ([`crate::client_cert_verifier`]). Whether it authenticates a client is
//!   decided per request ([`crate::clientauth`]).
//!
//! Nothing here logs or returns the content of a file: every error is a fixed text that names
//! the file and the kind of problem, never a parser's or rustls's detail. A renewed certificate takes a restart.

use std::path::Path;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::NoServerSessionStorage;
use rustls::sign::{CertifiedKey, SingleCertAndKey};

use crate::config::{ClientCertificates, ServerTlsSection};

/// Largest `cert_pem_path` file read: 1 MiB, as for a `ca_pem_path` file
/// ([`crate::idp::jwks::MAX_CA_FILE_BYTES`]). A chain is a few KiB.
pub(crate) const MAX_CERT_FILE_BYTES: u64 = crate::idp::jwks::MAX_CA_FILE_BYTES;

/// Largest `key_pem_path` file read: 64 KiB, as for an issuer key file
/// ([`crate::issuer_keys::MAX_KEY_FILE_BYTES`]). An RSA 4096 key in PEM is about 3 KiB.
pub(crate) const MAX_KEY_FILE_BYTES: u64 = crate::issuer_keys::MAX_KEY_FILE_BYTES;

/// The ALPN protocols the listener offers: HTTP/1.1 only.
pub(crate) const ALPN: &[&[u8]] = &[b"http/1.1"];

/// The TLS configuration of `[server.tls]`.
///
/// # Errors
///
/// A message that names the key and the path, never a file's content, when a file cannot be
/// used (see the module documentation) or rustls refuses the certificate or the key.
pub(crate) fn server_config(tls: &ServerTlsSection) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let cert_path = &tls.cert_pem_path;
    let key_path = &tls.key_pem_path;
    let certs = read_certs(cert_path, key_path).map_err(|why| {
        anyhow::anyhow!("[server.tls] cert_pem_path {}: {why}", cert_path.display())
    })?;
    let key = read_key(key_path).map_err(|why| {
        anyhow::anyhow!("[server.tls] key_pem_path {}: {why}", key_path.display())
    })?;
    build(certs, key, tls.client_certificates).map_err(|why| {
        anyhow::anyhow!(
            "[server.tls] cert_pem_path {} and key_pem_path {}: {why}",
            cert_path.display(),
            key_path.display()
        )
    })
}

/// The rustls configuration of `certs` (leaf first) and `key`, asking for client
/// certificates as `client_certificates` says.
fn build(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_certificates: ClientCertificates,
) -> Result<Arc<rustls::ServerConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certified = certified_key(certs, key, &provider)?;
    let algs = provider.signature_verification_algorithms;
    let builder = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("cannot set up TLS 1.3 ({e})"))?;
    let builder = match client_certificates {
        ClientCertificates::Off => builder.with_no_client_auth(),
        ClientCertificates::Optional => builder.with_client_cert_verifier(Arc::new(
            crate::client_cert_verifier::AnyClientCert::new(algs),
        )),
    };
    let mut config = builder.with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    config.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
    // No resumption: no session cache (TLS 1.2 style or TLS 1.3 stateful), no tickets. The
    // builder's ticketer already makes none; sending none makes that explicit.
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

/// The certificate chain and key as rustls signs with them, after checking that the key
/// belongs to the first certificate. Unlike `ConfigBuilder::with_single_cert`, a provider that
/// cannot tell whether they match is refused too.
fn certified_key(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    provider: &CryptoProvider,
) -> Result<CertifiedKey, String> {
    // No error detail from rustls or the file: fixed texts only.
    let signing_key = provider.key_provider.load_private_key(key).map_err(|_| {
        "the private key cannot be used; use an RSA, ECDSA P-256 or P-384, or Ed25519 key"
            .to_owned()
    })?;
    let certified = CertifiedKey::new(certs, signing_key);
    match certified.keys_match() {
        Ok(()) => Ok(certified),
        Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::KeyMismatch)) => Err(
            "the private key does not belong to the first certificate of the file (the \
             server's own certificate must come first, then the intermediates)"
                .into(),
        ),
        Err(rustls::Error::InconsistentKeys(_)) => {
            Err("cannot check that the private key belongs to the first certificate".into())
        }
        Err(_) => Err("the first certificate cannot be read as an X.509 certificate".into()),
    }
}

/// The certificates of the `cert_pem_path` file, in file order.
fn read_certs(path: &Path, key_path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let pem = read_file(path, MAX_CERT_FILE_BYTES, false)?;
    if pem.iter().all(u8::is_ascii_whitespace) {
        return Err("the file is empty; it must hold PEM certificates".into());
    }
    let has_key = mentions_private_key(&pem);
    // A private key here would be as exposed as the certificate, which is not secret; keep it
    // in key_pem_path. The same file for both keys is fine: it is checked as a key file. Any
    // mention of `PRIVATE KEY` counts, an encrypted or malformed key included.
    if has_key && path != key_path {
        return Err("the file holds a private key; keep the key in key_pem_path only".into());
    }
    // The parser's error is never shown: some of its variants print a whole line of the file,
    // which may be part of a private key.
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "not a valid PEM certificate file".to_owned())?;
    if certs.is_empty() {
        return Err("no PEM certificate (-----BEGIN CERTIFICATE-----) in the file".into());
    }
    Ok(certs)
}

/// Whether the bytes `PRIVATE KEY` appear anywhere in `pem`: a key section of any kind
/// (`PRIVATE KEY`, `EC PRIVATE KEY`, `RSA PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, ...), well
/// formed or not, on a line of its own or run together with others. Nothing is decoded.
fn mentions_private_key(pem: &[u8]) -> bool {
    const NEEDLE: &[u8] = b"PRIVATE KEY";
    pem.windows(NEEDLE.len()).any(|w| w == NEEDLE)
}

/// The one private key of the `key_pem_path` file.
fn read_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let pem = read_file(path, MAX_KEY_FILE_BYTES, true)?;
    if pem.iter().all(u8::is_ascii_whitespace) {
        return Err("the file is empty; it must hold a PEM private key".into());
    }
    // The parser's own error is not shown: it can quote part of the file.
    let mut keys = PrivateKeyDer::pem_slice_iter(&pem);
    let key = match keys.next() {
        Some(Ok(key)) => key,
        Some(Err(_)) => return Err("not a valid PEM private key file".into()),
        None => {
            return Err(
                "no private key (-----BEGIN PRIVATE KEY-----, -----BEGIN EC PRIVATE \
                 KEY----- or -----BEGIN RSA PRIVATE KEY-----) in the file; an encrypted key \
                 is not supported"
                    .into(),
            )
        }
    };
    match keys.next() {
        None => Ok(key),
        Some(Ok(_)) => Err(
            "the file holds more than one private key; keep only the key of \
             the certificate"
                .into(),
        ),
        Some(Err(_)) => Err("not a valid PEM private key file".into()),
    }
}

/// The bytes of a regular file of at most `max` bytes, checked before reading and again while
/// reading, as `ca_pem_path` files are read. For a `secret` file on Unix, the open file must
/// not be readable or writable by its group or by others.
fn read_file(path: &Path, max: u64, secret: bool) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let unreadable = |e: std::io::Error| format!("cannot read the file ({e})");
    let too_big = || format!("the file is larger than {} KiB", max / 1024);
    let file = std::fs::File::open(path).map_err(unreadable)?;
    let meta = file.metadata().map_err(unreadable)?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    if secret {
        check_key_mode(&meta)?;
    }
    if meta.len() > max {
        return Err(too_big());
    }
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if bytes.len() as u64 > max {
        return Err(too_big());
    }
    Ok(bytes)
}

/// On Unix, the rule of [`key_mode_ok`] for the open file and this process: the owner and
/// mode are the open file's, so they are those of the file that is read.
#[cfg(unix)]
fn check_key_mode(meta: &std::fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    key_mode_ok(meta.uid(), meta.mode(), rustix::process::geteuid().as_raw())
}

/// The key file rule, PostgreSQL's for `ssl_key_file`: the file is owned by the server's
/// effective user (`euid`) or by root; others get no bit, ever, and the group never write or
/// execute. A file owned by root may also be readable by its group (mode at most `0640`),
/// which is how a Kubernetes Secret volume with `fsGroup` or a distribution's `ssl-cert`
/// group gives a non-root server the key. A file owned by the server's user has no group bits
/// at all (mode at most `0600`). `mode` may carry the file type bits; only the permission
/// bits are read.
pub(crate) fn key_mode_ok(file_uid: u32, mode: u32, euid: u32) -> Result<(), String> {
    let perm = mode & 0o7777;
    if file_uid != euid && file_uid != 0 {
        return Err(format!(
            "the private key file is owned by uid {file_uid}, which is neither the server's \
             account (uid {euid}) nor root; another account could change or swap it. Make the \
             server's account (chown {euid}, chmod 600) or root (chown 0, chmod 640, group of \
             the server's account) its owner"
        ));
    }
    if perm & 0o007 != 0 {
        return Err(format!(
            "the private key file has mode {perm:04o}, which gives others access; no bit for \
             others is allowed. Use mode 0600 or 0400 owned by the server's account (chmod 600), \
             or 0640 or 0440 owned by root with the server's group"
        ));
    }
    if perm & 0o030 != 0 {
        return Err(format!(
            "the private key file has mode {perm:04o}, which lets its group write or execute it; \
             at most group read is allowed, and only when root owns the file. Use mode 0600 or \
             0400 owned by the server's account (chmod 600), or 0640 or 0440 owned by root"
        ));
    }
    if perm & 0o040 != 0 && file_uid != 0 {
        return Err(format!(
            "the private key file has mode {perm:04o} and is not owned by root, so its group may \
             read it; group read is allowed only when root owns the file. Use mode 0600 or 0400 \
             (chmod 600), or make root the owner (0640 or 0440, group of the server's account)"
        ));
    }
    if perm & 0o7000 != 0 {
        return Err(format!(
            "the private key file has mode {perm:04o}, with a setuid, setgid or sticky bit; \
             use mode 0600 (chmod 600)"
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn check_key_mode(_meta: &std::fs::Metadata) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A key pair and a self-signed certificate for `localhost`, as PEM.
    fn cert_and_key() -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (cert.pem(), key.serialize_pem())
    }

    /// Write `text` to `name` in `dir` with `mode` (Unix).
    fn write(dir: &Path, name: &str, text: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        path
    }

    fn section(cert: &Path, key: &Path) -> ServerTlsSection {
        ServerTlsSection {
            cert_pem_path: cert.to_owned(),
            key_pem_path: key.to_owned(),
            client_certificates: crate::config::ClientCertificates::Off,
        }
    }

    /// The error of `server_config`, which must fail.
    fn refusal(cert: &Path, key: &Path) -> String {
        format!("{:#}", server_config(&section(cert, key)).unwrap_err())
    }

    #[test]
    fn a_matching_certificate_and_key_build_a_tls13_only_config_without_resumption() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = cert_and_key();
        let cert = write(dir.path(), "server.crt", &cert, 0o644);
        let key = write(dir.path(), "server.key", &key, 0o600);
        let config = server_config(&section(&cert, &key)).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert_eq!(config.send_tls13_tickets, 0);
        assert_eq!(config.max_tls13_tickets, 0);
        assert_eq!(config.max_early_data_size, 0);
        assert!(!config.ticketer.enabled());
        assert!(!config.session_storage.can_cache());
        // TLS 1.3 only: a TLS 1.2 client is refused in tests/server_tls.rs.
        // The key file may also hold the certificate.
        let both = write(
            dir.path(),
            "both.pem",
            &format!(
                "{}{}",
                std::fs::read_to_string(&cert).unwrap(),
                std::fs::read_to_string(&key).unwrap()
            ),
            0o600,
        );
        server_config(&section(&both, &both)).unwrap();
    }

    /// `client_certificates = "optional"` builds, and keeps resumption off. Whether a
    /// certificate is asked for is checked through real handshakes (tests/mtls.rs): rustls
    /// does not expose the verifier of a built config.
    #[test]
    fn client_certificates_set_the_verifier() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = cert_and_key();
        let cert = write(dir.path(), "server.crt", &cert, 0o644);
        let key = write(dir.path(), "server.key", &key, 0o600);
        let mut optional = section(&cert, &key);
        optional.client_certificates = ClientCertificates::Optional;
        let optional = server_config(&optional).unwrap();
        assert_eq!(optional.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert_eq!(optional.send_tls13_tickets, 0);
        assert!(!optional.session_storage.can_cache());
        assert!(!optional.ticketer.enabled());
    }

    #[test]
    fn every_key_format_rustls_reads_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        for alg in [
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P384_SHA384,
            &rcgen::PKCS_ED25519,
        ] {
            let key = rcgen::KeyPair::generate_for(alg).unwrap();
            let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
            let c = write(dir.path(), "c.pem", &cert.pem(), 0o644);
            let k = write(dir.path(), "k.pem", &key.serialize_pem(), 0o600);
            server_config(&section(&c, &k)).unwrap();
        }
    }

    #[test]
    fn missing_empty_and_unusable_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = cert_and_key();
        let cert = write(dir.path(), "server.crt", &cert_pem, 0o644);
        let key = write(dir.path(), "server.key", &key_pem, 0o600);
        let missing = dir.path().join("missing.pem");

        let err = refusal(&missing, &key);
        assert!(
            err.contains("cert_pem_path") && err.contains("cannot read"),
            "{err}"
        );
        let err = refusal(&cert, &missing);
        assert!(
            err.contains("key_pem_path") && err.contains("cannot read"),
            "{err}"
        );
        let err = refusal(dir.path(), &key);
        assert!(err.contains("not a regular file"), "{err}");
        let err = refusal(&cert, dir.path());
        assert!(err.contains("not a regular file"), "{err}");

        let empty_cert = write(dir.path(), "empty.crt", " \n", 0o644);
        let err = refusal(&empty_cert, &key);
        assert!(
            err.contains("cert_pem_path") && err.contains("empty"),
            "{err}"
        );
        let empty_key = write(dir.path(), "empty.key", "", 0o600);
        let err = refusal(&cert, &empty_key);
        assert!(
            err.contains("key_pem_path") && err.contains("empty"),
            "{err}"
        );

        let big = "#".repeat(usize::try_from(MAX_CERT_FILE_BYTES).unwrap() + 1);
        let big_cert = write(dir.path(), "big.crt", &big, 0o644);
        let err = refusal(&big_cert, &key);
        assert!(err.contains("larger than"), "{err}");
        let big = "#".repeat(usize::try_from(MAX_KEY_FILE_BYTES).unwrap() + 1);
        let big_key = write(dir.path(), "big.key", &big, 0o600);
        let err = refusal(&cert, &big_key);
        assert!(err.contains("larger than"), "{err}");
    }

    #[test]
    fn a_certificate_file_without_a_certificate_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (_, key_pem) = cert_and_key();
        let key = write(dir.path(), "server.key", &key_pem, 0o600);
        let text = write(dir.path(), "text.crt", "not pem at all\n", 0o644);
        let err = refusal(&text, &key);
        assert!(err.contains("no PEM certificate"), "{err}");
        // A key where the certificate should be: refused as a key in the certificate file
        // (two paths), or for having no certificate (one path).
        let only_key = write(dir.path(), "only-key.crt", &key_pem, 0o600);
        let err = refusal(&only_key, &key);
        assert!(err.contains("holds a private key"), "{err}");
        let err = refusal(&only_key, &only_key);
        assert!(err.contains("no PEM certificate"), "{err}");
        let broken = write(
            dir.path(),
            "broken.crt",
            "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
            0o644,
        );
        let err = refusal(&broken, &key);
        assert!(err.contains("not a valid PEM certificate file"), "{err}");
        // A block that is base64 but not a certificate.
        let garbage = write(
            dir.path(),
            "garbage.crt",
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
            0o644,
        );
        let err = refusal(&garbage, &key);
        assert!(err.contains("first certificate cannot be read"), "{err}");
    }

    #[test]
    fn a_private_key_in_the_certificate_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = cert_and_key();
        let combined = write(
            dir.path(),
            "combined.pem",
            &format!("{cert_pem}{key_pem}"),
            0o644,
        );
        let key = write(dir.path(), "server.key", &key_pem, 0o600);
        let err = refusal(&combined, &key);
        assert!(err.contains("holds a private key"), "{err}");
        assert!(!err.contains("BEGIN PRIVATE KEY"), "{err}");
    }

    #[test]
    fn a_key_file_without_exactly_one_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = cert_and_key();
        let cert = write(dir.path(), "server.crt", &cert_pem, 0o644);
        let no_key = write(dir.path(), "no.key", &cert_pem, 0o600);
        let err = refusal(&cert, &no_key);
        assert!(err.contains("no private key"), "{err}");
        let (_, other_key) = cert_and_key();
        let two = write(
            dir.path(),
            "two.key",
            &format!("{key_pem}{other_key}"),
            0o600,
        );
        let err = refusal(&cert, &two);
        assert!(err.contains("more than one private key"), "{err}");
        let encrypted = write(
            dir.path(),
            "enc.key",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
            0o600,
        );
        let err = refusal(&cert, &encrypted);
        assert!(err.contains("no private key"), "{err}");
        // Broken base64 inside a key block: the parser's message (which may quote the file)
        // is not passed on.
        let secret_marker = "SECRETSECRET*";
        let broken = write(
            dir.path(),
            "broken.key",
            &format!("-----BEGIN PRIVATE KEY-----\n{secret_marker}\n-----END PRIVATE KEY-----\n"),
            0o600,
        );
        let err = refusal(&cert, &broken);
        assert!(err.contains("not a valid PEM private key file"), "{err}");
        assert!(!err.contains("SECRET"), "{err}");
        // A key block rustls cannot load.
        let junk = write(
            dir.path(),
            "junk.key",
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            0o600,
        );
        let err = refusal(&cert, &junk);
        assert!(err.contains("private key cannot be used"), "{err}");
    }

    /// A real key PEM with one character of its body replaced by `*`, and the body's lines.
    fn broken_key() -> (String, Vec<String>) {
        let (_, key_pem) = cert_and_key();
        let mut lines: Vec<String> = key_pem.lines().map(str::to_owned).collect();
        let body: Vec<String> = lines[1..lines.len() - 1].to_vec();
        let mid = &mut lines[1];
        let at = mid.len() / 2;
        mid.replace_range(at..=at, "*");
        (lines.join("\n") + "\n", body)
    }

    /// `err` shows no part of the key body: no line, no run of 6 characters, no list of byte
    /// values (the form the PEM parser prints a line in), no parser detail, and it is short
    /// once the file paths are taken out.
    fn assert_no_key_text(err: &str, body: &[String], paths: &[&Path]) {
        let mut text = err.to_owned();
        for p in paths {
            text = text.replace(&p.display().to_string(), "<path>");
        }
        assert!(text.len() < 300, "{} bytes: {text}", text.len());
        let joined: String = body.concat();
        for i in 0..joined.len().saturating_sub(6) {
            assert!(!text.contains(&joined[i..i + 6]), "{text}");
        }
        assert!(numbers_in_a_row(&text) <= 3, "{text}");
        for detail in [
            "InvalidCharacter",
            "base64",
            "Base64",
            "*",
            "missing section",
            "illegal section",
        ] {
            assert!(!text.contains(detail), "{detail}: {text}");
        }
    }

    /// The longest run of comma-separated numbers in `text` (`45, 45, 66` is 3).
    fn numbers_in_a_row(text: &str) -> usize {
        let mut best = 0;
        let mut run = 0;
        for part in text.split(',') {
            if !part.trim().is_empty() && part.trim().bytes().all(|b| b.is_ascii_digit()) {
                run += 1;
                best = best.max(run);
            } else {
                run = usize::from(
                    part.trim_end()
                        .rsplit(|c: char| !c.is_ascii_digit())
                        .next()
                        .is_some_and(|d| !d.is_empty()),
                );
                best = best.max(run);
            }
        }
        best
    }

    #[test]
    fn numbers_in_a_row_counts_byte_lists() {
        assert_eq!(numbers_in_a_row("no numbers"), 0);
        assert_eq!(numbers_in_a_row("line: [45, 45, 45, 66, 69]"), 4);
        assert_eq!(numbers_in_a_row("mode 0640, uid 0"), 1);
    }

    /// A real key and a certificate, run together on one line with every newline removed, in
    /// either order, as a file loses its line breaks when pasted through some tools.
    #[test]
    fn a_flattened_file_never_quotes_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = cert_and_key();
        let body: Vec<String> = key_pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .map(str::to_owned)
            .collect();
        let flat = |t: &str| t.replace(['\n', '\r'], "");
        let good_key = write(dir.path(), "good.key", &key_pem, 0o600);
        let good_cert = write(dir.path(), "good.crt", &cert_pem, 0o644);
        let cases = [
            ("key-first", flat(&format!("{key_pem}{cert_pem}"))),
            ("cert-first", flat(&format!("{cert_pem}{key_pem}"))),
            ("key-only", flat(&key_pem)),
            // A BEGIN line with text after it.
            (
                "trailing",
                key_pem.replacen(
                    "-----BEGIN PRIVATE KEY-----",
                    "-----BEGIN PRIVATE KEY----- x",
                    1,
                ) + &cert_pem,
            ),
            // CRLF line ends, and a CR-only file.
            ("crlf", format!("{key_pem}{cert_pem}").replace('\n', "\r\n")),
            ("cr", format!("{key_pem}{cert_pem}").replace('\n', "\r")),
        ];
        for (name, text) in cases {
            let file = write(dir.path(), &format!("{name}.pem"), &text, 0o600);
            for (cert, key) in [(&file, &file), (&file, &good_key), (&good_cert, &file)] {
                if let Err(e) = server_config(&section(cert, key)) {
                    let err = format!("{e:#}");
                    assert_no_key_text(&err, &body, &[cert, key]);
                } else {
                    // Only a well-formed file with other line ends may be accepted, and never
                    // as a certificate file next to another key file.
                    assert!(
                        matches!(name, "crlf" | "cr") && !(cert == &file && key == &good_key),
                        "{name} accepted as {} and {}",
                        cert.display(),
                        key.display()
                    );
                }
            }
        }
    }

    #[test]
    fn a_broken_key_block_is_never_quoted() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = cert_and_key();
        let (broken, body) = broken_key();
        let cert = write(dir.path(), "server.crt", &cert_pem, 0o644);
        let key = write(dir.path(), "server.key", &key_pem, 0o600);

        // The key file itself.
        let bad_key = write(dir.path(), "bad.key", &broken, 0o600);
        let err = refusal(&cert, &bad_key);
        assert!(err.contains("not a valid PEM private key file"), "{err}");
        assert_no_key_text(&err, &body, &[&cert, &bad_key]);

        // A combined file used for both keys: the certificate is parsed first.
        let combined = write(
            dir.path(),
            "combined.pem",
            &format!("{cert_pem}{broken}"),
            0o600,
        );
        let err = refusal(&combined, &combined);
        assert!(err.contains("not a valid PEM certificate file"), "{err}");
        assert_no_key_text(&err, &body, &[&combined]);

        // A combined file as the certificate only, next to a good key file.
        let err = refusal(&combined, &key);
        assert!(err.contains("holds a private key"), "{err}");
        assert_no_key_text(&err, &body, &[&combined, &key]);

        // A broken key block before the certificate.
        let first = write(
            dir.path(),
            "first.pem",
            &format!("{broken}{cert_pem}"),
            0o600,
        );
        let err = refusal(&first, &first);
        assert_no_key_text(&err, &body, &[&first]);
    }

    #[test]
    fn an_encrypted_key_in_the_certificate_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = cert_and_key();
        let encrypted = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n\
                         -----END ENCRYPTED PRIVATE KEY-----\n";
        let with_encrypted = write(
            dir.path(),
            "enc.pem",
            &format!("{cert_pem}{encrypted}"),
            0o600,
        );
        let key = write(dir.path(), "server.key", &key_pem, 0o600);
        let err = refusal(&with_encrypted, &key);
        assert!(err.contains("holds a private key"), "{err}");
        // As the key file too (the same path): the key file has no key rustls reads.
        let err = refusal(&with_encrypted, &with_encrypted);
        assert!(
            err.contains("key_pem_path") && err.contains("no private key"),
            "{err}"
        );
        assert!(err.contains("encrypted key is not supported"), "{err}");
    }

    #[test]
    fn a_key_of_another_certificate_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, _) = cert_and_key();
        let (_, other_key) = cert_and_key();
        let cert = write(dir.path(), "server.crt", &cert_pem, 0o644);
        let key = write(dir.path(), "other.key", &other_key, 0o600);
        let err = refusal(&cert, &key);
        assert!(
            err.contains("does not belong to the first certificate"),
            "{err}"
        );
        // The right key, but the certificate is not first in the file.
        let (leaf_pem, leaf_key) = cert_and_key();
        let chain = write(
            dir.path(),
            "chain.crt",
            &format!("{cert_pem}{leaf_pem}"),
            0o644,
        );
        let key = write(dir.path(), "leaf.key", &leaf_key, 0o600);
        let err = refusal(&chain, &key);
        assert!(
            err.contains("does not belong to the first certificate"),
            "{err}"
        );
    }

    /// [`key_mode_ok`], for every case, whoever runs the tests: a server that runs as a
    /// user, and one that runs as root.
    #[test]
    fn the_key_mode_rule_follows_postgresql() {
        const ROOT: u32 = 0;
        const USER: u32 = 10001;
        const OTHER: u32 = 12345;
        for euid in [USER, ROOT] {
            // Accepted: owned by the server's user with no group or other bits, or by root
            // with group read at most.
            for (uid, mode) in [
                (euid, 0o600),
                (euid, 0o400),
                (euid, 0o200),
                (ROOT, 0o600),
                (ROOT, 0o400),
                (ROOT, 0o640),
                (ROOT, 0o440),
                // The file type bits are ignored.
                (euid, 0o100_600),
                (ROOT, 0o100_440),
            ] {
                assert!(
                    key_mode_ok(uid, mode, euid).is_ok(),
                    "{euid} {uid} {mode:o}"
                );
            }
            let refused = |uid: u32, mode: u32, why: &str| {
                let err = key_mode_ok(uid, mode, euid).unwrap_err();
                assert!(err.contains(why), "{euid} {uid} {mode:o}: {err}");
                assert!(err.contains("chmod 6"), "{euid} {uid} {mode:o}: {err}");
            };
            // Another owner: never, whatever the mode.
            for mode in [0o600, 0o400, 0o640] {
                refused(OTHER, mode, "neither the server's account");
            }
            // Others: never, whoever owns it.
            for uid in [ROOT, euid] {
                for mode in [0o604, 0o602, 0o601, 0o644, 0o666, 0o444] {
                    refused(uid, mode, "gives others access");
                }
                // Group write or execute: never.
                for mode in [0o620, 0o610, 0o660, 0o670, 0o460] {
                    refused(uid, mode, "group write or execute");
                }
                for mode in [0o4600, 0o2600, 0o1600] {
                    refused(uid, mode, "setuid");
                }
            }
        }
        // Group read: only when root owns the file, also for a server that is not root.
        for mode in [0o640, 0o440] {
            let err = key_mode_ok(USER, mode, USER).unwrap_err();
            assert!(err.contains("not owned by root"), "{mode:o}: {err}");
        }
        let err = key_mode_ok(OTHER, 0o600, USER).unwrap_err();
        assert!(
            err.contains("uid 12345") && err.contains("uid 10001"),
            "{err}"
        );
    }

    /// The rule on real files: the owner is whoever runs the test, so the root-owned group
    /// read case is checked on disk only when that is root (`the_key_mode_rule_follows_postgresql`
    /// checks the decision itself for both owners).
    #[cfg(unix)]
    #[test]
    fn a_key_file_open_to_group_or_others_is_refused() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = cert_and_key();
        let cert = write(dir.path(), "server.crt", &cert_pem, 0o644);
        let owner = std::fs::metadata(&cert).unwrap().uid();
        for mode in [0o644, 0o604, 0o666, 0o620, 0o660, 0o602] {
            let key = write(dir.path(), &format!("k{mode:o}.key"), &key_pem, mode);
            let err = refusal(&cert, &key);
            assert!(err.contains("chmod 600"), "{mode:o}: {err}");
            assert!(err.contains(&format!("{mode:04o}")), "{mode:o}: {err}");
        }
        for mode in [0o600, 0o400] {
            let key = write(dir.path(), &format!("k{mode:o}.key"), &key_pem, mode);
            server_config(&section(&cert, &key)).unwrap();
        }
        for mode in [0o640, 0o440] {
            let key = write(dir.path(), &format!("g{mode:o}.key"), &key_pem, mode);
            if owner == 0 {
                server_config(&section(&cert, &key)).unwrap();
            } else {
                let err = refusal(&cert, &key);
                assert!(err.contains("not owned by root"), "{mode:o}: {err}");
            }
        }
        // Owned by another account: refused. Only root can give a file away, so this runs
        // on disk only as root.
        if owner == 0 {
            let key = write(dir.path(), "theirs.key", &key_pem, 0o600);
            std::os::unix::fs::chown(&key, Some(12345), None).unwrap();
            let err = refusal(&cert, &key);
            assert!(err.contains("neither the server's account"), "{err}");
        }
        // The certificate file's mode does not matter.
        let key = write(dir.path(), "ok.key", &key_pem, 0o600);
        let cert = write(dir.path(), "open.crt", &cert_pem, 0o666);
        server_config(&section(&cert, &key)).unwrap();
    }
}
