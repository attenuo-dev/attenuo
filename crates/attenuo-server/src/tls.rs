//! `[server.tls]`: the TLS configuration of the main listener.
//!
//! [`server_config`] reads the certificate chain and the private key once, at startup, and
//! refuses anything it cannot use as it is (fail closed): a file that cannot be read, is not
//! a regular file, is empty or too large; a certificate file with no certificate, or with a
//! private key in it; a key file with no private key or more than one; a key file that its
//! group or others may read or write (Unix); a key that does not belong to the first
//! certificate.
//!
//! The configuration it builds:
//!
//! - the `ring` provider, the one reqwest already uses, given to the builder explicitly: no
//!   process-wide default provider is installed;
//! - TLS 1.3 only;
//! - ALPN `http/1.1` only (the listener serves HTTP/1, [`crate::listen`]);
//! - no session resumption: no session cache, no tickets, no early data, so every connection
//!   makes a full handshake;
//! - no client authentication.
//!
//! Nothing here logs or returns the content of a file. A renewed certificate takes a restart.

use std::path::Path;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::NoServerSessionStorage;
use rustls::sign::{CertifiedKey, SingleCertAndKey};

use crate::config::ServerTlsSection;

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
    build(certs, key).map_err(|why| {
        anyhow::anyhow!(
            "[server.tls] cert_pem_path {} and key_pem_path {}: {why}",
            cert_path.display(),
            key_path.display()
        )
    })
}

/// The rustls configuration of `certs` (leaf first) and `key`.
fn build(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<rustls::ServerConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certified = certified_key(certs, key, &provider)?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("cannot set up TLS 1.3 ({e})"))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
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
    let signing_key = provider.key_provider.load_private_key(key).map_err(|e| {
        format!(
            "the private key cannot be used ({e}); use an RSA, ECDSA P-256 or P-384, or \
             Ed25519 key"
        )
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
        Err(e) => Err(format!("the first certificate cannot be read ({e})")),
    }
}

/// The certificates of the `cert_pem_path` file, in file order.
fn read_certs(path: &Path, key_path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let pem = read_file(path, MAX_CERT_FILE_BYTES, false)?;
    if pem.iter().all(u8::is_ascii_whitespace) {
        return Err("the file is empty; it must hold PEM certificates".into());
    }
    let has_key = has_private_key_label(&pem);
    // A private key here would be as exposed as the certificate, which is not secret; keep it
    // in key_pem_path. The same file for both keys is fine: it is checked as a key file. Any
    // `... PRIVATE KEY` section counts, an encrypted one included, which rustls does not read.
    if has_key && path != key_path {
        return Err("the file holds a private key; keep the key in key_pem_path only".into());
    }
    // The parser decodes every section, so its error can quote a character of a key block
    // in a file that holds one: then it is not shown.
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            if has_key {
                "not a valid PEM file".to_owned()
            } else {
                format!("not a PEM certificate file ({e})")
            }
        })?;
    if certs.is_empty() {
        return Err("no PEM certificate (-----BEGIN CERTIFICATE-----) in the file".into());
    }
    Ok(certs)
}

/// Whether `pem` has a line that begins a `... PRIVATE KEY` section: `PRIVATE KEY`,
/// `EC PRIVATE KEY`, `RSA PRIVATE KEY`, and also kinds the PEM parser skips, such as
/// `ENCRYPTED PRIVATE KEY` (PKCS#8 encrypted, RFC 5958). Read from the labels alone, without
/// decoding anything.
fn has_private_key_label(pem: &[u8]) -> bool {
    pem.split(|b| *b == b'\n' || *b == b'\r').any(|line| {
        let line = line.trim_ascii();
        line.starts_with(b"-----BEGIN ") && line.ends_with(b"PRIVATE KEY-----")
    })
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

/// On Unix, refuse a key file that its group or others may read or write (any bit of `0o077`).
/// The mode is the open file's, so it is the file that is read.
#[cfg(unix)]
fn check_key_mode(meta: &std::fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "the private key file has mode {mode:04o}; it must not be readable or writable by \
             its group or by others. Give it mode 0600 or 0400, owned by the server's account \
             (chmod 600)"
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
        assert!(err.contains("not a PEM certificate file"), "{err}");
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

    /// `err` shows no part of the key body: no line, no run of 6 characters, no parser detail.
    fn assert_no_key_text(err: &str, body: &[String]) {
        for line in body {
            assert!(!err.contains(line.as_str()), "{err}");
            for i in 0..line.len().saturating_sub(6) {
                assert!(!err.contains(&line[i..i + 6]), "{err}");
            }
        }
        for detail in ["InvalidCharacter", "base64", "Base64", "*"] {
            assert!(!err.contains(detail), "{detail}: {err}");
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
        assert_no_key_text(&err, &body);

        // A combined file used for both keys: the certificate is parsed first.
        let combined = write(
            dir.path(),
            "combined.pem",
            &format!("{cert_pem}{broken}"),
            0o600,
        );
        let err = refusal(&combined, &combined);
        assert!(err.contains("not a valid PEM file"), "{err}");
        assert_no_key_text(&err, &body);

        // A combined file as the certificate only, next to a good key file.
        let err = refusal(&combined, &key);
        assert!(err.contains("holds a private key"), "{err}");
        assert_no_key_text(&err, &body);

        // A broken key block before the certificate.
        let first = write(
            dir.path(),
            "first.pem",
            &format!("{broken}{cert_pem}"),
            0o600,
        );
        let err = refusal(&first, &first);
        assert_no_key_text(&err, &body);
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

    #[cfg(unix)]
    #[test]
    fn a_key_file_open_to_group_or_others_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = cert_and_key();
        let cert = write(dir.path(), "server.crt", &cert_pem, 0o644);
        for mode in [0o640, 0o604, 0o620, 0o602, 0o660, 0o644, 0o666] {
            let key = write(dir.path(), &format!("k{mode:o}.key"), &key_pem, mode);
            let err = refusal(&cert, &key);
            assert!(err.contains("chmod 600"), "{mode:o}: {err}");
            assert!(
                err.contains("must not be readable or writable"),
                "{mode:o}: {err}"
            );
            assert!(err.contains(&format!("{mode:04o}")), "{mode:o}: {err}");
        }
        for mode in [0o600, 0o400] {
            let key = write(dir.path(), &format!("k{mode:o}.key"), &key_pem, mode);
            server_config(&section(&cert, &key)).unwrap();
        }
        // The certificate file's mode does not matter.
        let key = write(dir.path(), "ok.key", &key_pem, 0o600);
        let cert = write(dir.path(), "open.crt", &cert_pem, 0o666);
        server_config(&section(&cert, &key)).unwrap();
    }
}
