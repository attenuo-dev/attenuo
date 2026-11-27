//! `[server.tls]`: the TLS configuration of the main listener.
//!
//! [`ServerTls::load`] reads the certificate chain and the private key at startup, and
//! [`ServerTls::read_new`] reads them again for `POST /admin/tls/reload`. Both refuse anything
//! they cannot use as it is (fail closed): a file that cannot be read, is not a regular file,
//! is empty or too large; a certificate file with no certificate, or with a private key in it;
//! a key file with no private key or more than one private-key section (of any kind, an
//! encrypted or unknown one included); a key file whose owner and mode break
//! PostgreSQL's `ssl_key_file` rule ([`key_mode_ok`], Unix: owned by the server's effective
//! user or root, no access for others); a key that does not belong to the first certificate.
//! A reload also refuses a first certificate whose dates cannot be read, that has expired, that
//! is not valid yet or that is a CA, and a chain of more than [`MAX_RELOAD_CHAIN_CERTS`]
//! certificates or [`MAX_RELOAD_CHAIN_DER_BYTES`] bytes of DER. Startup does not check the
//! dates, and only logs a warning for a CA first certificate or a chain over those limits, so
//! a server that starts today keeps starting.
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
//! **Reload.** The paths and `client_certificates` are the ones read at startup; a reload
//! reads only the files' content again. Every setting above comes from this code ([`build`]),
//! never from the files, so a reload cannot change it. The new configuration is put in force
//! in one step ([`ServerTls::swap`]). The accept loop takes one snapshot of it for each new
//! connection, before the handshake: a handshake uses the old configuration or the new one,
//! whole, never a mix. A connection that is already open keeps the configuration it was made
//! with. No lock is held across an `await`: the snapshot is an `Arc` clone under a read lock.
//!
//! Nothing here logs or returns the content of a file: every error is a fixed text that names
//! the file and the kind of problem, never a parser's or rustls's detail.

use std::path::Path;
use std::sync::{Arc, PoisonError, RwLock};

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::NoServerSessionStorage;
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use sha2::Digest;
use time::OffsetDateTime;

use crate::config::{ClientCertificates, ServerTlsSection};
use crate::metrics::HandshakeFailure;

/// Largest `cert_pem_path` file read: 1 MiB, as for a `ca_pem_path` file
/// ([`crate::idp::jwks::MAX_CA_FILE_BYTES`]). A chain is a few KiB.
pub(crate) const MAX_CERT_FILE_BYTES: u64 = crate::idp::jwks::MAX_CA_FILE_BYTES;

/// Largest `key_pem_path` file read: 64 KiB, as for an issuer key file
/// ([`crate::issuer_keys::MAX_KEY_FILE_BYTES`]). An RSA 4096 key in PEM is about 3 KiB.
pub(crate) const MAX_KEY_FILE_BYTES: u64 = crate::issuer_keys::MAX_KEY_FILE_BYTES;

/// The most certificates a reload accepts in `cert_pem_path`, the first one included. The
/// chain is sent in every handshake; a server certificate and its intermediates are two to
/// four. Startup only warns above it.
pub(crate) const MAX_RELOAD_CHAIN_CERTS: usize = 10;

/// The most DER bytes, all certificates together, a reload accepts in `cert_pem_path`.
/// Startup only warns above it.
pub(crate) const MAX_RELOAD_CHAIN_DER_BYTES: usize = 64 * 1024;

/// The ALPN protocols the listener offers: HTTP/1.1 only.
pub(crate) const ALPN: &[&[u8]] = &[b"http/1.1"];

/// What kind of problem stopped the files from being used. Each is one error code of
/// `POST /admin/tls/reload` ([`crate::routes::tls_reload`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Problem {
    /// A file cannot be read: missing, no permission, not a regular file, too large, or a key
    /// file whose owner or mode breaks the rule of [`key_mode_ok`].
    Unreadable,
    /// A file can be read but cannot be used: empty, not PEM, no certificate, a private key in
    /// the certificate file, no key or more than one, a key rustls cannot use, a first
    /// certificate that cannot be parsed or whose dates cannot be read; on a reload also a
    /// first certificate that is a CA, or a chain over the limits.
    Invalid,
    /// The private key does not belong to the first certificate.
    KeyMismatch,
    /// The first certificate's `notAfter` is in the past (reload only).
    Expired,
    /// The first certificate's `notBefore` is in the future (reload only).
    NotYetValid,
}

/// Which setting of `[server.tls]` a [`LoadError`] is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Setting {
    /// `cert_pem_path`.
    Cert,
    /// `key_pem_path`.
    Key,
    /// Both: the key and the certificate do not go together.
    Both,
}

/// Why the files of `[server.tls]` cannot be used. `why` is a fixed text (with at most an I/O
/// error's own words, a mode or a uid): never a file's content, never a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoadError {
    pub(crate) problem: Problem,
    pub(crate) setting: Setting,
    pub(crate) why: String,
}

impl LoadError {
    fn new(problem: Problem, setting: Setting, why: impl Into<String>) -> Self {
        Self {
            problem,
            setting,
            why: why.into(),
        }
    }

    /// The message of a startup refusal: the setting, its path and the problem.
    fn startup_message(&self, tls: &ServerTlsSection) -> String {
        let (cert, key) = (tls.cert_pem_path.display(), tls.key_pem_path.display());
        match self.setting {
            Setting::Cert => format!("[server.tls] cert_pem_path {cert}: {}", self.why),
            Setting::Key => format!("[server.tls] key_pem_path {key}: {}", self.why),
            Setting::Both => format!(
                "[server.tls] cert_pem_path {cert} and key_pem_path {key}: {}",
                self.why
            ),
        }
    }

    /// The message of a reload refusal: the setting and the problem, without the path (the
    /// operator knows it from the config; the answer does not repeat it).
    pub(crate) fn reload_message(&self) -> String {
        let setting = match self.setting {
            Setting::Cert => "cert_pem_path",
            Setting::Key => "key_pem_path",
            Setting::Both => "cert_pem_path and key_pem_path",
        };
        format!("[server.tls] {setting}: {}", self.why)
    }
}

/// One certificate chain and key in force on the main listener, with the rustls configuration
/// built from them.
#[derive(Debug)]
pub(crate) struct Material {
    /// The configuration every new connection's handshake uses.
    pub(crate) config: Arc<rustls::ServerConfig>,
    /// The SHA-256 of the first certificate's DER bytes.
    pub(crate) leaf_sha256: [u8; 32],
    /// The first certificate's `notBefore` and `notAfter`, in Unix seconds; `None` when they
    /// cannot be read (accepted at startup only).
    pub(crate) validity: Option<(i64, i64)>,
    /// How many certificates the chain file holds, the first one included.
    pub(crate) chain_len: usize,
    /// The DER bytes of all those certificates together.
    pub(crate) chain_der_bytes: usize,
    /// Whether the first certificate's `basicConstraints` says it is a CA.
    pub(crate) leaf_is_ca: bool,
}

impl Material {
    /// The SHA-256 of the first certificate, lower-case hex.
    pub(crate) fn leaf_sha256_hex(&self) -> String {
        hex::encode(self.leaf_sha256)
    }

    /// The first certificate's `notAfter`, in Unix seconds, for the metrics gauge: 0 when it
    /// cannot be read or is before 1970.
    pub(crate) fn not_after_unix(&self) -> u64 {
        self.validity
            .map_or(0, |(_, after)| u64::try_from(after).unwrap_or(0))
    }
}

/// `[server.tls]` in force: the settings read at startup, and the certificate chain and key in
/// force now, which `POST /admin/tls/reload` swaps.
#[derive(Debug)]
pub(crate) struct ServerTls {
    /// The paths and `client_certificates`, as read at startup; never changed.
    section: ServerTlsSection,
    /// The material in force.
    current: RwLock<Arc<Material>>,
    /// Held by `POST /admin/tls/reload` from reading the files to the swap and its audit
    /// record, so two reloads cannot cross (the one that read the older files swapping last).
    /// Waited on in async code, so a waiting reload holds no thread and is dropped with its
    /// request; the owned guard then moves into the blocking task that runs the reload, so a
    /// reload that has started keeps it to its end.
    pub(crate) reloading: Arc<tokio::sync::Mutex<()>>,
}

impl ServerTls {
    /// Read the files of `tls` at startup, with the checks of the module documentation (the
    /// dates are not checked).
    ///
    /// # Errors
    ///
    /// A message that names the setting and the path, never a file's content, when a file
    /// cannot be used or rustls refuses the certificate or the key.
    pub(crate) fn load(tls: &ServerTlsSection) -> anyhow::Result<Self> {
        let material = load(tls).map_err(|e| anyhow::anyhow!(e.startup_message(tls)))?;
        // Refused on a reload, accepted at startup so that a server that starts today keeps
        // starting: one warning each.
        if material.chain_len > MAX_RELOAD_CHAIN_CERTS
            || material.chain_der_bytes > MAX_RELOAD_CHAIN_DER_BYTES
        {
            tracing::warn!(
                certificates = material.chain_len,
                der_bytes = material.chain_der_bytes,
                max_certificates = MAX_RELOAD_CHAIN_CERTS,
                max_der_bytes = MAX_RELOAD_CHAIN_DER_BYTES,
                "[server.tls] cert_pem_path: the chain is longer than a reload accepts; every \
                 handshake sends all of it"
            );
        }
        if material.leaf_is_ca {
            tracing::warn!(
                "[server.tls] cert_pem_path: the first certificate is a CA certificate \
                 (basicConstraints cA); a reload refuses one"
            );
        }
        Ok(Self {
            section: tls.clone(),
            current: RwLock::new(Arc::new(material)),
            reloading: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// The settings read at startup.
    pub(crate) fn section(&self) -> &ServerTlsSection {
        &self.section
    }

    /// The material in force now. It stays usable, unchanged, after a later swap.
    pub(crate) fn current(&self) -> Arc<Material> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Read the files again, from the paths read at startup, with the startup checks and also
    /// the chain's size, whether the first certificate is a CA, and its dates at `now`. Reads
    /// files: call it off the async workers.
    ///
    /// # Errors
    ///
    /// The first problem found, as at startup; a chain over [`MAX_RELOAD_CHAIN_CERTS`] or
    /// [`MAX_RELOAD_CHAIN_DER_BYTES`]; a CA, expired, not yet valid or undated first
    /// certificate.
    pub(crate) fn read_new(&self, now: OffsetDateTime) -> Result<Material, LoadError> {
        let material = load(&self.section)?;
        if material.chain_len > MAX_RELOAD_CHAIN_CERTS {
            return Err(LoadError::new(
                Problem::Invalid,
                Setting::Cert,
                format!(
                    "the file holds {} certificates; a reload accepts at most \
                     {MAX_RELOAD_CHAIN_CERTS} (the server's certificate and its intermediates)",
                    material.chain_len
                ),
            ));
        }
        if material.chain_der_bytes > MAX_RELOAD_CHAIN_DER_BYTES {
            return Err(LoadError::new(
                Problem::Invalid,
                Setting::Cert,
                format!(
                    "the certificates are {} bytes of DER together; a reload accepts at most {} \
                     KiB",
                    material.chain_der_bytes,
                    MAX_RELOAD_CHAIN_DER_BYTES / 1024
                ),
            ));
        }
        if material.leaf_is_ca {
            return Err(LoadError::new(
                Problem::Invalid,
                Setting::Cert,
                "the first certificate is a CA certificate (basicConstraints cA); the server's \
                 own certificate must come first",
            ));
        }
        let Some((not_before, not_after)) = material.validity else {
            return Err(LoadError::new(
                Problem::Invalid,
                Setting::Cert,
                "the validity dates of the first certificate cannot be read",
            ));
        };
        let now = now.unix_timestamp();
        if now > not_after {
            return Err(LoadError::new(
                Problem::Expired,
                Setting::Cert,
                format!(
                    "the first certificate expired at {} (notAfter)",
                    rfc3339(not_after)
                ),
            ));
        }
        if now < not_before {
            return Err(LoadError::new(
                Problem::NotYetValid,
                Setting::Cert,
                format!(
                    "the first certificate is not valid before {} (notBefore)",
                    rfc3339(not_before)
                ),
            ));
        }
        Ok(material)
    }

    /// Put `new` in force for every connection accepted from now on, and return the material it
    /// replaces.
    pub(crate) fn swap(&self, new: Material) -> Arc<Material> {
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        std::mem::replace(&mut *current, Arc::new(new))
    }
}

/// `t` (Unix seconds) as RFC 3339, or the number when it is out of range.
pub(crate) fn rfc3339(t: i64) -> String {
    OffsetDateTime::from_unix_timestamp(t)
        .ok()
        .and_then(|d| {
            d.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| t.to_string())
}

/// The TLS configuration of `[server.tls]`, as startup builds it.
///
/// # Errors
///
/// See [`ServerTls::load`].
#[cfg(test)]
pub(crate) fn server_config(tls: &ServerTlsSection) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    Ok(ServerTls::load(tls)?.current().config.clone())
}

/// Read and check the files of `tls`, and build the configuration: the startup checks.
fn load(tls: &ServerTlsSection) -> Result<Material, LoadError> {
    let certs = read_certs(&tls.cert_pem_path, &tls.key_pem_path)?;
    let key = read_key(&tls.key_pem_path)?;
    let leaf_sha256: [u8; 32] = sha2::Sha256::digest(certs[0].as_ref()).into();
    let validity = crate::client_pki::validity(certs[0].as_ref());
    let leaf_is_ca = crate::client_pki::is_ca(certs[0].as_ref());
    let chain_len = certs.len();
    let chain_der_bytes = certs.iter().map(|c| c.as_ref().len()).sum();
    let config = build(certs, key, tls.client_certificates)?;
    Ok(Material {
        config,
        leaf_sha256,
        validity,
        chain_len,
        chain_der_bytes,
        leaf_is_ca,
    })
}

/// The rustls configuration of `certs` (leaf first) and `key`, asking for client
/// certificates as `client_certificates` says.
fn build(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_certificates: ClientCertificates,
) -> Result<Arc<rustls::ServerConfig>, LoadError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certified = certified_key(certs, key, &provider)?;
    let algs = provider.signature_verification_algorithms;
    let builder = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| {
            LoadError::new(
                Problem::Invalid,
                Setting::Both,
                format!("cannot set up TLS 1.3 ({e})"),
            )
        })?;
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
) -> Result<CertifiedKey, LoadError> {
    let refused = |problem, why: &str| LoadError::new(problem, Setting::Both, why);
    // No error detail from rustls or the file: fixed texts only.
    let signing_key = provider.key_provider.load_private_key(key).map_err(|_| {
        refused(
            Problem::Invalid,
            "the private key cannot be used; use an RSA, ECDSA P-256 or P-384, or Ed25519 key",
        )
    })?;
    let certified = CertifiedKey::new(certs, signing_key);
    match certified.keys_match() {
        Ok(()) => Ok(certified),
        Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::KeyMismatch)) => {
            Err(refused(
                Problem::KeyMismatch,
                "the private key does not belong to the first certificate of the file (the \
                 server's own certificate must come first, then the intermediates)",
            ))
        }
        Err(rustls::Error::InconsistentKeys(_)) => Err(refused(
            Problem::Invalid,
            "cannot check that the private key belongs to the first certificate",
        )),
        Err(_) => Err(refused(
            Problem::Invalid,
            "the first certificate cannot be read as an X.509 certificate",
        )),
    }
}

/// The certificates of the `cert_pem_path` file, in file order.
fn read_certs(path: &Path, key_path: &Path) -> Result<Vec<CertificateDer<'static>>, LoadError> {
    let invalid = |why: &str| LoadError::new(Problem::Invalid, Setting::Cert, why);
    let pem = read_file(path, MAX_CERT_FILE_BYTES, false)
        .map_err(|why| LoadError::new(Problem::Unreadable, Setting::Cert, why))?;
    if pem.iter().all(u8::is_ascii_whitespace) {
        return Err(invalid("the file is empty; it must hold PEM certificates"));
    }
    let has_key = mentions_private_key(&pem);
    // A private key here would be as exposed as the certificate, which is not secret; keep it
    // in key_pem_path. The same file for both keys is fine: it is checked as a key file. Any
    // mention of `PRIVATE KEY` counts, an encrypted or malformed key included.
    if has_key && path != key_path {
        return Err(invalid(
            "the file holds a private key; keep the key in key_pem_path only",
        ));
    }
    // The parser's error is never shown: some of its variants print a whole line of the file,
    // which may be part of a private key.
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid("not a valid PEM certificate file"))?;
    if certs.is_empty() {
        return Err(invalid(
            "no PEM certificate (-----BEGIN CERTIFICATE-----) in the file",
        ));
    }
    Ok(certs)
}

/// Whether the bytes `PRIVATE KEY` appear anywhere in `pem`: a key section of any kind
/// (`PRIVATE KEY`, `EC PRIVATE KEY`, `RSA PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, ...), well
/// formed or not, on a line of its own or run together with others. Nothing is decoded.
pub(crate) fn mentions_private_key(pem: &[u8]) -> bool {
    const NEEDLE: &[u8] = b"PRIVATE KEY";
    pem.windows(NEEDLE.len()).any(|w| w == NEEDLE)
}

/// How many PEM sections of `pem` begin as a private key of any kind: each `BEGIN` whose
/// label, up to the next `-----` or line end, holds `PRIVATE KEY` (`PRIVATE KEY`,
/// `EC PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, `OPENSSH PRIVATE KEY`, ...). Nothing is decoded.
/// Linear: each label is scanned once, from its `BEGIN` to its end.
pub(crate) fn private_key_sections(pem: &[u8]) -> usize {
    const BEGIN: &[u8] = b"BEGIN";
    const NEEDLE: &[u8] = b"PRIVATE KEY";
    let mut count = 0;
    let mut i = 0;
    while i + BEGIN.len() <= pem.len() {
        if !pem[i..].starts_with(BEGIN) {
            i += 1;
            continue;
        }
        let start = i + BEGIN.len();
        // The label ends at the next `-----`, line end, or the next `BEGIN` (counted on its
        // own), whichever comes first.
        let mut end = start;
        while end < pem.len()
            && !pem[end..].starts_with(b"-----")
            && !pem[end..].starts_with(BEGIN)
            && pem[end] != b'\n'
            && pem[end] != b'\r'
        {
            end += 1;
        }
        if pem[start..end].windows(NEEDLE.len()).any(|w| w == NEEDLE) {
            count += 1;
        }
        i = end.max(start);
    }
    count
}

/// The one private key of the `key_pem_path` file.
fn read_key(path: &Path) -> Result<PrivateKeyDer<'static>, LoadError> {
    let invalid = |why: &str| LoadError::new(Problem::Invalid, Setting::Key, why);
    let pem = read_file(path, MAX_KEY_FILE_BYTES, true)
        .map_err(|why| LoadError::new(Problem::Unreadable, Setting::Key, why))?;
    if pem.iter().all(u8::is_ascii_whitespace) {
        return Err(invalid("the file is empty; it must hold a PEM private key"));
    }
    // Every private-key section counts, one the parser skips (encrypted, unknown kind)
    // included: a second key next to the one used is refused, whatever its kind.
    if private_key_sections(&pem) > 1 {
        return Err(invalid(
            "the file holds more than one private key; keep only the key of the certificate",
        ));
    }
    // The parser's own error is not shown: it can quote part of the file.
    let mut keys = PrivateKeyDer::pem_slice_iter(&pem);
    let key = match keys.next() {
        Some(Ok(key)) => key,
        Some(Err(_)) => return Err(invalid("not a valid PEM private key file")),
        None => {
            return Err(invalid(
                "no private key (-----BEGIN PRIVATE KEY-----, -----BEGIN EC PRIVATE \
                 KEY----- or -----BEGIN RSA PRIVATE KEY-----) in the file; an encrypted key \
                 is not supported",
            ))
        }
    };
    match keys.next() {
        None => Ok(key),
        Some(Ok(_)) => Err(invalid(
            "the file holds more than one private key; keep only the key of \
             the certificate",
        )),
        Some(Err(_)) => Err(invalid("not a valid PEM private key file")),
    }
}

/// Why a TLS handshake of the main listener failed, from the error the handshake returned
/// (a timeout is counted by the accept loop itself). Reads only the kind of the rustls error,
/// never a text, so the label set stays fixed whatever the peer sends.
pub(crate) fn handshake_failure(e: &std::io::Error) -> HandshakeFailure {
    use rustls::Error as E;
    let Some(err) = e.get_ref().and_then(|i| i.downcast_ref::<E>()) else {
        return HandshakeFailure::Other;
    };
    match err {
        E::InvalidCertificate(_) | E::NoCertificatesPresented | E::InvalidCertRevocationList(_) => {
            HandshakeFailure::BadClientCertificate
        }
        E::AlertReceived(_) => HandshakeFailure::PeerAlert,
        E::InappropriateMessage { .. }
        | E::InappropriateHandshakeMessage { .. }
        | E::InvalidMessage(_)
        | E::PeerIncompatible(_)
        | E::PeerMisbehaved(_)
        | E::PeerSentOversizedRecord
        | E::NoApplicationProtocol
        | E::DecryptError
        | E::InvalidEncryptedClientHello(_)
        | E::UnsupportedNameType => HandshakeFailure::Protocol,
        _ => HandshakeFailure::Other,
    }
}

/// The bytes of a regular file of at most `max` bytes, checked before reading and again while
/// reading, as `ca_pem_path` files are read. For a `secret` file on Unix, the open file must
/// not be readable or writable by its group or by others. The file is opened without blocking
/// ([`open_nonblocking`]) and its type is checked on the open handle, so a FIFO is refused
/// rather than waited on.
pub(crate) fn read_file(path: &Path, max: u64, secret: bool) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let unreadable = |e: std::io::Error| format!("cannot read the file ({e})");
    let too_big = || format!("the file is larger than {} KiB", max / 1024);
    let file = open_nonblocking(path).map_err(unreadable)?;
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

/// Open `path` for reading without blocking on a FIFO or a device: on Unix with
/// `O_NONBLOCK`, which a regular file ignores.
fn open_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
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
        // A usable key next to a section the parser skips (encrypted, OpenSSH, an unknown
        // kind), before or after it, on lines of their own or run together: more than one key.
        for other in [
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
            "-----BEGIN FOO PRIVATE KEY-----\nAAAA\n-----END FOO PRIVATE KEY-----\n",
        ] {
            for text in [
                format!("{key_pem}{other}"),
                format!("{other}{key_pem}"),
                format!("{}{}", key_pem.trim_end(), other),
            ] {
                let two = write(dir.path(), "two.key", &text, 0o600);
                let err = refusal(&cert, &two);
                assert!(err.contains("more than one private key"), "{other}: {err}");
                assert!(!err.contains("AAAA"), "{err}");
            }
        }
        assert_eq!(private_key_sections(key_pem.as_bytes()), 1);
        assert_eq!(private_key_sections(cert_pem.as_bytes()), 0);
        assert_eq!(private_key_sections(b"BEGIN"), 0);
        assert_eq!(private_key_sections(b""), 0);
        // A long label still counts: the label runs to its `-----`, however long.
        let long = format!(
            "-----BEGIN {} PRIVATE KEY-----\nAAAA\n-----END {0} PRIVATE KEY-----\n",
            "X".repeat(70)
        );
        assert_eq!(private_key_sections(long.as_bytes()), 1);
        let two = write(dir.path(), "two.key", &format!("{key_pem}{long}"), 0o600);
        let err = refusal(&cert, &two);
        assert!(err.contains("more than one private key"), "{err}");
        // Two on one line, and a `BEGIN` inside a label, count each section once.
        assert_eq!(
            private_key_sections(b"-----BEGIN PRIVATE KEY----------BEGIN EC PRIVATE KEY-----"),
            2
        );
        assert_eq!(private_key_sections(b"BEGINBEGIN PRIVATE KEY"), 1);
        assert_eq!(private_key_sections(b"-----END PRIVATE KEY-----"), 0);
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

    /// A key pair and a certificate for `localhost` valid from `not_before` to `not_after`
    /// (Unix seconds), as PEM.
    fn dated_cert_and_key(not_before: i64, not_after: i64) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.not_before = OffsetDateTime::from_unix_timestamp(not_before).unwrap();
        params.not_after = OffsetDateTime::from_unix_timestamp(not_after).unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    const DAY: i64 = 86_400;

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    /// A reload reads the same paths again: a new certificate written over the old files is
    /// put in force by a swap, and the swap returns the old material, still usable.
    #[test]
    fn a_reload_reads_the_same_paths_and_swaps_whole() {
        let dir = tempfile::tempdir().unwrap();
        let t = now().unix_timestamp();
        let (cert_pem, key_pem) = dated_cert_and_key(t - DAY, t + DAY);
        let cert = write(dir.path(), "server.crt", &cert_pem, 0o644);
        let key = write(dir.path(), "server.key", &key_pem, 0o600);
        let mut tls_section = section(&cert, &key);
        tls_section.client_certificates = ClientCertificates::Optional;
        let tls = ServerTls::load(&tls_section).unwrap();
        let first = tls.current();
        assert_eq!(first.chain_len, 1);
        assert_eq!(first.validity, Some((t - DAY, t + DAY)));
        assert_eq!(
            u64::try_from(t + DAY).unwrap(),
            first.not_after_unix(),
            "the gauge value"
        );

        let (cert2, key2) = dated_cert_and_key(t - DAY, t + 2 * DAY);
        write(dir.path(), "server.crt", &cert2, 0o644);
        write(dir.path(), "server.key", &key2, 0o600);
        let new = tls.read_new(now()).unwrap();
        assert_ne!(new.leaf_sha256, first.leaf_sha256);
        let old = tls.swap(new);
        assert_eq!(old.leaf_sha256, first.leaf_sha256);
        let second = tls.current();
        assert_ne!(second.leaf_sha256, first.leaf_sha256);
        assert_eq!(second.validity, Some((t - DAY, t + 2 * DAY)));
        // The settings did not change: they come from the code and the startup section.
        for config in [&first.config, &second.config] {
            assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
            assert_eq!(config.send_tls13_tickets, 0);
            assert_eq!(config.max_tls13_tickets, 0);
            assert_eq!(config.max_early_data_size, 0);
            assert!(!config.ticketer.enabled());
            assert!(!config.session_storage.can_cache());
        }
        assert_eq!(tls.section(), &tls_section);
    }

    /// A reload refuses what startup refuses, with the same problem, and names the setting
    /// but never the path.
    #[test]
    fn a_reload_refuses_what_startup_refuses_without_naming_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let t = now().unix_timestamp();
        let (cert_pem, key_pem) = dated_cert_and_key(t - DAY, t + DAY);
        let cert = write(dir.path(), "server.crt", &cert_pem, 0o644);
        let key = write(dir.path(), "server.key", &key_pem, 0o600);
        let tls = ServerTls::load(&section(&cert, &key)).unwrap();
        let (_, other_key) = dated_cert_and_key(t - DAY, t + DAY);
        let refused = |problem: Problem, setting: Setting| {
            let e = tls.read_new(now()).unwrap_err();
            assert_eq!((e.problem, e.setting), (problem, setting), "{e:?}");
            let msg = e.reload_message();
            assert!(!msg.contains(&dir.path().display().to_string()), "{msg}");
            assert!(msg.starts_with("[server.tls] "), "{msg}");
            msg
        };
        // A key of another certificate.
        write(dir.path(), "server.key", &other_key, 0o600);
        let msg = refused(Problem::KeyMismatch, Setting::Both);
        assert!(msg.contains("does not belong"), "{msg}");
        write(dir.path(), "server.key", &key_pem, 0o600);
        // An empty certificate file: an empty chain.
        write(dir.path(), "server.crt", "", 0o644);
        refused(Problem::Invalid, Setting::Cert);
        // Not PEM.
        write(dir.path(), "server.crt", "not pem\n", 0o644);
        refused(Problem::Invalid, Setting::Cert);
        write(dir.path(), "server.crt", &cert_pem, 0o644);
        // A key file open to others.
        #[cfg(unix)]
        {
            write(dir.path(), "server.key", &key_pem, 0o644);
            let msg = refused(Problem::Unreadable, Setting::Key);
            assert!(msg.contains("0644"), "{msg}");
            write(dir.path(), "server.key", &key_pem, 0o600);
        }
        // Gone.
        std::fs::remove_file(&key).unwrap();
        refused(Problem::Unreadable, Setting::Key);
        write(dir.path(), "server.key", &key_pem, 0o600);
        // A private key in the certificate file.
        write(
            dir.path(),
            "server.crt",
            &format!("{cert_pem}{key_pem}"),
            0o644,
        );
        let msg = refused(Problem::Invalid, Setting::Cert);
        assert!(!msg.contains("BEGIN PRIVATE KEY"), "{msg}");
        write(dir.path(), "server.crt", &cert_pem, 0o644);
        // A broken key block is never quoted.
        let (broken, body) = broken_key();
        write(dir.path(), "server.key", &broken, 0o600);
        let msg = refused(Problem::Invalid, Setting::Key);
        assert_no_key_text(&msg, &body, &[]);
        write(dir.path(), "server.key", &key_pem, 0o600);
        // Every refusal left the material in force alone, and good files read again.
        tls.read_new(now()).unwrap();
    }

    /// A reload refuses an expired or not yet valid first certificate, which startup accepts.
    #[test]
    fn a_reload_checks_the_dates_startup_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let t = now().unix_timestamp();
        for (from, to, problem, word) in [
            (t - 2 * DAY, t - DAY, Problem::Expired, "expired"),
            (
                t + DAY,
                t + 2 * DAY,
                Problem::NotYetValid,
                "not valid before",
            ),
        ] {
            let (cert_pem, key_pem) = dated_cert_and_key(from, to);
            let cert = write(dir.path(), "server.crt", &cert_pem, 0o644);
            let key = write(dir.path(), "server.key", &key_pem, 0o600);
            // Startup takes it (and the gauge shows its notAfter).
            let tls = ServerTls::load(&section(&cert, &key)).unwrap();
            assert_eq!(tls.current().validity, Some((from, to)));
            let e = tls.read_new(now()).unwrap_err();
            assert_eq!(e.problem, problem);
            assert_eq!(e.setting, Setting::Cert);
            assert!(e.why.contains(word), "{}", e.why);
            // The edges are valid: notBefore and notAfter themselves.
            for at in [from, to] {
                tls.read_new(OffsetDateTime::from_unix_timestamp(at).unwrap())
                    .unwrap();
            }
            let past = OffsetDateTime::from_unix_timestamp(to + 1).unwrap();
            assert_eq!(tls.read_new(past).unwrap_err().problem, Problem::Expired);
            let early = OffsetDateTime::from_unix_timestamp(from - 1).unwrap();
            assert_eq!(
                tls.read_new(early).unwrap_err().problem,
                Problem::NotYetValid
            );
        }
    }

    /// A reload refuses a chain of more than ten certificates or 64 KiB of DER, and a first
    /// certificate that is a CA; startup accepts them (and logs a warning).
    #[test]
    fn a_reload_refuses_a_long_chain_or_a_ca_certificate_that_startup_takes() {
        let dir = tempfile::tempdir().unwrap();
        let t = now().unix_timestamp();
        let (cert_pem, key_pem) = dated_cert_and_key(t - DAY, t + DAY);
        let key = write(dir.path(), "server.key", &key_pem, 0o600);
        let refused = |cert_text: &str, key_text: &str, word: &str| {
            let cert = write(dir.path(), "server.crt", cert_text, 0o644);
            write(dir.path(), "server.key", key_text, 0o600);
            let tls = ServerTls::load(&section(&cert, &key)).unwrap();
            let e = tls.read_new(now()).unwrap_err();
            assert_eq!(
                (e.problem, e.setting),
                (Problem::Invalid, Setting::Cert),
                "{e:?}"
            );
            assert!(e.why.contains(word), "{}", e.why);
            tls.current()
        };

        // Ten certificates are taken; eleven are refused.
        let ten = cert_pem.repeat(MAX_RELOAD_CHAIN_CERTS);
        let cert = write(dir.path(), "server.crt", &ten, 0o644);
        let tls = ServerTls::load(&section(&cert, &key)).unwrap();
        assert_eq!(tls.read_new(now()).unwrap().chain_len, 10);
        let eleven = cert_pem.repeat(MAX_RELOAD_CHAIN_CERTS + 1);
        let m = refused(&eleven, &key_pem, "11 certificates");
        assert_eq!(m.chain_len, 11);

        // Five certificates, more than 64 KiB of DER together: four large ones after the
        // server's. (One certificate of more than 64 KiB cannot be parsed at all.)
        let names: Vec<String> = (0..800)
            .map(|i| format!("host-{i:05}.example.org"))
            .collect();
        let big = rcgen::CertificateParams::new(names)
            .unwrap()
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap();
        assert!(4 * big.der().len() > MAX_RELOAD_CHAIN_DER_BYTES);
        let long = format!("{cert_pem}{}", big.pem().repeat(4));
        let m = refused(&long, &key_pem, "64 KiB");
        assert_eq!(m.chain_len, 5);
        assert!(m.chain_der_bytes > MAX_RELOAD_CHAIN_DER_BYTES);

        // A CA certificate first.
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.not_before = OffsetDateTime::from_unix_timestamp(t - DAY).unwrap();
        params.not_after = OffsetDateTime::from_unix_timestamp(t + DAY).unwrap();
        let ca = params.self_signed(&ca_key).unwrap();
        let m = refused(&ca.pem(), &ca_key.serialize_pem(), "CA certificate");
        assert!(m.leaf_is_ca);
        // An end-entity certificate is not a CA.
        write(dir.path(), "server.crt", &cert_pem, 0o644);
        write(dir.path(), "server.key", &key_pem, 0o600);
        assert!(
            !ServerTls::load(&section(&cert, &key))
                .unwrap()
                .current()
                .leaf_is_ca
        );
    }

    /// The reason of a failed handshake comes from the kind of the rustls error only.
    #[test]
    fn handshake_failures_are_classified_by_kind() {
        let io = |e: rustls::Error| std::io::Error::new(std::io::ErrorKind::InvalidData, e);
        let cases = [
            (
                io(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadSignature,
                )),
                HandshakeFailure::BadClientCertificate,
            ),
            (
                io(rustls::Error::NoCertificatesPresented),
                HandshakeFailure::BadClientCertificate,
            ),
            (
                io(rustls::Error::AlertReceived(
                    rustls::AlertDescription::UnknownCA,
                )),
                HandshakeFailure::PeerAlert,
            ),
            (
                io(rustls::Error::PeerIncompatible(
                    rustls::PeerIncompatible::SupportedVersionsExtensionRequired,
                )),
                HandshakeFailure::Protocol,
            ),
            (
                io(rustls::Error::InvalidMessage(
                    rustls::InvalidMessage::InvalidContentType,
                )),
                HandshakeFailure::Protocol,
            ),
            (
                io(rustls::Error::NoApplicationProtocol),
                HandshakeFailure::Protocol,
            ),
            (
                io(rustls::Error::General("attacker text".into())),
                HandshakeFailure::Other,
            ),
            (
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "tls handshake eof"),
                HandshakeFailure::Other,
            ),
            (
                std::io::Error::from(std::io::ErrorKind::ConnectionReset),
                HandshakeFailure::Other,
            ),
        ];
        for (e, want) in cases {
            assert_eq!(handshake_failure(&e), want, "{e}");
        }
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

    /// A FIFO is refused without waiting for a writer: nothing ever writes to this one, so a
    /// blocking open would hang the test (and a server's start or reload).
    #[cfg(unix)]
    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo.pem");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .unwrap();
        for secret in [false, true] {
            assert_eq!(
                read_file(&fifo, 1024, secret).unwrap_err(),
                "not a regular file"
            );
        }
        let ca = crate::client_pki::read_ca_file(&fifo).unwrap_err();
        assert_eq!(ca, "not a regular file");
    }
}
