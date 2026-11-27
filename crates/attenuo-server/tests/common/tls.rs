//! A test certificate authority and an HTTPS key server whose certificate it issued, for the
//! key URL tests with `ca_pem_path` (`key_url_ca.rs`, `client_jwks_uri.rs`), the server
//! certificate files and TLS clients of the `[server.tls]` tests (`server_tls.rs`), and
//! client certificates for the mTLS client authentication tests (`mtls.rs`): self-signed
//! ones, and ones a CA or an intermediate CA issued; and the CRLs of `client_crl.rs`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A certificate authority made for one test: a root, or an intermediate CA another one
/// issued.
pub struct Ca {
    pub cert: rcgen::Certificate,
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    /// What a client sends after a certificate this CA issued: nothing for a root, this
    /// certificate and those above it (roots left out) for an intermediate.
    above: Vec<rustls::pki_types::CertificateDer<'static>>,
}

impl Ca {
    pub fn new(name: &str) -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = Self::ca_params(name);
        let cert = params.self_signed(&key).unwrap();
        Self {
            cert,
            params,
            key,
            above: Vec::new(),
        }
    }

    fn ca_params(name: &str) -> rcgen::CertificateParams {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params
    }

    /// An intermediate CA this CA issues.
    pub fn intermediate(&self, name: &str) -> Self {
        self.intermediate_with(name, |_| {})
    }

    /// An intermediate CA this CA issues, with `edit` applied to its parameters (a serial
    /// number, for a CRL that revokes it).
    pub fn intermediate_with(
        &self,
        name: &str,
        edit: impl FnOnce(&mut rcgen::CertificateParams),
    ) -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = Self::ca_params(name);
        edit(&mut params);
        let cert = params
            .signed_by(&key, &rcgen::Issuer::from_params(&self.params, &self.key))
            .unwrap();
        let mut above = vec![cert.der().clone()];
        above.extend(self.above.iter().cloned());
        Self {
            cert,
            params,
            key,
            above,
        }
    }

    /// A new certificate for this CA, with its name and key, that `issuer` signs, with `edit`
    /// applied to its parameters (its dates, for a copy that has expired).
    pub fn reissued(
        &self,
        issuer: &Ca,
        edit: impl FnOnce(&mut rcgen::CertificateParams),
    ) -> rcgen::Certificate {
        let mut params = self.params.clone();
        edit(&mut params);
        params
            .signed_by(
                &self.key,
                &rcgen::Issuer::from_params(&issuer.params, &issuer.key),
            )
            .unwrap()
    }

    /// A client certificate this CA issues: valid from a day ago for 30 days, `CA:FALSE`,
    /// extended key usage `clientAuth`, no names, then `edit`. It is sent with the
    /// intermediates up to the root, as a client sends its chain.
    pub fn client(&self, edit: impl FnOnce(&mut rcgen::CertificateParams)) -> ClientCert {
        let key = rcgen::KeyPair::generate().unwrap();
        let now = time::OffsetDateTime::now_utc();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "client");
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(30);
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        edit(&mut params);
        let cert = params
            .signed_by(&key, &rcgen::Issuer::from_params(&self.params, &self.key))
            .unwrap();
        ClientCert {
            der: cert.der().clone(),
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            key_der: key.serialize_der(),
            chain: self.above.clone(),
        }
    }

    /// The CA's own certificate and key, presented as a client certificate.
    pub fn as_client(&self) -> ClientCert {
        ClientCert {
            der: self.cert.der().clone(),
            cert_pem: self.cert.pem(),
            key_pem: self.key.serialize_pem(),
            key_der: self.key.serialize_der(),
            chain: self.above.clone(),
        }
    }

    /// A CRL this CA signs (PEM), listing the certificates with `serials` as revoked, with
    /// `thisUpdate` and `nextUpdate` and the `cRLNumber` `number`.
    pub fn crl(
        &self,
        serials: &[u64],
        this_update: time::OffsetDateTime,
        next_update: time::OffsetDateTime,
        number: u64,
    ) -> String {
        self.crl_with(serials, this_update, next_update, number, |_| {})
    }

    /// [`Ca::crl`], with `edit` applied to the parameters (an `issuingDistributionPoint`).
    pub fn crl_with(
        &self,
        serials: &[u64],
        this_update: time::OffsetDateTime,
        next_update: time::OffsetDateTime,
        number: u64,
        edit: impl FnOnce(&mut rcgen::CertificateRevocationListParams),
    ) -> String {
        let mut params = rcgen::CertificateRevocationListParams {
            this_update,
            next_update,
            crl_number: rcgen::SerialNumber::from(number),
            issuing_distribution_point: None,
            revoked_certs: serials
                .iter()
                .map(|s| rcgen::RevokedCertParams {
                    serial_number: rcgen::SerialNumber::from(*s),
                    revocation_time: this_update,
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
            .pem()
            .unwrap()
    }

    /// Write the CA certificate as PEM into `dir`.
    pub fn write(&self, dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, self.cert.pem()).unwrap();
        path
    }

    /// A server certificate for `names` (DNS names or IP addresses) signed by this CA.
    pub fn leaf(&self, names: &[&str]) -> (rustls::pki_types::CertificateDer<'static>, Vec<u8>) {
        self.leaf_with(names, |_| {})
    }

    /// [`Ca::leaf`], with `edit` applied to its parameters (its dates, for example).
    pub fn leaf_with(
        &self,
        names: &[&str],
        edit: impl FnOnce(&mut rcgen::CertificateParams),
    ) -> (rustls::pki_types::CertificateDer<'static>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let mut params = rcgen::CertificateParams::new(names).unwrap();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        edit(&mut params);
        let issuer = rcgen::Issuer::from_params(&self.params, &self.key);
        let cert = params.signed_by(&key, &issuer).unwrap();
        (cert.der().clone(), key.serialize_der())
    }
}

impl Ca {
    /// The CA certificate as a root for a reqwest client.
    pub fn reqwest_root(&self) -> reqwest::Certificate {
        reqwest::Certificate::from_pem(self.cert.pem().as_bytes()).unwrap()
    }

    /// A `rustls` client config that trusts this CA only, offers `alpn` and speaks `versions`.
    pub fn rustls_client(
        &self,
        versions: &[&'static rustls::SupportedProtocolVersion],
        alpn: &[&[u8]],
    ) -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.cert.der().clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        config
    }

    /// A `rustls` client config that trusts this CA only, speaks TLS 1.3, offers `http/1.1`
    /// and presents `client` (a certificate and a key) when the server asks for one.
    pub fn rustls_client_with(
        &self,
        client: Arc<dyn rustls::client::ResolvesClientCert>,
    ) -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.cert.der().clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_client_cert_resolver(client);
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config
    }

    /// A reqwest client that trusts this CA only and presents `identity`, if any.
    pub fn reqwest_client(&self, identity: Option<&ClientCert>) -> reqwest::Client {
        let mut builder = reqwest::Client::builder()
            .tls_built_in_root_certs(false)
            .add_root_certificate(self.reqwest_root());
        if let Some(id) = identity {
            builder = builder.identity(id.identity());
        }
        builder.build().unwrap()
    }

    /// Write a server certificate for `names` (with this CA's certificate after it) and its
    /// key into `dir` as PEM files, the key with mode 0600. Returns the two paths.
    pub fn write_server_files(&self, dir: &Path, names: &[&str]) -> (PathBuf, PathBuf) {
        self.write_server_files_with(dir, names, |_| {})
    }

    /// [`Ca::write_server_files`], the certificate made with `edit` ([`Ca::leaf_with`]).
    pub fn write_server_files_with(
        &self,
        dir: &Path,
        names: &[&str],
        edit: impl FnOnce(&mut rcgen::CertificateParams),
    ) -> (PathBuf, PathBuf) {
        let (cert, key) = self.leaf_with(names, edit);
        let cert_path = dir.join("server.crt");
        let key_path = dir.join("server.key");
        std::fs::write(
            &cert_path,
            format!("{}{}", pem("CERTIFICATE", &cert), self.cert.pem()),
        )
        .unwrap();
        std::fs::write(&key_path, pem("PRIVATE KEY", &key)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        (cert_path, key_path)
    }
}

/// A client certificate and its key: self-signed, as an agent or a PEP makes one for RFC 8705
/// `self_signed_tls_client_auth`, or issued by a [`Ca`] for `tls_client_auth`.
#[derive(Clone)]
pub struct ClientCert {
    pub der: rustls::pki_types::CertificateDer<'static>,
    pub cert_pem: String,
    pub key_pem: String,
    key_der: Vec<u8>,
    /// The certificates the client sends after its own (intermediate CAs).
    pub chain: Vec<rustls::pki_types::CertificateDer<'static>>,
}

impl std::fmt::Debug for ClientCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ClientCert")
            .field(&self.sha256_hex())
            .finish()
    }
}

impl ClientCert {
    /// Valid from a day ago for 30 days, `CA:FALSE`, extended key usage `clientAuth`: what the
    /// guide's `openssl req -x509` command makes.
    pub fn new(name: &str) -> Self {
        let now = time::OffsetDateTime::now_utc();
        Self::with_dates(
            name,
            now - time::Duration::days(1),
            now + time::Duration::days(30),
        )
    }

    /// Valid from `not_before` to `not_after`.
    pub fn with_dates(
        name: &str,
        not_before: time::OffsetDateTime,
        not_after: time::OffsetDateTime,
    ) -> Self {
        Self::made(name, |p| {
            p.not_before = not_before;
            p.not_after = not_after;
        })
    }

    /// Made with `edit` applied over [`ClientCert::new`]'s parameters.
    pub fn made(name: &str, edit: impl FnOnce(&mut rcgen::CertificateParams)) -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let now = time::OffsetDateTime::now_utc();
        let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(30);
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        edit(&mut params);
        let cert = params.self_signed(&key).unwrap();
        Self {
            der: cert.der().clone(),
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            key_der: key.serialize_der(),
            chain: Vec::new(),
        }
    }

    /// The same certificate, sent with no intermediates.
    pub fn without_chain(&self) -> Self {
        Self {
            chain: Vec::new(),
            ..self.clone()
        }
    }

    /// The lowercase hex SHA-256 of the DER bytes: a `tls_client_cert_sha256` value.
    pub fn sha256_hex(&self) -> String {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(self.der.as_ref()))
    }

    /// The base64url SHA-256: the `x5t#S256` of the audit records.
    pub fn x5t_s256(&self) -> String {
        use base64::Engine as _;
        use sha2::Digest;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(self.der.as_ref()))
    }

    /// For a reqwest client: the certificate, the intermediates, the key.
    pub fn identity(&self) -> reqwest::Identity {
        let chain: String = self.chain.iter().map(|c| pem("CERTIFICATE", c)).collect();
        reqwest::Identity::from_pem(format!("{}{chain}{}", self.cert_pem, self.key_pem).as_bytes())
            .unwrap()
    }

    /// The certificate with its own key, for a raw rustls client.
    pub fn resolver(&self) -> Arc<dyn rustls::client::ResolvesClientCert> {
        self.resolver_signing_with(self)
    }

    /// This certificate, but the handshake signed with `other`'s key: a client that sends a
    /// certificate whose private key it does not hold.
    pub fn resolver_signing_with(
        &self,
        other: &ClientCert,
    ) -> Arc<dyn rustls::client::ResolvesClientCert> {
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(other.key_der.clone().into());
        let signing = rustls::crypto::ring::sign::any_supported_type(&key).unwrap();
        let mut certs = vec![self.der.clone()];
        certs.extend(self.chain.iter().cloned());
        Arc::new(Fixed(Arc::new(rustls::sign::CertifiedKey::new(
            certs, signing,
        ))))
    }
}

/// `der` as a PEM block with `label`.
pub fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

/// A client certificate resolver that always presents the same certificate and key, whether
/// or not they belong together.
#[derive(Debug)]
struct Fixed(Arc<rustls::sign::CertifiedKey>);

impl rustls::client::ResolvesClientCert for Fixed {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// An HTTPS server on 127.0.0.1 whose certificate (for `127.0.0.1` only) chains to `ca`. It
/// answers `GET <path>` with the JSON stored for the path, `/moved` with a redirect, anything
/// else with 404, and counts the requests per path. HTTP/1.1, one request per connection.
pub struct TlsKeyServer {
    pub port: u16,
    docs: Arc<Mutex<HashMap<String, Value>>>,
    hits: Arc<Mutex<HashMap<String, usize>>>,
    pub handshakes_failed: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TlsKeyServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TlsKeyServer {
    pub async fn start(ca: &Ca) -> Self {
        let (cert, key) = ca.leaf(&["127.0.0.1"]);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert, ca.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let docs: Arc<Mutex<HashMap<String, Value>>> = Arc::default();
        let hits: Arc<Mutex<HashMap<String, usize>>> = Arc::default();
        let handshakes_failed = Arc::new(AtomicUsize::new(0));
        let (d, h, f) = (docs.clone(), hits.clone(), handshakes_failed.clone());
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let (acceptor, d, h, f) = (acceptor.clone(), d.clone(), h.clone(), f.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        f.fetch_add(1, Ordering::SeqCst);
                        return;
                    };
                    let mut req = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !req.windows(4).any(|w| w == b"\r\n\r\n") && req.len() < 16 * 1024 {
                        match tls.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => req.extend_from_slice(&buf[..n]),
                        }
                    }
                    let line = String::from_utf8_lossy(&req);
                    let path = line.split_whitespace().nth(1).unwrap_or("/").to_owned();
                    *h.lock().unwrap().entry(path.clone()).or_default() += 1;
                    let doc = d.lock().unwrap().get(&path).cloned();
                    let resp = match (path.as_str(), doc) {
                        ("/moved", _) => "HTTP/1.1 302 Found\r\nLocation: /bundle\r\n\
                             Content-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_owned(),
                        (_, Some(doc)) => {
                            let body = doc.to_string();
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            )
                        }
                        (_, None) => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\
                             Connection: close\r\n\r\n"
                            .to_owned(),
                    };
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Self {
            port,
            docs,
            hits,
            handshakes_failed,
            task,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }

    pub fn serve(&self, path: &str, doc: Value) {
        self.docs.lock().unwrap().insert(path.into(), doc);
    }

    pub fn hits(&self, path: &str) -> usize {
        self.hits.lock().unwrap().get(path).copied().unwrap_or(0)
    }
}
