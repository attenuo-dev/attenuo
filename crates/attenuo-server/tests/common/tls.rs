//! A test certificate authority and an HTTPS key server whose certificate it issued, for the
//! key URL tests with `ca_pem_path` (`key_url_ca.rs`, `client_jwks_uri.rs`), and the server
//! certificate files and TLS clients of the `[server.tls]` tests (`server_tls.rs`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A certificate authority made for one test.
pub struct Ca {
    pub cert: rcgen::Certificate,
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
}

impl Ca {
    pub fn new(name: &str) -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let cert = params.self_signed(&key).unwrap();
        Self { cert, params, key }
    }

    /// Write the CA certificate as PEM into `dir`.
    pub fn write(&self, dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, self.cert.pem()).unwrap();
        path
    }

    /// A server certificate for `names` (DNS names or IP addresses) signed by this CA.
    pub fn leaf(&self, names: &[&str]) -> (rustls::pki_types::CertificateDer<'static>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let mut params = rcgen::CertificateParams::new(names).unwrap();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
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

    /// Write a server certificate for `names` (with this CA's certificate after it) and its
    /// key into `dir` as PEM files, the key with mode 0600. Returns the two paths.
    pub fn write_server_files(&self, dir: &Path, names: &[&str]) -> (PathBuf, PathBuf) {
        let (cert, key) = self.leaf(names);
        let pem = |label: &str, der: &[u8]| {
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
        };
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
