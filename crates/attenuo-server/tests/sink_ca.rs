//! `[audit.sink] ca_pem_path`: a webhook receiver or an S3-compatible store served over HTTPS
//! with a certificate from a private CA made in the test. Without the setting the request is
//! refused (the CA is not a web PKI root) and the error names the TLS cause; with the sink's
//! CA it is delivered; with another CA it is refused; the hostname check stays. Also: an S3
//! PUT with a session token sends and signs `x-amz-security-token`, and an S3 error answer's
//! `<Code>` (such as `ExpiredToken`) is in the error the sink logs.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use attenuo_audit::Checkpoint;
use attenuo_server::config::{SinkKind, SinkSection};
use attenuo_server::metrics::Metrics;
use attenuo_server::sink::{CheckpointSink, S3Credentials, SigV4Request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A certificate authority made for one test.
struct Ca {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

impl Ca {
    fn new(name: &str) -> Self {
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
        Self { cert, key }
    }

    fn write(&self, dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, self.cert.pem()).unwrap();
        path
    }

    fn leaf(&self, names: &[&str]) -> (rustls::pki_types::CertificateDer<'static>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let mut params = rcgen::CertificateParams::new(names).unwrap();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, &self.cert, &self.key).unwrap();
        (cert.der().clone(), key.serialize_der())
    }
}

/// One request as received: method, path, headers (names lowercased), body.
#[derive(Clone, Debug)]
struct Got {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Got {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// An HTTPS server on 127.0.0.1 with a certificate for `names` from `ca`. Every request is
/// answered with `answer` (status line and body) and kept. One request per connection.
struct TlsReceiver {
    port: u16,
    got: Arc<Mutex<Vec<Got>>>,
    handshakes_failed: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TlsReceiver {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TlsReceiver {
    async fn start(ca: &Ca, names: &[&str], answer: (&'static str, &'static str)) -> Self {
        let (cert, key) = ca.leaf(names);
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
        let got: Arc<Mutex<Vec<Got>>> = Arc::default();
        let handshakes_failed = Arc::new(AtomicUsize::new(0));
        let (g, f) = (got.clone(), handshakes_failed.clone());
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let (acceptor, g, f) = (acceptor.clone(), g.clone(), f.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        f.fetch_add(1, Ordering::SeqCst);
                        return;
                    };
                    let Some(req) = read_request(&mut tls).await else {
                        return;
                    };
                    g.lock().unwrap().push(req);
                    let (status, body) = answer;
                    let resp = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/xml\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Self {
            port,
            got,
            handshakes_failed,
            task,
        }
    }

    fn got(&self) -> Vec<Got> {
        self.got.lock().unwrap().clone()
    }
}

async fn read_request<S: AsyncReadExt + Unpin>(s: &mut S) -> Option<Got> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > 64 * 1024 {
            return None;
        }
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split_whitespace();
    let (method, path) = (first.next()?.to_owned(), first.next()?.to_owned());
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    Some(Got {
        method,
        path,
        headers,
        body,
    })
}

const OK: (&str, &str) = ("200 OK", "");

fn cp(seq: u64) -> Checkpoint {
    Checkpoint {
        seq,
        head_hash: format!("{seq:064x}"),
        at: "2026-11-14T00:00:00Z".into(),
        kid: "k1".into(),
        signature: "sig".into(),
    }
}

fn fast(mut s: SinkSection) -> SinkSection {
    s.initial_backoff_ms = 50;
    s.max_backoff_seconds = 1;
    s.timeout_seconds = 5;
    s
}

fn s3_section(endpoint: String, ca: Option<PathBuf>, token: Option<&str>) -> SinkSection {
    let mut s = fast(SinkSection::new(SinkKind::S3));
    s.endpoint = Some(endpoint);
    s.bucket = Some("audit-anchor".into());
    s.access_key_id = Some("AKIDTEST".into());
    s.secret_access_key = Some("secret/key".into());
    s.session_token = token.map(str::to_owned);
    s.ca_pem_path = ca;
    s
}

fn webhook_section(url: String, ca: Option<PathBuf>) -> SinkSection {
    let mut s = fast(SinkSection::new(SinkKind::Webhook));
    s.url = Some(url);
    s.ca_pem_path = ca;
    s
}

/// Start the sink, push one checkpoint, and wait until it is delivered or an attempt failed.
/// Returns the sink (so its state can be read) after that.
async fn push_one(cfg: &SinkSection) -> CheckpointSink {
    let sink = CheckpointSink::start(cfg, None, Metrics::new()).unwrap();
    sink.handle().push(&cp(2));
    for _ in 0..200 {
        if sink.handle().delivered() > 0 || sink.status().last_error.is_some() {
            return sink;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("neither delivered nor failed: {:?}", sink.status());
}

fn last_error(sink: &CheckpointSink) -> String {
    sink.status().last_error.unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_s3_store_behind_a_private_ca_needs_the_sinks_ca() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("attenuo test CA");
    let other = Ca::new("another CA");
    let ca_pem = ca.write(dir.path(), "ca.pem");
    let other_pem = other.write(dir.path(), "other.pem");
    let store = TlsReceiver::start(&ca, &["127.0.0.1"], OK).await;
    let endpoint = format!("https://127.0.0.1:{}", store.port);

    // Without the setting: the built-in roots do not hold the private CA.
    let sink = push_one(&s3_section(endpoint.clone(), None, None)).await;
    let e = last_error(&sink);
    assert_eq!(sink.handle().delivered(), 0);
    assert!(e.starts_with("request failed"), "{e}");
    assert!(e.contains("invalid peer certificate"), "{e}");
    assert!(e.contains("UnknownIssuer"), "{e}");
    assert!(store.got().is_empty());
    assert!(store.handshakes_failed.load(Ordering::SeqCst) >= 1);
    drop(sink);

    // With another CA: refused the same way.
    let sink = push_one(&s3_section(endpoint.clone(), Some(other_pem), None)).await;
    let e = last_error(&sink);
    assert_eq!(sink.handle().delivered(), 0, "{e}");
    assert!(e.contains("UnknownIssuer"), "{e}");
    drop(sink);

    // With the store's CA: delivered.
    let sink = push_one(&s3_section(endpoint, Some(ca_pem), None)).await;
    assert_eq!(sink.handle().delivered(), 1, "{:?}", sink.status());
    let got = store.got();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].method, "PUT");
    assert!(got[0]
        .path
        .starts_with("/audit-anchor/attenuo/checkpoints/"));
    assert_eq!(
        got[0].header("host"),
        Some(format!("127.0.0.1:{}", store.port).as_str())
    );
    assert_eq!(got[0].header("x-amz-security-token"), None);
}

/// The CA adds a root and nothing else: a certificate that does not name the host is still
/// refused, and the error says so.
#[tokio::test(flavor = "multi_thread")]
async fn the_hostname_check_stays() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("attenuo test CA");
    let ca_pem = ca.write(dir.path(), "ca.pem");
    let store = TlsReceiver::start(&ca, &["s3.internal.example"], OK).await;
    let sink = push_one(&s3_section(
        format!("https://127.0.0.1:{}", store.port),
        Some(ca_pem),
        None,
    ))
    .await;
    let e = last_error(&sink);
    assert_eq!(sink.handle().delivered(), 0, "{e}");
    assert!(
        e.contains("NotValidForName") || e.contains("not valid for name"),
        "{e}"
    );
}

/// With STS credentials the PUT carries `x-amz-security-token`, and it is one of the signed
/// headers: the signature recomputed over what arrived matches.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_token_is_sent_and_signed() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("attenuo test CA");
    let ca_pem = ca.write(dir.path(), "ca.pem");
    let store = TlsReceiver::start(&ca, &["127.0.0.1"], OK).await;
    let token = "FwoGZXIvYXdzE//session+token/with=chars";
    let sink = push_one(&s3_section(
        format!("https://127.0.0.1:{}", store.port),
        Some(ca_pem),
        Some(token),
    ))
    .await;
    assert_eq!(sink.handle().delivered(), 1, "{:?}", sink.status());
    let got = store.got().remove(0);
    assert_eq!(got.header("x-amz-security-token"), Some(token));
    let auth = got.header("authorization").unwrap().to_owned();
    assert!(
        auth.contains(
            "SignedHeaders=content-type;host;x-amz-checksum-sha256;x-amz-content-sha256;\
             x-amz-date;x-amz-sdk-checksum-algorithm;x-amz-security-token, "
        ),
        "{auth}"
    );
    let h = |n: &str| got.header(n).unwrap().to_owned();
    let signed: Vec<(String, String)> = [
        "content-type",
        "host",
        "x-amz-checksum-sha256",
        "x-amz-content-sha256",
        "x-amz-date",
        "x-amz-sdk-checksum-algorithm",
        "x-amz-security-token",
    ]
    .iter()
    .map(|n| (n.to_string(), h(n)))
    .collect();
    let creds = S3Credentials {
        access_key_id: "AKIDTEST".into(),
        secret_access_key: "secret/key".into(),
        session_token: Some(token.into()),
    };
    let payload = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&got.body));
    let expected = attenuo_server::sink::sigv4_authorization(&SigV4Request {
        method: "PUT",
        canonical_uri: &got.path,
        canonical_query: "",
        headers: &signed,
        payload_sha256: &payload,
        region: "us-east-1",
        service: "s3",
        amz_date: &h("x-amz-date"),
        creds: &creds,
    });
    assert_eq!(auth, expected);
}

/// A refused PUT names S3's error code, so an expired session token (`ExpiredToken`) can be
/// told from a wrong secret (`SignatureDoesNotMatch`); both are 403.
#[tokio::test(flavor = "multi_thread")]
async fn an_s3_refusal_names_the_error_code() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("attenuo test CA");
    let ca_pem = ca.write(dir.path(), "ca.pem");
    let store = TlsReceiver::start(
        &ca,
        &["127.0.0.1"],
        (
            "403 Forbidden",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>ExpiredToken</Code>\
             <Message>The provided token has expired.</Message></Error>",
        ),
    )
    .await;
    let sink = push_one(&s3_section(
        format!("https://127.0.0.1:{}", store.port),
        Some(ca_pem),
        Some("expired-token"),
    ))
    .await;
    assert_eq!(
        last_error(&sink),
        "S3 answered 403 Forbidden (ExpiredToken)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_webhook_behind_a_private_ca_needs_the_sinks_ca() {
    let dir = tempfile::tempdir().unwrap();
    let ca = Ca::new("attenuo test CA");
    let ca_pem = ca.write(dir.path(), "ca.pem");
    let rx = TlsReceiver::start(&ca, &["127.0.0.1"], OK).await;
    let url = format!("https://127.0.0.1:{}/hook", rx.port);
    let sink = push_one(&webhook_section(url.clone(), None)).await;
    let e = last_error(&sink);
    assert!(e.contains("UnknownIssuer"), "{e}");
    drop(sink);
    let sink = push_one(&webhook_section(url, Some(ca_pem))).await;
    assert_eq!(sink.handle().delivered(), 1, "{:?}", sink.status());
    assert_eq!(rx.got()[0].method, "POST");
    assert_eq!(rx.got()[0].path, "/hook");
}

/// A file that is missing, empty, holds no certificate, or a certificate that does not parse
/// refuses to start, naming the key and the path. A file sink does not take the key.
#[test]
fn a_bad_ca_file_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, text: &str| {
        let p = dir.path().join(name);
        std::fs::write(&p, text).unwrap();
        p
    };
    let key_only = rcgen::KeyPair::generate().unwrap().serialize_pem();
    let cases = [
        (dir.path().join("missing.pem"), "cannot read the file"),
        (write("empty.pem", "\n"), "empty"),
        (write("key.pem", &key_only), "no PEM certificate"),
        (
            write(
                "garbage.pem",
                "-----BEGIN CERTIFICATE-----\nAAECAwQFBgcICQ==\n-----END CERTIFICATE-----\n",
            ),
            "trust anchor",
        ),
    ];
    for (path, want) in cases {
        for cfg in [
            s3_section("https://s3.example".into(), Some(path.clone()), None),
            webhook_section("https://anchor.example/hook".into(), Some(path.clone())),
        ] {
            let err =
                CheckpointSink::start(&cfg, None, Metrics::new()).expect_err("must not start");
            let msg = format!("{err:#}");
            assert!(msg.contains("[audit.sink] ca_pem_path"), "{msg}");
            assert!(msg.contains(&path.display().to_string()), "{msg}");
            assert!(msg.contains(want), "{want}: {msg}");
        }
    }
    let mut file = SinkSection::new(SinkKind::File);
    file.path = Some(dir.path().join("cp.jsonl"));
    file.ca_pem_path = Some(dir.path().join("ca.pem"));
    let e = file.validate().unwrap_err().to_string();
    assert!(e.contains("does not use ca_pem_path"), "{e}");
}

#[test]
fn ca_pem_path_parses_from_toml() {
    let cfg = attenuo_server::Config::from_toml(
        r#"
[audit.sink]
kind = "s3"
endpoint = "https://minio.internal:9000"
bucket = "attenuo-checkpoints"
ca_pem_path = "/etc/attenuo/s3-ca.pem"
"#,
    )
    .unwrap();
    assert_eq!(
        cfg.audit.sink.unwrap().ca_pem_path.as_deref(),
        Some(Path::new("/etc/attenuo/s3-ca.pem"))
    );
}
