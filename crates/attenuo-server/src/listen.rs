//! The server's accept loop: `axum::serve` with a header-read timeout, the peer address and,
//! on the main listener with `[server.tls]`, TLS.
//!
//! `axum::serve` gives hyper no timer, so hyper's header-read timeout never runs and a client
//! can hold a connection (and a task) open forever by sending a request's headers one byte at
//! a time, or by never sending a second request (audit finding S-4). This loop serves each
//! connection with hyper's HTTP/1 server, a tokio timer and `[limits]
//! header_read_timeout_seconds`, which bounds both the wait for a request's headers and the
//! idle time of a kept-alive connection. Each request carries the peer address as
//! [`axum::extract::ConnectInfo`], which the `POST /token` peer limit reads
//! ([`crate::limits`]).
//!
//! With a [`TlsAcceptor`] ([`crate::tls`]), each connection first makes its TLS handshake, in
//! the connection's own task (never in the accept loop, so a slow handshake does not hold up
//! the others) and within the same header-read timeout: a peer that connects and sends
//! nothing, or half a handshake, is dropped when it runs out. The request headers then get the
//! timeout again, as on a plain connection. With `[server.tls] client_certificates =
//! "optional"`, the certificate the client proved in the handshake goes into each request of
//! the connection as a [`ClientCertificate`]; nothing else ever sets it. A failed handshake (a
//! plain-HTTP request, an old TLS version, a client that does not trust the certificate) closes
//! the connection and the listener goes on. It is counted in `tls_handshake_failures_total` by
//! a reason from a fixed set ([`crate::metrics::HandshakeFailure`]), and logged at debug at
//! most once per 10 seconds, with the number of failures not logged since: a flood of failed
//! handshakes adds neither series nor log lines without bound.
//!
//! Each connection takes one snapshot of the TLS configuration in force
//! ([`crate::tls::ServerTls::current`]) before its handshake, so a `POST /admin/tls/reload`
//! that swaps it meanwhile changes nothing for that connection: it uses the old configuration
//! or the new one, whole. No lock is held across an `await`.
//!
//! With [`Transport::Forwarded`] (`[server.forwarded_client_cert]`) the connection is plain
//! HTTP and its TCP peer address must be in `trusted_peers`: any other peer gets `403
//! forwarded_peer_not_trusted` for every request it sends, without routing, and the
//! connection is closed. Requests of a trusted peer carry [`ServedForwarded`], which is what
//! lets [`crate::forwarded::headers`] read the `Client-Cert` headers; no other loop sets it.
//! Such a connection never speaks TLS, so it never has a handshake certificate.
//!
//! Shutdown is `axum::serve`'s: once `shutdown` resolves the listener is dropped, every
//! connection is told to finish its request in progress and close, and the returned future
//! resolves when the last connection task has ended. A connection still in its handshake is
//! dropped at once: it has no request in progress.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::response::IntoResponse as _;
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt as _;

use crate::client_cert::ClientCertificate;
use crate::forwarded::TrustedPeers;
use crate::metrics::{HandshakeFailure, Metrics};
use crate::tls::ServerTls;

/// For the debug line of a failed handshake: at most one per 10 seconds.
static HANDSHAKE_FAILED: crate::forwarded::Throttle = crate::forwarded::Throttle::new();

/// What a listener speaks, and where a request's client certificate may come from.
#[derive(Clone)]
pub(crate) enum Transport {
    /// Plain HTTP; no client certificate.
    Plain,
    /// TLS ([`crate::tls`]) with the configuration in force when each connection is
    /// accepted; the certificate of the handshake, if any. Failed handshakes are counted in
    /// the metrics.
    Tls(std::sync::Arc<ServerTls>, std::sync::Arc<Metrics>),
    /// Plain HTTP from the peers listed only; the certificate from the `Client-Cert` headers
    /// ([`crate::forwarded`]).
    Forwarded(std::sync::Arc<TrustedPeers>),
}

impl Transport {
    /// Whether connections speak TLS.
    pub(crate) fn is_tls(&self) -> bool {
        matches!(self, Transport::Tls(..))
    }
}

/// Serve `app` on `listener` until `shutdown` resolves, then drain as `axum::serve`'s graceful
/// shutdown does. Returns once every connection has ended. Every connection speaks as
/// `transport` says.
pub(crate) async fn serve(
    listener: tokio::net::TcpListener,
    app: Router,
    transport: Transport,
    header_read_timeout: Duration,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) {
    // Dropped (and so seen as closed by every connection) when the loop stops accepting.
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(());
    // One receiver per live connection: `closed` resolves when the last one is gone.
    let (live_tx, live_rx) = tokio::sync::watch::channel(());
    tokio::pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(e) => {
                    accept_error(e).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let app = app.clone();
        let transport = transport.clone();
        let mut stop = stop_rx.clone();
        let live = live_rx.clone();
        tokio::spawn(async move {
            // Facts about the connection that each request carries go into `PeerService`:
            // the peer address, whether the connection is TLS or from a trusted forwarding
            // proxy, and the client certificate the TLS handshake proved (taken from the
            // stream below, once the handshake is done).
            let mut service = PeerService {
                app,
                peer,
                tls: transport.is_tls(),
                forwarded: false,
                untrusted: false,
                client_cert: None,
            };
            match transport {
                Transport::Plain => {
                    serve_connection(stream, service, header_read_timeout, &mut stop).await
                }
                Transport::Forwarded(peers) => {
                    // The TCP peer, never a header: `X-Forwarded-For` and the like play no part.
                    if peers.contains(peer.ip()) {
                        service.forwarded = true;
                    } else {
                        match crate::forwarded::UNTRUSTED.warn() {
                            Some(suppressed) => tracing::warn!(
                                %peer,
                                suppressed,
                                "a peer that is not in [server.forwarded_client_cert] \
                                 trusted_peers connected to the forwarding listener; its \
                                 requests are refused with 403"
                            ),
                            None => tracing::debug!(
                                %peer,
                                "untrusted peer on the forwarding listener; refused"
                            ),
                        }
                        service.untrusted = true;
                    }
                    serve_connection(stream, service, header_read_timeout, &mut stop).await
                }
                Transport::Tls(tls, metrics) => {
                    // One snapshot for the whole handshake: a reload after this line does not
                    // change it.
                    let acceptor = TlsAcceptor::from(tls.current().config.clone());
                    drop(tls);
                    let handshake =
                        tokio::time::timeout(header_read_timeout, acceptor.accept(stream));
                    let stream = tokio::select! {
                        res = handshake => match res {
                            Ok(Ok(stream)) => stream,
                            Ok(Err(e)) => {
                                handshake_failed(
                                    &metrics,
                                    peer,
                                    crate::tls::handshake_failure(&e),
                                    Some(&e),
                                );
                                return;
                            }
                            Err(_) => {
                                handshake_failed(&metrics, peer, HandshakeFailure::Timeout, None);
                                return;
                            }
                        },
                        // Shutting down: a connection still in its handshake has no request
                        // to finish.
                        _ = stop.changed() => return,
                    };
                    // The end-entity certificate, when the client sent one: its handshake
                    // signature verified (`crate::client_cert_verifier`). The certificates
                    // the client sent after it are kept as intermediates (bounded,
                    // `crate::client_cert::MAX_INTERMEDIATES`) for the CA check of
                    // `tls_client_auth`. Only this loop sets it; the requests of this
                    // connection all carry it.
                    service.client_cert = stream
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(ClientCertificate::from_handshake);
                    serve_connection(stream, service, header_read_timeout, &mut stop).await;
                }
            }
            drop(live);
        });
    }
    drop(listener);
    drop(stop_tx);
    drop(live_rx);
    live_tx.closed().await;
}

/// Count a failed handshake, and log it at debug unless one was logged in the last 10 seconds.
fn handshake_failed(
    metrics: &Metrics,
    peer: SocketAddr,
    reason: HandshakeFailure,
    error: Option<&std::io::Error>,
) {
    metrics.tls_handshake_failed(reason);
    if let Some(suppressed) = HANDSHAKE_FAILED.warn() {
        match error {
            Some(e) => tracing::debug!(
                %peer,
                reason = reason.label(),
                error = %e,
                suppressed,
                "TLS handshake failed (suppressed: failures not logged since the last line)"
            ),
            None => tracing::debug!(
                %peer,
                reason = reason.label(),
                suppressed,
                "TLS handshake not done within the header-read timeout (suppressed: failures \
                 not logged since the last line)"
            ),
        }
    }
}

/// Serve one connection with hyper's HTTP/1 server until it ends; once `stop` changes (or its
/// sender is dropped), finish the request in progress and close.
async fn serve_connection<S>(
    stream: S,
    service: PeerService,
    header_read_timeout: Duration,
    stop: &mut tokio::sync::watch::Receiver<()>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout);
    let conn = builder
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();
    tokio::pin!(conn);
    let mut stopping = false;
    loop {
        tokio::select! {
            res = conn.as_mut() => {
                if let Err(e) = res {
                    tracing::trace!(error = %e, "connection ended with an error");
                }
                break;
            }
            _ = stop.changed(), if !stopping => {
                stopping = true;
                conn.as_mut().graceful_shutdown();
            }
        }
    }
}

/// What `axum::serve` does with a failed accept: a per-connection error is skipped, anything
/// else (out of file descriptors) is logged and retried after a second, so the loop does not
/// spin.
async fn accept_error(e: std::io::Error) {
    use std::io::ErrorKind as K;
    if matches!(
        e.kind(),
        K::ConnectionRefused | K::ConnectionAborted | K::ConnectionReset
    ) {
        return;
    }
    tracing::error!(error = %e, "accept failed; retrying in 1 s");
    tokio::time::sleep(Duration::from_secs(1)).await;
}

/// Put into each request that came over a TLS connection of this accept loop. A router built
/// over a state with `[server.tls]` refuses requests without it ([`require_tls`]), so that it
/// is never served as plain HTTP by a loop that does not speak TLS.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ServedOverTls;

/// Put into each request that came, over a connection of this accept loop, from a peer in
/// `[server.forwarded_client_cert] trusted_peers` to the forwarding listener. Only then are
/// the `Client-Cert` headers read ([`crate::forwarded::headers`]). [`require_tls`] takes it in
/// place of [`ServedOverTls`]: the proxy ended the client's TLS, by the operator's
/// declaration. Only [`serve`] with [`Transport::Forwarded`] sets it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ServedForwarded;

/// The router as a hyper service of one connection, adding the peer address (and, on a TLS
/// connection, [`ServedOverTls`] and the client certificate, if any; on a trusted forwarding
/// connection, [`ServedForwarded`]) to each request.
#[derive(Clone)]
struct PeerService {
    app: Router,
    peer: SocketAddr,
    tls: bool,
    /// From a trusted peer of the forwarding listener.
    forwarded: bool,
    /// From a peer of the forwarding listener that is not trusted: every request is refused
    /// without routing.
    untrusted: bool,
    /// The certificate the client proved in the TLS handshake ([`ClientCertificate`]).
    client_cert: Option<ClientCertificate>,
}

impl hyper::service::Service<hyper::Request<Incoming>> for PeerService {
    type Response = axum::response::Response;
    type Error = Infallible;
    type Future = futures_util::future::Either<
        std::future::Ready<Result<axum::response::Response, Infallible>>,
        tower::util::Oneshot<Router, axum::extract::Request>,
    >;

    fn call(&self, req: hyper::Request<Incoming>) -> Self::Future {
        if self.untrusted {
            // The body is not read; the connection closes after this answer.
            return futures_util::future::Either::Left(std::future::ready(Ok(
                crate::forwarded::untrusted_peer(),
            )));
        }
        let mut req = req.map(axum::body::Body::new);
        req.extensions_mut().insert(ConnectInfo(self.peer));
        if self.tls {
            req.extensions_mut().insert(ServedOverTls);
        }
        if self.forwarded {
            req.extensions_mut().insert(ServedForwarded);
        }
        // Set by this loop only: a request off the wire has no extensions of its own.
        if let Some(cert) = &self.client_cert {
            req.extensions_mut().insert(cert.clone());
        }
        futures_util::future::Either::Right(self.app.clone().oneshot(req))
    }
}

/// Middleware of the main router when `[server.tls]` is set: a request that did not come over
/// a TLS connection of [`serve`] (or from a trusted peer of the forwarding listener,
/// [`ServedForwarded`]) is answered `500` with an empty body and logged as an error.
/// This catches a router served by something other than [`crate::run`] (such as
/// [`crate::serve_until`], which never speaks TLS) while discovery and DPoP name `https://`
/// URLs: fail closed rather than take tokens in cleartext.
pub(crate) async fn require_tls(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if req.extensions().get::<ServedOverTls>().is_some()
        || req.extensions().get::<ServedForwarded>().is_some()
    {
        return next.run(req).await;
    }
    // An error once per process, so a misconfigured embedder does not flood the log; every
    // later refusal at debug.
    static LOGGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if LOGGED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::debug!("a request reached the main router without TLS; refused with 500");
    } else {
        tracing::error!(
            "a request reached the main router without TLS although [server.tls] is set; \
             serve the router with attenuo_server::run or serve, not serve_until or another \
             server. Every such request is refused with 500 (logged at debug from now on)"
        );
    }
    axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn start(
        header_read_timeout: Duration,
    ) -> (
        SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let app = Router::new().route(
            "/peer",
            get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.ip().to_string() }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(serve(
            listener,
            app,
            Transport::Plain,
            header_read_timeout,
            async move {
                let _ = rx.await;
            },
        ));
        (addr, tx, task)
    }

    /// Every request carries the peer address.
    #[tokio::test]
    async fn requests_carry_the_peer_address() {
        let (addr, stop, task) = start(Duration::from_secs(5)).await;
        let body = reqwest::get(format!("http://{addr}/peer"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "127.0.0.1");
        stop.send(()).unwrap();
        task.await.unwrap();
    }

    /// A client that sends part of its headers and then nothing is cut off at the header-read
    /// timeout; one that sends them in time is answered.
    #[tokio::test]
    async fn a_slow_header_is_cut_off() {
        let (addr, stop, task) = start(Duration::from_millis(300)).await;
        let mut slow = tokio::net::TcpStream::connect(addr).await.unwrap();
        slow.write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\n")
            .await
            .unwrap();
        let started = std::time::Instant::now();
        let mut buf = Vec::new();
        // The server closes the connection (possibly after a 408); the read ends.
        let read = tokio::time::timeout(Duration::from_secs(5), slow.read_to_end(&mut buf)).await;
        assert!(read.is_ok(), "the connection was not closed");
        assert!(started.elapsed() >= Duration::from_millis(250));
        assert!(!String::from_utf8_lossy(&buf).contains("127.0.0.1"));

        let mut quick = tokio::net::TcpStream::connect(addr).await.unwrap();
        quick
            .write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        quick.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        stop.send(()).unwrap();
        task.await.unwrap();
    }

    /// An idle kept-alive connection is closed at the header-read timeout too.
    #[tokio::test]
    async fn an_idle_keep_alive_connection_is_closed() {
        let (addr, stop, task) = start(Duration::from_millis(300)).await;
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        conn.write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(5), conn.read_to_end(&mut buf)).await;
        assert!(read.is_ok(), "the idle connection was not closed");
        assert!(String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 200"));
        stop.send(()).unwrap();
        task.await.unwrap();
    }
}
