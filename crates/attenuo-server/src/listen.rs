//! The server's accept loop: `axum::serve` with a header-read timeout and the peer address.
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
//! Shutdown is `axum::serve`'s: once `shutdown` resolves the listener is dropped, every
//! connection is told to finish its request in progress and close, and the returned future
//! resolves when the last connection task has ended.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use tower::ServiceExt as _;

/// Serve `app` on `listener` until `shutdown` resolves, then drain as `axum::serve`'s graceful
/// shutdown does. Returns once every connection has ended.
pub(crate) async fn serve(
    listener: tokio::net::TcpListener,
    app: Router,
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
        let service = PeerService {
            app: app.clone(),
            peer,
        };
        let mut stop = stop_rx.clone();
        let live = live_rx.clone();
        tokio::spawn(async move {
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
            drop(live);
        });
    }
    drop(listener);
    drop(stop_tx);
    drop(live_rx);
    live_tx.closed().await;
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

/// The router as a hyper service of one connection, adding the peer address to each request.
#[derive(Clone)]
struct PeerService {
    app: Router,
    peer: SocketAddr,
}

impl hyper::service::Service<hyper::Request<Incoming>> for PeerService {
    type Response = axum::response::Response;
    type Error = Infallible;
    type Future = tower::util::Oneshot<Router, axum::extract::Request>;

    fn call(&self, req: hyper::Request<Incoming>) -> Self::Future {
        let mut req = req.map(axum::body::Body::new);
        req.extensions_mut().insert(ConnectInfo(self.peer));
        self.app.clone().oneshot(req)
    }
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
        let task = tokio::spawn(serve(listener, app, header_read_timeout, async move {
            let _ = rx.await;
        }));
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
