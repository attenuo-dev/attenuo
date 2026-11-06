//! `Connection: close` on an HTTP/1 answer sent before the request body was read to its end.
//!
//! Many refusals are decided on the headers alone: the proxy authenticates before it reads the
//! body (so an anonymous caller cannot make it buffer), and refuses a declared length over
//! `max_request_body_bytes` without reading it; the admin routes and the console refuse a
//! missing bearer or content type the same way. Hyper then closes the connection, since the
//! unread rest of the body would be read as the next request, but the answer did not say so,
//! and a client that reused the connection at once (the retry after 401 `use_dpop_nonce`)
//! got no answer (board item 63). [`mark_early_refusal`] wraps the request body to see
//! whether it was read to its end, and if not adds `Connection: close` to the answer, which
//! makes every HTTP/1.1 client open a new connection for its next request.
//!
//! Why not read the rest of the body instead, up to the body limit, and keep the connection:
//! that is what the proxy avoids on purpose, an unauthenticated caller could make the server
//! read 4 MiB for every refusal, and the connection is only worth keeping for the one retry.
//! The header is not set on HTTP/2, where it is not allowed and an unread stream is reset on
//! its own.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::{header, HeaderValue, Version};
use axum::middleware::Next;
use axum::response::Response;
use http_body::{Body as _, Frame, SizeHint};

/// Middleware: add `Connection: close` to the answer of an HTTP/1 request whose body had not
/// been read to its end when the answer was ready (see the module docs).
pub(crate) async fn mark_early_refusal(req: Request, next: Next) -> Response {
    if req.version() > Version::HTTP_11 {
        return next.run(req).await;
    }
    let (parts, body) = req.into_parts();
    let ended = Arc::new(AtomicBool::new(body.is_end_stream()));
    let body = Body::new(Tracked {
        inner: body,
        ended: ended.clone(),
    });
    let mut resp = next.run(Request::from_parts(parts, body)).await;
    if !ended.load(Ordering::Acquire) {
        resp.headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    resp
}

/// A request body that records when it has been read to its end.
struct Tracked {
    inner: Body,
    ended: Arc<AtomicBool>,
}

impl http_body::Body for Tracked {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(None) => self.ended.store(true, Ordering::Release),
            Poll::Ready(Some(Ok(_))) if self.inner.is_end_stream() => {
                self.ended.store(true, Ordering::Release)
            }
            _ => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
