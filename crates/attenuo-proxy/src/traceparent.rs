//! W3C Trace Context for the OpenTelemetry export (`docs/design/otel-export.md`, section 4).
//!
//! The proxy has no OpenTelemetry dependency. It opens `tracing` spans in the
//! [`OTEL_TARGET`] target, parses an inbound `traceparent` header into a [`TraceParent`], and
//! hands both to the [`TraceHook`] its authorizer returns ([`crate::Authorizer::trace`]). The
//! server, which owns the subscriber and the exporter, turns the value into the span's parent
//! or a span link, and gives back the `traceparent` the proxy inserts on the upstream request.
//! With no hook (tracing off, or the proxy used on its own) nothing is parsed and nothing is
//! inserted upstream, so behaviour is as before.
//!
//! Spans in [`OTEL_TARGET`] are the only ones an exporter sees, and they are built with the
//! fields of the design's allow-list only (section 3.3): no token, subject, argument, result
//! or URL. Every other span and event keeps feeding the log and never reaches the exporter.

use axum::http::HeaderMap;

/// The `tracing` target of every span the OpenTelemetry exporter may send. The server's
/// subscriber routes this target to the exporter only, and every other target to the log only.
pub const OTEL_TARGET: &str = "attenuo::otel";

/// A count or sequence number as an exported span attribute. `tracing` hands a `u64` field to
/// the OpenTelemetry layer as a debug string, so an attribute recorded from a `u64` or `usize`
/// reached a collector as `"42"`; recorded as an `i64` it is an OTLP integer, which is what
/// `http.response.status_code` is in the semantic conventions and what a backend compares.
/// Saturates at `i64::MAX`, which no sequence number or chain depth reaches.
pub fn otel_int(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// The W3C Trace Context request header.
pub const TRACEPARENT_HEADER: &str = "traceparent";

/// One parsed `traceparent` value: version `00`, a trace id and a parent span id that are not
/// all zeros, and the trace flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceParent {
    /// The 16-byte trace id.
    pub trace_id: [u8; 16],
    /// The 8-byte id of the caller's span (the parent).
    pub parent_id: [u8; 8],
    /// Trace flags; bit 0 is `sampled`.
    pub flags: u8,
}

impl TraceParent {
    /// Parse one header value. Only version `00` in its exact form is accepted: 55 characters,
    /// lowercase hex, dashes in place, a trace id and a parent id that are not all zeros.
    /// Anything else is `None`, which the caller treats as no header at all: a malformed
    /// `traceparent` starts a new trace and is never a refusal.
    pub fn parse(value: &str) -> Option<Self> {
        let b = value.as_bytes();
        if b.len() != 55 || &b[..3] != b"00-" || b[35] != b'-' || b[52] != b'-' {
            return None;
        }
        let mut trace_id = [0u8; 16];
        let mut parent_id = [0u8; 8];
        let mut flags = [0u8; 1];
        lower_hex(&b[3..35], &mut trace_id)?;
        lower_hex(&b[36..52], &mut parent_id)?;
        lower_hex(&b[53..55], &mut flags)?;
        if trace_id == [0; 16] || parent_id == [0; 8] {
            return None;
        }
        Some(Self {
            trace_id,
            parent_id,
            flags: flags[0],
        })
    }

    /// The request's `traceparent`: exactly one header whose value [`parse`](Self::parse)s. A
    /// missing, repeated, non-ASCII or malformed header is `None`.
    pub fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let mut values = headers.get_all(TRACEPARENT_HEADER).iter();
        let first = values.next()?;
        if values.next().is_some() {
            return None;
        }
        Self::parse(first.to_str().ok()?)
    }

    /// Whether the caller sampled its span (flag bit 0).
    pub fn sampled(&self) -> bool {
        self.flags & 0x01 == 0x01
    }

    /// The header value, `00-{trace_id}-{parent_id}-{flags}`.
    pub fn to_header(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            hex::encode(self.trace_id),
            hex::encode(self.parent_id),
            self.flags
        )
    }
}

/// Decode lowercase hex into `out`; uppercase and anything else is `None` (Trace Context
/// section 3.2.2 allows lowercase only).
fn lower_hex(src: &[u8], out: &mut [u8]) -> Option<()> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    if src.len() != out.len() * 2 {
        return None;
    }
    for (i, pair) in src.as_chunks::<2>().0.iter().enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(())
}

/// How spans in [`OTEL_TARGET`] are joined to traces outside the process. The server
/// implements it over its tracer; the proxy calls it at the points the design names.
pub trait TraceHook: Send + Sync + std::fmt::Debug {
    /// Called once for an entry-point span (`mcp.request`), after it is created and before it
    /// is first entered, with the request's parsed `traceparent`. The hook makes `inbound`
    /// the span's parent, links the span to it, or ignores it, as configured.
    fn inbound(&self, span: &tracing::Span, inbound: Option<TraceParent>);

    /// The context of the innermost exported span entered on this thread, to link to later:
    /// a result recorded after the response, or the end of a stream the request opened.
    /// `None` when no exported span is entered.
    fn current(&self) -> Option<TraceParent>;

    /// The `traceparent` to insert on the upstream request sent inside `span` (the
    /// `attenuo.upstream` span), or `None` to insert nothing. The value names attenuo's span,
    /// never the client's header (SR-27).
    fn outbound(&self, span: &tracing::Span) -> Option<TraceParent>;

    /// Give `span`, created outside any exported span (a result recorded on a stream after the
    /// request returned), a link to `origin`. Does nothing when an exported span is entered on
    /// this thread, so a span that already has a parent in the same trace gets no link.
    fn link_detached(&self, span: &tracing::Span, origin: TraceParent);
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    #[test]
    fn parses_the_spec_example_and_round_trips() {
        let tp = TraceParent::parse(GOOD).unwrap();
        assert!(tp.sampled());
        assert_eq!(tp.to_header(), GOOD);
        assert_eq!(hex::encode(tp.trace_id), "4bf92f3577b34da6a3ce929d0e0e4736");
    }

    #[test]
    fn malformed_values_are_none() {
        for bad in [
            "",
            "garbage",
            // wrong version, uppercase, zero ids, wrong length, wrong separators
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-1",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
            "00_4bf92f3577b34da6a3ce929d0e0e4736_00f067aa0ba902b7_01",
            "00-4bf92f3577b34da6a3ce929d0e0e473g-00f067aa0ba902b7-01",
        ] {
            assert_eq!(TraceParent::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_repeated_header_is_none() {
        let mut h = HeaderMap::new();
        assert_eq!(TraceParent::from_headers(&h), None);
        h.append(TRACEPARENT_HEADER, GOOD.parse().unwrap());
        assert!(TraceParent::from_headers(&h).is_some());
        h.append(TRACEPARENT_HEADER, GOOD.parse().unwrap());
        assert_eq!(TraceParent::from_headers(&h), None);
    }
}
