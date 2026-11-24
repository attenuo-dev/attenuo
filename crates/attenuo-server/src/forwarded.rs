//! `[server.forwarded_client_cert]`: TLS client certificates that a trusted reverse proxy
//! forwards in the RFC 9440 headers `Client-Cert` and `Client-Cert-Chain`
//! ([ADR-0021](../../docs/decisions/0021-forwarded-client-certificates.md)).
//!
//! The proxy ends TLS, checks the client's handshake, and sends the client's certificate to a
//! listener of its own. attenuo does not see the handshake, so it trusts the proxy for proof
//! of possession. Anyone who can send these headers to that listener can claim any
//! certificate, so the headers are fenced:
//!
//! 1. They are read only on the forwarding listener (`listen`), which [`crate::run`] serves
//!    with [`crate::listen::Transport::Forwarded`]. Only that accept loop marks a request
//!    [`ServedForwarded`]; a request off the wire has no extensions.
//! 2. That listener takes connections from `trusted_peers` only: the TCP peer address, never a
//!    header. Any other peer gets a fixed `403 forwarded_peer_not_trusted` for every request,
//!    before routing, and the connection is closed.
//! 3. With the section set, a request that carries either header on any other listener (the
//!    main listener, `[admin] listen`, the console, the metrics listener) is refused with
//!    `400 client_cert_header_not_accepted` and logged ([`headers`]). Without the section this
//!    module is not mounted and the headers are ignored, as before.
//! 4. The forwarding listener never speaks TLS and never takes a handshake certificate; the
//!    TLS listener never reads the headers. Each request has one possible source.
//! 5. The headers are parsed strictly ([`parse`]): one `Client-Cert` line holding one RFC 8941
//!    Byte Sequence with no parameters, an optional `Client-Cert-Chain` line holding a List of
//!    at most [`MAX_INTERMEDIATES`] such items, canonical base64, size caps, and DER that
//!    rustls-webpki can read. Anything else is `400 client_cert_header_malformed`, with a
//!    fixed text that never echoes the header.
//! 6. The certificate becomes the [`ClientCertificate`] the handshake path makes, marked
//!    [`CertSource::Forwarded`](crate::client_cert::CertSource::Forwarded), and goes
//!    through the same client authentication ([`crate::clientauth`]). It is made anew for every request. The CA check's answers
//!    ([`crate::client_pki::PerConnection`]) are shared only by requests that forward the
//!    same certificate and the same intermediates ([`crate::client_pki::SharedStates`]),
//!    never by two certificates a proxy sends on one kept-alive connection.
//! 7. Only the routes in [`SERVED_ROUTES`] answer there ([`only_served_routes`]).
//!
//! The listener and `trusted_peers` are read at start only; a reload does not change them.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse as _;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rustls::pki_types::CertificateDer;

use crate::client_cert::{ClientCertificate, MAX_INTERMEDIATES};
use crate::config::Config;
use crate::error::ApiError;
use crate::listen::ServedForwarded;

/// The leaf certificate header (RFC 9440 §2.2), lowercase as `http` stores names.
pub(crate) const CLIENT_CERT: &str = "client-cert";
/// The chain header (RFC 9440 §2.3).
pub(crate) const CLIENT_CERT_CHAIN: &str = "client-cert-chain";

/// Most DER bytes of one forwarded certificate. A client certificate is rarely over 2 KiB; a
/// certificate with many names may be larger.
pub(crate) const MAX_CERT_DER_BYTES: usize = 16 * 1024;
/// Most DER bytes of the leaf and the chain together: rustls' bound for the whole certificate
/// message of a handshake, so a forwarded chain is never larger than a native one.
pub(crate) const MAX_TOTAL_DER_BYTES: usize = 64 * 1024;
/// Most characters of one Byte Sequence item: the base64 of [`MAX_CERT_DER_BYTES`] and its
/// two colons.
const MAX_ITEM_CHARS: usize = MAX_CERT_DER_BYTES.div_ceil(3) * 4 + 2;
/// Most bytes of a `Client-Cert` value: one item and some spaces.
const MAX_LEAF_VALUE_BYTES: usize = MAX_ITEM_CHARS + 16;
/// Most bytes of a `Client-Cert-Chain` value: [`MAX_INTERMEDIATES`] items, their separators
/// and some spaces.
const MAX_CHAIN_VALUE_BYTES: usize = MAX_INTERMEDIATES * (MAX_ITEM_CHARS + 4) + 16;
/// Most entries of `trusted_peers`.
pub(crate) const MAX_TRUSTED_PEERS: usize = 64;
/// The widest IPv4 network `trusted_peers` may name: `/8`.
const MIN_PREFIX_V4: u8 = 8;
/// The widest IPv6 network `trusted_peers` may name: `/32`, the size of a large provider's
/// whole allocation. A proxy's addresses fit in far less.
const MIN_PREFIX_V6: u8 = 32;

/// The `detail` of `400 client_cert_header_malformed`. Fixed: the header is never echoed.
pub(crate) const MALFORMED_DETAIL: &str = "the Client-Cert or Client-Cert-Chain header is not a \
     well-formed RFC 9440 certificate header";
/// The `detail` of `400 client_cert_header_not_accepted`.
pub(crate) const NOT_ACCEPTED_DETAIL: &str = "this listener does not take Client-Cert or \
     Client-Cert-Chain headers; they are read only on the [server.forwarded_client_cert] listener";
/// The `detail` of `403 forwarded_peer_not_trusted`.
pub(crate) const UNTRUSTED_PEER_DETAIL: &str = "this listener takes requests only from the \
     addresses in [server.forwarded_client_cert] trusted_peers";

/// One `trusted_peers` entry: an address and a prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Net {
    addr: IpAddr,
    prefix: u8,
}

impl Net {
    /// Read `a.b.c.d`, `a.b.c.d/n`, an IPv6 address, or an IPv6 address with `/n`. Refused:
    /// anything else (a zone such as `%eth0` too), a prefix longer than the address, a prefix
    /// with a sign or a leading zero, a prefix shorter than [`MIN_PREFIX_V4`] or
    /// [`MIN_PREFIX_V6`] (so `/0`), bits set after the prefix, the unspecified address
    /// (`0.0.0.0`, `::`) or a network that starts at it, an IPv4-mapped IPv6 address (write it
    /// as IPv4), and an IPv6 link-local address (`fe80::/10`: the peer's zone is not compared,
    /// so the entry would match that address on every interface).
    pub(crate) fn parse(s: &str) -> Result<Self, String> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| "is not an IP address or a CIDR (such as 10.0.0.0/24)".to_owned())?;
        let bits = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => bits,
            Some(p) => {
                let digits = !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
                if !digits || (p.len() > 1 && p.starts_with('0')) {
                    return Err("has a prefix length that is not a plain number".into());
                }
                match p.parse::<u8>() {
                    Ok(n) if n <= bits => n,
                    _ => return Err(format!("has a prefix length over {bits}")),
                }
            }
        };
        let min = if addr.is_ipv4() {
            MIN_PREFIX_V4
        } else {
            MIN_PREFIX_V6
        };
        if prefix < min {
            return Err(format!(
                "is wider than /{min} (the widest {} network allowed): name the proxy's own \
                 addresses",
                if addr.is_ipv4() { "IPv4" } else { "IPv6" }
            ));
        }
        if addr.is_unspecified() {
            return Err(if prefix == bits {
                "is the unspecified address, which is never a peer's address".into()
            } else {
                "is a network at the unspecified address, not a proxy's network".into()
            });
        }
        if let IpAddr::V6(v6) = addr {
            if v6.to_ipv4_mapped().is_some() {
                return Err("is an IPv4-mapped IPv6 address: write it as IPv4".into());
            }
            if v6.segments()[0] & 0xffc0 == 0xfe80 {
                return Err(
                    "is an IPv6 link-local address: its zone is not compared, so it would \
                     match that address on every interface. Use a global or unique local \
                     address"
                        .into(),
                );
            }
        }
        let net = Self { addr, prefix };
        if net.network() != addr {
            return Err(format!(
                "has bits set after the prefix: write {}/{prefix}",
                net.network()
            ));
        }
        Ok(net)
    }

    /// The address with every bit after the prefix cleared.
    fn network(self) -> IpAddr {
        match self.addr {
            IpAddr::V4(a) => IpAddr::V4((u32::from(a) & mask32(self.prefix)).into()),
            IpAddr::V6(a) => IpAddr::V6((u128::from(a) & mask128(self.prefix)).into()),
        }
    }

    /// Whether `ip` is in this network. IPv4 entries hold IPv4 peers only, IPv6 entries IPv6
    /// peers only ([`TrustedPeers::contains`] turns an IPv4-mapped peer into IPv4 first).
    fn contains(self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                u32::from(ip) & mask32(self.prefix) == u32::from(net)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                u128::from(ip) & mask128(self.prefix) == u128::from(net)
            }
            _ => false,
        }
    }
}

fn mask32(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

fn mask128(prefix: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
}

/// `trusted_peers`, read: at least one entry, at most [`MAX_TRUSTED_PEERS`], each a [`Net`],
/// none twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedPeers(Vec<Net>);

impl TrustedPeers {
    /// Read `entries` as the config holds them.
    ///
    /// # Errors
    ///
    /// The startup message: no entry, too many, one that is not a [`Net`] (named), or one
    /// listed twice.
    pub(crate) fn parse(entries: &[String]) -> anyhow::Result<Self> {
        if entries.is_empty() {
            anyhow::bail!(
                "[server.forwarded_client_cert] trusted_peers is empty: list the IP addresses \
                 or CIDRs of the reverse proxy (for example [\"127.0.0.1/32\"]). Without them \
                 the listener would take a forwarded certificate from anyone who can reach it"
            );
        }
        if entries.len() > MAX_TRUSTED_PEERS {
            anyhow::bail!(
                "[server.forwarded_client_cert] trusted_peers has {} entries; at most \
                 {MAX_TRUSTED_PEERS} are allowed",
                entries.len()
            );
        }
        let mut nets: Vec<Net> = Vec::with_capacity(entries.len());
        for e in entries {
            let net = Net::parse(e).map_err(|why| {
                anyhow::anyhow!("[server.forwarded_client_cert] trusted_peers entry {e:?} {why}")
            })?;
            if nets.contains(&net) {
                anyhow::bail!("[server.forwarded_client_cert] trusted_peers lists {e:?} twice");
            }
            nets.push(net);
        }
        Ok(Self(nets))
    }

    /// How many entries there are.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the TCP peer `ip` is one of the entries. An IPv4-mapped IPv6 peer (a dual-stack
    /// listener on `[::]` accepting an IPv4 client) is compared as IPv4.
    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        self.0.iter().any(|n| n.contains(ip))
    }
}

/// `[server.forwarded_client_cert]`, checked: where the forwarding listener binds and which
/// peers it takes.
#[derive(Debug)]
pub(crate) struct Settings {
    /// `listen`.
    pub(crate) listen: SocketAddr,
    /// `trusted_peers`.
    pub(crate) peers: Arc<TrustedPeers>,
    /// The CA check's answers for the certificates forwarded lately, shared by the requests
    /// that forward the same certificate and intermediates
    /// ([`crate::client_pki::SharedStates`]).
    pub(crate) pki: Arc<crate::client_pki::SharedStates>,
}

/// Whether two listen addresses would be the same socket: the same port (not 0) and the same
/// address, or either one unspecified (`0.0.0.0` or `[::]` takes the port on every address).
fn same_socket(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() != 0
        && a.port() == b.port()
        && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
}

impl Settings {
    /// Check `[server.forwarded_client_cert]` as startup does; `None` when the section is
    /// absent.
    ///
    /// # Errors
    ///
    /// When `trusted_peers` is refused ([`TrustedPeers::parse`]); when `listen` is the address
    /// of `[server] listen`, `[admin] listen`, the console listener or the metrics listener
    /// (when those are on); or when `[server] public_url` is not set to an `https://` URL:
    /// clients reach this listener through the proxy's TLS, and discovery and DPoP must name
    /// that URL.
    pub(crate) fn from_config(config: &Config) -> anyhow::Result<Option<Self>> {
        let Some(section) = &config.server.forwarded_client_cert else {
            return Ok(None);
        };
        let peers = TrustedPeers::parse(&section.trusted_peers)?;
        let listen = section.listen;
        let others = [
            Some(("[server] listen", config.server.listen)),
            config.admin.listen.map(|a| ("[admin] listen", a)),
            config
                .admin_ui
                .enabled
                .then_some(("[admin_ui] listen", config.admin_ui.listen)),
            config
                .metrics
                .enabled
                .then_some(("[metrics] listen", config.metrics.listen)),
        ];
        for (name, addr) in others.into_iter().flatten() {
            if same_socket(listen, addr) {
                anyhow::bail!(
                    "[server.forwarded_client_cert] listen = {listen} is {name} too: the \
                     forwarding listener needs an address of its own, so that forwarded \
                     certificate headers are never read where other clients connect"
                );
            }
        }
        if !config
            .server
            .public_url
            .as_deref()
            .is_some_and(|u| u.starts_with("https://"))
        {
            anyhow::bail!(
                "[server.forwarded_client_cert] needs [server] public_url set to the https:// \
                 URL clients use to reach the reverse proxy: discovery and DPoP must name that \
                 URL, not the plain-HTTP forwarding listener"
            );
        }
        if listen.ip().is_unspecified() {
            tracing::warn!(
                %listen,
                "[server.forwarded_client_cert] listen is on every address: trusted_peers is \
                 the only fence. Bind it to the address the proxy connects to"
            );
        }
        Ok(Some(Self {
            listen,
            peers: Arc::new(peers),
            pki: Arc::new(crate::client_pki::SharedStates::new()),
        }))
    }
}

/// Read the forwarded certificate headers of a request on the forwarding listener: `None`
/// when neither header is there, else the certificate with its intermediates. The `Err` is
/// the reason for the log only; the answer is always the same `400`.
///
/// # Errors
///
/// As [`parse_values`], and when either header appears on more than one line, a value holds
/// a byte that is not visible ASCII, a space or a tab, or a certificate is not DER that
/// rustls-webpki can read.
pub(crate) fn parse(
    headers: &HeaderMap,
    pki: &crate::client_pki::SharedStates,
) -> Result<Option<ClientCertificate>, &'static str> {
    let one = |name: &str, repeated: &'static str| {
        let mut all = headers.get_all(name).iter();
        match (all.next(), all.next()) {
            (None, _) => Ok(None),
            (Some(v), None) => Ok(Some(v.as_bytes())),
            (Some(_), Some(_)) => Err(repeated),
        }
    };
    let leaf = one(CLIENT_CERT, "client_cert_repeated")?;
    let chain = one(CLIENT_CERT_CHAIN, "chain_repeated")?;
    let Some((leaf, chain)) = parse_values(leaf, chain)? else {
        return Ok(None);
    };
    let leaf = CertificateDer::from(leaf);
    if webpki::EndEntityCert::try_from(&leaf).is_err() {
        return Err("not_a_certificate");
    }
    let chain: Vec<CertificateDer<'static>> = chain.into_iter().map(CertificateDer::from).collect();
    for c in &chain {
        if webpki::EndEntityCert::try_from(c).is_err() {
            return Err("not_a_certificate");
        }
    }
    Ok(Some(ClientCertificate::forwarded(leaf, &chain, pki)))
}

/// The DER of a `Client-Cert` and of each `Client-Cert-Chain` member, in order.
pub(crate) type Parsed = (Vec<u8>, Vec<Vec<u8>>);

/// The DER bytes of the leaf and of each chain certificate from the two header values (each
/// `None` when that header is absent): `None` when both are absent. The rules of RFC 9440 and
/// RFC 8941 §4.2, strictly:
///
/// - `Client-Cert` is one Byte Sequence (`:` base64 `:`) with no parameters; spaces before
///   and after it are allowed.
/// - `Client-Cert-Chain` is a List of such items, separated by `,` with optional spaces or
///   tabs around it and after the last (only spaces before the first), at most
///   [`MAX_INTERMEDIATES`] of them, none empty, no trailing comma.
///   It needs a `Client-Cert`.
/// - The base64 is the standard alphabet with padding, canonical (no stray bits), and not
///   empty. Each certificate is at most [`MAX_CERT_DER_BYTES`], all of them together at most
///   [`MAX_TOTAL_DER_BYTES`].
///
/// # Errors
///
/// The reason, for the log only.
pub(crate) fn parse_values(
    leaf: Option<&[u8]>,
    chain: Option<&[u8]>,
) -> Result<Option<Parsed>, &'static str> {
    let leaf = match (leaf, chain) {
        (None, None) => return Ok(None),
        (None, Some(_)) => return Err("chain_without_leaf"),
        (Some(l), _) => l,
    };
    for v in std::iter::once(leaf).chain(chain) {
        if !v
            .iter()
            .all(|&b| b == b' ' || b == b'\t' || b.is_ascii_graphic())
        {
            return Err("not_visible_ascii");
        }
    }
    if leaf.len() > MAX_LEAF_VALUE_BYTES {
        return Err("too_large");
    }
    let leaf = byte_sequence(trim(leaf, b" "))?;
    let mut total = leaf.len();
    let mut certs = Vec::new();
    if let Some(chain) = chain {
        if chain.len() > MAX_CHAIN_VALUE_BYTES {
            return Err("too_large");
        }
        // RFC 8941 §4.2: SP only before the list. §4.2.1: OWS (SP or HTAB) after each member,
        // the last one too, and after each comma.
        let members: Vec<&[u8]> = trim_start(chain, b" ").split(|&b| b == b',').collect();
        if members.len() > MAX_INTERMEDIATES {
            return Err("too_many_intermediates");
        }
        for (i, m) in members.into_iter().enumerate() {
            let m = if i > 0 { trim_start(m, b" \t") } else { m };
            let m = trim_end(m, b" \t");
            let der = byte_sequence(m)?;
            total += der.len();
            certs.push(der);
        }
    }
    if total > MAX_TOTAL_DER_BYTES {
        return Err("too_large");
    }
    Ok(Some((leaf, certs)))
}

/// `v` without the bytes of `what` at either end.
fn trim<'a>(v: &'a [u8], what: &[u8]) -> &'a [u8] {
    trim_end(trim_start(v, what), what)
}

/// `v` without the bytes of `what` at its start.
fn trim_start<'a>(mut v: &'a [u8], what: &[u8]) -> &'a [u8] {
    while let Some((first, rest)) = v.split_first() {
        if !what.contains(first) {
            break;
        }
        v = rest;
    }
    v
}

/// `v` without the bytes of `what` at its end.
fn trim_end<'a>(mut v: &'a [u8], what: &[u8]) -> &'a [u8] {
    while let Some((last, rest)) = v.split_last() {
        if !what.contains(last) {
            break;
        }
        v = rest;
    }
    v
}

/// One RFC 8941 Byte Sequence item with nothing after it, decoded.
fn byte_sequence(item: &[u8]) -> Result<Vec<u8>, &'static str> {
    if item.is_empty() {
        return Err("empty_item");
    }
    if item.len() > MAX_ITEM_CHARS {
        return Err("too_large");
    }
    let Some(rest) = item.strip_prefix(b":") else {
        return Err("not_a_byte_sequence");
    };
    let Some(end) = rest.iter().position(|&b| b == b':') else {
        return Err("not_a_byte_sequence");
    };
    let (b64, after) = (&rest[..end], &rest[end + 1..]);
    match after.first() {
        None => {}
        Some(b';') => return Err("parameters"),
        Some(_) => return Err("trailing_data"),
    }
    if b64.is_empty() {
        return Err("empty_item");
    }
    let alphabet = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=';
    if !b64.iter().copied().all(alphabet) {
        return Err("invalid_base64");
    }
    let der = STANDARD.decode(b64).map_err(|_| "invalid_base64")?;
    // The engine already refuses padding that is not canonical and stray bits; encoding again
    // makes sure there is one spelling of each certificate.
    if STANDARD.encode(&der).as_bytes() != b64 {
        return Err("invalid_base64");
    }
    if der.len() > MAX_CERT_DER_BYTES {
        return Err("too_large");
    }
    Ok(der)
}

/// A warning at most once per [`Throttle::PERIOD`]; the others at debug, counted in the next
/// warning. So a flood of refused requests does not flood the log, and the first is always
/// seen.
pub(crate) struct Throttle {
    /// Seconds since [`epoch`] after which the next warning may be logged.
    next: AtomicU64,
    /// The refusals logged at debug since the last warning.
    suppressed: AtomicU64,
}

/// The process's own start of time for [`Throttle`].
fn epoch() -> std::time::Instant {
    static EPOCH: OnceLock<std::time::Instant> = OnceLock::new();
    *EPOCH.get_or_init(std::time::Instant::now)
}

impl Throttle {
    /// At most one warning per this many seconds.
    const PERIOD: u64 = 10;

    pub(crate) const fn new() -> Self {
        Self {
            next: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
        }
    }

    /// `Some(n)` when this event is to be logged at warn (`n` events were logged at debug
    /// since the last warning), `None` when at debug.
    pub(crate) fn warn(&self) -> Option<u64> {
        let now = epoch().elapsed().as_secs();
        let next = self.next.load(Ordering::Relaxed);
        if now >= next
            && self
                .next
                .compare_exchange(
                    next,
                    now + Self::PERIOD,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            return Some(self.suppressed.swap(0, Ordering::Relaxed));
        }
        self.suppressed.fetch_add(1, Ordering::Relaxed);
        None
    }
}

static NOT_ACCEPTED: Throttle = Throttle::new();
static MALFORMED: Throttle = Throttle::new();

/// The peer address of a request, as the accept loop set it, for a log line.
fn peer(req: &axum::extract::Request) -> String {
    req.extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map_or_else(|| "unknown".to_owned(), |c| c.0.to_string())
}

/// Middleware of every listener when `[server.forwarded_client_cert]` is set, outside the
/// routes (so an unknown path too).
///
/// - On the forwarding listener ([`ServedForwarded`]): read the headers ([`parse`]). A good
///   certificate goes into the request as a [`ClientCertificate`] with source `forwarded`; a
///   bad one is `400 client_cert_header_malformed`. Both headers are then taken off the
///   request, so nothing after this (a handler, the MCP proxy's upstream) sees them.
/// - On any other listener: a request with either header is `400
///   client_cert_header_not_accepted`, logged at warn with the peer address (throttled,
///   [`Throttle`]).
pub(crate) async fn headers(
    axum::extract::State(pki): axum::extract::State<Arc<crate::client_pki::SharedStates>>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let has_headers =
        req.headers().contains_key(CLIENT_CERT) || req.headers().contains_key(CLIENT_CERT_CHAIN);
    if req.extensions().get::<ServedForwarded>().is_none() {
        if !has_headers {
            return next.run(req).await;
        }
        let peer = peer(&req);
        match NOT_ACCEPTED.warn() {
            Some(suppressed) => tracing::warn!(
                peer = %peer,
                suppressed,
                "a request carried a Client-Cert or Client-Cert-Chain header on a listener that \
                 does not take forwarded certificates; refused with 400. Point the proxy at \
                 [server.forwarded_client_cert] listen, or look for a client that tries to \
                 claim a certificate"
            ),
            None => tracing::debug!(
                peer = %peer,
                "forwarded certificate header on another listener; refused"
            ),
        }
        return ApiError::bad_request("invalid_request", NOT_ACCEPTED_DETAIL)
            .with_description("client_cert_header_not_accepted")
            .into_response();
    }
    // The forwarding listener speaks no TLS, so no handshake certificate can be here; if one
    // were, two sources would meet in one request.
    if req.extensions_mut().remove::<ClientCertificate>().is_some() {
        tracing::error!("a request on the forwarding listener carried a handshake certificate");
        return ApiError::internal("handshake certificate on the forwarding listener")
            .into_response();
    }
    if has_headers {
        match parse(req.headers(), &pki) {
            Ok(Some(cert)) => {
                req.extensions_mut().insert(cert);
            }
            Ok(None) => {}
            Err(reason) => {
                let peer = peer(&req);
                match MALFORMED.warn() {
                    Some(suppressed) => tracing::warn!(
                        peer = %peer,
                        reason,
                        suppressed,
                        "the proxy forwarded a Client-Cert or Client-Cert-Chain header that is \
                         not well formed; refused with 400"
                    ),
                    None => tracing::debug!(
                        peer = %peer,
                        reason,
                        "malformed forwarded certificate header; refused"
                    ),
                }
                return ApiError::bad_request("invalid_request", MALFORMED_DETAIL)
                    .with_description("client_cert_header_malformed")
                    .into_response();
            }
        }
        req.headers_mut().remove(CLIENT_CERT);
        req.headers_mut().remove(CLIENT_CERT_CHAIN);
    }
    next.run(req).await
}

/// The routes of the main router that the forwarding listener serves, by the template axum
/// matched, each with why a client reaches it through the proxy. Every other route answers
/// there as a path the router does not know ([`only_served_routes`]). A new route is not
/// served until it is listed here; a test fails until it is listed here or in
/// [`NOT_SERVED_ROUTES`] / [`NOT_SERVED_PREFIXES`].
pub(crate) const SERVED_ROUTES: &[(&str, &str)] = &[
    (
        "/token",
        "agents exchange tokens, authenticated by the forwarded certificate",
    ),
    ("/token/renew", "agents renew the tokens they got there"),
    (
        "/access/v1/evaluation",
        "PEPs, authenticated by the forwarded certificate",
    ),
    ("/access/v1/evaluations", "PEPs, as above"),
    ("/access/v1/search/action", "PEPs, as above"),
    (
        "/mcp/{server}",
        "agents call MCP servers through attenuo at its public URL",
    ),
    (
        "/approvals/{id}",
        "the approver opens the approval link, which names the public URL",
    ),
    (
        "/.well-known/jwks.json",
        "token verifiers read the keys at the public URL",
    ),
    (
        "/.well-known/authzen-configuration",
        "PEPs discover the endpoints at the public URL",
    ),
    ("/healthz", "the proxy's health check"),
    ("/readyz", "the proxy's readiness check"),
];

/// Routes of the main router that the forwarding listener never serves, each with why.
// Read by the route test only: [`only_served_routes`] serves nothing it does not list.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const NOT_SERVED_ROUTES: &[(&str, &str)] = &[
    (
        "/ext-authz/v1/mcp/{server}",
        "a gateway calls it directly, with the agent's request headers copied into its check; \
         on this listener a copied Client-Cert would be read as one the proxy checked",
    ),
    ("/", "the console listener's own router, not the main one"),
    ("/favicon.svg", "the console listener's own router"),
    ("/metrics", "the metrics listener's own router"),
    (
        "/mcp",
        "the fake MCP server of the proxy crate's testing module",
    ),
];

/// Path prefixes the forwarding listener never serves: the admin API (operators use the main
/// or the `[admin] listen` listener).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const NOT_SERVED_PREFIXES: &[&str] = &["/admin/"];

/// Outermost layer of the main router when `[server.forwarded_client_cert]` is set: on the
/// forwarding listener ([`ServedForwarded`]) a request whose matched route is not in
/// [`SERVED_ROUTES`] answers as a path the router does not know (`404`, empty body), for
/// every method, before any other layer runs. Elsewhere it does nothing. One router serves
/// both listeners, so MCP sessions and limits stay shared.
pub(crate) async fn only_served_routes(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if req.extensions().get::<ServedForwarded>().is_some() {
        let served = req
            .extensions()
            .get::<axum::extract::MatchedPath>()
            .is_some_and(|p| SERVED_ROUTES.iter().any(|(r, _)| *r == p.as_str()));
        if !served {
            return StatusCode::NOT_FOUND.into_response();
        }
    }
    next.run(req).await
}

/// The answer to every request of a peer that is not in `trusted_peers`: `403
/// forwarded_peer_not_trusted` with `Connection: close`.
pub(crate) fn untrusted_peer() -> axum::response::Response {
    let mut res = ApiError::new(
        StatusCode::FORBIDDEN,
        "forwarded_peer_not_trusted",
        UNTRUSTED_PEER_DETAIL,
    )
    .into_response();
    res.headers_mut().insert(
        axum::http::header::CONNECTION,
        axum::http::HeaderValue::from_static("close"),
    );
    res
}

/// For the log line of a refused peer.
pub(crate) static UNTRUSTED: Throttle = Throttle::new();

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_cert::CertSource;

    fn b64(der: &[u8]) -> String {
        format!(":{}:", STANDARD.encode(der))
    }

    fn values(leaf: Option<&str>, chain: Option<&str>) -> Result<Option<Parsed>, &'static str> {
        parse_values(leaf.map(str::as_bytes), chain.map(str::as_bytes))
    }

    /// [`super::parse`] with a cache of its own.
    fn parse(h: &HeaderMap) -> Result<Option<ClientCertificate>, &'static str> {
        super::parse(h, &crate::client_pki::SharedStates::new())
    }

    fn nets(entries: &[&str]) -> anyhow::Result<TrustedPeers> {
        TrustedPeers::parse(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn trusted_peers_are_read_strictly() {
        let p = nets(&[
            "127.0.0.1/32",
            "10.1.0.0/16",
            "::1",
            "fd00::/32",
            "192.0.2.7",
        ])
        .unwrap();
        for ip in [
            "127.0.0.1",
            "10.1.200.3",
            "::1",
            "fd00:0:12::1",
            "192.0.2.7",
            "::ffff:10.1.0.1",
        ] {
            assert!(p.contains(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "127.0.0.2",
            "10.2.0.1",
            "::2",
            "fe80::1",
            "fd01::1",
            "192.0.2.8",
            "::ffff:127.0.0.2",
        ] {
            assert!(!p.contains(ip.parse().unwrap()), "{ip}");
        }
        // A v4 entry never holds a v6 peer that is not mapped, nor the reverse.
        let v4 = nets(&["127.0.0.0/8"]).unwrap();
        assert!(!v4.contains("::7f00:1".parse().unwrap()));
        assert!(nets(&["10.0.0.0/8", "128.0.0.0/8", "2001:db8::/32", "fd00::/48"]).is_ok());

        for (entry, why) in [
            (
                "0.0.0.0/0",
                "wider than /8 (the widest IPv4 network allowed)",
            ),
            ("0.0.0.0", "is the unspecified address"),
            ("::/0", "wider than /32 (the widest IPv6 network allowed)"),
            ("::/8", "wider than /32"),
            ("::", "is the unspecified address"),
            ("0.0.0.0/8", "a network at the unspecified address"),
            ("::/32", "a network at the unspecified address"),
            ("128.0.0.0/1", "wider than /8"),
            ("10.0.0.0/7", "wider than /8"),
            ("fd00::/8", "wider than /32"),
            ("2001:db8::/31", "wider than /32"),
            ("fe80::1", "link-local"),
            ("fe80::/64", "link-local"),
            ("febf:ffff::/32", "link-local"),
            ("10.0.0.1/8", "bits set after the prefix: write 10.0.0.0/8"),
            ("127.0.0.1/33", "prefix length over 32"),
            ("::1/129", "prefix length over 128"),
            ("127.0.0.1/+32", "not a plain number"),
            ("127.0.0.1/032", "not a plain number"),
            ("127.0.0.1/", "not a plain number"),
            ("127.0.0.1/ 32", "not a plain number"),
            ("localhost", "not an IP address"),
            ("127.0.0.1:80", "not an IP address"),
            ("fe80::1%eth0", "not an IP address"),
            (" 127.0.0.1", "not an IP address"),
            ("", "not an IP address"),
            ("::ffff:127.0.0.1", "IPv4-mapped"),
        ] {
            let e = nets(&[entry]).unwrap_err().to_string();
            assert!(
                e.starts_with(&format!(
                    "[server.forwarded_client_cert] trusted_peers entry {entry:?}"
                )) && e.contains(why),
                "{entry}: {e}"
            );
        }
        let e = nets(&[]).unwrap_err().to_string();
        assert!(e.contains("trusted_peers is empty"), "{e}");
        let e = nets(&["127.0.0.1", "127.0.0.1/32"])
            .unwrap_err()
            .to_string();
        assert!(e.contains("twice"), "{e}");
        let many: Vec<String> = (0..=MAX_TRUSTED_PEERS)
            .map(|i| format!("10.0.{}.{}", i / 256, i % 256))
            .collect();
        let e = TrustedPeers::parse(&many).unwrap_err().to_string();
        assert!(e.contains("at most 64"), "{e}");
    }

    #[test]
    fn valid_headers_with_and_without_a_chain() {
        assert_eq!(values(None, None), Ok(None));
        let leaf = b"leaf der".to_vec();
        let (a, b) = (b"intermediate a".to_vec(), b"intermediate b".to_vec());
        assert_eq!(
            values(Some(&b64(&leaf)), None),
            Ok(Some((leaf.clone(), vec![])))
        );
        // Spaces around the item; spaces and tabs around the commas of the list.
        assert_eq!(
            values(
                Some(&format!("  {}  ", b64(&leaf))),
                Some(&format!(" {} ,\t{}", b64(&a), b64(&b)))
            ),
            Ok(Some((leaf.clone(), vec![a.clone(), b.clone()])))
        );
        assert_eq!(
            values(
                Some(&b64(&leaf)),
                Some(&format!("{}\t, \t{}  ", b64(&a), b64(&b)))
            ),
            Ok(Some((leaf.clone(), vec![a.clone(), b.clone()])))
        );
        // OWS after the last member, a tab too (RFC 8941 §4.2.1).
        for chain in [
            format!("{}\t", b64(&a)),
            format!("{}, {} \t ", b64(&a), b64(&b)),
        ] {
            assert!(
                values(Some(&b64(&leaf)), Some(&chain)).unwrap().is_some(),
                "{chain:?}"
            );
        }
        let four = vec![b64(&a); MAX_INTERMEDIATES].join(", ");
        assert_eq!(
            values(Some(&b64(&leaf)), Some(&four))
                .unwrap()
                .unwrap()
                .1
                .len(),
            MAX_INTERMEDIATES
        );
        // Every length of the last base64 group.
        for n in 1..=6 {
            let der = vec![0xA5u8; n];
            assert_eq!(values(Some(&b64(&der)), None), Ok(Some((der, vec![]))));
        }
    }

    #[test]
    fn malformed_headers_are_refused() {
        let leaf = b64(b"leaf der");
        let a = b64(b"intermediate");
        let chain5 = vec![a.clone(); MAX_INTERMEDIATES + 1].join(", ");
        let big = b64(&vec![1u8; MAX_CERT_DER_BYTES + 1]);
        let at_cap = b64(&vec![1u8; MAX_CERT_DER_BYTES]);
        let over_total = vec![at_cap.clone(); MAX_INTERMEDIATES].join(", ");
        for (l, c, why) in [
            (None, Some(a.as_str()), "chain_without_leaf"),
            (Some(""), None, "empty_item"),
            (Some("   "), None, "empty_item"),
            (Some("::"), None, "empty_item"),
            (Some(":"), None, "not_a_byte_sequence"),
            (Some("bGVhZg=="), None, "not_a_byte_sequence"),
            (Some("\"bGVhZg==\""), None, "not_a_byte_sequence"),
            (Some(":bGVhZg==:;a=1"), None, "parameters"),
            (Some(":bGVhZg==:;"), None, "parameters"),
            (Some(":bGVhZg==: ;a"), None, "trailing_data"),
            (Some(":bGVhZg==:, :bGVhZg==:"), None, "trailing_data"),
            (Some(":bGVhZg==::"), None, "trailing_data"),
            (Some(":bGVhZg:"), None, "invalid_base64"),
            (Some(":bGVhZh==:"), None, "invalid_base64"),
            (Some(":bGVh Zg==:"), None, "invalid_base64"),
            (Some(":bGVhZg-_:"), None, "invalid_base64"),
            (Some(":bGVhZg===:"), None, "invalid_base64"),
            (Some(":=bGVhZg=:"), None, "invalid_base64"),
            (Some("\t:bGVhZg==:"), None, "not_a_byte_sequence"),
            (Some(":bGVhZg==:\u{e9}"), None, "not_visible_ascii"),
            (Some(":bGVhZg==:\r"), None, "not_visible_ascii"),
            (Some(big.as_str()), None, "too_large"),
            (Some(leaf.as_str()), Some(""), "empty_item"),
            (Some(leaf.as_str()), Some(" "), "empty_item"),
            (Some(leaf.as_str()), Some(&format!("{a},")), "empty_item"),
            (Some(leaf.as_str()), Some(&format!(",{a}")), "empty_item"),
            (
                Some(leaf.as_str()),
                Some(&format!("{a},,{a}")),
                "empty_item",
            ),
            (Some(leaf.as_str()), Some(&format!("{a};x")), "parameters"),
            // Only SP before the first member (RFC 8941 §4.2).
            (
                Some(leaf.as_str()),
                Some(&format!("\t{a}")),
                "not_a_byte_sequence",
            ),
            (
                Some(leaf.as_str()),
                Some(&format!(" \t{a}, {a}")),
                "not_a_byte_sequence",
            ),
            (Some(&format!("{leaf}\t")), None, "trailing_data"),
            (
                Some(leaf.as_str()),
                Some(&format!("{a} {a}")),
                "trailing_data",
            ),
            (
                Some(leaf.as_str()),
                Some(&format!("({a})")),
                "not_a_byte_sequence",
            ),
            (Some(leaf.as_str()), Some(&chain5), "too_many_intermediates"),
            (Some(leaf.as_str()), Some(big.as_str()), "too_large"),
            (Some(at_cap.as_str()), Some(&over_total), "too_large"),
        ] {
            assert_eq!(values(l, c), Err(why), "{l:?} {c:?}");
        }
        // A value far over the cap is refused before it is read.
        let huge = "A".repeat(MAX_CHAIN_VALUE_BYTES + 1);
        assert_eq!(values(Some(&leaf), Some(&huge)), Err("too_large"));
        let huge = "A".repeat(MAX_LEAF_VALUE_BYTES + 1);
        assert_eq!(values(Some(&huge), None), Err("too_large"));
    }

    fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn self_signed() -> Vec<u8> {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["client".to_string()]).unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn the_header_map_is_read_strictly() {
        let der = self_signed();
        let leaf = b64(&der);
        assert!(parse(&HeaderMap::new()).unwrap().is_none());
        let cert = parse(&header_map(&[("Client-Cert", &leaf)]))
            .unwrap()
            .unwrap();
        assert_eq!(cert.der().as_ref(), der.as_slice());
        assert_eq!(cert.source(), CertSource::Forwarded);
        assert_eq!(cert.audit_value()["source"], "forwarded");
        assert_eq!(cert.intermediates(), Some(&[][..]));
        // Two lines of either header.
        assert_eq!(
            parse(&header_map(&[
                ("Client-Cert", &leaf),
                ("client-cert", &leaf)
            ]))
            .unwrap_err(),
            "client_cert_repeated"
        );
        let other = b64(&self_signed());
        assert_eq!(
            parse(&header_map(&[
                ("Client-Cert", &leaf),
                ("Client-Cert-Chain", &other),
                ("Client-Cert-Chain", &other)
            ]))
            .unwrap_err(),
            "chain_repeated"
        );
        // Base64 of something that is not a certificate, as the leaf or in the chain.
        assert_eq!(
            parse(&header_map(&[("Client-Cert", &b64(b"not der"))])).unwrap_err(),
            "not_a_certificate"
        );
        assert_eq!(
            parse(&header_map(&[
                ("Client-Cert", &leaf),
                ("Client-Cert-Chain", &b64(b"junk"))
            ]))
            .unwrap_err(),
            "not_a_certificate"
        );
        // A chain certificate that is a copy of the leaf is kept out of the intermediates,
        // as on the handshake path.
        let cert = parse(&header_map(&[
            ("Client-Cert", &leaf),
            ("Client-Cert-Chain", &leaf),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(cert.intermediates(), Some(&[][..]));
    }

    /// Each parse is a certificate of its own. Two parses of the same certificate and
    /// intermediates kept share the CA check's state; another certificate has its own.
    #[test]
    fn each_parse_is_a_new_certificate() {
        let shared = crate::client_pki::SharedStates::new();
        let leaf = b64(&self_signed());
        let (m1, m2) = (b64(&self_signed()), b64(&self_signed()));
        let h = header_map(&[("Client-Cert", &leaf)]);
        let a = super::parse(&h, &shared).unwrap().unwrap();
        let b = super::parse(&h, &shared).unwrap().unwrap();
        assert_eq!(a.sha256(), b.sha256());
        assert!(std::ptr::eq(a.pki_state(), b.pki_state()));
        let with = |m: &str| {
            super::parse(
                &header_map(&[("Client-Cert", &leaf), ("Client-Cert-Chain", m)]),
                &shared,
            )
            .unwrap()
            .unwrap()
        };
        // The key is the intermediates kept: a self-signed one is dropped (it cannot help a
        // path), so these share the state of the certificate alone. Kept intermediates make
        // another key (`client_pki` tests).
        let (c, d) = (with(&m1), with(&m2));
        assert!(std::ptr::eq(a.pki_state(), c.pki_state()));
        assert!(std::ptr::eq(c.pki_state(), d.pki_state()));
        let other = b64(&self_signed());
        let e = super::parse(&header_map(&[("Client-Cert", &other)]), &shared)
            .unwrap()
            .unwrap();
        assert!(!std::ptr::eq(a.pki_state(), e.pki_state()));
    }

    /// Every router path in the server and proxy crates (`.route(`, `.route_service(`,
    /// `.nest(` in any source file, test modules aside) is a string literal, or a constant
    /// listed here, and is either served on the forwarding listener or explicitly not; so a
    /// new route forces a decision. Every listed route exists. The listener is default-deny
    /// whatever this finds ([`only_served_routes`]).
    #[test]
    fn every_route_is_decided_for_the_forwarding_listener() {
        const CONSTANTS: &[(&str, &str)] = &[("UI_PREFIX", crate::admin_ui::UI_PREFIX)];
        fn rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let path = e.unwrap().path();
                if path.is_dir() {
                    rs_files(&path, out);
                } else if path.extension().is_some_and(|x| x == "rs") {
                    out.push(path);
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        rs_files(&root.join("src"), &mut files);
        rs_files(&root.join("../attenuo-proxy/src"), &mut files);
        assert!(files.len() > 20, "{files:?}");
        let mut found = Vec::new();
        for file in &files {
            let text = std::fs::read_to_string(file).unwrap();
            // Not the test modules, not comments.
            let text = text.split("\n#[cfg(test)]\nmod ").next().unwrap();
            let code: String = text
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            for call in [".route(", ".route_service(", ".nest("] {
                let mut rest = code.as_str();
                while let Some(at) = rest.find(call) {
                    rest = &rest[at + call.len()..];
                    let t = rest.trim_start();
                    let path = if let Some(after) = t.strip_prefix('"') {
                        after[..after.find('"').unwrap()].to_owned()
                    } else {
                        let ident: String = t
                            .chars()
                            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                            .collect();
                        match CONSTANTS.iter().find(|(n, _)| *n == ident) {
                            Some((_, v)) => (*v).to_owned(),
                            None => panic!(
                                "{}: {call} with a path that is not a string literal: {:?}",
                                file.display(),
                                &t[..t.len().min(40)]
                            ),
                        }
                    };
                    found.push(path);
                }
            }
        }
        assert!(found.len() > 20, "{found:?}");
        for path in &found {
            let served = SERVED_ROUTES.iter().any(|(r, _)| r == path);
            let not = NOT_SERVED_ROUTES.iter().any(|(r, _)| r == path)
                || NOT_SERVED_PREFIXES.iter().any(|p| path.starts_with(p));
            assert!(
                served != not,
                "{path}: add it to SERVED_ROUTES or NOT_SERVED_ROUTES in forwarded.rs (and to \
                 the list in docs/reference/http-api.md)"
            );
        }
        for (r, _) in SERVED_ROUTES.iter().chain(NOT_SERVED_ROUTES) {
            assert!(
                found.iter().any(|f| f == r),
                "{r} is listed but not mounted"
            );
        }
    }

    /// A router with a served route, a route that is not served, an admin route and a handler
    /// that reports what it sees, behind [`only_served_routes`] and [`headers`], with the
    /// forwarding marker set or not.
    fn marked_router(forwarded: bool) -> axum::Router {
        use axum::routing::{get, post};
        let seen = |req: axum::extract::Request| async move {
            let h = req.headers();
            format!(
                "client-cert={} chain={} cert={}",
                h.contains_key(CLIENT_CERT),
                h.contains_key(CLIENT_CERT_CHAIN),
                req.extensions()
                    .get::<ClientCertificate>()
                    .map_or("none".into(), |c| c.source().as_str().to_owned())
            )
        };
        let app = axum::Router::new()
            .route("/token", post(seen))
            .route("/mcp/{server}", post(seen))
            .route("/ext-authz/v1/mcp/{server}", post(seen))
            .route("/admin/whoami", get(seen))
            .layer(axum::middleware::from_fn_with_state(
                Arc::new(crate::client_pki::SharedStates::new()),
                headers,
            ))
            .layer(axum::middleware::from_fn(only_served_routes));
        if forwarded {
            app.layer(axum::middleware::from_fn(
                |mut req: axum::extract::Request, next: axum::middleware::Next| async move {
                    req.extensions_mut().insert(ServedForwarded);
                    next.run(req).await
                },
            ))
        } else {
            app
        }
    }

    async fn send(
        app: &axum::Router,
        method: &str,
        path: &str,
        hs: &[(&str, &str)],
    ) -> (StatusCode, String) {
        use tower::ServiceExt as _;
        let mut req = axum::http::Request::builder().method(method).uri(path);
        for (k, v) in hs {
            req = req.header(*k, *v);
        }
        let res = app
            .clone()
            .oneshot(req.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let body = axum::body::to_bytes(res.into_body(), 1 << 16)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// On the forwarding listener only the listed routes answer; the others, and unknown
    /// paths, are one bare 404 for every method. Elsewhere nothing changes.
    #[tokio::test]
    async fn the_forwarding_listener_serves_the_listed_routes_only() {
        let fwd = marked_router(true);
        let unknown = send(&fwd, "GET", "/no/such/path", &[]).await;
        assert_eq!(unknown, (StatusCode::NOT_FOUND, String::new()));
        for (method, path) in [
            ("POST", "/ext-authz/v1/mcp/github"),
            ("GET", "/ext-authz/v1/mcp/github"),
            ("GET", "/admin/whoami"),
            ("POST", "/admin/whoami"),
            ("DELETE", "/admin/whoami"),
        ] {
            assert_eq!(
                send(&fwd, method, path, &[]).await,
                unknown,
                "{method} {path}"
            );
        }
        assert_eq!(send(&fwd, "POST", "/token", &[]).await.0, StatusCode::OK);
        assert_eq!(
            send(&fwd, "POST", "/mcp/github", &[]).await.0,
            StatusCode::OK
        );
        // A served path with a method it does not take is the router's 405, as elsewhere.
        assert_eq!(
            send(&fwd, "GET", "/token", &[]).await.0,
            StatusCode::METHOD_NOT_ALLOWED
        );
        let main = marked_router(false);
        for (method, path) in [
            ("POST", "/ext-authz/v1/mcp/github"),
            ("GET", "/admin/whoami"),
            ("POST", "/token"),
        ] {
            assert_eq!(
                send(&main, method, path, &[]).await.0,
                StatusCode::OK,
                "{path}"
            );
        }
    }

    /// The headers are read and taken off the request before any handler (the MCP proxy's
    /// too) sees it; the handler sees the certificate only as the request's extension.
    #[tokio::test]
    async fn the_headers_are_gone_before_a_handler_sees_the_request() {
        let fwd = marked_router(true);
        let leaf = b64(&self_signed());
        let chain = b64(&self_signed());
        for path in ["/token", "/mcp/github"] {
            let (status, body) = send(
                &fwd,
                "POST",
                path,
                &[("Client-Cert", &leaf), ("Client-Cert-Chain", &chain)],
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert_eq!(
                body, "client-cert=false chain=false cert=forwarded",
                "{path}"
            );
        }
        // An empty `Client-Cert`, as a proxy that sets it for a client without a certificate
        // would send, is refused: never read as "no certificate".
        let (status, body) = send(&fwd, "POST", "/token", &[("Client-Cert", "")]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("client_cert_header_malformed"), "{body}");
        // Elsewhere the headers are refused before the handler.
        let (status, body) = send(
            &marked_router(false),
            "POST",
            "/token",
            &[("Client-Cert", &leaf)],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("client_cert_header_not_accepted"), "{body}");
    }

    #[test]
    fn the_throttle_warns_once_per_period() {
        let t = Throttle::new();
        assert_eq!(t.warn(), Some(0));
        assert_eq!(t.warn(), None);
        assert_eq!(t.warn(), None);
        // Make the period pass.
        t.next.store(0, Ordering::Relaxed);
        assert_eq!(t.warn(), Some(2));
    }

    fn settings(toml: &str) -> anyhow::Result<Option<Settings>> {
        Settings::from_config(&Config::from_toml(toml).unwrap())
    }

    #[test]
    fn the_section_is_checked() {
        const URL: &str = "[server]\npublic_url = \"https://attenuo.example\"\n";
        let section = |listen: &str, peers: &str| {
            format!(
                "[server.forwarded_client_cert]\nlisten = \"{listen}\"\ntrusted_peers = {peers}\n"
            )
        };
        assert!(settings("").unwrap().is_none());
        let ok = settings(&format!(
            "{URL}{}",
            section("127.0.0.1:8444", "[\"127.0.0.1\"]")
        ))
        .unwrap()
        .unwrap();
        assert_eq!(ok.listen, "127.0.0.1:8444".parse().unwrap());
        assert!(ok.peers.contains("127.0.0.1".parse().unwrap()));

        for (toml, want) in [
            (
                section("127.0.0.1:8444", "[\"127.0.0.1\"]"),
                "needs [server] public_url set to the https:// URL",
            ),
            (
                "[server]\npublic_url = \"http://localhost:8080\"\n".to_owned()
                    + &section("127.0.0.1:8444", "[\"127.0.0.1\"]"),
                "needs [server] public_url set to the https:// URL",
            ),
            (
                format!("{URL}{}", section("127.0.0.1:8444", "[]")),
                "trusted_peers is empty",
            ),
            (
                format!("{URL}{}", section("127.0.0.1:8444", "[\"0.0.0.0/0\"]")),
                "wider than /8",
            ),
            (
                format!("{URL}{}", section("127.0.0.1:8080", "[\"127.0.0.1\"]")),
                "listen = 127.0.0.1:8080 is [server] listen too",
            ),
            (
                format!("{URL}{}", section("0.0.0.0:8080", "[\"127.0.0.1\"]")),
                "is [server] listen too",
            ),
            (
                format!(
                    "{URL}[admin]\nlisten = \"127.0.0.1:9102\"\n{}",
                    section("127.0.0.1:9102", "[\"127.0.0.1\"]")
                ),
                "is [admin] listen too",
            ),
            (
                format!(
                    "{URL}[admin_ui]\nenabled = true\n{}",
                    section("127.0.0.1:9101", "[\"127.0.0.1\"]")
                ),
                "is [admin_ui] listen too",
            ),
            (
                format!(
                    "{URL}[metrics]\nenabled = true\n{}",
                    section("127.0.0.1:9100", "[\"127.0.0.1\"]")
                ),
                "is [metrics] listen too",
            ),
        ] {
            let e = settings(&toml).unwrap_err().to_string();
            assert!(e.contains(want), "{toml}: {e}");
            assert!(e.starts_with("[server.forwarded_client_cert]"), "{e}");
        }
        // The console and metrics addresses count only when those listeners are on.
        assert!(settings(&format!(
            "{URL}{}",
            section("127.0.0.1:9100", "[\"127.0.0.1\"]")
        ))
        .unwrap()
        .is_some());
        // The section's keys: `listen` and `trusted_peers` are required, nothing else is known.
        for toml in [
            "[server.forwarded_client_cert]\ntrusted_peers = [\"127.0.0.1\"]\n",
            "[server.forwarded_client_cert]\nlisten = \"127.0.0.1:8444\"\n",
            "[server.forwarded_client_cert]\nlisten = \"127.0.0.1:8444\"\ntrusted_peers = \
             [\"127.0.0.1\"]\nheader = \"X-Client-Cert\"\n",
            "[server.forwarded_client_cert]\nlisten = \"127.0.0.1:8444\"\ntrusted_peers = \
             \"127.0.0.1\"\n",
        ] {
            assert!(Config::from_toml(toml).is_err(), "{toml}");
        }
    }

    #[test]
    fn same_socket_rules() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert!(same_socket(a("127.0.0.1:8080"), a("127.0.0.1:8080")));
        assert!(same_socket(a("0.0.0.0:8080"), a("127.0.0.1:8080")));
        assert!(same_socket(a("127.0.0.1:8080"), a("[::]:8080")));
        assert!(!same_socket(a("127.0.0.1:8080"), a("127.0.0.2:8080")));
        assert!(!same_socket(a("127.0.0.1:8080"), a("127.0.0.1:8081")));
        assert!(!same_socket(a("127.0.0.1:0"), a("127.0.0.1:0")));
    }
}
