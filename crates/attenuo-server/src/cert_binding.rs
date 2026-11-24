//! Certificate-bound access tokens (RFC 8705 §3,
//! [ADR-0022](../../docs/decisions/0022-certificate-bound-tokens.md)).
//!
//! **Binding.** With `[token] tls_client_certificate_bound_access_tokens = true`, a token that
//! `POST /token` issues (hop 0 or an exchange) to an agent that authenticated with its TLS
//! client certificate (`self_signed_tls_client_auth` or `tls_client_auth`, from attenuo's own
//! handshake or from a trusted proxy's `Client-Cert` header) is bound to that certificate: its
//! `cnf` is `{"x5t#S256": <base64url SHA-256 of the certificate's DER>}`. The response says
//! `token_type: "Bearer"`: RFC 8705 §3 has the client send the token as a bearer token, over a
//! connection that shows the certificate. A token has one binding only, so such a request with
//! a `DPoP` header is refused (`dpop_with_certificate_binding`). Off by default; with the
//! setting off nothing is bound to a certificate.
//!
//! **Use.** A certificate-bound token is accepted only on a request whose verified client
//! certificate ([`ClientCertificate`], set by the TLS accept loop or by the forwarding
//! listener's header check, never by anything else) has the same SHA-256, compared in constant
//! time. That holds whatever the setting says: once bound, always bound. Refused, with 401:
//!
//! - no certificate on the request (a plain listener, a TLS connection without one, a
//!   gateway route that sees no agent certificate): `client_certificate_required`;
//! - another certificate: `client_certificate_mismatch`;
//! - a `DPoP` header, or the `DPoP` authorization scheme: `dpop_with_certificate_binding`.
//!
//! **Exchange.** A child of a certificate-bound token is bound to the same certificate, and
//! the exchange request must show that certificate. No `DPoP` header and no
//! `subject_token_dpop` are taken with such a subject token (`dpop_with_certificate_binding`):
//! there is no way to get an unbound child, a key-bound child, or a child bound to another
//! certificate from it. A key-bound (`cnf.jkt`) subject token keeps the DPoP rules of
//! [`crate::dpop`] exactly, whatever this setting says: its child is key-bound.
//!
//! The certificate a token is bound to is the one thing that proves its holder. A new
//! certificate (a rotation) does not carry the binding over: the agent gets new tokens.

use attenuo_proxy::AuthError;
use attenuo_token::Confirmation;
use axum::http::{HeaderMap, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use time::OffsetDateTime;

use crate::client_cert::ClientCertificate;
use crate::dpop::{Dpop, DpopFailure};
use crate::error::ApiError;

/// Code of a certificate-bound token on a request without a verified client certificate.
pub(crate) const CLIENT_CERTIFICATE_REQUIRED: &str = "client_certificate_required";
/// Code of a certificate-bound token on a request with another client certificate.
pub(crate) const CLIENT_CERTIFICATE_MISMATCH: &str = "client_certificate_mismatch";
/// Code of a DPoP proof (or the `DPoP` scheme) where the token is, or would be, bound to a
/// certificate: a token has one binding only.
pub(crate) const DPOP_WITH_CERTIFICATE_BINDING: &str = "dpop_with_certificate_binding";

/// How a token is bound, or how a request proved the binding of the token it presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Binding {
    /// A bearer token.
    #[default]
    None,
    /// Bound to a DPoP key (`cnf.jkt`), proved by a DPoP proof.
    Dpop,
    /// Bound to a TLS client certificate (`cnf.x5t#S256`), shown on the request.
    Cert,
}

impl Binding {
    /// The binding of `cnf`.
    pub(crate) fn of(cnf: Option<&Confirmation>) -> Self {
        match cnf {
            None => Binding::None,
            Some(Confirmation::Jkt(_)) => Binding::Dpop,
            Some(Confirmation::X5tS256(_)) => Binding::Cert,
        }
    }

    /// Bound to a DPoP key: the audit record's `dpop_bound`.
    pub(crate) fn dpop(self) -> bool {
        self == Binding::Dpop
    }

    /// Bound to a certificate: the audit record's `cert_bound`.
    pub(crate) fn cert(self) -> bool {
        self == Binding::Cert
    }

    /// Add `"cert_bound": true` to an audit record's arguments when bound to a certificate.
    /// Records of other requests do not get the member, so they digest as before.
    pub(crate) fn add_to(self, args: &mut serde_json::Value) {
        if self.cert() {
            args["cert_bound"] = true.into();
        }
    }
}

/// Why a certificate binding refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertFailure {
    /// The request has no verified client certificate.
    Required,
    /// The request's client certificate is another one.
    Mismatch,
    /// A DPoP proof (or the `DPoP` scheme) with a certificate-bound token. `issuing`: at
    /// `POST /token`, where the token is about to be bound.
    WithDpop { issuing: bool },
}

impl CertFailure {
    /// The stable code.
    pub(crate) fn code(self) -> &'static str {
        match self {
            CertFailure::Required => CLIENT_CERTIFICATE_REQUIRED,
            CertFailure::Mismatch => CLIENT_CERTIFICATE_MISMATCH,
            CertFailure::WithDpop { .. } => DPOP_WITH_CERTIFICATE_BINDING,
        }
    }
}

impl From<CertFailure> for ApiError {
    fn from(f: CertFailure) -> Self {
        let code = f.code();
        match f {
            CertFailure::Required => ApiError::new(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "the token is bound to a TLS client certificate: send it over a connection \
                 that shows that certificate",
            ),
            CertFailure::Mismatch => ApiError::new(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "the token is bound to another TLS client certificate than the one this \
                 request shows",
            ),
            CertFailure::WithDpop { issuing: false } => ApiError::new(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "the token is bound to a TLS client certificate, not to a DPoP key: send it \
                 with the Bearer scheme and no DPoP proof",
            ),
            CertFailure::WithDpop { issuing: true } => ApiError::bad_request(
                "invalid_request",
                "a token has one binding: this one is, or would be, bound to the TLS client \
                 certificate, so the request must not carry a DPoP proof",
            ),
        }
        .with_description(code)
    }
}

impl From<CertFailure> for AuthError {
    fn from(f: CertFailure) -> Self {
        AuthError::CertificateBinding(f.code().to_owned())
    }
}

/// A refusal of a token's binding: by DPoP or by the certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BindingFailure {
    /// [`crate::dpop`] refused.
    Dpop(DpopFailure),
    /// The certificate binding refused.
    Cert(CertFailure),
}

impl From<DpopFailure> for BindingFailure {
    fn from(f: DpopFailure) -> Self {
        BindingFailure::Dpop(f)
    }
}

impl From<CertFailure> for BindingFailure {
    fn from(f: CertFailure) -> Self {
        BindingFailure::Cert(f)
    }
}

impl From<BindingFailure> for ApiError {
    fn from(f: BindingFailure) -> Self {
        match f {
            BindingFailure::Dpop(d) => d.into(),
            BindingFailure::Cert(c) => c.into(),
        }
    }
}

impl From<BindingFailure> for AuthError {
    fn from(f: BindingFailure) -> Self {
        match f {
            BindingFailure::Dpop(d) => d.into(),
            BindingFailure::Cert(c) => c.into(),
        }
    }
}

/// What a request presents with a token.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Presented<'a> {
    /// The token's verified `cnf`.
    pub(crate) cnf: Option<&'a Confirmation>,
    /// The token.
    pub(crate) token: &'a str,
    /// The request's `DPoP` header.
    pub(crate) proof: Option<&'a str>,
    /// The request's `Authorization` header names the `DPoP` scheme.
    pub(crate) dpop_scheme: bool,
    /// The SHA-256 of the request's verified client certificate.
    pub(crate) cert: Option<&'a [u8; 32]>,
    /// The request's method, for a DPoP proof's `htm`.
    pub(crate) method: &'a str,
    /// The request's URL, for a DPoP proof's `htu`.
    pub(crate) url: &'a str,
}

/// Check the binding of a presented token (the MCP proxy's bearer, `POST /token/renew`, the
/// AuthZEN bearer, an agent's `GET /approvals/{id}`): a certificate-bound token needs the
/// request's certificate ([`check_cert`]) and no DPoP; any other token goes to
/// [`Dpop::check_presented`] as before. Returns how the binding was proved.
///
/// # Errors
///
/// The [`CertFailure`]s of [`check_cert`], [`CertFailure::WithDpop`] (`issuing: false`), and
/// the failures of [`Dpop::check_presented`].
pub(crate) fn check_presented(
    dpop: &Dpop,
    p: &Presented<'_>,
    now: OffsetDateTime,
) -> Result<Binding, BindingFailure> {
    if let Some(Confirmation::X5tS256(bound)) = p.cnf {
        if p.proof.is_some() || p.dpop_scheme {
            return Err(CertFailure::WithDpop { issuing: false }.into());
        }
        check_cert(bound, p.cert)?;
        return Ok(Binding::Cert);
    }
    let dpop_bound = dpop.check_presented(p.cnf, p.token, p.proof, p.method, p.url, now)?;
    Ok(if dpop_bound {
        Binding::Dpop
    } else {
        Binding::None
    })
}

/// Does `cert` (the SHA-256 of the request's verified client certificate) match `bound` (a
/// token's `cnf.x5t#S256`)? Compared in constant time.
///
/// # Errors
///
/// [`CertFailure::Required`] without a certificate; [`CertFailure::Mismatch`] for another one,
/// and for a `bound` value that is not a base64url SHA-256 (the verifier refuses such a token
/// first).
pub(crate) fn check_cert(bound: &str, cert: Option<&[u8; 32]>) -> Result<(), CertFailure> {
    let cert = cert.ok_or(CertFailure::Required)?;
    let bound = URL_SAFE_NO_PAD
        .decode(bound)
        .map_err(|_| CertFailure::Mismatch)?;
    if crate::routes::admin::constant_time_eq(&bound, cert) {
        Ok(())
    } else {
        Err(CertFailure::Mismatch)
    }
}

/// Whether an `Authorization` header names the `DPoP` scheme (RFC 9449 §7.1), in any letter
/// case.
pub(crate) fn dpop_scheme(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("dpop"))
}

/// The certificate a token that `POST /token` issues is bound to: the one that authenticated
/// the agent, when `[token] tls_client_certificate_bound_access_tokens` is on and the agent
/// authenticated with it; `None` otherwise.
pub(crate) fn issuing_cert(
    enabled: bool,
    client: Option<&crate::clientauth::Authenticated>,
) -> Option<&ClientCertificate> {
    client
        .filter(|_| enabled)
        .and_then(crate::clientauth::Authenticated::client_cert)
}

/// The binding of a root token at hop 0: to `cert` ([`issuing_cert`]) when there is one, and
/// then with no `DPoP` header; otherwise by [`Dpop::bind_new`], as before.
///
/// # Errors
///
/// [`CertFailure::WithDpop`] (`issuing: true`) for a `DPoP` header with a certificate binding;
/// the failures of [`Dpop::bind_new`] otherwise.
pub(crate) fn bind_root(
    dpop: &Dpop,
    cert: Option<&ClientCertificate>,
    header: Option<&str>,
    url: &str,
    now: OffsetDateTime,
) -> Result<Option<Confirmation>, BindingFailure> {
    if let Some(cert) = cert {
        if header.is_some() {
            return Err(CertFailure::WithDpop { issuing: true }.into());
        }
        return Ok(Some(Confirmation::x5t_s256(cert.x5t_s256())));
    }
    Ok(dpop.bind_new(header, "POST", url, now)?)
}

/// What an exchange request carries that decides its child's binding.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ExchangeBinding<'a> {
    /// The subject token's verified `cnf`.
    pub(crate) parent: Option<&'a Confirmation>,
    /// The subject token.
    pub(crate) subject_token: &'a str,
    /// The `actor` the child is for.
    pub(crate) actor: &'a str,
    /// The request's `DPoP` header.
    pub(crate) header: Option<&'a str>,
    /// The body's `subject_token_dpop`.
    pub(crate) subject_proof: Option<&'a str>,
    /// The certificate to bind an unbound parent's child to ([`issuing_cert`]).
    pub(crate) issuing: Option<&'a ClientCertificate>,
    /// The SHA-256 of the request's verified client certificate, whoever it authenticated.
    pub(crate) cert: Option<&'a [u8; 32]>,
    /// The `/token` URL a DPoP proof names.
    pub(crate) url: &'a str,
}

/// The binding of an exchange's child (see the module docs):
///
/// - certificate-bound parent: the same certificate, which the request must show, and no DPoP
///   proof of either kind;
/// - key-bound parent: [`Dpop::bind_exchange`], exactly as without certificate binding;
/// - unbound parent: as at hop 0 ([`bind_root`]).
///
/// # Errors
///
/// The [`CertFailure`]s of [`check_cert`] for a certificate-bound parent,
/// [`CertFailure::WithDpop`] (`issuing: true`), and the failures of [`Dpop::bind_exchange`] and
/// [`Dpop::bind_new`].
pub(crate) fn bind_exchange(
    dpop: &Dpop,
    x: &ExchangeBinding<'_>,
    now: OffsetDateTime,
) -> Result<Option<Confirmation>, BindingFailure> {
    match x.parent {
        Some(Confirmation::X5tS256(bound)) => {
            if x.header.is_some() || x.subject_proof.is_some() {
                return Err(CertFailure::WithDpop { issuing: true }.into());
            }
            check_cert(bound, x.cert)?;
            Ok(Some(Confirmation::x5t_s256(bound.clone())))
        }
        Some(parent @ Confirmation::Jkt(_)) => Ok(dpop.bind_exchange(
            Some(parent),
            x.subject_token,
            x.actor,
            x.header,
            x.subject_proof,
            x.url,
            now,
        )?),
        None => bind_root(dpop, x.issuing, x.header, x.url, now),
    }
}

/// Middleware of the MCP proxy's routes: give the proxy the request's verified client
/// certificate as [`attenuo_proxy::ClientCertThumbprint`], from the [`ClientCertificate`] the
/// accept loop or the forwarding listener's header check set, and from nothing else. Any
/// thumbprint already in the extensions is dropped first (none can be: a request off the wire
/// has no extensions).
pub(crate) async fn expose_to_proxy(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    req.extensions_mut()
        .remove::<attenuo_proxy::ClientCertThumbprint>();
    let thumbprint = req
        .extensions()
        .get::<ClientCertificate>()
        .map(|c| attenuo_proxy::ClientCertThumbprint(*c.sha256()));
    if let Some(t) = thumbprint {
        req.extensions_mut().insert(t);
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::CertificateDer;

    fn cert(bytes: &[u8]) -> ClientCertificate {
        ClientCertificate::new(CertificateDer::from(bytes.to_vec()))
    }

    #[test]
    fn the_certificate_must_be_the_bound_one() {
        let a = cert(b"a");
        let b = cert(b"b");
        let bound = a.x5t_s256();
        assert_eq!(check_cert(&bound, Some(a.sha256())), Ok(()));
        assert_eq!(
            check_cert(&bound, Some(b.sha256())),
            Err(CertFailure::Mismatch)
        );
        assert_eq!(check_cert(&bound, None), Err(CertFailure::Required));
        assert_eq!(
            check_cert("not base64!", Some(a.sha256())),
            Err(CertFailure::Mismatch)
        );
        // A prefix of the right thumbprint is not it.
        assert_eq!(
            check_cert(&bound[..42], Some(a.sha256())),
            Err(CertFailure::Mismatch)
        );
    }

    #[test]
    fn the_binding_of_a_cnf() {
        assert_eq!(Binding::of(None), Binding::None);
        let j = Confirmation::jkt("x");
        let c = Confirmation::x5t_s256("x");
        assert!(Binding::of(Some(&j)).dpop() && !Binding::of(Some(&j)).cert());
        assert!(Binding::of(Some(&c)).cert() && !Binding::of(Some(&c)).dpop());
        let mut args = serde_json::json!({"a": 1});
        Binding::Dpop.add_to(&mut args);
        Binding::None.add_to(&mut args);
        assert_eq!(args, serde_json::json!({"a": 1}));
        Binding::Cert.add_to(&mut args);
        assert_eq!(args, serde_json::json!({"a": 1, "cert_bound": true}));
    }

    #[test]
    fn the_dpop_scheme_is_seen_in_any_case() {
        let mut h = HeaderMap::new();
        assert!(!dpop_scheme(&h));
        for (v, dpop) in [
            ("Bearer t", false),
            ("DPoP t", true),
            ("dpop t", true),
            ("Basic t", false),
        ] {
            h.insert(axum::http::header::AUTHORIZATION, v.parse().unwrap());
            assert_eq!(dpop_scheme(&h), dpop, "{v}");
        }
    }

    #[test]
    fn refusals_have_their_codes_and_statuses() {
        for (f, status, error, code) in [
            (
                CertFailure::Required,
                401,
                "invalid_token",
                CLIENT_CERTIFICATE_REQUIRED,
            ),
            (
                CertFailure::Mismatch,
                401,
                "invalid_token",
                CLIENT_CERTIFICATE_MISMATCH,
            ),
            (
                CertFailure::WithDpop { issuing: false },
                401,
                "invalid_token",
                DPOP_WITH_CERTIFICATE_BINDING,
            ),
            (
                CertFailure::WithDpop { issuing: true },
                400,
                "invalid_request",
                DPOP_WITH_CERTIFICATE_BINDING,
            ),
        ] {
            let e = ApiError::from(f);
            assert_eq!(e.status.as_u16(), status);
            assert_eq!(e.code, error);
            assert_eq!(e.stable_code(), code);
            assert_eq!(AuthError::from(f).reason(), code);
        }
    }
}
