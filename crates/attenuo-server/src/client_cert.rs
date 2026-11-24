//! The client certificate of a TLS connection, as every request on that connection carries it.
//!
//! The accept loop ([`crate::listen`]) takes the end-entity certificate the client sent in its
//! TLS handshake (proven by [`crate::client_cert_verifier::AnyClientCert`]) and puts a
//! [`ClientCertificate`] into the extensions of each request of the connection. Nothing else
//! sets it: no header is ever read for it (`Client-Cert`, `X-Forwarded-Client-Cert` and the
//! like are ignored). Client authentication ([`crate::clientauth`]) decides per request whether
//! it authenticates anyone.

use std::sync::{Arc, OnceLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rustls::pki_types::{CertificateDer, UnixTime};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

/// Most intermediate certificates kept from a client's handshake, after its own certificate.
/// A chain with more is kept without them and refused by the CA check
/// ([`crate::client_pki`]); a client certificate from a CA rarely needs more than one or
/// two. The whole certificate message is at most 64 KiB (rustls' limit for a handshake
/// message), so this also bounds what a connection keeps.
pub(crate) const MAX_INTERMEDIATES: usize = 8;

/// The end-entity certificate the client proved it holds the key of, with its SHA-256
/// thumbprint, and the other certificates the client sent after it (the intermediates, for
/// the CA check of `tls_client_auth`). Cheap to clone: one per connection, shared by its
/// requests.
#[derive(Clone)]
pub(crate) struct ClientCertificate(Arc<Inner>);

struct Inner {
    der: CertificateDer<'static>,
    sha256: [u8; 32],
    /// The certificates after the first, in the order the client sent them; `None` when it
    /// sent more than [`MAX_INTERMEDIATES`].
    intermediates: Option<Vec<CertificateDer<'static>>>,
}

impl std::fmt::Debug for ClientCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ClientCertificate")
            .field(&self.x5t_s256())
            .finish()
    }
}

/// Why a certificate whose thumbprint is pinned does not authenticate, for the debug log only:
/// every one is answered as any other failed client authentication (SR-110).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotUsable {
    /// `notAfter` is in the past.
    Expired,
    /// `notBefore` is in the future.
    NotYetValid,
    /// rustls-webpki refuses it as a client certificate for another reason: it is a CA
    /// certificate (`basicConstraints` `CA:TRUE`), its extended key usage leaves out
    /// `clientAuth`, it has an unknown critical extension, its signature does not verify with
    /// its own key, and the like.
    Refused,
}

impl NotUsable {
    /// The reason in the debug log.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            NotUsable::Expired => "certificate_expired",
            NotUsable::NotYetValid => "certificate_not_yet_valid",
            NotUsable::Refused => "certificate_not_usable",
        }
    }
}

impl ClientCertificate {
    /// The certificate `der`, with no intermediates.
    #[cfg(test)]
    pub(crate) fn new(der: CertificateDer<'static>) -> Self {
        Self::with_intermediates(der, Some(Vec::new()))
    }

    /// The certificates the client sent in its TLS handshake, its own first: `None` when it
    /// sent none.
    pub(crate) fn from_handshake(chain: &[CertificateDer<'_>]) -> Option<Self> {
        let (leaf, rest) = chain.split_first()?;
        let intermediates = (rest.len() <= MAX_INTERMEDIATES)
            .then(|| rest.iter().map(|c| c.clone().into_owned()).collect());
        Some(Self::with_intermediates(
            leaf.clone().into_owned(),
            intermediates,
        ))
    }

    fn with_intermediates(
        der: CertificateDer<'static>,
        intermediates: Option<Vec<CertificateDer<'static>>>,
    ) -> Self {
        let sha256 = Sha256::digest(der.as_ref()).into();
        Self(Arc::new(Inner {
            der,
            sha256,
            intermediates,
        }))
    }

    /// The end-entity certificate's DER bytes.
    pub(crate) fn der(&self) -> &CertificateDer<'static> {
        &self.0.der
    }

    /// The certificates the client sent after its own, for path building; `None` when it
    /// sent more than [`MAX_INTERMEDIATES`].
    pub(crate) fn intermediates(&self) -> Option<&[CertificateDer<'static>]> {
        self.0.intermediates.as_deref()
    }

    /// The SHA-256 of the certificate's DER bytes.
    pub(crate) fn sha256(&self) -> &[u8; 32] {
        &self.0.sha256
    }

    /// The thumbprint as RFC 8705 §3.1 `x5t#S256` writes it: base64url, no padding.
    pub(crate) fn x5t_s256(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.sha256)
    }

    /// The member an audit record of a request authenticated by this certificate carries in its
    /// digested arguments: `{"x5t#S256": ..., "source": "tls"}`.
    pub(crate) fn audit_value(&self) -> serde_json::Value {
        serde_json::json!({ "x5t#S256": self.x5t_s256(), "source": "tls" })
    }

    /// Whether the certificate is usable as a client certificate at `now`, as rustls-webpki
    /// checks one that chains to itself as the only trust anchor: within its validity dates,
    /// not a CA certificate, `clientAuth` in its extended key usage when it has one, no unknown
    /// critical extension, and signed by its own key. The same rules as for a certificate a
    /// CA issued, with the certificate as its own CA; no revocation check.
    pub(crate) fn check_usable(&self, now: OffsetDateTime) -> Result<(), NotUsable> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(self.0.der.clone())
            .map_err(|_| NotUsable::Refused)?;
        let verifier =
            rustls::server::WebPkiClientVerifier::builder_with_provider(roots.into(), provider())
                .build()
                .map_err(|_| NotUsable::Refused)?;
        let secs = u64::try_from(now.unix_timestamp()).unwrap_or(0);
        let at = UnixTime::since_unix_epoch(std::time::Duration::from_secs(secs));
        match verifier.verify_client_cert(&self.0.der, &[], at) {
            Ok(_) => Ok(()),
            Err(rustls::Error::InvalidCertificate(e)) => Err(match e {
                rustls::CertificateError::Expired
                | rustls::CertificateError::ExpiredContext { .. } => NotUsable::Expired,
                rustls::CertificateError::NotValidYet
                | rustls::CertificateError::NotValidYetContext { .. } => NotUsable::NotYetValid,
                _ => NotUsable::Refused,
            }),
            Err(_) => Err(NotUsable::Refused),
        }
    }
}

/// The `ring` provider, the listener's, made once.
pub(crate) fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    static PROVIDER: OnceLock<Arc<rustls::crypto::CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| Arc::new(rustls::crypto::ring::default_provider()))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(secs).unwrap()
    }

    /// A self-signed certificate made with `edit`.
    fn cert(edit: impl FnOnce(&mut rcgen::CertificateParams)) -> ClientCertificate {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["client".to_string()]).unwrap();
        params.not_before = at(1_000_000);
        params.not_after = at(2_000_000);
        edit(&mut params);
        ClientCertificate::new(params.self_signed(&key).unwrap().der().clone())
    }

    /// The thumbprint is the SHA-256 of the DER bytes, as `openssl x509 -outform DER | openssl
    /// dgst -sha256` prints it in hex, and base64url for `x5t#S256`.
    #[test]
    fn the_thumbprint_is_the_sha256_of_the_der() {
        // A fixed vector: SHA-256("abc").
        let abc = ClientCertificate::new(CertificateDer::from(b"abc".to_vec()));
        assert_eq!(
            hex::encode(abc.sha256()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            abc.x5t_s256(),
            "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
        );
        assert_eq!(
            abc.audit_value(),
            serde_json::json!({"x5t#S256": "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0", "source": "tls"})
        );
    }

    /// The handshake's chain: the first certificate is the client's, the rest are kept as
    /// intermediates, up to [`MAX_INTERMEDIATES`].
    #[test]
    fn the_handshake_chain_is_kept_up_to_a_limit() {
        assert!(ClientCertificate::from_handshake(&[]).is_none());
        let der = |b: &[u8]| CertificateDer::from(b.to_vec());
        let leaf = ClientCertificate::from_handshake(&[der(b"leaf")]).unwrap();
        assert_eq!(leaf.der().as_ref(), b"leaf");
        assert_eq!(leaf.intermediates(), Some(&[][..]));
        let chain: Vec<_> = std::iter::once(der(b"leaf"))
            .chain((0..MAX_INTERMEDIATES).map(|i| der(&[u8::try_from(i).unwrap()])))
            .collect();
        let full = ClientCertificate::from_handshake(&chain).unwrap();
        assert_eq!(full.intermediates().unwrap(), &chain[1..]);
        assert_eq!(full.sha256(), leaf.sha256());
        let mut long = chain.clone();
        long.push(der(b"one too many"));
        let long = ClientCertificate::from_handshake(&long).unwrap();
        assert_eq!(long.der().as_ref(), b"leaf");
        assert!(long.intermediates().is_none());
        assert!(ClientCertificate::new(der(b"x"))
            .intermediates()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn dates_are_checked() {
        let c = cert(|_| {});
        assert_eq!(c.check_usable(at(1_500_000)), Ok(()));
        assert_eq!(c.check_usable(at(2_000_001)), Err(NotUsable::Expired));
        assert_eq!(c.check_usable(at(999_999)), Err(NotUsable::NotYetValid));
    }

    #[test]
    fn a_ca_certificate_or_a_server_only_certificate_is_not_usable() {
        let now = at(1_500_000);
        let ca = cert(|p| p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained));
        assert_eq!(ca.check_usable(now), Err(NotUsable::Refused));
        let server = cert(|p| {
            p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        });
        assert_eq!(server.check_usable(now), Err(NotUsable::Refused));
        let client = cert(|p| {
            p.is_ca = rcgen::IsCa::ExplicitNoCa;
            p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        });
        assert_eq!(client.check_usable(now), Ok(()));
        // No subject alternative name at all is fine: names are not checked.
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.not_before = at(1_000_000);
        params.not_after = at(2_000_000);
        let bare = ClientCertificate::new(params.self_signed(&key).unwrap().der().clone());
        assert_eq!(bare.check_usable(now), Ok(()));
        let junk = ClientCertificate::new(CertificateDer::from(b"junk".to_vec()));
        assert_eq!(junk.check_usable(now), Err(NotUsable::Refused));
        assert_eq!(NotUsable::Expired.reason(), "certificate_expired");
    }

    /// A certificate signed by a CA (not self-signed) is refused by this check: it does not
    /// chain to itself. This method is for self-signed certificates only.
    #[test]
    fn a_certificate_issued_by_another_key_is_not_usable() {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.not_before = at(1_000_000);
        ca_params.not_after = at(2_000_000);
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["client".to_string()]).unwrap();
        params.not_before = at(1_000_000);
        params.not_after = at(2_000_000);
        let leaf = params.signed_by(&key, &issuer).unwrap();
        let c = ClientCertificate::new(leaf.der().clone());
        assert_eq!(c.check_usable(at(1_500_000)), Err(NotUsable::Refused));
    }
}
