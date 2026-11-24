//! The client certificate check of the TLS layer, for `[server.tls] client_certificates =
//! "optional"`.
//!
//! [`AnyClientCert`] is a rustls [`ClientCertVerifier`] that makes the handshake prove one
//! thing and nothing more: **the client holds the private key of the certificate it sent.**
//!
//! What it checks:
//!
//! - the end-entity certificate parses as an X.509 certificate (rustls-webpki's parser), so
//!   that its public key can be read;
//! - the TLS 1.3 `CertificateVerify` signature, over the handshake transcript, verifies with
//!   that certificate's public key, by [`rustls::crypto::verify_tls13_signature`] with the
//!   signature algorithms of the provider the listener uses (the `ring` provider). That
//!   function maps the signature scheme to exactly one algorithm, and rustls-webpki refuses
//!   a public key of another type or curve, so an ECDSA P-256 scheme never verifies with a
//!   P-384 key.
//!
//! What it does not check, on purpose:
//!
//! - no chain, no trust anchor, no issuer: any certificate, self-signed or not, passes;
//! - no dates, no key usage, no extended key usage, no names;
//! - no revocation (no CRL, no OCSP);
//! - the intermediates the client sent are ignored.
//!
//! It never requires a certificate ([`ClientCertVerifier::client_auth_mandatory`] is
//! `false`): a client without one connects as before. It asks for one
//! ([`ClientCertVerifier::offer_client_auth`] is `true`) with an empty list of acceptable
//! issuers, so a client sends whatever certificate it is configured with.
//!
//! TLS 1.2 is refused: the listener speaks TLS 1.3 only ([`crate::tls`]), so the TLS 1.2
//! method is never called; if it ever were, it fails closed instead of checking a signature.
//!
//! **Why the trust decision is not made here.** The handshake happens once per connection,
//! but which certificates are trusted can change at any time: `POST /admin/agents/reload`
//! swaps the `[[agents]]` and `[[peps]]` lists without a restart. So the TLS layer only proves
//! possession, the certificate is attached to every request of the connection
//! ([`crate::client_cert::ClientCertificate`], set by the accept loop only, never from a
//! header), and each request decides, against its own snapshot of the lists, whether the
//! certificate authenticates a client ([`crate::clientauth`]: its SHA-256 thumbprint must be
//! one the named entry lists, and its dates must hold). A certificate removed by a reload
//! stops working on the next request of a connection that is already open. With session
//! resumption off ([`crate::tls`]), every certificate a request carries was proven in this
//! process, on that connection.

use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::ParsedCertificate;
use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};

/// Accepts any client certificate whose TLS 1.3 handshake signature verifies; see the module
/// documentation for what that does and does not mean.
#[derive(Debug)]
pub(crate) struct AnyClientCert {
    /// The signature algorithms of the listener's provider.
    algs: WebPkiSupportedAlgorithms,
}

impl AnyClientCert {
    /// A verifier that checks handshake signatures with `algs`.
    pub(crate) fn new(algs: WebPkiSupportedAlgorithms) -> Self {
        Self { algs }
    }
}

impl ClientCertVerifier for AnyClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    /// Parse the certificate and nothing else: no chain, no dates (see the module docs).
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        ParsedCertificate::try_from(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    /// Never used: the listener speaks TLS 1.3 only. Refuses.
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General(
            "TLS 1.2 client authentication is not supported".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier() -> AnyClientCert {
        AnyClientCert::new(
            rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn self_signed(
        alg: &'static rcgen::SignatureAlgorithm,
    ) -> (CertificateDer<'static>, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate_for(alg).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["client".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (cert.der().clone(), key)
    }

    #[test]
    fn asks_for_a_certificate_and_never_requires_one() {
        let v = verifier();
        assert!(v.offer_client_auth());
        assert!(!v.client_auth_mandatory());
        assert!(v.root_hint_subjects().is_empty());
        assert!(!v.requires_raw_public_keys());
        assert_eq!(
            v.supported_verify_schemes(),
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        );
    }

    /// Any parseable certificate passes, whatever its issuer or dates; bytes that are not a
    /// certificate do not.
    #[test]
    fn any_parseable_certificate_passes_and_garbage_does_not() {
        let v = verifier();
        let (cert, _) = self_signed(&rcgen::PKCS_ECDSA_P256_SHA256);
        let now = UnixTime::now();
        assert!(v.verify_client_cert(&cert, &[], now).is_ok());
        // Expired a long time ago: dates are not this layer's business.
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["old".to_string()]).unwrap();
        params.not_before = time::OffsetDateTime::from_unix_timestamp(0).unwrap();
        params.not_after = time::OffsetDateTime::from_unix_timestamp(86_400).unwrap();
        let old = params.self_signed(&key).unwrap().der().clone();
        assert!(v.verify_client_cert(&old, &[], now).is_ok());
        for junk in [&b""[..], b"\x30\x03\x02\x01\x01", b"not a certificate"] {
            let der = CertificateDer::from(junk.to_vec());
            assert!(v.verify_client_cert(&der, &[], now).is_err(), "{junk:?}");
        }
    }

    // The signature methods need a `DigitallySignedStruct`, which only rustls can build: they
    // are tested through real handshakes in tests/mtls.rs (a certificate sent with a
    // `CertificateVerify` signed by another key fails the handshake).
}
