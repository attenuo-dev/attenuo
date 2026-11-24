//! Signed approval tokens (output labelling, design section 3.7, ADR-0009).
//!
//! When a gated call's approval is granted, the server hands out a JWT signed with the same
//! issuer key as its delegation tokens (same `kid`, same JWKS), with header
//! `typ: attenuo-approval+jwt` and these claims:
//!
//! | Claim | Value |
//! |---|---|
//! | `iss`, `aud` | the issuer's `iss` and `aud`, as in a delegation token |
//! | `sub` | the approver: the user's `sub`, or `urn:attenuo:admin` for an operator |
//! | `by` | `user` or `operator` |
//! | `chain_id` | the delegation run (the lease of its first hop) |
//! | `lease` | the lease of the hop that made the gated call |
//! | `ch` | the call hash (`ToolCall::call_hash`) |
//! | `iat` | when the approval was granted |
//! | `exp` | the approval's `expires_at` |
//! | `jti` | the approval id |
//! | `cnf.jkt` | the calling hop's key thumbprint, when that hop's token is DPoP-bound |
//!
//! Every claim comes from the stored approval, so the token for one grant is always the same
//! bytes (Ed25519 signatures are deterministic). The token is a portable proof of the grant,
//! not the grant itself: the server's approval record is what makes it single use.
//! [`Verifier::verify_approval`] checks signature, `typ`, `iss`, `aud` and `exp`;
//! [`ApprovalClaims::check_binding`] checks the claims against a call.

use jsonwebtoken::{Algorithm, Header};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::dpop::Confirmation;
use crate::error::TokenError;
use crate::issuer::Issuer;
use crate::verifier::Verifier;

/// Header `typ` of an approval token.
pub const APPROVAL_TOKEN_TYPE: &str = "attenuo-approval+jwt";

/// The claims of an approval token (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalClaims {
    /// The issuer that signed the approval.
    pub iss: String,
    /// The audience the approval is for.
    pub aud: String,
    /// The approver's subject.
    pub sub: String,
    /// `user` or `operator`.
    pub by: String,
    /// The delegation run the approval is for (its chain id).
    pub chain_id: String,
    /// The lease of the hop whose call was approved.
    pub lease: String,
    /// The call hash the approval is bound to.
    pub ch: String,
    /// When the approval was granted, Unix seconds.
    pub iat: i64,
    /// Expires at, Unix seconds.
    pub exp: i64,
    /// The approval id.
    pub jti: String,
    /// The calling hop's key, when its token is DPoP-bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,
}

/// What [`Issuer::issue_approval`] signs: a granted approval. `iss` and `aud` come from the
/// issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalGrant<'a> {
    /// The approval id (`jti`).
    pub approval_id: &'a str,
    /// The approver's subject (`sub`).
    pub approver: &'a str,
    /// `user` or `operator` (`by`).
    pub by: &'a str,
    /// The delegation run (`chain_id`).
    pub chain_id: &'a str,
    /// The calling hop's lease (`lease`).
    pub lease: &'a str,
    /// The call hash (`ch`).
    pub call_hash: &'a str,
    /// When the approval was granted (`iat`).
    pub granted_at: OffsetDateTime,
    /// When the approval expires (`exp`).
    pub expires_at: OffsetDateTime,
    /// `cnf.jkt` of the calling hop's token, if it is bound.
    pub jkt: Option<&'a str>,
}

/// Which binding claim of an approval token did not match the call it was presented with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalMismatch {
    /// `chain_id` names another delegation run.
    #[error("the approval token is for another delegation run (`chain_id`)")]
    ChainId,
    /// `lease` names another hop.
    #[error("the approval token is for another hop (`lease`)")]
    Lease,
    /// `ch` is the hash of another call.
    #[error("the approval token is for another call (`ch`)")]
    CallHash,
    /// `cnf.jkt` does not match the calling hop's key binding.
    #[error(
        "the approval token is bound to another key, or the call's binding differs (`cnf.jkt`)"
    )]
    Key,
}

impl ApprovalClaims {
    /// Check the binding claims against a call: the call's run, the calling hop's lease, the
    /// call hash, and the calling hop's key thumbprint (`None` for a bearer hop). The key must
    /// match exactly: a token minted for a bound hop is refused without that hop's key, and a
    /// token with no `cnf` is refused for a bound hop.
    ///
    /// # Errors
    ///
    /// The first claim that differs, checked in this order: [`ApprovalMismatch::ChainId`],
    /// [`ApprovalMismatch::Lease`], [`ApprovalMismatch::CallHash`], [`ApprovalMismatch::Key`]
    /// (also when only one of the token and the hop has a key).
    pub fn check_binding(
        &self,
        chain_id: &str,
        lease: &str,
        call_hash: &str,
        jkt: Option<&str>,
    ) -> Result<(), ApprovalMismatch> {
        if self.chain_id != chain_id {
            return Err(ApprovalMismatch::ChainId);
        }
        if self.lease != lease {
            return Err(ApprovalMismatch::Lease);
        }
        if self.ch != call_hash {
            return Err(ApprovalMismatch::CallHash);
        }
        // An approval is bound to a key only, never to a certificate.
        let bound = match &self.cnf {
            None => None,
            Some(Confirmation::Jkt(k)) => Some(k.as_str()),
            Some(Confirmation::X5tS256(_)) => return Err(ApprovalMismatch::Key),
        };
        if bound != jkt {
            return Err(ApprovalMismatch::Key);
        }
        Ok(())
    }

    /// `exp` as a time.
    pub fn expires_at(&self) -> Option<OffsetDateTime> {
        OffsetDateTime::from_unix_timestamp(self.exp).ok()
    }
}

impl Issuer {
    /// Sign an approval token for a granted approval (see the module docs), with the current
    /// key and its `kid`.
    ///
    /// # Errors
    ///
    /// [`TokenError::Key`] or [`TokenError::Malformed`] if `jsonwebtoken` cannot encode or sign
    /// the claims, which does not happen with the issuer's Ed25519 key.
    pub fn issue_approval(&self, grant: &ApprovalGrant<'_>) -> Result<String, TokenError> {
        let claims = ApprovalClaims {
            iss: self.config().issuer.clone(),
            aud: self.config().audience.clone(),
            sub: grant.approver.to_owned(),
            by: grant.by.to_owned(),
            chain_id: grant.chain_id.to_owned(),
            lease: grant.lease.to_owned(),
            ch: grant.call_hash.to_owned(),
            iat: grant.granted_at.unix_timestamp(),
            exp: grant.expires_at.unix_timestamp(),
            jti: grant.approval_id.to_owned(),
            cnf: grant.jkt.map(Confirmation::jkt),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some(APPROVAL_TOKEN_TYPE.to_owned());
        header.kid = Some(self.key_id());
        Ok(jsonwebtoken::encode(&header, &claims, self.encoding_key())?)
    }
}

impl Verifier {
    /// Verify an approval token as of `now`: the EdDSA signature under a trusted key (by
    /// `kid`), header `typ` = [`APPROVAL_TOKEN_TYPE`], `iss`, `aud`, and `exp` after `now`.
    /// The binding claims are checked separately ([`ApprovalClaims::check_binding`]). A
    /// delegation token is refused here ([`TokenError::WrongType`]), as an approval token is
    /// refused by [`Verifier::verify`].
    ///
    /// # Errors
    ///
    /// [`TokenError::UnknownKeyId`] for a `kid` no trusted key has,
    /// [`TokenError::InvalidSignature`] for a signature no candidate key verifies,
    /// [`TokenError::Malformed`] for a token that is not a JWT of approval claims or has a
    /// malformed `cnf.jkt`, [`TokenError::WrongType`], [`TokenError::WrongIssuer`],
    /// [`TokenError::WrongAudience`], and [`TokenError::Expired`] when `exp` is at or before
    /// `now`.
    pub fn verify_approval(
        &self,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<ApprovalClaims, TokenError> {
        let (header, claims) = self.decode_signed::<ApprovalClaims>(token)?;
        if header.typ.as_deref() != Some(APPROVAL_TOKEN_TYPE) {
            return Err(TokenError::WrongType);
        }
        if claims.iss != self.issuer() {
            return Err(TokenError::WrongIssuer);
        }
        if claims.aud != self.audience() {
            return Err(TokenError::WrongAudience);
        }
        if claims.exp <= now.unix_timestamp() {
            return Err(TokenError::Expired);
        }
        match &claims.cnf {
            Some(c @ Confirmation::Jkt(_)) if !c.is_well_formed() => {
                return Err(TokenError::Malformed(
                    "`cnf.jkt` is not a SHA-256 thumbprint".into(),
                ));
            }
            // This server never binds an approval to a certificate.
            Some(Confirmation::X5tS256(_)) => {
                return Err(TokenError::Malformed(
                    "an approval token is never bound to a certificate (`cnf.x5t#S256`)".into(),
                ));
            }
            _ => {}
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IssuerConfig;
    use attenuo_core::{AgentId, Capability, CapabilitySet, OriginatingUser};
    use time::{macros::datetime, Duration};

    const JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

    fn issuer() -> Issuer {
        Issuer::generate(IssuerConfig {
            issuer: "https://attenuo.test".into(),
            audience: "attenuo".into(),
            max_depth: 4,
            default_ttl: Duration::minutes(5),
        })
    }

    fn t0() -> OffsetDateTime {
        datetime!(2026-10-24 12:00 UTC)
    }

    fn grant(jkt: Option<&str>) -> ApprovalGrant<'_> {
        ApprovalGrant {
            approval_id: "a1",
            approver: "user:alice",
            by: "user",
            chain_id: "L0",
            lease: "L1",
            call_hash: "ch1",
            granted_at: t0(),
            expires_at: t0() + Duration::seconds(120),
            jkt,
        }
    }

    #[test]
    fn issue_and_verify_round_trip() {
        let i = issuer();
        let token = i.issue_approval(&grant(Some(JKT))).unwrap();
        // Deterministic: the same grant gives the same token.
        assert_eq!(token, i.issue_approval(&grant(Some(JKT))).unwrap());
        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.typ.as_deref(), Some(APPROVAL_TOKEN_TYPE));
        assert_eq!(header.kid, Some(i.key_id()));
        let c = i.verifier().verify_approval(&token, t0()).unwrap();
        assert_eq!(c.jti, "a1");
        assert_eq!(c.iss, "https://attenuo.test");
        assert_eq!(c.aud, "attenuo");
        assert_eq!(c.by, "user");
        assert_eq!(c.cnf.as_ref().unwrap().key_thumbprint(), Some(JKT));
        assert_eq!(c.check_binding("L0", "L1", "ch1", Some(JKT)), Ok(()));
        assert_eq!(
            c.check_binding("L9", "L1", "ch1", Some(JKT)),
            Err(ApprovalMismatch::ChainId)
        );
        assert_eq!(
            c.check_binding("L0", "L2", "ch1", Some(JKT)),
            Err(ApprovalMismatch::Lease)
        );
        assert_eq!(
            c.check_binding("L0", "L1", "ch2", Some(JKT)),
            Err(ApprovalMismatch::CallHash)
        );
        assert_eq!(
            c.check_binding("L0", "L1", "ch1", None),
            Err(ApprovalMismatch::Key)
        );
        let bearer = i
            .verifier()
            .verify_approval(&i.issue_approval(&grant(None)).unwrap(), t0())
            .unwrap();
        assert!(bearer.cnf.is_none());
        assert_eq!(
            bearer.check_binding("L0", "L1", "ch1", Some(JKT)),
            Err(ApprovalMismatch::Key)
        );
        // An approval bound to a certificate matches no call, with a key or without one.
        let mut cert = bearer.clone();
        cert.cnf = Some(Confirmation::x5t_s256(JKT));
        for jkt in [None, Some(JKT)] {
            assert_eq!(
                cert.check_binding("L0", "L1", "ch1", jkt),
                Err(ApprovalMismatch::Key)
            );
        }
    }

    #[test]
    fn expiry_key_and_type_are_checked() {
        let i = issuer();
        let token = i.issue_approval(&grant(None)).unwrap();
        assert!(matches!(
            i.verifier()
                .verify_approval(&token, t0() + Duration::seconds(120)),
            Err(TokenError::Expired)
        ));
        assert!(matches!(
            issuer().verifier().verify_approval(&token, t0()),
            Err(TokenError::UnknownKeyId(_))
        ));
        // A delegation token is not an approval token, and the other way round.
        let user = OriginatingUser {
            subject: "user:alice".into(),
            issuer: "https://idp.test".into(),
            authenticated_at: t0(),
            attributes: Default::default(),
        };
        let delegation = i
            .issue_root(
                user,
                AgentId::new("a"),
                CapabilitySet::from_iter([Capability::new("s", "t")]),
                None,
                t0(),
            )
            .unwrap();
        assert!(matches!(
            i.verifier().verify_approval(&delegation.token, t0()),
            Err(TokenError::WrongType) | Err(TokenError::Malformed(_))
        ));
        assert!(i.verifier().verify(&token, t0()).is_err());
        // A tampered payload fails the signature.
        let mut parts: Vec<&str> = token.split('.').collect();
        let other = i
            .issue_approval(&ApprovalGrant {
                call_hash: "ch-evil",
                ..grant(None)
            })
            .unwrap();
        let other_payload = other.split('.').nth(1).unwrap().to_owned();
        parts[1] = &other_payload;
        assert!(matches!(
            i.verifier().verify_approval(&parts.join("."), t0()),
            Err(TokenError::InvalidSignature)
        ));
    }

    /// The wire format, pinned: this exact token is verified by the Python and TypeScript SDK
    /// tests (`verify_approval_token`, `verifyApprovalToken`) against the JWKS below, with
    /// `now` = `iat`. If this changes, those fixtures must change with it.
    #[test]
    fn wire_format_is_pinned_for_the_sdks() {
        const PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
            MC4CAQAwBQYDK2VwBCIEID5wG4j128wRESlsagZytRF1giPExiQJqUaD10xxL1r+\n\
            -----END PRIVATE KEY-----\n";
        let i = Issuer::from_pem(
            IssuerConfig {
                issuer: "https://attenuo.test".into(),
                audience: "attenuo".into(),
                max_depth: 4,
                default_ttl: Duration::minutes(5),
            },
            PEM,
        )
        .unwrap();
        let token = i
            .issue_approval(&ApprovalGrant {
                approval_id: "0f8e6c1a-4b7d-4f61-9a39-2f4f5b0e8d11",
                approver: "alice",
                by: "user",
                chain_id: "lease-root",
                lease: "lease-hop",
                call_hash: "ab".repeat(32).as_str(),
                granted_at: t0(),
                expires_at: t0() + Duration::seconds(120),
                jkt: Some(JKT),
            })
            .unwrap();
        let jwk_x = {
            use base64::Engine;
            let pem = i.public_key_pem();
            let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
            let der = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap();
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&der[12..])
        };
        assert_eq!(t0().unix_timestamp(), 1_792_843_200);
        assert_eq!(jwk_x, "psIk2NjWmiuoUxoim49SIawYPoOBE8gaMWWVX9fpjVU");
        assert_eq!(i.key_id(), "1OiSA9mGwRnxk7pfP2CCGw");
        assert_eq!(token, FIXTURE);
    }

    const FIXTURE: &str = concat!(
        "eyJ0eXAiOiJhdHRlbnVvLWFwcHJvdmFsK2p3dCIsImFsZyI6IkVkRFNBIiwia2lkIjoiMU9pU0E5bUd3Um54azdwZlAyQ0NHdyJ9.",
        "eyJpc3MiOiJodHRwczovL2F0dGVudW8udGVzdCIsImF1ZCI6ImF0dGVudW8iLCJzdWIiOiJhbGljZSIsImJ5IjoidXNlciIsImNoYWluX2lkIjoibGVhc2Utcm9vdCIsImxlYXNlIjoibGVhc2UtaG9wIiwiY2giOiJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiIiwiaWF0IjoxNzkyODQzMjAwLCJleHAiOjE3OTI4NDMzMjAsImp0aSI6IjBmOGU2YzFhLTRiN2QtNGY2MS05YTM5LTJmNGY1YjBlOGQxMSIsImNuZiI6eyJqa3QiOiIwWmNPQ09SWk5ZeS1EV3BxcTMwalp5SkdIVE4wZDJIZ2xCVjN1aWd1QTRJIn19.",
        "YMQGXdHjU1Mzr1i15LY7f74Zl6XliQFvHVBs1FzW0mahmH_ngo3PHkfsZWltnvBvsLrv5GQuSXmCxg-IP45kAw"
    );
}
