//! Strict verification of delegation tokens.

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use onbehalf_core::DelegationChain;
use time::OffsetDateTime;

use crate::claims::{canonical_user_bytes, ActClaim, Claims, TOKEN_TYPE};
use crate::error::TokenError;
use crate::keys::PublicKey;

/// A successfully verified token: the chain to authorize against and the full claim set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedToken {
    /// The delegation chain, already validated at the verification time.
    pub chain: DelegationChain,
    /// All claims as they appeared in the token.
    pub claims: Claims,
}

/// Public-key-only verifier for delegation tokens.
///
/// A `Verifier` holds no secret and can live in every proxy or resource server. It trusts one
/// issuer key (v0); the originating-user signature `ou_sig` is checked against the same key.
#[derive(Clone)]
pub struct Verifier {
    public_key: PublicKey,
    decoding_key: DecodingKey,
    issuer: String,
    audience: String,
    max_depth: usize,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("public_key", &self.public_key)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("max_depth", &self.max_depth)
            .finish_non_exhaustive()
    }
}

impl Verifier {
    pub(crate) fn new(
        public_key: PublicKey,
        issuer: String,
        audience: String,
        max_depth: usize,
    ) -> Self {
        let decoding_key = DecodingKey::from_ed_der(public_key.raw());
        Self {
            public_key,
            decoding_key,
            issuer,
            audience,
            max_depth,
        }
    }

    /// Build a verifier from the issuer's `PUBLIC KEY` PEM (see `Issuer::public_key_pem`).
    pub fn from_public_pem(
        issuer: &str,
        audience: &str,
        max_depth: usize,
        public_pem: &str,
    ) -> Result<Self, TokenError> {
        Ok(Self::new(
            PublicKey::from_pem(public_pem)?,
            issuer.to_owned(),
            audience.to_owned(),
            max_depth,
        ))
    }

    /// The issuer identifier this verifier accepts.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The audience this verifier accepts.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Maximum delegation depth this verifier accepts.
    pub fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// Verify `token` as of `now`.
    ///
    /// Checks, in order: EdDSA signature; header and claim `typ`; `iss`; `aud`; `exp` against
    /// `now`; `sub`/`act` consistency with the chain; `ou_sig` over the originating-user block;
    /// and finally `chain.validate_at(now, max_depth)`. Time is taken from `now`, never from the
    /// system clock, so callers control leeway and tests are deterministic.
    pub fn verify(&self, token: &str, now: OffsetDateTime) -> Result<VerifiedToken, TokenError> {
        // Let jsonwebtoken check only the signature and algorithm; every other check below
        // uses the caller's clock and maps to a precise TokenError variant.
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();

        let data = jsonwebtoken::decode::<Claims>(token, &self.decoding_key, &validation)?;
        let claims = data.claims;

        if data.header.typ.as_deref() != Some(TOKEN_TYPE) || claims.typ != TOKEN_TYPE {
            return Err(TokenError::WrongType);
        }
        if claims.iss != self.issuer {
            return Err(TokenError::WrongIssuer);
        }
        if claims.aud != self.audience {
            return Err(TokenError::WrongAudience);
        }
        if claims.exp <= now.unix_timestamp() {
            return Err(TokenError::Expired);
        }
        if claims.sub != claims.chain.originating_user.subject {
            return Err(TokenError::Malformed(
                "`sub` does not match the chain's originating user".into(),
            ));
        }
        if ActClaim::from_chain(&claims.chain).as_ref() != Some(&claims.act) {
            return Err(TokenError::Malformed(
                "`act` does not match the chain's hops".into(),
            ));
        }
        let last_exp = claims
            .chain
            .hops
            .last()
            .map(|h| h.expires_at.unix_timestamp())
            .ok_or(TokenError::Chain(onbehalf_core::ChainError::NoHops))?;
        if last_exp != claims.exp {
            return Err(TokenError::Malformed(
                "`exp` does not match the last hop's expiry".into(),
            ));
        }
        let user_bytes = canonical_user_bytes(&claims.chain.originating_user);
        if !self.public_key.verify_detached(&user_bytes, &claims.ou_sig) {
            return Err(TokenError::InvalidSignature);
        }
        claims.chain.validate_at(now, self.max_depth)?;

        Ok(VerifiedToken {
            chain: claims.chain.clone(),
            claims,
        })
    }
}
