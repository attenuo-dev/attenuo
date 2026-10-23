//! Strict verification of delegation tokens.

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use onbehalf_core::DelegationChain;
use time::OffsetDateTime;

use crate::claims::{ou_sig_message, ActClaim, Claims, OU_SIG_VERSION, TOKEN_TYPE};
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
/// A `Verifier` holds no secret and can live in every proxy or resource server. It trusts a set
/// of issuer keys, each named by its `kid` (normally the current key plus, during a rotation,
/// the retired one). A token whose header names a `kid` is checked against that key only; an
/// unknown `kid` is rejected. A token without a `kid` is tried against each key. The
/// originating-user signature `ou_sig` (version 2 only) must verify under the trusted key its
/// `ou_kid` names: it is made once at the root and copied into children, which may be signed
/// by a newer key.
#[derive(Clone)]
pub struct Verifier {
    keys: Vec<TrustedKey>,
    issuer: String,
    audience: String,
    max_depth: usize,
}

#[derive(Clone)]
struct TrustedKey {
    kid: String,
    public_key: PublicKey,
    decoding_key: DecodingKey,
}

impl TrustedKey {
    fn new(public_key: PublicKey) -> Self {
        Self {
            kid: public_key.kid(),
            decoding_key: DecodingKey::from_ed_der(public_key.raw()),
            public_key,
        }
    }
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field(
                "kids",
                &self.keys.iter().map(|k| &k.kid).collect::<Vec<_>>(),
            )
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
        Self {
            keys: vec![TrustedKey::new(public_key)],
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

    /// Trust one more key, given as a `PUBLIC KEY` PEM (for example a retired issuer key
    /// during a rotation). Adding a key that is already trusted is a no-op.
    pub fn with_public_pem(mut self, public_pem: &str) -> Result<Self, TokenError> {
        self.add_key(PublicKey::from_pem(public_pem)?);
        Ok(self)
    }

    pub(crate) fn add_key(&mut self, key: PublicKey) {
        if !self.keys.iter().any(|k| k.public_key == key) {
            self.keys.push(TrustedKey::new(key));
        }
    }

    /// The `kid` of every trusted key.
    pub fn key_ids(&self) -> Vec<String> {
        self.keys.iter().map(|k| k.kid.clone()).collect()
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
    /// `now`; `sub`/`act` consistency with the chain; `ou_sig_v` (only 2 is accepted) and
    /// `ou_sig` over `iss`, the originating-user block and the root hop, under the `ou_kid` key;
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

        let header = jsonwebtoken::decode_header(token)?;
        let candidates: Vec<&TrustedKey> = match header.kid.as_deref() {
            Some(kid) => match self.keys.iter().find(|k| k.kid == kid) {
                Some(k) => vec![k],
                None => return Err(TokenError::UnknownKeyId(kid.to_owned())),
            },
            None => self.keys.iter().collect(),
        };
        let mut result = Err(TokenError::InvalidSignature);
        for key in candidates {
            match jsonwebtoken::decode::<Claims>(token, &key.decoding_key, &validation) {
                Ok(d) => {
                    result = Ok(d);
                    break;
                }
                Err(e) => result = Err(e.into()),
            }
        }
        let data = result?;
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
        if claims.ou_sig_v != OU_SIG_VERSION {
            // A missing claim deserializes as 0: a version-1 token from before SR-14.
            return Err(TokenError::UnsupportedOuSig(claims.ou_sig_v.max(1)));
        }
        let ou_key = self
            .keys
            .iter()
            .find(|k| k.kid == claims.ou_kid)
            .ok_or(TokenError::InvalidSignature)?;
        let root = claims
            .chain
            .hops
            .first()
            .ok_or(TokenError::Chain(onbehalf_core::ChainError::NoHops))?;
        let message = ou_sig_message(&claims.iss, &claims.chain.originating_user, root);
        if !ou_key.public_key.verify_detached(&message, &claims.ou_sig) {
            return Err(TokenError::InvalidSignature);
        }
        claims.chain.validate_at(now, self.max_depth)?;

        Ok(VerifiedToken {
            chain: claims.chain.clone(),
            claims,
        })
    }
}
