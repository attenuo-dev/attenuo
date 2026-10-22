//! Error type for token minting and verification.

use onbehalf_core::ChainError;
use thiserror::Error;

/// Why a token could not be minted, exchanged, or verified.
///
/// Verification checks run in a fixed order (signature, type, issuer, audience, expiry,
/// originating-user signature, chain), and the first failing check determines the variant.
/// The order means a caller never learns anything about the payload of a token whose signature
/// does not verify.
#[derive(Debug, Error)]
pub enum TokenError {
    /// The token's `exp` is at or before the verification time.
    #[error("token has expired")]
    Expired,
    /// The JWT signature does not verify under any trusted key, or the originating-user block
    /// signature (`ou_sig`) does not verify.
    #[error("token signature is invalid")]
    InvalidSignature,
    /// The header names a `kid` that is not among the trusted keys.
    #[error("token was signed with an unknown key id `{0}`")]
    UnknownKeyId(String),
    /// `iss` does not match the configured issuer.
    #[error("token issuer is not trusted")]
    WrongIssuer,
    /// `aud` does not match the configured audience.
    #[error("token audience does not match")]
    WrongAudience,
    /// The header `typ` or the `typ` claim is not `onbehalf+jwt`.
    #[error("token type is not a delegation token")]
    WrongType,
    /// The token is not a well-formed JWT, or its claims do not have the expected shape.
    #[error("malformed token: {0}")]
    Malformed(String),
    /// The embedded delegation chain violates an invariant (attenuation, depth, expiry order).
    #[error("delegation chain is invalid: {0}")]
    Chain(#[from] ChainError),
    /// A key could not be generated, parsed, or used.
    #[error("key error: {0}")]
    Key(String),
}

impl From<jsonwebtoken::errors::Error> for TokenError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;
        match err.kind() {
            ErrorKind::InvalidSignature => TokenError::InvalidSignature,
            ErrorKind::ExpiredSignature => TokenError::Expired,
            ErrorKind::InvalidIssuer => TokenError::WrongIssuer,
            ErrorKind::InvalidAudience => TokenError::WrongAudience,
            ErrorKind::InvalidEcdsaKey
            | ErrorKind::InvalidRsaKey(_)
            | ErrorKind::RsaFailedSigning
            | ErrorKind::InvalidKeyFormat => TokenError::Key(err.to_string()),
            _ => TokenError::Malformed(err.to_string()),
        }
    }
}
