//! JWT claim set of a delegation token.

use onbehalf_core::{DelegationChain, OriginatingUser};
use serde::{Deserialize, Serialize};

/// Value of the JWT header `typ` and of the `typ` claim. Verifiers reject anything else, so a
/// delegation token can never be confused with an ordinary access token for the same audience.
pub const TOKEN_TYPE: &str = "onbehalf+jwt";

/// RFC 8693 §3 token type identifier for the tokens this crate issues and accepts.
pub const JWT_TOKEN_TYPE_URN: &str = "urn:ietf:params:oauth:token-type:jwt";

/// The `act` (actor) claim, nested as in RFC 8693 §4.1.
///
/// The outermost `ActClaim` is the agent currently acting (the last hop of the chain); each
/// nested `act` is the party that delegated to it, down to the root agent that received the
/// grant directly from the user, whose `act` is `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActClaim {
    /// Agent identifier of this actor.
    pub sub: String,
    /// The actor that delegated to this one, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<ActClaim>>,
}

impl ActClaim {
    /// Build the nested actor claim from a chain (last hop outermost, root hop innermost).
    ///
    /// Returns `None` for a chain with no hops.
    pub fn from_chain(chain: &DelegationChain) -> Option<ActClaim> {
        chain.hops.iter().fold(None, |inner, hop| {
            Some(ActClaim {
                sub: hop.agent.0.clone(),
                act: inner.map(Box::new),
            })
        })
    }

    /// Depth of the nesting: number of actors represented.
    pub fn depth(&self) -> usize {
        1 + self.act.as_deref().map(ActClaim::depth).unwrap_or(0)
    }
}

/// The claims of a delegation token.
///
/// The authoritative content is `chain`; `sub` and `act` are derived from it so that generic
/// RFC 8693 consumers can read who is acting for whom without understanding `chain`. Verifiers
/// check that they agree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer identifier of the onbehalf token service.
    pub iss: String,
    /// Intended audience (the proxy or resource that will evaluate the chain).
    pub aud: String,
    /// Subject of the originating user (`chain.originating_user.subject`).
    pub sub: String,
    /// Current actor with nested parents; innermost is the root agent.
    pub act: ActClaim,
    /// Unique token id.
    pub jti: String,
    /// Issued-at, seconds since the Unix epoch.
    pub iat: i64,
    /// Expiry, seconds since the Unix epoch. Always equal to the last hop's `expires_at`.
    pub exp: i64,
    /// The delegation chain this token carries.
    pub chain: DelegationChain,
    /// Always [`TOKEN_TYPE`].
    pub typ: String,
    /// Detached issuer signature over the canonical JSON of `chain.originating_user`, base64url.
    ///
    /// It is produced once, at root issuance, and copied unchanged through every exchange. A
    /// verifier recomputes the canonical encoding and checks the signature, so an exchanged token
    /// whose user block was edited fails even if its outer JWT signature is valid under a
    /// different legitimate issuer key (multi-issuer deployments). In v0 both signatures use the
    /// same key; the separate field keeps the user block independently verifiable when that
    /// changes.
    pub ou_sig: String,
}

/// Canonical byte encoding of the originating-user block that `ou_sig` signs.
///
/// Canonical means `serde_json` compact output with map keys in `BTreeMap` order; the core types
/// are `BTreeMap`-backed, so re-serializing a decoded block yields the same bytes.
pub fn canonical_user_bytes(user: &OriginatingUser) -> Vec<u8> {
    serde_json::to_vec(user).expect("OriginatingUser serializes")
}
