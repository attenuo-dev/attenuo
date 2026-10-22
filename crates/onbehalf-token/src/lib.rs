//! Delegation tokens for `onbehalf`: RFC 8693-style token exchange carrying a signed
//! [`DelegationChain`](onbehalf_core::DelegationChain).
//!
//! An [`Issuer`] holds an Ed25519 key and mints short-lived JWTs (`alg` = EdDSA,
//! `typ` = `onbehalf+jwt`). A [`Verifier`] holds only the public key and checks tokens
//! strictly. The guarantees are:
//!
//! 1. **The originating-user block is signed once.** At [`Issuer::issue_root`] the issuer signs
//!    the canonical JSON of the `OriginatingUser` and stores the detached signature in the
//!    `ou_sig` claim. Exchanges copy it unchanged, and every verification recomputes and checks
//!    it, so no hop can alter who the chain is for, even if the outer JWT is re-signed by another
//!    legitimate issuer key.
//! 2. **Exchanges only narrow.** [`Issuer::exchange`] builds the child chain with
//!    `DelegationChain::extend` from `onbehalf-core`: the requested capabilities must be covered
//!    by the parent's, and the child's expiry is clamped to the parent's.
//! 3. **Verification is strict.** [`Verifier::verify`] checks the signature, `typ`, `iss`,
//!    `aud`, `exp` against a caller-supplied clock, the consistency of `sub`/`act` with the
//!    chain, `ou_sig`, and finally `DelegationChain::validate_at(now, max_depth)`.
//!
//! [`ExchangeRequest`] and [`ExchangeResponse`] give the JSON shapes for an HTTP token-exchange
//! endpoint.
//!
//! ```
//! use onbehalf_core::{AgentId, Capability, CapabilitySet, OriginatingUser};
//! use onbehalf_token::{Issuer, IssuerConfig};
//! use time::{macros::datetime, Duration};
//!
//! let issuer = Issuer::generate(IssuerConfig {
//!     issuer: "https://onbehalf.example".into(),
//!     audience: "mcp-proxy".into(),
//!     max_depth: 8,
//!     default_ttl: Duration::minutes(10),
//! });
//! let now = datetime!(2026-10-22 21:00 UTC);
//! let user = OriginatingUser {
//!     subject: "user:mudit".into(),
//!     issuer: "https://idp.example".into(),
//!     authenticated_at: now,
//!     attributes: Default::default(),
//! };
//! let root = issuer
//!     .issue_root(
//!         user,
//!         AgentId::new("agent:planner"),
//!         CapabilitySet::from_iter([Capability::new("github", "read_*")]),
//!         None,
//!         now,
//!     )
//!     .unwrap();
//! let child = issuer
//!     .exchange(
//!         &root.token,
//!         AgentId::new("agent:coder"),
//!         CapabilitySet::from_iter([Capability::new("github", "read_file")]),
//!         Some(Duration::hours(5)),
//!         now + Duration::minutes(1),
//!     )
//!     .unwrap();
//! assert_eq!(child.expires_at, root.expires_at); // clamped to the parent
//! let verified = issuer.verifier().verify(&child.token, now + Duration::minutes(2)).unwrap();
//! assert_eq!(verified.claims.act.sub, "agent:coder");
//! assert_eq!(verified.claims.act.act.unwrap().sub, "agent:planner");
//! ```

pub mod claims;
pub mod error;
pub mod exchange;
pub mod issuer;
mod keys;
pub mod verifier;

pub use claims::{ActClaim, Claims, JWT_TOKEN_TYPE_URN, TOKEN_TYPE};
pub use error::TokenError;
pub use exchange::{
    ExchangeRequest, ExchangeResponse, AUTHORIZATION_DETAILS_TYPE, TOKEN_EXCHANGE_GRANT_TYPE,
};
pub use issuer::{IssuedToken, Issuer, IssuerConfig};
pub use verifier::{VerifiedToken, Verifier};
