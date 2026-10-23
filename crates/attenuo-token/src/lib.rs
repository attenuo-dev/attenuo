//! Delegation tokens for `attenuo`: RFC 8693-style token exchange carrying a signed
//! [`DelegationChain`](attenuo_core::DelegationChain).
//!
//! An [`Issuer`] holds an Ed25519 key and mints short-lived JWTs (`alg` = EdDSA,
//! `typ` = `attenuo+jwt`). A [`Verifier`] holds only the public key and checks tokens
//! strictly. The guarantees are:
//!
//! 1. **The originating-user block is signed once.** At [`Issuer::issue_root`] the issuer signs
//!    `iss`, the canonical JSON of the `OriginatingUser` and the root hop, domain-separated
//!    (`ou_sig` v3, [`claims::ou_sig_payload`], RFC 8785 canonical JSON), and stores the
//!    detached signature in the `ou_sig` claim with `ou_sig_v` = 3 and the signing key's
//!    `ou_kid`. Exchanges copy them
//!    unchanged, and every verification recomputes and checks the signature, so no hop can alter
//!    who the chain is for or how it started, even if the outer JWT is re-signed by another
//!    legitimate issuer key, and a user's signature cannot be lifted into another chain.
//! 2. **Exchanges only narrow.** [`Issuer::exchange`] builds the child chain with
//!    `DelegationChain::extend` from `attenuo-core`: the requested capabilities must be covered
//!    by the parent's, and the child's expiry is clamped to the parent's.
//! 3. **Verification is strict.** [`Verifier::verify`] checks the signature, `typ`, `iss`,
//!    `aud`, `exp` against a caller-supplied clock, the consistency of `sub`/`act` with the
//!    chain, `ou_sig`, and finally `DelegationChain::validate_at(now, max_depth)`.
//!
//! [`ExchangeRequest`] and [`ExchangeResponse`] give the JSON shapes for an HTTP token-exchange
//! endpoint.
//!
//! ```
//! use attenuo_core::{AgentId, Capability, CapabilitySet, OriginatingUser};
//! use attenuo_token::{Issuer, IssuerConfig};
//! use time::{macros::datetime, Duration};
//!
//! let issuer = Issuer::generate(IssuerConfig {
//!     issuer: "https://attenuo.example".into(),
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
pub mod detached;
pub mod dpop;
pub mod error;
pub mod exchange;
pub mod issuer;
mod keys;
pub mod verifier;

pub use claims::{
    ActClaim, Claims, MayAct, JWT_TOKEN_TYPE_URN, OU_SIG_CONTEXT, OU_SIG_VERSION, TOKEN_TYPE,
};
pub use detached::{verify_detached, DetachedSigner};
pub use dpop::{Confirmation, DpopError, DpopKey};
pub use error::TokenError;
pub use exchange::{
    ExchangeRequest, ExchangeResponse, AUTHORIZATION_DETAILS_TYPE, TOKEN_EXCHANGE_GRANT_TYPE,
};
pub use issuer::{IssueOptions, IssuedToken, Issuer, IssuerConfig};
pub use verifier::{VerifiedToken, Verifier};
