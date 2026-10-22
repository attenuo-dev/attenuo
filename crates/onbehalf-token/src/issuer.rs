//! Minting root tokens and performing RFC 8693 exchanges.

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use onbehalf_core::{AgentId, CapabilitySet, DelegationChain, LeaseId, OriginatingUser};
use time::{Duration, OffsetDateTime};

use crate::claims::{canonical_user_bytes, ActClaim, Claims, TOKEN_TYPE};
use crate::error::TokenError;
use crate::keys::SigningKey;
use crate::verifier::Verifier;

/// Static configuration of an [`Issuer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerConfig {
    /// Value of the `iss` claim; verifiers must be configured with the same string.
    pub issuer: String,
    /// Value of the `aud` claim: the proxy or resource the tokens are meant for.
    pub audience: String,
    /// Maximum number of hops a chain may have (see `onbehalf_core::chain::DEFAULT_MAX_DEPTH`).
    pub max_depth: usize,
    /// Lifetime used when a caller does not request one.
    pub default_ttl: Duration,
}

/// A minted token together with the data it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedToken {
    /// The compact JWS.
    pub token: String,
    /// The chain embedded in the token.
    pub chain: DelegationChain,
    /// When the token (and its last hop) expires.
    pub expires_at: OffsetDateTime,
    /// Lease of the hop this token was minted for. Revoke it to deny this hop and everything
    /// delegated from it.
    pub lease: LeaseId,
}

/// Holder of the signing key. Mints root tokens and exchanges them for narrower child tokens.
///
/// Every token an `Issuer` produces embeds a `DelegationChain` built with `DelegationChain::root`
/// or `DelegationChain::extend` from `onbehalf-core`, so attenuation and expiry monotonicity are
/// enforced by the same code that verifiers run.
pub struct Issuer {
    key: SigningKey,
    encoding_key: EncodingKey,
    config: IssuerConfig,
}

impl std::fmt::Debug for Issuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issuer")
            .field("config", &self.config)
            .field("public_key", &self.key.public_key())
            .finish_non_exhaustive()
    }
}

impl Issuer {
    /// Create an issuer with a fresh random Ed25519 key pair.
    ///
    /// # Panics
    /// Panics if the system random number generator is unavailable, which is a fatal
    /// environment error rather than a recoverable one.
    pub fn generate(config: IssuerConfig) -> Self {
        let key = SigningKey::generate().expect("system RNG available");
        Self::with_key(config, key)
    }

    /// Create an issuer from a PKCS#8 `PRIVATE KEY` PEM holding an Ed25519 key.
    pub fn from_pem(config: IssuerConfig, private_pem: &str) -> Result<Self, TokenError> {
        Ok(Self::with_key(config, SigningKey::from_pem(private_pem)?))
    }

    fn with_key(config: IssuerConfig, key: SigningKey) -> Self {
        let encoding_key = EncodingKey::from_ed_der(key.pkcs8_der());
        Self {
            key,
            encoding_key,
            config,
        }
    }

    /// The configuration this issuer was built with.
    pub fn config(&self) -> &IssuerConfig {
        &self.config
    }

    /// The issuer's public key as a `PUBLIC KEY` PEM, for distribution to verifiers.
    pub fn public_key_pem(&self) -> String {
        self.key.public_key().to_pem()
    }

    /// The issuer's private key as a PKCS#8 `PRIVATE KEY` PEM, for persistence. Secret.
    pub fn private_key_pem(&self) -> String {
        self.key.private_pem()
    }

    /// A verifier holding only the public key and this issuer's `iss`/`aud`/`max_depth`.
    pub fn verifier(&self) -> Verifier {
        Verifier::new(
            self.key.public_key(),
            self.config.issuer.clone(),
            self.config.audience.clone(),
            self.config.max_depth,
        )
    }

    /// Mint the root token: `agent` acts for `user` with `capabilities` for `ttl`
    /// (default: `config.default_ttl`), starting at `now`.
    ///
    /// This is the only place the originating-user block is signed (`ou_sig`); exchanges copy
    /// that signature unchanged.
    pub fn issue_root(
        &self,
        user: OriginatingUser,
        agent: AgentId,
        capabilities: CapabilitySet,
        ttl: Option<Duration>,
        now: OffsetDateTime,
    ) -> Result<IssuedToken, TokenError> {
        let lease = new_lease();
        let chain = DelegationChain::root(
            user,
            agent,
            capabilities,
            now,
            ttl.unwrap_or(self.config.default_ttl),
            lease.clone(),
        )?;
        let ou_sig = self
            .key
            .sign_detached(&canonical_user_bytes(&chain.originating_user));
        self.mint(chain, ou_sig, lease, now)
    }

    /// RFC 8693 token exchange: verify `parent_token`, then mint a child token for `actor` whose
    /// capabilities are `requested` (which must be covered by the parent's) and whose expiry is
    /// the earlier of `now + ttl` and the parent's expiry.
    ///
    /// Fails with [`TokenError::Chain`] when `requested` widens the parent's capabilities or the
    /// chain would exceed `max_depth`, and with the verification error if the parent token is
    /// not valid at `now`.
    pub fn exchange(
        &self,
        parent_token: &str,
        actor: AgentId,
        requested: CapabilitySet,
        ttl: Option<Duration>,
        now: OffsetDateTime,
    ) -> Result<IssuedToken, TokenError> {
        let parent = self.verifier().verify(parent_token, now)?;
        let lease = new_lease();
        let chain = parent.chain.extend(
            actor,
            requested,
            now,
            ttl.unwrap_or(self.config.default_ttl),
            lease.clone(),
            self.config.max_depth,
        )?;
        self.mint(chain, parent.claims.ou_sig, lease, now)
    }

    fn mint(
        &self,
        chain: DelegationChain,
        ou_sig: String,
        lease: LeaseId,
        now: OffsetDateTime,
    ) -> Result<IssuedToken, TokenError> {
        let expires_at = chain
            .hops
            .last()
            .map(|h| h.expires_at)
            .ok_or(TokenError::Chain(onbehalf_core::ChainError::NoHops))?;
        let act = ActClaim::from_chain(&chain)
            .ok_or(TokenError::Chain(onbehalf_core::ChainError::NoHops))?;
        let claims = Claims {
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            sub: chain.originating_user.subject.clone(),
            act,
            jti: uuid::Uuid::new_v4().to_string(),
            iat: now.unix_timestamp(),
            exp: expires_at.unix_timestamp(),
            chain: chain.clone(),
            typ: TOKEN_TYPE.to_owned(),
            ou_sig,
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some(TOKEN_TYPE.to_owned());
        let token = jsonwebtoken::encode(&header, &claims, &self.encoding_key)?;
        Ok(IssuedToken {
            token,
            chain,
            expires_at,
            lease,
        })
    }
}

fn new_lease() -> LeaseId {
    LeaseId::new(uuid::Uuid::new_v4().to_string())
}
