//! Minting root tokens and performing RFC 8693 exchanges.

use std::sync::Arc;

use attenuo_core::{AgentId, CapabilitySet, DelegationChain, LeaseId, OriginatingUser};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use time::{Duration, OffsetDateTime};

use crate::claims::{ou_sig_message, ActClaim, Claims, MayAct, OU_SIG_VERSION, TOKEN_TYPE};
use crate::detached::DetachedSigner;
use crate::dpop::Confirmation;
use crate::error::TokenError;
use crate::keys::{PublicKey, SigningKey};
use crate::verifier::Verifier;

/// Static configuration of an [`Issuer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerConfig {
    /// Value of the `iss` claim; verifiers must be configured with the same string.
    pub issuer: String,
    /// Value of the `aud` claim: the proxy or resource the tokens are meant for.
    pub audience: String,
    /// Maximum number of hops a chain may have (see `attenuo_core::chain::DEFAULT_MAX_DEPTH`).
    pub max_depth: usize,
    /// Lifetime used when a caller does not request one.
    pub default_ttl: Duration,
}

/// Optional parts of a root issuance or an exchange.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IssueOptions {
    /// `may_act` for the new token (RFC 8693 §4.4): who may exchange it next.
    pub may_act: Option<MayAct>,
    /// An upper bound on the new token's expiry besides the requested TTL and (for an
    /// exchange) the parent's expiry; for example the `exp` of the actor token that
    /// authenticated the exchange. At or before `now` fails with [`TokenError::NoLifetimeLeft`].
    pub not_after: Option<OffsetDateTime>,
    /// Bind the new token to a key (`cnf`, RFC 9449). The caller has verified a DPoP proof
    /// for it. For an exchange of a bound parent this is mandatory
    /// ([`TokenError::BindingRequired`]); whoever calls [`Issuer::exchange_with`] must also
    /// have checked possession of the parent's key, since the issuer cannot see the request.
    pub cnf: Option<Confirmation>,
}

impl IssueOptions {
    /// The TTL to use: `ttl` (or `default`), capped at `not_after - now`.
    fn ttl(
        &self,
        ttl: Option<Duration>,
        default: Duration,
        now: OffsetDateTime,
    ) -> Result<Duration, TokenError> {
        let ttl = ttl.unwrap_or(default);
        match self.not_after {
            None => Ok(ttl),
            Some(limit) => {
                let left = limit - now;
                if left < Duration::seconds(1) {
                    return Err(TokenError::NoLifetimeLeft(format!(
                        "capped at {limit}, which is not after now"
                    )));
                }
                Ok(ttl.min(left))
            }
        }
    }
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
    /// The key binding, when the token is sender-constrained.
    pub cnf: Option<Confirmation>,
}

/// Holder of the signing key. Mints root tokens and exchanges them for narrower child tokens.
///
/// Every token an `Issuer` produces embeds a `DelegationChain` built with `DelegationChain::root`
/// or `DelegationChain::extend` from `attenuo-core`, so attenuation and expiry monotonicity are
/// enforced by the same code that verifiers run.
pub struct Issuer {
    key: Arc<SigningKey>,
    /// Retired public keys that still verify (rotation overlap); never used to sign.
    previous: Vec<PublicKey>,
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
            key: Arc::new(key),
            previous: Vec::new(),
            encoding_key,
            config,
        }
    }

    /// Also trust tokens signed by a retired key, given as a `PUBLIC KEY` or `PRIVATE KEY` PEM
    /// (only the public half is used). The key never signs. Use this during a rotation, so
    /// tokens minted before the switch keep verifying (and can still be exchanged) until they
    /// expire. Adding the current key again is a no-op.
    pub fn trust_previous_key(&mut self, pem: &str) -> Result<(), TokenError> {
        let key = if pem.contains("-----BEGIN PRIVATE KEY-----") {
            SigningKey::from_pem(pem)?.public_key()
        } else {
            PublicKey::from_pem(pem)?
        };
        if key != self.key.public_key() && !self.previous.contains(&key) {
            self.previous.push(key);
        }
        Ok(())
    }

    /// `kid` of the current signing key, as put in every token's header.
    pub fn key_id(&self) -> String {
        self.key.public_key().kid()
    }

    /// The `kid` and `PUBLIC KEY` PEM of every trusted key: the signing key first, then the
    /// retired ones. This is what a JWKS endpoint publishes.
    pub fn trusted_public_keys(&self) -> Vec<(String, String)> {
        std::iter::once(self.key.public_key())
            .chain(self.previous.iter().cloned())
            .map(|k| (k.kid(), k.to_pem()))
            .collect()
    }

    /// A cloneable handle that signs non-token payloads (audit checkpoints) with the current
    /// key, domain-separated by a context string. See [`crate::detached`].
    pub fn detached_signer(&self) -> DetachedSigner {
        DetachedSigner::new(Arc::clone(&self.key))
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

    /// A verifier holding only public keys (the current one and any retired ones added with
    /// [`Issuer::trust_previous_key`]) and this issuer's `iss`/`aud`/`max_depth`.
    pub fn verifier(&self) -> Verifier {
        let mut v = Verifier::new(
            self.key.public_key(),
            self.config.issuer.clone(),
            self.config.audience.clone(),
            self.config.max_depth,
        );
        for k in &self.previous {
            v.add_key(k.clone());
        }
        v
    }

    /// Mint the root token: `agent` acts for `user` with `capabilities` for `ttl`
    /// (default: `config.default_ttl`), starting at `now`.
    ///
    /// This is the only place the originating-user block is signed (`ou_sig`, bound to `iss`
    /// and this root hop, see [`crate::claims::ou_sig_payload`]); exchanges copy that
    /// signature, its version and its `kid` unchanged.
    pub fn issue_root(
        &self,
        user: OriginatingUser,
        agent: AgentId,
        capabilities: CapabilitySet,
        ttl: Option<Duration>,
        now: OffsetDateTime,
    ) -> Result<IssuedToken, TokenError> {
        self.issue_root_with(
            user,
            agent,
            capabilities,
            ttl,
            now,
            &IssueOptions::default(),
        )
    }

    /// [`Issuer::issue_root`] with [`IssueOptions`] (`may_act`, an expiry cap).
    pub fn issue_root_with(
        &self,
        user: OriginatingUser,
        agent: AgentId,
        capabilities: CapabilitySet,
        ttl: Option<Duration>,
        now: OffsetDateTime,
        options: &IssueOptions,
    ) -> Result<IssuedToken, TokenError> {
        let lease = new_lease();
        let chain = DelegationChain::root(
            user,
            agent,
            capabilities,
            now,
            options.ttl(ttl, self.config.default_ttl, now)?,
            lease.clone(),
        )?;
        // RFC 3339 has no form for a year outside 0..=9999, which `OffsetDateTime` can hold
        // (an IdP's `auth_time` of -1e11 is year -1200). The `ou_sig` encoding would panic on
        // such a chain (found by the `ou_sig` fuzz target), so refuse it here.
        serde_json::to_vec(&chain).map_err(|e| {
            TokenError::Malformed(format!("chain has no JSON form (time out of range?): {e}"))
        })?;
        let ou = OuSig {
            sig: self.key.sign_detached(&ou_sig_message(
                &self.config.issuer,
                &chain.originating_user,
                &chain.hops[0],
            )),
            kid: self.key.public_key().kid(),
        };
        self.mint(chain, ou, lease, options, now)
    }

    /// RFC 8693 token exchange: verify `parent_token`, then mint a child token for `actor` whose
    /// capabilities are `requested` (which must be covered by the parent's) and whose expiry is
    /// the earlier of `now + ttl` and the parent's expiry.
    ///
    /// Fails with [`TokenError::Chain`] when `requested` widens the parent's capabilities or the
    /// chain would exceed `max_depth`, with [`TokenError::ActorNotPermitted`] when the parent
    /// carries `may_act` and `actor` is not listed, and with the verification error if the
    /// parent token is not valid at `now`.
    pub fn exchange(
        &self,
        parent_token: &str,
        actor: AgentId,
        requested: CapabilitySet,
        ttl: Option<Duration>,
        now: OffsetDateTime,
    ) -> Result<IssuedToken, TokenError> {
        self.exchange_with(
            parent_token,
            actor,
            requested,
            ttl,
            now,
            &IssueOptions::default(),
        )
    }

    /// [`Issuer::exchange`] with [`IssueOptions`]: `may_act` for the child, an expiry cap
    /// applied on top of the parent's expiry, and a key binding (`cnf`). A bound parent
    /// (`cnf.jkt`) needs a bound child: without `options.cnf` this fails with
    /// [`TokenError::BindingRequired`]. The child may be bound to another key than the
    /// parent's; checking that the requester holds the parent's key is the caller's job.
    pub fn exchange_with(
        &self,
        parent_token: &str,
        actor: AgentId,
        requested: CapabilitySet,
        ttl: Option<Duration>,
        now: OffsetDateTime,
        options: &IssueOptions,
    ) -> Result<IssuedToken, TokenError> {
        let parent = self.verifier().verify(parent_token, now)?;
        if let Some(may_act) = &parent.claims.may_act {
            if !may_act.permits(&actor.0) {
                return Err(TokenError::ActorNotPermitted(actor.0));
            }
        }
        if parent.claims.cnf.is_some() && options.cnf.is_none() {
            return Err(TokenError::BindingRequired);
        }
        let lease = new_lease();
        let chain = parent.chain.extend(
            actor,
            requested,
            now,
            options.ttl(ttl, self.config.default_ttl, now)?,
            lease.clone(),
            self.config.max_depth,
        )?;
        self.mint(
            chain,
            OuSig {
                sig: parent.claims.ou_sig,
                kid: parent.claims.ou_kid,
            },
            lease,
            options,
            now,
        )
    }

    fn mint(
        &self,
        chain: DelegationChain,
        ou: OuSig,
        lease: LeaseId,
        options: &IssueOptions,
        now: OffsetDateTime,
    ) -> Result<IssuedToken, TokenError> {
        if let Some(cnf) = &options.cnf {
            if !cnf.is_well_formed() {
                return Err(TokenError::Malformed(
                    "cnf.jkt must be a base64url SHA-256 thumbprint".into(),
                ));
            }
        }
        let expires_at = chain
            .hops
            .last()
            .map(|h| h.expires_at)
            .ok_or(TokenError::Chain(attenuo_core::ChainError::NoHops))?;
        let act = ActClaim::from_chain(&chain)
            .ok_or(TokenError::Chain(attenuo_core::ChainError::NoHops))?;
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
            ou_sig: ou.sig,
            ou_sig_v: OU_SIG_VERSION,
            ou_kid: ou.kid,
            may_act: options.may_act.clone(),
            cnf: options.cnf.clone(),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some(TOKEN_TYPE.to_owned());
        header.kid = Some(self.key.public_key().kid());
        let token = jsonwebtoken::encode(&header, &claims, &self.encoding_key)?;
        Ok(IssuedToken {
            token,
            chain,
            expires_at,
            lease,
            cnf: options.cnf.clone(),
        })
    }
}

/// The originating-user signature and the `kid` of the key that made it.
struct OuSig {
    sig: String,
    kid: String,
}

fn new_lease() -> LeaseId {
    LeaseId::new(uuid::Uuid::new_v4().to_string())
}
