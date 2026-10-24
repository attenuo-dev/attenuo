//! Building the shared state from a [`Config`].

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::Context;
use attenuo_audit::{CheckpointKeys, SqliteAudit, SqliteLeaseStore};
use attenuo_policy::{PolicyEngine, PolicyEngineBuilder};
use attenuo_token::{Issuer, IssuerConfig, Verifier};
use serde_json::Value;
use sha2::Digest;
use time::{Duration, OffsetDateTime};

use crate::actor::ActorTrustRegistry;
use crate::authz::Pipeline;
use crate::config::{ActorAuth, AgentConfig, Config, RootGrant};
use crate::idp::IdpRegistry;
use crate::metrics::Metrics;

/// Everything the handlers share.
pub struct AppState {
    pub issuer: Issuer,
    pub verifier: Verifier,
    pub pipeline: Arc<Pipeline>,
    pub audit: Arc<SqliteAudit>,
    /// Public keys that may have signed audit checkpoints (the JWKS: current plus retired).
    pub checkpoint_keys: CheckpointKeys,
    /// `[audit] checkpoint_interval_seconds`; zero means no timer.
    pub checkpoint_interval: std::time::Duration,
    pub leases: Arc<SqliteLeaseStore>,
    /// Policy file to re-read on reload; `None` when no policy file is configured.
    pub policies_path: Option<PathBuf>,
    /// Digest and load time of the policy set in force, for `GET /admin/policies`. The engine
    /// does not keep them, so they live here: set at startup and on every successful reload
    /// (while the engine's write lock is held, so the two never disagree), and left alone by
    /// a failed one.
    pub loaded_policies: RwLock<LoadedPolicies>,
    pub admin_token: Option<String>,
    pub root_grants: Vec<RootGrant>,
    /// Trusted IdPs for hop-0 intake.
    pub idps: IdpRegistry,
    /// Agents allowed to present IdP credentials (`[[agents]]`, validated).
    pub agents: Vec<AgentConfig>,
    /// `[dev] allow_root_mint`.
    pub dev_allow_root_mint: bool,
    /// `[token] require_actor_auth`.
    pub require_actor_auth: bool,
    /// `[token] actor_auth`.
    pub actor_auth: ActorAuth,
    /// Issuers of actor tokens (`[[actor_trust]]`).
    pub actor_trust: ActorTrustRegistry,
    /// `[authzen] allow_unsigned_chain`.
    pub authzen_allow_unsigned_chain: bool,
    /// `[authzen] max_batch`.
    pub authzen_max_batch: usize,
    /// `[authzen] diagnostics`.
    pub authzen_diagnostics: crate::config::AuthzenDiagnostics,
    /// PEPs allowed to send unsigned chains (`[[peps]]`, validated).
    pub peps: Vec<AgentConfig>,
    pub public_url: Option<String>,
    /// `[issuer] lease_interval_seconds`: lifetime of a lease after issuance or renewal.
    pub lease_interval: Duration,
    /// Precomputed `/.well-known/jwks.json` body.
    pub jwks: Value,
    pub metrics: Arc<Metrics>,
    /// One-time use of IdP credentials and of (parent token, actor) exchanges.
    pub replay: crate::replay::ReplayCache,
    /// Sender-constrained tokens: `[token] dpop*` and the proof replay cache (SR-24).
    pub dpop: Arc<crate::dpop::Dpop>,
    /// `[audit.sink]`: ships every checkpoint off the host (SR-21); `None` when unset.
    pub checkpoint_sink: Option<crate::sink::CheckpointSink>,
    /// `[audit.sink] fail_readiness`.
    pub sink_fails_readiness: bool,
    /// `[approvals] client_id`: the `aud` of approval ID tokens, when set.
    pub approvals_client_id: Option<String>,
}

impl AppState {
    /// Load keys, policies and storage as the config says.
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        config.check_server_names()?;
        config.server.check_public_url()?;
        config.check_admin_token()?;
        config.metrics.check_listen()?;
        config.admin_ui.check_listen()?;
        if config.authzen.max_batch == 0 {
            anyhow::bail!("[authzen] max_batch must be at least 1");
        }
        config.proxy.stream_recheck()?;
        config.proxy.check_limits()?;
        config.token.check_dpop()?;
        config.approvals.check()?;
        let issuer = load_issuer(config)?;
        // Server DPoP nonces are keyed by the issuer's private key (see `crate::dpop`).
        let dpop = Arc::new(
            crate::dpop::Dpop::new(
                config.token.dpop,
                config.token.dpop_max_age_seconds,
                config.token.dpop_replay_capacity,
                config.server.public_url.clone(),
            )
            .with_nonce(config.token.dpop_nonce, issuer.private_key_pem().as_bytes()),
        );
        let verifier = issuer.verifier();
        let jwks = crate::jwks::jwks_from_keys(&issuer.trusted_public_keys())?;

        let (engine, policies_sha256) = build_engine(config)?;
        let loaded_policies = RwLock::new(LoadedPolicies {
            sha256: policies_sha256,
            loaded_at: OffsetDateTime::now_utc(),
        });
        let policy = Arc::new(RwLock::new(engine));

        let checkpoint_keys = CheckpointKeys::from_jwks(&jwks)?;
        let metrics = Metrics::new();
        let checkpoint_sink = match &config.audit.sink {
            Some(cfg) => {
                let sink = crate::sink::CheckpointSink::start(
                    cfg,
                    config.server.public_url.clone(),
                    metrics.clone(),
                )?;
                if let Some(path) = &cfg.path {
                    warn_if_same_mount(path, &config.audit.sqlite_path);
                }
                Some(sink)
            }
            None => None,
        };
        let (audit, leases) = open_storage(
            &config.audit,
            issuer.detached_signer(),
            metrics.clone(),
            checkpoint_sink.as_ref().map(|s| s.handle()),
        )?;
        let pipeline = Arc::new(
            Pipeline::new(policy, leases.clone(), audit.clone())
                .with_metrics(metrics.clone())
                .with_approval_ttl(config.approvals.ttl())
                .with_approval_verifier(verifier.clone()),
        );
        let idps = IdpRegistry::from_config(&config.idps, &config.issuer.issuer)?;
        let agents = crate::idp::intake::validate_agents(&config.agents)?;
        let peps = crate::clientauth::validate_clients("[[peps]]", &config.peps)?;
        for idp in &config.idps {
            for agent in agents
                .iter()
                .filter(|a| !idp.client_ids.contains_key(&a.id))
            {
                tracing::warn!(
                    idp = ?idp.issuer,
                    agent = ?agent.id,
                    "[[idps]] client_ids has no entry for this agent: its ID tokens must carry \
                     aud = `{0}` (the agent id). Set client_ids.{0} = \"<client id at the IdP>\" \
                     to bind ID tokens to the agent explicitly (SR-37)",
                    agent.id
                );
            }
        }
        let actor_trust = ActorTrustRegistry::from_config(&config.actor_trust)?;
        let actor_auth = config.token.actor_auth;
        if actor_auth == ActorAuth::ActorToken && actor_trust.is_empty() {
            anyhow::bail!(
                "[token] actor_auth = \"actor_token\" needs at least one [[actor_trust]] entry"
            );
        }
        if actor_auth == ActorAuth::Secret && !actor_trust.is_empty() {
            tracing::warn!(
                "[[actor_trust]] is configured but [token] actor_auth = \"secret\": actor \
                 tokens are refused"
            );
        }
        if !config.token.require_actor_auth {
            tracing::warn!(
                "[token] require_actor_auth = false: POST /token exchanges accept any `actor` \
                 without authenticating it, so agent identity in policies and audit records is \
                 only asserted"
            );
        } else if agents.is_empty() && actor_trust.is_empty() {
            tracing::warn!(
                "[[agents]] and [[actor_trust]] are empty and [token] require_actor_auth = \
                 true: every token exchange will be rejected"
            );
        }
        if config.authzen.allow_unsigned_chain {
            if peps.is_empty() {
                anyhow::bail!(
                    "[authzen] allow_unsigned_chain = true needs at least one [[peps]] entry"
                );
            }
            tracing::warn!(
                "[authzen] allow_unsigned_chain = true: authenticated [[peps]] may send \
                 delegation chains without the signed token"
            );
        }
        if config.dev.allow_root_mint {
            tracing::warn!(
                "!!! [dev] allow_root_mint = true: POST /admin/root-token mints root tokens for \
                 users nobody has verified. Development only; never enable this in a deployment. !!!"
            );
        }
        if !idps.is_empty() && agents.is_empty() {
            tracing::warn!(
                "[[idps]] are configured but [[agents]] is empty; IdP intake rejects every request"
            );
        }

        Ok(Self {
            issuer,
            verifier,
            pipeline,
            audit,
            checkpoint_keys,
            checkpoint_interval: std::time::Duration::from_secs(
                config.audit.checkpoint_interval_seconds,
            ),
            leases,
            policies_path: config.policy.policies_path.clone(),
            loaded_policies,
            admin_token: config.admin.token.clone(),
            root_grants: config.root_grants.clone(),
            idps,
            agents,
            dev_allow_root_mint: config.dev.allow_root_mint,
            authzen_allow_unsigned_chain: config.authzen.allow_unsigned_chain,
            authzen_max_batch: config.authzen.max_batch,
            authzen_diagnostics: config.authzen.diagnostics,
            require_actor_auth: config.token.require_actor_auth,
            actor_auth,
            actor_trust,
            peps,
            public_url: config.server.public_url.clone(),
            lease_interval: lease_interval(config)?,
            jwks,
            metrics,
            replay: crate::replay::ReplayCache::default(),
            dpop,
            checkpoint_sink,
            sink_fails_readiness: config.audit.sink.as_ref().is_some_and(|s| s.fail_readiness),
            approvals_client_id: config.approvals.client_id.clone(),
        })
    }

    /// Run `f` on tokio's blocking pool.
    ///
    /// SQLite audit and lease I/O is synchronous and takes a lock, so handlers run it here
    /// instead of on an async worker. Appends still serialize on the audit store's lock, which
    /// is what keeps the hash chain linear no matter how many blocking threads call in.
    pub async fn blocking<R, F>(self: &Arc<Self>, f: F) -> R
    where
        F: FnOnce(&AppState) -> R + Send + 'static,
        R: Send + 'static,
    {
        let state = Arc::clone(self);
        match tokio::task::spawn_blocking(move || f(&state)).await {
            Ok(r) => r,
            Err(e) => std::panic::resume_unwind(e.into_panic()),
        }
    }

    /// Expiry to register for a freshly issued lease: `min(now + lease_interval, token_exp)`.
    pub fn initial_lease_expiry(
        &self,
        now: OffsetDateTime,
        token_exp: OffsetDateTime,
    ) -> OffsetDateTime {
        (now + self.lease_interval).min(token_exp)
    }
}

/// What is known about the policy set in force beyond what the engine holds.
///
/// `GET /admin/policies` reports it so an operator can tell which version of the file is
/// loaded (and `GET /admin/policies/check` whether the file has changed since).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedPolicies {
    /// Hex SHA-256 of the policy file text that was loaded; `None` when no
    /// `policy.policies_path` is configured (no policies, every call denied).
    pub sha256: Option<String>,
    /// When that text was loaded: server start, or the last successful reload.
    pub loaded_at: OffsetDateTime,
}

fn lease_interval(config: &Config) -> anyhow::Result<Duration> {
    let secs = i64::try_from(config.issuer.lease_interval_seconds)
        .context("issuer.lease_interval_seconds is too large")?;
    if secs <= 0 {
        anyhow::bail!("issuer.lease_interval_seconds must be positive");
    }
    Ok(Duration::seconds(secs))
}

fn issuer_config(config: &Config) -> anyhow::Result<IssuerConfig> {
    let ttl = i64::try_from(config.issuer.default_ttl_seconds)
        .context("issuer.default_ttl_seconds is too large")?;
    if ttl <= 0 {
        anyhow::bail!("issuer.default_ttl_seconds must be positive");
    }
    Ok(IssuerConfig {
        issuer: config.issuer.issuer.clone(),
        audience: config.issuer.audience.clone(),
        max_depth: config.issuer.max_depth,
        default_ttl: Duration::seconds(ttl),
    })
}

/// Read the issuer key, or generate it (and write it if a path is configured).
fn load_issuer(config: &Config) -> anyhow::Result<Issuer> {
    let ic = issuer_config(config)?;
    let mut issuer = match &config.issuer.private_key_pem_path {
        Some(path) if path.exists() => {
            let pem = std::fs::read_to_string(path)
                .with_context(|| format!("reading issuer key {}", path.display()))?;
            Issuer::from_pem(ic, &pem)
                .with_context(|| format!("parsing issuer key {}", path.display()))?
        }
        Some(path) => {
            let issuer = Issuer::generate(ic);
            write_private_key(path, &issuer.private_key_pem())?;
            tracing::info!(path = %path.display(), "generated a new issuer key");
            issuer
        }
        None => {
            tracing::warn!(
                "issuer.private_key_pem_path is not set; using an ephemeral key \
                 (tokens will not survive a restart)"
            );
            Issuer::generate(ic)
        }
    };
    for path in &config.issuer.previous_key_paths {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("reading previous issuer key {}", path.display()))?;
        issuer
            .trust_previous_key(&pem)
            .with_context(|| format!("parsing previous issuer key {}", path.display()))?;
    }
    tracing::info!(
        public_key = %issuer.public_key_pem().trim(),
        kid = %issuer.key_id(),
        previous_keys = issuer.trusted_public_keys().len() - 1,
        "issuer public key"
    );
    Ok(issuer)
}

fn write_private_key(path: &Path, pem: &str) -> anyhow::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("creating issuer key {}", path.display()))?;
    std::io::Write::write_all(&mut f, pem.as_bytes())?;
    Ok(())
}

/// Build the policy engine, and return the hex SHA-256 of the policy file text it loaded.
///
/// The file is read here (not by the builder) so the digest is of exactly the text the engine
/// holds.
fn build_engine(config: &Config) -> anyhow::Result<(PolicyEngine, Option<String>)> {
    let catalog = config.policy.load_catalog()?;
    let mut builder = PolicyEngineBuilder::new()
        .with_catalog(catalog)
        .with_unknown_tools(config.policy.unknown_tools)
        .with_legacy_bare_actions(config.policy.legacy_bare_actions)
        .with_annotation_import(config.policy.import_annotations)
        .with_track_usage(config.policy.track_usage);
    if config.policy.legacy_bare_actions {
        tracing::warn!(
            "[policy] legacy_bare_actions = true is deprecated: policies name actions as \
             Action::\"<tool>\", which matches that tool on every server (SR-13). Rewrite them as \
             Action::\"<server>/<tool>\" (`attenuo policy lint` lists them) and remove the switch"
        );
    }
    let user_attrs = attenuo_policy::parse_user_attributes(&config.policy.user_attributes)
        .map_err(|e| anyhow::anyhow!("[policy] {e}"))?;
    for (name, ty) in user_attrs {
        builder = builder.with_user_attr(name, ty);
    }
    match config.policy.unknown_tools {
        attenuo_policy::UnknownTools::Deny => {}
        attenuo_policy::UnknownTools::Sensitive => tracing::info!(
            "[policy] unknown_tools = \"sensitive\": tools missing from the catalog are \
             evaluated as sensitive"
        ),
        attenuo_policy::UnknownTools::Allow => tracing::warn!(
            "[policy] unknown_tools = \"allow\": tools missing from the catalog are evaluated \
             as neither readonly nor sensitive, so forbids keyed on resource.sensitive do not \
             apply to them"
        ),
    }
    let (builder, digest) = match &config.policy.policies_path {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("loading policies: reading {}", path.display()))?;
            let digest = hex::encode(sha2::Sha256::digest(text.as_bytes()));
            (builder.with_policies_str(&text), Some(digest))
        }
        None => {
            tracing::warn!(
                "policy.policies_path is not set; no policies are loaded and every call is denied"
            );
            (builder, None)
        }
    };
    let engine = builder.build().context("loading policies")?;
    for w in engine.validation_warnings() {
        tracing::warn!(warning = %w, "policy validation warning");
    }
    tracing::info!(
        policies = ?engine.policy_ids(),
        sha256 = ?digest,
        run_usage = ?engine.usage_tracking_reasons(),
        "policies loaded"
    );
    Ok((engine, digest))
}

/// A file sink on the same filesystem as the SQLite log does not get the checkpoints off the
/// host's disk; say so (SR-21).
fn warn_if_same_mount(sink_path: &Path, sqlite_path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if sqlite_path == ":memory:" {
            return;
        }
        let dir = |p: &Path| {
            p.parent()
                .filter(|d| !d.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
                .to_path_buf()
        };
        let dev = |p: &Path| std::fs::metadata(p).ok().map(|m| m.dev());
        if let (Some(a), Some(b)) = (dev(&dir(sink_path)), dev(&dir(Path::new(sqlite_path)))) {
            if a == b {
                tracing::warn!(
                    sink = %sink_path.display(),
                    sqlite = sqlite_path,
                    "[audit.sink] path is on the same filesystem as the audit log: an attacker \
                     who can rewrite the log can rewrite this file too. Put it on another mount \
                     and ship it off the host"
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (sink_path, sqlite_path);
}

fn open_storage(
    cfg: &crate::config::AuditSection,
    signer: attenuo_token::DetachedSigner,
    metrics: Arc<Metrics>,
    sink: Option<crate::sink::SinkHandle>,
) -> anyhow::Result<(Arc<SqliteAudit>, Arc<SqliteLeaseStore>)> {
    // Runs after the commit that wrote the checkpoint was synced (SR-50); the sink only queues.
    let count = move |cp: &attenuo_audit::Checkpoint| {
        metrics.audit_checkpoint();
        if let Some(sink) = &sink {
            sink.push(cp);
        }
    };
    let path = cfg.sqlite_path.as_str();
    if path == ":memory:" {
        tracing::warn!("audit.sqlite_path is :memory:; the audit log is lost on exit");
        return Ok((
            Arc::new(
                SqliteAudit::open_in_memory()?
                    .with_checkpointing(signer, cfg.checkpoint_every)
                    .with_checkpoint_hook(count),
            ),
            Arc::new(SqliteLeaseStore::open_in_memory()?),
        ));
    }
    let p = Path::new(path);
    if let Some(dir) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let wal_interval = std::time::Duration::from_secs(cfg.wal_checkpoint_seconds);
    let audit = SqliteAudit::open_with(p, cfg.durability)
        .with_context(|| format!("opening audit log {path}"))?
        .with_checkpointing(signer, cfg.checkpoint_every)
        .with_checkpoint_hook(count)
        .with_wal_checkpoints(wal_interval)
        .with_context(|| format!("starting the WAL checkpointer for {path}"))?;
    let mut leases = SqliteLeaseStore::open_with(p, cfg.durability)
        .with_context(|| format!("opening lease store {path}"))?;
    if !wal_interval.is_zero() {
        // Same file: the audit store's checkpointer covers it.
        leases = leases.without_wal_autocheckpoint()?;
    }
    tracing::info!(
        path,
        durability = %cfg.durability,
        wal_checkpoint_seconds = cfg.wal_checkpoint_seconds,
        "audit store opened (WAL)"
    );
    Ok((Arc::new(audit), Arc::new(leases)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped example config and policy file load together (the policy validates against
    /// the example catalog).
    #[test]
    fn example_config_builds_state() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let text = std::fs::read_to_string(root.join("config/example.toml")).unwrap();
        let mut cfg = Config::from_toml(&text).unwrap();
        cfg.policy.policies_path = Some(root.join("config/policies/default.cedar"));
        cfg.issuer.private_key_pem_path = None;
        cfg.audit.sqlite_path = ":memory:".into();
        let state = AppState::from_config(&cfg).unwrap();
        let ids = state.pipeline.policy().read().unwrap().policy_ids();
        assert!(ids.contains(&"permit_readonly_tools".to_string()));
        assert_eq!(state.admin_token, None);
    }

    #[test]
    fn lease_interval_defaults_to_300_and_must_be_positive() {
        let mut cfg = Config::default();
        assert_eq!(cfg.issuer.lease_interval_seconds, 300);
        let state = AppState::from_config(&cfg).unwrap();
        assert_eq!(state.lease_interval, Duration::seconds(300));
        let now = OffsetDateTime::now_utc();
        // The token's expiry wins when it is sooner than one interval.
        let soon = now + Duration::seconds(10);
        assert_eq!(state.initial_lease_expiry(now, soon), soon);
        let late = now + Duration::hours(1);
        assert_eq!(
            state.initial_lease_expiry(now, late),
            now + Duration::seconds(300)
        );
        cfg.issuer.lease_interval_seconds = 0;
        assert!(AppState::from_config(&cfg).is_err());
    }

    #[test]
    fn authzen_max_batch_defaults_to_64_and_must_be_positive() {
        let mut cfg = Config::default();
        assert_eq!(cfg.authzen.max_batch, 64);
        assert_eq!(AppState::from_config(&cfg).unwrap().authzen_max_batch, 64);
        cfg.authzen.max_batch = 0;
        let err = AppState::from_config(&cfg).err().unwrap();
        assert!(err.to_string().contains("max_batch"), "{err}");
    }

    #[test]
    fn actor_token_only_needs_a_trusted_issuer() {
        let mut cfg = Config::default();
        cfg.token.actor_auth = ActorAuth::ActorToken;
        let err = AppState::from_config(&cfg).err().unwrap();
        assert!(err.to_string().contains("[[actor_trust]]"), "{err}");
    }

    /// SR-08: unsigned AuthZEN chains cannot be switched on without a PEP to authenticate.
    #[test]
    fn unsigned_authzen_chains_need_peps() {
        let mut cfg = Config::default();
        cfg.authzen.allow_unsigned_chain = true;
        let err = AppState::from_config(&cfg).err().unwrap();
        assert!(err.to_string().contains("[[peps]]"), "{err}");
    }

    #[test]
    fn declared_user_attributes_extend_the_schema() {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("p.cedar");
        std::fs::write(
            &policy,
            r#"@id("eng") permit(principal, action, resource)
               when { context.originating_user.attributes has groups &&
                      context.originating_user.attributes.groups.contains("eng") &&
                      context.originating_user.attributes has department &&
                      context.originating_user.attributes.department == "platform" };"#,
        )
        .unwrap();
        let mut cfg = Config::default();
        cfg.policy.policies_path = Some(policy);

        let warnings = |cfg: &Config| {
            let state = AppState::from_config(cfg).unwrap();
            let engine = state.pipeline.policy().read().unwrap();
            engine.validation_warnings().to_vec()
        };
        assert!(!warnings(&cfg).is_empty(), "undeclared attributes warn");

        cfg.policy.user_attributes = [
            ("groups".to_string(), "set<string>".to_string()),
            ("department".to_string(), "string".to_string()),
        ]
        .into();
        assert!(warnings(&cfg).is_empty());
        let state = AppState::from_config(&cfg).unwrap();
        let schema = state
            .pipeline
            .policy()
            .read()
            .unwrap()
            .schema_text()
            .to_string();
        assert!(schema.contains("\"groups\"?: Set<String>"), "{schema}");
        assert!(schema.contains("\"department\"?: String"), "{schema}");

        cfg.policy.user_attributes = [("groups".to_string(), "list".to_string())].into();
        let err = AppState::from_config(&cfg).err().unwrap().to_string();
        assert!(err.contains("user_attributes.groups"), "{err}");
    }

    #[test]
    fn issuer_key_is_written_once_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.issuer.private_key_pem_path = Some(dir.path().join("k/issuer.pem"));
        let a = AppState::from_config(&cfg).unwrap();
        let b = AppState::from_config(&cfg).unwrap();
        assert_eq!(a.issuer.public_key_pem(), b.issuer.public_key_pem());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("k/issuer.pem"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
