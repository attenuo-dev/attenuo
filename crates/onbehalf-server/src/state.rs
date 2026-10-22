//! Building the shared state from a [`Config`].

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::Context;
use onbehalf_audit::{SqliteAudit, SqliteLeaseStore};
use onbehalf_policy::{PolicyEngine, PolicyEngineBuilder};
use onbehalf_token::{Issuer, IssuerConfig, Verifier};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use crate::authz::Pipeline;
use crate::config::{Config, RootGrant};

/// Everything the handlers share.
pub struct AppState {
    pub issuer: Issuer,
    pub verifier: Verifier,
    pub pipeline: Arc<Pipeline>,
    pub audit: Arc<SqliteAudit>,
    pub leases: Arc<SqliteLeaseStore>,
    /// Policy file to re-read on reload; `None` when no policy file is configured.
    pub policies_path: Option<PathBuf>,
    pub admin_token: Option<String>,
    pub root_grants: Vec<RootGrant>,
    pub public_url: Option<String>,
    /// `[issuer] lease_interval_seconds`: lifetime of a lease after issuance or renewal.
    pub lease_interval: Duration,
    /// Precomputed `/.well-known/jwks.json` body.
    pub jwks: Value,
}

impl AppState {
    /// Load keys, policies and storage as the config says.
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let issuer = load_issuer(config)?;
        let verifier = issuer.verifier();
        let jwks = crate::jwks::jwks_from_public_pem(&issuer.public_key_pem())?;

        let engine = build_engine(config)?;
        let policy = Arc::new(RwLock::new(engine));

        let (audit, leases) = open_storage(&config.audit.sqlite_path)?;
        let pipeline = Arc::new(Pipeline::new(policy, leases.clone(), audit.clone()));

        Ok(Self {
            issuer,
            verifier,
            pipeline,
            audit,
            leases,
            policies_path: config.policy.policies_path.clone(),
            admin_token: config.admin.token.clone(),
            root_grants: config.root_grants.clone(),
            public_url: config.server.public_url.clone(),
            lease_interval: lease_interval(config)?,
            jwks,
        })
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
    let issuer = match &config.issuer.private_key_pem_path {
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
    tracing::info!(public_key = %issuer.public_key_pem().trim(), "issuer public key");
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

fn build_engine(config: &Config) -> anyhow::Result<PolicyEngine> {
    let catalog = config.policy.load_catalog()?;
    let builder = PolicyEngineBuilder::new().with_catalog(catalog);
    let builder = match &config.policy.policies_path {
        Some(path) => builder.with_policies_file(path),
        None => {
            tracing::warn!(
                "policy.policies_path is not set; no policies are loaded and every call is denied"
            );
            builder
        }
    };
    let engine = builder.build().context("loading policies")?;
    for w in engine.validation_warnings() {
        tracing::warn!(warning = %w, "policy validation warning");
    }
    tracing::info!(policies = ?engine.policy_ids(), "policies loaded");
    Ok(engine)
}

fn open_storage(path: &str) -> anyhow::Result<(Arc<SqliteAudit>, Arc<SqliteLeaseStore>)> {
    if path == ":memory:" {
        tracing::warn!("audit.sqlite_path is :memory:; the audit log is lost on exit");
        return Ok((
            Arc::new(SqliteAudit::open_in_memory()?),
            Arc::new(SqliteLeaseStore::open_in_memory()?),
        ));
    }
    let p = Path::new(path);
    if let Some(dir) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let audit = SqliteAudit::open(p).with_context(|| format!("opening audit log {path}"))?;
    let leases =
        SqliteLeaseStore::open(p).with_context(|| format!("opening lease store {path}"))?;
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
        assert_eq!(
            state.admin_token.as_deref(),
            Some("dev-admin-token-change-me")
        );
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
