//! `onbehalf-server --config <file>` (or `ONBEHALF_CONFIG=<file>`).
//!
//! Logging is controlled by `RUST_LOG` (default `info`).

use std::path::PathBuf;

use clap::Parser;
use onbehalf_server::config::{Config, CONFIG_ENV};
use tracing_subscriber::EnvFilter;

/// onbehalf: delegation tokens, per-call policy and a hash-chained audit log for AI agents.
#[derive(Debug, Parser)]
#[command(name = "onbehalf-server", version, about)]
struct Args {
    /// Path to the TOML config file. Falls back to the ONBEHALF_CONFIG environment variable.
    #[arg(long, short)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    let path = args
        .config
        .or_else(|| std::env::var_os(CONFIG_ENV).map(PathBuf::from))
        .ok_or_else(|| {
            anyhow::anyhow!("no config file: pass --config <file> or set {CONFIG_ENV}")
        })?;
    tracing::info!(config = %path.display(), "loading config");
    let mut config = Config::load(&path)?;
    config.apply_env();
    onbehalf_server::serve(config).await
}
