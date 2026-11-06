//! `attenuo-server --config <file>` (or `ATTENUO_CONFIG=<file>`).
//!
//! Logging is controlled by `RUST_LOG` (default `info`).

#![warn(missing_docs)]
#![warn(unreachable_pub)]

use std::path::PathBuf;

use attenuo_server::config::{Config, CONFIG_ENV};
use clap::Parser;
use tracing_subscriber::EnvFilter;

/// attenuo: delegation tokens, per-call policy and a hash-chained audit log for AI agents.
#[derive(Debug, Parser)]
#[command(name = "attenuo-server", version, about)]
struct Args {
    /// Path to the TOML config file. Falls back to the ATTENUO_CONFIG environment variable.
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
    attenuo_server::serve(config).await
}
