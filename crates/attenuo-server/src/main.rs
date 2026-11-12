//! `attenuo-server --config <file>` (or `ATTENUO_CONFIG=<file>`).
//!
//! Logging is controlled by `RUST_LOG` (default `info`), its format by `[logging]` and
//! `ATTENUO_LOG_FORMAT` ([`attenuo_server::logging`]). `[telemetry]` adds OpenTelemetry trace
//! export over OTLP/HTTP ([`attenuo_server::telemetry`]).

#![warn(missing_docs)]
#![warn(unreachable_pub)]

use std::path::PathBuf;

use attenuo_server::config::{Config, CONFIG_ENV};
use clap::Parser;

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
    let args = Args::parse();
    let path = args
        .config
        .or_else(|| std::env::var_os(CONFIG_ENV).map(PathBuf::from))
        .ok_or_else(|| {
            anyhow::anyhow!("no config file: pass --config <file> or set {CONFIG_ENV}")
        })?;
    let mut config = Config::load(&path)?;
    config.apply_env();
    // The subscriber needs `[logging]` and `[telemetry]`, so it is installed once the file is
    // read. An unknown log format or a bad `[telemetry]` section stops the server here; an
    // unreachable collector does not.
    let telemetry = attenuo_server::telemetry::init(&config.logging, &config.telemetry)?;
    tracing::info!(config = %path.display(), "config loaded");
    let res = attenuo_server::serve(config).await;
    // After the request drain: give queued spans a bounded moment to leave the host.
    if telemetry.exporting() {
        let _ = tokio::task::spawn_blocking(move || {
            telemetry.shutdown(attenuo_server::telemetry::TELEMETRY_SHUTDOWN_GRACE)
        })
        .await;
    }
    res
}
