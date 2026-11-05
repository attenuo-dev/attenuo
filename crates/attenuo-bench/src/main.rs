#![deny(unsafe_code)]

use attenuo_bench::{run, Opts};
use clap::Parser;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run(Opts::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("attenuo-bench: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
