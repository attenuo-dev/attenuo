use clap::Parser;
use onbehalf_bench::{run, Opts};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run(Opts::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("onbehalf-bench: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
