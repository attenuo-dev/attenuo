//! A stand-in MCP server for demos: `read_file`, `create_issue` and `delete_repo`, backed by the
//! crate's `FakeMcpServer` (which echoes every `tools/call` instead of doing anything).
//!
//! ```sh
//! cargo run -p attenuo-proxy --features testing --example fake_mcp -- --port 3001
//! ```
//!
//! It prints `listening on http://<addr>/mcp` once bound, and one line to stderr for every
//! `tools/call` it receives, so a demo can show which calls actually reached the upstream.
//! `--port 0` (the default) picks a free port; `--host ADDR` (default 127.0.0.1) is the bind
//! address; `--tools a,b,c` changes the tool names.

use attenuo_proxy::testing::FakeMcpServer;
use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::middleware::{from_fn, Next};
use axum::response::Response;
use serde_json::Value;

async fn log_calls(req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = to_bytes(body, 1 << 20).await.unwrap_or_default();
    if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
        if v["method"] == "tools/call" {
            eprintln!(
                "fake-mcp: tools/call {} {}",
                v["params"]["name"].as_str().unwrap_or("?"),
                v["params"]["arguments"]
            );
        }
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut port: u16 = 0;
    let mut host = "127.0.0.1".to_string();
    let mut tools = vec![
        "read_file".to_string(),
        "create_issue".to_string(),
        "delete_repo".to_string(),
    ];
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--port" => {
                port = args
                    .next()
                    .and_then(|p| p.parse().ok())
                    .ok_or_else(|| anyhow::anyhow!("--port needs a number"))?
            }
            "--host" => {
                host = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--host needs an address"))?
            }
            "--tools" => {
                tools = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--tools needs a comma-separated list"))?
                    .split(',')
                    .map(str::to_owned)
                    .collect()
            }
            other => {
                anyhow::bail!("unknown argument `{other}` (try --port N, --host ADDR, --tools a,b)")
            }
        }
    }
    let names: Vec<&str> = tools.iter().map(String::as_str).collect();
    let router = FakeMcpServer::new(&names)
        .router()
        .layer(from_fn(log_calls));
    let listener = tokio::net::TcpListener::bind((host.as_str(), port)).await?;
    println!("listening on http://{}/mcp", listener.local_addr()?);
    axum::serve(listener, router).await?;
    Ok(())
}
