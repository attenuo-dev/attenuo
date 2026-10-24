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
//!
//! Scripted outputs: `POST /script` with `{"outputs": {"<tool>": ["text", ...]}}` replaces the
//! script. Each later `tools/call` of `<tool>` takes the next text from its list and gets it as
//! a second `text` content item after the echo; a tool with no text left gets the echo only.
//! `{"outputs": {}}` clears the script. The injection suite uses this for its `output:` field.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use attenuo_proxy::testing::FakeMcpServer;
use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use serde_json::{json, Value};

/// Texts still to be returned, per tool name, in order.
#[derive(Clone, Default)]
struct Script(Arc<Mutex<HashMap<String, VecDeque<String>>>>);

impl Script {
    fn take(&self, tool: &str) -> Option<String> {
        self.0.lock().ok()?.get_mut(tool)?.pop_front()
    }
}

async fn set_script(State(script): State<Script>, body: Bytes) -> StatusCode {
    let Ok(v) = serde_json::from_slice::<Value>(&body) else {
        return StatusCode::BAD_REQUEST;
    };
    let Some(outputs) = v["outputs"].as_object() else {
        return StatusCode::BAD_REQUEST;
    };
    let mut new = HashMap::new();
    for (tool, texts) in outputs {
        let Some(list) = texts.as_array() else {
            return StatusCode::BAD_REQUEST;
        };
        let texts: Option<VecDeque<String>> =
            list.iter().map(|t| t.as_str().map(str::to_owned)).collect();
        let Some(texts) = texts else {
            return StatusCode::BAD_REQUEST;
        };
        new.insert(tool.clone(), texts);
    }
    match script.0.lock() {
        Ok(mut m) => {
            *m = new;
            StatusCode::NO_CONTENT
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Append the scripted text of each reply's request `id` to that reply's `content`.
fn add_output(reply: &mut Value, outputs: &[(Value, String)]) {
    let items = match reply {
        Value::Array(items) => items.iter_mut().collect::<Vec<_>>(),
        other => vec![other],
    };
    for item in items {
        let Some((_, text)) = outputs.iter().find(|(id, _)| *id == item["id"]) else {
            continue;
        };
        if let Some(content) = item["result"]["content"].as_array_mut() {
            content.push(json!({"type": "text", "text": text}));
        }
    }
}

async fn log_calls(State(script): State<Script>, req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = to_bytes(body, 1 << 20).await.unwrap_or_default();
    let mut outputs: Vec<(Value, String)> = Vec::new();
    if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
        if v["method"] == "tools/call" {
            eprintln!(
                "fake-mcp: tools/call {} {}",
                v["params"]["name"].as_str().unwrap_or("?"),
                v["params"]["arguments"]
            );
        }
        let msgs = match &v {
            Value::Array(items) => items.iter().collect::<Vec<_>>(),
            other => vec![other],
        };
        for m in msgs {
            if m["method"] == "tools/call" {
                if let Some(text) = script.take(m["params"]["name"].as_str().unwrap_or_default()) {
                    outputs.push((m["id"].clone(), text));
                }
            }
        }
    }
    let response = next
        .run(Request::from_parts(parts, Body::from(bytes)))
        .await;
    if outputs.is_empty() {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let bytes = to_bytes(body, 1 << 24).await.unwrap_or_default();
    let Ok(mut reply) = serde_json::from_slice::<Value>(&bytes) else {
        return Response::from_parts(parts, Body::from(bytes));
    };
    add_output(&mut reply, &outputs);
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(reply.to_string()))
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
    let script = Script::default();
    let router = Router::new()
        .route("/script", post(set_script))
        .with_state(script.clone())
        .merge(FakeMcpServer::new(&names).router())
        .layer(from_fn_with_state(script, log_calls));
    let listener = tokio::net::TcpListener::bind((host.as_str(), port)).await?;
    println!("listening on http://{}/mcp", listener.local_addr()?);
    axum::serve(listener, router).await?;
    Ok(())
}
