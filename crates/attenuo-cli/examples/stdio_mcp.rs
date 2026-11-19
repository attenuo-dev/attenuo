//! A stand-in STDIO MCP server for the `attenuo stdio-bridge` tests: newline-delimited
//! JSON-RPC on stdin and stdout, a log line on stderr for everything it receives.
//!
//! ```sh
//! cargo run -p attenuo-cli --example stdio_mcp
//! attenuo stdio-bridge --listen 127.0.0.1:3001 -- target/debug/examples/stdio_mcp
//! ```
//!
//! Tools: `read_file`, `create_issue`, `delete_repo` and `echo` answer
//! `{"name": ..., "arguments": ...}` as text, like the proxy's fake HTTP server; `slow` does
//! the same after `arguments.ms` milliseconds; `big` answers a text of `arguments.bytes`
//! bytes; `pid` answers its process id; `stats` answers how many `initialize` requests and
//! `notifications/initialized` it got; `exit` exits with status 3 at once.
//!
//! Before answering a `tools/call` it writes a `notifications/progress` that carries a
//! `result` member and a `ping` request that reuses the call's id, which a bridge must take
//! for neither the answer nor anything else. Calls are answered on their own threads, so a
//! slow call does not hold up a fast one and answers can come out of order.
//!
//! Every line on stderr starts with `stdio-mcp:`: `tools/call NAME ARGS`, `initialize`, and
//! `response ID` for each response it receives.

use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

const TOOLS: &[&str] = &[
    "read_file",
    "create_issue",
    "delete_repo",
    "echo",
    "slow",
    "big",
    "pid",
    "stats",
    "exit",
];

fn send(out: &Mutex<std::io::Stdout>, msg: &Value) {
    let mut out = out.lock().expect("stdout lock");
    let _ = writeln!(out, "{msg}");
    let _ = out.flush();
}

fn text(id: &Value, text: String) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": {
        "content": [{"type": "text", "text": text}], "isError": false}})
}

fn main() {
    let out = Arc::new(Mutex::new(std::io::stdout()));
    let inits = Arc::new(AtomicU64::new(0));
    let initialized = Arc::new(AtomicU64::new(0));
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            eprintln!("stdio-mcp: not JSON: {line}");
            continue;
        };
        let id = msg.get("id").cloned();
        let method = msg["method"].as_str().map(str::to_owned);
        let (Some(method), Some(id)) = (method, id.clone()) else {
            match (msg["method"].as_str(), id) {
                (Some("notifications/initialized"), _) => {
                    initialized.fetch_add(1, Ordering::SeqCst);
                }
                (Some(m), _) => eprintln!("stdio-mcp: notification {m}"),
                (None, Some(id)) => eprintln!("stdio-mcp: response {id}"),
                (None, None) => eprintln!("stdio-mcp: not a message"),
            }
            continue;
        };
        match method.as_str() {
            "initialize" => {
                inits.fetch_add(1, Ordering::SeqCst);
                eprintln!("stdio-mcp: initialize");
                let version = msg["params"]["protocolVersion"]
                    .as_str()
                    .unwrap_or("2025-06-18");
                send(
                    &out,
                    &json!({"jsonrpc": "2.0", "id": id, "result": {
                        "protocolVersion": version,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "stdio-mcp", "version": "0.0.0"}}}),
                );
            }
            "tools/list" => {
                let tools: Vec<Value> = TOOLS
                    .iter()
                    .map(|t| json!({"name": t, "inputSchema": {"type": "object"}}))
                    .collect();
                send(
                    &out,
                    &json!({"jsonrpc": "2.0", "id": id, "result": {"tools": tools}}),
                );
            }
            "ping" => send(&out, &json!({"jsonrpc": "2.0", "id": id, "result": {}})),
            "tools/call" => {
                let name = msg["params"]["name"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                let args = msg["params"]
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                eprintln!("stdio-mcp: tools/call {name} {args}");
                if name == "exit" {
                    std::process::exit(3);
                }
                send(
                    &out,
                    &json!({"jsonrpc": "2.0", "method": "notifications/progress",
                            "params": {"progressToken": id, "progress": 0}, "result": {}}),
                );
                send(&out, &json!({"jsonrpc": "2.0", "id": id, "method": "ping"}));
                let out = out.clone();
                let stats = (
                    inits.load(Ordering::SeqCst),
                    initialized.load(Ordering::SeqCst),
                );
                std::thread::spawn(move || {
                    let reply = match name.as_str() {
                        "slow" => {
                            let ms = args["ms"].as_u64().unwrap_or(0);
                            std::thread::sleep(Duration::from_millis(ms));
                            text(&id, json!({"name": name, "arguments": args}).to_string())
                        }
                        "big" => {
                            let n = args["bytes"].as_u64().unwrap_or(0);
                            text(&id, "x".repeat(usize::try_from(n).unwrap_or(0)))
                        }
                        "pid" => text(&id, std::process::id().to_string()),
                        "stats" => text(
                            &id,
                            json!({"initialize": stats.0, "initialized": stats.1}).to_string(),
                        ),
                        n if TOOLS.contains(&n) => {
                            text(&id, json!({"name": name, "arguments": args}).to_string())
                        }
                        other => json!({"jsonrpc": "2.0", "id": id, "error": {
                            "code": -32602, "message": format!("unknown tool {other}")}}),
                    };
                    send(&out, &reply);
                });
            }
            other => send(
                &out,
                &json!({"jsonrpc": "2.0", "id": id, "error": {
                    "code": -32601, "message": format!("method not found: {other}")}}),
            ),
        }
    }
}
