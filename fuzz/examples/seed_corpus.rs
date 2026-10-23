//! Write seed inputs for the byte-oriented targets into `fuzz/corpus/<target>/`: the fixture's
//! valid token, its delegation chain, and a valid signed audit export (JSONL and JSON form).
//!
//! `cargo +nightly run --manifest-path fuzz/Cargo.toml --example seed_corpus`

use std::fs;
use std::path::Path;

fn write(target: &str, name: &str, bytes: &[u8]) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join(target);
    fs::create_dir_all(&dir).expect("create corpus dir");
    fs::write(dir.join(name), bytes).expect("write seed");
}

fn main() {
    let f = onbehalf_fuzz::fixture();
    write("token_verify_bytes", "valid_token", f.token.as_bytes());
    let chain = serde_json::to_vec_pretty(&f.claims["chain"]).unwrap();
    write("chain_validate", "valid_chain", &chain);

    let a = onbehalf_fuzz::audit_fixture();
    write(
        "audit_export_bytes",
        "valid_export.jsonl",
        a.text.as_bytes(),
    );
    let json_form = serde_json::to_vec(&onbehalf_audit::to_json_form(&a.export)).unwrap();
    write("audit_export_bytes", "valid_export.json", &json_form);

    let proof = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"a"}}}"#;
    let batch = r#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","method":"notifications/initialized"}]"#;
    write(
        "proxy_sse",
        "event",
        format!("data: {proof}\n\n").as_bytes(),
    );
    write(
        "proxy_sse",
        "batch_event",
        format!("data: {batch}\r\n\r\n").as_bytes(),
    );
    println!("seeds written under fuzz/corpus/");
}
