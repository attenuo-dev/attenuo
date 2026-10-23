//! `onbehalf`: a command line for a running onbehalf server.
//!
//! Exit status: 0 on success, 1 on an error, 2 when the server answered but said no (a denied
//! call, a negative AuthZEN decision, a broken audit chain), so scripts can tell the two apart.

mod cli;
mod client;
mod jwt;
mod policy_cmd;
mod render;
mod secrets;

use std::io::Read;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::{json, Map, Value};
use time::OffsetDateTime;

use cli::{AuditCmd, AuthzenCmd, Cli, Command, ExportFormat, Field, LeaseCmd, PolicyCmd, TokenCmd};
use client::Client;

/// JSON-RPC error code the proxy uses for a denied call.
const CODE_DENIED: i64 = -32003;

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Ok,
    /// The server answered, and the answer was "no".
    No,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    for line in secrets::argv_warnings(std::env::args_os()) {
        eprintln!("{line}");
    }
    match run(cli).await {
        Ok(Outcome::Ok) => ExitCode::SUCCESS,
        Ok(Outcome::No) => ExitCode::from(2),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Print an offline command's output and map its status to the exit code.
fn finish(run: policy_cmd::Run, error: &str) -> Result<Outcome> {
    print!("{}", run.stdout);
    eprint!("{}", run.stderr);
    match run.status {
        policy_cmd::Status::Ok => Ok(Outcome::Ok),
        policy_cmd::Status::Failed => Ok(Outcome::No),
        policy_cmd::Status::Error => Err(anyhow::anyhow!("{error}")),
    }
}

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

async fn run(cli: Cli) -> Result<Outcome> {
    let json = cli.json;
    // `token inspect` without --verify is purely local; do not insist on a sane --server.
    let mut stdin = secrets::Stdin::default();
    let admin_token = secrets::resolve(
        "admin token",
        cli.admin_token.clone(),
        cli.admin_token_stdin,
        cli.admin_token_file.as_deref(),
        secrets::ADMIN_TOKEN_ENV,
        &mut stdin,
    )?;
    let client = Client::new(&cli.server, admin_token);
    match cli.command {
        Command::Token(TokenCmd::Inspect(args)) => inspect(client.ok(), args, json).await,
        Command::Token(TokenCmd::Root(a)) => {
            let client = client?;
            let resp = client
                .admin_post("/admin/root-token", &a.request_body()?)
                .await?;
            print_token(&resp, a.print, json);
            Ok(Outcome::Ok)
        }
        Command::Token(TokenCmd::Exchange(a)) => {
            let client = client?;
            let subject_token = secrets::resolve_token(
                "--subject-token",
                a.subject_token.clone(),
                a.subject_token_file.as_deref(),
                &mut stdin,
            )?;
            let mut body = json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": subject_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "actor": a.actor,
                "authorization_details": [{
                    "type": "onbehalf_capabilities",
                    "capabilities": cli::parse_caps(&a.caps)?,
                }],
            });
            if let Some(ttl) = a.ttl_seconds {
                body["requested_ttl_seconds"] = ttl.into();
            }
            if a.actor_token.as_deref() == Some("-") {
                // Only one value can come from stdin.
                stdin.claim("actor token")?;
            }
            if let Some(token) = a.actor_token(std::io::stdin())? {
                body["actor_token"] = token.into();
                body["actor_token_type"] = "urn:ietf:params:oauth:token-type:jwt".into();
            }
            let may_act = a.may_act();
            if !may_act.is_empty() {
                body["may_act"] = json!({ "sub": may_act });
            }
            let secret = secrets::resolve(
                "client secret",
                a.client_secret,
                a.client_secret_stdin,
                a.client_secret_file.as_deref(),
                secrets::CLIENT_SECRET_ENV,
                &mut stdin,
            )?;
            if let Some(secret) = secret {
                body["client_id"] = a.client_id.unwrap_or_else(|| a.actor.clone()).into();
                body["client_secret"] = secret.into();
            }
            let resp = client.exchange(&body).await?;
            print_token(&resp, a.print, json);
            Ok(Outcome::Ok)
        }
        Command::Call(a) => {
            let client = client?;
            let token = secrets::resolve_token(
                "--token",
                a.token.token,
                a.token.token_file.as_deref(),
                &mut stdin,
            )?;
            let args: Map<String, Value> = a.args.into_iter().collect();
            let resp = client
                .mcp(
                    &token,
                    &a.server,
                    "tools/call",
                    json!({"name": a.tool, "arguments": args}),
                )
                .await?;
            Ok(print_call(&resp, json))
        }
        Command::Tools(a) => {
            let client = client?;
            let token = secrets::resolve_token(
                "--token",
                a.token.token,
                a.token.token_file.as_deref(),
                &mut stdin,
            )?;
            let resp = client
                .mcp(&token, &a.server, "tools/list", json!({}))
                .await?;
            Ok(print_tools(&resp, json))
        }
        Command::Lease(LeaseCmd::Revoke { id, reason }) => {
            let body = match reason {
                Some(r) => json!({ "reason": r }),
                None => json!({}),
            };
            let resp = client?
                .admin_post(&format!("/admin/leases/{id}/revoke"), &body)
                .await?;
            if json {
                print_json(&resp);
            } else {
                println!(
                    "revoked {} lease(s) starting at {} (reason: {})",
                    resp["revoked"],
                    resp["lease_id"].as_str().unwrap_or(&id),
                    resp["reason"].as_str().unwrap_or("-")
                );
            }
            Ok(Outcome::Ok)
        }
        Command::Lease(LeaseCmd::Show { id }) => {
            let resp = client?.admin_get(&format!("/admin/leases/{id}")).await?;
            if json {
                print_json(&resp);
            } else {
                let s = |k: &str| resp[k].as_str().unwrap_or("-").to_string();
                println!("lease    {}", s("lease_id"));
                println!(
                    "active   {}",
                    if resp["active"] == true { "yes" } else { "no" }
                );
                println!("parent   {}", s("parent"));
                println!("expires  {}", s("expires_at"));
                if !resp["revoked_at"].is_null() {
                    println!("revoked  {} ({})", s("revoked_at"), s("revoke_reason"));
                }
            }
            Ok(Outcome::Ok)
        }
        Command::Audit(AuditCmd::Tail {
            lines,
            follow,
            interval_ms,
        }) => audit_tail(&client?, lines, follow, interval_ms, json).await,
        Command::Audit(AuditCmd::Verify {
            file: Some(file),
            jwks,
        }) => audit_verify_file(client, &file, jwks.as_deref(), json).await,
        Command::Audit(AuditCmd::Export {
            from,
            to,
            format,
            out,
        }) => audit_export(&client?, from, to, format, out.as_deref()).await,
        Command::Audit(AuditCmd::Verify { .. }) => {
            let resp = client?.admin_get("/admin/audit/verify").await?;
            let ok = resp["ok"] == true;
            if json {
                print_json(&resp);
            } else {
                for line in verify_lines(&resp) {
                    println!("{line}");
                }
            }
            Ok(if ok { Outcome::Ok } else { Outcome::No })
        }
        Command::Policy(PolicyCmd::Test { files }) => {
            finish(policy_cmd::test(&files, json), "policy test failed to run")
        }
        Command::Policy(PolicyCmd::Lint {
            policy,
            config,
            schema,
        }) => finish(
            policy_cmd::lint(&policy, config.as_deref(), schema, json),
            "policy lint failed to run",
        ),
        Command::Policy(PolicyCmd::Reload) => {
            let resp = client?
                .admin_post("/admin/policies/reload", &json!({}))
                .await?;
            if json {
                print_json(&resp);
            } else {
                let ids = resp["policy_ids"].as_array().cloned().unwrap_or_default();
                println!("reloaded {} policies", ids.len());
                for id in ids {
                    println!("  {}", id.as_str().unwrap_or_default());
                }
                for w in resp["warnings"].as_array().into_iter().flatten() {
                    println!("warning: {}", w.as_str().unwrap_or_default());
                }
            }
            Ok(Outcome::Ok)
        }
        Command::Authzen(AuthzenCmd::Eval {
            token,
            server,
            tool,
            args,
        }) => {
            let input: Map<String, Value> = args.into_iter().collect();
            // The server fills an empty subject id from the verified chain.
            let req = json!({
                "subject": {"type": "agent", "id": ""},
                "action": {"name": tool, "properties": {"server": server}},
                "resource": {"type": "tool", "id": format!("{server}/{tool}")},
                "context": {"input": input},
            });
            let client = client?;
            let token = secrets::resolve_token(
                "--token",
                token.token,
                token.token_file.as_deref(),
                &mut stdin,
            )?;
            let resp = client.authzen(&token, &req).await?;
            let allow = resp["decision"] == true;
            if json {
                print_json(&resp);
            } else {
                let ctx = &resp["context"];
                println!(
                    "{}  {}",
                    if allow { "ALLOW" } else { "DENY" },
                    ctx["reason"].as_str().unwrap_or("-")
                );
                println!("decision {}", ctx["decision_id"].as_str().unwrap_or("-"));
                let pols: Vec<&str> = ctx["policy_ids"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect();
                if !pols.is_empty() {
                    println!("policies {}", pols.join(", "));
                }
            }
            Ok(if allow { Outcome::Ok } else { Outcome::No })
        }
    }
}

fn print_token(resp: &Value, only: Option<Field>, json: bool) {
    match only {
        Some(Field::Token) => println!("{}", resp["access_token"].as_str().unwrap_or_default()),
        Some(Field::Lease) => println!("{}", resp["lease"].as_str().unwrap_or_default()),
        None if json => print_json(resp),
        None => {
            println!("lease       {}", resp["lease"].as_str().unwrap_or("-"));
            println!("expires_in  {}s", resp["expires_in"]);
            println!(
                "token       {}",
                resp["access_token"].as_str().unwrap_or("-")
            );
        }
    }
}

async fn inspect(client: Option<Client>, args: cli::InspectArgs, json: bool) -> Result<Outcome> {
    let token = if args.jwt == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s.trim().to_string()
    } else {
        args.jwt.trim().to_string()
    };
    let decoded = jwt::decode_unverified(&token)?;
    let now = OffsetDateTime::now_utc();
    let mut verdict: Option<Result<()>> = None;
    if args.verify {
        let client = client.context("--verify needs a valid --server URL to fetch the JWKS")?;
        let jwks = client.get("/.well-known/jwks.json").await?;
        verdict = Some(
            jwt::verify_with_jwks(
                &token,
                &decoded,
                &jwks,
                args.issuer.as_deref(),
                args.audience.as_deref(),
                now,
            )
            .map(|_| ()),
        );
    }
    let verified = verdict.as_ref().map(|v| v.is_ok());
    if json {
        print_json(&json!({
            "header": decoded.header,
            "claims": decoded.claims_json,
            "verified": verified,
            "verify_error": verdict.as_ref().and_then(|v| v.as_ref().err()).map(|e| e.to_string()),
        }));
    } else {
        let c = &decoded.claims;
        print!("{}", render::render_chain_tree(&c.chain, now));
        println!();
        println!("iss {}   aud {}   jti {}", c.iss, c.aud, c.jti);
        if let Ok(exp) = OffsetDateTime::from_unix_timestamp(c.exp) {
            println!(
                "exp {} ({})",
                render::fmt_time(exp),
                render::fmt_relative(exp, now)
            );
        }
        match &verdict {
            None => println!("signature NOT verified (decoded only; pass --verify to check it)"),
            Some(Ok(())) => println!("verified: signature, type, issuer, audience, expiry, chain"),
            Some(Err(e)) => println!("verification FAILED: {e}"),
        }
    }
    match verdict {
        Some(Err(_)) => Ok(Outcome::No),
        _ => Ok(Outcome::Ok),
    }
}

/// Print a `tools/call` response. A policy denial is reported with its reason and decision id.
fn print_call(resp: &Value, json: bool) -> Outcome {
    if json {
        print_json(resp);
    }
    if let Some(err) = resp.get("error") {
        let denied = err["code"].as_i64() == Some(CODE_DENIED);
        if !json {
            if denied {
                println!("DENIED  {}", err["data"]["reason"].as_str().unwrap_or("-"));
                println!(
                    "decision {}",
                    err["data"]["decision_id"].as_str().unwrap_or("-")
                );
            } else {
                eprintln!(
                    "error {}: {}",
                    err["code"],
                    err["message"].as_str().unwrap_or("-")
                );
            }
        }
        return Outcome::No;
    }
    if !json {
        let result = &resp["result"];
        println!("ALLOWED");
        for item in result["content"].as_array().into_iter().flatten() {
            match item["text"].as_str() {
                Some(t) if item["type"] == "text" => println!("{t}"),
                _ => println!("{item}"),
            }
        }
        if result["isError"] == true {
            println!("(the tool reported an error)");
        }
    }
    Outcome::Ok
}

fn print_tools(resp: &Value, json: bool) -> Outcome {
    if json {
        print_json(resp);
        return if resp.get("error").is_some() {
            Outcome::No
        } else {
            Outcome::Ok
        };
    }
    if let Some(err) = resp.get("error") {
        eprintln!(
            "error {}: {}",
            err["code"],
            err["message"].as_str().unwrap_or("-")
        );
        return Outcome::No;
    }
    let tools = resp["result"]["tools"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if tools.is_empty() {
        println!("(no tools visible to this token)");
    }
    for t in tools {
        println!(
            "{:<20} {}",
            t["name"].as_str().unwrap_or("-"),
            t["description"].as_str().unwrap_or("")
        );
    }
    Outcome::Ok
}

/// Human-readable lines for a `/admin/audit/verify` report: the chain verdict, then the
/// checkpoint status (how many, the last signed seq, how many entries are not yet covered, and
/// any checkpoint that failed).
fn verify_lines(resp: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if resp["first_bad_seq"].is_null() {
        out.push(format!(
            "audit chain OK: {} entries verified",
            resp["entries"]
        ));
    } else {
        out.push(format!(
            "audit chain BROKEN at seq {} ({} entries examined)",
            resp["first_bad_seq"], resp["entries"]
        ));
    }
    let n = resp["checkpoints"].as_u64().unwrap_or(0);
    match resp["last_signed_seq"].as_u64() {
        Some(seq) => out.push(format!(
            "checkpoints: {n} signed, last at seq {seq} ({} entries after it are not yet signed)",
            resp["unsigned_tail"]
        )),
        None if n == 0 => out.push("checkpoints: none signed yet".to_string()),
        None => out.push(format!("checkpoints: {n} found, none verified")),
    }
    for bad in resp["bad_checkpoints"].as_array().into_iter().flatten() {
        out.push(format!(
            "checkpoint at seq {} INVALID: {}",
            bad["seq"],
            bad["reason"].as_str().unwrap_or("unknown")
        ));
    }
    out
}

/// `audit export`: stream the server's JSON Lines to `out` (or stdout), or collect them into
/// one JSON object for `--format json`.
async fn audit_export(
    client: &Client,
    from: u64,
    to: Option<u64>,
    format: ExportFormat,
    out: Option<&std::path::Path>,
) -> Result<Outcome> {
    use std::io::Write;

    let mut path = format!("/admin/audit/export?from={from}");
    if let Some(to) = to {
        path.push_str(&format!("&to={to}"));
    }
    let mut resp = client.admin_get_stream(&path).await?;
    let mut sink: Box<dyn Write> = match out {
        Some(p) => Box::new(std::io::BufWriter::new(
            std::fs::File::create(p).with_context(|| format!("creating {}", p.display()))?,
        )),
        None => Box::new(std::io::stdout().lock()),
    };
    match format {
        ExportFormat::Jsonl => {
            while let Some(chunk) = resp.chunk().await? {
                sink.write_all(&chunk)?;
            }
        }
        ExportFormat::Json => {
            let text = resp.text().await?;
            let export = onbehalf_audit::parse_export(&text)?;
            serde_json::to_writer_pretty(&mut sink, &onbehalf_audit::to_json_form(&export))?;
            writeln!(sink)?;
        }
    }
    sink.flush()?;
    Ok(Outcome::Ok)
}

/// `audit verify --file`: check an export with nothing but the issuer's JWKS.
async fn audit_verify_file(
    client: Result<Client>,
    file: &std::path::Path,
    jwks: Option<&std::path::Path>,
    json: bool,
) -> Result<Outcome> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let export = onbehalf_audit::parse_export(&text)
        .with_context(|| format!("parsing {}", file.display()))?;
    let jwks: Value = match jwks {
        Some(p) => serde_json::from_str(
            &std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
        )
        .with_context(|| format!("{} is not JSON", p.display()))?,
        None => client?
            .get("/.well-known/jwks.json")
            .await
            .context("fetching the JWKS (or pass --jwks <file>)")?,
    };
    let keys = onbehalf_audit::CheckpointKeys::from_jwks(&jwks)?;
    let report = onbehalf_audit::verify_export(&export, &keys)?;
    let v = serde_json::to_value(&report)?;
    if json {
        print_json(&v);
    } else {
        for line in export_lines(&v) {
            println!("{line}");
        }
    }
    Ok(if report.report.ok {
        Outcome::Ok
    } else {
        Outcome::No
    })
}

/// Text for an offline export verification: what the file covers, then the same chain and
/// checkpoint lines as the live `audit verify`.
fn export_lines(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    match (v["first_seq"].as_u64(), v["last_seq"].as_u64()) {
        (Some(f), Some(l)) => out.push(format!("export covers seq {f}..{l}")),
        _ => out.push("export holds no entries".to_string()),
    }
    out.extend(verify_lines(v));
    if v["truncated"] == true {
        out.push("export is TRUNCATED: entries named in its header are missing".to_string());
    }
    if v["from_genesis"] == false && v["first_seq"].is_u64() {
        out.push(format!(
            "note: the file does not start at the first entry of the log; entries before seq {} are not covered",
            v["first_seq"]
        ));
    }
    out
}

/// One line per audit entry.
fn fmt_audit_entry(e: &Value) -> String {
    let r = &e["record"];
    let agents: Vec<&str> = r["agents"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    // Admin actions have no delegation chain, so no agents.
    let who = if agents.is_empty() {
        "by".to_string()
    } else {
        format!("{} for", agents.join(" > "))
    };
    format!(
        "#{:<4} {}  {:<5} {}/{}  {} {}  reason={}  id={}",
        e["seq"].as_u64().unwrap_or(0),
        r["at"].as_str().unwrap_or("-"),
        r["decision"].as_str().unwrap_or("-").to_uppercase(),
        r["server"].as_str().unwrap_or("-"),
        r["tool"].as_str().unwrap_or("-"),
        who,
        r["originating_subject"].as_str().unwrap_or("-"),
        r["reason"].as_str().unwrap_or("-"),
        r["id"].as_str().unwrap_or("-"),
    )
}

async fn audit_tail(
    client: &Client,
    lines: u64,
    follow: bool,
    interval_ms: u64,
    json: bool,
) -> Result<Outcome> {
    let show = |e: &Value| {
        if json {
            println!("{e}");
        } else {
            println!("{}", fmt_audit_entry(e));
        }
    };
    // `head` comes with any page; unlike `/admin/audit/checkpoint` it signs nothing, so polling
    // with `--follow` does not add a checkpoint per new entry.
    let head = client
        .admin_get("/admin/audit?from=1&limit=1")
        .await
        .ok()
        .and_then(|c| c["head"].as_u64())
        .unwrap_or(0);
    let mut from = (head + 1).saturating_sub(lines).max(1);
    loop {
        let page = client
            .admin_get(&format!("/admin/audit?from={from}&limit=1000"))
            .await?;
        for e in page["entries"].as_array().into_iter().flatten() {
            show(e);
            if let Some(seq) = e["seq"].as_u64() {
                from = seq + 1;
            }
        }
        if page["next"].is_null() {
            if !follow {
                return Ok(Outcome::Ok);
            }
            tokio::time::sleep(Duration::from_millis(interval_ms.max(50))).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_lines_describe_coverage_and_problems() {
        let v = json!({"entries": 5, "ok": false, "first_bad_seq": null, "checkpoints": 1,
                       "last_signed_seq": 8, "unsigned_tail": 0, "bad_checkpoints": [],
                       "first_seq": 4, "last_seq": 8, "from_genesis": false,
                       "truncated": true});
        let lines = export_lines(&v);
        assert_eq!(lines[0], "export covers seq 4..8");
        assert!(lines.iter().any(|l| l.contains("TRUNCATED")), "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|l| l.contains("entries before seq 4 are not covered")),
            "{lines:?}"
        );
    }

    #[test]
    fn verify_output_reports_checkpoint_status() {
        let ok = json!({"entries": 12, "ok": true, "first_bad_seq": null, "checkpoints": 2,
                        "last_signed_seq": 10, "unsigned_tail": 2, "bad_checkpoints": []});
        let lines = verify_lines(&ok);
        assert_eq!(lines[0], "audit chain OK: 12 entries verified");
        assert!(lines[1].contains("2 signed, last at seq 10"), "{lines:?}");
        assert!(lines[1].contains("2 entries after it"), "{lines:?}");

        let none = json!({"entries": 3, "ok": true, "first_bad_seq": null, "checkpoints": 0,
                          "last_signed_seq": null, "unsigned_tail": 3, "bad_checkpoints": []});
        assert_eq!(verify_lines(&none)[1], "checkpoints: none signed yet");

        let bad = json!({"entries": 8, "ok": false, "first_bad_seq": null, "checkpoints": 1,
                         "last_signed_seq": null, "unsigned_tail": 8,
                         "bad_checkpoints": [{"seq": 5, "reason": "signature does not verify"}]});
        let lines = verify_lines(&bad);
        assert_eq!(lines[1], "checkpoints: 1 found, none verified");
        assert_eq!(
            lines[2],
            "checkpoint at seq 5 INVALID: signature does not verify"
        );
    }

    #[test]
    fn audit_line_names_decision_tool_chain_and_id() {
        let e = json!({"seq": 7, "record": {
            "id": "abc", "at": "2026-10-22T09:00:00Z", "decision": "deny",
            "reason": "capability_denied", "originating_subject": "alice",
            "agents": ["planner", "coder"], "server": "github", "tool": "delete_repo"}});
        assert_eq!(
            fmt_audit_entry(&e),
            "#7    2026-10-22T09:00:00Z  DENY  github/delete_repo  planner > coder for alice  reason=capability_denied  id=abc"
        );
    }

    #[test]
    fn denial_is_recognised_and_success_is_not() {
        let denied = json!({"jsonrpc": "2.0", "id": 1, "error": {
            "code": -32003, "message": "onbehalf: denied: policy_deny",
            "data": {"reason": "policy_deny", "decision_id": "d1"}}});
        assert_eq!(print_call(&denied, false), Outcome::No);
        let ok = json!({"jsonrpc": "2.0", "id": 1, "result": {
            "content": [{"type": "text", "text": "hi"}], "isError": false}});
        assert_eq!(print_call(&ok, false), Outcome::Ok);
    }

    #[test]
    fn tools_list_prints_or_fails() {
        let ok = json!({"result": {"tools": [{"name": "read_file", "description": "d"}]}});
        assert_eq!(print_tools(&ok, false), Outcome::Ok);
        assert_eq!(
            print_tools(&json!({"error": {"code": -1}}), false),
            Outcome::No
        );
    }

    #[test]
    fn server_name_instead_of_url_is_explained() {
        let err = Client::new("github", None).err().unwrap().to_string();
        assert!(err.contains("base URL"), "{err}");
    }
}
