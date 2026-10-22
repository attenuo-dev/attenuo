//! `onbehalf`: a command line for a running onbehalf server.
//!
//! Exit status: 0 on success, 1 on an error, 2 when the server answered but said no (a denied
//! call, a negative AuthZEN decision, a broken audit chain), so scripts can tell the two apart.

mod cli;
mod client;
mod jwt;
mod render;

use std::io::Read;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::{json, Map, Value};
use time::OffsetDateTime;

use cli::{AuditCmd, AuthzenCmd, Cli, Command, Field, LeaseCmd, PolicyCmd, TokenCmd};
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
    match run(cli).await {
        Ok(Outcome::Ok) => ExitCode::SUCCESS,
        Ok(Outcome::No) => ExitCode::from(2),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

async fn run(cli: Cli) -> Result<Outcome> {
    let json = cli.json;
    // `token inspect` without --verify is purely local; do not insist on a sane --server.
    let client = Client::new(&cli.server, cli.admin_token.clone());
    match cli.command {
        Command::Token(TokenCmd::Inspect(args)) => inspect(client.ok(), args, json).await,
        Command::Token(TokenCmd::Root(a)) => {
            let client = client?;
            let mut body = Map::new();
            body.insert("subject".into(), a.subject.into());
            body.insert("issuer".into(), a.issuer.into());
            body.insert("agent".into(), a.agent.into());
            if !a.caps.is_empty() {
                body.insert("capabilities".into(), cli::parse_caps(&a.caps)?.into());
            }
            if let Some(ttl) = a.ttl_seconds {
                body.insert("ttl_seconds".into(), ttl.into());
            }
            if !a.attrs.is_empty() {
                body.insert(
                    "attributes".into(),
                    a.attrs.into_iter().collect::<Map<_, _>>().into(),
                );
            }
            let resp = client
                .admin_post("/admin/root-token", &Value::Object(body))
                .await?;
            print_token(&resp, a.print, json);
            Ok(Outcome::Ok)
        }
        Command::Token(TokenCmd::Exchange(a)) => {
            let client = client?;
            let mut body = json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": a.subject_token,
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
            let resp = client.exchange(&body).await?;
            print_token(&resp, a.print, json);
            Ok(Outcome::Ok)
        }
        Command::Call(a) => {
            let args: Map<String, Value> = a.args.into_iter().collect();
            let resp = client?
                .mcp(
                    &a.token,
                    &a.server,
                    "tools/call",
                    json!({"name": a.tool, "arguments": args}),
                )
                .await?;
            Ok(print_call(&resp, json))
        }
        Command::Tools(a) => {
            let resp = client?
                .mcp(&a.token, &a.server, "tools/list", json!({}))
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
        Command::Audit(AuditCmd::Verify) => {
            let resp = client?.admin_get("/admin/audit/verify").await?;
            let ok = resp["ok"] == true;
            if json {
                print_json(&resp);
            } else if ok {
                println!("audit chain OK: {} entries verified", resp["entries"]);
            } else {
                println!(
                    "audit chain BROKEN at seq {} ({} entries examined)",
                    resp["first_bad_seq"], resp["entries"]
                );
            }
            Ok(if ok { Outcome::Ok } else { Outcome::No })
        }
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
            let resp = client?.authzen(&token, &req).await?;
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

/// One line per audit entry.
fn fmt_audit_entry(e: &Value) -> String {
    let r = &e["record"];
    let agents: Vec<&str> = r["agents"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    format!(
        "#{:<4} {}  {:<5} {}/{}  {} for {}  reason={}  id={}",
        e["seq"].as_u64().unwrap_or(0),
        r["at"].as_str().unwrap_or("-"),
        r["decision"].as_str().unwrap_or("-").to_uppercase(),
        r["server"].as_str().unwrap_or("-"),
        r["tool"].as_str().unwrap_or("-"),
        agents.join(" > "),
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
    let head = client
        .admin_get("/admin/audit/checkpoint")
        .await
        .ok()
        .and_then(|c| c["seq"].as_u64())
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
