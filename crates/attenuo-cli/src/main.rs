//! `attenuo`: a command line for a running attenuo server.
//!
//! Exit status: 0 on success, 1 on an error, 2 when the server answered but said no (a denied
//! call, a negative AuthZEN decision, a broken audit chain), so scripts can tell the two apart.
//! `budget refund` also exits 3 when the decision was already refunded, so a retried refund can
//! be told from one that found nothing to refund (2).

mod cli;
mod client;
mod dpop_key;
mod jwt;
mod policy_cmd;
mod render;
mod secrets;
mod watch;

use std::io::Read;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::{json, Map, Value};
use time::OffsetDateTime;

use cli::{
    ApprovalCmd, AuditCmd, AuthzenCmd, BudgetCmd, Cli, Command, ExportFormat, Field, KeyCmd,
    LeaseCmd, PolicyCmd, TokenCmd,
};
use client::{query_escape, Client};
use render::fmt_audit_entry;

/// JSON-RPC error code the proxy uses for a denied call.
const CODE_DENIED: i64 = -32003;
/// JSON-RPC error code the proxy uses for a call that needs an approval (ADR-0009).
const CODE_APPROVAL_REQUIRED: i64 = -32008;

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Ok,
    /// The server answered, and the answer was "no".
    No,
    /// The server answered with a refusal that has an exit status of its own (the message is
    /// already on stderr).
    Exit(u8),
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
        Ok(Outcome::Exit(code)) => ExitCode::from(code),
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
        Command::Key(KeyCmd::Gen { dpop }) => {
            let key = dpop_key::generate(&dpop)?;
            if json {
                print_json(&json!({"path": dpop, "jkt": key.thumbprint(), "alg": key.alg()}));
            } else {
                println!("wrote DPoP key {} ({})", dpop.display(), key.alg());
                println!("jkt  {}", key.thumbprint());
            }
            Ok(Outcome::Ok)
        }
        Command::Token(TokenCmd::Root(a)) => {
            let client = client?;
            let key = dpop_key::load_opt(a.dpop_key.as_deref())?;
            let resp = client.root(&a.request_body()?, key.as_ref()).await?;
            print_token(&resp, a.print, json);
            Ok(Outcome::Ok)
        }
        Command::Token(TokenCmd::SignOff(a)) => {
            let client = client?;
            let subject_token = secrets::resolve_token(
                "--subject-token",
                a.subject_token.clone(),
                a.subject_token_file.as_deref(),
                &mut stdin,
            )?;
            let proof = dpop_key::sign_off(
                &client.token_url(),
                &subject_token,
                &a.dpop_key,
                &a.child_jkt,
                &a.actor,
            )?;
            if json {
                print_json(&json!({"subject_token_dpop": proof}));
            } else {
                println!("{proof}");
            }
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
                    "type": "attenuo_capabilities",
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
            if let Some(may_act) = a.may_act_claim()? {
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
            let given = a
                .subject_token_dpop_file
                .as_deref()
                .map(|p| secrets::from_file("subject_token_dpop", p))
                .transpose()?;
            let url = client.token_url();
            let proofs = |nonce: Option<&str>| {
                dpop_key::exchange_proofs(
                    &url,
                    &subject_token,
                    &a.actor,
                    a.dpop_key.as_deref(),
                    a.subject_dpop_key.as_deref(),
                    given.is_some(),
                    nonce,
                )
            };
            let (_, sign_off) = proofs(None)?;
            if let Some(proof) = sign_off.or(given.clone()) {
                body["subject_token_dpop"] = proof.into();
            }
            // The header proof is made again, with the server's nonce, if it asks for one.
            let resp = client.exchange(&body, |nonce| Ok(proofs(nonce)?.0)).await?;
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
            let key = dpop_key::load_opt(a.token.dpop_key.as_deref())?;
            let resp = client
                .mcp(
                    &token,
                    key.as_ref(),
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
            let key = dpop_key::load_opt(a.token.dpop_key.as_deref())?;
            let resp = client
                .mcp(&token, key.as_ref(), &a.server, "tools/list", json!({}))
                .await?;
            Ok(print_tools(&resp, json))
        }
        Command::Lease(LeaseCmd::Revoke {
            id: None,
            user,
            chain_id,
            preview,
            reason,
        }) => {
            let mut body = match (user, chain_id) {
                (Some(u), None) => json!({ "user": u }),
                (None, Some(c)) => json!({ "chain_id": c }),
                _ => anyhow::bail!("give exactly one of a lease id, --user or --chain-id"),
            };
            if let Some(r) = reason {
                body["reason"] = json!(r);
            }
            let path = if preview {
                "/admin/leases/revoke?preview=true"
            } else {
                "/admin/leases/revoke"
            };
            let resp = client?.admin_post(path, &body).await?;
            if json {
                print_json(&resp);
            } else {
                print!("{}", render::render_selector_revocation(&resp));
            }
            Ok(Outcome::Ok)
        }
        Command::Lease(LeaseCmd::Revoke {
            id: Some(id),
            reason,
            ..
        }) => {
            let body = match reason {
                Some(r) => json!({ "reason": r }),
                None => json!({}),
            };
            let resp = client?
                .admin_post(
                    &format!("/admin/leases/{}/revoke", query_escape(&id)),
                    &body,
                )
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
        Command::Approval(ApprovalCmd::List {
            chain_id,
            state,
            limit,
        }) => {
            let mut q = Vec::new();
            if let Some(c) = chain_id {
                q.push(format!("chain_id={}", query_escape(&c)));
            }
            if let Some(s) = state {
                q.push(format!("state={}", query_escape(&s)));
            }
            if let Some(n) = limit {
                q.push(format!("limit={n}"));
            }
            let mut path = "/admin/approvals".to_string();
            if !q.is_empty() {
                path.push('?');
                path.push_str(&q.join("&"));
            }
            let resp = client?.admin_get(&path).await?;
            if json {
                print_json(&resp);
            } else {
                print!("{}", render::render_approvals(&resp));
            }
            Ok(Outcome::Ok)
        }
        Command::Approval(ApprovalCmd::Show { id }) => {
            let resp = client?
                .admin_get(&format!("/admin/approvals/{}", query_escape(&id)))
                .await?;
            if json {
                print_json(&resp);
            } else {
                print!("{}", render::render_approval(&resp));
            }
            Ok(Outcome::Ok)
        }
        Command::Approval(ApprovalCmd::Grant { id }) => {
            approval_decide(&client?, &id, "grant", json).await
        }
        Command::Approval(ApprovalCmd::Decline { id }) => {
            approval_decide(&client?, &id, "decline", json).await
        }
        Command::Approval(ApprovalCmd::Verify(args)) => approval_verify(client, args, json).await,
        Command::Budget(BudgetCmd::Refund {
            decision_id,
            reason,
        }) => budget_refund(&client?, &decision_id, &reason, json).await,
        Command::Lease(LeaseCmd::Show { id }) => {
            let resp = client?
                .admin_get(&format!("/admin/leases/{}", query_escape(&id)))
                .await?;
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
        Command::Lease(LeaseCmd::Tree { id, max_nodes }) => {
            let mut path = format!("/admin/leases/{}/tree", query_escape(&id));
            if let Some(n) = max_nodes {
                path.push_str(&format!("?max_nodes={n}"));
            }
            let resp = client?.admin_get(&path).await?;
            if json {
                print_json(&resp);
            } else {
                print!("{}", render::render_lease_tree(&resp));
            }
            Ok(Outcome::Ok)
        }
        Command::Audit(AuditCmd::Tail {
            lines,
            before,
            follow,
            interval_ms,
            filter,
        }) => audit_tail(&client?, lines, before, &filter, follow, interval_ms, json).await,
        Command::Audit(AuditCmd::Show { seq, id }) => {
            let path = match (seq, id) {
                (Some(seq), _) => format!("/admin/audit/entries/{seq}"),
                (None, Some(id)) => format!("/admin/audit/records/{}", query_escape(&id)),
                (None, None) => unreachable!("clap requires a seq or --id"),
            };
            let resp = client?.admin_get(&path).await?;
            if json {
                print_json(&resp);
            } else {
                print!("{}", render::render_entry_view(&resp));
            }
            Ok(Outcome::Ok)
        }
        Command::Audit(AuditCmd::Checkpoints { before, limit }) => {
            // The list route only reads; `/admin/audit/checkpoint` (singular) would sign one.
            let mut query = Vec::new();
            if let Some(b) = before {
                query.push(format!("before={b}"));
            }
            if let Some(l) = limit {
                query.push(format!("limit={l}"));
            }
            let mut path = "/admin/audit/checkpoints".to_string();
            if !query.is_empty() {
                path = format!("{path}?{}", query.join("&"));
            }
            let resp = client?.admin_get(&path).await?;
            if json {
                print_json(&resp);
            } else {
                print!("{}", render::render_checkpoints(&resp));
            }
            Ok(Outcome::Ok)
        }
        Command::Audit(AuditCmd::Verify {
            file: Some(file),
            jwks,
            allow_unsigned_tail,
            checkpoints,
        }) => {
            let options = attenuo_audit::VerifyOptions {
                allow_unsigned_tail,
            };
            audit_verify_file(
                client,
                &file,
                jwks.as_deref(),
                checkpoints.as_deref(),
                options,
                json,
            )
            .await
        }
        Command::Audit(AuditCmd::Export {
            from,
            to,
            format,
            out,
            kind,
            chain_id,
        }) => {
            let filter = attenuo_audit::RecordFilter { kind, chain_id };
            audit_export(&client?, from, to, &filter, format, out.as_deref()).await
        }
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
        Command::Policy(PolicyCmd::Test(args)) => {
            let opts = policy_cmd::TestOptions::from(&args);
            // `Some` with --via authzen: the server and the bearer.
            let remote = match args.via {
                cli::Via::Local => {
                    if args.token.token.is_some() || args.token.token_file.is_some() {
                        anyhow::bail!("--token and --token-file need --via authzen");
                    }
                    None
                }
                cli::Via::Authzen => {
                    if args.schema_file.is_some() {
                        anyhow::bail!(
                            "--schema-file has no effect with --via authzen: the server validates \
                             with its own schema"
                        );
                    }
                    let client = client?;
                    let token = secrets::resolve_token(
                        "--token",
                        args.token.token,
                        args.token.token_file.as_deref(),
                        &mut stdin,
                    )?;
                    let key = dpop_key::load_opt(args.token.dpop_key.as_deref())?;
                    Some((client, token, key))
                }
            };
            let run_once = || async {
                match &remote {
                    None => policy_cmd::test(&args.files, &opts, json),
                    Some((client, token, key)) => {
                        let remote = policy_cmd::Remote {
                            client,
                            token,
                            dpop_key: key.as_ref(),
                        };
                        policy_cmd::test_authzen(&args.files, &remote, &opts, json).await
                    }
                }
            };
            if !args.watch {
                return finish(run_once().await, "policy test failed to run");
            }
            loop {
                let paths = watch::watched_paths(&args.files, opts.schema_file.as_deref());
                let seen = watch::Snapshot::take(&paths);
                let run = run_once().await;
                if !json {
                    print!("{}", watch::CLEAR);
                }
                print!("{}", run.stdout);
                eprint!("{}", run.stderr);
                let t = OffsetDateTime::now_utc();
                eprintln!(
                    "[{:02}:{:02}:{:02} UTC] watching {} file(s); Ctrl-C to stop",
                    t.hour(),
                    t.minute(),
                    t.second(),
                    seen.len()
                );
                tokio::task::spawn_blocking(move || {
                    watch::wait_for_change(
                        &seen,
                        || watch::Snapshot::take(&paths),
                        std::thread::sleep,
                    )
                })
                .await?;
            }
        }
        Command::Policy(PolicyCmd::Lint {
            policy,
            config,
            schema_file,
            schema,
        }) => finish(
            policy_cmd::lint_with_schema(
                &policy,
                config.as_deref(),
                schema_file.as_deref(),
                schema,
                json,
            ),
            "policy lint failed to run",
        ),
        Command::Policy(PolicyCmd::Show) => {
            let resp = client?.admin_get("/admin/policies").await?;
            if json {
                print_json(&resp);
            } else {
                print!("{}", render::render_policies(&resp));
            }
            Ok(Outcome::Ok)
        }
        Command::Policy(PolicyCmd::Check) => {
            let resp = client?.admin_get("/admin/policies/check").await?;
            if json {
                print_json(&resp);
            } else {
                print!("{}", render::render_policy_check(&resp));
            }
            Ok(if resp["ok"] == true {
                Outcome::Ok
            } else {
                Outcome::No
            })
        }
        Command::Policy(PolicyCmd::Evaluate(a)) => {
            let client = client?;
            let body = evaluate_body(&a, &mut stdin)?;
            let resp = client.admin_post("/admin/policies/evaluate", &body).await?;
            if json {
                print_json(&resp);
            } else {
                print!("{}", render::render_evaluation(&resp));
            }
            Ok(if resp["decision"] == "allow" {
                Outcome::Ok
            } else {
                Outcome::No
            })
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
            let client = client?;
            let token_src_key = token.dpop_key.clone();
            let token = secrets::resolve_token(
                "--token",
                token.token,
                token.token_file.as_deref(),
                &mut stdin,
            )?;
            let key = dpop_key::load_opt(token_src_key.as_deref())?;
            let resp = client.authzen(&token, &req, key.as_ref()).await?;
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

/// The body of `POST /admin/policies/evaluate`: the AuthZEN request `authzen eval` sends, plus
/// either the `token` (the server takes the chain from it and fills the empty subject id) or
/// the chain from `--chain-file` (then `subject.id` must name its current agent).
fn evaluate_body(a: &cli::EvaluateArgs, stdin: &mut secrets::Stdin) -> Result<Value> {
    let input: Map<String, Value> = a.args.iter().cloned().collect();
    let mut req = json!({
        "subject": {"type": "agent", "id": ""},
        "action": {"name": a.tool, "properties": {"server": a.server}},
        "resource": {"type": "tool", "id": format!("{}/{}", a.server, a.tool)},
        "context": {"input": input},
    });
    match &a.chain_file {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            let chain: attenuo_core::DelegationChain = serde_json::from_str(&text)
                .with_context(|| format!("{} is not a delegation chain", path.display()))?;
            let agent = chain
                .current_agent()
                .map(|a| a.0.clone())
                .context("the chain has no hops")?;
            req["subject"] = json!({
                "type": "agent",
                "id": agent,
                "properties": {"chain": serde_json::to_value(&chain)?},
            });
        }
        None => {
            let token =
                secrets::resolve_token("--token", a.token.clone(), a.token_file.as_deref(), stdin)?;
            req["token"] = json!(token);
        }
    }
    Ok(req)
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
        if let Some(cnf) = &c.cnf {
            println!(
                "bound to DPoP key jkt {} (needs a proof by that key)",
                cnf.jkt
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
/// `approval grant` / `approval decline`: decide as the operator and print the approval.
/// Exit status of `budget refund` when the decision charged nothing (404).
const EXIT_NOTHING_CHARGED: u8 = 2;
/// Exit status of `budget refund` when the decision was already refunded (409).
const EXIT_ALREADY_REFUNDED: u8 = 3;

/// `budget refund`: `POST /admin/budgets/refund`. The two refusals a script may want to tell
/// apart get one line on stderr and exit statuses of their own; anything else is an error.
async fn budget_refund(
    client: &Client,
    decision_id: &str,
    reason: &str,
    json: bool,
) -> Result<Outcome> {
    let body = json!({ "decision_id": decision_id, "reason": reason });
    match client.admin_post("/admin/budgets/refund", &body).await {
        Ok(resp) => {
            if json {
                print_json(&resp);
            } else {
                print!("{}", render::render_refund(&resp));
            }
            Ok(Outcome::Ok)
        }
        Err(e) => match refund_refusal(&e, decision_id) {
            Some((code, line)) => {
                eprintln!("error: {line}");
                Ok(Outcome::Exit(code))
            }
            None => Err(e),
        },
    }
}

/// The exit status and message for a refund the server refused as nothing charged (404
/// `not_found`) or already refunded (409 `already_refunded`). A 404 without that code (a
/// server too old to have the route) stays an ordinary error.
fn refund_refusal(e: &anyhow::Error, decision_id: &str) -> Option<(u8, String)> {
    let api = e.downcast_ref::<client::ApiError>()?;
    match (api.status.as_u16(), api.code.as_deref()?) {
        (404, "not_found") => Some((
            EXIT_NOTHING_CHARGED,
            format!("decision {decision_id} charged no run limit or run usage; nothing to refund"),
        )),
        (409, "already_refunded") => Some((
            EXIT_ALREADY_REFUNDED,
            format!("the charge of decision {decision_id} was already refunded"),
        )),
        _ => None,
    }
}

async fn approval_decide(client: &Client, id: &str, decision: &str, json: bool) -> Result<Outcome> {
    let resp = client
        .admin_post(
            &format!("/admin/approvals/{}", query_escape(id)),
            &json!({ "decision": decision }),
        )
        .await?;
    if json {
        print_json(&resp);
    } else {
        print!("{}", render::render_approval(&resp));
    }
    Ok(Outcome::Ok)
}

/// `approval verify`: check an approval token offline against the issuer's JWKS.
async fn approval_verify(
    client: Result<Client>,
    args: cli::ApprovalVerifyArgs,
    json: bool,
) -> Result<Outcome> {
    let token = if args.token == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s.trim().to_string()
    } else {
        args.token.trim().to_string()
    };
    let (header, claims) = jwt::decode_approval_unverified(&token)?;
    let jwks: Value = match args.jwks.as_deref() {
        Some(u) if u.starts_with("http://") || u.starts_with("https://") => reqwest::get(u)
            .await
            .and_then(reqwest::Response::error_for_status)
            .with_context(|| format!("fetching the JWKS from {u}"))?
            .json()
            .await
            .context("the JWKS is not JSON")?,
        Some(p) => serde_json::from_str(
            &std::fs::read_to_string(p).with_context(|| format!("reading {p}"))?,
        )
        .with_context(|| format!("{p} is not JSON"))?,
        None => client?
            .get("/.well-known/jwks.json")
            .await
            .context("fetching the JWKS (or pass --jwks <url|file>)")?,
    };
    let binding = jwt::ApprovalBinding {
        chain_id: args.chain_id.as_deref(),
        lease: args.lease.as_deref(),
        call_hash: args.call_hash.as_deref(),
        jkt: args.jkt.as_deref().map(|k| (k != "none").then_some(k)),
    };
    let verdict = jwt::verify_approval_with_jwks(
        &token,
        &jwks,
        args.issuer.as_deref(),
        args.audience.as_deref(),
        &binding,
        OffsetDateTime::now_utc(),
    );
    let error = verdict.as_ref().err().map(|e| format!("{e:#}"));
    if json {
        print_json(&json!({
            "header": header,
            "claims": claims,
            "valid": verdict.is_ok(),
            "error": error,
        }));
    } else {
        let s = |k: &str| claims[k].as_str().unwrap_or("-").to_string();
        let exp = claims["exp"]
            .as_i64()
            .and_then(|t| OffsetDateTime::from_unix_timestamp(t).ok())
            .and_then(|t| {
                t.format(&time::format_description::well_known::Rfc3339)
                    .ok()
            })
            .unwrap_or_else(|| "-".into());
        println!("approval  {}", s("jti"));
        println!("by        {} ({})", s("sub"), s("by"));
        println!("chain_id  {}", s("chain_id"));
        println!("lease     {}", s("lease"));
        println!("call hash {}", s("ch"));
        println!("expires   {exp}");
        println!(
            "cnf.jkt   {}",
            claims["cnf"]["jkt"].as_str().unwrap_or("- (bearer hop)")
        );
        println!("iss {}   aud {}", s("iss"), s("aud"));
        match &error {
            None => println!("VALID (signature, typ, iss, aud, exp and the given binding)"),
            Some(e) => println!("INVALID: {e}"),
        }
    }
    Ok(if verdict.is_ok() {
        Outcome::Ok
    } else {
        Outcome::No
    })
}

fn print_call(resp: &Value, json: bool) -> Outcome {
    if json {
        print_json(resp);
    }
    if let Some(err) = resp.get("error") {
        let denied = err["code"].as_i64() == Some(CODE_DENIED);
        if !json {
            if err["code"].as_i64() == Some(CODE_APPROVAL_REQUIRED) {
                let d = &err["data"];
                let s = |k: &str| d[k].as_str().unwrap_or("-").to_string();
                println!("APPROVAL REQUIRED");
                println!("approval  {}", s("approval_id"));
                println!("expires   {}", s("expires_at"));
                println!("call hash {}", s("call_hash"));
                println!("decision  {}", s("decision_id"));
            } else if denied {
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

/// Request path of `audit export`.
fn export_path(from: u64, to: Option<u64>, filter: &attenuo_audit::RecordFilter) -> String {
    let mut path = format!("/admin/audit/export?from={from}");
    if let Some(to) = to {
        path.push_str(&format!("&to={to}"));
    }
    if let Some(kind) = filter.kind {
        path.push_str(&format!("&kind={kind}"));
    }
    if let Some(chain_id) = &filter.chain_id {
        path.push_str(&format!("&chain_id={}", query_escape(chain_id)));
    }
    path
}

/// `audit export`: stream the server's JSON Lines to `out` (or stdout), or collect them into
/// one JSON object for `--format json`.
async fn audit_export(
    client: &Client,
    from: u64,
    to: Option<u64>,
    filter: &attenuo_audit::RecordFilter,
    format: ExportFormat,
    out: Option<&std::path::Path>,
) -> Result<Outcome> {
    use std::io::Write;

    let path = export_path(from, to, filter);
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
            let export = attenuo_audit::parse_export(&text)?;
            serde_json::to_writer_pretty(&mut sink, &attenuo_audit::to_json_form(&export))?;
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
    shipped: Option<&std::path::Path>,
    options: attenuo_audit::VerifyOptions,
    json: bool,
) -> Result<Outcome> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let export = attenuo_audit::parse_export(&text)
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
    let keys = attenuo_audit::CheckpointKeys::from_jwks(&jwks)?;
    let report = attenuo_audit::verify_export_with(&export, &keys, options)?;
    let mut v = serde_json::to_value(&report)?;
    let mut ok = report.report.ok;
    if let Some(p) = shipped {
        let text =
            std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
        let lines = attenuo_audit::parse_shipped(&text)
            .with_context(|| format!("parsing {}", p.display()))?;
        let cross = attenuo_audit::cross_check(&export, &lines, &keys);
        ok &= cross.ok;
        v["shipped"] = serde_json::to_value(&cross)?;
        v["ok"] = json!(ok);
    }
    if json {
        print_json(&v);
    } else {
        for line in export_lines(&v) {
            println!("{line}");
        }
        if v.get("shipped").is_some() {
            for line in shipped_lines(&v["shipped"]) {
                println!("{line}");
            }
        }
    }
    Ok(if ok { Outcome::Ok } else { Outcome::No })
}

/// Text for the cross-check against shipped checkpoints (`--checkpoints`).
fn shipped_lines(v: &Value) -> Vec<String> {
    let mut out = vec![format!(
        "shipped checkpoints: {} in the file, {} inside the export's range, {} match",
        v["shipped"], v["in_range"], v["matched"]
    )];
    for m in v["mismatches"].as_array().into_iter().flatten() {
        out.push(format!(
            "shipped checkpoint seq {} (line {}) MISMATCH: {}",
            m["seq"],
            m["line"],
            m["reason"].as_str().unwrap_or_default()
        ));
    }
    if let Some(n) = v["beyond_range"].as_u64().filter(|n| *n > 0) {
        out.push(format!(
            "note: {n} shipped checkpoints lie past the export's range and were not checked; if \
             the export runs to the head of the log, the log is shorter than what was shipped \
             (last shipped seq {})",
            v["last_shipped_seq"]
        ));
    }
    if v["ok"] == true {
        out.push("shipped checkpoints: OK".to_string());
    } else {
        out.push(
            "shipped checkpoints: FAILED (signed again after shipping, or deleted)".to_string(),
        );
    }
    out
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
    if let Some(n) = v["outside_range"].as_u64().filter(|n| *n > 0) {
        out.push(format!(
            "export holds {n} entries OUTSIDE the range its header declares"
        ));
    }
    if v["unsigned_tail_rejected"] == true {
        out.push(format!(
            "export REJECTED: {} entries after the last checkpoint are not signed (pass \
             --allow-unsigned-tail to accept an export newer than its last checkpoint)",
            v["unsigned_tail"]
        ));
    }
    if v["from_genesis"] == false && v["first_seq"].is_u64() {
        out.push(format!(
            "note: the file does not start at the first entry of the log; entries before seq {} are not covered",
            v["first_seq"]
        ));
    }
    out
}

/// Largest page `GET /admin/audit` serves.
const MAX_AUDIT_PAGE: u64 = 1000;

/// `audit tail`: the newest `lines` matching entries (below `before` when given), read newest
/// first and printed oldest first, then with `follow` every new matching entry as it comes.
///
/// A filtered page may come back short, even empty, with `prev`/`next` set (the server bounds
/// how far one page scans), so both loops keep following the link rather than stopping at
/// the first short page.
async fn audit_tail(
    client: &Client,
    lines: u64,
    before: Option<u64>,
    filter: &cli::AuditFilter,
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
    let q = filter.query();
    let want = usize::try_from(lines).unwrap_or(usize::MAX);
    let mut newest_first: Vec<Value> = Vec::new();
    let mut cursor = before;
    // `head` comes with any page; unlike `/admin/audit/checkpoint` it signs nothing, so polling
    // with `--follow` does not add a checkpoint per new entry.
    let mut head = None;
    loop {
        let limit = (lines - newest_first.len() as u64).clamp(1, MAX_AUDIT_PAGE);
        let mut path = format!("/admin/audit?order=desc&limit={limit}{q}");
        if let Some(b) = cursor {
            path.push_str(&format!("&before={b}"));
        }
        let page = client.admin_get(&path).await?;
        head.get_or_insert(page["head"].as_u64().unwrap_or(0));
        for e in page["entries"].as_array().into_iter().flatten() {
            if newest_first.len() < want {
                newest_first.push(e.clone());
            }
        }
        match page["prev"].as_u64() {
            Some(prev) if newest_first.len() < want => cursor = Some(prev),
            _ => break,
        }
    }
    for e in newest_first.iter().rev() {
        show(e);
    }
    if !follow {
        return Ok(Outcome::Ok);
    }
    // The first descending page read up to `head` (clap keeps `--before` away from
    // `--follow`), so everything after it is new.
    let mut from = head.unwrap_or(0) + 1;
    loop {
        let page = client
            .admin_get(&format!(
                "/admin/audit?from={from}&limit={MAX_AUDIT_PAGE}{q}"
            ))
            .await?;
        for e in page["entries"].as_array().into_iter().flatten() {
            show(e);
            if let Some(seq) = e["seq"].as_u64() {
                from = seq + 1;
            }
        }
        // `next` is past the entries shown, or past the seqs a short filtered page scanned.
        match page["next"].as_u64() {
            Some(next) => from = from.max(next),
            None => tokio::time::sleep(Duration::from_millis(interval_ms.max(50))).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refund_refusals_get_their_own_line_and_exit_status() {
        use reqwest::StatusCode;
        let err = |status, body: &str| client::api_error(status, body);
        let nothing = err(
            StatusCode::NOT_FOUND,
            r#"{"error":"not_found","detail":"no budget charge"}"#,
        );
        let (code, line) = refund_refusal(&nothing, "D1").unwrap();
        assert_eq!(code, 2);
        assert_eq!(
            line,
            "decision D1 charged no run limit or run usage; nothing to refund"
        );
        let twice = err(
            StatusCode::CONFLICT,
            r#"{"error":"already_refunded","detail":"once"}"#,
        );
        assert_eq!(
            refund_refusal(&twice, "D1"),
            Some((
                3,
                "the charge of decision D1 was already refunded".to_string()
            ))
        );
        // A 404 with no code (no such route on an older server), another 409 code, or a
        // transport error stays an ordinary error (exit 1).
        assert_eq!(refund_refusal(&err(StatusCode::NOT_FOUND, ""), "D1"), None);
        let other = err(StatusCode::CONFLICT, r#"{"error":"other"}"#);
        assert_eq!(refund_refusal(&other, "D1"), None);
        let forbidden = err(StatusCode::UNAUTHORIZED, r#"{"error":"not_found"}"#);
        assert_eq!(refund_refusal(&forbidden, "D1"), None);
        assert_eq!(refund_refusal(&anyhow::anyhow!("no route"), "D1"), None);
    }

    #[test]
    fn export_lines_describe_coverage_and_problems() {
        let v = json!({"entries": 5, "ok": false, "first_bad_seq": null, "checkpoints": 1,
                       "last_signed_seq": 8, "unsigned_tail": 0, "bad_checkpoints": [],
                       "first_seq": 4, "last_seq": 8, "from_genesis": false,
                       "truncated": true, "outside_range": 0,
                       "unsigned_tail_rejected": false});
        let lines = export_lines(&v);
        assert_eq!(lines[0], "export covers seq 4..8");
        assert!(lines.iter().any(|l| l.contains("TRUNCATED")), "{lines:?}");
        assert!(!lines
            .iter()
            .any(|l| l.contains("OUTSIDE") || l.contains("REJECTED")));
        // Fuzzing F5: more entries than declared, and an unsigned tail refused.
        let v = json!({"entries": 6, "ok": false, "first_bad_seq": null, "checkpoints": 1,
                       "last_signed_seq": 5, "unsigned_tail": 1, "bad_checkpoints": [],
                       "first_seq": 1, "last_seq": 6, "from_genesis": true,
                       "truncated": false, "outside_range": 1,
                       "unsigned_tail_rejected": true});
        let f5 = export_lines(&v);
        assert!(f5.iter().any(|l| l.contains("1 entries OUTSIDE")), "{f5:?}");
        assert!(
            f5.iter()
                .any(|l| l.contains("REJECTED") && l.contains("--allow-unsigned-tail")),
            "{f5:?}"
        );
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
    fn export_path_carries_range_and_escaped_filters() {
        use attenuo_audit::RecordFilter;
        assert_eq!(
            export_path(1, None, &RecordFilter::default()),
            "/admin/audit/export?from=1"
        );
        let f = RecordFilter {
            kind: Some(attenuo_core::RecordKind::LeaseRenew),
            chain_id: Some("l 1&x=é".into()),
        };
        assert_eq!(
            export_path(5, Some(9), &f),
            "/admin/audit/export?from=5&to=9&kind=lease_renew&chain_id=l%201%26x%3D%C3%A9"
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
            "code": -32003, "message": "attenuo: denied: policy_deny",
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
