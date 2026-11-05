//! `attenuo policy test` and `attenuo policy lint`: offline checks of a policy set. They
//! never talk to a server, except `policy test --via authzen` and `--via admin-evaluate`, which
//! send the cases to a running server's AuthZEN endpoint or its admin dry run.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use attenuo_policy::testing::{self, CaseReport, TestFile, TestReport};
use attenuo_policy::{LintSeverity, PolicyEngineBuilder};
use serde_json::{json, Value};

/// How a run ended, which maps to the process exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Everything passed (exit 0).
    Ok,
    /// The checks ran and some failed (exit 2).
    Failed,
    /// Something could not run at all: unreadable file, malformed YAML, bad policy (exit 1).
    Error,
}

/// What to print and how it ended.
#[derive(Debug)]
pub struct Run {
    pub stdout: String,
    pub stderr: String,
    pub status: Status,
}

impl Run {
    fn new() -> Self {
        Self {
            stdout: String::new(),
            stderr: String::new(),
            status: Status::Ok,
        }
    }

    fn error(message: String) -> Self {
        Self {
            stderr: format!("error: {message}\n"),
            status: Status::Error,
            ..Self::new()
        }
    }
}

fn pretty(v: &Value) -> String {
    format!("{}\n", serde_json::to_string_pretty(v).unwrap_or_default())
}

/// How `policy test` runs and when it fails, beyond the files.
#[derive(Debug, Clone, Default)]
pub struct TestOptions {
    /// Fail (exit 2) when some policy was not exercised by any case.
    pub fail_on_unexercised: bool,
    /// Base schema replacing the built-in one (and any config's `[policy] schema_path`).
    pub schema_file: Option<PathBuf>,
}

impl From<&crate::cli::TestArgs> for TestOptions {
    fn from(a: &crate::cli::TestArgs) -> Self {
        Self {
            fail_on_unexercised: a.fail_on_unexercised,
            schema_file: a.schema_file.clone(),
        }
    }
}

/// `attenuo policy test <file>...`
pub fn test(files: &[PathBuf], opts: &TestOptions, json_out: bool) -> Run {
    let mut reports: Vec<(&Path, TestReport)> = Vec::new();
    let mut errors: Vec<(&Path, String)> = Vec::new();
    for path in files {
        let loaded = TestFile::load(path).map(|f| match &opts.schema_file {
            Some(s) => f.with_schema_file(s),
            None => f,
        });
        match loaded.and_then(|f| f.run()) {
            Ok(report) => reports.push((path, report)),
            Err(e) => errors.push((path, e.to_string())),
        }
    }
    report(&reports, &errors, &[], opts, json_out)
}

/// The server and credentials of `policy test --via authzen`.
pub struct Remote<'a> {
    pub client: &'a crate::client::Client,
    pub token: &'a str,
    pub dpop_key: Option<&'a attenuo_token::DpopKey>,
}

/// `attenuo policy test --via authzen <file>...`: every case is decided by the server's
/// `POST /access/v1/evaluation`, with the token's chain. Cases the endpoint cannot express
/// (see [`testing::TestCase::authzen_skip_reason`]) are skipped and listed as such. Every
/// evaluation is a real decision on the server, so each one writes an audit record there.
pub async fn test_authzen(
    files: &[PathBuf],
    remote: &Remote<'_>,
    opts: &TestOptions,
    json_out: bool,
) -> Run {
    let token_chain = match crate::jwt::decode_unverified(remote.token) {
        Ok(d) => d.claims.chain,
        Err(e) => return Run::error(format!("--token: {e:#}")),
    };
    let mut reports: Vec<(&Path, TestReport)> = Vec::new();
    let mut errors: Vec<(&Path, String)> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    for path in files {
        let file = match TestFile::load(path) {
            Ok(f) => f,
            Err(e) => {
                errors.push((path, e.to_string()));
                continue;
            }
        };
        if file.sets_now() {
            notes.push(format!(
                "{}: `now` is not sent; the server evaluates at its own clock",
                path.display()
            ));
        }
        let mut cases = Vec::with_capacity(file.cases.len());
        let mut failure = None;
        for case in &file.cases {
            if let Some(why) = case.authzen_skip_reason(&token_chain) {
                cases.push(case.skip(why));
                continue;
            }
            let input = match case.input(file.now_unix()) {
                Ok(i) => i,
                Err(e) => {
                    cases.push(case.errored(e));
                    continue;
                }
            };
            let body = authzen_body(&input.call);
            match remote
                .client
                .authzen(remote.token, &body, remote.dpop_key)
                .await
                .and_then(|v| {
                    serde_json::from_value::<attenuo_policy::authzen::EvaluationResponse>(v)
                        .map_err(|e| anyhow::anyhow!("the server's answer is not AuthZEN: {e}"))
                }) {
                Ok(resp) => cases.push(case.check(testing::Actual::from(
                    attenuo_policy::authzen::to_outcome(&resp),
                ))),
                Err(e) => {
                    // A refused token or an unreachable server fails every case the same way.
                    failure = Some(format!("case `{}`: {e:#}", case.name));
                    break;
                }
            }
        }
        match failure {
            Some(e) => errors.push((path, e)),
            None => match file.report_for(cases) {
                Ok(r) => reports.push((path, r)),
                Err(e) => errors.push((path, e.to_string())),
            },
        }
    }
    report(&reports, &errors, &notes, opts, json_out)
}

/// The AuthZEN request for a case's call. The subject id is left empty: the server fills it
/// from the bearer's chain, which is the chain that makes the call.
fn authzen_body(call: &attenuo_core::ToolCall) -> Value {
    let mut context =
        json!({ "input": Value::Object(call.arguments.clone().into_iter().collect()) });
    if let Some(sid) = &call.session_id {
        context["session_id"] = json!(sid);
    }
    json!({
        "subject": {"type": "agent", "id": ""},
        "action": {"name": call.tool, "properties": {"server": call.server}},
        "resource": {"type": "tool", "id": format!("{}/{}", call.server, call.tool),
                     "properties": {"server": call.server, "tool": call.tool}},
        "context": context,
    })
}

/// `attenuo policy test --via admin-evaluate <file>...`: every case, with the chain it
/// describes, is decided by the server's admin dry run (`POST /admin/policies/evaluate`, the
/// client's admin token). The dry run takes an admin-supplied chain, the case's `session`,
/// `approval`, `usage` and `budget`, checks no lease, charges no counter and writes no audit
/// record, so every case replays as written, none is skipped. The server validates the chain at
/// its own clock, so each chain is stamped at the current time (see
/// [`testing::TestCase::input_at`]). A case the server refuses with 400 (a chain deeper than its
/// `max_depth`, an approval `by` it does not know, a negative `budget` figure) is reported as
/// that case's error; any other refusal (a bad admin token, a server without the route) or a
/// transport error stops the file.
pub async fn test_admin_evaluate(
    files: &[PathBuf],
    client: &crate::client::Client,
    opts: &TestOptions,
    json_out: bool,
) -> Run {
    let mut reports: Vec<(&Path, TestReport)> = Vec::new();
    let mut errors: Vec<(&Path, String)> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    for path in files {
        let file = match TestFile::load(path) {
            Ok(f) => f,
            Err(e) => {
                errors.push((path, e.to_string()));
                continue;
            }
        };
        if file.sets_now() {
            notes.push(format!(
                "{}: `now` is not sent; chains are stamped at the current time and the server \
                 evaluates at its own clock",
                path.display()
            ));
        }
        let mut cases = Vec::with_capacity(file.cases.len());
        let mut failure = None;
        for case in &file.cases {
            let at = time::OffsetDateTime::now_utc().unix_timestamp();
            let input = match case.input_at(file.now_unix(), at) {
                Ok(i) => i,
                Err(e) => {
                    cases.push(case.errored(e));
                    continue;
                }
            };
            let body = admin_evaluate_body(&input, case.budget.as_ref());
            let answer = client
                .admin_post("/admin/policies/evaluate", &body)
                .await
                .and_then(|v| admin_evaluate_actual(&v));
            match answer {
                Ok(actual) => cases.push(case.check(actual)),
                Err(e) => match e.downcast_ref::<crate::client::ApiError>() {
                    Some(api) if api.status == reqwest::StatusCode::BAD_REQUEST => {
                        cases.push(case.errored(format!("the server refused the case: {api}")));
                    }
                    _ => {
                        failure = Some(format!("case `{}`: {e:#}", case.name));
                        break;
                    }
                },
            }
        }
        match failure {
            Some(e) => errors.push((path, e)),
            None => match file.report_for(cases) {
                Ok(r) => reports.push((path, r)),
                Err(e) => errors.push((path, e.to_string())),
            },
        }
    }
    report(&reports, &errors, &notes, opts, json_out)
}

/// The admin dry-run request for a case: the AuthZEN request with the case's chain, plus its
/// labels as the run's state. `session` and `usage` are always sent, so the dry run never reads
/// them from the server's store; `approval` only when the case carries one. `budget` is sent
/// as the case states it (only the members it sets), and only when it sets one: the server
/// then decides the run limits on it instead of its counters (with no limit in the chain,
/// Cedar sees the figures as given, as offline).
fn admin_evaluate_body(input: &testing::CaseInput, budget: Option<&testing::BudgetSpec>) -> Value {
    let mut body = serde_json::to_value(attenuo_policy::authzen::to_request(
        &input.chain,
        &input.call,
    ))
    .unwrap_or_default();
    let l = &input.labels;
    body["session"] = json!({
        "tainted": l.session.tainted,
        "tainted_by": l.session.tainted_by,
        "untrusted_args": l.args.untrusted,
        "args_contain_untrusted": l.args.contain_untrusted,
    });
    body["usage"] = json!({
        "calls": l.usage.calls,
        "amount": l.usage.amount,
        "destination_seen": l.usage.destination_seen,
    });
    if l.approval.present {
        body["approval"] = json!({ "by": l.approval.by });
    }
    if let Some(b) = budget {
        let mut stated = serde_json::Map::new();
        let figures = [
            ("limited", b.limited.map(Value::from)),
            ("calls_remaining", b.calls_remaining.map(Value::from)),
            ("amount_remaining", b.amount_remaining.map(Value::from)),
            ("destination_new", b.destination_new.map(Value::from)),
        ];
        for (key, v) in figures {
            if let Some(v) = v {
                stated.insert(key.to_string(), v);
            }
        }
        body["budget"] = Value::Object(stated);
    }
    body
}

/// Read the dry run's answer (`{decision: "allow" | "deny", reason, policy_ids, diagnostics,
/// ...}`) as what was decided.
fn admin_evaluate_actual(v: &Value) -> anyhow::Result<testing::Actual> {
    let decision: attenuo_core::Decision = serde_json::from_value(v["decision"].clone())
        .map_err(|e| anyhow::anyhow!("the server's answer has no decision: {e}"))?;
    let strings = |key: &str| -> Vec<String> {
        v[key]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok(testing::Actual {
        decision,
        reason: v["reason"].as_str().unwrap_or_default().to_string(),
        policy_ids: strings("policy_ids"),
        diagnostics: strings("diagnostics"),
    })
}

/// Print the reports of a `policy test` run (however the cases were evaluated) and decide its
/// status.
fn report(
    reports: &[(&Path, TestReport)],
    errors: &[(&Path, String)],
    notes: &[String],
    opts: &TestOptions,
    json_out: bool,
) -> Run {
    let mut run = Run::new();
    let passed: usize = reports.iter().map(|(_, r)| r.passed()).sum();
    let failed: usize = reports.iter().map(|(_, r)| r.failed()).sum();
    let skipped: usize = reports.iter().map(|(_, r)| r.skipped()).sum();
    let coverage = testing::coverage(reports.iter().map(|(_, r)| r));

    if json_out {
        let mut entries: Vec<Value> = reports
            .iter()
            .map(|(p, r)| {
                json!({"file": p, "cases": r.cases, "passed": r.passed(), "failed": r.failed(),
                       "skipped": r.skipped()})
            })
            .collect();
        entries.extend(errors.iter().map(|(p, e)| json!({"file": p, "error": e})));
        run.stdout = pretty(&json!({
            "files": entries, "passed": passed, "failed": failed, "skipped": skipped,
            "errors": errors.len(),
            "notes": notes,
            "coverage": {
                "policies": coverage.policies,
                "exercised": coverage.exercised(),
                "unexercised": coverage.unexercised,
            },
        }));
    } else {
        for n in notes {
            let _ = writeln!(run.stdout, "note: {n}");
        }
        for (path, report) in reports {
            let _ = writeln!(run.stdout, "{}", path.display());
            for case in &report.cases {
                render_case(&mut run.stdout, case);
            }
            run.stdout.push('\n');
        }
        for (path, e) in errors {
            let _ = writeln!(run.stderr, "error: {}: {e}", path.display());
        }
        if !reports.is_empty() {
            let _ = write!(run.stdout, "{passed} passed, {failed} failed");
            if skipped > 0 {
                let _ = write!(run.stdout, ", {skipped} skipped");
            }
            let _ = write!(
                run.stdout,
                " ({} cases in {} file{})",
                passed + failed + skipped,
                reports.len(),
                if reports.len() == 1 { "" } else { "s" }
            );
            if !errors.is_empty() {
                let _ = write!(run.stdout, "; {} file(s) could not be run", errors.len());
            }
            run.stdout.push('\n');
            render_coverage(&mut run.stdout, &coverage);
        }
    }
    let unexercised_fails = opts.fail_on_unexercised && !coverage.unexercised.is_empty();
    run.status = if !errors.is_empty() {
        Status::Error
    } else if failed > 0 || unexercised_fails {
        Status::Failed
    } else {
        Status::Ok
    };
    run
}

fn render_coverage(out: &mut String, coverage: &testing::Coverage) {
    if coverage.policies == 0 {
        return;
    }
    let plural = |n: usize| if n == 1 { "policy" } else { "policies" };
    if coverage.unexercised.is_empty() {
        let _ = writeln!(
            out,
            "all {} {} exercised",
            coverage.policies,
            plural(coverage.policies)
        );
        return;
    }
    let _ = writeln!(
        out,
        "{} of {} {} not exercised:",
        coverage.unexercised.len(),
        coverage.policies,
        plural(coverage.policies)
    );
    for p in &coverage.unexercised {
        let loc = match (&p.file, p.line) {
            (Some(f), Some(l)) => format!("{}:{l}", f.display()),
            (Some(f), None) => f.display().to_string(),
            (None, _) => "-".to_string(),
        };
        let _ = writeln!(out, "  {loc}  {}", p.id);
    }
}

fn render_case(out: &mut String, case: &CaseReport) {
    if let Some(why) = &case.skipped {
        let _ = writeln!(out, "  - {}  (skipped: {why})", case.name);
        return;
    }
    let mark = if case.passed { "\u{2713}" } else { "\u{2717}" };
    let detail = match &case.actual {
        Some(a) => {
            let mut d = format!("{}: {}", a.decision.as_str(), a.reason);
            if !a.policy_ids.is_empty() {
                let _ = write!(d, " [{}]", a.policy_ids.join(", "));
            }
            d
        }
        None => "not evaluated".to_string(),
    };
    let _ = writeln!(out, "  {mark} {}  ({detail})", case.name);
    for f in &case.failures {
        let _ = writeln!(out, "      {f}");
    }
    if let Some(e) = &case.error {
        let _ = writeln!(out, "      {e}");
    }
    if !case.passed {
        if let Some(a) = &case.actual {
            for d in &a.diagnostics {
                let _ = writeln!(out, "      diagnostic: {d}");
            }
        }
    }
}

/// A catalog declaring every `<server>/<tool>` action the policy names, with default
/// attributes, plus the action ids that are not server-scoped (and so were left out).
fn catalog_from_policy(text: &str) -> (attenuo_policy::ToolCatalog, Vec<String>) {
    let mut catalog = attenuo_policy::ToolCatalog::new();
    let mut skipped = Vec::new();
    for id in attenuo_policy::policy_action_names(text) {
        match id.split_once('/') {
            Some((server, tool)) if !server.is_empty() && !tool.is_empty() => {
                catalog.insert(server, tool, attenuo_policy::ToolAttrs::new());
            }
            _ => skipped.push(id),
        }
    }
    (catalog, skipped)
}

/// `attenuo policy lint <policy.cedar> [--config server.toml] [--schema]`
#[cfg(test)]
pub fn lint(policy: &Path, config: Option<&Path>, show_schema: bool, json_out: bool) -> Run {
    lint_with_schema(policy, config, None, show_schema, json_out)
}

/// `attenuo policy lint <policy.cedar> [--config server.toml] [--schema-file F] [--schema]`.
/// The base schema is `schema_file`, else the config's `[policy] schema_path`, else the
/// built-in one.
pub fn lint_with_schema(
    policy: &Path,
    config: Option<&Path>,
    schema_file: Option<&Path>,
    show_schema: bool,
    json_out: bool,
) -> Run {
    let mut run = Run::new();
    let text = match std::fs::read_to_string(policy) {
        Ok(t) => t,
        Err(e) => return Run::error(format!("reading {}: {e}", policy.display())),
    };
    let mut notes: Vec<String> = Vec::new();
    let catalog = match config.map(testing::load_catalog).transpose() {
        Ok(Some(c)) => c,
        Ok(None) => {
            // No config: declare the tools the policy itself names so server-scoped actions
            // validate. Tool attributes and argument types are unknown, so anything that
            // depends on them cannot be checked.
            let (catalog, skipped) = catalog_from_policy(&text);
            notes.push(
                "no --config: tools were declared from the policy's own action names; \
                 `context.input` and user attributes are not declared, so \"impossible policy\" \
                 warnings are dropped for policies that read them; `resource.readonly`, \
                 `resource.sensitive` and input types were not checked against a real catalog (pass --config <server.toml> \
                 for the full check)"
                    .to_string(),
            );
            if !skipped.is_empty() {
                notes.push(format!(
                    "no --config: not declared (not `<server>/<tool>`): {}",
                    skipped.join(", ")
                ));
            }
            catalog
        }
        Err(e) => return Run::error(e.to_string()),
    };
    let catalog_empty = catalog.is_empty() && config.is_some();
    let user_attrs = match config.map(testing::load_user_attrs).transpose() {
        Ok(a) => a.unwrap_or_default(),
        Err(e) => return Run::error(e.to_string()),
    };
    let legacy_bare_actions = match config
        .map(testing::load_legacy_bare_actions_from_config)
        .transpose()
    {
        Ok(v) => v.flatten().unwrap_or(false),
        Err(e) => return Run::error(e.to_string()),
    };
    let mut builder = PolicyEngineBuilder::new()
        .with_catalog(catalog)
        .with_legacy_bare_actions(legacy_bare_actions);
    for (name, ty) in user_attrs {
        builder = builder.with_user_attr(name, ty);
    }
    let base_path = match schema_file {
        Some(p) => Some(p.to_path_buf()),
        None => match config
            .map(testing::load_schema_path_from_config)
            .transpose()
        {
            Ok(p) => p.flatten(),
            Err(e) => return Run::error(e.to_string()),
        },
    };
    if let Some(p) = &base_path {
        match std::fs::read_to_string(p) {
            Ok(base) => builder = builder.with_schema_str(&base),
            Err(e) => return Run::error(format!("reading {}: {e}", p.display())),
        }
        if let Err(e) = builder.check_schema() {
            return Run::error(format!("{}: {e}", p.display()));
        }
    }
    let schema = builder.schema_text();
    let report = attenuo_policy::lint_with_options(
        &text,
        &schema,
        attenuo_policy::LintOptions {
            legacy_bare_actions,
            undeclared_catalog: config.is_none(),
        },
    );

    if json_out {
        let mut v = serde_json::to_value(&report).unwrap_or_default();
        v["file"] = json!(policy);
        v["notes"] = json!(notes);
        if show_schema {
            v["schema"] = json!(schema);
        }
        run.stdout = pretty(&v);
    } else {
        if show_schema {
            run.stdout.push_str(&schema);
            if !schema.ends_with('\n') {
                run.stdout.push('\n');
            }
            run.stdout.push('\n');
        }
        for n in &notes {
            let _ = writeln!(run.stdout, "note: {n}");
        }
        for i in &report.issues {
            let sev = match i.severity {
                LintSeverity::Error => "error",
                LintSeverity::Warning => "warning",
            };
            let loc = match (i.line, i.column) {
                (Some(l), Some(c)) => format!("{}:{l}:{c}", policy.display()),
                _ => policy.display().to_string(),
            };
            let id = i
                .policy_id
                .as_deref()
                .map(|p| format!(" ({p})"))
                .unwrap_or_default();
            let _ = writeln!(run.stdout, "{loc}: {sev}[{}]{id}: {}", i.stage, i.message);
        }
        if report.has_errors() && catalog_empty {
            let _ = writeln!(
                run.stdout,
                "hint: the config declares no tools; add them under [policy.catalog] (or [policy] catalog_path)"
            );
        }
        let _ = writeln!(
            run.stdout,
            "{}: {} polic{}, {} error(s), {} warning(s)",
            policy.display(),
            report.policy_ids.len(),
            if report.policy_ids.len() == 1 {
                "y"
            } else {
                "ies"
            },
            report.error_count(),
            report.warning_count()
        );
    }
    if report.has_errors() {
        run.status = Status::Failed;
    }
    run
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str =
        "@id(\"read\")\npermit(principal, action == Action::\"github/read_file\", resource);\n";
    const CONFIG: &str = "[policy.catalog.github.read_file]\nreadonly = true\n";

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    fn setup(expect: &str) -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "p.cedar", POLICY);
        write(d.path(), "c.toml", CONFIG);
        let t = write(
            d.path(),
            "t.yaml",
            &format!(
                "policies: p.cedar\ncatalog: c.toml\ncases:\n  - name: read\n    chain: [coder]\n    call: {{ server: github, tool: read_file }}\n    expect: {expect}\n"
            ),
        );
        (d, t)
    }

    #[test]
    fn passing_file_exits_ok_with_checkmarks() {
        let (_d, t) = setup("allow");
        let r = test(&[t], &TestOptions::default(), false);
        assert_eq!(r.status, Status::Ok);
        assert!(r.stdout.contains("\u{2713} read"), "{}", r.stdout);
        assert!(r.stdout.contains("1 passed, 0 failed (1 cases in 1 file)"));
    }

    #[test]
    fn failing_case_exits_failed_and_explains() {
        let (_d, t) = setup("deny");
        let r = test(&[t], &TestOptions::default(), false);
        assert_eq!(r.status, Status::Failed);
        assert!(r.stdout.contains("\u{2717} read"));
        assert!(
            r.stdout.contains("expected deny, got allow"),
            "{}",
            r.stdout
        );
    }

    #[test]
    fn unreadable_or_malformed_file_exits_error_but_others_still_run() {
        let (d, t) = setup("allow");
        let bad = write(d.path(), "bad.yaml", "cases: [");
        let r = test(
            &[bad, t, d.path().join("missing.yaml")],
            &TestOptions::default(),
            false,
        );
        assert_eq!(r.status, Status::Error);
        assert!(r.stdout.contains("1 passed"));
        assert_eq!(r.stderr.matches("error:").count(), 2, "{}", r.stderr);
    }

    #[test]
    fn json_output_is_machine_readable() {
        let (_d, t) = setup("deny");
        let r = test(&[t], &TestOptions::default(), true);
        let v: Value = serde_json::from_str(&r.stdout).unwrap();
        assert_eq!(v["failed"], 1);
        assert_eq!(v["files"][0]["cases"][0]["actual"]["decision"], "allow");
        assert_eq!(v["coverage"]["policies"], 1);
        assert_eq!(v["coverage"]["exercised"], 1);
        assert_eq!(v["coverage"]["unexercised"], json!([]));
    }

    #[test]
    fn unexercised_policies_are_listed_and_fail_only_on_request() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "p.cedar",
            &format!("{POLICY}\n@id(\"never\")\nforbid(principal, action, resource) when {{ context.chain.depth > 5 }};\n"),
        );
        write(d.path(), "c.toml", CONFIG);
        let t = write(
            d.path(),
            "t.yaml",
            "policies: p.cedar\ncatalog: c.toml\ncases:\n  - name: read\n    chain: [coder]\n    call: { server: github, tool: read_file }\n    expect: allow\n",
        );
        let r = test(std::slice::from_ref(&t), &TestOptions::default(), false);
        assert_eq!(r.status, Status::Ok, "{}", r.stdout);
        assert!(
            r.stdout.contains("1 of 2 policies not exercised:"),
            "{}",
            r.stdout
        );
        let line = format!("  {}:4  never", d.path().join("p.cedar").display());
        assert!(r.stdout.contains(&line), "{}", r.stdout);

        let strict = TestOptions {
            fail_on_unexercised: true,
            ..TestOptions::default()
        };
        let r = test(std::slice::from_ref(&t), &strict, false);
        assert_eq!(r.status, Status::Failed, "{}", r.stdout);

        let j = test(std::slice::from_ref(&t), &strict, true);
        let v: Value = serde_json::from_str(&j.stdout).unwrap();
        assert_eq!(v["coverage"]["policies"], 2);
        assert_eq!(v["coverage"]["unexercised"][0]["id"], "never");
        assert_eq!(v["coverage"]["unexercised"][0]["line"], 4);

        // Every policy exercised: a one-line summary, and the strict run passes.
        let (_d, t) = setup("allow");
        let r = test(&[t], &strict, false);
        assert_eq!(r.status, Status::Ok, "{}", r.stdout);
        assert!(r.stdout.contains("all 1 policy exercised"), "{}", r.stdout);
    }

    #[test]
    fn lint_clean_with_and_without_config() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "p.cedar", POLICY);
        let c = write(d.path(), "c.toml", CONFIG);
        let ok = lint(&p, Some(&c), false, false);
        assert_eq!(ok.status, Status::Ok, "{}", ok.stdout);
        assert!(ok.stdout.contains("1 policy, 0 error(s)"));

        // Without a config the policy's own action names declare the tools: no false error.
        let bare = lint(&p, None, false, false);
        assert_eq!(bare.status, Status::Ok, "{}", bare.stdout);
        assert!(bare.stdout.contains("note: no --config"), "{}", bare.stdout);
        assert!(bare.stdout.contains("0 error(s)"), "{}", bare.stdout);
        assert!(bare.stdout.contains("0 warning(s)"), "{}", bare.stdout);
    }

    #[test]
    fn lint_reports_line_and_column_and_schema() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            d.path(),
            "p.cedar",
            "permit(principal, action, resource);\nforbid(principal action, resource);\n",
        );
        let r = lint(&p, None, true, false);
        assert_eq!(r.status, Status::Failed);
        assert!(r.stdout.contains("entity Agent"), "schema printed");
        assert!(r.stdout.contains("p.cedar:2:"), "{}", r.stdout);
        let j = lint(&p, None, false, true);
        let v: Value = serde_json::from_str(&j.stdout).unwrap();
        assert_eq!(v["issues"][0]["line"], 2);
    }

    #[test]
    fn admin_evaluate_body_carries_the_chain_and_labels_and_reads_the_answer() {
        let f = TestFile::from_yaml_str(
            r#"
cases:
  - name: labelled
    chain: [a, b]
    session: { tainted_by: [web/fetch] }
    approval: { by: user }
    usage: { calls: 3 }
    budget: { calls_remaining: 0, destination_new: false }
    call: { server: github, tool: create_issue, arguments: { repo: acme/api } }
    expect: deny
  - name: plain
    call: { server: github, tool: read_file }
    expect: allow
"#,
        )
        .unwrap();
        let input = f.cases[0].input(f.now_unix()).unwrap();
        let body = admin_evaluate_body(&input, f.cases[0].budget.as_ref());
        assert_eq!(body["subject"]["id"], "b");
        assert_eq!(
            body["subject"]["properties"]["chain"]["hops"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(body["action"]["properties"]["server"], "github");
        assert_eq!(body["context"]["input"]["repo"], "acme/api");
        assert_eq!(body["session"]["tainted"], true);
        assert_eq!(body["session"]["tainted_by"], json!(["web/fetch"]));
        assert_eq!(body["approval"], json!({"by": "user"}));
        assert_eq!(body["usage"]["calls"], 3);
        // `budget` as the case states it, members it leaves out left out.
        assert_eq!(
            body["budget"],
            json!({"calls_remaining": 0, "destination_new": false})
        );
        assert!(body.get("token").is_none());
        // Without labels the run is sent as untainted with no usage, and no approval.
        let plain = admin_evaluate_body(&f.cases[1].input(f.now_unix()).unwrap(), None);
        assert_eq!(plain["session"]["tainted"], false);
        assert_eq!(plain["usage"]["calls"], 0);
        assert!(plain.get("approval").is_none());
        assert!(plain.get("budget").is_none());

        let a = admin_evaluate_actual(&json!({
            "decision": "deny", "reason": "policy_deny", "policy_ids": ["p"],
            "diagnostics": [], "lease_check": "skipped"
        }))
        .unwrap();
        assert!(!a.decision.is_allow());
        assert_eq!(
            (a.reason.as_str(), a.policy_ids.clone()),
            ("policy_deny", vec!["p".to_string()])
        );
        assert!(admin_evaluate_actual(&json!({"reason": "x"})).is_err());
    }

    #[test]
    fn test_and_lint_subcommands_parse() {
        use crate::cli::{Cli, Command, PolicyCmd};
        use clap::Parser;
        let cli = Cli::try_parse_from(["attenuo", "policy", "test", "a.yaml", "b.yaml", "--json"])
            .unwrap();
        assert!(cli.json);
        let Command::Policy(PolicyCmd::Test(args)) = cli.command else {
            panic!("not policy test")
        };
        assert_eq!(args.files.len(), 2);
        assert!(!args.fail_on_unexercised);
        let cli = Cli::try_parse_from([
            "attenuo",
            "policy",
            "test",
            "a.yaml",
            "--fail-on-unexercised",
            "--watch",
            "--schema-file",
            "base.cedarschema",
            "--via",
            "authzen",
            "--token-file",
            "t.jwt",
        ])
        .unwrap();
        let Command::Policy(PolicyCmd::Test(args)) = cli.command else {
            panic!("not policy test")
        };
        assert!(args.fail_on_unexercised);
        assert!(args.watch);
        assert_eq!(args.schema_file, Some(PathBuf::from("base.cedarschema")));
        assert_eq!(args.via, crate::cli::Via::Authzen);
        assert_eq!(args.token.token_file, Some(PathBuf::from("t.jwt")));

        // The admin token flags are global: before `policy test` or after it.
        for argv in [
            &["attenuo", "--admin-token-file", "a.txt", "policy", "test"][..],
            &["attenuo", "policy", "test", "--admin-token-file", "a.txt"][..],
        ] {
            let mut argv = argv.to_vec();
            argv.extend(["a.yaml", "--via", "admin-evaluate"]);
            let cli = Cli::try_parse_from(argv).unwrap();
            assert_eq!(cli.admin_token_file, Some(PathBuf::from("a.txt")));
            let Command::Policy(PolicyCmd::Test(args)) = cli.command else {
                panic!("not policy test")
            };
            assert_eq!(args.via, crate::cli::Via::AdminEvaluate);
        }

        let cli = Cli::try_parse_from([
            "attenuo", "policy", "lint", "p.cedar", "--config", "s.toml", "--schema",
        ])
        .unwrap();
        let Command::Policy(PolicyCmd::Lint {
            policy,
            config,
            schema_file,
            schema,
        }) = cli.command
        else {
            panic!("not policy lint")
        };
        assert_eq!(policy, PathBuf::from("p.cedar"));
        assert_eq!(config, Some(PathBuf::from("s.toml")));
        assert!(schema);
        assert_eq!(schema_file, None);

        assert!(Cli::try_parse_from(["attenuo", "policy", "test"]).is_err());
    }

    #[test]
    fn lint_flags_bare_actions_unless_the_config_opts_into_them_sr13() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            d.path(),
            "p.cedar",
            "@id(\"read\")\npermit(principal, action == Action::\"read_file\", resource);\n",
        );
        let c = write(d.path(), "c.toml", CONFIG);
        let r = lint(&p, Some(&c), false, false);
        assert_eq!(r.status, Status::Failed);
        assert!(
            r.stdout
                .contains("p.cedar:2:29: error[actions] (read): bare action"),
            "{}",
            r.stdout
        );
        let legacy = write(
            d.path(),
            "legacy.toml",
            &format!("[policy]\nlegacy_bare_actions = true\n{CONFIG}"),
        );
        let r = lint(&p, Some(&legacy), false, false);
        assert_eq!(r.status, Status::Ok, "{}", r.stdout);
        assert!(r.stdout.contains("warning[actions]"), "{}", r.stdout);
    }

    #[test]
    fn lint_missing_file_is_an_error() {
        let r = lint(Path::new("/nonexistent.cedar"), None, false, false);
        assert_eq!(r.status, Status::Error);
    }

    /// A base schema that adds an optional `owner` to `Tool`, and a policy that reads it.
    fn custom_schema_setup() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let base = attenuo_policy::DEFAULT_SCHEMA.replace(
            "    destructive: Bool,\n",
            "    destructive: Bool,\n    owner?: String,\n",
        );
        let schema = write(d.path(), "base.cedarschema", &base);
        let policy = write(
            d.path(),
            "p.cedar",
            "@id(\"owned\")\npermit(principal, action == Action::\"github/read_file\", resource)\nwhen { resource has owner && resource.owner == \"alice\" };\n",
        );
        let t = write(
            d.path(),
            "t.yaml",
            "policies: p.cedar\ncatalog: c.toml\ncases:\n  - name: no owner attribute at run time\n    call: { server: github, tool: read_file }\n    expect: deny\n",
        );
        write(d.path(), "c.toml", CONFIG);
        (d, schema, policy, t)
    }

    #[test]
    fn schema_file_replaces_the_base_schema_in_test_and_lint() {
        let (d, schema, policy, t) = custom_schema_setup();
        // The built-in base does not declare `owner`: the policy is impossible, so a warning.
        let plain = lint(&policy, Some(&d.path().join("c.toml")), false, false);
        assert!(plain.stdout.contains("1 warning(s)"), "{}", plain.stdout);

        let opts = TestOptions {
            schema_file: Some(schema.clone()),
            ..TestOptions::default()
        };
        let r = test(std::slice::from_ref(&t), &opts, false);
        assert_eq!(r.status, Status::Ok, "{}{}", r.stdout, r.stderr);
        let l = lint_with_schema(
            &policy,
            Some(&d.path().join("c.toml")),
            Some(&schema),
            true,
            false,
        );
        assert_eq!(l.status, Status::Ok, "{}{}", l.stdout, l.stderr);
        assert!(l.stdout.contains("owner?: String"), "{}", l.stdout);
        assert!(
            l.stdout.contains("0 error(s), 0 warning(s)"),
            "{}",
            l.stdout
        );

        // The config's `[policy] schema_path` (relative to the config) works the same way.
        write(
            d.path(),
            "c.toml",
            &format!("[policy]\nschema_path = \"base.cedarschema\"\n{CONFIG}"),
        );
        let r = test(std::slice::from_ref(&t), &TestOptions::default(), false);
        assert_eq!(r.status, Status::Ok, "{}{}", r.stdout, r.stderr);
        let l = lint(&policy, Some(&d.path().join("c.toml")), false, false);
        assert!(l.stdout.contains("0 warning(s)"), "{}", l.stdout);
    }

    #[test]
    fn a_schema_file_without_the_required_entities_is_refused() {
        let (d, _schema, policy, t) = custom_schema_setup();
        let bad = write(
            d.path(),
            "bad.cedarschema",
            &attenuo_policy::DEFAULT_SCHEMA.replace("chain_depth: Long", "chain_depth?: Long"),
        );
        let opts = TestOptions {
            schema_file: Some(bad.clone()),
            ..TestOptions::default()
        };
        let r = test(std::slice::from_ref(&t), &opts, false);
        assert_eq!(r.status, Status::Error);
        assert!(r.stderr.contains("custom base schema"), "{}", r.stderr);
        assert!(r.stderr.contains("chain_depth"), "{}", r.stderr);

        let l = lint_with_schema(&policy, None, Some(&bad), false, false);
        assert_eq!(l.status, Status::Error);
        assert!(l.stderr.contains("custom base schema"), "{}", l.stderr);

        let no_server = write(
            d.path(),
            "noserver.cedarschema",
            "entity User; entity Agent in [User, Agent]; entity Tool;",
        );
        let l = lint_with_schema(&policy, None, Some(&no_server), false, false);
        assert!(
            l.stderr
                .contains("does not declare the entity type(s) Server"),
            "{}",
            l.stderr
        );
        let missing = lint_with_schema(&policy, None, Some(&d.path().join("nope")), false, false);
        assert_eq!(missing.status, Status::Error);
    }
}
