//! `onbehalf policy test` and `onbehalf policy lint`: offline checks of a policy set. They
//! never talk to a server.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use onbehalf_policy::testing::{self, CaseReport, TestFile, TestReport};
use onbehalf_policy::{LintSeverity, PolicyEngineBuilder};
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

/// `onbehalf policy test <file>...`
pub fn test(files: &[PathBuf], json_out: bool) -> Run {
    let mut run = Run::new();
    let mut reports: Vec<(&Path, TestReport)> = Vec::new();
    let mut errors: Vec<(&Path, String)> = Vec::new();
    for path in files {
        match TestFile::load(path).and_then(|f| f.run()) {
            Ok(report) => reports.push((path, report)),
            Err(e) => errors.push((path, e.to_string())),
        }
    }
    let passed: usize = reports.iter().map(|(_, r)| r.passed()).sum();
    let failed: usize = reports.iter().map(|(_, r)| r.failed()).sum();

    if json_out {
        let mut entries: Vec<Value> = reports
            .iter()
            .map(|(p, r)| {
                json!({"file": p, "cases": r.cases, "passed": r.passed(), "failed": r.failed()})
            })
            .collect();
        entries.extend(errors.iter().map(|(p, e)| json!({"file": p, "error": e})));
        run.stdout = pretty(&json!({
            "files": entries, "passed": passed, "failed": failed, "errors": errors.len(),
        }));
    } else {
        for (path, report) in &reports {
            let _ = writeln!(run.stdout, "{}", path.display());
            for case in &report.cases {
                render_case(&mut run.stdout, case);
            }
            run.stdout.push('\n');
        }
        for (path, e) in &errors {
            let _ = writeln!(run.stderr, "error: {}: {e}", path.display());
        }
        if !reports.is_empty() {
            let _ = write!(
                run.stdout,
                "{passed} passed, {failed} failed ({} cases in {} file{})",
                passed + failed,
                reports.len(),
                if reports.len() == 1 { "" } else { "s" }
            );
            if !errors.is_empty() {
                let _ = write!(run.stdout, "; {} file(s) could not be run", errors.len());
            }
            run.stdout.push('\n');
        }
    }
    run.status = if !errors.is_empty() {
        Status::Error
    } else if failed > 0 {
        Status::Failed
    } else {
        Status::Ok
    };
    run
}

fn render_case(out: &mut String, case: &CaseReport) {
    let mark = if case.passed { "\u{2713}" } else { "\u{2717}" };
    let detail = match &case.actual {
        Some(a) => {
            let mut d = format!(
                "{}: {}",
                if a.decision.is_allow() {
                    "allow"
                } else {
                    "deny"
                },
                a.reason
            );
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

/// `onbehalf policy lint <policy.cedar> [--config server.toml] [--schema]`
pub fn lint(policy: &Path, config: Option<&Path>, show_schema: bool, json_out: bool) -> Run {
    let mut run = Run::new();
    let text = match std::fs::read_to_string(policy) {
        Ok(t) => t,
        Err(e) => return Run::error(format!("reading {}: {e}", policy.display())),
    };
    let catalog = match config.map(testing::load_catalog).transpose() {
        Ok(c) => c.unwrap_or_default(),
        Err(e) => return Run::error(e.to_string()),
    };
    let catalog_empty = catalog.is_empty();
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
    let schema = builder.schema_text();
    let report = onbehalf_policy::lint_with_options(
        &text,
        &schema,
        onbehalf_policy::LintOptions {
            legacy_bare_actions,
        },
    );

    if json_out {
        let mut v = serde_json::to_value(&report).unwrap_or_default();
        v["file"] = json!(policy);
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
                "hint: pass --config <server.toml> so tools named in the policy are declared from its [policy.catalog]"
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
        let r = test(&[t], false);
        assert_eq!(r.status, Status::Ok);
        assert!(r.stdout.contains("\u{2713} read"), "{}", r.stdout);
        assert!(r.stdout.contains("1 passed, 0 failed (1 cases in 1 file)"));
    }

    #[test]
    fn failing_case_exits_failed_and_explains() {
        let (_d, t) = setup("deny");
        let r = test(&[t], false);
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
        let r = test(&[bad, t, d.path().join("missing.yaml")], false);
        assert_eq!(r.status, Status::Error);
        assert!(r.stdout.contains("1 passed"));
        assert_eq!(r.stderr.matches("error:").count(), 2, "{}", r.stderr);
    }

    #[test]
    fn json_output_is_machine_readable() {
        let (_d, t) = setup("deny");
        let r = test(&[t], true);
        let v: Value = serde_json::from_str(&r.stdout).unwrap();
        assert_eq!(v["failed"], 1);
        assert_eq!(v["files"][0]["cases"][0]["actual"]["decision"], "allow");
    }

    #[test]
    fn lint_clean_with_config_and_noisy_without() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "p.cedar", POLICY);
        let c = write(d.path(), "c.toml", CONFIG);
        let ok = lint(&p, Some(&c), false, false);
        assert_eq!(ok.status, Status::Ok, "{}", ok.stdout);
        assert!(ok.stdout.contains("1 policy, 0 error(s)"));

        let bad = lint(&p, None, false, false);
        assert_eq!(bad.status, Status::Failed);
        assert!(bad.stdout.contains("hint: pass --config"), "{}", bad.stdout);
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
    fn test_and_lint_subcommands_parse() {
        use crate::cli::{Cli, Command, PolicyCmd};
        use clap::Parser;
        let cli = Cli::try_parse_from(["onbehalf", "policy", "test", "a.yaml", "b.yaml", "--json"])
            .unwrap();
        assert!(cli.json);
        let Command::Policy(PolicyCmd::Test { files }) = cli.command else {
            panic!("not policy test")
        };
        assert_eq!(files.len(), 2);

        let cli = Cli::try_parse_from([
            "onbehalf", "policy", "lint", "p.cedar", "--config", "s.toml", "--schema",
        ])
        .unwrap();
        let Command::Policy(PolicyCmd::Lint {
            policy,
            config,
            schema,
        }) = cli.command
        else {
            panic!("not policy lint")
        };
        assert_eq!(policy, PathBuf::from("p.cedar"));
        assert_eq!(config, Some(PathBuf::from("s.toml")));
        assert!(schema);

        assert!(Cli::try_parse_from(["onbehalf", "policy", "test"]).is_err());
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
}
