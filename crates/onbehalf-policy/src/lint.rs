//! Lint a Cedar policy file: parse it, then validate it against a schema, reporting every
//! problem with the line and column it points at.
//!
//! [`PolicyEngineBuilder::build`](crate::PolicyEngineBuilder::build) stops at the first failing
//! stage and flattens errors to a string. This module keeps going where it can and keeps the
//! source locations, which is what an editor or a CI log wants.

use std::str::FromStr;

use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
use miette::Diagnostic;
use serde::Serialize;

/// Whether an issue fails the lint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LintSeverity {
    Error,
    Warning,
}

/// One problem found in a policy file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LintIssue {
    pub severity: LintSeverity,
    /// `schema`, `parse`, or `validate`.
    pub stage: &'static str,
    /// The policy the issue is about, when Cedar names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    pub message: String,
    /// 1-based line in the policy text, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// 1-based column (in characters), when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
}

/// Everything [`lint`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LintReport {
    pub issues: Vec<LintIssue>,
    /// Ids of the policies that parsed (empty when parsing failed).
    pub policy_ids: Vec<String>,
}

impl LintReport {
    pub fn error_count(&self) -> usize {
        self.count(LintSeverity::Error)
    }

    pub fn warning_count(&self) -> usize {
        self.count(LintSeverity::Warning)
    }

    pub fn has_errors(&self) -> bool {
        self.error_count() > 0
    }

    fn count(&self, sev: LintSeverity) -> usize {
        self.issues.iter().filter(|i| i.severity == sev).count()
    }
}

type Loc = Option<(usize, usize)>;

/// Convert a byte offset into a 1-based (line, column).
fn line_col(text: &str, offset: usize) -> (usize, usize) {
    let offset = offset.min(text.len());
    let before = text.get(..offset).unwrap_or("");
    let line = before.matches('\n').count() + 1;
    let col = before
        .rsplit('\n')
        .next()
        .map(|l| l.chars().count())
        .unwrap_or(0)
        + 1;
    (line, col)
}

/// Flatten a (possibly multi-error) diagnostic into leaf messages with locations.
fn leaves(d: &dyn Diagnostic, text: &str, out: &mut Vec<(String, Loc)>) {
    let related: Vec<&dyn Diagnostic> = d.related().map(|r| r.collect()).unwrap_or_default();
    if related.is_empty() {
        let loc = d
            .labels()
            .and_then(|mut l| l.next())
            .map(|l| line_col(text, l.offset()));
        out.push((d.to_string(), loc));
    } else {
        for r in related {
            leaves(r, text, out);
        }
    }
}

fn issue(
    severity: LintSeverity,
    stage: &'static str,
    policy_id: Option<String>,
    message: String,
    loc: Loc,
) -> LintIssue {
    LintIssue {
        severity,
        stage,
        policy_id,
        message,
        line: loc.map(|l| l.0),
        column: loc.map(|l| l.1),
    }
}

/// Lint `policy_text` against `schema_text` (see
/// [`PolicyEngineBuilder::schema_text`](crate::PolicyEngineBuilder::schema_text)), in Cedar
/// strict validation mode, the mode the engine itself uses.
pub fn lint(policy_text: &str, schema_text: &str) -> LintReport {
    let mut report = LintReport::default();

    let schema = match Schema::from_cedarschema_str(schema_text) {
        Ok((s, _)) => s,
        Err(e) => {
            report.issues.push(issue(
                LintSeverity::Error,
                "schema",
                None,
                e.to_string(),
                None,
            ));
            return report;
        }
    };

    let parsed = match PolicySet::from_str(policy_text) {
        Ok(p) => p,
        Err(e) => {
            let mut found = Vec::new();
            leaves(&e, policy_text, &mut found);
            for (message, loc) in found {
                report
                    .issues
                    .push(issue(LintSeverity::Error, "parse", None, message, loc));
            }
            return report;
        }
    };

    // Apply @id annotations the way the engine does, so ids in messages match audit records
    // and duplicate ids are caught here too.
    let policies = match crate::apply_id_annotations(&parsed) {
        Ok(p) => p,
        Err(e) => {
            report.issues.push(issue(
                LintSeverity::Error,
                "parse",
                None,
                e.to_string(),
                None,
            ));
            return report;
        }
    };
    report.policy_ids = policies.policies().map(|p| p.id().to_string()).collect();
    report.policy_ids.sort();

    let result = Validator::new(schema).validate(&policies, ValidationMode::Strict);
    for e in result.validation_errors() {
        let mut found = Vec::new();
        leaves(e, policy_text, &mut found);
        for (message, loc) in found {
            report.issues.push(issue(
                LintSeverity::Error,
                "validate",
                Some(e.policy_id().to_string()),
                message,
                loc,
            ));
        }
    }
    for w in result.validation_warnings() {
        let mut found = Vec::new();
        leaves(w, policy_text, &mut found);
        for (message, loc) in found {
            report.issues.push(issue(
                LintSeverity::Warning,
                "validate",
                Some(w.policy_id().to_string()),
                message,
                loc,
            ));
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArgType, PolicyEngineBuilder, ToolAttrs, ToolCatalog};

    fn schema() -> String {
        PolicyEngineBuilder::new()
            .with_catalog(ToolCatalog::new().with(
                "github",
                "read_file",
                ToolAttrs::new().with_input("repo", ArgType::String),
            ))
            .schema_text()
    }

    #[test]
    fn clean_policy_has_no_issues() {
        let r = lint(
            "@id(\"p\")\npermit(principal, action == Action::\"read_file\", resource);\n",
            &schema(),
        );
        assert!(r.issues.is_empty(), "{:?}", r.issues);
        assert_eq!(r.policy_ids, vec!["p"]);
    }

    #[test]
    fn parse_error_has_line_and_column() {
        let r = lint(
            "permit(principal, action, resource);\n\nforbid(principal action, resource);\n",
            &schema(),
        );
        assert!(r.has_errors());
        let i = &r.issues[0];
        assert_eq!(i.stage, "parse");
        assert_eq!(i.line, Some(3), "{i:?}");
        assert!(i.column.is_some());
    }

    #[test]
    fn validation_error_points_at_the_policy() {
        let text = "permit(principal, action, resource);\n\n@id(\"bad\")\npermit(principal, action == Action::\"nope\", resource);\n";
        let r = lint(text, &schema());
        let i = r
            .issues
            .iter()
            .find(|i| i.stage == "validate")
            .expect("validation issue");
        assert_eq!(i.policy_id.as_deref(), Some("bad"));
        assert!(i.line.is_some(), "{i:?}");
    }

    #[test]
    fn duplicate_ids_are_reported() {
        let text = "@id(\"x\")\npermit(principal, action, resource);\n@id(\"x\")\nforbid(principal, action, resource);\n";
        let r = lint(text, &schema());
        assert!(r.has_errors());
        assert!(r.issues[0].message.contains("duplicate"), "{:?}", r.issues);
    }

    #[test]
    fn line_col_counts_chars() {
        assert_eq!(line_col("ab\ncd", 4), (2, 2));
        assert_eq!(line_col("é\nx", 3), (2, 1));
        assert_eq!(line_col("abc", 99), (1, 4));
    }
}
