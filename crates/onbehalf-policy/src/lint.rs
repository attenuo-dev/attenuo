//! Lint a Cedar policy file: parse it, then validate it against a schema, reporting every
//! problem with the line and column it points at.
//!
//! [`PolicyEngineBuilder::build`](crate::PolicyEngineBuilder::build) stops at the first failing
//! stage and flattens errors to a string. This module keeps going where it can and keeps the
//! source locations, which is what an editor or a CI log wants.
//!
//! It also flags bare actions (`Action::"read_file"`, stage `actions`): since SR-13 an action
//! names its server (`Action::"github/read_file"`). A bare action is an error by default and a
//! deprecation warning under [`LintOptions::legacy_bare_actions`].

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
    /// `schema`, `parse`, `actions` or `validate`.
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

/// Options for [`lint_with_options`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LintOptions {
    /// The policies are for an engine with `[policy] legacy_bare_actions = true`: bare actions
    /// are warnings (deprecated) instead of errors. The schema text must match (generated with
    /// the same switch).
    pub legacy_bare_actions: bool,
}

/// An `Action::"<id>"` entity reference in policy text, outside comments, with the policy it is
/// in (its `@id`, else Cedar's default `policy<N>`) and its location.
struct ActionRef {
    id: String,
    policy_id: String,
    loc: (usize, usize),
}

/// Read a string literal whose opening quote is at `start`; returns its raw contents and the
/// index just past the closing quote.
fn read_string(text: &str, start: usize) -> (String, usize) {
    let bytes = text.as_bytes();
    let mut j = start + 1;
    while j < bytes.len() && bytes[j] != b'"' {
        j += if bytes[j] == b'\\' { 2 } else { 1 };
    }
    let end = j.min(bytes.len());
    (text[start + 1..end].to_string(), (j + 1).min(bytes.len()))
}

fn skip_ws(bytes: &[u8], mut j: usize) -> usize {
    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
        j += 1;
    }
    j
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Find every `Action::"..."` in `text`. A small scanner, not a Cedar parser: it skips `//`
/// comments and string literals, tracks `@id("...")` annotations and counts `;` to know which
/// policy it is in. Only run on text that already parsed.
fn action_refs(text: &str) -> Vec<ActionRef> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut index = 0usize;
    let mut current_id: Option<String> = None;
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'"' => i = read_string(text, i).1,
            b';' => {
                index += 1;
                current_id = None;
                i += 1;
            }
            b'@' if text[i + 1..].starts_with("id")
                && bytes.get(i + 3).is_some_and(|b| !is_ident(*b)) =>
            {
                let j = skip_ws(bytes, i + 3);
                if bytes.get(j) == Some(&b'(') {
                    let k = skip_ws(bytes, j + 1);
                    if bytes.get(k) == Some(&b'"') {
                        let (id, next) = read_string(text, k);
                        current_id = Some(id);
                        i = next;
                        continue;
                    }
                }
                i += 1;
            }
            b'A' if text[i..].starts_with("Action")
                && (i == 0 || !is_ident(bytes[i - 1]))
                && bytes.get(i + 6).is_none_or(|b| !is_ident(*b)) =>
            {
                let start = i;
                let j = skip_ws(bytes, i + 6);
                if text[j..].starts_with("::") {
                    let k = skip_ws(bytes, j + 2);
                    if bytes.get(k) == Some(&b'"') {
                        let (id, next) = read_string(text, k);
                        out.push(ActionRef {
                            id,
                            policy_id: current_id
                                .clone()
                                .unwrap_or_else(|| format!("policy{index}")),
                            loc: line_col(text, start),
                        });
                        i = next;
                        continue;
                    }
                }
                i += 6;
            }
            _ => i += 1,
        }
    }
    out
}

/// Issues for bare (not server-scoped) actions, SR-13.
fn bare_action_issues(text: &str, options: LintOptions) -> Vec<LintIssue> {
    action_refs(text)
        .into_iter()
        .filter(|r| r.id != crate::GENERIC_ACTION && !r.id.contains('/'))
        .map(|r| {
            let (severity, message) = if options.legacy_bare_actions {
                (
                    LintSeverity::Warning,
                    format!(
                        "bare action `Action::\"{id}\"` matches `{id}` on every server; \
                         [policy] legacy_bare_actions is deprecated: write \
                         `Action::\"<server>/{id}\"` and turn it off",
                        id = r.id
                    ),
                )
            } else {
                (
                    LintSeverity::Error,
                    format!(
                        "bare action `Action::\"{id}\"`: actions are server-scoped, write \
                         `Action::\"<server>/{id}\"` (SR-13); bare actions load only with the \
                         deprecated [policy] legacy_bare_actions = true",
                        id = r.id
                    ),
                )
            };
            issue(severity, "actions", Some(r.policy_id), message, Some(r.loc))
        })
        .collect()
}

/// Lint `policy_text` against `schema_text` (see
/// [`PolicyEngineBuilder::schema_text`](crate::PolicyEngineBuilder::schema_text)), in Cedar
/// strict validation mode, the mode the engine itself uses, with default [`LintOptions`] (bare
/// actions are errors).
pub fn lint(policy_text: &str, schema_text: &str) -> LintReport {
    lint_with_options(policy_text, schema_text, LintOptions::default())
}

/// [`lint`] with options.
pub fn lint_with_options(policy_text: &str, schema_text: &str, options: LintOptions) -> LintReport {
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
    report
        .issues
        .extend(bare_action_issues(policy_text, options));

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
            "@id(\"p\")\npermit(principal, action == Action::\"github/read_file\", resource);\n",
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
    fn bare_actions_are_flagged_sr13() {
        let text = concat!(
            "// Action::\"in_comment\" is ignored\n",
            "@id(\"bare\")\n",
            "permit(principal, action in [Action::\"invoke\", Action :: \"read_file\"], resource);\n",
            "permit(principal, action == Action::\"github/read_file\", resource)\n",
            "when { \"Action::\\\"x\\\"\" == \"y\" };\n",
        );
        let r = lint(text, &schema());
        let bare: Vec<&LintIssue> = r.issues.iter().filter(|i| i.stage == "actions").collect();
        assert_eq!(bare.len(), 1, "{:?}", r.issues);
        assert_eq!(bare[0].severity, LintSeverity::Error);
        assert_eq!(bare[0].policy_id.as_deref(), Some("bare"));
        assert_eq!((bare[0].line, bare[0].column), (Some(3), Some(48)));
        assert!(bare[0].message.contains("<server>/read_file"));

        // Under the legacy switch the same reference is a warning, and it validates.
        let legacy_schema = PolicyEngineBuilder::new()
            .with_legacy_bare_actions(true)
            .with_catalog(ToolCatalog::new().with("github", "read_file", ToolAttrs::new()))
            .schema_text();
        let r = lint_with_options(
            "@id(\"bare\")\npermit(principal, action == Action::\"read_file\", resource);\n",
            &legacy_schema,
            LintOptions {
                legacy_bare_actions: true,
            },
        );
        assert!(!r.has_errors(), "{:?}", r.issues);
        assert_eq!(r.warning_count(), 1, "{:?}", r.issues);
    }

    #[test]
    fn unannotated_policies_get_cedar_default_ids() {
        let text = "permit(principal, action, resource);\nforbid(principal, action == Action::\"read_file\", resource);\n";
        let refs = action_refs(text);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].policy_id, "policy1");
    }

    #[test]
    fn line_col_counts_chars() {
        assert_eq!(line_col("ab\ncd", 4), (2, 2));
        assert_eq!(line_col("é\nx", 3), (2, 1));
        assert_eq!(line_col("abc", 99), (1, 4));
    }
}
