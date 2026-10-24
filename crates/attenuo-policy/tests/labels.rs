//! Output labelling in the policy engine (ADR-0009): the catalog's `destructive` and `output`,
//! narrowing-only import of MCP annotations, the always-present Cedar attributes, and
//! `@obligation("approval")`.

use std::path::Path;

use attenuo_core::{AgentId, Capability, CapabilitySet, DelegationChain, LeaseId, OriginatingUser};
use attenuo_core::{Decision, ToolCall};
use attenuo_policy::testing::TestFile;
use attenuo_policy::{
    AnnotationImport, CallLabels, OutputLabel, PolicyEngine, PolicyEngineBuilder, PolicyError,
    SessionLabels, ToolAttrs, ToolCatalog, REASON_APPROVAL_REQUIRED, REASON_CAPABILITY_DENIED,
    REASON_POLICY_ALLOW, REASON_POLICY_DENY,
};
use serde_json::json;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

fn now() -> OffsetDateTime {
    datetime!(2026-10-24 09:00 UTC)
}

fn chain(caps: &[(&str, &str)]) -> DelegationChain {
    DelegationChain::root(
        OriginatingUser {
            subject: "alice".into(),
            issuer: "https://idp.example".into(),
            authenticated_at: now() - Duration::minutes(1),
            attributes: Default::default(),
        },
        AgentId::new("assistant"),
        CapabilitySet::from_iter(caps.iter().map(|(s, t)| Capability::new(*s, *t))),
        now(),
        Duration::hours(1),
        LeaseId::new("run-1"),
    )
    .unwrap()
}

fn catalog() -> ToolCatalog {
    ToolCatalog::new()
        .with("web", "fetch", ToolAttrs::new().readonly(true))
        .with("fs", "read", ToolAttrs::new().readonly(true))
        .with("fs", "delete", ToolAttrs::new())
        .with("fs", "append", ToolAttrs::new().destructive(false))
        .with(
            "bank",
            "balance",
            ToolAttrs::new().readonly(true).output(OutputLabel::Trusted),
        )
}

const ASK_AFTER_TAINT: &str = r#"
@id("ask")
@obligation("approval")
forbid (principal, action, resource)
when { resource.destructive && context.session.tainted && !context.approval.present };
"#;

fn engine(policies: &str, import: AnnotationImport) -> PolicyEngine {
    PolicyEngineBuilder::new()
        .with_catalog(catalog())
        .with_annotation_import(import)
        .with_policies_str(policies)
        .build()
        .unwrap()
}

fn tainted() -> CallLabels {
    CallLabels {
        session: SessionLabels::from_sources(["web/fetch"]),
        ..Default::default()
    }
}

fn all_caps() -> DelegationChain {
    chain(&[("web", "*"), ("fs", "*"), ("bank", "*")])
}

#[test]
fn destructive_defaults_to_not_readonly() {
    assert!(ToolAttrs::new().is_destructive());
    assert!(!ToolAttrs::new().readonly(true).is_destructive());
    assert!(!ToolAttrs::new().destructive(false).is_destructive());
    assert!(ToolAttrs::new()
        .readonly(true)
        .destructive(true)
        .is_destructive());
    // TOML catalog entries: `destructive` and `output` next to `readonly` and `sensitive`.
    let t: ToolAttrs = toml::from_str("readonly = true\noutput = \"trusted\"\n").unwrap();
    assert_eq!(t.output, OutputLabel::Trusted);
    assert!(!t.is_destructive());
    let t: ToolAttrs = toml::from_str("destructive = false\n").unwrap();
    assert_eq!(t.output, OutputLabel::Untrusted);
    assert!(!t.is_destructive() && !t.readonly);
    assert!(toml::from_str::<ToolAttrs>("output = \"maybe\"\n").is_err());
}

#[test]
fn approval_required_only_when_every_applicable_forbid_carries_the_obligation() {
    let policies = format!(
        "{ASK_AFTER_TAINT}
@id(\"no_deletes_of_root\")
forbid (principal, action == Action::\"fs/delete\", resource)
when {{ context.input has path && context.input.path == \"/\" }};
@id(\"all\")
permit (principal, action, resource);"
    );
    let e = engine(&policies, AnnotationImport::Never);
    let c = all_caps();
    let delete = |path: &str| ToolCall::new("fs", "delete", json!({ "path": path }));

    // Untainted: allowed.
    let o = e.authorize(&c, &delete("a.txt"), now());
    assert_eq!(o.reason, REASON_POLICY_ALLOW);

    // Tainted, only the approval forbid applies: ask.
    let o = e.authorize_labelled(&c, &delete("a.txt"), &tainted(), now());
    assert_eq!(o.decision, Decision::Deny);
    assert_eq!(o.reason, REASON_APPROVAL_REQUIRED);
    assert_eq!(o.policy_ids, vec!["ask"]);

    // A plain forbid applies too: it wins, so no approval could unlock the call.
    let o = e.authorize_labelled(&c, &delete("/"), &tainted(), now());
    assert_eq!(o.reason, REASON_POLICY_DENY);
    let mut ids = o.policy_ids.clone();
    ids.sort();
    assert_eq!(ids, vec!["ask", "no_deletes_of_root"]);

    // Untainted, the plain forbid alone: policy_deny as before.
    let o = e.authorize(&c, &delete("/"), now());
    assert_eq!(o.reason, REASON_POLICY_DENY);

    // Not destructive: not gated.
    for (tool, args) in [("read", json!({})), ("append", json!({"path": "log"}))] {
        let o = e.authorize_labelled(&c, &ToolCall::new("fs", tool, args), &tainted(), now());
        assert_eq!(o.reason, REASON_POLICY_ALLOW, "{tool}");
    }
}

#[test]
fn approval_cannot_help_a_call_no_permit_allows() {
    // Only the approval forbid and a narrow permit for reads.
    let policies = format!(
        "{ASK_AFTER_TAINT}
@id(\"reads\")
permit (principal, action, resource) when {{ resource.readonly }};"
    );
    let e = engine(&policies, AnnotationImport::Never);
    let o = e.authorize_labelled(
        &all_caps(),
        &ToolCall::new("fs", "delete", json!({})),
        &tainted(),
        now(),
    );
    assert_eq!(o.reason, REASON_POLICY_DENY);
}

#[test]
fn capability_stage_runs_before_the_obligation() {
    let e = engine(
        &format!("{ASK_AFTER_TAINT}\npermit (principal, action, resource);"),
        AnnotationImport::Never,
    );
    let narrow = chain(&[("fs", "read")]);
    let o = e.authorize_labelled(
        &narrow,
        &ToolCall::new("fs", "delete", json!({})),
        &tainted(),
        now(),
    );
    assert_eq!(o.reason, REASON_CAPABILITY_DENIED);
}

#[test]
fn an_unreadable_taint_state_is_tainted() {
    let e = engine(
        &format!("{ASK_AFTER_TAINT}\npermit (principal, action, resource);"),
        AnnotationImport::Never,
    );
    let unknown = CallLabels {
        session: SessionLabels::unknown(),
        ..Default::default()
    };
    let o = e.authorize_labelled(
        &all_caps(),
        &ToolCall::new("fs", "delete", json!({})),
        &unknown,
        now(),
    );
    assert_eq!(o.reason, REASON_APPROVAL_REQUIRED);
}

#[test]
fn tainted_by_names_the_sources() {
    let e = engine(
        r#"@id("only_after_web")
           permit (principal, action, resource)
           when { context.session.tainted_by.contains("web/fetch") };"#,
        AnnotationImport::Never,
    );
    let c = all_caps();
    let call = ToolCall::new("fs", "read", json!({}));
    assert_eq!(e.authorize(&c, &call, now()).reason, REASON_POLICY_DENY);
    assert_eq!(
        e.authorize_labelled(&c, &call, &tainted(), now()).reason,
        REASON_POLICY_ALLOW
    );
    // The phase 1 constants.
    let e = engine(
        r#"permit (principal, action, resource)
           when { !context.args_contain_untrusted && context.untrusted_args.isEmpty() &&
                  !context.approval.present && context.approval.by == "" };"#,
        AnnotationImport::Never,
    );
    assert_eq!(
        e.authorize_labelled(&c, &call, &tainted(), now()).reason,
        REASON_POLICY_ALLOW
    );
}

#[test]
fn obligations_other_than_approval_on_a_forbid_are_refused_at_load() {
    for text in [
        "@obligation(\"aproval\") forbid (principal, action, resource);",
        "@obligation(\"approval\") permit (principal, action, resource);",
    ] {
        let err = PolicyEngineBuilder::new()
            .with_catalog(catalog())
            .with_policies_str(text)
            .build()
            .unwrap_err();
        assert!(matches!(err, PolicyError::Obligation(_)), "{text}: {err}");
    }
    // A reload is refused the same way and the old set stays in force.
    let mut e = engine(
        "permit (principal, action, resource);",
        AnnotationImport::Never,
    );
    assert!(e
        .reload_policies_str("@obligation(\"x\") forbid (principal, action, resource);")
        .is_err());
    assert_eq!(
        e.authorize(
            &all_caps(),
            &ToolCall::new("fs", "delete", json!({})),
            now()
        )
        .reason,
        REASON_POLICY_ALLOW
    );
    // And a reload can add the obligation.
    e.reload_policies_str(&format!(
        "{ASK_AFTER_TAINT}\npermit (principal, action, resource);"
    ))
    .unwrap();
    assert_eq!(
        e.authorize_labelled(
            &all_caps(),
            &ToolCall::new("fs", "delete", json!({})),
            &tainted(),
            now()
        )
        .reason,
        REASON_APPROVAL_REQUIRED
    );
}

/// `annotation_import_only_narrows` (ADR-0009): a hint can make a tool destructive or
/// not read-only, never the reverse, and only under `narrowing`.
#[test]
fn annotation_import_only_narrows() {
    let policies = format!(
        "{ASK_AFTER_TAINT}\npermit (principal, action, resource) when {{ resource.readonly || \
         context.session.tainted }};"
    );
    let c = all_caps();
    let read = ToolCall::new("fs", "read", json!({}));

    // `never`: annotations change nothing.
    let e = engine(&policies, AnnotationImport::Never);
    assert!(!e.import_annotations("fs", "read", Some(false), Some(true)));
    assert_eq!(
        e.authorize_labelled(&c, &read, &tainted(), now()).reason,
        REASON_POLICY_ALLOW
    );

    let e = engine(&policies, AnnotationImport::Narrowing);
    // Hints that would widen are ignored: `fs/delete` stays destructive, `fs/append` (an
    // explicit `destructive = false`) is not made read-only.
    assert!(!e.import_annotations("fs", "delete", Some(true), Some(false)));
    assert!(e.effective_attrs("fs", "delete").unwrap().is_destructive());
    assert!(!e.import_annotations("fs", "append", Some(true), None));
    assert!(!e.effective_attrs("fs", "append").unwrap().readonly);
    // Tools outside the catalog are not tracked.
    assert!(!e.import_annotations("fs", "unknown", Some(false), Some(true)));

    // `fs/read` is read-only in the catalog; the server says it is not, and destructive.
    assert_eq!(
        e.authorize_labelled(&c, &read, &tainted(), now()).reason,
        REASON_POLICY_ALLOW
    );
    assert!(e.import_annotations("fs", "read", Some(false), None));
    let attrs = e.effective_attrs("fs", "read").unwrap();
    assert!(!attrs.readonly && attrs.is_destructive());
    assert_eq!(
        e.authorize_labelled(&c, &read, &tainted(), now()).reason,
        REASON_APPROVAL_REQUIRED
    );
    // Sticky: a later listing that says read-only again does not undo it.
    assert!(!e.import_annotations("fs", "read", Some(true), Some(false)));
    assert!(!e.effective_attrs("fs", "read").unwrap().readonly);

    // An explicit `destructive = false` falls only to `destructiveHint: true`.
    // `readOnlyHint: false` on a tool that is already not read-only leaves an explicit
    // `destructive = false` alone.
    e.import_annotations("fs", "append", Some(false), None);
    assert!(!e.effective_attrs("fs", "append").unwrap().is_destructive());
    assert!(e.import_annotations("fs", "append", None, Some(true)));
    assert!(e.effective_attrs("fs", "append").unwrap().is_destructive());
    // Trusted output is never touched by annotations.
    e.import_annotations("bank", "balance", Some(false), Some(true));
    assert_eq!(
        e.effective_attrs("bank", "balance").unwrap().output,
        OutputLabel::Trusted
    );
}

#[test]
fn shipped_example_policies_pass_their_tests() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policies/output-labels_test.yaml");
    let file = TestFile::load(&path).unwrap();
    let report = file.run().unwrap();
    for case in &report.cases {
        assert!(
            case.passed,
            "{}: {:?} {:?}",
            case.name, case.failures, case.error
        );
    }
    assert!(report.cases.len() >= 8);
}

/// `context.approval` reaches Cedar: a granted approval lifts the approval forbid, and
/// `approval.by` is visible to policy. A plain forbid is not lifted by an approval.
#[test]
fn a_granted_approval_lifts_only_the_approval_forbid() {
    let policies = format!(
        "{ASK_AFTER_TAINT}
@id(\"operators_may_not_approve_deletes\")
forbid (principal, action == Action::\"fs/delete\", resource)
when {{ context.approval.present && context.approval.by == \"operator\" }};
@id(\"all\")
permit (principal, action, resource);"
    );
    let e = engine(&policies, AnnotationImport::Never);
    let c = all_caps();
    let delete = ToolCall::new("fs", "delete", json!({ "path": "a.txt" }));
    let with = |by: &str| CallLabels {
        approval: attenuo_policy::ApprovalContext::by(by),
        ..tainted()
    };
    let o = e.authorize_labelled(&c, &delete, &tainted(), now());
    assert_eq!(o.reason, REASON_APPROVAL_REQUIRED);
    let o = e.authorize_labelled(&c, &delete, &with("user"), now());
    assert_eq!(o.reason, REASON_POLICY_ALLOW);
    let o = e.authorize_labelled(&c, &delete, &with("operator"), now());
    assert_eq!(o.reason, REASON_POLICY_DENY);
    assert_eq!(o.policy_ids, vec!["operators_may_not_approve_deletes"]);
}
