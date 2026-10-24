//! A `range` constraint in a policy test file: the case-file grammar takes it in a full
//! capability object, the harness enforces it in the capability stage, and a chain whose child
//! widens it is reported as a malformed case, as the server would refuse to issue it.

use attenuo_policy::testing::TestFile;
use attenuo_policy::PolicyEngineBuilder;

const CASES: &str = r#"
unknown_tools: allow
cases:
  - name: inside the range
    chain:
      - agent: payer
        capabilities:
          - server: banking
            tool: send_money
            constraints: { amount: { op: range, value: { min: 1, max: 2000 } } }
    call: { server: banking, tool: send_money, arguments: { amount: 2000 } }
    expect: allow
    reason: policy_allow
  - name: above the range
    chain:
      - agent: payer
        capabilities:
          - server: banking
            tool: send_money
            constraints: { amount: { op: range, value: { min: 1, max: 2000 } } }
    call: { server: banking, tool: send_money, arguments: { amount: 2001 } }
    expect: deny
    reason: capability_denied
  - name: a narrower child range
    chain:
      - agent: planner
        capabilities:
          - server: banking
            tool: send_money
            constraints: { amount: { op: range, value: { max: 2000 } } }
      - agent: payer
        capabilities:
          - server: banking
            tool: send_money
            constraints: { amount: { op: range, value: { min: 0, max: 50 } } }
    call: { server: banking, tool: send_money, arguments: { amount: 51 } }
    expect: deny
    reason: capability_denied
"#;

fn permit_all() -> attenuo_policy::PolicyEngine {
    PolicyEngineBuilder::new()
        .with_policies_str(r#"@id("all") permit(principal, action, resource);"#)
        .with_unknown_tools(attenuo_policy::UnknownTools::Allow)
        .build()
        .unwrap()
}

#[test]
fn range_constraints_in_case_files() {
    let file = TestFile::from_yaml_str(CASES).unwrap();
    let report = file.run_with(&permit_all());
    assert!(report.all_passed(), "{report:#?}");
}

#[test]
fn a_widening_child_range_is_a_malformed_case() {
    let yaml = CASES.replace("{ min: 0, max: 50 }", "{ min: 0, max: 5000 }");
    let report = TestFile::from_yaml_str(&yaml)
        .unwrap()
        .run_with(&permit_all());
    let widened = &report.cases[2];
    assert!(!widened.passed);
    assert!(widened.error.is_some(), "{widened:#?}");
}

#[test]
fn a_malformed_range_is_a_file_error() {
    let yaml = CASES.replace("{ min: 1, max: 2000 }", "{ min: 3000, max: 2000 }");
    assert!(TestFile::from_yaml_str(&yaml).is_err());
}
