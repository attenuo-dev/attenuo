//! `attenuo policy lint` without `--config`: a correct server-scoped policy must not report
//! errors, and the output must say what could not be checked.

use std::process::Command;

const DEMO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../examples/github-leak-demo/policy.cedar"
);

fn lint(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_attenuo"))
        .args(["policy", "lint"])
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn demo_policy_lints_clean_without_a_config() {
    let (code, out) = lint(&[DEMO]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("0 error(s), 0 warning(s)"), "{out}");
    assert!(out.contains("note: no --config"), "{out}");
}

#[test]
fn no_config_still_catches_real_errors() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("p.cedar");
    std::fs::write(
        &p,
        "permit(principal, action == Action::\"read_file\", resource);\n",
    )
    .unwrap();
    let (code, out) = lint(&[p.to_str().unwrap()]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("bare action"), "{out}");
    assert!(out.contains("not declared"), "{out}");
}

#[test]
fn no_config_still_warns_on_an_impossible_policy() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("p.cedar");
    std::fs::write(
        &p,
        "permit(principal, action == Action::\"github/read_file\", resource) when { false };\n",
    )
    .unwrap();
    let (code, out) = lint(&[p.to_str().unwrap()]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("warning[validate]"), "{out}");
}
