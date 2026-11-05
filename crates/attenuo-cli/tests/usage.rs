//! Exit status of usage errors: 1, like any other error, so that 2 means only "the answer was
//! no". Help and version still exit 0.

use std::process::Command;

fn attenuo(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_attenuo"))
        .args(args)
        .env_remove("ATTENUO_SERVER")
        .env_remove("ATTENUO_ADMIN_TOKEN")
        .env_remove("ATTENUO_TOKEN")
        .output()
        .unwrap()
}

#[test]
fn an_unknown_flag_exits_1_with_clap_message_on_stderr() {
    let out = attenuo(&["--no-such-flag"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--no-such-flag"), "{stderr}");
    assert!(out.stdout.is_empty(), "{out:?}");
}

#[test]
fn an_unknown_subcommand_or_missing_argument_exits_1() {
    assert_eq!(attenuo(&["no-such-command"]).status.code(), Some(1));
    // `policy test` needs at least a file.
    let out = attenuo(&["policy", "test"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
}

#[test]
fn help_and_version_exit_0_on_stdout() {
    for args in [
        &["--help"][..],
        &["--version"][..],
        &["policy", "--help"][..],
    ] {
        let out = attenuo(args);
        assert_eq!(out.status.code(), Some(0), "{args:?}: {out:?}");
        assert!(!out.stdout.is_empty(), "{args:?}: {out:?}");
    }
}
