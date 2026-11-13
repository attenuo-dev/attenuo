//! `--admin-server` / `ATTENUO_ADMIN_SERVER`: with a server that serves `/admin/*` on its own
//! `[admin] listen` address, the CLI sends admin requests there and everything else to
//! `--server`; without it, admin requests go to `--server` as before.

mod common;

use std::process::{Command, Output};

use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::Config;

use common::attenuo;

const ADMIN: &str = "admin-server-flag-test-token-0123456789";

/// Run the CLI off the async runtime (the server runs on it).
async fn run(mut cmd: Command) -> Output {
    tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_string()
}

/// A free loopback address for `[admin] listen` (the tests serve the admin router themselves).
fn free_port() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// A server with `[admin] listen`: the main listener and the admin listener, and their URLs.
/// The main listener answers `/admin/*` with 404; the admin one has nothing but `/admin/*`.
struct Split {
    _main: Spawned,
    _admin: Spawned,
    main: String,
    admin: String,
    _dir: tempfile::TempDir,
}

async fn split() -> Split {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.audit.sqlite_path = dir
        .path()
        .join("audit.sqlite")
        .to_string_lossy()
        .into_owned();
    cfg.admin.token = Some(ADMIN.into());
    cfg.admin.listen = Some(free_port());
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let main = spawn_router(router).await.unwrap();
    let admin = spawn_router(attenuo_server::admin_router(state))
        .await
        .unwrap();
    Split {
        main: main.url("").trim_end_matches('/').to_string(),
        admin: admin.url("").trim_end_matches('/').to_string(),
        _main: main,
        _admin: admin,
        _dir: dir,
    }
}

/// `attenuo audit verify` (an admin command) with the admin token in the environment.
fn verify(global: &[&str]) -> Command {
    let mut c = attenuo();
    c.env("ATTENUO_ADMIN_TOKEN", ADMIN)
        .args(global)
        .args(["--json", "audit", "verify"]);
    c
}

#[tokio::test]
async fn admin_commands_go_to_the_admin_server_when_it_is_set() {
    let s = split().await;

    // Flag before the subcommand, flag after it, and the environment variable.
    let mut after = attenuo();
    after.env("ATTENUO_ADMIN_TOKEN", ADMIN).args([
        "--server",
        &s.main,
        "audit",
        "verify",
        "--admin-server",
        &s.admin,
    ]);
    let mut env = verify(&["--server", &s.main]);
    env.env("ATTENUO_ADMIN_SERVER", &s.admin);
    for cmd in [
        verify(&["--server", &s.main, "--admin-server", &s.admin]),
        after,
        env,
    ] {
        let out = run(cmd).await;
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        assert!(!text(&out.stdout).contains("404"), "{}", text(&out.stdout));
    }

    // A trailing slash is fine; something that is not a URL is refused before any request.
    let out = run(verify(&[
        "--server",
        &s.main,
        "--admin-server",
        &format!("{}/", s.admin),
    ]))
    .await;
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let out = run(verify(&["--server", &s.main, "--admin-server", "admin"])).await;
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(
        text(&out.stderr).contains("--admin-server must be"),
        "{}",
        text(&out.stderr)
    );
}

#[tokio::test]
async fn admin_commands_fall_back_to_server_without_it() {
    let s = split().await;

    // Unset: `/admin/*` goes to `--server`, so the admin listener's URL there works ...
    let out = run(verify(&["--server", &s.admin])).await;
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    // An empty `ATTENUO_ADMIN_SERVER` counts as unset.
    let mut empty = verify(&["--server", &s.admin]);
    empty.env("ATTENUO_ADMIN_SERVER", "");
    let out = run(empty).await;
    assert_eq!(out.status.code(), Some(0), "{out:?}");

    // ... and the main listener's does not (it answers `/admin/*` as an unknown path).
    let out = run(verify(&["--server", &s.main])).await;
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(text(&out.stderr).contains("404"), "{}", text(&out.stderr));
}

#[tokio::test]
async fn other_commands_ignore_the_admin_server() {
    let s = split().await;

    // `health` reads `/healthz`, which only the main listener has.
    for admin in [s.admin.as_str(), "http://127.0.0.1:1"] {
        let mut c = attenuo();
        c.args(["--server", &s.main, "--admin-server", admin, "health"]);
        let out = run(c).await;
        assert_eq!(out.status.code(), Some(0), "{out:?}");

        let mut c = attenuo();
        c.env("ATTENUO_ADMIN_SERVER", admin)
            .args(["--server", &s.main, "health", "--ready"]);
        let out = run(c).await;
        assert_eq!(out.status.code(), Some(0), "{out:?}");
    }

    // Sent to the admin listener, the same probe fails: it is not the main listener.
    let mut c = attenuo();
    c.args(["--server", &s.admin, "health"]);
    let out = run(c).await;
    assert_eq!(out.status.code(), Some(1), "{out:?}");
}
