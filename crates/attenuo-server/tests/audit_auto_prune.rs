//! The automatic prune of the audit log (`[audit.retention] prune = "auto"`, ADR-0015 phase
//! 2) through a real server: it prunes what is older than `keep_seconds` and nothing newer,
//! nothing while `[audit.sink]` is behind and again once it recovers, never alongside a manual
//! prune, nothing when the prefix does not verify, keeps going after a failed run, runs on its
//! timer, stops at shutdown, and refuses to start with settings that cannot work. With
//! `archive_dir`, each prune first writes and verifies the archive file and signs its digest,
//! fails closed when it cannot, and recovers from a crash between the archive and the prune.

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use attenuo_audit::{AnchorState, AuditSink, PRUNE_TOOL};
use attenuo_core::{Decision, DecisionRecord, RecordKind, ToolCall};
use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::auto_prune::{
    archive_file_name, auto_prune_prepare, hold_auto_prune_runs, AUTO_PRUNE_SUBJECT,
    OUTCOME_FAILED, OUTCOME_PRUNED, OUTCOME_SKIPPED,
};
use attenuo_server::config::{PruneMode, SinkKind, SinkSection};
use attenuo_server::{auto_prune_once, AppState, Config};
use axum::http::StatusCode;
use serde_json::{json, Value};
use time::{Duration, OffsetDateTime};

use common::{wait_for, Running};

const ADMIN: &str = "admin";
/// 90 days, the `min_age_seconds` default: records written 200 days ago are older.
const KEEP: u64 = 7_776_000;

/// Change the first byte of the entry hash of seq 5 to another value. (Writing a fixed `ff`
/// left the hash as it was when it began with `ff`, one run in 256.)
const TAMPER_SEQ_5: &str =
    "UPDATE audit SET entry_hash = CASE WHEN substr(entry_hash, 1, 2) = 'ff' \
     THEN '00' ELSE 'ff' END || substr(entry_hash, 3) WHERE seq = 5";

/// A file-backed config with a checkpoint every 10 entries, a file sink and `prune = "auto"`
/// keeping 90 days, with an interval long enough that the timer never fires in a test that
/// calls [`auto_prune_once`] itself.
fn config(dir: &tempfile::TempDir) -> Config {
    let mut cfg = Config::default();
    cfg.audit.sqlite_path = dir
        .path()
        .join("audit.sqlite")
        .to_string_lossy()
        .into_owned();
    cfg.audit.checkpoint_every = 10;
    // No checkpoint timer: the checkpoints are the count's, so the boundaries are known.
    cfg.audit.checkpoint_interval_seconds = 0;
    let mut sink = SinkSection::new(SinkKind::File);
    sink.path = Some(dir.path().join("shipped.jsonl"));
    sink.initial_backoff_ms = 5;
    sink.max_backoff_seconds = 1;
    cfg.audit.sink = Some(sink);
    cfg.audit.retention.prune = PruneMode::Auto;
    cfg.audit.retention.keep_seconds = Some(KEEP);
    cfg.audit.retention.interval_seconds = Some(86_400);
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    cfg.issuer.private_key_pem_path = Some(dir.path().join("issuer.pem"));
    cfg
}

/// An admin-like record of no chain, written at `at`.
fn record(i: usize, at: OffsetDateTime) -> DecisionRecord {
    let call = ToolCall::new("attenuo", "admin.test", json!({ "i": i }));
    DecisionRecord {
        id: uuid::Uuid::new_v4(),
        at,
        kind: RecordKind::Admin,
        chain_id: None,
        decision: Decision::Allow,
        reason: "admin_action".into(),
        originating_subject: "urn:attenuo:admin".into(),
        agents: Vec::new(),
        chain_depth: 0,
        chain_digest: attenuo_core::digest::sha256_json(&Value::Null),
        leases: Vec::new(),
        server: "attenuo".into(),
        tool: call.tool.clone(),
        arguments_digest: call.arguments_digest(),
        session_id: None,
        policy_ids: Vec::new(),
        dpop_bound: false,
        decision_id: None,
        result: None,
        labels: None,
        approval: None,
        budget: None,
        usage: None,
        search: None,
        id_jag_ceiling: None,
    }
}

fn old() -> OffsetDateTime {
    OffsetDateTime::now_utc() - Duration::days(200)
}

/// Well inside the keep window, but older than nothing the test cares about.
fn recent() -> OffsetDateTime {
    OffsetDateTime::now_utc() - Duration::days(10)
}

struct Harness {
    server: Spawned,
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

async fn start(dir: tempfile::TempDir, cfg: Config) -> Harness {
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    Harness {
        server: spawn_router(router).await.unwrap(),
        state,
        _dir: dir,
    }
}

/// Append `n` records written at `at`, then wait until the sink delivered the checkpoint
/// of the newest multiple of 10. Records older than the keep window are followed by one
/// [`recent`] record: the automatic prune measures the window back from the newest entry, so
/// a log whose newest entry is old has nothing old enough.
async fn fill(state: &AppState, n: usize, at: OffsetDateTime) {
    for i in 0..n {
        state.audit.append(record(i, at)).unwrap();
    }
    if at < OffsetDateTime::now_utc() - Duration::seconds(KEEP as i64) {
        state.audit.append(record(n, recent())).unwrap();
    }
    let head = state.audit.head().unwrap().map_or(0, |e| e.seq);
    let last = (head / 10) * 10;
    let sink = state.checkpoint_sink.as_ref().unwrap();
    wait_for(|| sink.delivered_through() >= Some(last)).await;
}

impl Harness {
    async fn get(&self, path: &str) -> (StatusCode, Value) {
        let r = reqwest::Client::new()
            .get(self.server.url(path))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap();
        (r.status(), r.json().await.unwrap_or(Value::Null))
    }

    async fn prune(&self, through: u64) -> (StatusCode, Value) {
        let r = reqwest::Client::new()
            .post(self.server.url("/admin/audit/prune"))
            .bearer_auth(ADMIN)
            .json(&json!({ "through": through, "archive_sha256": "ab".repeat(32) }))
            .send()
            .await
            .unwrap();
        (r.status(), r.json().await.unwrap_or(Value::Null))
    }

    fn verify_ok(&self) {
        let r = self
            .state
            .audit
            .verify_chain_signed(&self.state.keys().checkpoint_keys)
            .unwrap();
        assert!(r.ok, "{r:?}");
    }
}

/// The run prunes through the newest checkpoint whose entry is older than `keep_seconds`,
/// and keeps everything newer; its record is a prune record by the server, not by an
/// operator, with no archive digest; the plan, the metrics and the next runs say what
/// happened.
#[tokio::test]
async fn it_prunes_what_is_older_than_the_keep_window_and_nothing_newer() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&dir);
    let h = start(dir, cfg).await;
    fill(&h.state, 25, old()).await;
    fill(&h.state, 10, recent()).await;
    let (_, plan) = h.get("/admin/audit/prune/plan").await;
    assert_eq!(
        plan["auto"],
        json!({
            "keep_seconds": KEEP,
            "interval_seconds": 86400,
            "max_entries_per_run": 1_000_000,
            "archive_dir": null,
            "last_run": null
        }),
        "{plan}"
    );

    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.reason, run.through),
        (OUTCOME_PRUNED, "ok", Some(20)),
        "{run:?}"
    );
    // The checkpoint at 30 names a recent entry: kept. So is everything from 21 on.
    let a = h.state.audit.newest_anchor().unwrap().unwrap();
    assert_eq!(a.anchor.through_seq, 20);
    assert_eq!(a.anchor.archive_sha256, None);
    assert_eq!(Some(a.anchor.prune_seq), run.prune_seq);
    let p = h.state.audit.entry_at(a.anchor.prune_seq).unwrap().unwrap();
    assert_eq!(p.record.tool, PRUNE_TOOL);
    assert_eq!(p.record.originating_subject, AUTO_PRUNE_SUBJECT);
    assert_eq!(p.record.reason, "admin_action");
    assert!(a.anchor.check_prune_record(&p).is_ok());
    assert_eq!(h.state.audit.first_retained_seq().unwrap(), 21);
    assert_eq!(h.state.audit.len().unwrap(), 16 + 1);
    h.verify_ok();

    // The plan reports the run; the metrics count it.
    let (_, plan) = h.get("/admin/audit/prune/plan").await;
    assert_eq!(plan["auto"]["last_run"]["outcome"], "pruned", "{plan}");
    assert_eq!(plan["auto"]["last_run"]["through"], 20, "{plan}");
    assert_eq!(plan["auto"]["last_run"]["archive"], Value::Null, "{plan}");
    let text = h.state.metrics.render();
    assert!(
        text.contains("attenuo_audit_auto_prune_runs_total{outcome=\"pruned\",reason=\"ok\"} 1\n"),
        "{text}"
    );
    assert!(!text.contains("attenuo_audit_prune_last_timestamp_seconds 0\n"));
    assert!(!text.contains("attenuo_audit_auto_prune_last_run_timestamp_seconds 0\n"));

    // While the rows are deleted, the next run is skipped; once they are, nothing older than
    // the window is left at a checkpoint.
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.reason),
        (OUTCOME_SKIPPED, "prune_in_progress")
    );
    assert_eq!(attenuo_server::prune_audit_log(&h.state).await, 20);
    assert_eq!(a.state, AnchorState::Deleting);
    let sink = h.state.checkpoint_sink.as_ref().unwrap();
    let s = h.state.clone();
    wait_for(move || {
        s.audit
            .newest_anchor()
            .ok()
            .flatten()
            .is_some_and(|a| a.shipped_at.is_some())
    })
    .await;
    wait_for(|| sink.delivered_through() >= Some(a.anchor.prune_seq)).await;
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.reason),
        (OUTCOME_SKIPPED, "prune_too_recent"),
        "{run:?}"
    );
    assert_eq!(h.state.audit.pruned_through().unwrap(), Some(20));
    h.verify_ok();
    let text = h.state.metrics.render();
    assert!(
        text.contains(
            "attenuo_audit_auto_prune_runs_total{outcome=\"skipped\",reason=\"prune_too_recent\"} 1\n"
        ),
        "{text}"
    );
}

/// A webhook receiver that fails while `fail` is set.
async fn hook(fail: Arc<AtomicBool>) -> Spawned {
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move || {
            let fail = fail.clone();
            async move {
                if fail.load(Ordering::SeqCst) {
                    StatusCode::INTERNAL_SERVER_ERROR
                } else {
                    StatusCode::OK
                }
            }
        }),
    );
    spawn_router(app).await.unwrap()
}

/// While the sink fails, nothing is pruned, however old: each run is skipped with
/// `sink_behind`. Once the receiver accepts again and the sink has delivered a checkpoint at
/// or past the boundary, the next run prunes. While the new anchor is not delivered, no
/// further prune is made either.
#[tokio::test]
async fn nothing_is_pruned_while_the_sink_is_behind_then_it_prunes_after_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let fail = Arc::new(AtomicBool::new(true));
    let receiver = hook(fail.clone()).await;
    let mut cfg = config(&dir);
    let mut sink = SinkSection::new(SinkKind::Webhook);
    sink.url = Some(receiver.url("/hook"));
    sink.initial_backoff_ms = 5;
    sink.max_backoff_seconds = 1;
    sink.timeout_seconds = 2;
    cfg.audit.sink = Some(sink);
    let h = start(dir, cfg).await;
    for i in 0..45 {
        h.state.audit.append(record(i, old())).unwrap();
    }
    h.state.audit.append(record(45, recent())).unwrap();
    let sink = h.state.checkpoint_sink.as_ref().unwrap();
    // The receiver has been asked and refused.
    wait_for(|| sink.status().last_error.is_some()).await;
    for _ in 0..3 {
        let run = auto_prune_once(&h.state).await;
        assert_eq!(
            (run.outcome, run.reason),
            (OUTCOME_SKIPPED, "sink_behind"),
            "{run:?}"
        );
    }
    assert_eq!(h.state.audit.pruned_through().unwrap(), None);
    assert_eq!(h.state.audit.len().unwrap(), 46);
    let text = h.state.metrics.render();
    assert!(
        text.contains(
            "attenuo_audit_auto_prune_runs_total{outcome=\"skipped\",reason=\"sink_behind\"} 3\n"
        ),
        "{text}"
    );

    // The receiver recovers: the queue drains, and the next run prunes through 40.
    fail.store(false, Ordering::SeqCst);
    wait_for(|| sink.delivered_through() >= Some(40)).await;
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.through),
        (OUTCOME_PRUNED, Some(40)),
        "{run:?}"
    );
    attenuo_server::prune_audit_log(&h.state).await;
    h.verify_ok();
}

/// A manual prune and the automatic one at the same moment: exactly one of them commits, the
/// other is refused or skipped, and the log verifies. Several rounds, since the race can go
/// either way. Two automatic runs at once: one prunes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_manual_prune_and_the_automatic_one_never_both_commit() {
    let (mut manual_won, mut auto_won) = (0, 0);
    for _ in 0..6 {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(&dir);
        let h = start(dir, cfg).await;
        fill(&h.state, 205, old()).await;
        let (manual, auto) = tokio::join!(h.prune(200), auto_prune_once(&h.state));
        let anchors = h.state.audit.anchors_before(u64::MAX, 10).unwrap();
        assert_eq!(anchors.len(), 1, "one prune, not two: {anchors:?}");
        match (manual.0, auto.outcome) {
            (StatusCode::OK, OUTCOME_SKIPPED) => {
                manual_won += 1;
                assert!(anchors[0].anchor.archive_sha256.is_some());
            }
            (s, OUTCOME_PRUNED) if s.is_client_error() => {
                auto_won += 1;
                assert_eq!(anchors[0].anchor.archive_sha256, None);
            }
            other => panic!("both or neither committed: {other:?} {manual:?} {auto:?}"),
        }
        h.verify_ok();
    }
    assert_eq!(manual_won + auto_won, 6);

    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&dir);
    let h = start(dir, cfg).await;
    fill(&h.state, 205, old()).await;
    let (a, b) = tokio::join!(auto_prune_once(&h.state), auto_prune_once(&h.state));
    let pruned = [a.outcome, b.outcome]
        .iter()
        .filter(|o| **o == OUTCOME_PRUNED)
        .count();
    assert_eq!(pruned, 1, "{a:?} {b:?}");
    assert_eq!(h.state.audit.anchors_before(u64::MAX, 10).unwrap().len(), 1);
    h.verify_ok();
}

/// A prefix that does not verify (an entry rewritten in the file) is not pruned: the run
/// fails with `verify_failed`, and the next one fails too until the log is whole. A prune
/// whose transaction fails is a failed run (`error`) that changes nothing; the run after it
/// prunes.
#[tokio::test]
async fn a_prefix_that_does_not_verify_is_kept_and_a_failed_run_is_retried() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&dir);
    let h = start(dir, cfg).await;
    fill(&h.state, 25, old()).await;
    let hash: String = h
        .state
        .audit
        .with_connection(|c| {
            let h: String = c.query_row("SELECT entry_hash FROM audit WHERE seq = 5", [], |r| {
                r.get(0)
            })?;
            c.execute(TAMPER_SEQ_5, [])?;
            Ok(h)
        })
        .unwrap();
    for _ in 0..2 {
        let run = auto_prune_once(&h.state).await;
        assert_eq!(
            (run.outcome, run.reason, run.through),
            (OUTCOME_FAILED, "verify_failed", Some(20)),
            "{run:?}"
        );
        assert!(run.detail.unwrap().contains("first_bad_seq Some(5)"));
    }
    assert_eq!(h.state.audit.pruned_through().unwrap(), None);
    assert_eq!(h.state.audit.len().unwrap(), 26);
    let (_, plan) = h.get("/admin/audit/prune/plan").await;
    assert_eq!(
        plan["auto"]["last_run"]["reason"], "verify_failed",
        "{plan}"
    );

    // Whole again; then the prune's own transaction fails once.
    h.state
        .audit
        .with_connection(|c| {
            c.execute("UPDATE audit SET entry_hash = ?1 WHERE seq = 5", [&hash])?;
            Ok(())
        })
        .unwrap();
    h.state.audit.fail_prune_at_step(3);
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.reason),
        (OUTCOME_FAILED, "error"),
        "{run:?}"
    );
    assert_eq!(h.state.audit.pruned_through().unwrap(), None);
    assert_eq!(h.state.audit.len().unwrap(), 26);
    h.state.audit.fail_prune_at_step(0);
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.through),
        (OUTCOME_PRUNED, Some(20)),
        "{run:?}"
    );
    let text = h.state.metrics.render();
    for line in [
        "attenuo_audit_auto_prune_runs_total{outcome=\"failed\",reason=\"verify_failed\"} 2\n",
        "attenuo_audit_auto_prune_runs_total{outcome=\"failed\",reason=\"error\"} 1\n",
        "attenuo_audit_auto_prune_runs_total{outcome=\"pruned\",reason=\"ok\"} 1\n",
    ] {
        assert!(text.contains(line), "{line}{text}");
    }
    h.verify_ok();
}

/// A server run as `serve` runs one, with a one-second interval: the timer prunes on its
/// own, a failing run does not stop it (it fails on every tick and the server still
/// answers), `/readyz` does not look at it, and the server stops promptly with the timer
/// stopped.
#[tokio::test]
async fn the_timer_prunes_keeps_going_after_failures_and_stops_at_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir);
    cfg.audit.retention.interval_seconds = Some(1);
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    fill(&state, 25, old()).await;
    // A broken prefix first, before the timer starts: each tick fails.
    let hash: String = state
        .audit
        .with_connection(|c| {
            let h: String = c.query_row("SELECT entry_hash FROM audit WHERE seq = 5", [], |r| {
                r.get(0)
            })?;
            c.execute(TAMPER_SEQ_5, [])?;
            Ok(h)
        })
        .unwrap();
    let running = Running::start(cfg.clone(), state.clone(), router).await;
    let failed = |s: &AppState| {
        s.metrics.render().lines().any(|l| {
            l.starts_with(
                "attenuo_audit_auto_prune_runs_total{outcome=\"failed\",reason=\"verify_failed\"} ",
            ) && l.rsplit(' ').next().and_then(|n| n.parse::<u64>().ok()) >= Some(2)
        })
    };
    let s = state.clone();
    wait_for(move || failed(&s)).await;
    let r = reqwest::get(running.url("/readyz")).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(state.audit.pruned_through().unwrap(), None);
    // Mended: the next tick prunes.
    state
        .audit
        .with_connection(|c| {
            c.execute("UPDATE audit SET entry_hash = ?1 WHERE seq = 5", [&hash])?;
            Ok(())
        })
        .unwrap();
    // Wait on the run's own record, which is set after its commit, not on the log.
    let s = state.clone();
    wait_for(move || {
        s.auto_prune
            .last()
            .is_some_and(|r| r.outcome == OUTCOME_PRUNED)
    })
    .await;
    let last = state.auto_prune.last().unwrap();
    assert_eq!(last.through, Some(20), "{last:?}");
    assert_eq!(state.audit.pruned_through().unwrap(), Some(20));

    // Shutdown: `run` returns promptly and the state is released, so no tick runs after.
    tokio::time::timeout(StdDuration::from_secs(20), running.stop(state))
        .await
        .expect("the server stops with the automatic prune on");
}

/// Settings that cannot work refuse to start, each naming what is wrong.
#[test]
fn start_up_refuses_auto_settings_that_cannot_work() {
    let dir = tempfile::tempdir().unwrap();
    let refuse = |cfg: Config, needle: &str| {
        let e = attenuo_server::build(&cfg).err().expect("must refuse");
        let text = format!("{e:#}");
        assert!(text.contains(needle), "{needle}: {text}");
    };
    let mut cfg = config(&dir);
    cfg.audit.sink = None;
    refuse(cfg, "needs [audit.sink]");
    let mut cfg = config(&dir);
    cfg.audit.retention.keep_seconds = None;
    refuse(cfg, "needs keep_seconds");
    let mut cfg = config(&dir);
    cfg.audit.retention.keep_seconds = Some(KEEP - 1);
    refuse(cfg, "at least min_age_seconds");
    let mut cfg = config(&dir);
    cfg.audit.retention.interval_seconds = Some(0);
    refuse(cfg, "interval_seconds must be between 1 and 86400");
    let mut cfg = config(&dir);
    cfg.audit.sqlite_path = ":memory:".into();
    refuse(cfg, ":memory:");
    for mode in [PruneMode::Manual, PruneMode::Off] {
        let mut cfg = config(&dir);
        cfg.audit.retention.prune = mode;
        refuse(cfg, "keep_seconds is only for prune = \"auto\"");
    }
    let mut cfg = config(&dir);
    cfg.audit.retention.prune = PruneMode::Manual;
    cfg.audit.retention.keep_seconds = None;
    refuse(cfg, "interval_seconds is only for prune = \"auto\"");
    let mut cfg = config(&dir);
    cfg.audit.retention.archive_dir = Some(dir.path().join("missing"));
    refuse(cfg, "archive_dir");
    let mut cfg = config(&dir);
    let file = dir.path().join("a-file");
    std::fs::write(&file, "x").unwrap();
    cfg.audit.retention.archive_dir = Some(file);
    refuse(cfg, "is not a directory");
    let mut cfg = config(&dir);
    cfg.audit.retention.max_entries_per_run = Some(0);
    refuse(cfg, "max_entries_per_run must be at least 1");
    let mut cfg = config(&dir);
    cfg.audit.retention.prune = PruneMode::Manual;
    cfg.audit.retention.keep_seconds = None;
    cfg.audit.retention.interval_seconds = None;
    cfg.audit.retention.archive_dir = Some(dir.path().to_path_buf());
    refuse(cfg, "archive_dir is only for prune = \"auto\"");
    // "auto" allows the admin's prunes too.
    let cfg = config(&dir);
    let (_router, state) = attenuo_server::build(&cfg).unwrap();
    assert!(state.retention.allows_prune());
}

/// `prune = "auto"` allows the manual route, with `min_age_seconds` as its floor: an admin
/// prune works as with `"manual"`.
#[tokio::test]
async fn auto_also_allows_the_manual_route() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&dir);
    let h = start(dir, cfg).await;
    fill(&h.state, 25, old()).await;
    let (status, body) = h.prune(20).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let a = h.state.audit.newest_anchor().unwrap().unwrap();
    let p = h.state.audit.entry_at(a.anchor.prune_seq).unwrap().unwrap();
    assert_eq!(p.record.originating_subject, "urn:attenuo:admin");
    let text = h.state.metrics.render();
    assert!(!text.contains("attenuo_audit_prune_last_timestamp_seconds 0\n"));
}

/// [`config`] with `archive_dir` set to a new directory `archive` in `dir`.
fn with_archive(dir: &tempfile::TempDir) -> (Config, PathBuf) {
    let mut cfg = config(dir);
    let archive = dir.path().join("archive");
    std::fs::create_dir(&archive).unwrap();
    cfg.audit.retention.archive_dir = Some(archive.clone());
    (cfg, archive)
}

/// The names in `dir`, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

fn sha256_hex(path: &Path) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(std::fs::read(path).unwrap()))
}

/// Finish the deletes of the last prune and wait until its anchor and the head are
/// delivered, so the next run is not skipped with `prune_in_progress` or `sink_behind`.
async fn settle(state: &Arc<AppState>) {
    attenuo_server::prune_audit_log(state).await;
    let s = state.clone();
    wait_for(move || {
        s.audit
            .newest_anchor()
            .ok()
            .flatten()
            .is_some_and(|a| a.shipped_at.is_some())
    })
    .await;
    let head = state.audit.head().unwrap().unwrap().seq;
    let sink = state.checkpoint_sink.as_ref().unwrap();
    wait_for(|| sink.delivered_through() >= Some(head)).await;
}

/// With `archive_dir`, each of two prunes in a row writes the entries it removes as an export
/// file named by its range, mode 0600, that verifies on its own (the first from genesis, the
/// second from the first prune's anchor), and signs the file's SHA-256 into its anchor. The
/// plan names the directory and the file of the last run.
#[tokio::test]
async fn with_archive_dir_each_prune_keeps_a_verified_copy_and_signs_its_digest() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, archive) = with_archive(&dir);
    let h = start(dir, cfg).await;
    let keys = h.state.keys().checkpoint_keys.clone();
    fill(&h.state, 25, old()).await;

    let run = auto_prune_once(&h.state).await;
    let first = archive_file_name(1, 20);
    assert_eq!(
        first,
        "audit-00000000000000000001-00000000000000000020.jsonl"
    );
    assert_eq!(
        (run.outcome, run.through, run.archive.as_deref()),
        (OUTCOME_PRUNED, Some(20), Some(first.as_str())),
        "{run:?}"
    );
    assert_eq!(names(&archive), vec![first.clone()]);
    let a1 = h.state.audit.newest_anchor().unwrap().unwrap().anchor;
    assert_eq!(
        a1.archive_sha256.as_deref(),
        Some(sha256_hex(&archive.join(&first)).as_str())
    );
    let got = attenuo_audit::verify_export_file(&archive.join(&first), &keys, Default::default())
        .unwrap();
    assert!(got.report.report.ok && got.report.from_genesis, "{got:?}");
    assert_eq!((got.header.from, got.header.to, got.entries), (1, 20, 20));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(archive.join(&first))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let (_, plan) = h.get("/admin/audit/prune/plan").await;
    assert_eq!(
        plan["auto"]["archive_dir"],
        archive.display().to_string(),
        "{plan}"
    );
    assert_eq!(
        plan["auto"]["last_run"]["archive"],
        first.as_str(),
        "{plan}"
    );

    // The second prune: its archive starts after the first one's anchor.
    settle(&h.state).await;
    fill(&h.state, 20, old()).await;
    let run = auto_prune_once(&h.state).await;
    let second = archive_file_name(21, 40);
    assert_eq!(
        (run.outcome, run.through, run.archive.as_deref()),
        (OUTCOME_PRUNED, Some(40), Some(second.as_str())),
        "{run:?}"
    );
    assert_eq!(names(&archive), vec![first, second.clone()]);
    let a2 = h.state.audit.newest_anchor().unwrap().unwrap().anchor;
    assert_eq!(
        a2.archive_sha256.as_deref(),
        Some(sha256_hex(&archive.join(&second)).as_str())
    );
    let got = attenuo_audit::verify_export_file(&archive.join(&second), &keys, Default::default())
        .unwrap();
    assert!(got.report.report.ok && got.report.from_anchor, "{got:?}");
    assert_eq!(got.header.anchor, Some(a1));
    h.verify_ok();
}

/// The archive cannot be written (the directory replaced by a file) or a different file
/// already has its name: the run fails with its own reason, nothing is pruned, the other file
/// is left exactly as it was, and no temporary file stays. Once the cause is gone, the next
/// run prunes.
#[tokio::test]
async fn an_archive_that_cannot_be_written_or_differs_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, archive) = with_archive(&dir);
    let h = start(dir, cfg).await;
    fill(&h.state, 25, old()).await;

    std::fs::remove_dir(&archive).unwrap();
    std::fs::write(&archive, "not a directory").unwrap();
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.reason, run.through),
        (OUTCOME_FAILED, "archive_write_failed", Some(20)),
        "{run:?}"
    );
    assert_eq!(h.state.audit.pruned_through().unwrap(), None);
    assert_eq!(h.state.audit.len().unwrap(), 26);

    std::fs::remove_file(&archive).unwrap();
    std::fs::create_dir(&archive).unwrap();
    let name = archive_file_name(1, 20);
    std::fs::write(archive.join(&name), "someone else's file\n").unwrap();
    for _ in 0..2 {
        let run = auto_prune_once(&h.state).await;
        assert_eq!(
            (run.outcome, run.reason, run.archive.as_deref()),
            (OUTCOME_FAILED, "archive_exists", Some(name.as_str())),
            "{run:?}"
        );
        assert!(run.detail.unwrap().contains("never replaced"));
    }
    assert_eq!(
        std::fs::read_to_string(archive.join(&name)).unwrap(),
        "someone else's file\n"
    );
    assert_eq!(
        names(&archive),
        vec![name.clone()],
        "no temporary file left"
    );
    assert_eq!(h.state.audit.pruned_through().unwrap(), None);
    assert_eq!(h.state.audit.len().unwrap(), 26);
    let text = h.state.metrics.render();
    for line in [
        "attenuo_audit_auto_prune_runs_total{outcome=\"failed\",reason=\"archive_write_failed\"} 1\n",
        "attenuo_audit_auto_prune_runs_total{outcome=\"failed\",reason=\"archive_exists\"} 2\n",
    ] {
        assert!(text.contains(line), "{line}{text}");
    }

    std::fs::remove_file(archive.join(&name)).unwrap();
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.through),
        (OUTCOME_PRUNED, Some(20)),
        "{run:?}"
    );
    let a = h.state.audit.newest_anchor().unwrap().unwrap().anchor;
    assert_eq!(
        a.archive_sha256.as_deref(),
        Some(sha256_hex(&archive.join(&name)).as_str())
    );
    h.verify_ok();
}

/// A crash after the archive file is in place and before the prune commits: after a restart
/// (with more old entries, so the plan alone would go further), the next run removes the
/// stale temporary file, plans to the boundary of the file it finds, uses that file as it is
/// (the same bytes), and signs its digest. One archive file, and the log verifies.
#[tokio::test]
async fn a_crash_between_the_archive_and_the_prune_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, archive) = with_archive(&dir);
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    fill(&state, 25, old()).await;
    let prepared = auto_prune_prepare(&state).await.expect("prepared");
    let written = prepared.archive.clone().expect("an archive");
    assert_eq!((prepared.from, prepared.through), (1, 20));
    assert!(!written.reused);
    assert_eq!(written.name, archive_file_name(1, 20));
    assert_eq!(
        state.audit.pruned_through().unwrap(),
        None,
        "nothing committed"
    );
    // What a crash in the middle of a later write would leave.
    let stale = archive.join(format!(".{}.4242.tmp", archive_file_name(1, 30)));
    std::fs::write(&stale, "half a file").unwrap();

    drop(server);
    let released = state.released();
    drop(state);
    tokio::time::timeout(StdDuration::from_secs(10), released)
        .await
        .expect("the first server let go of its state");

    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let _server = spawn_router(router).await.unwrap();
    fill(&state, 20, old()).await;
    let run = auto_prune_once(&state).await;
    assert_eq!(
        (run.outcome, run.through, run.archive.as_deref()),
        (OUTCOME_PRUNED, Some(20), Some(written.name.as_str())),
        "{run:?}"
    );
    assert_eq!(names(&archive), vec![written.name.clone()]);
    let a = state.audit.newest_anchor().unwrap().unwrap().anchor;
    assert_eq!(a.archive_sha256.as_deref(), Some(written.sha256.as_str()));
    assert_eq!(sha256_hex(&written.path), written.sha256);
    let r = state
        .audit
        .verify_chain_signed(&state.keys().checkpoint_keys)
        .unwrap();
    assert!(r.ok, "{r:?}");
}

/// `max_entries_per_run` splits a long prefix into several prunes, each at a checkpoint
/// inside the limit. When no checkpoint falls inside the limit, the run prunes to the
/// smallest allowed checkpoint above it, not to the plan's boundary.
#[tokio::test]
async fn max_entries_per_run_splits_a_long_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir);
    cfg.audit.retention.max_entries_per_run = Some(15);
    let h = start(dir, cfg).await;
    fill(&h.state, 45, old()).await;
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.through),
        (OUTCOME_PRUNED, Some(10)),
        "{run:?}"
    );
    settle(&h.state).await;
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.through),
        (OUTCOME_PRUNED, Some(20)),
        "{run:?}"
    );
    h.verify_ok();

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir);
    cfg.audit.retention.max_entries_per_run = Some(5);
    let h = start(dir, cfg).await;
    fill(&h.state, 25, old()).await;
    // No checkpoint in 1..=5: the smallest allowed one above the limit, not the whole plan.
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.through),
        (OUTCOME_PRUNED, Some(10)),
        "{run:?}"
    );
    settle(&h.state).await;
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.through),
        (OUTCOME_PRUNED, Some(20)),
        "{run:?}"
    );
    h.verify_ok();
}

/// A clock the test moves: [`Stepped::step`] steps the wall clock alone, either way (a clock
/// jump), and [`Stepped::pass`] moves both clocks ahead (time that really passed). Both run on
/// in real time besides.
#[derive(Debug, Default)]
struct Stepped {
    wall: std::sync::atomic::AtomicI64,
    mono: std::sync::atomic::AtomicU64,
}

impl Stepped {
    fn step(&self, by: Duration) {
        self.wall.fetch_add(by.whole_seconds(), Ordering::SeqCst);
    }

    fn pass(&self, by: Duration) {
        self.step(by);
        self.mono
            .fetch_add(by.whole_seconds().unsigned_abs(), Ordering::SeqCst);
    }
}

impl attenuo_core::Clock for Stepped {
    fn now_utc(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc() + Duration::seconds(self.wall.load(Ordering::SeqCst))
    }
    fn now(&self) -> std::time::Instant {
        std::time::Instant::now() + StdDuration::from_secs(self.mono.load(Ordering::SeqCst))
    }
}

/// Append one record stamped with the server's clock now (traffic).
fn touch(state: &AppState) {
    state.audit.append(record(0, state.now())).unwrap();
}

async fn start_with_clock(dir: tempfile::TempDir, cfg: Config, clock: Arc<Stepped>) -> Harness {
    let (router, state) = attenuo_server::build_with_clock(&cfg, clock).unwrap();
    Harness {
        server: spawn_router(router).await.unwrap(),
        state,
        _dir: dir,
    }
}

/// The count of `audit_auto_prune_runs_total{outcome, reason}` in `text`.
fn runs(text: &str, outcome: &str, reason: &str) -> u64 {
    let key = format!(
        "attenuo_audit_auto_prune_runs_total{{outcome=\"{outcome}\",reason=\"{reason}\"}} "
    );
    text.lines()
        .find_map(|l| l.strip_prefix(&key))
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

/// With the clocks in step, time passing prunes what is older than the window. Then the wall
/// clock jumps 400 days ahead: that run is skipped as `clock_jump` and prunes nothing. The
/// runs after it have the clocks in step again, but with no new entry since the jump the
/// window is measured back from the newest entry, so nothing more is old enough.
#[tokio::test]
async fn a_clock_jump_ahead_is_skipped_and_then_makes_nothing_old_enough() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(Stepped::default());
    let cfg = config(&dir);
    let h = start_with_clock(dir, cfg, clock.clone()).await;
    fill(&h.state, 25, old()).await;
    fill(&h.state, 10, recent()).await;
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.through),
        (OUTCOME_PRUNED, Some(20)),
        "{run:?}"
    );
    settle(&h.state).await;
    let len = h.state.audit.len().unwrap();

    clock.step(Duration::days(400));
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.reason),
        (OUTCOME_SKIPPED, "clock_jump"),
        "{run:?}"
    );
    assert!(
        run.detail
            .as_deref()
            .unwrap_or("")
            .contains("wall clock moved"),
        "{run:?}"
    );
    for _ in 0..3 {
        let run = auto_prune_once(&h.state).await;
        assert_eq!(
            (run.outcome, run.reason),
            (OUTCOME_SKIPPED, "prune_too_recent"),
            "{run:?}"
        );
    }
    assert_eq!(h.state.audit.pruned_through().unwrap(), Some(20));
    assert_eq!(h.state.audit.len().unwrap(), len);
    let text = h.state.metrics.render();
    assert_eq!(runs(&text, "skipped", "clock_jump"), 1, "{text}");
    h.verify_ok();
}

/// A step within the slack is no jump. A step back by more than the slack is: that run is
/// skipped, and the next one, with the clocks in step, prunes as usual.
#[tokio::test]
async fn a_clock_step_back_skips_one_run_and_a_small_step_none() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(Stepped::default());
    let cfg = config(&dir);
    let h = start_with_clock(dir, cfg, clock.clone()).await;
    fill(&h.state, 25, old()).await;
    clock.step(Duration::minutes(30));
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.through),
        (OUTCOME_PRUNED, Some(20)),
        "{run:?}"
    );
    settle(&h.state).await;
    fill(&h.state, 20, old()).await;
    clock.step(-Duration::hours(2));
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.reason),
        (OUTCOME_SKIPPED, "clock_jump"),
        "{run:?}"
    );
    assert_eq!(h.state.audit.pruned_through().unwrap(), Some(20));
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.through),
        (OUTCOME_PRUNED, Some(40)),
        "{run:?}"
    );
    h.verify_ok();
}

/// A run that lasts longer than the interval (it waits for the run lock the test holds), then
/// a stop: once that run ends, no other run starts, although a tick is due.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_during_a_long_run_starts_no_further_run() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir);
    cfg.audit.retention.interval_seconds = Some(1);
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let metrics = state.metrics.clone();
    let held = hold_auto_prune_runs(&state).await;
    let running = Running::start(cfg.clone(), state.clone(), router).await;
    // The first tick (at one second) starts a run that waits; more ticks fall due.
    tokio::time::sleep(StdDuration::from_millis(2500)).await;
    let stopping = tokio::spawn(running.stop(state));
    tokio::time::sleep(StdDuration::from_millis(300)).await;
    drop(held);
    tokio::time::timeout(StdDuration::from_secs(20), stopping)
        .await
        .expect("the server stops")
        .unwrap();
    let text = metrics.render();
    let total: u64 = text
        .lines()
        .filter(|l| l.starts_with("attenuo_audit_auto_prune_runs_total{"))
        .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
        .sum();
    assert_eq!(total, 1, "one run, the one that waited: {text}");
}

/// A manual prune that commits while the automatic run writes its archive: the run is
/// skipped as `concurrent_prune`, not failed, and leaves no file.
#[tokio::test]
async fn a_prune_during_the_archive_write_is_a_concurrent_skip() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, archive) = with_archive(&dir);
    let h = start(dir, cfg).await;
    fill(&h.state, 25, old()).await;
    let audit = h.state.audit.clone();
    h.state.audit.on_next_export_page(move || {
        let limits = attenuo_audit::PruneLimits {
            min_age: Duration::ZERO,
            sink: None,
            now: OffsetDateTime::now_utc(),
        };
        audit
            .prune_through(10, Some("ab".repeat(32)), &limits, |args| {
                let call = ToolCall::new("attenuo", PRUNE_TOOL, args.clone());
                let mut r = record(0, OffsetDateTime::now_utc());
                r.tool = call.tool.clone();
                r.arguments_digest = call.arguments_digest();
                r
            })
            .unwrap();
    });
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.reason, run.through),
        (OUTCOME_SKIPPED, "concurrent_prune", Some(20)),
        "{run:?}"
    );
    assert_eq!(h.state.audit.pruned_through().unwrap(), Some(10));
    assert!(names(&archive).is_empty(), "{:?}", names(&archive));
    h.verify_ok();
}

/// A store error in the prune transaction: the prune may have committed for all the run
/// can tell, so the archive it wrote stays; the next run checks it, uses it as it is, and
/// signs its digest.
#[tokio::test]
async fn an_archive_is_kept_after_a_store_error_and_used_by_the_next_run() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, archive) = with_archive(&dir);
    let h = start(dir, cfg).await;
    fill(&h.state, 25, old()).await;
    h.state.audit.fail_prune_at_step(3);
    let name = archive_file_name(1, 20);
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.reason, run.archive.as_deref()),
        (OUTCOME_FAILED, "error", Some(name.as_str())),
        "{run:?}"
    );
    assert_eq!(names(&archive), vec![name.clone()]);
    let sha = sha256_hex(&archive.join(&name));
    h.state.audit.fail_prune_at_step(0);
    let run = auto_prune_once(&h.state).await;
    assert_eq!(run.outcome, OUTCOME_PRUNED, "{run:?}");
    assert_eq!(names(&archive), vec![name.clone()]);
    let a = h.state.audit.newest_anchor().unwrap().unwrap().anchor;
    assert_eq!(a.archive_sha256.as_deref(), Some(sha.as_str()));
}

/// Files in `archive_dir` from an earlier run or from someone else:
///
/// - a file for a smaller boundary from the same first seq that is not a valid archive sets
///   the boundary and then fails the run (`archive_exists`), left as it is;
/// - a valid archive of another range under the target's name fails the same way, through
///   the archive check;
/// - a file for a boundary past the run's is left alone and the run prunes;
/// - a valid archive written under a cap is used after the cap changed.
#[tokio::test]
async fn files_left_in_archive_dir_are_checked_used_or_left_alone() {
    // A leftover with other bytes, below the boundary.
    let dir = tempfile::tempdir().unwrap();
    let (cfg, archive) = with_archive(&dir);
    let h = start(dir, cfg).await;
    fill(&h.state, 25, old()).await;
    let low = archive.join(archive_file_name(1, 10));
    std::fs::write(&low, "not an archive\n").unwrap();
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.reason, run.through),
        (OUTCOME_FAILED, "archive_exists", Some(10)),
        "{run:?}"
    );
    assert_eq!(std::fs::read_to_string(&low).unwrap(), "not an archive\n");
    assert_eq!(h.state.audit.pruned_through().unwrap(), None);
    std::fs::remove_file(&low).unwrap();

    // A leftover past the boundary: left alone, and the run prunes to its own boundary.
    let high = archive.join(archive_file_name(1, 40));
    std::fs::write(&high, "from another setting\n").unwrap();
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.through),
        (OUTCOME_PRUNED, Some(20)),
        "{run:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&high).unwrap(),
        "from another setting\n"
    );
    assert_eq!(
        names(&archive),
        vec![archive_file_name(1, 20), archive_file_name(1, 40)]
    );

    // A valid archive written under a cap of 15 (through 10), and the cap then lifted: the
    // next run plans to 10 for it and uses it, not a second file.
    let dir = tempfile::tempdir().unwrap();
    let (mut cfg, archive) = with_archive(&dir);
    cfg.audit.retention.max_entries_per_run = Some(15);
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    fill(&state, 45, old()).await;
    let prepared = auto_prune_prepare(&state).await.expect("prepared");
    assert_eq!(prepared.through, 10);
    let written = prepared.archive.unwrap();
    // The same valid archive under the name of another range is refused, after its check.
    let wrong = archive.join(archive_file_name(1, 40));
    std::fs::copy(&written.path, &wrong).unwrap();
    drop(server);
    let released = state.released();
    drop(state);
    tokio::time::timeout(StdDuration::from_secs(10), released)
        .await
        .expect("the first server let go of its state");
    cfg.audit.retention.max_entries_per_run = None;
    std::fs::remove_file(&written.path).unwrap();
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let _server = spawn_router(router).await.unwrap();
    fill(&state, 10, recent()).await;
    let run = auto_prune_once(&state).await;
    assert_eq!(
        (run.outcome, run.reason, run.through),
        (OUTCOME_FAILED, "archive_exists", Some(40)),
        "{run:?}"
    );
    assert!(
        run.detail.as_deref().unwrap_or("").contains("not 1..40"),
        "{run:?}"
    );
    // The copy back under its own name: used as it is.
    std::fs::rename(&wrong, &written.path).unwrap();
    let run = auto_prune_once(&state).await;
    assert_eq!(
        (run.outcome, run.through, run.archive.as_deref()),
        (OUTCOME_PRUNED, Some(10), Some(written.name.as_str())),
        "{run:?}"
    );
    let a = state.audit.newest_anchor().unwrap().unwrap().anchor;
    assert_eq!(a.archive_sha256.as_deref(), Some(written.sha256.as_str()));
    assert_eq!(names(&archive), vec![written.name.clone()]);
}

/// The wall clock jumps 400 days ahead, and then traffic comes, stamped with the jumped
/// clock. The newest entry no longer holds the cutoff back, but the cutoff cannot move faster
/// than the monotonic clock, so the entries written 10 days ago stay through every later run.
#[tokio::test]
async fn after_a_clock_jump_traffic_makes_no_young_entry_old_enough() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(Stepped::default());
    let cfg = config(&dir);
    let h = start_with_clock(dir, cfg, clock.clone()).await;
    fill(&h.state, 25, old()).await;
    let run = auto_prune_once(&h.state).await;
    assert_eq!(run.through, Some(20), "{run:?}");
    settle(&h.state).await;
    fill(&h.state, 10, recent()).await;
    clock.step(Duration::days(400));
    let run = auto_prune_once(&h.state).await;
    assert_eq!(run.reason, "clock_jump", "{run:?}");
    let now = h.state.now();
    fill(&h.state, 10, now).await;
    for _ in 0..3 {
        let run = auto_prune_once(&h.state).await;
        assert_eq!(
            (run.outcome, run.reason),
            (OUTCOME_SKIPPED, "prune_too_recent"),
            "{run:?}"
        );
        touch(&h.state);
    }
    assert_eq!(h.state.audit.pruned_through().unwrap(), Some(20));
    assert_eq!(h.state.audit.first_retained_seq().unwrap(), 21);
    h.verify_ok();
}

/// An idle server whose wall clock jumps 400 days ahead: 25 old entries, then 10 entries 10
/// days old. The prune of the old ones is right. Its own record, stamped with the jumped
/// clock, does not count as the newest entry, so the runs after it keep the 10-day-old
/// entries: on an idle server the last `keep_seconds` before the newest entry stay.
#[tokio::test]
async fn after_a_clock_jump_an_idle_server_keeps_its_young_entries() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(Stepped::default());
    let cfg = config(&dir);
    let h = start_with_clock(dir, cfg, clock.clone()).await;
    fill(&h.state, 25, old()).await;
    fill(&h.state, 10, recent()).await;
    clock.step(Duration::days(400));
    let run = auto_prune_once(&h.state).await;
    assert_eq!(run.reason, "clock_jump", "{run:?}");
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.through),
        (OUTCOME_PRUNED, Some(20)),
        "{run:?}"
    );
    settle(&h.state).await;
    for _ in 0..3 {
        let run = auto_prune_once(&h.state).await;
        assert_eq!(
            (run.outcome, run.reason),
            (OUTCOME_SKIPPED, "prune_too_recent"),
            "{run:?}"
        );
    }
    assert_eq!(h.state.audit.pruned_through().unwrap(), Some(20));
    assert_eq!(h.state.audit.first_retained_seq().unwrap(), 21);
    h.verify_ok();
}

/// Steps of 59 minutes, each under the clock-jump slack, one per run, that add up to more
/// than 80 days, then traffic at the stepped clock: no step is seen as a jump, and still
/// nothing 10 days old is pruned.
#[tokio::test]
async fn small_clock_steps_that_add_up_prune_nothing_young() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(Stepped::default());
    let cfg = config(&dir);
    let h = start_with_clock(dir, cfg, clock.clone()).await;
    fill(&h.state, 10, recent()).await;
    for _ in 0..1_960 {
        clock.step(Duration::minutes(59));
        let run = auto_prune_once(&h.state).await;
        assert_eq!(
            (run.outcome, run.reason),
            (OUTCOME_SKIPPED, "prune_too_recent"),
            "{run:?}"
        );
    }
    touch(&h.state);
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.reason),
        (OUTCOME_SKIPPED, "prune_too_recent"),
        "{run:?}"
    );
    assert_eq!(h.state.audit.pruned_through().unwrap(), None);
    let text = h.state.metrics.render();
    assert_eq!(runs(&text, "skipped", "clock_jump"), 0, "{text}");
}

/// Time that really passes (both clocks move 20 days) makes entries 85 days old older than
/// the window, and the next run prunes them.
#[tokio::test]
async fn time_that_really_passes_still_prunes() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(Stepped::default());
    let cfg = config(&dir);
    let h = start_with_clock(dir, cfg, clock.clone()).await;
    fill(&h.state, 25, OffsetDateTime::now_utc() - Duration::days(85)).await;
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.reason),
        (OUTCOME_SKIPPED, "prune_too_recent"),
        "{run:?}"
    );
    clock.pass(Duration::days(20));
    touch(&h.state);
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.through),
        (OUTCOME_PRUNED, Some(20)),
        "{run:?}"
    );
    h.verify_ok();
}

/// A step back of two hours, with traffic: entries 30 minutes past the window are not old
/// enough by the slow clock, so pruning waits. Once the clock is set right, the next run
/// prunes them.
#[tokio::test]
async fn after_a_step_back_pruning_waits_and_then_resumes() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(Stepped::default());
    let cfg = config(&dir);
    let h = start_with_clock(dir, cfg, clock.clone()).await;
    let at = OffsetDateTime::now_utc() - Duration::seconds(KEEP as i64) - Duration::minutes(30);
    fill(&h.state, 25, at).await;
    clock.step(-Duration::hours(2));
    let run = auto_prune_once(&h.state).await;
    assert_eq!(run.reason, "clock_jump", "{run:?}");
    touch(&h.state);
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.reason),
        (OUTCOME_SKIPPED, "prune_too_recent"),
        "{run:?}"
    );
    clock.step(Duration::hours(2));
    let run = auto_prune_once(&h.state).await;
    assert_eq!(run.reason, "clock_jump", "{run:?}");
    touch(&h.state);
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.through),
        (OUTCOME_PRUNED, Some(20)),
        "{run:?}"
    );
    h.verify_ok();
}

/// Write a valid archive of 1..=20 with a prepare, stop the server, change the file with
/// `tamper`, start again and run: the run must refuse the file (`archive_exists`), leave it
/// as it is, and prune nothing. Answers the run's detail.
async fn planted(tamper: impl FnOnce(&str) -> String) -> String {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, _archive) = with_archive(&dir);
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let server = spawn_router(router).await.unwrap();
    fill(&state, 25, old()).await;
    let written = auto_prune_prepare(&state)
        .await
        .expect("prepared")
        .archive
        .unwrap();
    drop(server);
    let released = state.released();
    drop(state);
    tokio::time::timeout(StdDuration::from_secs(10), released)
        .await
        .expect("the first server let go of its state");
    let text = std::fs::read_to_string(&written.path).unwrap();
    let forged = tamper(&text);
    assert_ne!(forged, text);
    std::fs::write(&written.path, &forged).unwrap();

    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let _server = spawn_router(router).await.unwrap();
    fill(&state, 10, recent()).await;
    let run = auto_prune_once(&state).await;
    assert_eq!(
        (run.outcome, run.reason, run.through),
        (OUTCOME_FAILED, "archive_exists", Some(20)),
        "{run:?}"
    );
    assert_eq!(state.audit.newest_anchor().unwrap(), None, "nothing signed");
    assert_eq!(state.audit.pruned_through().unwrap(), None);
    assert_eq!(std::fs::read_to_string(&written.path).unwrap(), forged);
    run.detail.unwrap_or_default()
}

/// A valid archive with content the hash chain does not cover is never signed: fields added
/// to records and to the header, a key given twice, or lines added at the end.
#[tokio::test]
async fn a_planted_archive_with_extra_content_is_refused_not_signed() {
    let detail = planted(|text| {
        text.replacen(
            "\"record\":{",
            "\"record\":{\"note\":\"FORGED: approved by nobody\",",
            3,
        )
        .replacen(
            "{\"type\":\"header\",",
            "{\"type\":\"header\",\"comment\":\"planted\",",
            1,
        )
    })
    .await;
    assert!(detail.contains("never replaced"), "{detail}");
    planted(|text| text.replacen("\"record\":{", "\"record\":{\"reason\":\"forged\",", 1)).await;
    planted(|text| format!("{text}{{\"type\":\"note\",\"text\":\"forged\"}}\n")).await;
    planted(|text| format!("{text}\n")).await;
}

/// A manual prune that commits after the archive is written and checked, just before the
/// automatic prune's transaction: the run is skipped as `concurrent_prune`, and the file it
/// wrote, which no prune can have used, is removed.
#[tokio::test]
async fn a_prune_just_before_the_commit_is_a_concurrent_skip() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, archive) = with_archive(&dir);
    let h = start(dir, cfg).await;
    fill(&h.state, 25, old()).await;
    let audit = h.state.audit.clone();
    h.state.audit.on_next_prune(move || {
        let limits = attenuo_audit::PruneLimits {
            min_age: Duration::ZERO,
            sink: None,
            now: OffsetDateTime::now_utc(),
        };
        audit
            .prune_through(10, Some("ab".repeat(32)), &limits, |args| {
                let call = ToolCall::new("attenuo", PRUNE_TOOL, args.clone());
                let mut r = record(0, OffsetDateTime::now_utc());
                r.tool = call.tool.clone();
                r.arguments_digest = call.arguments_digest();
                r
            })
            .unwrap();
    });
    let run = auto_prune_once(&h.state).await;
    assert_eq!(
        (run.outcome, run.reason, run.through),
        (OUTCOME_SKIPPED, "concurrent_prune", Some(20)),
        "{run:?}"
    );
    assert_eq!(h.state.audit.pruned_through().unwrap(), Some(10));
    assert!(names(&archive).is_empty(), "{:?}", names(&archive));
    h.verify_ok();
}
