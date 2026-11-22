//! Audit retention through the server (ADR-0015): `[audit.retention]` and its start-up
//! refusals, the prune routes and their guards, the reads after a prune (410 `audit_pruned`,
//! `first`, the export's anchor), the shipped anchor, the deletes on the maintenance task and
//! their resumption after a restart, and appends while a prune runs.

mod common;

use std::sync::Arc;

use attenuo_audit::{
    cross_check, parse_export, parse_shipped, parse_shipped_anchors, verify_export, AnchorState,
    AuditSink, PRUNE_TOOL,
};
use attenuo_core::{Decision, DecisionRecord, RecordKind, ToolCall};
use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::config::{PruneMode, SinkKind, SinkSection};
use attenuo_server::{AppState, Config};
use axum::http::StatusCode;
use serde_json::{json, Value};
use sha2::Digest;
use time::{Duration, OffsetDateTime};

use common::{wait_for, Running};

const ADMIN: &str = "admin";

/// A file-backed config with a checkpoint every 10 entries, a file sink, and `prune`.
fn config(dir: &tempfile::TempDir, prune: PruneMode) -> Config {
    let mut cfg = Config::default();
    cfg.audit.sqlite_path = dir
        .path()
        .join("audit.sqlite")
        .to_string_lossy()
        .into_owned();
    cfg.audit.checkpoint_every = 10;
    let mut sink = SinkSection::new(SinkKind::File);
    sink.path = Some(dir.path().join("shipped.jsonl"));
    sink.initial_backoff_ms = 5;
    sink.max_backoff_seconds = 1;
    cfg.audit.sink = Some(sink);
    cfg.audit.retention.prune = prune;
    cfg.admin.token = Some(ADMIN.into());
    cfg.dev.allow_root_mint = true;
    // One key across restarts, so the anchor and checkpoints still verify.
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

/// Long ago enough for the 90-day default.
fn old() -> OffsetDateTime {
    OffsetDateTime::now_utc() - Duration::days(200)
}

struct Harness {
    server: Spawned,
    state: Arc<AppState>,
    dir: tempfile::TempDir,
}

async fn start(dir: tempfile::TempDir, cfg: Config) -> Harness {
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    Harness {
        server: spawn_router(router).await.unwrap(),
        state,
        dir,
    }
}

impl Harness {
    /// `n` old records, then wait until the sink has delivered the newest checkpoint.
    async fn fill(&self, n: usize) {
        for i in 0..n {
            self.state.audit.append(record(i, old())).unwrap();
        }
        let last = (n as u64 / 10) * 10;
        let sink = self.state.checkpoint_sink.as_ref().unwrap();
        wait_for(|| sink.delivered_through() >= Some(last)).await;
    }

    async fn get(&self, path: &str) -> (StatusCode, Value) {
        let r = reqwest::Client::new()
            .get(self.server.url(path))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap();
        (r.status(), r.json().await.unwrap_or(Value::Null))
    }

    async fn text(&self, path: &str) -> (StatusCode, String) {
        let r = reqwest::Client::new()
            .get(self.server.url(path))
            .bearer_auth(ADMIN)
            .send()
            .await
            .unwrap();
        (r.status(), r.text().await.unwrap())
    }

    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let r = reqwest::Client::new()
            .post(self.server.url(path))
            .bearer_auth(ADMIN)
            .json(&body)
            .send()
            .await
            .unwrap();
        (r.status(), r.json().await.unwrap_or(Value::Null))
    }

    async fn prune(&self, through: u64, digest: Option<&str>) -> (StatusCode, Value) {
        self.post(
            "/admin/audit/prune",
            json!({"through": through, "archive_sha256": digest}),
        )
        .await
    }

    fn shipped(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("shipped.jsonl")).unwrap_or_default()
    }
}

/// `prune = "off"` (the default): both prune routes refuse with `prune_disabled`, nothing
/// changes, and the read-only additions (`first`, `pruned_through`, the anchors list) are there.
#[tokio::test]
async fn prune_off_answers_prune_disabled_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&dir, PruneMode::Off);
    let h = start(dir, cfg).await;
    h.fill(25).await;
    let (status, body) = h.get("/admin/audit/prune/plan?through=20").await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::CONFLICT, Some("prune_disabled"))
    );
    let (status, body) = h.prune(20, None).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::CONFLICT, Some("prune_disabled"))
    );
    assert_eq!(h.state.audit.len().unwrap(), 25);
    let (status, body) = h.get("/admin/audit/anchors").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"anchors": [], "next_cursor": null}));
    let (_, body) = h.get("/admin/audit?limit=1").await;
    assert_eq!(body["first"], 1);
    let (_, body) = h.get("/admin/audit/verify").await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["pruned_through"], Value::Null);
    assert_eq!(body["anchors"], 0);
    let (status, body) = h.get("/admin/audit/entries/1").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = h.get("/admin/audit/entries/99").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The settings that cannot work refuse to start, each with a message naming it.
#[test]
fn start_up_refuses_a_prune_setting_that_cannot_work() {
    let dir = tempfile::tempdir().unwrap();
    let refuse = |cfg: Config, needle: &str| {
        let e = attenuo_server::build(&cfg).err().expect("must refuse");
        let text = format!("{e:#}");
        assert!(text.contains(needle), "{needle}: {text}");
    };
    let mut cfg = config(&dir, PruneMode::Manual);
    cfg.audit.sqlite_path = ":memory:".into();
    refuse(cfg, ":memory:");
    let mut cfg = config(&dir, PruneMode::Manual);
    cfg.audit.sink = None;
    refuse(cfg, "needs [audit.sink]");
    let mut cfg = config(&dir, PruneMode::Manual);
    cfg.audit.retention.min_age_seconds = 86_400;
    refuse(cfg, "min_age_seconds = 86400 is below");
    let e = Config::from_toml("[audit.retention]\nprune = \"auto\"\n").unwrap_err();
    assert!(e.to_string().contains("not built"), "{e}");
    // And the default settings with "manual" start.
    let _ = attenuo_server::build(&config(&dir, PruneMode::Manual)).unwrap();
}

/// The whole flow on a server with a file sink: plan, archive, prune, the reads after it, the
/// shipped objects, the deletes on the maintenance task, and verify throughout.
#[tokio::test]
async fn a_prune_end_to_end_with_a_file_sink() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&dir, PruneMode::Manual);
    let h = start(dir, cfg).await;
    h.fill(35).await;
    let keys = h.state.checkpoint_keys.clone();
    let pruned_id = h.state.audit.entry_at(7).unwrap().unwrap().record.id;

    // The plan rounds 27 down to the checkpoint at 20.
    let (status, plan) = h.get("/admin/audit/prune/plan?through=27").await;
    assert_eq!(status, StatusCode::OK, "{plan}");
    assert_eq!(
        (&plan["from"], &plan["through"], &plan["entries"]),
        (&json!(1), &json!(20), &json!(20))
    );
    assert_eq!(plan["guards"]["limited_by"], "prune_not_at_checkpoint");
    let (status, _) = h
        .get("/admin/audit/prune/plan?through=20&before=2026-01-01T00:00:00Z")
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The archive: 1..=20, verified strictly on its own.
    let (_, archive) = h.text("/admin/audit/export?from=1&to=20").await;
    let rep = verify_export(&parse_export(&archive).unwrap(), &keys).unwrap();
    assert!(rep.report.ok && rep.from_genesis, "{rep:?}");
    let digest = hex::encode(sha2::Sha256::digest(archive.as_bytes()));
    // A real cursor of a page that ends below the boundary, taken before the prune.
    let (_, page) = h.get("/admin/audit?limit=3").await;
    let cursor = page["next_cursor"].as_str().unwrap().to_string();
    assert_eq!(page["entries"][2]["seq"], 3);

    // The prune.
    let (status, out) = h.prune(20, Some(&digest)).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out["pruned_through"], 20);
    assert_eq!(out["prune_seq"], 36);
    assert_eq!(out["checkpoint_before"]["seq"], 35);
    assert_eq!(out["checkpoint_after"]["seq"], 36);
    assert_eq!(out["deleting"], true);
    assert_eq!(out["already"], false);
    assert_eq!(out["anchor"]["archive_sha256"], digest.as_str());
    assert_eq!(out["shipped"]["queued"], true);
    let prune_entry = h.state.audit.entry_at(36).unwrap().unwrap().record;
    assert_eq!(
        (
            prune_entry.tool.as_str(),
            prune_entry.originating_subject.as_str()
        ),
        (PRUNE_TOOL, "urn:attenuo:admin")
    );
    // A repeat is idempotent; another digest for the same boundary is a conflict.
    let (status, again) = h.prune(20, Some(&digest)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (&again["already"], &again["anchor"]),
        (&json!(true), &out["anchor"])
    );
    let (status, body) = h.prune(20, Some(&"0".repeat(64))).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::CONFLICT, Some("prune_conflict"))
    );
    // A malformed digest is a 400.
    let (status, _) = h.prune(30, Some("ABC")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Reads start at 21.
    let (status, body) = h.get("/admin/audit/entries/7").await;
    assert_eq!(status, StatusCode::GONE, "{body}");
    assert_eq!(body["code"], "audit_pruned");
    assert_eq!(
        (&body["pruned_through"], &body["prune_seq"], &body["first"]),
        (&json!(20), &json!(36), &json!(21))
    );
    let (status, _) = h.get("/admin/audit/entries/21").await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = h.get("/admin/audit?from=1&limit=3").await;
    assert_eq!(body["first"], 21);
    assert_eq!(body["entries"][0]["seq"], 21);
    // The cursor below the boundary resumes at B + 1.
    let (status, body) = h
        .get(&format!("/admin/audit?limit=3&cursor={cursor}"))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["entries"][0]["seq"], 21, "{body}");
    let (_, body) = h.get("/admin/audit?order=desc&to=15").await;
    assert_eq!(body["entries"], json!([]));
    assert_eq!(body["next_cursor"], Value::Null);
    let (status, body) = h.get(&format!("/admin/audit/records/{pruned_id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body["detail"]
            .as_str()
            .unwrap()
            .contains("pruned through seq 20"),
        "{body}"
    );
    let (status, body) = h
        .post(
            "/admin/budgets/refund",
            json!({ "decision_id": pruned_id.to_string() }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body["detail"]
            .as_str()
            .unwrap()
            .contains("pruned through seq 20"),
        "{body}"
    );

    // The export: from 21 by default, with the anchor; at or below 20 is gone.
    for q in ["from=5", "to=20", "from=20&to=30"] {
        let (status, body) = h.get(&format!("/admin/audit/export?{q}")).await;
        assert_eq!(
            (status, body["code"].as_str()),
            (StatusCode::GONE, Some("audit_pruned")),
            "{q}"
        );
    }
    let (_, retained) = h.text("/admin/audit/export").await;
    let export = parse_export(&retained).unwrap();
    let header = export.header.as_ref().unwrap();
    assert_eq!(header.from, 21);
    assert_eq!(header.anchor.as_ref().map(|a| a.through_seq), Some(20));
    let rep = verify_export(&export, &keys).unwrap();
    assert!(
        rep.report.ok && rep.from_anchor && !rep.from_genesis,
        "{rep:?}"
    );
    // The archive and the retained export link.
    let archive = parse_export(&archive).unwrap();
    assert_eq!(
        archive.entries.last().unwrap().entry_hash,
        export.entries[0].prev_hash
    );
    // An export that starts later has no anchor and verifies as a window.
    let (_, later) = h.text("/admin/audit/export?from=25").await;
    let later = parse_export(&later).unwrap();
    assert!(later.header.unwrap().anchor.is_none());

    // Verify, before and after the deletes.
    let (_, v) = h.get("/admin/audit/verify").await;
    assert_eq!(
        (&v["ok"], &v["pruned_through"], &v["anchors"]),
        (&json!(true), &json!(20), &json!(1)),
        "{v}"
    );
    assert_eq!(attenuo_server::prune_audit_log(&h.state).await, 20);
    let (_, anchors) = h.get("/admin/audit/anchors").await;
    assert_eq!(anchors["anchors"][0]["state"], "done");
    assert_eq!(anchors["anchors"][0]["through_seq"], 20);
    let (_, v) = h.get("/admin/audit/verify").await;
    assert_eq!(v["ok"], true, "{v}");
    let (_, again) = h.prune(20, Some(&digest)).await;
    assert_eq!(
        (&again["already"], &again["deleting"]),
        (&json!(true), &json!(false))
    );
    let text = h.state.metrics.render();
    assert!(
        text.contains("attenuo_audit_pruned_entries_total 20\n"),
        "{text}"
    );
    let size = text
        .lines()
        .find_map(|l| l.strip_prefix("attenuo_audit_db_size_bytes "))
        .unwrap();
    assert!(size.parse::<u64>().unwrap() > 0);
    assert!(text.contains("attenuo_audit_db_free_bytes "));

    // The sink shipped both checkpoints and the anchor, and the retained export cross-checks.
    let sink = h.state.checkpoint_sink.as_ref().unwrap();
    wait_for(|| sink.delivered_through() >= Some(36)).await;
    wait_for(|| {
        parse_shipped_anchors(&h.shipped())
            .map(|a| a.len())
            .unwrap_or(0)
            == 1
    })
    .await;
    let shipped = h.shipped();
    let anchors = parse_shipped_anchors(&shipped).unwrap();
    assert_eq!(anchors[0].1.anchor.through_seq, 20);
    let cps = parse_shipped(&shipped).unwrap();
    for seq in [10, 20, 30, 35, 36] {
        assert!(cps.iter().any(|c| c.checkpoint.seq == seq), "shipped {seq}");
    }
    let r = cross_check(&export, &cps, &keys);
    assert!(r.ok, "{r:?}");

    // The delivery is recorded and reported.
    let s = h.state.clone();
    wait_for(move || {
        s.audit
            .newest_anchor()
            .ok()
            .flatten()
            .is_some_and(|a| a.shipped_at.is_some())
    })
    .await;
    let (_, anchors) = h.get("/admin/audit/anchors").await;
    assert!(anchors["anchors"][0]["shipped_at"].is_string(), "{anchors}");
    let (_, again) = h.prune(20, Some(&digest)).await;
    assert!(again["shipped"]["anchor_shipped_at"].is_string(), "{again}");
    assert_eq!(
        (
            &again["shipped"]["queued"],
            &again["shipped"]["anchor_pending"]
        ),
        (&json!(false), &json!(false)),
        "{again}"
    );

    // An anchor not delivered (as after a crash before its delivery) holds the next prune
    // with `sink_behind`; the repeated request queues it again, and once it is delivered the
    // next prune goes through.
    h.state
        .audit
        .with_connection(|c| {
            c.execute("UPDATE audit_anchors SET shipped_at = NULL", [])?;
            Ok(())
        })
        .unwrap();
    for i in 0..10 {
        h.state.audit.append(record(100 + i, old())).unwrap();
    }
    wait_for(|| sink.delivered_through() >= Some(40)).await;
    let (status, body) = h.prune(40, None).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::CONFLICT, Some("sink_behind")),
        "{body}"
    );
    assert!(
        body["detail"]
            .as_str()
            .unwrap()
            .contains("the anchor of the prune through seq 20"),
        "{body}"
    );
    let (_, plan) = h.get("/admin/audit/prune/plan").await;
    assert_eq!(plan["guards"]["anchor_undelivered"], true, "{plan}");
    let (_, again) = h.prune(20, Some(&digest)).await;
    assert_eq!(again["shipped"]["queued"], true, "{again}");
    assert_eq!(
        again["shipped"]["anchor_shipped_at"],
        Value::Null,
        "{again}"
    );
    let s = h.state.clone();
    wait_for(move || s.audit.unshipped_anchors().is_ok_and(|u| u.is_empty())).await;
    let (status, body) = h.prune(40, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Each guard refuses through the route with its code, and nothing is written.
#[tokio::test]
async fn every_guard_refuses_through_the_route() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&dir, PruneMode::Manual);
    let h = start(dir, cfg).await;
    h.fill(25).await;
    let refuse = |status: StatusCode, body: &Value, code: &str| {
        assert_eq!(body["code"], code, "{body}");
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
    };
    let (status, body) = h.prune(15, None).await;
    refuse(status, &body, "prune_not_at_checkpoint");
    // Recent entries: 10 more written now, and the checkpoint at 30.
    for i in 0..10 {
        h.state
            .audit
            .append(record(i, OffsetDateTime::now_utc()))
            .unwrap();
    }
    let (status, body) = h.prune(30, None).await;
    refuse(status, &body, "prune_too_recent");
    // A live run: a root token minted now has its lease in the registry.
    let r = reqwest::Client::new()
        .post(h.server.url("/admin/root-token"))
        .bearer_auth(ADMIN)
        .json(&json!({"subject": "alice", "issuer": "https://idp.example",
                      "agent": "planner", "capabilities": ["github:*"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let (status, plan) = h.get("/admin/audit/prune/plan").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(plan["guards"]["live_run_seq"], 36, "{plan}");
    assert_eq!(h.state.audit.len().unwrap(), 37);
    // Accepted at 20; while it deletes, another is refused; below it is gone.
    let (status, body) = h.prune(20, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = h.prune(10, None).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::GONE, Some("audit_pruned"))
    );
    // The same members as every other 410 `audit_pruned`.
    assert_eq!(
        (&body["pruned_through"], &body["prune_seq"], &body["first"]),
        (&json!(20), &json!(38), &json!(21)),
        "{body}"
    );
    for _ in 0..10 {
        h.state.audit.append(record(0, old())).unwrap();
    }
    let (status, body) = h.prune(40, None).await;
    refuse(status, &body, "prune_in_progress");
}

/// A sink that has delivered nothing: `sink_behind`.
#[tokio::test]
async fn a_sink_that_delivered_nothing_refuses_with_sink_behind() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir, PruneMode::Manual);
    let mut sink = SinkSection::new(SinkKind::Webhook);
    // Nothing listens there: every delivery fails.
    sink.url = Some("http://127.0.0.1:9/hook".into());
    sink.timeout_seconds = 1;
    cfg.audit.sink = Some(sink);
    let h = start(dir, cfg).await;
    for i in 0..25 {
        h.state.audit.append(record(i, old())).unwrap();
    }
    let (status, body) = h.prune(20, None).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::CONFLICT, Some("sink_behind")),
        "{body}"
    );
    let (_, plan) = h.get("/admin/audit/prune/plan").await;
    assert_eq!(plan["through"], Value::Null, "{plan}");
    assert_eq!(plan["guards"]["limited_by"], "sink_behind");
}

/// Appends from several tasks while the prune commits and its deletes run: the appends start
/// before the prune and go on after it, none is denied, and every seq above the old head is
/// an append or the prune record, each given once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn appends_during_a_prune_are_kept() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&dir, PruneMode::Manual);
    let h = start(dir, cfg).await;
    h.fill(1005).await;
    let stop = Arc::new(AtomicBool::new(false));
    let mut tasks = Vec::new();
    for t in 0..4 {
        let (state, stop) = (h.state.clone(), stop.clone());
        tasks.push(tokio::spawn(async move {
            let mut seqs = Vec::new();
            let mut i = 0;
            while !stop.load(Ordering::SeqCst) {
                let e = state
                    .blocking(move |s| s.audit.append(record(t * 100_000 + i, old())))
                    .await
                    .expect("an append during a prune is not denied");
                seqs.push(e.seq);
                i += 1;
            }
            seqs
        }));
    }
    // The appends are running before the prune.
    let s = h.state.clone();
    wait_for(move || s.audit.head().ok().flatten().is_some_and(|e| e.seq >= 1025)).await;
    let (status, body) = h.prune(1000, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let prune_seq = body["prune_seq"].as_u64().unwrap();
    let deleted = attenuo_server::prune_audit_log(&h.state).await;
    // And go on after it.
    let s = h.state.clone();
    wait_for(move || {
        s.audit
            .head()
            .ok()
            .flatten()
            .is_some_and(|e| e.seq >= prune_seq + 25)
    })
    .await;
    stop.store(true, Ordering::SeqCst);
    let mut seqs: Vec<u64> = Vec::new();
    for t in tasks {
        seqs.extend(t.await.unwrap());
    }
    let n = seqs.len();
    seqs.sort_unstable();
    seqs.dedup();
    assert_eq!(seqs.len(), n, "no seq given twice");
    assert!(
        seqs.iter().any(|&s| s < prune_seq),
        "an append before the prune record"
    );
    assert!(seqs.iter().any(|&s| s > prune_seq), "an append after it");
    assert!(!seqs.contains(&prune_seq));
    // Every seq above the old head: an append or the prune record.
    let head = h.state.audit.head().unwrap().unwrap().seq;
    let mut all = seqs.clone();
    all.push(prune_seq);
    all.sort_unstable();
    assert_eq!(all, (1006..=head).collect::<Vec<_>>());
    let total = deleted + attenuo_server::prune_audit_log(&h.state).await;
    assert_eq!(total, 1000);
    assert_eq!(
        h.state.audit.newest_anchor().unwrap().unwrap().state,
        AnchorState::Done
    );
    let (_, v) = h.get("/admin/audit/verify").await;
    assert_eq!(v["ok"], true, "{v}");
    // 5 old entries above the boundary, the prune record, and the appends.
    assert_eq!(v["entries"], json!(5 + 1 + n), "{v}");
}

/// A delegation chain whose root lease is in the registry and has a record at or below the
/// boundary: `prune_live_run` through the route, and nothing is written.
#[tokio::test]
async fn a_live_run_refuses_through_the_route() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&dir, PruneMode::Manual);
    let h = start(dir, cfg).await;
    // The mint's records come first, so the run's first record is below the boundary.
    let r = reqwest::Client::new()
        .post(h.server.url("/admin/root-token"))
        .bearer_auth(ADMIN)
        .json(&json!({"subject": "alice", "issuer": "https://idp.example",
                      "agent": "planner", "capabilities": ["github:*"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let minted = h.state.audit.len().unwrap() as usize;
    h.fill(30 - minted).await;
    let before = h.state.audit.len().unwrap();
    let (_, plan) = h.get("/admin/audit/prune/plan").await;
    let live = plan["guards"]["live_run_seq"].as_u64().unwrap();
    assert!(live <= 20, "{plan}");
    let (status, body) = h.prune(20, None).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::CONFLICT, Some("prune_live_run")),
        "{body}"
    );
    assert_eq!(h.state.audit.len().unwrap(), before);
    assert_eq!(h.state.audit.pruned_through().unwrap(), None);
}

/// An anchor the sink had not delivered when the server stopped is queued again at the next
/// start, delivered, and recorded.
#[tokio::test]
async fn an_undelivered_anchor_is_shipped_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&dir, PruneMode::Manual);
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let running = Running::start(cfg.clone(), state.clone(), router).await;
    for i in 0..25 {
        state.audit.append(record(i, old())).unwrap();
    }
    let sink = state.checkpoint_sink.as_ref().unwrap();
    wait_for(|| sink.delivered_through() >= Some(20)).await;
    let r = reqwest::Client::new()
        .post(running.url("/admin/audit/prune"))
        .bearer_auth(ADMIN)
        .json(&json!({"through": 20}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let s = state.clone();
    wait_for(move || s.audit.unshipped_anchors().is_ok_and(|u| u.is_empty())).await;
    running.stop(state).await;
    // As if the process had died with the anchor still queued: not delivered, not in the file.
    let path = dir.path().join("shipped.jsonl");
    let kept: String = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .filter(|l| !l.contains("attenuo-shipped-anchor-v1"))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&path, kept).unwrap();
    {
        let log = attenuo_audit::SqliteAudit::open(dir.path().join("audit.sqlite")).unwrap();
        log.with_connection(|c| {
            c.execute("UPDATE audit_anchors SET shipped_at = NULL", [])?;
            Ok(())
        })
        .unwrap();
        assert_eq!(log.unshipped_anchors().unwrap().len(), 1);
    }

    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let running = Running::start(cfg, state.clone(), router).await;
    let s = state.clone();
    wait_for(move || s.audit.unshipped_anchors().is_ok_and(|u| u.is_empty())).await;
    let anchors = parse_shipped_anchors(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(anchors.len(), 1);
    assert_eq!(anchors[0].1.anchor.through_seq, 20);
    running.stop(state).await;
}

/// The server stops between the prune's commit and its deletes: after a restart, even with
/// `prune` turned back off, the maintenance task finishes them and the anchor reaches `done`.
#[tokio::test]
async fn the_deletes_resume_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&dir, PruneMode::Manual);
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    let running = Running::start(cfg.clone(), state.clone(), router).await;
    for i in 0..25 {
        state.audit.append(record(i, old())).unwrap();
    }
    let sink = state.checkpoint_sink.as_ref().unwrap();
    wait_for(|| sink.delivered_through() >= Some(20)).await;
    let r = reqwest::Client::new()
        .post(running.url("/admin/audit/prune"))
        .bearer_auth(ADMIN)
        .json(&json!({"through": 20}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    running.stop(state).await;

    let mut cfg = config(&dir, PruneMode::Off);
    cfg.audit.retention.batch_rows = 7;
    // The ticker's first run is one interval after the start.
    cfg.leases.maintenance_interval_seconds = 1;
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    assert_eq!(
        state.audit.newest_anchor().unwrap().unwrap().state,
        AnchorState::Deleting
    );
    assert_eq!(state.audit.first_retained_seq().unwrap(), 21);
    let running = Running::start(cfg, state.clone(), router).await;
    let s = state.clone();
    wait_for(move || {
        s.audit
            .newest_anchor()
            .ok()
            .flatten()
            .is_some_and(|a| a.state == AnchorState::Done)
    })
    .await;
    assert!(
        state
            .audit
            .verify_chain_signed(&state.checkpoint_keys)
            .unwrap()
            .ok
    );
    running.stop(state).await;
}

/// An export that a prune overtakes: the body was read up to seq 500 when a prune through
/// 1000 committed, so the pages still to come would skip the pruned rows. The body ends with
/// an error instead of a file with a gap. The router is driven directly, so the export only
/// reads a page when the test asks for the next frame (no socket buffer reads ahead).
#[tokio::test]
async fn an_export_overtaken_by_a_prune_ends_with_an_error() {
    use futures_util::StreamExt as _;
    use tower::ServiceExt as _;

    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&dir, PruneMode::Manual);
    let (router, state) = attenuo_server::build(&cfg).unwrap();
    for i in 0..1200 {
        state.audit.append(record(i, old())).unwrap();
    }
    let sink = state.checkpoint_sink.as_ref().unwrap();
    wait_for(|| sink.delivered_through() >= Some(1200)).await;

    let req = |method: &str, path: &str, body: Option<Value>| {
        axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {ADMIN}"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                body.map(|b| b.to_string()).unwrap_or_default(),
            ))
            .unwrap()
    };
    let resp = router
        .clone()
        .oneshot(req("GET", "/admin/audit/export?from=1&to=1200", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body().into_data_stream();
    let mut text = String::new();
    // The header, then the first page (seq 1 to 500).
    while !text.contains("\"seq\":500,") {
        let frame = body.next().await.expect("more frames").unwrap();
        text.push_str(std::str::from_utf8(&frame).unwrap());
    }
    assert!(!text.contains("\"seq\":501,"), "the export read ahead");

    let resp = router
        .clone()
        .oneshot(req(
            "POST",
            "/admin/audit/prune",
            Some(json!({"through": 1000})),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let mut error = None;
    while let Some(frame) = body.next().await {
        match frame {
            Ok(b) => text.push_str(std::str::from_utf8(&b).unwrap()),
            Err(e) => {
                error = Some(e.to_string());
                break;
            }
        }
    }
    let error = error.expect("the body ends with an error");
    assert!(
        error.contains("pruned through seq 1000 during the export"),
        "{error}"
    );
    // Nothing after the first page reached the body, and no checkpoint lines: the reader has
    // a file that does not verify as complete.
    assert!(!text.contains("\"seq\":501,"));
    assert!(parse_export(&text)
        .map(|e| verify_export(&e, &state.checkpoint_keys)
            .map_or(true, |r| !r.report.ok || r.truncated))
        .unwrap_or(true));
}

/// `from` and `through_hash` tie a prune to the archive it was made after: an archive that
/// does not start at the first retained seq, or whose last entry is not the entry at the
/// boundary, is refused with `prune_archive_mismatch` and nothing is written. A repeat is
/// compared with the stored anchor.
#[tokio::test]
async fn a_prune_is_refused_when_its_archive_is_not_the_pruned_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&dir, PruneMode::Manual);
    let h = start(dir, cfg).await;
    h.fill(35).await;
    let hash_at = |seq: u64| h.state.audit.entry_at(seq).unwrap().unwrap().entry_hash;
    let digest = "ab".repeat(32);
    let head = h.state.audit.head().unwrap().unwrap().seq;

    // An archive of 11..=20 on a log that starts at 1.
    let (status, body) = h
        .post(
            "/admin/audit/prune",
            json!({"through": 20, "archive_sha256": digest, "from": 11, "through_hash": hash_at(20)}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "prune_archive_mismatch");
    assert!(
        body["detail"]
            .as_str()
            .unwrap()
            .contains("starts at seq 11"),
        "{body}"
    );
    // An archive that ends at another entry.
    let (status, body) = h
        .post(
            "/admin/audit/prune",
            json!({"through": 20, "archive_sha256": digest, "from": 1, "through_hash": hash_at(19)}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "prune_archive_mismatch");
    // Malformed values are 400s.
    for bad in [
        json!({"through": 20, "from": 0}),
        json!({"through": 20, "through_hash": "AB"}),
    ] {
        let (status, _) = h.post("/admin/audit/prune", bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    // Nothing was written.
    assert_eq!(h.state.audit.head().unwrap().unwrap().seq, head);
    assert!(h.state.audit.newest_anchor().unwrap().is_none());

    // The right archive prunes; its repeat answers `already`, and a repeat that names another
    // start or hash is refused.
    let good =
        json!({"through": 20, "archive_sha256": digest, "from": 1, "through_hash": hash_at(20)});
    let (status, body) = h.post("/admin/audit/prune", good.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = h.post("/admin/audit/prune", good).await;
    assert_eq!(
        (status, &body["already"]),
        (StatusCode::OK, &json!(true)),
        "{body}"
    );
    let (status, body) = h
        .post(
            "/admin/audit/prune",
            json!({"through": 20, "archive_sha256": digest, "from": 5}),
        )
        .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::CONFLICT, Some("prune_archive_mismatch")),
        "{body}"
    );
    let (status, body) = h
        .post(
            "/admin/audit/prune",
            json!({"through": 20, "archive_sha256": digest, "through_hash": "00".repeat(32)}),
        )
        .await;
    assert_eq!(body["code"], "prune_archive_mismatch", "{status} {body}");

    // After the deletes, the next prune's archive must start at 21.
    attenuo_server::prune_audit_log(&h.state).await;
    let s = h.state.clone();
    wait_for(move || {
        s.audit
            .newest_anchor()
            .ok()
            .flatten()
            .is_some_and(|a| a.shipped_at.is_some())
    })
    .await;
    let sink = h.state.checkpoint_sink.as_ref().unwrap();
    let head = h.state.audit.head().unwrap().unwrap().seq;
    wait_for(|| sink.delivered_through() >= Some(head)).await;
    let (status, body) = h
        .post(
            "/admin/audit/prune",
            json!({"through": 30, "from": 1, "through_hash": hash_at(30)}),
        )
        .await;
    assert_eq!(body["code"], "prune_archive_mismatch", "{status} {body}");
    let (status, body) = h
        .post(
            "/admin/audit/prune",
            json!({"through": 30, "from": 21, "through_hash": hash_at(30)}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["anchor"]["previous_through_seq"], 20);
}
