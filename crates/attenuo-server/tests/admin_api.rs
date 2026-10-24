//! The audit query API: `GET /admin/audit` filters and two-way paging, the single-entry
//! routes, the read-only checkpoint list, and the headers every admin answer carries.
//!
//! The fixture appends records straight to the server's audit store, so every field is known
//! and the expected pages are computed from the fixture table, not from the filter code.

use std::collections::BTreeSet;
use std::sync::Arc;

use attenuo_audit::{AuditSink, LeaseStore};
use attenuo_core::{AgentId, Decision, DecisionRecord, LeaseId, RecordKind};
use attenuo_proxy::testing::{spawn_router, Spawned};
use attenuo_server::{AppState, Config};
use reqwest::header::{CACHE_CONTROL, WWW_AUTHENTICATE, X_CONTENT_TYPE_OPTIONS};
use reqwest::StatusCode;
use serde_json::Value;
use time::macros::datetime;

const ADMIN: &str = "admin-api-test-token";

struct Harness {
    server: Spawned,
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn start(admin_token: Option<&str>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.audit.sqlite_path = dir
            .path()
            .join("audit.sqlite")
            .to_string_lossy()
            .into_owned();
        cfg.admin.token = admin_token.map(str::to_string);
        let (router, state) = attenuo_server::build(&cfg).unwrap();
        let server = spawn_router(router).await.unwrap();
        Self {
            server,
            state,
            _dir: dir,
        }
    }

    /// A server whose log holds [`FIXTURE`], seqs 1 to 12.
    async fn with_fixture() -> Self {
        let h = Self::start(Some(ADMIN)).await;
        for (i, row) in FIXTURE.iter().enumerate() {
            h.state.audit.append(row.record(i as u64 + 1)).unwrap();
        }
        h
    }

    /// GET with the admin bearer; the status, the response and its JSON body.
    async fn get(&self, path: &str, query: &[(&str, &str)]) -> (StatusCode, Value) {
        let r = self.send(path, query, Some(ADMIN)).await;
        let status = r.status();
        (status, r.json().await.unwrap())
    }

    async fn send(
        &self,
        path: &str,
        query: &[(&str, &str)],
        bearer: Option<&str>,
    ) -> reqwest::Response {
        let mut req = reqwest::Client::new()
            .get(self.server.url(path))
            .query(query);
        if let Some(b) = bearer {
            req = req.bearer_auth(b);
        }
        req.send().await.unwrap()
    }

    fn checkpoint_rows(&self) -> i64 {
        self.state
            .audit
            .with_connection(|c| {
                Ok(c.query_row("SELECT COUNT(*) FROM checkpoints", [], |r| r.get(0))?)
            })
            .unwrap()
    }
}

/// One fixture record. `at` is 12:00 UTC plus the seq in seconds.
struct Row {
    kind: RecordKind,
    allow: bool,
    reason: &'static str,
    subject: &'static str,
    agent: &'static str,
    lease: &'static str,
    server: &'static str,
    tool: &'static str,
}

impl Row {
    fn record(&self, seq: u64) -> DecisionRecord {
        DecisionRecord {
            id: uuid::Uuid::new_v4(),
            at: datetime!(2026-10-23 12:00 UTC) + time::Duration::seconds(seq as i64),
            kind: self.kind,
            chain_id: Some(self.lease.to_string()),
            decision: if self.allow {
                Decision::Allow
            } else {
                Decision::Deny
            },
            reason: self.reason.into(),
            originating_subject: self.subject.into(),
            agents: vec![AgentId::new(self.agent)],
            chain_depth: 1,
            chain_digest: "digest".into(),
            leases: vec![LeaseId::new(self.lease)],
            server: self.server.into(),
            tool: self.tool.into(),
            arguments_digest: "args".into(),
            session_id: None,
            policy_ids: Vec::new(),
            dpop_bound: false,
            decision_id: None,
            result: None,
            labels: None,
            approval: None,
            budget: None,
            usage: None,
        }
    }
}

// A positional constructor keeps the fixture table one row per line.
#[allow(clippy::too_many_arguments)]
const fn row(
    kind: RecordKind,
    allow: bool,
    reason: &'static str,
    subject: &'static str,
    agent: &'static str,
    lease: &'static str,
    server: &'static str,
    tool: &'static str,
) -> Row {
    Row {
        kind,
        allow,
        reason,
        subject,
        agent,
        lease,
        server,
        tool,
    }
}

/// Agents `l1` and `l10` (a prefix match would mix them), leases and subjects with `_` (a
/// `LIKE` wildcard: `a_1` against `ab1`, `team_a` against `teamxa`), tools `50%` and `50x`.
const FIXTURE: [Row; 12] = {
    use RecordKind as K;
    [
        row(
            K::Decision,
            true,
            "policy_allow",
            "alice",
            "l1",
            "a_1",
            "github",
            "50%",
        ),
        row(
            K::Decision,
            false,
            "policy_deny",
            "bob",
            "l10",
            "ab1",
            "github",
            "50x",
        ),
        row(
            K::Exchange,
            true,
            "issued",
            "alice",
            "l1",
            "a_1",
            "attenuo",
            "token.exchange",
        ),
        row(
            K::Decision,
            false,
            "policy_deny",
            "team_a",
            "l1",
            "a_1",
            "slack",
            "50%",
        ),
        row(
            K::LeaseRenew,
            true,
            "renewed",
            "teamxa",
            "l10",
            "ab1",
            "attenuo",
            "lease.renew",
        ),
        row(
            K::Decision,
            true,
            "policy_allow",
            "alice",
            "l10",
            "ab1",
            "github",
            "50x",
        ),
        row(
            K::Decision,
            false,
            "lease_revoked",
            "bob",
            "l1",
            "a_1",
            "github",
            "read_file",
        ),
        row(
            K::Decision,
            false,
            "policy_deny",
            "team_a",
            "l1",
            "ab1",
            "slack",
            "read_file",
        ),
        row(
            K::Decision,
            true,
            "policy_allow",
            "alice",
            "l10",
            "a_1",
            "github",
            "50%",
        ),
        row(
            K::Exchange,
            true,
            "issued",
            "bob",
            "l1",
            "ab1",
            "attenuo",
            "token.exchange",
        ),
        row(
            K::Decision,
            false,
            "policy_deny",
            "teamxa",
            "l10",
            "a_1",
            "github",
            "read_file",
        ),
        row(
            K::Decision,
            true,
            "policy_allow",
            "alice",
            "l1",
            "ab1",
            "slack",
            "50%",
        ),
    ]
};

/// Seqs of the fixture rows that pass `keep`.
fn fixture_seqs(keep: impl Fn(&Row) -> bool) -> Vec<u64> {
    FIXTURE
        .iter()
        .enumerate()
        .filter(|(_, r)| keep(r))
        .map(|(i, _)| i as u64 + 1)
        .collect()
}

fn seqs_of(body: &Value) -> Vec<u64> {
    body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["seq"].as_u64().unwrap())
        .collect()
}

fn keys(body: &Value) -> BTreeSet<&str> {
    body.as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

#[tokio::test]
async fn without_new_parameters_the_page_is_unchanged() {
    let h = Harness::with_fixture().await;
    let (status, body) = h
        .get("/admin/audit", &[("from", "3"), ("limit", "4")])
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(keys(&body), BTreeSet::from(["entries", "next", "head"]));
    let expected = serde_json::to_value(h.state.audit.range(3, 4).unwrap()).unwrap();
    assert_eq!(body["entries"], expected);
    assert_eq!(body["next"], 7);
    assert_eq!(body["head"], 12);

    let (_, body) = h.get("/admin/audit", &[]).await;
    assert_eq!(seqs_of(&body), (1..=12).collect::<Vec<_>>());
    assert_eq!(body["next"], Value::Null);
    let (_, body) = h.get("/admin/audit", &[("order", "asc")]).await;
    assert_eq!(keys(&body), BTreeSet::from(["entries", "next", "head"]));
}

#[tokio::test]
async fn each_filter_returns_exactly_the_matching_entries() {
    let h = Harness::with_fixture().await;
    type Case = (Vec<(&'static str, &'static str)>, Vec<u64>);
    let cases: Vec<Case> = vec![
        (
            vec![("kind", "exchange,lease_renew")],
            fixture_seqs(|r| matches!(r.kind, RecordKind::Exchange | RecordKind::LeaseRenew)),
        ),
        (
            vec![("kind", "decision")],
            fixture_seqs(|r| r.kind == RecordKind::Decision),
        ),
        (vec![("decision", "deny")], fixture_seqs(|r| !r.allow)),
        (vec![("decision", "allow")], fixture_seqs(|r| r.allow)),
        (
            vec![("reason", "lease_revoked")],
            fixture_seqs(|r| r.reason == "lease_revoked"),
        ),
        (
            vec![("subject", "team_a")],
            fixture_seqs(|r| r.subject == "team_a"),
        ),
        (vec![("agent", "l1")], fixture_seqs(|r| r.agent == "l1")),
        (vec![("agent", "l10")], fixture_seqs(|r| r.agent == "l10")),
        (vec![("lease", "a_1")], fixture_seqs(|r| r.lease == "a_1")),
        (
            vec![("server", "slack")],
            fixture_seqs(|r| r.server == "slack"),
        ),
        (vec![("tool", "50%")], fixture_seqs(|r| r.tool == "50%")),
        (
            vec![("chain_id", "ab1")],
            fixture_seqs(|r| r.lease == "ab1"),
        ),
        (
            vec![
                ("since", "2026-10-23T12:00:04Z"),
                ("until", "2026-10-23T12:00:09Z"),
            ],
            vec![4, 5, 6, 7, 8],
        ),
        // The same instant written with another offset.
        (
            vec![("since", "2026-10-23T14:00:10+02:00")],
            vec![10, 11, 12],
        ),
        (
            vec![
                ("kind", "decision"),
                ("decision", "allow"),
                ("agent", "l10"),
            ],
            fixture_seqs(|r| r.kind == RecordKind::Decision && r.allow && r.agent == "l10"),
        ),
    ];
    for (query, want) in cases {
        assert!(!want.is_empty(), "{query:?} matches nothing in the fixture");
        let (status, body) = h.get("/admin/audit", &query).await;
        assert_eq!(status, StatusCode::OK, "{query:?}: {body}");
        assert_eq!(seqs_of(&body), want, "{query:?}");
        // Descending gives the same entries, newest first.
        let mut desc = query.clone();
        desc.push(("order", "desc"));
        let (_, body) = h.get("/admin/audit", &desc).await;
        let mut rev = want.clone();
        rev.reverse();
        assert_eq!(seqs_of(&body), rev, "{desc:?}");
    }
}

#[tokio::test]
async fn values_match_literally() {
    let h = Harness::with_fixture().await;
    // `l1` is not a prefix of `l10`, and the reverse.
    let (_, body) = h.get("/admin/audit", &[("agent", "l1")]).await;
    assert_eq!(seqs_of(&body), [1, 3, 4, 7, 8, 10, 12]);
    // `_` and `%` are characters, not wildcards.
    for (field, value) in [("subject", "team_a"), ("lease", "a_1"), ("tool", "50%")] {
        let (_, body) = h.get("/admin/audit", &[(field, value)]).await;
        let got = seqs_of(&body);
        for seq in &got {
            let r = &FIXTURE[*seq as usize - 1];
            let actual = match field {
                "subject" => r.subject,
                "lease" => r.lease,
                _ => r.tool,
            };
            assert_eq!(actual, value, "{field}={value} returned seq {seq}");
        }
        assert!(!got.is_empty());
    }
    for (field, value) in [
        ("agent", "l"),
        ("agent", "l_"),
        ("agent", "%"),
        ("lease", "a%"),
        ("subject", "team%"),
        ("tool", "50_"),
        ("server", "%"),
    ] {
        let (status, body) = h.get("/admin/audit", &[(field, value)]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(seqs_of(&body), Vec::<u64>::new(), "{field}={value}");
    }
}

/// Follow `next` (ascending) or `prev` (descending) until it is null; return every seq seen.
async fn page_through(
    h: &Harness,
    filter: &[(&'static str, &'static str)],
    desc: bool,
) -> Vec<u64> {
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..100 {
        let mut q: Vec<(&str, &str)> = filter.to_vec();
        q.push(("limit", "2"));
        if desc {
            q.push(("order", "desc"));
        }
        if let Some(c) = cursor.as_deref() {
            q.push((if desc { "before" } else { "from" }, c));
        }
        let (status, body) = h.get("/admin/audit", &q).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        seen.extend(seqs_of(&body));
        let link = if desc { &body["prev"] } else { &body["next"] };
        match link.as_u64() {
            Some(n) => cursor = Some(n.to_string()),
            None => return seen,
        }
    }
    panic!("paging did not end");
}

#[tokio::test]
async fn paging_both_ways_has_no_gaps_or_repeats() {
    let h = Harness::with_fixture().await;
    let all: Vec<u64> = (1..=12).collect();
    assert_eq!(page_through(&h, &[], false).await, all);
    let mut back = page_through(&h, &[], true).await;
    back.reverse();
    assert_eq!(back, all);

    let filter = [("agent", "l10")];
    let want = fixture_seqs(|r| r.agent == "l10");
    assert_eq!(page_through(&h, &filter, false).await, want);
    let mut back = page_through(&h, &filter, true).await;
    back.reverse();
    assert_eq!(back, want);

    // A descending page carries both links: `prev` goes on back, `next` reads forward.
    let (_, body) = h
        .get(
            "/admin/audit",
            &[("order", "desc"), ("before", "9"), ("limit", "3")],
        )
        .await;
    assert_eq!(
        keys(&body),
        BTreeSet::from(["entries", "next", "head", "prev"])
    );
    assert_eq!(seqs_of(&body), [8, 7, 6]);
    assert_eq!(body["prev"], 6);
    assert_eq!(body["next"], 9);
    let (_, body) = h
        .get("/admin/audit", &[("from", "9"), ("limit", "100")])
        .await;
    assert_eq!(seqs_of(&body), [9, 10, 11, 12]);
    // The newest page has nothing newer.
    let (_, body) = h
        .get("/admin/audit", &[("order", "desc"), ("limit", "3")])
        .await;
    assert_eq!(seqs_of(&body), [12, 11, 10]);
    assert_eq!(body["next"], Value::Null);
    // `before` past the head is the same as no `before`.
    let (_, body) = h
        .get("/admin/audit", &[("order", "desc"), ("before", "1000")])
        .await;
    assert_eq!(seqs_of(&body).len(), 12);
    assert_eq!(body["prev"], Value::Null);
}

/// A filtered page stops after `MAX_AUDIT_SCAN` seqs even when nothing matched, and says
/// where to go on. Most of the log here is filler rows written with SQL: they fail the
/// `agent` prefilter, so they are never decoded.
#[tokio::test]
async fn a_filtered_page_reads_a_bounded_window() {
    let h = Harness::start(Some(ADMIN)).await;
    let filler = attenuo_server::routes::admin::MAX_AUDIT_SCAN + 5;
    h.state
        .audit
        .with_connection(|c| {
            c.execute(
                "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?1) \
                 INSERT INTO audit SELECT i, 'p' || i, 'h' || i, '2026-10-23T12:00:00Z', \
                 'allow', 'r', 's', '[]', 0, 'd', '[]', 'srv', 't', 'a', NULL, '[]', '{}', \
                 'decision', NULL FROM n",
                [filler as i64],
            )?;
            Ok(())
        })
        .unwrap();
    // One real entry on top, so the head decodes.
    h.state.audit.append(FIXTURE[0].record(filler + 1)).unwrap();
    let head = filler + 1;
    let (status, body) = h.get("/admin/audit", &[("agent", "l1")]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(seqs_of(&body), Vec::<u64>::new());
    let window = attenuo_server::routes::admin::MAX_AUDIT_SCAN;
    assert_eq!(body["next"], window + 1);
    let next = (window + 1).to_string();
    let (_, body) = h
        .get("/admin/audit", &[("agent", "l1"), ("from", &next)])
        .await;
    assert_eq!(seqs_of(&body), [head]);
    assert_eq!(body["next"], Value::Null);

    let (_, body) = h
        .get(
            "/admin/audit",
            &[("agent", "l1"), ("order", "desc"), ("limit", "5")],
        )
        .await;
    assert_eq!(seqs_of(&body), [head]);
    let prev = head - window + 1;
    assert_eq!(body["prev"], prev);
    let before = prev.to_string();
    let (_, body) = h
        .get(
            "/admin/audit",
            &[("agent", "l1"), ("order", "desc"), ("before", &before)],
        )
        .await;
    assert_eq!(seqs_of(&body), Vec::<u64>::new());
    assert_eq!(body["prev"], Value::Null);
}

#[tokio::test]
async fn bad_parameters_are_400() {
    let h = Harness::with_fixture().await;
    for query in [
        vec![("kind", "decisions")],
        vec![("kind", "decision,")],
        vec![("decision", "maybe")],
        vec![("order", "sideways")],
        vec![("since", "yesterday")],
        vec![("until", "2026-10-23")],
        vec![("agent", "")],
        vec![("chain_id", "")],
        vec![("before", "5")],
        vec![("order", "desc"), ("from", "5")],
        vec![("order", "desc"), ("before", "0")],
    ] {
        let (status, body) = h.get("/admin/audit", &query).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query:?}");
        assert_eq!(body["error"], "invalid_request", "{query:?}");
    }
    let (status, _) = h.get("/admin/audit/checkpoints", &[("before", "0")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn one_entry_by_seq_or_by_record_id() {
    let h = Harness::with_fixture().await;
    let leases = &h.state.leases;
    let far = datetime!(2099-01-01 00:00 UTC);
    leases.register(&LeaseId::new("ab1"), None, far).unwrap();
    leases
        .revoke(
            &LeaseId::new("ab1"),
            "test",
            time::OffsetDateTime::now_utc(),
        )
        .unwrap();
    leases.register(&LeaseId::new("a_1"), None, far).unwrap();
    // Sign the head (seq 12), then record a policy reload after it.
    let (status, _) = h.get("/admin/audit/checkpoint", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let mut reload = FIXTURE[0].record(13);
    reload.kind = RecordKind::Admin;
    reload.server = "attenuo".into();
    reload.tool = "admin.policies.reload".into();
    h.state.audit.append(reload).unwrap();

    let (status, body) = h.get("/admin/audit/entries/2", &[]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let entry = &h.state.audit.range(2, 1).unwrap()[0];
    assert_eq!(body["entry"], serde_json::to_value(entry).unwrap());
    assert_eq!(body["lease_states"][0]["lease_id"], "ab1");
    assert_eq!(body["lease_states"][0]["known"], true);
    assert_eq!(body["lease_states"][0]["active"], false);
    assert_eq!(body["lease_states"][0]["revoke_reason"], "test");
    assert_eq!(body["covered_by_checkpoint"]["seq"], 12);
    assert_eq!(body["policy_reloaded_after"], 13);

    let id = entry.record.id.to_string();
    let (status, by_id) = h.get(&format!("/admin/audit/records/{id}"), &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(by_id, body);
    // Upper case is the same UUID.
    let (status, upper) = h
        .get(&format!("/admin/audit/records/{}", id.to_uppercase()), &[])
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(upper, body);

    let (_, one) = h.get("/admin/audit/entries/1", &[]).await;
    assert_eq!(one["lease_states"][0]["lease_id"], "a_1");
    assert_eq!(one["lease_states"][0]["active"], true);
    // The newest entry: not covered yet, and nothing after it.
    let (_, last) = h.get("/admin/audit/entries/13", &[]).await;
    assert_eq!(last["covered_by_checkpoint"], Value::Null);
    assert_eq!(last["policy_reloaded_after"], Value::Null);
    // A lease the registry never saw.
    let mut stray = FIXTURE[0].record(14);
    stray.leases = vec![LeaseId::new("nowhere")];
    h.state.audit.append(stray).unwrap();
    let (_, s) = h.get("/admin/audit/entries/14", &[]).await;
    assert_eq!(s["lease_states"][0]["known"], false);
    assert_eq!(s["lease_states"][0]["active"], false);
}

#[tokio::test]
async fn unknown_entries_are_404_and_malformed_ids_400() {
    let h = Harness::with_fixture().await;
    for path in [
        "/admin/audit/entries/13".to_string(),
        "/admin/audit/entries/0".to_string(),
        format!("/admin/audit/records/{}", uuid::Uuid::new_v4()),
    ] {
        let (status, body) = h.get(&path, &[]).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(body["error"], "not_found", "{path}");
    }
    let (status, body) = h.get("/admin/audit/records/not-a-uuid", &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn listing_checkpoints_never_signs_one() {
    let h = Harness::with_fixture().await;
    assert_eq!(h.checkpoint_rows(), 0);
    let (_, body) = h.get("/admin/audit/checkpoints", &[]).await;
    assert_eq!(body["checkpoints"], Value::Array(Vec::new()));
    assert_eq!(
        h.checkpoint_rows(),
        0,
        "an empty listing must not sign the head"
    );

    // Two checkpoints (at 12 and 13), then an unsigned head (14).
    h.get("/admin/audit/checkpoint", &[]).await;
    h.state.audit.append(FIXTURE[0].record(13)).unwrap();
    h.get("/admin/audit/checkpoint", &[]).await;
    h.state.audit.append(FIXTURE[0].record(14)).unwrap();
    assert_eq!(h.checkpoint_rows(), 2);

    let (status, body) = h.get("/admin/audit/checkpoints", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let seqs: Vec<u64> = body["checkpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, [13, 12]);
    assert_eq!(body["prev"], Value::Null);
    for field in ["seq", "head_hash", "at", "kid", "signature"] {
        assert!(body["checkpoints"][0].get(field).is_some(), "{field}");
    }
    let (_, page) = h.get("/admin/audit/checkpoints", &[("limit", "1")]).await;
    assert_eq!(page["checkpoints"][0]["seq"], 13);
    assert_eq!(page["prev"], 13);
    let (_, page) = h
        .get(
            "/admin/audit/checkpoints",
            &[("limit", "1"), ("before", "13")],
        )
        .await;
    assert_eq!(page["checkpoints"][0]["seq"], 12);
    assert_eq!(h.checkpoint_rows(), 2, "listing must not sign");
}

#[tokio::test]
async fn admin_answers_carry_no_store_and_nosniff() {
    let h = Harness::with_fixture().await;
    for (path, bearer, status) in [
        ("/admin/audit", Some(ADMIN), StatusCode::OK),
        ("/admin/audit/entries/1", Some(ADMIN), StatusCode::OK),
        (
            "/admin/audit/entries/99",
            Some(ADMIN),
            StatusCode::NOT_FOUND,
        ),
        ("/admin/audit/checkpoints", Some(ADMIN), StatusCode::OK),
        ("/admin/audit/export", Some(ADMIN), StatusCode::OK),
        ("/admin/leases/nope", Some(ADMIN), StatusCode::NOT_FOUND),
        ("/admin/audit", None, StatusCode::UNAUTHORIZED),
    ] {
        let r = h.send(path, &[], bearer).await;
        assert_eq!(r.status(), status, "{path}");
        assert_eq!(r.headers()[CACHE_CONTROL], "no-store", "{path}");
        assert_eq!(r.headers()[X_CONTENT_TYPE_OPTIONS], "nosniff", "{path}");
    }
}

#[tokio::test]
async fn the_new_routes_need_the_admin_bearer() {
    let h = Harness::with_fixture().await;
    let paths = [
        "/admin/audit",
        "/admin/audit/entries/1",
        "/admin/audit/records/00000000-0000-0000-0000-000000000000",
        "/admin/audit/checkpoints",
    ];
    for path in paths {
        for bearer in [None, Some("wrong-token")] {
            let r = h.send(path, &[], bearer).await;
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{path} {bearer:?}");
            assert_eq!(
                r.headers()[WWW_AUTHENTICATE],
                "Bearer realm=\"attenuo-admin\""
            );
            let body: Value = r.json().await.unwrap();
            assert_eq!(body["error"], "unauthorized");
            assert!(body.get("entries").is_none());
        }
    }

    let h = Harness::start(None).await;
    for path in paths {
        let r = h.send(path, &[], Some(ADMIN)).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "{path}");
        assert_eq!(r.headers()[X_CONTENT_TYPE_OPTIONS], "nosniff");
        let body: Value = r.json().await.unwrap();
        assert_eq!(body["error"], "admin_disabled");
    }
}
