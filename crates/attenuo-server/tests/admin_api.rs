//! The audit query API: `GET /admin/audit` filters and cursor paging both ways, the
//! single-entry routes, the read-only checkpoint list, and the headers every admin answer
//! carries.
//!
//! The fixture appends records straight to the server's audit store, so every field is known
//! and the expected pages are computed from the fixture table, not from the filter code.

use std::collections::BTreeSet;
use std::sync::Arc;

use attenuo_audit::{AuditSink, LeaseRegistry};
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
async fn a_page_is_entries_next_cursor_and_head() {
    let h = Harness::with_fixture().await;
    let (status, body) = h
        .get("/admin/audit", &[("from", "3"), ("limit", "4")])
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        keys(&body),
        BTreeSet::from(["entries", "next_cursor", "head"])
    );
    let expected = serde_json::to_value(h.state.audit.range(3, 4).unwrap()).unwrap();
    assert_eq!(body["entries"], expected);
    assert_eq!(body["head"], 12);
    let cursor = body["next_cursor"].as_str().unwrap().to_string();
    let (_, body) = h
        .get(
            "/admin/audit",
            &[("from", "3"), ("limit", "4"), ("cursor", &cursor)],
        )
        .await;
    assert_eq!(seqs_of(&body), [7, 8, 9, 10]);

    // Without parameters: the whole (small) log, and nothing after it.
    let (_, body) = h.get("/admin/audit", &[]).await;
    assert_eq!(seqs_of(&body), (1..=12).collect::<Vec<_>>());
    assert_eq!(body["next_cursor"], Value::Null);
    // A page that ends exactly at the head says so: no cursor to an empty page.
    let (_, body) = h
        .get("/admin/audit", &[("from", "9"), ("limit", "4")])
        .await;
    assert_eq!(seqs_of(&body), [9, 10, 11, 12]);
    assert_eq!(body["next_cursor"], Value::Null);
    let (_, body) = h
        .get("/admin/audit", &[("order", "desc"), ("limit", "12")])
        .await;
    assert_eq!(body["next_cursor"], Value::Null);
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

/// Follow `next_cursor` until it is null, with `limit=2` and the same filter (and `order`)
/// on every page; return every seq seen. `between` runs after each page but the last.
async fn page_through_with(
    h: &Harness,
    filter: &[(&'static str, &'static str)],
    desc: bool,
    mut between: impl FnMut(),
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
            q.push(("cursor", c));
        }
        let (status, body) = h.get("/admin/audit", &q).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        seen.extend(seqs_of(&body));
        match body["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => return seen,
        }
        between();
    }
    panic!("paging did not end");
}

async fn page_through(
    h: &Harness,
    filter: &[(&'static str, &'static str)],
    desc: bool,
) -> Vec<u64> {
    page_through_with(h, filter, desc, || {}).await
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

    // `from` and `to` select a range in either order, and the cursor stays inside it.
    let range = [("from", "4"), ("to", "9")];
    assert_eq!(page_through(&h, &range, false).await, [4, 5, 6, 7, 8, 9]);
    assert_eq!(page_through(&h, &range, true).await, [9, 8, 7, 6, 5, 4]);
    let ranged = [("from", "2"), ("to", "11"), ("agent", "l10")];
    let want: Vec<u64> = fixture_seqs(|r| r.agent == "l10")
        .into_iter()
        .filter(|s| (2..=11).contains(s))
        .collect();
    assert_eq!(page_through(&h, &ranged, false).await, want);
    // `to` past the head is the same as no `to`.
    let (_, body) = h
        .get("/admin/audit", &[("order", "desc"), ("to", "1000")])
        .await;
    assert_eq!(seqs_of(&body).len(), 12);
    assert_eq!(body["next_cursor"], Value::Null);
    // A range above the head is empty.
    let (status, body) = h.get("/admin/audit", &[("from", "13")]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(seqs_of(&body), Vec::<u64>::new());
    assert_eq!(body["next_cursor"], Value::Null);
}

/// Entries appended while a client pages do not shift the entries it has not read yet: newest
/// first, the new ones sort above the first page and are not seen; oldest first, they come
/// after everything that was there, once each.
#[tokio::test]
async fn appends_during_paging_cause_no_repeats_or_gaps() {
    let h = Harness::with_fixture().await;
    let head = |h: &Harness| h.state.audit.head().unwrap().unwrap().seq;
    let state = h.state.clone();
    let mut next = 13u64;
    let back = page_through_with(&h, &[], true, || {
        state.audit.append(FIXTURE[1].record(next)).unwrap();
        next += 1;
    })
    .await;
    assert_eq!(back, (1..=12).rev().collect::<Vec<_>>());
    assert!(head(&h) > 12, "entries were appended while paging");

    let before = head(&h);
    let state = h.state.clone();
    let mut next = before + 1;
    let forward = page_through_with(&h, &[], false, || {
        state.audit.append(FIXTURE[1].record(next)).unwrap();
        next += 1;
    })
    .await;
    // Every entry that existed, in order, once; then each one appended while paging, once.
    assert!(head(&h) > before);
    assert_eq!(forward, (1..=head(&h)).collect::<Vec<_>>());
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
    // Short (empty) but not the end: the cursor goes on past the window read.
    let next = body["next_cursor"].as_str().unwrap().to_string();
    let (_, body) = h
        .get("/admin/audit", &[("agent", "l1"), ("cursor", &next)])
        .await;
    assert_eq!(seqs_of(&body), [head]);
    assert_eq!(body["next_cursor"], Value::Null);

    let (_, body) = h
        .get(
            "/admin/audit",
            &[("agent", "l1"), ("order", "desc"), ("limit", "5")],
        )
        .await;
    assert_eq!(seqs_of(&body), [head]);
    let prev = body["next_cursor"].as_str().unwrap().to_string();
    let (_, body) = h
        .get(
            "/admin/audit",
            &[("agent", "l1"), ("order", "desc"), ("cursor", &prev)],
        )
        .await;
    assert_eq!(seqs_of(&body), Vec::<u64>::new());
    assert_eq!(body["next_cursor"], Value::Null);
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
        // Removed paging parameters are refused, not ignored.
        vec![("before", "5")],
        vec![("order", "desc"), ("before", "0")],
        vec![("from", "0")],
        vec![("to", "0")],
        vec![("from", "5"), ("to", "4")],
        // Out-of-range limits are refused, not clamped.
        vec![("limit", "0")],
        vec![("limit", "1001")],
    ] {
        let (status, body) = h.get("/admin/audit", &query).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query:?}");
        assert_eq!(body["error"], "invalid_request", "{query:?}");
    }
    let (status, _) = h.get("/admin/audit", &[("limit", "1000")]).await;
    assert_eq!(status, StatusCode::OK);
    for query in [
        vec![("before", "0")],
        vec![("limit", "0")],
        vec![("limit", "1001")],
    ] {
        let (status, body) = h.get("/admin/audit/checkpoints", &query).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query:?}");
        assert_eq!(body["error"], "invalid_request", "{query:?}");
    }
}

#[tokio::test]
async fn malformed_or_foreign_cursors_are_400_invalid_cursor() {
    let h = Harness::with_fixture().await;
    let (_, asc) = h.get("/admin/audit", &[("limit", "2")]).await;
    let asc = asc["next_cursor"].as_str().unwrap().to_string();
    let (_, desc) = h
        .get("/admin/audit", &[("limit", "2"), ("order", "desc")])
        .await;
    let desc = desc["next_cursor"].as_str().unwrap().to_string();
    assert_ne!(asc, desc);
    // The cursor carries no filter value: the same page position under a filter on a
    // subject gives the same cursor as without it.
    let (_, filtered) = h
        .get("/admin/audit", &[("limit", "1"), ("subject", "alice")])
        .await;
    let c = filtered["next_cursor"].as_str().unwrap();
    assert!(!c.contains("alice"));

    let mut tampered = asc.clone().into_bytes();
    tampered[0] = if tampered[0] == b'B' { b'C' } else { b'B' };
    let tampered = String::from_utf8(tampered).unwrap();
    let cases: Vec<(&str, Vec<(&str, &str)>)> = vec![
        ("/admin/audit", vec![("cursor", "")]),
        ("/admin/audit", vec![("cursor", "not-a-cursor")]),
        ("/admin/audit", vec![("cursor", "%%%")]),
        ("/admin/audit", vec![("cursor", &tampered)]),
        // Issued for the other order.
        ("/admin/audit", vec![("cursor", &desc)]),
        ("/admin/audit", vec![("cursor", &asc), ("order", "desc")]),
        // Issued by another list.
        ("/admin/audit/checkpoints", vec![("cursor", &desc)]),
        ("/admin/approvals", vec![("cursor", &desc)]),
    ];
    for (path, query) in cases {
        let (status, body) = h.get(path, &query).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path} {query:?}: {body}");
        assert_eq!(body["error"], "invalid_cursor", "{path} {query:?}");
        let detail = body["detail"].as_str().unwrap();
        for (_, v) in &query {
            assert!(v.len() < 4 || !detail.contains(v), "{detail} quotes {v}");
        }
    }
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
    assert_eq!(body["next_cursor"], Value::Null);
    for field in ["seq", "head_hash", "at", "kid", "signature"] {
        assert!(body["checkpoints"][0].get(field).is_some(), "{field}");
    }
    let (_, page) = h.get("/admin/audit/checkpoints", &[("limit", "1")]).await;
    assert_eq!(page["checkpoints"][0]["seq"], 13);
    let cursor = page["next_cursor"].as_str().unwrap().to_string();
    // A checkpoint signed while paging sorts above the first page and does not shift it.
    h.state.audit.append(FIXTURE[0].record(15)).unwrap();
    h.get("/admin/audit/checkpoint", &[]).await;
    let (_, page) = h
        .get(
            "/admin/audit/checkpoints",
            &[("limit", "1"), ("cursor", &cursor)],
        )
        .await;
    assert_eq!(page["checkpoints"][0]["seq"], 12);
    assert_eq!(page["next_cursor"], Value::Null, "12 is the oldest");
    assert_eq!(h.checkpoint_rows(), 3, "listing must not sign");
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

/// Approvals created straight in the store: `runs` runs (root leases `run0`, `run1`, ...) of
/// `per_run` approvals each, created round-robin, every one decided at once (even index
/// granted, odd declined) so no run reaches the pending cap. Returns the ids in creation
/// order.
fn seed_approvals(h: &Harness, runs: usize, per_run: usize, first: usize) -> Vec<String> {
    use attenuo_audit::{Approval, ApprovalMethod, ApprovalState, ApprovalStore, Approver};
    use attenuo_core::{Capability, CapabilitySet, DelegationChain, OriginatingUser};
    let now = time::OffsetDateTime::now_utc();
    let far = datetime!(2099-01-01 00:00 UTC);
    let mut ids = Vec::new();
    for i in first..first + runs * per_run {
        let run = format!("run{}", i % runs);
        let lease = LeaseId::new(&run);
        h.state.leases.register(&lease, None, far).unwrap();
        let chain = DelegationChain::root(
            OriginatingUser {
                subject: "alice".into(),
                issuer: "https://idp.example".into(),
                authenticated_at: now,
                attributes: Default::default(),
            },
            AgentId::new("planner"),
            CapabilitySet::from_iter(vec![Capability::new("github", "*")]),
            now,
            time::Duration::hours(1),
            lease.clone(),
        )
        .unwrap();
        let a = Approval {
            id: uuid::Uuid::new_v4().to_string(),
            chain_id: lease.clone(),
            lease,
            call_hash: format!("{i:064x}"),
            server: "github".into(),
            tool: "delete_repo".into(),
            arguments: serde_json::json!({ "n": i }),
            labels: Vec::new(),
            untrusted_args: Vec::new(),
            decision_id: uuid::Uuid::new_v4().to_string(),
            chain,
            created_at: now,
            expires_at: now + time::Duration::minutes(10),
            state: ApprovalState::Pending,
            approver: None,
            decided_at: None,
            consumed_by: None,
            jkt: None,
        };
        let (a, created) = h.state.leases.create_approval(&a).unwrap();
        assert!(created);
        let approver = Approver {
            subject: "urn:attenuo:admin".into(),
            method: ApprovalMethod::AdminToken,
        };
        h.state
            .leases
            .decide_approval(&a.id, i.is_multiple_of(2), &approver, now)
            .unwrap();
        ids.push(a.id);
    }
    ids
}

/// Follow `next_cursor` of `GET /admin/approvals` with `query` until it is null; the ids seen.
async fn approval_pages(
    h: &Harness,
    query: &[(&str, &str)],
    mut between: impl FnMut(),
) -> Vec<String> {
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..1000 {
        let mut q = query.to_vec();
        if let Some(c) = cursor.as_deref() {
            q.push(("cursor", c));
        }
        let (status, body) = h.get("/admin/approvals", &q).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(keys(&body), BTreeSet::from(["approvals", "next_cursor"]));
        seen.extend(
            body["approvals"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a["approval_id"].as_str().unwrap().to_string()),
        );
        match body["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => return seen,
        }
        between();
    }
    panic!("paging did not end");
}

/// K-7: the list stopped at the newest 500. Every approval is reachable now, newest first,
/// once each, under the filters, and approvals created while paging do not shift the rest.
#[tokio::test]
async fn every_approval_is_reachable_past_500() {
    let h = Harness::with_fixture().await;
    let mut ids = seed_approvals(&h, 3, 220, 0);
    ids.reverse();
    assert_eq!(ids.len(), 660);

    // The default page (100) and the largest (500) both reach every one.
    assert_eq!(approval_pages(&h, &[], || {}).await, ids);
    assert_eq!(approval_pages(&h, &[("limit", "500")], || {}).await, ids);
    let (_, first) = h.get("/admin/approvals", &[]).await;
    assert_eq!(first["approvals"].as_array().unwrap().len(), 100);

    // New approvals while paging sort above the first page.
    let mut next = 10_000;
    let state_h = &h;
    let mut added = 0;
    let got = approval_pages(&h, &[("limit", "250")], || {
        seed_approvals(state_h, 1, 1, next);
        next += 1;
        added += 1;
    })
    .await;
    assert_eq!(got, ids);
    assert_eq!(added, 2);

    // chain_id and state still filter, before the limit, with the cursor.
    let want: Vec<String> = ids
        .iter()
        .enumerate()
        .filter(|(k, _)| {
            let i = 659 - k;
            i % 3 == 1 && i.is_multiple_of(2)
        })
        .map(|(_, id)| id.clone())
        .collect();
    assert_eq!(want.len(), 110);
    let got = approval_pages(
        &h,
        &[("chain_id", "run1"), ("state", "granted"), ("limit", "7")],
        || {},
    )
    .await;
    assert_eq!(got, want);

    for limit in ["0", "501"] {
        let (status, body) = h.get("/admin/approvals", &[("limit", limit)]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{limit}");
        assert_eq!(body["error"], "invalid_request");
    }
    let (status, body) = h
        .get("/admin/approvals", &[("cursor", "AAAAAAAAAAAAAAA")])
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_cursor");
}
