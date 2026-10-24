//! The server's request bodies over HTTP (`attenuo_server::router`, through
//! `tower::ServiceExt::oneshot`): `POST /access/v1/evaluation` and `/access/v1/evaluations`
//! (AuthZEN, with a valid bearer token whose root hop carries run limits, so the arguments
//! reach `charges_for` and run usage), `POST /approvals/{id}` and `POST /admin/approvals/{id}`
//! (decision bodies, ids, authorization headers). The first campaign fuzzed the AuthZEN shape
//! only through `PolicyEngine::evaluate`, not the routes.
//!
//! Properties beyond "no panic":
//!
//! - no 5xx answer;
//! - an allowed evaluation has reason `policy_allow`, and a batch answers one result per entry;
//! - a decision on an approval that does not exist never succeeds.
#![no_main]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use arbitrary::{Result, Unstructured};
use attenuo_audit::LeaseStore;
use attenuo_core::limits::MAX_COUNTED_VALUES;
use attenuo_core::{AgentId, ArgLimit, Capability, CapabilitySet, Derive, Limits, OriginatingUser};
use attenuo_fuzz::{edge_number, edge_string, json_value};
use attenuo_policy::ToolAttrs;
use attenuo_server::{AppState, Config};
use attenuo_token::approval::ApprovalGrant;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use libfuzzer_sys::fuzz_target;
use serde_json::{json, Map, Value};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;

const ADMIN: &str = "fuzz-admin-token";
/// Inputs served by one server before it is rebuilt, so the in-memory audit log stays small.
const REBUILD_EVERY: u32 = 400;

const POLICY: &str = r#"
@id("allow")
permit(principal, action, resource);

@id("usage_cap")
forbid(principal, action == Action::"bank/send", resource)
when { context.usage.calls >= 50 || context.usage.amount > 100000 };

@id("ask")
@obligation("approval")
forbid(principal, action == Action::"bank/delete", resource)
when { !context.approval.present };
"#;

struct Server {
    router: Router,
    state: Arc<AppState>,
    token: String,
    chain: Value,
    served: u32,
}

fn dir() -> &'static std::path::Path {
    static D: OnceLock<std::path::PathBuf> = OnceLock::new();
    D.get_or_init(|| {
        let d = std::env::temp_dir().join(format!("attenuo-fuzz-http-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("policies.cedar"), POLICY).unwrap();
        d
    })
}

fn build() -> Server {
    let mut cfg = Config::default();
    cfg.issuer.issuer = "https://attenuo.fuzz".into();
    cfg.issuer.audience = "attenuo-fuzz".into();
    cfg.issuer.private_key_pem_path = None;
    cfg.audit.sqlite_path = ":memory:".into();
    cfg.policy.policies_path = Some(dir().join("policies.cedar"));
    cfg.policy.catalog = BTreeMap::from([(
        "bank".to_string(),
        BTreeMap::from([
            (
                "send".to_string(),
                ToolAttrs::new()
                    .destructive(true)
                    .with_amount("amount")
                    .with_destination("to#host"),
            ),
            ("delete".to_string(), ToolAttrs::new().destructive(true)),
            ("read".to_string(), ToolAttrs::new().readonly(true)),
        ]),
    )]);
    cfg.admin.token = Some(ADMIN.into());
    let (router, state) = attenuo_server::build(&cfg).expect("server builds");
    let now = OffsetDateTime::now_utc();
    let limits = Limits {
        calls: Some(1_000_000),
        sum: Some(ArgLimit::new("amount", 1_000_000_000)),
        calls_per: Some(ArgLimit::new("to", 1_000_000)),
        distinct: Some(ArgLimit::new("url", 1_000_000).derived(Derive::Host)),
    };
    let issued = state
        .issuer
        .issue_root(
            OriginatingUser {
                subject: "user:mudit".into(),
                issuer: "https://idp.example".into(),
                authenticated_at: now,
                attributes: BTreeMap::new(),
            },
            AgentId::new("agent:planner"),
            CapabilitySet::from_iter([
                Capability::new("bank", "send").with_limits(limits),
                Capability::new("bank", "*"),
            ]),
            Some(Duration::days(1)),
            now,
        )
        .expect("root token issues");
    state
        .leases
        .register(&issued.lease, None, now + Duration::days(1))
        .expect("lease registers");
    Server {
        router,
        token: issued.token,
        chain: serde_json::to_value(&issued.chain).unwrap(),
        state,
        served: 0,
    }
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static R: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    R.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    })
}

thread_local! {
    static SERVER: RefCell<Option<Server>> = const { RefCell::new(None) };
}

#[derive(Debug, Clone, Copy)]
enum Auth {
    Bearer,
    DpopScheme,
    Garbage,
    Basic,
    Admin,
    None,
}

#[derive(Debug)]
enum Body_ {
    Raw(Vec<u8>),
    Json(Value),
}

#[derive(Debug)]
enum Route {
    Evaluation(Body_),
    Evaluations(Body_, Option<usize>),
    UserDecide(String, Body_),
    AdminDecide(String, Body_),
}

#[derive(Debug)]
struct Input {
    auth: Auth,
    garbage: String,
    route: Route,
}

const TOOLS: &[&str] = &["send", "delete", "read", "unknown", "", "send/x"];

fn arguments(u: &mut Unstructured<'_>) -> Result<Value> {
    let mut m = Map::new();
    for _ in 0..u.int_in_range(0usize..=5)? {
        let k = *u.choose(&["amount", "to", "url", "memo", "__entity", ""])?;
        let v = match u.int_in_range(0u8..=5)? {
            0 => edge_number(u)?,
            1 => json!(format!("https://{}/x", edge_string(u)?)),
            2 => {
                let n = MAX_COUNTED_VALUES - 1 + u.int_in_range(0usize..=2)?;
                Value::Array(
                    (0..n)
                        .map(|i| json!(format!("https://h{i}.example/")))
                        .collect(),
                )
            }
            3 => json!(u.int_in_range(0u64..=10)?),
            _ => json_value(u, 4)?,
        };
        m.insert(k.into(), v);
    }
    Ok(Value::Object(m))
}

/// Set `v[a][b]`, making `v[a]` an object first if an earlier edit replaced it.
fn put(v: &mut Value, a: &str, b: &str, x: Value) {
    if !v[a].is_object() {
        v[a] = json!({});
    }
    v[a][b] = x;
}

/// An AuthZEN evaluation object, mostly well formed, with edits.
fn evaluation(u: &mut Unstructured<'_>, approval_token: &dyn Fn(&str) -> String) -> Result<Value> {
    let tool = *u.choose(TOOLS)?;
    let mut v = json!({
        "subject": {"type": "agent", "id": ""},
        "action": {"name": tool},
        "resource": {"type": "tool", "id": format!("bank/{tool}")},
        "context": {"input": arguments(u)?},
    });
    for _ in 0..u.int_in_range(0usize..=3)? {
        match u.int_in_range(0u8..=9)? {
            0 => put(&mut v, "subject", "type", Value::String(edge_string(u)?)),
            1 => put(&mut v, "subject", "id", Value::String(edge_string(u)?)),
            2 => put(
                &mut v,
                "subject",
                "properties",
                json!({"chain": json_value(u, 3)?}),
            ),
            3 => put(
                &mut v,
                "action",
                "properties",
                json!({"server": edge_string(u)?}),
            ),
            4 => put(&mut v, "resource", "id", Value::String(edge_string(u)?)),
            5 => put(
                &mut v,
                "context",
                "approval_token",
                json!(approval_token(&edge_string(u)?)),
            ),
            6 => put(&mut v, "context", "approval_token", json_value(u, 1)?),
            7 => put(&mut v, "context", "session_id", json_value(u, 1)?),
            8 => {
                v["pep_id"] = Value::String(edge_string(u)?);
                v["pep_secret"] = Value::String(edge_string(u)?);
            }
            _ => v["context"] = json_value(u, 3)?,
        }
    }
    Ok(v)
}

fn body(
    u: &mut Unstructured<'_>,
    json: impl FnOnce(&mut Unstructured<'_>) -> Result<Value>,
) -> Result<Body_> {
    Ok(if u.ratio(1u8, 6u8)? {
        Body_::Raw(u.arbitrary()?)
    } else {
        Body_::Json(json(u)?)
    })
}

fn decide_body(u: &mut Unstructured<'_>) -> Result<Value> {
    Ok(match u.int_in_range(0u8..=4)? {
        0 => json!({"decision": *u.choose(&["grant", "decline", "Grant", "", "grant\u{0}"])?}),
        1 => json!({"decision": "grant", "extra": json_value(u, 1)?}),
        2 => json!({"decision": json_value(u, 1)?}),
        _ => json_value(u, 2)?,
    })
}

fn id(u: &mut Unstructured<'_>) -> Result<String> {
    Ok(match u.int_in_range(0u8..=2)? {
        0 => "00000000-0000-4000-8000-000000000001".into(),
        1 => uuid::Uuid::from_u128(u.arbitrary()?).to_string(),
        _ => edge_string(u)?,
    })
}

/// A valid approval token from the server's issuer for a call and approval id that may or may
/// not exist, or garbage.
fn approval_token_for<'a>(state: &'a AppState, chain: &Value) -> impl Fn(&str) -> String + 'a {
    let chain_id = chain
        .pointer("/hops/0/lease")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    move |id: &str| {
        let now = OffsetDateTime::now_utc();
        state
            .issuer
            .issue_approval(&ApprovalGrant {
                approval_id: id,
                approver: "user:mudit",
                by: "user",
                chain_id: &chain_id,
                lease: &chain_id,
                call_hash: id,
                granted_at: now,
                expires_at: now + Duration::minutes(5),
                jkt: None,
            })
            .unwrap_or_else(|_| id.to_string())
    }
}

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

impl Input {
    fn generate(u: &mut Unstructured<'_>, server: &Server) -> Result<Self> {
        let tok = approval_token_for(&server.state, &server.chain);
        let auth = match u.int_in_range(0u8..=7)? {
            0..=3 => Auth::Bearer,
            4 => Auth::DpopScheme,
            5 => Auth::Garbage,
            6 => Auth::Basic,
            _ => {
                if u.arbitrary()? {
                    Auth::Admin
                } else {
                    Auth::None
                }
            }
        };
        let route = match u.int_in_range(0u8..=5)? {
            0 | 1 => Route::Evaluation(body(u, |u| evaluation(u, &tok))?),
            2 | 3 => {
                let n = u.int_in_range(0usize..=4)?;
                let mut count = None;
                let b = body(u, |u| {
                    let items: Vec<Value> = (0..n)
                        .map(|_| {
                            if u.ratio(1u8, 6u8)? {
                                json_value(u, 1)
                            } else {
                                evaluation(u, &tok)
                            }
                        })
                        .collect::<Result<_>>()?;
                    count = Some(items.len());
                    let mut v = json!({
                        "subject": {"type": "agent", "id": ""},
                        "evaluations": items,
                    });
                    if u.ratio(1u8, 4u8)? {
                        v["options"] = json!({"evaluations_semantic": edge_string(u)?});
                    }
                    Ok(v)
                })?;
                Route::Evaluations(b, count)
            }
            4 => Route::UserDecide(id(u)?, body(u, decide_body)?),
            _ => Route::AdminDecide(id(u)?, body(u, decide_body)?),
        };
        Ok(Input {
            auth,
            garbage: edge_string(u)?,
            route,
        })
    }
}

fn send(
    server: &Server,
    path: &str,
    auth: Auth,
    garbage: &str,
    body: &Body_,
) -> Option<(StatusCode, Value)> {
    let mut req = Request::builder().method("POST").uri(path);
    let value = match auth {
        Auth::Bearer => Some(format!("Bearer {}", server.token)),
        Auth::DpopScheme => Some(format!("DPoP {}", server.token)),
        Auth::Garbage => Some(format!("Bearer {garbage}")),
        Auth::Basic => Some(format!("Basic {garbage}")),
        Auth::Admin => Some(format!("Bearer {ADMIN}")),
        Auth::None => None,
    };
    if let Some(v) = value {
        req = req.header("authorization", v);
    }
    let bytes = match body {
        Body_::Raw(b) => b.clone(),
        Body_::Json(v) => serde_json::to_vec(v).unwrap(),
    };
    let req = req
        .header("content-type", "application/json")
        .body(Body::from(bytes))
        .ok()?;
    let resp = runtime().block_on(async {
        let resp = server
            .router
            .clone()
            .oneshot(req)
            .await
            .expect("infallible");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 16 << 20)
            .await
            .expect("body reads");
        (status, bytes)
    });
    let (status, bytes) = resp;
    assert!(
        !status.is_server_error(),
        "{path} answered {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    Some((
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    ))
}

fn check_evaluation(v: &Value) {
    if v["decision"] == json!(true) {
        assert_eq!(
            v["context"]["reason"],
            json!(attenuo_policy::REASON_POLICY_ALLOW),
            "allowed without policy_allow: {v}"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    SERVER.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.as_ref().is_none_or(|s| s.served >= REBUILD_EVERY) {
            *slot = Some(build());
        }
        let server = slot.as_mut().unwrap();
        server.served += 1;
        let mut u = Unstructured::new(data);
        let Ok(input) = Input::generate(&mut u, server) else {
            return;
        };
        match &input.route {
            Route::Evaluation(b) => {
                if let Some((StatusCode::OK, v)) = send(
                    server,
                    "/access/v1/evaluation",
                    input.auth,
                    &input.garbage,
                    b,
                ) {
                    check_evaluation(&v);
                }
            }
            Route::Evaluations(b, count) => {
                if let Some((StatusCode::OK, v)) = send(
                    server,
                    "/access/v1/evaluations",
                    input.auth,
                    &input.garbage,
                    b,
                ) {
                    let results = v["evaluations"].as_array().expect("evaluations array");
                    if let Some(n) = count {
                        assert_eq!(results.len(), *n, "one result per evaluation");
                    }
                    for r in results {
                        check_evaluation(r);
                    }
                }
            }
            Route::UserDecide(id, b) => {
                let path = format!("/approvals/{}", percent_encode(id));
                if let Some((status, v)) = send(server, &path, input.auth, &input.garbage, b) {
                    assert_ne!(
                        status,
                        StatusCode::OK,
                        "decided an approval that does not exist: {v}"
                    );
                }
            }
            Route::AdminDecide(id, b) => {
                let path = format!("/admin/approvals/{}", percent_encode(id));
                if let Some((status, v)) = send(server, &path, input.auth, &input.garbage, b) {
                    assert_ne!(
                        status,
                        StatusCode::OK,
                        "decided an approval that does not exist: {v}"
                    );
                }
            }
        }
    });
});
