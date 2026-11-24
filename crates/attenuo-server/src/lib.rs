//! `attenuo-server`: wires the token issuer, policy engine, audit log, lease registry and MCP
//! proxy into one HTTP service.
//!
//! The crate holds no authorization logic of its own beyond composing the others
//! ([ADR-0004](../../docs/decisions/0004-rust-workspace-layout.md)); the one place a call is
//! decided is [`authz::Pipeline::decide`]. See `docs/design/server.md` for the request flow.
//!
//! | Route | Auth | Purpose |
//! |---|---|---|
//! | `POST /token` | client credentials + IdP credential | hop 0 from an OIDC ID token or ID-JAG (`idp`) |
//! | `POST /token` | subject token in body; actor by client credentials or `actor_token` (`actor`) | RFC 8693 exchange, hop n to n+1 |
//! | `POST /token/renew` | delegation token (bearer; with a `DPoP` proof when bound, [`dpop`]) | extend the last hop's lease |
//! | `POST /access/v1/evaluation` | delegation token (bearer); or `[[peps]]` credentials with `[authzen] allow_unsigned_chain` | AuthZEN evaluation |
//! | `POST /access/v1/evaluations` | same as above | AuthZEN batch evaluation, at most `[authzen] max_batch` entries |
//! | `POST /access/v1/search/action` | same as above | AuthZEN action search: the catalog tools of one server the pipeline would allow, at most `[authzen] max_batch` evaluated per page; one `search` audit record, no charge or approval |
//! | `GET /.well-known/authzen-configuration` | none | AuthZEN metadata |
//! | `GET /.well-known/jwks.json` | none | issuer public key |
//! | `GET /healthz` | none | liveness |
//! | `GET /metrics` | none | Prometheus metrics, on `[metrics] listen` only (separate port) |
//! | `GET /readyz` | none | readiness: audit store and lease store answer; `[audit.sink]` health ([`sink`]) |
//! | `POST/GET/DELETE /mcp/{server}` | delegation token | MCP proxy |
//! | `POST/GET/DELETE /ext-authz/v1/mcp/{server}` | gateway secret, then the delegation token it forwards | the proxy's decision for a gateway's `extAuthz` check, mounted only with an `[[ext_authz]]` entry |
//! | `POST /admin/root-token` | admin | dev-only hop-0 mint ([`routes::dev_root`]), mounted only with `[dev] allow_root_mint = true` |
//! | `POST /admin/leases/{id}/revoke`, `GET /admin/leases/{id}` | admin | leases |
//! | `POST /admin/leases/revoke?preview` | admin | revoke every lease of one user, one chain, or the chains that opened one MCP session (`session`), with the cascade, audited ([`routes::admin::revoke_by_selector`]) |
//! | `GET /admin/leases/{id}/tree?max_nodes` | admin | lease subtree, ancestors and how many leases a revoke would change (read-only, [`routes::admin::lease_tree`]) |
//! | `POST /admin/budgets/refund` | admin | return what one decision charged to the run limits, once, audited ([`routes::admin::refund_budget`]) |
//! | `GET /admin/audit`, `/admin/audit/verify`, `/admin/audit/checkpoint` | admin | audit |
//! | `GET /admin/audit/entries/{seq}`, `/admin/audit/records/{id}`, `/admin/audit/checkpoints` | admin | one entry with its context; stored checkpoints (read-only) |
//! | `GET /admin/audit/export?from&to` | admin | stream a verifiable slice of the log as JSON Lines |
//! | `GET /admin/audit/prune/plan?through` or `?before`, `POST /admin/audit/prune` | admin | plan and commit a prune of the oldest entries behind a signed anchor, with `[audit.retention] prune = "manual"` or `"auto"` ([`routes::retention`]; the automatic prune is [`auto_prune`]) |
//! | `GET /admin/audit/anchors` | admin | the signed anchors of past prunes, newest first (read-only) |
//! | `POST /admin/policies/reload` | admin | hot-reload the Cedar policy file |
//! | `POST /admin/operators/reload` | admin | re-read `[[admin.operators]]` from the config file and swap them in ([`routes::admin::reload_operators`]) |
//! | `POST /admin/agents/reload` | admin | re-read `[[agents]]` and `[[peps]]` from the config file, check them as startup does and swap both in at once; tokens already issued are not revoked ([`routes::admin::reload_agents`]) |
//! | `POST /admin/keys/reload` | admin | re-read the `[issuer]` key files named in the config file and swap in the new signing key and verifying keys at once; refuses to drop the current key or a key that signed the audit log unless asked ([`routes::keys::reload_keys`]) |
//! | `GET /admin/policies` | admin | the policy set in force: ids, text, file digest, load time ([`routes::policies`]) |
//! | `GET /admin/policies/check` | admin | lint the policy file on disk against the running schema; swaps nothing |
//! | `POST /admin/policies/evaluate` | admin | dry run: what the loaded policies say about one call, optionally with a stated run-limit state (`budget`); no lease check, no charge, no audit |
//! | `POST /approvals/{id}` | the originating user's IdP ID token (never a delegation token) | grant or decline a pending approval ([`routes::approvals`]) |
//! | `GET /approvals/{id}` | the user's ID token, or a delegation token of the same run | the approval: exact call, labels, state, expiry |
//! | `GET /admin/approvals?chain_id`, `GET /admin/approvals/{id}`, `POST /admin/approvals/{id}` | admin | list, show, and grant or decline as an operator |
//! | `GET /admin/whoami` | admin | the name, role and expiry of the credential that sent the request ([`routes::admin::whoami`]) |
//!
//! "admin" in the Auth column means an admin credential (`[admin] token` or an
//! `[[admin.operators]]` entry, [`operators`]) whose role is at least the one
//! [`operators::ROUTE_ROLES`] lists for the route: `viewer` for reads, `operator` for revoking
//! leases and deciding approvals, `admin` for the rest. A role too low is 403
//! `admin_role_insufficient`.
//!
//! **Console listener.** With `[admin_ui] enabled = true` a second listener on
//! `[admin_ui] listen` (default `127.0.0.1:9101`) serves the embedded console under
//! `/admin/ui/` and the admin routes above that have no side effect, behind the same admin
//! bearer; revoke, reload and budget refunds only with `[admin_ui] allow_write = true`, and never
//! `/admin/root-token`. Every response there carries a strict CSP and the other headers in
//! [`admin_ui::SECURITY_HEADERS`], and no CORS headers. See [`admin_ui`].
//!
//! **Admin listener.** With `[admin] listen` set, every `/admin/*` route above is served on
//! that address only ([`admin_router`]), behind the same admin bearer, and the main listener
//! answers those paths as it answers any unknown path. Without it they are on the main
//! listener, which the server accepts off loopback only with `[admin] serve_on_main_listener =
//! true` (S-1). `/healthz`, `/readyz` and everything else stay on the main listener.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(unreachable_pub)]
#![warn(clippy::missing_errors_doc)]
#![warn(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

pub(crate) mod actor;
// Used by the integration tests.
pub mod admin_ui;
// Used by the integration tests.
pub mod auto_prune;
// Used by the benches (`result_digest`).
pub mod authz;
pub(crate) mod clientauth;
pub mod config;
// Used by the fuzz targets.
pub mod dpop;
pub(crate) mod early_close;
// Used by the integration tests.
pub mod error;
pub(crate) mod idp;
pub mod issuer_keys;
pub(crate) mod limits;
pub(crate) mod listen;
// Used by `main` and the integration tests.
pub mod logging;
// Used by the integration tests.
pub mod metrics;
// Used by the integration tests.
pub mod notify;
// Used by the integration tests.
pub mod operators;
pub(crate) mod replay;
// Used by the integration tests.
pub mod routes;
// Used by the integration tests.
pub mod sink;
pub(crate) mod state;
pub mod telemetry;
pub(crate) mod tls;

/// Thin wrappers over the crate-private `[idps.id_jag_ceiling]` code, for the cargo-fuzz target
/// `idjag_ceiling` (`fuzz/`). **Not a public API**: behind the `fuzzing` feature, which only
/// `fuzz/Cargo.toml` enables, hidden from the docs, and free to change or go with any release.
/// Each wrapper calls the server's own function; none holds logic of its own.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    use attenuo_core::CapabilitySet;
    use serde_json::{Map, Value};

    use crate::config::IdJagCeilingConfig;
    use crate::error::ApiError;
    use crate::idp::ceiling;

    /// A checked `[idps.id_jag_ceiling]` (`idp::ceiling::IdJagCeiling`).
    #[derive(Debug, Clone)]
    pub struct IdJagCeiling(ceiling::IdJagCeiling);

    /// `idp::ceiling::Applied`: the ceiling for one ID-JAG.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Applied {
        /// The ceiling's capabilities.
        pub capabilities: CapabilitySet,
        /// The claims that were present and narrowed it, in the order applied.
        pub claims: Vec<&'static str>,
        /// The steps before the last that hold a capability with limits.
        pub limited_steps: Vec<CapabilitySet>,
        /// What each claim whose capabilities hold limits named.
        pub limited_claims: Vec<CapabilitySet>,
    }

    impl IdJagCeiling {
        /// `IdJagCeiling::from_config`, as the server checks the table at start.
        ///
        /// # Errors
        ///
        /// The message the server refuses to start with.
        pub fn from_config(cfg: &IdJagCeilingConfig) -> Result<Self, String> {
            ceiling::IdJagCeiling::from_config(cfg).map(Self)
        }

        /// `IdJagCeiling::apply`: the ceiling an ID-JAG with these `claims` leaves of `grant`.
        pub fn apply(&self, grant: &CapabilitySet, claims: &Map<String, Value>) -> Applied {
            let a = self.0.apply(grant, claims);
            Applied {
                capabilities: a.capabilities,
                claims: a.claims,
                limited_steps: a.limited_steps,
                limited_claims: a.limited_claims,
            }
        }
    }

    /// Hop-0 narrowing of `requested` against the root grant `granted` and, when given, the
    /// ceiling and the ID-JAG's `claims`: `idp::intake::narrow` once the ceiling is looked up.
    ///
    /// # Errors
    ///
    /// The `400 invalid_scope` the intake answers with.
    pub fn narrow(
        granted: &CapabilitySet,
        ceiling: Option<&IdJagCeiling>,
        claims: &Map<String, Value>,
        requested: &CapabilitySet,
    ) -> Result<CapabilitySet, ApiError> {
        crate::idp::intake::narrow_with(
            ceiling.map(|c| &c.0),
            "https://idp.fuzz",
            "agent:fuzz",
            claims,
            granted,
            requested,
        )
        .map(|n| n.capabilities)
    }
}

use std::sync::Arc;

use attenuo_proxy::{ProxyConfig, UpstreamConfig};
use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

pub use authz::{Pipeline, PipelineDecision, ServerAuthorizer, SharedPolicy};
pub use auto_prune::auto_prune_once;
pub use config::Config;
pub use state::AppState;

/// Build the state and the full router from a config.
///
/// # Errors
///
/// As [`AppState::from_config`].
pub fn build(config: &Config) -> anyhow::Result<(Router, Arc<AppState>)> {
    build_with_clock(config, attenuo_core::clock::system_clock())
}

/// [`build`], with every request check (token, lease and approval expiry, the proxy's
/// session TTL and record windows) reading the time from `clock`. Tests pass a
/// [`attenuo_core::ManualClock`] to step past a TTL instead of sleeping through it.
///
/// # Errors
///
/// As [`AppState::from_config`].
pub fn build_with_clock(
    config: &Config,
    clock: Arc<dyn attenuo_core::Clock>,
) -> anyhow::Result<(Router, Arc<AppState>)> {
    let state = Arc::new(AppState::from_config_with_clock(config, clock)?);
    let router = router(state.clone(), config.upstreams.clone(), config);
    Ok((router, state))
}

/// The full router of the main listener over an existing state: every route of the table
/// above, the admin routes included unless `[admin] listen` moves them to a listener of their
/// own ([`admin_router`]). Then `/admin/*` is not mounted here at all, so the main listener
/// answers it exactly as it answers any path it does not know.
pub fn router(state: Arc<AppState>, upstreams: Vec<UpstreamConfig>, config: &Config) -> Router {
    use routes::{approvals, authzen, renew, token, wellknown};

    let authzen_routes = Router::new()
        .route("/access/v1/evaluation", post(authzen::evaluation))
        .route("/access/v1/evaluations", post(authzen::evaluations))
        .route("/access/v1/search/action", post(authzen::search_action))
        .route_layer(axum::middleware::from_fn(authzen::echo_request_id));
    let mut token_routes = Router::new()
        .route(
            "/token",
            post(token::exchange).layer(axum::middleware::from_fn_with_state(
                state.limits.clone(),
                limits::token_peer_limit,
            )),
        )
        .route("/token/renew", post(renew::renew));
    // One exported span per token and AuthZEN request, only when tracing is on.
    let (authzen_routes, token_routes) = if state.trace.is_some() {
        let layer = axum::middleware::from_fn_with_state(state.clone(), telemetry::trace_route);
        token_routes = token_routes.route_layer(layer.clone());
        (authzen_routes.route_layer(layer), token_routes)
    } else {
        (authzen_routes, token_routes)
    };

    let mut api = Router::new()
        .route("/healthz", get(wellknown::healthz))
        .route("/readyz", get(routes::ops::readyz))
        .route("/.well-known/jwks.json", get(wellknown::jwks))
        .route(
            "/.well-known/authzen-configuration",
            get(wellknown::authzen_configuration),
        )
        .merge(token_routes)
        .route(
            "/approvals/{id}",
            get(approvals::user_get).post(approvals::user_decide),
        )
        .merge(authzen_routes);
    if config.admin.on_main_listener() {
        api = api.merge(admin_routes(&state));
    }
    let api = api
        .with_state(state.clone())
        // The span records the route template, never the URI (SR-90).
        .layer(TraceLayer::new_for_http().make_span_with(attenuo_proxy::http_trace::request_span));

    let authorizer = Arc::new(
        ServerAuthorizer::new(state.keys.clone(), state.pipeline.clone())
            .with_dpop(state.dpop.clone())
            .with_trace(state.trace.clone())
            .with_limits(state.limits.clone()),
    );
    let proxy = attenuo_proxy::router_with_clock(
        // Validated in `AppState::from_config`.
        config
            .proxy
            .apply(ProxyConfig::new(config.server.listen, upstreams))
            .with_ext_authz(config.ext_authz.clone()),
        authorizer,
        state.clock.clone(),
    );
    // `[limits]`: the deadlines inside the in-flight cap, both inside the metrics layer so
    // that their refusals are counted by route like any answer. Main listener only.
    let app = api
        .merge(proxy)
        .layer(axum::middleware::from_fn_with_state(
            state.limits.clone(),
            limits::deadlines,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.limits.clone(),
            limits::shed,
        ));
    let app = outer_layers(app, &state);
    // `[server.tls]`: outermost, so nothing runs for a request that did not come over TLS.
    if state.main_tls.is_some() {
        app.layer(axum::middleware::from_fn(listen::require_tls))
    } else {
        app
    }
}

/// The router of the `[admin] listen` listener (S-1): the admin routes of the table above
/// behind the same `require_admin` layer, response headers, request span, metrics and
/// `DPoP-Nonce` header as on the main listener, and nothing else (no `/healthz`, `/readyz` or
/// discovery; any other path answers as an unknown path does on the main listener). [`run`]
/// serves it when `[admin] listen` is set.
pub fn admin_router(state: Arc<AppState>) -> Router {
    let admin = admin_routes(&state)
        .with_state(state.clone())
        // The span records the route template, never the URI (SR-90).
        .layer(TraceLayer::new_for_http().make_span_with(attenuo_proxy::http_trace::request_span));
    outer_layers(admin, &state)
}

/// Every `/admin/*` route of the table above, behind [`routes::admin::require_admin`]. Mounted
/// on the main listener ([`router`]) or on its own ([`admin_router`]), never on both.
fn admin_routes(state: &Arc<AppState>) -> Router<Arc<AppState>> {
    use routes::{admin, approvals, dev_root, keys, policies, retention};

    let mut admin_routes = Router::new()
        .route("/admin/whoami", get(admin::whoami))
        .route("/admin/leases/revoke", post(admin::revoke_by_selector))
        .route("/admin/leases/{lease_id}", get(admin::lease_status))
        .route("/admin/leases/{lease_id}/revoke", post(admin::revoke_lease))
        .route("/admin/leases/{lease_id}/tree", get(admin::lease_tree))
        .route("/admin/budgets/refund", post(admin::refund_budget))
        .route("/admin/audit", get(admin::audit_range))
        .route("/admin/audit/verify", get(admin::audit_verify))
        .route("/admin/audit/entries/{seq}", get(admin::audit_entry))
        .route("/admin/audit/records/{id}", get(admin::audit_record))
        .route("/admin/audit/checkpoints", get(admin::audit_checkpoints))
        .route("/admin/audit/checkpoint", get(admin::audit_checkpoint))
        .route("/admin/audit/export", get(admin::audit_export))
        .route("/admin/audit/prune/plan", get(retention::prune_plan))
        .route("/admin/audit/prune", post(retention::prune))
        .route("/admin/audit/anchors", get(retention::anchors))
        .route("/admin/policies", get(policies::get_policies))
        .route("/admin/policies/check", get(policies::check_policies))
        .route(
            "/admin/policies/evaluate",
            post(policies::evaluate_policies),
        )
        .route("/admin/policies/reload", post(admin::reload_policies))
        .route("/admin/operators/reload", post(admin::reload_operators))
        .route("/admin/agents/reload", post(admin::reload_agents))
        .route("/admin/keys/reload", post(keys::reload_keys))
        .route("/admin/approvals", get(approvals::admin_list))
        .route(
            "/admin/approvals/{id}",
            get(approvals::admin_get).post(approvals::admin_decide),
        );
    if state.dev_allow_root_mint {
        admin_routes = admin_routes.route("/admin/root-token", post(dev_root::mint_root));
    }
    admin_routes
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            admin::require_admin,
        ))
        // Added last, so it wraps `require_admin` and its 401/403 answers get the headers too.
        .route_layer(axum::middleware::from_fn(admin::admin_response_headers))
}

/// The layers around everything the main and the admin listener serve, unknown paths included.
fn outer_layers(app: Router, state: &Arc<AppState>) -> Router {
    app.layer(axum::middleware::from_fn_with_state(
        state.dpop.clone(),
        dpop::nonce_header,
    ))
    .layer(axum::middleware::from_fn_with_state(
        state.metrics.clone(),
        metrics::track_http,
    ))
    // Outermost, so it sees every answer, the early refusals of the layers above included.
    .layer(axum::middleware::from_fn(early_close::mark_early_refusal))
}

/// Start the `[audit] checkpoint_interval_seconds` timer: every `period`, sign the head if
/// entries were appended since the newest checkpoint. (The `checkpoint_every` count trigger
/// runs inside the append itself.) Dropping the handle does not stop it; abort it to stop.
/// [`run`] stops its own timer between ticks instead, so that no signing is cut off halfway.
pub fn spawn_checkpointer(
    state: Arc<AppState>,
    period: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(checkpoint_ticks(state, period, std::future::pending()))
}

/// The timer of [`spawn_checkpointer`], until `stop` resolves. `stop` is only looked at
/// between ticks: a signing in progress on the blocking pool finishes first, so that when this
/// returns nothing it started still holds the state.
async fn checkpoint_ticks(
    state: Arc<AppState>,
    period: std::time::Duration,
    stop: impl std::future::Future<Output = ()>,
) {
    tokio::pin!(stop);
    let mut tick = tokio::time::interval(period);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await; // the first tick is immediate
    loop {
        tokio::select! {
            () = &mut stop => return,
            _ = tick.tick() => {}
        }
        let result = state
            .blocking(|s| s.audit.checkpoint_if_new(time::OffsetDateTime::now_utc()))
            .await;
        match result {
            Ok(Some(cp)) => {
                tracing::info!(seq = cp.seq, kid = %cp.kid, "audit checkpoint signed")
            }
            Ok(None) => {}
            Err(e) => tracing::error!(error = %e, "signing an audit checkpoint failed"),
        }
    }
}

/// Default of `[leases] maintenance_interval_seconds`: how often the lease maintenance ticker
/// runs ([`spawn_lease_maintenance`]).
pub const LEASE_MAINTENANCE_PERIOD: std::time::Duration = std::time::Duration::from_secs(60);

/// Default of `[leases] maintenance_batch_rows`: rows one pruning pass looks at (session
/// bindings, leases, or run state), one short write transaction each. A lease pass also reads and deletes the whole tree of every top lease
/// among them; a run-state pass, every charge-log row of each charged decision among them.
pub const LEASE_PRUNE_BATCH: usize = 1_000;

/// Default of `[leases] maintenance_max_passes`: most passes of each kind in one run of the
/// ticker, so one run looks at no more than `maintenance_batch_rows * maintenance_max_passes`
/// rows (100,000 by default) of each table before it waits for the next period.
pub const LEASE_PRUNE_MAX_PASSES: usize = 100;

/// Run pruning passes on the blocking pool until one reaches the end of its table or
/// `[leases] maintenance_max_passes` have run. `pass` returns what it deleted and whether it
/// wrapped; `count` adds what one pass deleted to its metrics (and returns the total, for
/// the return value and the log line). Returns the total deleted.
async fn prune_in_passes<F, P>(
    state: &Arc<AppState>,
    what: &'static str,
    pass: F,
    count: fn(&metrics::Metrics, P) -> u64,
) -> u64
where
    F: Fn(&AppState, time::OffsetDateTime) -> Result<(P, bool), attenuo_audit::AuditError>
        + Copy
        + Send
        + 'static,
    P: Send + 'static,
{
    let mut total = 0;
    for _ in 0..state.lease_maintenance.max_passes {
        let now = state.now();
        match state.blocking(move |s| pass(s, now)).await {
            Ok((pruned, wrapped)) => {
                total += count(&state.metrics, pruned);
                if wrapped {
                    break;
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "pruning {what} failed");
                break;
            }
        }
        tokio::task::yield_now().await;
    }
    if total > 0 {
        tracing::info!(pruned = total, "pruned {what} of ended chains");
    }
    total
}

/// One run of session retention (`[leases] session_retention_seconds`): pruning passes of
/// `[leases] maintenance_batch_rows` bindings, each its own write transaction on the blocking
/// pool, until a pass reaches the end of the table or `maintenance_max_passes` have run. The
/// next run continues where this one stopped. Counts every deleted binding in
/// `lease_sessions_pruned_total` and returns how many it deleted; 0 when retention is off.
pub async fn prune_session_bindings(state: &Arc<AppState>) -> u64 {
    let Some(retention) = state.session_retention else {
        return 0;
    };
    prune_in_passes(
        state,
        "session bindings",
        move |s, now| {
            use attenuo_audit::StoreRetention;
            let batch = s.lease_maintenance.batch_rows;
            let p = s.leases.prune_sessions(now, retention, batch)?;
            Ok((p.pruned, p.wrapped))
        },
        |m, n| {
            m.lease_sessions_pruned(n);
            n
        },
    )
    .await
}

/// One run of lease retention (`[leases] retention_seconds`): passes of
/// [`StoreRetention::prune_leases`](attenuo_audit::StoreRetention::prune_leases) over
/// `maintenance_batch_rows` lease rows each (looked at, read to decide a run, or deleted),
/// bounded like [`prune_session_bindings`]. A lease tree goes whole once every lease in it
/// ended (revoked or expired) longer ago than the retention, with its subjects and bindings;
/// a tree wider than a pass is read to the end and then deleted over several passes, children
/// first, and may carry over to the next run. Counts every deleted lease in
/// `leases_pruned_total` and returns how many it deleted; 0 when retention is off.
pub async fn prune_lease_registry(state: &Arc<AppState>) -> u64 {
    let Some(retention) = state.lease_retention else {
        return 0;
    };
    prune_in_passes(
        state,
        "leases",
        move |s, now| {
            use attenuo_audit::StoreRetention;
            let batch = s.lease_maintenance.batch_rows;
            let p = s.leases.prune_leases(now, retention, batch)?;
            Ok((p.pruned, p.wrapped))
        },
        |m, n| {
            m.leases_pruned(n);
            n
        },
    )
    .await
}

/// One run of run-state retention (`[leases] run_state_retention_seconds`): passes of
/// [`StoreRetention::prune_run_state`](attenuo_audit::StoreRetention::prune_run_state) over
/// `maintenance_batch_rows` rows each, bounded like [`prune_session_bindings`]. Run-limit
/// counters, the charge log and approvals go once the leases they belong to are gone from the
/// registry and they are older than the retention; nothing of a lease still in the registry
/// is touched. Counts each kind in `run_state_pruned_total{kind}` and returns how many rows
/// (counters, charge-log entries and approvals together) it deleted; 0 when retention is off.
pub async fn prune_run_state(state: &Arc<AppState>) -> u64 {
    let Some(retention) = state.run_state_retention else {
        return 0;
    };
    prune_in_passes(
        state,
        "run-limit counters, charges and approvals",
        move |s, now| {
            use attenuo_audit::StoreRetention;
            let batch = s.lease_maintenance.batch_rows;
            let p = s.leases.prune_run_state(now, retention, batch)?;
            Ok((p, p.wrapped))
        },
        |m, p| {
            m.run_state_pruned(p.pruned_counters, p.pruned_charges, p.pruned_approvals);
            p.pruned_counters + p.pruned_charges + p.pruned_approvals
        },
    )
    .await
}

/// One run of per-user window retention (`[leases] user_window_retention_seconds`, run limits
/// phase 3): passes of
/// [`StoreRetention::prune_user_windows`](attenuo_audit::StoreRetention::prune_user_windows), bounded
/// like [`prune_run_state`]. A window and its charges go once the window ended longer ago than
/// the retention; an open window is never touched. Counts what it deleted in
/// `run_state_pruned_total{kind="user_window"}` and returns it; 0 when retention is off.
pub async fn prune_user_windows(state: &Arc<AppState>) -> u64 {
    let Some(retention) = state.user_window_retention else {
        return 0;
    };
    prune_in_passes(
        state,
        "per-user windows",
        move |s, now| {
            use attenuo_audit::StoreRetention;
            let batch = s.lease_maintenance.batch_rows;
            let p = s.leases.prune_user_windows(now, retention, batch)?;
            Ok((p, p.wrapped))
        },
        |m, p| {
            let n = p.pruned_windows + p.pruned_charges;
            m.user_windows_pruned(n);
            n
        },
    )
    .await
}

/// One run of the deletes of a committed prune of the audit log (`[audit.retention]`,
/// ADR-0015): transactions of `[audit.retention] batch_rows` rows each, at most `[leases]
/// maintenance_max_passes` of them, yielding between them so appends take the write gate in
/// between. The state is in the file, so a restart resumes where the last batch stopped; the
/// last batch sets the anchor `done`. Counts what it deleted in `audit_pruned_entries_total`
/// and returns it; 0 when no prune is deleting.
pub async fn prune_audit_log(state: &Arc<AppState>) -> u64 {
    let batch = usize::try_from(state.retention.batch_rows).unwrap_or(usize::MAX);
    let mut total = 0;
    let mut through = None;
    for _ in 0..state.lease_maintenance.max_passes {
        match state.blocking(move |s| s.audit.prune_step(batch)).await {
            Ok(step) => {
                total += step.deleted;
                state.metrics.audit_pruned_entries(step.deleted);
                through = step.through_seq.or(through);
                if step.done {
                    if let Some(b) = step.through_seq {
                        tracing::info!(
                            through = b,
                            "audit prune done: every pruned row is deleted"
                        );
                    }
                    break;
                }
                if step.through_seq.is_none() {
                    break;
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "deleting pruned audit rows failed");
                break;
            }
        }
        tokio::task::yield_now().await;
    }
    if total > 0 {
        tracing::info!(deleted = total, through = ?through, "deleted pruned audit rows");
    }
    total
}

/// Start the lease maintenance ticker: every `[leases] maintenance_interval_seconds`,
/// [`prune_session_bindings`], then [`prune_lease_registry`], then [`prune_run_state`], then
/// [`prune_user_windows`], then [`prune_audit_log`] (each
/// does nothing when its retention is 0, or when no prune of the audit log is deleting). Sessions go first, so a binding whose chain is about
/// to be pruned is counted as a session; run state goes last, since it is only pruned once
/// its leases are gone. Dropping the handle does not stop it; abort it to stop. [`run`] stops
/// its own ticker between runs instead.
pub fn spawn_lease_maintenance(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(maintenance_ticks(state, std::future::pending()))
}

/// The ticker of [`spawn_lease_maintenance`], until `stop` resolves. `stop` is only looked at
/// between runs, as in [`checkpoint_ticks`]: a run in progress finishes its passes first.
async fn maintenance_ticks(state: Arc<AppState>, stop: impl std::future::Future<Output = ()>) {
    tokio::pin!(stop);
    let mut tick = tokio::time::interval(state.lease_maintenance.interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await; // the first tick is immediate
    loop {
        tokio::select! {
            () = &mut stop => return,
            _ = tick.tick() => {}
        }
        prune_session_bindings(&state).await;
        prune_lease_registry(&state).await;
        prune_run_state(&state).await;
        prune_user_windows(&state).await;
        prune_audit_log(&state).await;
    }
}

/// How long `[audit.sink]`, `[approvals.notify]` and `[leases.notify]` keep delivering what
/// they have queued after a shutdown signal. The three share this one grace: [`run`] stops
/// them side by side, by the same deadline.
pub const SINK_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// How long in-flight requests get to finish after a shutdown signal.
pub const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long [`serve`] waits, once [`run`] has returned, for the state to be dropped and the
/// single-writer fence released. After a clean drain nothing is left to wait for; only
/// requests abandoned at [`DRAIN_TIMEOUT`] can still hold the state, until they end.
pub const RELEASE_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// Bind `[server] listen` and serve until SIGINT or SIGTERM, then drain for [`DRAIN_TIMEOUT`]
/// and stop as [`run`] does. Returns once the state has been dropped, so the database's
/// single-writer fence is released before this returns (a supervisor or an embedder can start
/// the next server on the same file at once); a request still running after the drain is the
/// one thing that can keep it, and that is logged after [`RELEASE_GRACE`].
///
/// # Errors
///
/// When [`build`] fails, when `[server] listen` (or the metrics, admin or admin UI listener)
/// cannot be bound, or when serving fails with an I/O error. A failed final WAL checkpoint is logged, not
/// returned.
pub async fn serve(config: Config) -> anyhow::Result<()> {
    let (app, state) = build(&config)?;
    let listener = tokio::net::TcpListener::bind(config.server.listen).await?;
    let fence = state.store_fence().map(std::path::Path::to_path_buf);
    let released = state.released();
    let res = run(&config, state, app, listener, shutdown_signal()).await;
    match tokio::time::timeout(RELEASE_GRACE, released).await {
        Ok(()) => {
            if let Some(lock) = fence {
                tracing::info!(lock = %lock.display(), "single-writer fence released");
            }
        }
        Err(_) => tracing::warn!(
            "requests still running after the drain hold the server state: the database stays \
             fenced until they end or the process exits"
        ),
    }
    res
}

/// Serve `app` (built over `state` by [`build`]) on `listener` with everything [`serve`] runs
/// next to it (the checkpoint timer, lease maintenance, the `[metrics]`, `[admin] listen` and
/// `[admin_ui]` listeners) until `shutdown` resolves; then drain every listener for [`DRAIN_TIMEOUT`] and
/// stop. This is [`serve`] without the binding of `[server] listen` and the signal handling,
/// for an embedder that runs the server in its own process and stops it itself. With
/// `[server.tls]`, `listener` speaks TLS with the certificate and key `state` read at
/// startup; the other listeners always speak plain HTTP.
///
/// When it returns, everything it started has finished and been dropped: the listeners are
/// closed, their connections drained (or, past the drain timeout, abandoned), the timers stopped
/// between ticks and awaited, `[audit.sink]`, `[approvals.notify]` and `[leases.notify]` stopped
/// side by side within one shared grace ([`SINK_SHUTDOWN_GRACE`]), and the WAL checkpointed. `run` drops its own reference to `state` last, so once the caller
/// drops its references too the state goes, its stores close and the single-writer fence is
/// released; [`AppState::released`] resolves at that point.
///
/// # Errors
///
/// When the metrics, admin or admin UI listener cannot be bound (nothing has started then), or
/// when serving fails with an I/O error. A failed final WAL checkpoint is logged, not returned.
pub async fn run(
    config: &Config,
    state: Arc<AppState>,
    app: Router,
    listener: tokio::net::TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let tls = state.main_tls.clone().map(tokio_rustls::TlsAcceptor::from);
    tracing::info!(
        addr = %listener.local_addr()?,
        tls = tls.is_some(),
        upstreams = config.upstreams.len(),
        "attenuo server listening"
    );
    let metrics_listener = if config.metrics.enabled {
        let l = tokio::net::TcpListener::bind(config.metrics.listen).await?;
        tracing::info!(addr = %l.local_addr()?, "metrics listening (unauthenticated)");
        Some(l)
    } else {
        None
    };
    let admin_listener = match config.admin.listen {
        Some(addr) => {
            let l = tokio::net::TcpListener::bind(addr).await?;
            tracing::info!(
                addr = %l.local_addr()?,
                "admin API listening (/admin/*, not on the main listener)"
            );
            Some(l)
        }
        None => None,
    };
    let console_listener = if config.admin_ui.enabled {
        let l = tokio::net::TcpListener::bind(config.admin_ui.listen).await?;
        tracing::info!(
            addr = %l.local_addr()?,
            allow_write = config.admin_ui.allow_write,
            "admin console listening at /admin/ui/"
        );
        Some(l)
    } else {
        None
    };
    // One stop for everything started here: set when `shutdown` resolves, and seen as set too
    // once the sender is dropped (the main listener failing ends `serve_until` early).
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let stopped = move || {
        let mut rx = stop_rx.clone();
        async move {
            let _ = rx.wait_for(|stop| *stop).await;
        }
    };
    let header_read_timeout = config.limits.header_read_timeout();
    let mut tasks: Vec<(&str, tokio::task::JoinHandle<anyhow::Result<()>>)> = Vec::new();
    if !state.checkpoint_interval.is_zero() {
        let ticks = checkpoint_ticks(state.clone(), state.checkpoint_interval, stopped());
        tasks.push((
            "checkpoint timer",
            tokio::spawn(async move {
                ticks.await;
                Ok(())
            }),
        ));
    }
    // A prune's deletes resume after a restart even if `prune` was turned off since.
    let prune_deleting = state
        .audit
        .newest_anchor()
        .ok()
        .flatten()
        .is_some_and(|a| a.state == attenuo_audit::AnchorState::Deleting);
    if state.session_retention.is_some()
        || state.lease_retention.is_some()
        || state.run_state_retention.is_some()
        || state.user_window_retention.is_some()
        || state.retention.prune != config::PruneMode::Off
        || prune_deleting
    {
        let ticks = maintenance_ticks(state.clone(), stopped());
        tasks.push((
            "lease maintenance",
            tokio::spawn(async move {
                ticks.await;
                Ok(())
            }),
        ));
    }
    if state.retention.prune == config::PruneMode::Auto {
        let ticks = auto_prune::auto_prune_ticks(state.clone(), stopped());
        tasks.push((
            "automatic audit prune",
            tokio::spawn(async move {
                ticks.await;
                Ok(())
            }),
        ));
    }
    if let Some(l) = metrics_listener {
        let app = metrics::router(state.metrics.clone());
        let until = serve_and_release(l, app, None, stopped(), DRAIN_TIMEOUT, header_read_timeout);
        tasks.push(("metrics listener", tokio::spawn(until)));
    }
    if let Some(l) = admin_listener {
        let app = admin_router(state.clone());
        let until = serve_and_release(l, app, None, stopped(), DRAIN_TIMEOUT, header_read_timeout);
        tasks.push(("admin listener", tokio::spawn(until)));
    }
    if let Some(l) = console_listener {
        let app = admin_ui::router(state.clone(), config);
        let until = serve_and_release(l, app, None, stopped(), DRAIN_TIMEOUT, header_read_timeout);
        tasks.push(("admin console listener", tokio::spawn(until)));
    }
    let res = serve_and_release(
        listener,
        app,
        tls,
        async move {
            shutdown.await;
            let _ = stop_tx.send(true);
        },
        DRAIN_TIMEOUT,
        header_read_timeout,
    )
    .await;
    // The timers and the other listeners stop with the main one; wait for each, so none of
    // them still holds the state when this returns.
    for (what, task) in tasks {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "{what} failed"),
            Err(e) => tracing::warn!(error = %e, "{what} panicked"),
        }
    }
    // Give checkpoints still queued for `[audit.sink]`, and approval and revocation notices
    // still queued, one shared moment to leave the host: the three queues stop side by side,
    // each by the same deadline, so the wait is one grace (plus at most one request already
    // in flight, cut by its own timeout), not one per queue.
    let deadline = std::time::Instant::now() + SINK_SHUTDOWN_GRACE;
    let mut stopping = Vec::new();
    if state.checkpoint_sink.is_some() {
        let s = state.clone();
        stopping.push(tokio::task::spawn_blocking(move || {
            if let Some(sink) = &s.checkpoint_sink {
                sink.shutdown(deadline.saturating_duration_since(std::time::Instant::now()));
            }
        }));
    }
    if state.approval_notifier.is_some() {
        let s = state.clone();
        stopping.push(tokio::task::spawn_blocking(move || {
            if let Some(n) = &s.approval_notifier {
                n.shutdown(deadline.saturating_duration_since(std::time::Instant::now()));
            }
        }));
    }
    if state.lease_notifier.is_some() {
        let s = state.clone();
        stopping.push(tokio::task::spawn_blocking(move || {
            if let Some(n) = &s.lease_notifier {
                n.shutdown(deadline.saturating_duration_since(std::time::Instant::now()));
            }
        }));
    }
    for task in stopping {
        let _ = task.await;
    }
    // Requests have drained: fold the WAL into the database file before exiting.
    match state.blocking(|s| s.audit.checkpoint_wal()).await {
        Ok(Some(done)) if !done.complete() => {
            tracing::warn!(?done, "final WAL checkpoint was incomplete")
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "final WAL checkpoint failed"),
    }
    res
}

/// Serve `app` on `listener` until `shutdown` resolves, then stop accepting connections and
/// wait up to `drain` for in-flight requests before giving up on them. Connections get the
/// default `[limits] header_read_timeout_seconds`
/// ([`config::DEFAULT_HEADER_READ_TIMEOUT_SECONDS`]).
///
/// It never speaks TLS: every connection is plain HTTP, whatever the config says. [`run`] and
/// [`serve`] serve `[server.tls]`. A router that [`router`] or [`build`] made over a state with
/// `[server.tls]` answers every request served here with `500` (empty body, an error logged),
/// so it is never served in cleartext while discovery names `https://` URLs.
///
/// # Errors
///
/// When the server task fails with an I/O error or panics, before or during the drain. A drain
/// that times out is not an error: the requests still running are abandoned (no longer waited
/// for; each connection closes when its request ends).
pub async fn serve_until(
    listener: tokio::net::TcpListener,
    app: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    drain: std::time::Duration,
) -> anyhow::Result<()> {
    let header_read_timeout =
        std::time::Duration::from_secs(config::DEFAULT_HEADER_READ_TIMEOUT_SECONDS);
    serve_until_drained(listener, app, None, shutdown, drain, header_read_timeout)
        .await
        .map(drop)
}

/// [`serve_until`], saying whether every connection was drained (`false`: the drain timed out).
/// Each connection gets `header_read_timeout` ([`listen`]), and speaks TLS with `tls`.
async fn serve_until_drained(
    listener: tokio::net::TcpListener,
    app: Router,
    tls: Option<tokio_rustls::TlsAcceptor>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    drain: std::time::Duration,
    header_read_timeout: std::time::Duration,
) -> anyhow::Result<bool> {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server = listen::serve(listener, app, tls, header_read_timeout, async move {
        let _ = rx.await;
    });
    let mut server = tokio::spawn(server);
    tokio::select! {
        res = &mut server => return res.map(|()| true).map_err(Into::into),
        () = shutdown => {}
    }
    tracing::info!(
        drain_seconds = drain.as_secs_f32(),
        "shutdown signal received; draining"
    );
    let _ = tx.send(());
    match tokio::time::timeout(drain, &mut server).await {
        Ok(res) => {
            res?;
            tracing::info!("shutdown complete");
            Ok(true)
        }
        Err(_) => {
            // Wait for the abort, so the server future (and its copy of `app`) is dropped
            // before this returns. Requests still running on their connections are not stopped
            // by it: they end on their own.
            server.abort();
            let _ = server.await;
            tracing::warn!("drain timeout elapsed; abandoning the requests still running");
            Ok(false)
        }
    }
}

/// A copy of this is in every copy of a router [`serve_and_release`] serves: in the router
/// itself, in each connection's service and in each request.
#[derive(Clone)]
struct RouterCopy {
    _held: tokio::sync::mpsc::Sender<()>,
}

/// [`serve_until`], then, after a clean drain, wait until every copy of `app` is gone. axum's
/// drain ends when each connection's task has said it is done, which it says a moment before
/// it drops its copy of the router (and so of the state): this is what makes "drained" mean
/// "dropped". After a timed-out drain the requests still running keep their copies, and this
/// does not wait for them.
async fn serve_and_release(
    listener: tokio::net::TcpListener,
    app: Router,
    tls: Option<tokio_rustls::TlsAcceptor>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    drain: std::time::Duration,
    header_read_timeout: std::time::Duration,
) -> anyhow::Result<()> {
    let (copy, mut copies) = tokio::sync::mpsc::channel::<()>(1);
    let app = app.layer(axum::Extension(RouterCopy { _held: copy }));
    if serve_until_drained(listener, app, tls, shutdown, drain, header_read_timeout).await? {
        // Nothing is sent: `recv` answers `None` once the last sender, so the last copy, is gone.
        if tokio::time::timeout(drain, copies.recv()).await.is_err() {
            tracing::warn!("a copy of the router outlived the drain");
        }
    }
    Ok(())
}

/// Resolves on SIGINT (Ctrl-C) or, on Unix, SIGTERM (what `docker stop` and Kubernetes send).
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => tracing::info!("received SIGINT"),
                    _ = term.recv() => tracing::info!("received SIGTERM"),
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "cannot install SIGTERM handler; SIGINT only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;
    use std::time::{Duration, Instant};

    async fn slow() -> &'static str {
        tokio::time::sleep(Duration::from_millis(300)).await;
        "done"
    }

    async fn forever() -> &'static str {
        tokio::time::sleep(Duration::from_secs(60)).await;
        "never"
    }

    async fn start(
        drain: Duration,
    ) -> (
        String,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        let app = Router::new()
            .route("/slow", get(slow))
            .route("/forever", get(forever));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(serve_until(
            listener,
            app,
            async move {
                let _ = rx.await;
            },
            drain,
        ));
        (base, tx, task)
    }

    #[tokio::test]
    async fn in_flight_request_finishes_during_drain() {
        let (base, stop, task) = start(Duration::from_secs(5)).await;
        let url = format!("{base}/slow");
        let req = tokio::spawn(async move { reqwest::get(url).await.unwrap().text().await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        stop.send(()).unwrap();
        assert_eq!(req.await.unwrap().unwrap(), "done");
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn stuck_request_is_cut_off_after_drain_timeout() {
        let (base, stop, task) = start(Duration::from_millis(300)).await;
        let url = format!("{base}/forever");
        let req = tokio::spawn(async move { reqwest::get(url).await.map(|_| ()) });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let t = Instant::now();
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert!(t.elapsed() < Duration::from_secs(5));
        req.abort();
    }

    /// A server on `dir`'s SQLite file with everything `run` starts next to the main listener:
    /// the checkpoint timer, lease maintenance, the metrics listener and the admin console.
    fn everything_on(dir: &std::path::Path) -> Config {
        let mut cfg = Config::default();
        cfg.audit.sqlite_path = dir.join("audit.sqlite").to_string_lossy().into_owned();
        cfg.audit.checkpoint_interval_seconds = 1;
        cfg.leases.maintenance_interval_seconds = 1;
        cfg.admin.token = Some("restart-test-admin".into());
        cfg.metrics.enabled = true;
        cfg.metrics.listen = "127.0.0.1:0".parse().unwrap();
        cfg.admin_ui.enabled = true;
        cfg.admin_ui.listen = "127.0.0.1:0".parse().unwrap();
        cfg
    }

    /// A free loopback port, for a listener `run` binds itself (`[admin] listen`).
    ///
    /// The port is released before `run` binds it, so it must be one no other test can be given
    /// in between. A `127.0.0.1:0` bind takes its port from the system's ephemeral range, and
    /// the tests in this binary run in parallel and bind that way all the time: one of them
    /// could get the port just released, and the request meant for this server would reach
    /// that one. So the port comes from below the ephemeral range, and a counter keeps two
    /// calls in this process apart.
    fn free_port() -> std::net::SocketAddr {
        use std::sync::atomic::{AtomicU16, Ordering};
        const FIRST: u16 = 20_000;
        const COUNT: u16 = 12_000;
        static NEXT: AtomicU16 = AtomicU16::new(0);
        // Start at a different place in each process, so two test binaries do not walk the same ports.
        // The odd factor spreads neighbouring process ids apart.
        let start =
            u16::try_from(u64::from(std::process::id()) * 7919 % u64::from(COUNT)).unwrap_or(0);
        for _ in 0..COUNT {
            let step = NEXT.fetch_add(1, Ordering::Relaxed) % COUNT;
            let port = FIRST + (start + step) % COUNT;
            if let Ok(l) = std::net::TcpListener::bind(("127.0.0.1", port)) {
                return l.local_addr().unwrap();
            }
        }
        panic!(
            "no free loopback port between {FIRST} and {}",
            FIRST + COUNT - 1
        );
    }

    /// Stop a server through `run` and start the next one on the same file at once, again and
    /// again: once `run` has returned and the caller has dropped its state, nothing holds the
    /// single-writer fence, so the next start never meets it. Nothing waits in between, not
    /// even a yield to the scheduler. Each server is used first (a request that reads the database, over a
    /// connection the client keeps open across the stop), so a connection task holds a copy
    /// of the router when the stop begins. With `own_admin_listener`, `[admin] listen` is set
    /// too and that request goes to the admin listener, so it is that listener's connection
    /// that holds a copy (S-1); the main listener is used as well, for `/readyz`.
    async fn stop_and_restart_in_a_loop(own_admin_listener: bool) {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = everything_on(dir.path());
        if own_admin_listener {
            cfg.admin.listen = Some(free_port());
        }
        let client = reqwest::Client::new();
        let (mut app, mut state) = build(&cfg).unwrap();
        assert!(state.store_fence().is_some());
        for round in 0..20 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let main = listener.local_addr().unwrap();
            let url = format!(
                "http://{}/admin/audit/verify",
                cfg.admin.listen.unwrap_or(main)
            );
            let ready = format!("http://{main}/readyz");
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let released = state.released();
            // `run` is polled in this task, not spawned: the restart below follows its return
            // without a turn of the scheduler in between, so a task it left behind (aborted but
            // not yet dropped, or a connection still closing) would still hold the state.
            let serving = run(&cfg, state.clone(), app, listener, async move {
                let _ = stopped.await;
            });
            let using = async {
                // The admin listener is bound inside `run`: wait until it answers.
                let mut tries = 0;
                let resp = loop {
                    match client
                        .get(&url)
                        .bearer_auth("restart-test-admin")
                        .send()
                        .await
                    {
                        Ok(resp) => break resp,
                        Err(_) if tries < 200 => {
                            tries += 1;
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                        Err(e) => panic!("round {round}: {e}"),
                    }
                };
                assert!(
                    resp.status().is_success(),
                    "round {round}: {}",
                    resp.status()
                );
                // Ready, except for the DPoP restart fence: a restart this quick fences
                // proofs for some seconds, and `/readyz` says so (`crate::dpop`).
                let resp = client.get(&ready).send().await.unwrap();
                let status = resp.status();
                let body: serde_json::Value = resp.json().await.unwrap();
                let fenced = round > 0 && body["checks"]["dpop_restart_fence"] == "fenced";
                assert!(
                    status.is_success() || fenced,
                    "round {round}: {status} {body}"
                );
                for check in ["audit", "audit_append", "leases"] {
                    assert_eq!(body["checks"][check], "ok", "round {round}: {body}");
                }
                stop.send(()).unwrap();
            };
            let (res, ()) = tokio::join!(serving, using);
            res.unwrap();
            drop(state);
            (app, state) = build(&cfg).unwrap_or_else(|e| {
                panic!("round {round}: the stopped server still holds the database: {e:#}")
            });
            // The state was dropped just now, so this is already resolved.
            tokio::time::timeout(Duration::from_secs(1), released)
                .await
                .expect("released resolves once the state is dropped");
        }
    }

    #[tokio::test]
    async fn a_server_stopped_by_run_can_be_restarted_on_its_file_at_once() {
        stop_and_restart_in_a_loop(false).await;
    }

    /// The same on a multi-threaded runtime, where the connection tasks, the timers and the
    /// other listeners run on other workers than `run` itself.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_server_stopped_by_run_can_be_restarted_at_once_on_many_threads() {
        stop_and_restart_in_a_loop(false).await;
    }

    /// S-1: with `[admin] listen`, the admin listener goes through the same stop and drain,
    /// so the fence is released as soon as `run` returns.
    #[tokio::test]
    async fn a_server_with_an_admin_listener_can_be_restarted_on_its_file_at_once() {
        stop_and_restart_in_a_loop(true).await;
    }

    /// The same on a multi-threaded runtime.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_server_with_an_admin_listener_can_be_restarted_at_once_on_many_threads() {
        stop_and_restart_in_a_loop(true).await;
    }
}

#[cfg(test)]
mod maintenance_tests {
    use super::*;
    use attenuo_audit::LeaseRegistry;
    use attenuo_core::LeaseId;

    /// A server on an in-memory store with a lease retention of 1 s, the given
    /// `[leases] maintenance_batch_rows` and `maintenance_max_passes`, and 30 single-lease
    /// runs that expired an hour ago (so all of them are prunable).
    fn state_with_ended_runs(batch_rows: u64, max_passes: u64) -> Arc<AppState> {
        let mut cfg = Config::default();
        cfg.audit.sqlite_path = ":memory:".into();
        cfg.leases.retention_seconds = 1;
        cfg.leases.maintenance_batch_rows = batch_rows;
        cfg.leases.maintenance_max_passes = max_passes;
        let state = AppState::from_config(&cfg).unwrap();
        assert_eq!(
            state.lease_maintenance.batch_rows,
            usize::try_from(batch_rows).unwrap()
        );
        assert_eq!(
            state.lease_maintenance.max_passes,
            usize::try_from(max_passes).unwrap()
        );
        let expired = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
        for n in 0..30 {
            let id = LeaseId::new(format!("run{n:02}"));
            state.leases.register(&id, None, expired).unwrap();
        }
        Arc::new(state)
    }

    /// Runs of `prune_lease_registry` until one deletes nothing; returns what each deleted.
    async fn runs_until_clean(state: &Arc<AppState>) -> Vec<u64> {
        let mut runs = Vec::new();
        loop {
            let n = prune_lease_registry(state).await;
            if n == 0 {
                return runs;
            }
            runs.push(n);
            assert!(runs.len() < 100, "pruning does not finish: {runs:?}");
        }
    }

    /// `maintenance_batch_rows` sets the size of a pass and `maintenance_max_passes` how many
    /// one run makes: with one pass per run, a batch of 7 needs at least five runs (passes)
    /// for the 30 ended runs and never deletes more than 7 in one, where a batch of 1,000
    /// deletes them all in one; with 100 passes per run, the batch of 7 is done in one run
    /// again. What gets pruned is the same either way.
    #[tokio::test]
    async fn a_smaller_maintenance_batch_takes_more_passes() {
        let small = runs_until_clean(&state_with_ended_runs(7, 1)).await;
        assert!(small.len() >= 5, "{small:?}");
        assert!(small.iter().all(|&n| n <= 7), "{small:?}");
        assert_eq!(small.iter().sum::<u64>(), 30);

        assert_eq!(
            runs_until_clean(&state_with_ended_runs(1_000, 1)).await,
            [30]
        );
        assert_eq!(runs_until_clean(&state_with_ended_runs(7, 100)).await, [30]);

        let two = runs_until_clean(&state_with_ended_runs(7, 2)).await;
        assert!(two.iter().all(|&n| n <= 14), "{two:?}");
        assert!(
            two.len() >= 3 && two.len() < small.len(),
            "{two:?} vs {small:?}"
        );
        assert_eq!(two.iter().sum::<u64>(), 30);
    }

    /// `[leases]` maintenance settings out of range stop the server from starting.
    #[test]
    fn out_of_range_maintenance_settings_refuse_to_start() {
        for (key, value) in [
            ("maintenance_interval_seconds", 0),
            ("maintenance_batch_rows", 0),
            ("maintenance_batch_rows", 100_001),
            ("maintenance_max_passes", 0),
            ("maintenance_max_passes", 10_001),
        ] {
            let mut cfg = Config::from_toml(&format!("[leases]\n{key} = {value}\n")).unwrap();
            cfg.audit.sqlite_path = ":memory:".into();
            let err = AppState::from_config(&cfg).err().expect(key).to_string();
            assert!(err.starts_with(&format!("[leases] {key} must be")), "{err}");
        }
    }
}
