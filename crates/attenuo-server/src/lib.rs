//! `attenuo-server`: wires the token issuer, policy engine, audit log, lease registry and MCP
//! proxy into one HTTP service.
//!
//! The crate holds no authorization logic of its own beyond composing the others
//! ([ADR-0004](../../docs/decisions/0004-rust-workspace-layout.md)); the one place a call is
//! decided is [`authz::Pipeline::decide`]. See `docs/design/server.md` for the request flow.
//!
//! | Route | Auth | Purpose |
//! |---|---|---|
//! | `POST /token` | client credentials + IdP credential | hop 0 from an OIDC ID token or ID-JAG ([`idp`]) |
//! | `POST /token` | subject token in body; actor by client credentials or `actor_token` ([`actor`]) | RFC 8693 exchange, hop n to n+1 |
//! | `POST /token/renew` | delegation token (bearer; with a `DPoP` proof when bound, [`dpop`]) | extend the last hop's lease |
//! | `POST /access/v1/evaluation` | delegation token (bearer); or `[[peps]]` credentials with `[authzen] allow_unsigned_chain` | AuthZEN evaluation |
//! | `POST /access/v1/evaluations` | same as above | AuthZEN batch evaluation, at most `[authzen] max_batch` entries |
//! | `GET /.well-known/authzen-configuration` | none | AuthZEN metadata |
//! | `GET /.well-known/jwks.json` | none | issuer public key |
//! | `GET /healthz` | none | liveness |
//! | `GET /metrics` | none | Prometheus metrics, on `[metrics] listen` only (separate port) |
//! | `GET /readyz` | none | readiness: audit store and lease store answer; `[audit.sink]` health ([`sink`]) |
//! | `POST/GET/DELETE /mcp/{server}` | delegation token | MCP proxy |
//! | `POST /admin/root-token` | admin | dev-only hop-0 mint ([`routes::dev_root`]), mounted only with `[dev] allow_root_mint = true` |
//! | `POST /admin/leases/{id}/revoke`, `GET /admin/leases/{id}` | admin | leases |
//! | `POST /admin/leases/revoke?preview` | admin | revoke every lease of one user, one chain, or the chains that opened one MCP session (`session`), with the cascade, audited ([`routes::admin::revoke_by_selector`]) |
//! | `GET /admin/leases/{id}/tree?max_nodes` | admin | lease subtree, ancestors and how many leases a revoke would change (read-only, [`routes::admin::lease_tree`]) |
//! | `POST /admin/budgets/refund` | admin | return what one decision charged to the run limits, once, audited ([`routes::admin::refund_budget`]) |
//! | `GET /admin/audit`, `/admin/audit/verify`, `/admin/audit/checkpoint` | admin | audit |
//! | `GET /admin/audit/entries/{seq}`, `/admin/audit/records/{id}`, `/admin/audit/checkpoints` | admin | one entry with its context; stored checkpoints (read-only) |
//! | `GET /admin/audit/export?from&to` | admin | stream a verifiable slice of the log as JSON Lines |
//! | `POST /admin/policies/reload` | admin | hot-reload the Cedar policy file |
//! | `GET /admin/policies` | admin | the policy set in force: ids, text, file digest, load time ([`routes::policies`]) |
//! | `GET /admin/policies/check` | admin | lint the policy file on disk against the running schema; swaps nothing |
//! | `POST /admin/policies/evaluate` | admin | dry run: what the loaded policies say about one call, optionally with a stated run-limit state (`budget`); no lease check, no charge, no audit |
//! | `POST /approvals/{id}` | the originating user's IdP ID token (never a delegation token) | grant or decline a pending approval ([`routes::approvals`]) |
//! | `GET /approvals/{id}` | the user's ID token, or a delegation token of the same run | the approval: exact call, labels, state, expiry |
//! | `GET /admin/approvals?chain_id`, `GET /admin/approvals/{id}`, `POST /admin/approvals/{id}` | admin | list, show, and grant or decline as an operator |
//!
//! **Console listener.** With `[admin_ui] enabled = true` a second listener on
//! `[admin_ui] listen` (default `127.0.0.1:9101`) serves the embedded console under
//! `/admin/ui/` and the admin routes above that have no side effect, behind the same admin
//! bearer; revoke, reload and budget refunds only with `[admin_ui] allow_write = true`, and never
//! `/admin/root-token`. Every response there carries a strict CSP and the other headers in
//! [`admin_ui::SECURITY_HEADERS`], and no CORS headers. See [`admin_ui`].

#![deny(unsafe_code)]

pub mod actor;
pub mod admin_ui;
pub mod authz;
pub mod clientauth;
pub mod config;
pub mod dpop;
pub mod error;
pub mod idp;
pub mod jwks;
pub mod metrics;
pub mod replay;
pub mod routes;
pub mod sink;
pub mod state;

use std::sync::Arc;

use attenuo_proxy::{ProxyConfig, UpstreamConfig};
use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

pub use authz::{Pipeline, PipelineDecision, ServerAuthorizer};
pub use config::Config;
pub use state::AppState;

/// Build the state and the full router from a config.
pub fn build(config: &Config) -> anyhow::Result<(Router, Arc<AppState>)> {
    let state = Arc::new(AppState::from_config(config)?);
    let router = router(state.clone(), config.upstreams.clone(), config);
    Ok((router, state))
}

/// The full router over an existing state.
pub fn router(state: Arc<AppState>, upstreams: Vec<UpstreamConfig>, config: &Config) -> Router {
    use routes::{admin, approvals, authzen, dev_root, policies, renew, token, wellknown};

    let mut admin_routes = Router::new()
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
        .route("/admin/policies", get(policies::get_policies))
        .route("/admin/policies/check", get(policies::check_policies))
        .route(
            "/admin/policies/evaluate",
            post(policies::evaluate_policies),
        )
        .route("/admin/policies/reload", post(admin::reload_policies))
        .route("/admin/approvals", get(approvals::admin_list))
        .route(
            "/admin/approvals/{id}",
            get(approvals::admin_get).post(approvals::admin_decide),
        );
    if state.dev_allow_root_mint {
        admin_routes = admin_routes.route("/admin/root-token", post(dev_root::mint_root));
    }
    let admin_routes = admin_routes
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            admin::require_admin,
        ))
        // Added last, so it wraps `require_admin` and its 401/403 answers get the headers too.
        .route_layer(axum::middleware::from_fn(admin::admin_response_headers));

    let api = Router::new()
        .route("/healthz", get(wellknown::healthz))
        .route("/readyz", get(routes::ops::readyz))
        .route("/.well-known/jwks.json", get(wellknown::jwks))
        .route(
            "/.well-known/authzen-configuration",
            get(wellknown::authzen_configuration),
        )
        .route("/token", post(token::exchange))
        .route("/token/renew", post(renew::renew))
        .route(
            "/approvals/{id}",
            get(approvals::user_get).post(approvals::user_decide),
        )
        .route("/access/v1/evaluation", post(authzen::evaluation))
        .route("/access/v1/evaluations", post(authzen::evaluations))
        .merge(admin_routes)
        .with_state(state.clone())
        .layer(TraceLayer::new_for_http());

    let authorizer = Arc::new(
        ServerAuthorizer::new(state.verifier.clone(), state.pipeline.clone())
            .with_dpop(state.dpop.clone()),
    );
    let proxy = attenuo_proxy::router(
        // Validated in `AppState::from_config`.
        config
            .proxy
            .apply(ProxyConfig::new(config.server.listen, upstreams)),
        authorizer,
    );
    api.merge(proxy)
        .layer(axum::middleware::from_fn_with_state(
            state.dpop.clone(),
            dpop::nonce_header,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.metrics.clone(),
            metrics::track_http,
        ))
}

/// Start the `[audit] checkpoint_interval_seconds` timer: every `period`, sign the head if
/// entries were appended since the newest checkpoint. (The `checkpoint_every` count trigger
/// runs inside the append itself.) Dropping the handle does not stop it; abort it to stop.
pub fn spawn_checkpointer(
    state: Arc<AppState>,
    period: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await; // the first tick is immediate
        loop {
            tick.tick().await;
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
    })
}

/// How long `[audit.sink]` keeps delivering queued checkpoints after a shutdown signal.
pub const SINK_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// How long in-flight requests get to finish after a shutdown signal.
pub const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Bind `[server] listen` and serve until SIGINT or SIGTERM, then drain for [`DRAIN_TIMEOUT`].
pub async fn serve(config: Config) -> anyhow::Result<()> {
    let (app, state) = build(&config)?;
    let listener = tokio::net::TcpListener::bind(config.server.listen).await?;
    tracing::info!(addr = %listener.local_addr()?, upstreams = config.upstreams.len(), "attenuo server listening");
    let checkpoint_task = (!state.checkpoint_interval.is_zero())
        .then(|| spawn_checkpointer(state.clone(), state.checkpoint_interval));
    let metrics_task = if config.metrics.enabled {
        let l = tokio::net::TcpListener::bind(config.metrics.listen).await?;
        tracing::info!(addr = %l.local_addr()?, "metrics listening (unauthenticated)");
        let app = metrics::router(state.metrics.clone());
        Some(tokio::spawn(async move { axum::serve(l, app).await }))
    } else {
        None
    };
    let console_task = if config.admin_ui.enabled {
        let l = tokio::net::TcpListener::bind(config.admin_ui.listen).await?;
        tracing::info!(
            addr = %l.local_addr()?,
            allow_write = config.admin_ui.allow_write,
            "admin console listening at /admin/ui/"
        );
        let app = admin_ui::router(state.clone(), &config);
        Some(tokio::spawn(async move { axum::serve(l, app).await }))
    } else {
        None
    };
    let res = serve_until(listener, app, shutdown_signal(), DRAIN_TIMEOUT).await;
    if let Some(t) = console_task {
        t.abort();
    }
    if let Some(t) = metrics_task {
        t.abort();
    }
    if let Some(t) = checkpoint_task {
        t.abort();
    }
    // Give checkpoints still queued for `[audit.sink]` a moment to leave the host.
    if state.checkpoint_sink.is_some() {
        let s = state.clone();
        let _ = tokio::task::spawn_blocking(move || {
            if let Some(sink) = &s.checkpoint_sink {
                sink.shutdown(SINK_SHUTDOWN_GRACE);
            }
        })
        .await;
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
/// wait up to `drain` for in-flight requests before giving up on them.
pub async fn serve_until(
    listener: tokio::net::TcpListener,
    app: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    drain: std::time::Duration,
) -> anyhow::Result<()> {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = rx.await;
    });
    let mut server = tokio::spawn(async move { server.await });
    tokio::select! {
        res = &mut server => return Ok(res??),
        () = shutdown => {}
    }
    tracing::info!(
        drain_seconds = drain.as_secs_f32(),
        "shutdown signal received; draining"
    );
    let _ = tx.send(());
    match tokio::time::timeout(drain, &mut server).await {
        Ok(res) => {
            res??;
            tracing::info!("shutdown complete");
        }
        Err(_) => {
            server.abort();
            tracing::warn!("drain timeout elapsed; closing remaining connections");
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
}
