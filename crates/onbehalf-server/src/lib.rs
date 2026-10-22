//! `onbehalf-server`: wires the token issuer, policy engine, audit log, lease registry and MCP
//! proxy into one HTTP service.
//!
//! The crate holds no authorization logic of its own beyond composing the others
//! ([ADR-0004](../../docs/decisions/0004-rust-workspace-layout.md)); the one place a call is
//! decided is [`authz::Pipeline::decide`]. See `docs/design/server.md` for the request flow.
//!
//! | Route | Auth | Purpose |
//! |---|---|---|
//! | `POST /token` | subject token in body | RFC 8693 exchange, hop n to n+1 |
//! | `POST /token/renew` | delegation token (bearer) | extend the last hop's lease |
//! | `POST /access/v1/evaluation` | optional bearer | AuthZEN evaluation |
//! | `GET /.well-known/authzen-configuration` | none | AuthZEN metadata |
//! | `GET /.well-known/jwks.json` | none | issuer public key |
//! | `GET /healthz` | none | liveness |
//! | `POST/GET/DELETE /mcp/{server}` | delegation token | MCP proxy |
//! | `POST /admin/root-token` | admin | dev-only hop-0 mint ([`routes::dev_root`]) |
//! | `POST /admin/leases/{id}/revoke`, `GET /admin/leases/{id}` | admin | leases |
//! | `GET /admin/audit`, `/admin/audit/verify`, `/admin/audit/checkpoint` | admin | audit |
//! | `POST /admin/policies/reload` | admin | hot-reload the Cedar policy file |

#![deny(unsafe_code)]

pub mod authz;
pub mod config;
pub mod error;
pub mod jwks;
pub mod routes;
pub mod state;

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use onbehalf_proxy::{ProxyConfig, UpstreamConfig};
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
    use routes::{admin, authzen, dev_root, renew, token, wellknown};

    let admin_routes = Router::new()
        .route("/admin/root-token", post(dev_root::mint_root))
        .route("/admin/leases/{lease_id}", get(admin::lease_status))
        .route("/admin/leases/{lease_id}/revoke", post(admin::revoke_lease))
        .route("/admin/audit", get(admin::audit_range))
        .route("/admin/audit/verify", get(admin::audit_verify))
        .route("/admin/audit/checkpoint", get(admin::audit_checkpoint))
        .route("/admin/policies/reload", post(admin::reload_policies))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            admin::require_admin,
        ));

    let api = Router::new()
        .route("/healthz", get(wellknown::healthz))
        .route("/.well-known/jwks.json", get(wellknown::jwks))
        .route(
            "/.well-known/authzen-configuration",
            get(wellknown::authzen_configuration),
        )
        .route("/token", post(token::exchange))
        .route("/token/renew", post(renew::renew))
        .route("/access/v1/evaluation", post(authzen::evaluation))
        .merge(admin_routes)
        .with_state(state.clone())
        .layer(TraceLayer::new_for_http());

    let authorizer = Arc::new(ServerAuthorizer::new(
        state.verifier.clone(),
        state.pipeline.clone(),
    ));
    let proxy = onbehalf_proxy::router(
        ProxyConfig::new(config.server.listen, upstreams),
        authorizer,
    );
    api.merge(proxy)
}

/// Bind `[server] listen` and serve until Ctrl-C.
pub async fn serve(config: Config) -> anyhow::Result<()> {
    let (app, _state) = build(&config)?;
    let listener = tokio::net::TcpListener::bind(config.server.listen).await?;
    tracing::info!(addr = %listener.local_addr()?, upstreams = config.upstreams.len(), "onbehalf server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await?;
    Ok(())
}
