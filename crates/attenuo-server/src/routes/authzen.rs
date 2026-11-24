//! `POST /access/v1/evaluation`: OpenID AuthZEN evaluation, served by the same [`Pipeline`]
//! as the proxy.
//!
//! Where the chain comes from:
//!
//! - **Default: the bearer.** The request must carry `Authorization: Bearer <delegation
//!   token>`. The token is verified and its chain is used. If the body also carries
//!   `subject.properties.chain`, it must equal the token's chain. An empty `subject.id` is
//!   filled with the chain's current agent. Without a bearer the answer is 401. A token
//!   bound to a key (`cnf.jkt`) needs a DPoP proof for this request ([`crate::dpop`]), made
//!   once per HTTP request (a batch's entries share it); `Authorization: DPoP <token>` is
//!   accepted as well.
//! - **Opt-in: an unsigned body chain from an authenticated PEP.** Only with
//!   `[authzen] allow_unsigned_chain = true`. The caller must authenticate as a `[[peps]]` entry
//!   (HTTP Basic, or `pep_id` and `pep_secret` in the body; 401 `invalid_client` otherwise), and
//!   `subject.properties.chain` is then checked structurally (`validate_at`) and hop by hop
//!   against what this server issued: each hop's lease must carry a binding equal to the digest
//!   of the chain up to that hop (`LeaseRegistry::bind`). A chain that does not match (a forged
//!   user, widened attributes, a lease reused on another hop) is refused with 403
//!   `chain_not_issued` *before* any audit record is written, so it cannot put records in a
//!   victim's name. Lease ids alone are not secret (they are in every token), which is why they
//!   are not enough (SR-08).
//!
//! **Approval tokens.** A request may carry a signed approval token (output labelling,
//! ADR-0009) in `context.approval_token`, as the proxy's `params._meta["dev.attenuo/approval"]`
//! carries it. It is checked against the evaluated call exactly as at the proxy, with the
//! bearer's `cnf.jkt` as the hop's key binding when the request proved possession of it (an
//! unsigned body chain has no key binding, so a token minted for a DPoP-bound hop is refused
//! there). A refused token answers `decision: false` with reason `approval_invalid`.
//!
//! The response is the AuthZEN `{decision, context}` with `context.reason`,
//! `context.policy_ids`, `context.diagnostics` and `context.decision_id` (the audit record).
//! `context.diagnostics` (effective capabilities, lease ids, Cedar errors) is empty unless
//! `[authzen] diagnostics` allows the caller: by default only a caller that authenticated as a
//! `[[peps]]` entry gets it. With a bearer token, a PEP authenticates with `pep_id` and
//! `pep_secret` in the body (SR-17).
//!
//! [`Pipeline`]: crate::authz::Pipeline

use std::sync::Arc;

use attenuo_audit::LeaseRegistry;
use attenuo_core::DelegationChain;
use attenuo_policy::authzen::{self, EvaluationRequest, EvaluationResponse};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use super::extract::Body;
use super::parse_json;
use crate::client_cert::ClientCertificate;
use crate::clientauth;
use crate::error::{ApiError, REASON_INVALID_TOKEN, REASON_MISSING_TOKEN};
use crate::state::AppState;

/// Error code when a body chain does not match what this server issued.
pub const CHAIN_NOT_ISSUED: &str = "chain_not_issued";
/// `code` of a PEP's unsigned body chain that does not validate (an expired hop, a widening,
/// too deep): sent with `error` `invalid_request`.
pub const INVALID_CHAIN: &str = "invalid_chain";

// The `Err` is a full response, built once per refused request; boxing it buys nothing.
/// `POST /access/v1/evaluation`: decide one AuthZEN request through the pipeline (see the
/// module docs for where the chain comes from). A refusal is returned as a full response.
///
/// # Errors
///
/// A full error response (with a `WWW-Authenticate` challenge on a 401): 400 `invalid_request` for
/// a body that is not an AuthZEN request, a body chain that differs from the token's or fails
/// `validate_at`, or a non-string `context.approval_token`; 401 for a missing, invalid or expired
/// bearer, a missing or bad DPoP proof, or, with an unsigned body chain, a PEP that does not
/// authenticate (`invalid_client`); 403 `chain_not_issued` for a body chain this server did not
/// issue. A policy or lease refusal is not an error but `decision: false`.
#[allow(clippy::result_large_err)]
pub async fn evaluation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    extensions: axum::http::Extensions,
    Body(body): Body,
) -> Result<Json<EvaluationResponse>, Response> {
    // Token checks, lease lookups and the audit append all touch SQLite; keep them off the
    // async workers.
    in_two_steps(
        state,
        headers,
        cert(&extensions),
        body,
        evaluate_bearer,
        evaluate,
    )
    .await
}

/// The TLS client certificate of the request's connection, which only the accept loop sets
/// ([`crate::listen`]).
fn cert(extensions: &axum::http::Extensions) -> Option<ClientCertificate> {
    extensions.get::<ClientCertificate>().cloned()
}

/// The first step of an AuthZEN request: what it read, and the bearer, checked.
type FirstStep<P> = fn(&AppState, &HeaderMap, &Bytes) -> Result<(P, Option<Bearer>), ApiError>;
/// The second step: the PEP's authentication and the decision.
type SecondStep<P, R> =
    fn(&AppState, &HeaderMap, P, Option<Bearer>, &PepKeys) -> Result<R, ApiError>;

/// Run an AuthZEN request on the blocking pool in two steps around the fetch of a PEP's
/// `jwks_url` keys, which is async: `first` parses the request and checks the bearer; only
/// once it has passed are the keys of the PEP the request's assertion names fetched
/// ([`PepKeys::fetch`]), and `second` authenticates the PEP and decides. So a request with a
/// bad bearer, or with none while `[authzen] allow_unsigned_chain` is off, makes no fetch.
// The `Err` is a full response, built once per refused request; boxing it buys nothing.
#[allow(clippy::result_large_err)]
async fn in_two_steps<P, R>(
    state: Arc<AppState>,
    headers: HeaderMap,
    cert: Option<ClientCertificate>,
    body: Bytes,
    first: FirstStep<P>,
    second: SecondStep<P, R>,
) -> Result<Json<R>, Response>
where
    P: Send + 'static,
    R: Send + 'static,
{
    let refused = |e: ApiError| with_challenge(e.into_response());
    let (h, b) = (headers.clone(), body.clone());
    let (prepared, bearer) = state
        .blocking(move |s| first(s, &h, &b))
        .await
        .map_err(refused)?;
    // Between the bearer check and the decision there can now be a key fetch (at most 5
    // seconds). That is safe: the bearer's signature and expiry were checked in `first`, and
    // the decision in `second` looks up the chain's leases and their expiry again, as of its
    // own time (a lease never outlives its token).
    let wanted = bearer.is_some() || state.authzen_allow_unsigned_chain;
    let peps = PepKeys::fetch(&state, &body, wanted, cert).await;
    state
        .blocking(move |s| second(s, &headers, prepared, bearer, &peps))
        .await
        .map(Json)
        .map_err(refused)
}

/// Without a bearer, only a PEP with an unsigned chain may call, under `[authzen]
/// allow_unsigned_chain`: refused before the PEP's credentials are looked at otherwise. The
/// refusal is the one [`admit`] gives.
fn caller_may_authenticate(state: &AppState, bearer: Option<&Bearer>) -> Result<(), ApiError> {
    if bearer.is_none() && !state.authzen_allow_unsigned_chain {
        return Err(missing_bearer());
    }
    Ok(())
}

fn missing_bearer() -> ApiError {
    ApiError::unauthorized(
        REASON_MISSING_TOKEN,
        "a delegation token is required: send `Authorization: Bearer <token>` \
         ([authzen] allow_unsigned_chain is off)",
    )
}

/// `POST /access/v1/evaluations`: the AuthZEN "boxcar" form. Top-level `subject`, `action`,
/// `resource` and `context` are defaults; each entry of `evaluations` may replace any of them.
/// Every entry that is decided is decided and audited exactly like a single evaluation, in order.
///
/// At most `[authzen] max_batch` entries. Without
/// `evaluations` (absent or an empty array) the request is a single evaluation and gets a
/// single `{decision, context}` answer (AuthZEN 1.0 section 7.1). `options.evaluations_semantic`
/// (section 7.1.2.1) is `execute_all` (default), `deny_on_first_deny` or
/// `permit_on_first_permit`; the last two decide in order and stop after the first deny (a
/// failed entry counts) or permit, answering only the entries decided so far.
///
/// # Errors
///
/// As [`evaluation`], for the request as a whole: 400 `invalid_request` when the body is not a JSON
/// object, `evaluations` is not an array or `options.evaluations_semantic` is unknown, 400
/// `batch_too_large` beyond `[authzen] max_batch`, and the 401 and 403 of authentication, which
/// refuse the whole batch. Any other failure of one entry is that entry's `decision: false` with
/// `context.error`.
// The `Err` is a full response, built once per refused request; boxing it buys nothing.
#[allow(clippy::result_large_err)]
pub async fn evaluations(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    extensions: axum::http::Extensions,
    Body(body): Body,
) -> Result<Json<Value>, Response> {
    in_two_steps(
        state,
        headers,
        cert(&extensions),
        body,
        batch_bearer,
        evaluate_batch,
    )
    .await
}

/// What [`batch_bearer`] read from a batch request: the body without `evaluations` and
/// `options`, the entries, and the semantic (`None` for a request without entries, which is a
/// single evaluation).
struct Batch {
    raw: Value,
    items: Vec<Value>,
    semantic: Option<Semantic>,
}

/// Error code when a batch carries more evaluations than `[authzen] max_batch`.
pub const BATCH_TOO_LARGE: &str = "batch_too_large";

/// The first step of a batch: parse it, check its size and semantic, and check the bearer.
fn batch_bearer(
    state: &AppState,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<(Batch, Option<Bearer>), ApiError> {
    let mut raw: Value = parse_json(body)?;
    let Some(obj) = raw.as_object_mut() else {
        return Err(ApiError::bad_request(
            "invalid_request",
            "expected a JSON object",
        ));
    };
    let items = match obj.remove("evaluations") {
        Some(Value::Array(items)) => items,
        None => Vec::new(),
        Some(_) => {
            return Err(ApiError::bad_request(
                "invalid_request",
                "`evaluations` must be an array",
            ))
        }
    };
    if items.is_empty() {
        // AuthZEN 1.0 section 7.1: without `evaluations` (absent or empty) the request behaves
        // as a single Access Evaluation request, and so does its answer.
        obj.remove("options");
        let bearer = bearer_auth(state, headers, "/access/v1/evaluations")?;
        return Ok((
            Batch {
                raw,
                items,
                semantic: None,
            },
            bearer,
        ));
    }
    // Refuse before any evaluation runs, so an oversized batch writes nothing to the audit log.
    if items.len() > state.authzen_max_batch {
        return Err(ApiError::bad_request(
            BATCH_TOO_LARGE,
            format!(
                "{} evaluations exceed [authzen] max_batch = {}",
                items.len(),
                state.authzen_max_batch
            ),
        ));
    }
    let semantic = Semantic::from_options(obj.get("options"))?;
    obj.remove("options");
    let bearer = bearer_auth(state, headers, "/access/v1/evaluations")?;
    Ok((
        Batch {
            raw,
            items,
            semantic: Some(semantic),
        },
        bearer,
    ))
}

fn evaluate_batch(
    state: &AppState,
    headers: &HeaderMap,
    batch: Batch,
    bearer: Option<Bearer>,
    peps: &PepKeys,
) -> Result<Value, ApiError> {
    // One snapshot of `[[peps]]` for the whole request: a reload during a batch does not admit
    // the PEP for some entries and refuse it for others.
    let clients = &peps.clients;
    let Batch {
        mut raw,
        items,
        semantic,
    } = batch;
    caller_may_authenticate(state, bearer.as_ref())?;
    let Some(semantic) = semantic else {
        let pep = pep_assertion(
            state,
            &clients.peps,
            &peps.fetched,
            &peps.cert,
            headers,
            &mut raw,
        )?;
        let r = evaluate_value(
            state,
            &clients.peps,
            headers,
            &peps.cert,
            bearer.as_ref(),
            pep.as_deref(),
            raw,
        )?;
        return serde_json::to_value(r).map_err(ApiError::internal);
    };
    // A PEP's client assertion authenticates the whole request once, like the bearer: its
    // `jti` can be used only once, so the entries cannot each check it.
    let pep = pep_assertion(
        state,
        &clients.peps,
        &peps.fetched,
        &peps.cert,
        headers,
        &mut raw,
    )?;
    let Some(obj) = raw.as_object_mut() else {
        return Err(ApiError::internal("request body is no longer an object"));
    };

    let mut results = Vec::with_capacity(items.len());
    for item in items {
        let Value::Object(item) = item else {
            results.push(item_error(&ApiError::bad_request(
                "invalid_request",
                "each evaluation must be an object",
            )));
            // A failed entry is a deny (section 7.2.1), so `deny_on_first_deny` stops here.
            if semantic.stops_at(false) {
                break;
            }
            continue;
        };
        let mut merged = obj.clone();
        for (k, v) in item {
            merged.insert(k, v);
        }
        let decision = match evaluate_value(
            state,
            &clients.peps,
            headers,
            &peps.cert,
            bearer.as_ref(),
            pep.as_deref(),
            Value::Object(merged),
        ) {
            Ok(r) => {
                let decision = r.decision;
                results.push(serde_json::to_value(r).map_err(ApiError::internal)?);
                decision
            }
            Err(e) if matches!(e.status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) => {
                return Err(e)
            }
            Err(e) => {
                results.push(item_error(&e));
                false
            }
        };
        if semantic.stops_at(decision) {
            break;
        }
    }
    Ok(json!({ "evaluations": results }))
}

/// The path of the Action Search API (AuthZEN 1.0 section 8, default path of section 10.1).
pub const SEARCH_ACTION_PATH: &str = "/access/v1/search/action";

/// The `tool` of the audit record an action search appends (kind `search`, SR-117).
pub const SEARCH_AUDIT_TOOL: &str = "authzen.search";

/// `POST /access/v1/search/action`: the AuthZEN Action Search API. Which actions (tools) the
/// subject may perform on the resource (an MCP server), in the request's context.
///
/// - **Who may call.** Exactly who may call `POST /access/v1/evaluation`, authenticated the same
///   way, by the same code: the agent's delegation token, or a `[[peps]]` entry with an
///   unsigned chain under `[authzen] allow_unsigned_chain`.
/// - **Resource.** The MCP server: `resource.properties.server`, else `resource.id`, which must
///   then hold no `/` (a `<server>/<tool>` id names one tool, not a server). `resource.type`
///   is not checked, as for evaluation. An `action` in the request is ignored (section 8 leaves
///   it out of this request).
/// - **Candidates.** The `[policy] catalog` tools of that server that the chain's capabilities
///   could permit (the proxy's `tools/list` filter), in name order. A tool the catalog does not
///   list is never a result, also under `unknown_tools = "allow"`; a catalogued tool outside the
///   capabilities is not a candidate, so paging does not count the catalog (SR-116).
/// - **Results.** The candidates for which the pipeline would allow the call
///   ([`Pipeline::would_allow`](crate::authz::Pipeline::would_allow)): each result, sent back
///   as the `action` of `POST /access/v1/evaluation` with the same subject, resource and
///   context, is decided `true` while the run's state is unchanged. Each result is `{"name":
///   <tool>, "properties": {"server": <server>}}`. No reason, policy id or diagnostic is
///   returned, so a caller learns no more than evaluating each candidate one at a time would
///   tell it.
/// - **One audit record, no other side effect.** Each answered request appends one record of
///   kind `search` (SR-117): decision `allow`, reason `search_answered`, the chain, `server`
///   the searched server, tool `authzen.search`, the `arguments_digest` an evaluation of the
///   same `context.input` would record, `session_id` and `dpop_bound` as an evaluation sets
///   them, and `search: {evaluated, permitted}`, the counts of this page. Not per candidate,
///   and not a decision: no charge to run limits or usage, no approval taken or requested, no
///   decision metric. If the append fails the search fails (500) and nothing is answered. A
///   request refused before any candidate is evaluated (a 400, 401, 403 or 429) writes no
///   record. An approval-gated tool is not a result. `context.approval_token` is refused (400
///   `approval_token_not_accepted`): an approval token is spent by the one decision it names.
/// - **Rate limit.** `[limits] authzen_search_requests_per_minute` (off by default) counts
///   searches per run, the chain's root lease, once the caller has authenticated and before
///   any candidate is evaluated, in a table apart from `mcp_requests_per_minute`. Over it the
///   answer is 429 `rate_limited` with `Retry-After`, nothing is evaluated and no record is
///   written (SR-117).
/// - **Paging** (section 8.2). At most `[authzen] max_batch` candidates are evaluated per
///   request, the bound of a batch. `page.limit` (1 or more; above `max_batch` it is clamped)
///   is how many candidates one page evaluates, so a page holds at most that many results and
///   may hold fewer, even none, while more remain. `page.next_token` is the token of the next
///   page, or `""` after the last; `page.count` is the number of results in this answer.
///   `page.token` sends it back, with the same `subject`, `resource` and `context`: the token
///   is an opaque position bound to digests of the chain, the server and the `context` it was
///   issued for ([`super::page::SearchBinding`]), and one sent with a request whose chain,
///   server or `context` differs is 400 `invalid_cursor`. `page.limit` may change between
///   pages, and a policy or catalog reload between pages is not detected (8.2 allows repeats
///   or skips then).
///
/// # Errors
///
/// 400 `invalid_request` for a body that is not a JSON object or whose `subject` or `resource`
/// is malformed (as for evaluation); 400 `invalid_page` for a `page` that is not an object, a
/// `page.token` that is not a string or a `page.limit` that is not a positive integer; 400
/// `invalid_cursor` for a `page.token` this route did not issue or issued for another chain,
/// server or `context`; 400 `invalid_search_resource`
/// when the resource names no server; 400 `approval_token_not_accepted`; 429 `rate_limited`
/// over `[limits] authzen_search_requests_per_minute`; the 401 and 403 of authentication, as
/// for evaluation; and 500 `server_error` when the search's audit record cannot be appended.
// The `Err` is a full response, built once per refused request; boxing it buys nothing.
#[allow(clippy::result_large_err)]
pub async fn search_action(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    extensions: axum::http::Extensions,
    Body(body): Body,
) -> Result<Json<Value>, Response> {
    in_two_steps(
        state,
        headers,
        cert(&extensions),
        body,
        search_bearer,
        search_actions,
    )
    .await
}

/// What [`search_bearer`] read from a search request: the body, with the server as its
/// `action`, the page and the server.
struct Search {
    raw: Value,
    page: SearchPage,
    server: String,
}

/// The `page` of a search request: where to start in the candidate list (a token not yet
/// checked against the request, or none for the first page) and how many candidates to
/// evaluate.
struct SearchPage {
    token: Option<super::page::SearchCursor>,
    limit: usize,
}

impl SearchPage {
    fn from_request(page: Option<&Value>, max: usize) -> Result<Self, ApiError> {
        let refuse = |detail: &str| {
            ApiError::bad_request("invalid_request", detail).with_code("invalid_page")
        };
        let page = match page {
            None | Some(Value::Null) => {
                return Ok(Self {
                    token: None,
                    limit: max,
                })
            }
            Some(Value::Object(p)) => p,
            Some(_) => return Err(refuse("`page` must be an object")),
        };
        let limit = match page.get("limit") {
            None | Some(Value::Null) => max,
            Some(v) => match v.as_u64() {
                Some(0) | None => {
                    return Err(refuse("`page.limit` must be an integer of at least 1"))
                }
                Some(n) => usize::try_from(n).unwrap_or(usize::MAX).min(max),
            },
        };
        let token = match page.get("token") {
            None | Some(Value::Null) => None,
            Some(Value::String(t)) => Some(t.as_str()),
            Some(_) => return Err(refuse("`page.token` must be a string")),
        };
        // AuthZEN's end-of-results token is the empty string; a client that sends it back is
        // asking for the first page again, which is what leaving it out does.
        let token = token.filter(|t| !t.is_empty());
        // Its shape is checked now, before authentication, as the other members of `page`;
        // whether it belongs to this request once the chain is known (`start`).
        let token = super::page::decode_search("page.token", token)?;
        Ok(Self { token, limit })
    }

    /// The index of the first candidate of this page: 0 without a token, else the token's
    /// position once it is checked to have been issued for `binding`.
    fn start(&self, binding: &super::page::SearchBinding) -> Result<usize, ApiError> {
        match &self.token {
            None => Ok(0),
            Some(t) => Ok(usize::try_from(t.position_for(binding)?).unwrap_or(usize::MAX)),
        }
    }
}

/// The MCP server an action search's `resource` names.
fn search_server(resource: Option<&Value>) -> Result<String, ApiError> {
    let refuse = |detail: &str| {
        ApiError::bad_request("invalid_request", detail).with_code("invalid_search_resource")
    };
    let Some(resource) = resource.and_then(Value::as_object) else {
        // Missing or not an object: the request is malformed, as at evaluation.
        return Err(ApiError::bad_request(
            "invalid_request",
            "`resource` is required and must be an object",
        ));
    };
    let from_props = resource
        .get("properties")
        .and_then(|p| p.get("server"))
        .and_then(Value::as_str);
    let server = match from_props {
        Some(s) => s,
        None => match resource.get("id").and_then(Value::as_str) {
            Some(id) if id.contains('/') => {
                return Err(refuse(
                    "`resource.id` names one tool (`<server>/<tool>`); name the server in \
                     `resource.properties.server` or as the whole `resource.id`",
                ))
            }
            Some(id) => id,
            None => return Err(refuse("`resource` names no MCP server")),
        },
    };
    if server.is_empty() {
        return Err(refuse("`resource` names no MCP server"));
    }
    Ok(server.to_string())
}

/// The first step of a search: parse it, read its page and server, and check the bearer.
fn search_bearer(
    state: &AppState,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<(Search, Option<Bearer>), ApiError> {
    let mut raw: Value = parse_json(body)?;
    let Some(obj) = raw.as_object_mut() else {
        return Err(ApiError::bad_request(
            "invalid_request",
            "expected a JSON object",
        ));
    };
    let page = SearchPage::from_request(obj.get("page"), state.authzen_max_batch)?;
    obj.remove("page");
    let server = search_server(obj.get("resource"))?;
    // The request has no `action`: each candidate becomes one. Until then the call names the
    // server only.
    obj.insert(
        "action".into(),
        json!({ "name": "", "properties": { "server": server } }),
    );
    let bearer = bearer_auth(state, headers, SEARCH_ACTION_PATH)?;
    Ok((Search { raw, page, server }, bearer))
}

fn search_actions(
    state: &AppState,
    headers: &HeaderMap,
    search: Search,
    bearer: Option<Bearer>,
    peps: &PepKeys,
) -> Result<Value, ApiError> {
    let clients = &peps.clients;
    let Search {
        mut raw,
        page,
        server,
    } = search;
    caller_may_authenticate(state, bearer.as_ref())?;
    let pep = pep_assertion(
        state,
        &clients.peps,
        &peps.fetched,
        &peps.cert,
        headers,
        &mut raw,
    )?;
    let a = admit(
        state,
        &clients.peps,
        headers,
        &peps.cert,
        bearer.as_ref(),
        pep.as_deref(),
        raw,
    )?;
    // `[limits] authzen_search_requests_per_minute`, per run (the root lease of the bearer's
    // chain, or of a PEP's issued unsigned chain): only once the caller has authenticated, so
    // a caller without the credentials cannot use up a run's searches, and before any
    // candidate is evaluated. A search over it writes no record; this bounds how fast a run
    // can try arguments, and the record of each answered search shows that it did (SR-117).
    if let Some(run) = attenuo_core::chain_id_of(&a.chain) {
        state.limits.admit_search(&run)?;
    }
    if a.req
        .context
        .as_ref()
        .and_then(|c| c.get("approval_token"))
        .is_some_and(|t| !t.is_null())
    {
        return Err(ApiError::bad_request(
            "invalid_request",
            "context.approval_token is not accepted by action search: an approval token is \
             spent by the one decision it names; send it to POST /access/v1/evaluation",
        )
        .with_code("approval_token_not_accepted"));
    }
    // AuthZEN 1.0 section 8.2: a token sent with another query is refused. The binding is
    // recomputed from this request, so a token only ever continues the query it came from.
    let binding = super::page::SearchBinding::new(&a.chain, &server, a.req.context.as_ref());
    let page_start = page.start(&binding)?;

    let engine = state.pipeline.policy_snapshot();
    // Only the catalogued tools the chain's capabilities could permit, the proxy's `tools/list`
    // filter: no other tool can be a result (the capability stage denies it), and paging over
    // them would count the catalog for the caller (SR-116).
    let caps = a.chain.effective_capabilities();
    let candidates: Vec<&str> = engine
        .catalog()
        .iter()
        .filter(|((s, _), _)| *s == server)
        .map(|((_, tool), _)| tool.as_str())
        .filter(|tool| {
            caps.is_some_and(|c| attenuo_proxy::filter::could_permit_tool(c, &server, tool))
        })
        .collect();
    let start = page_start.min(candidates.len());
    let end = start.saturating_add(page.limit).min(candidates.len());
    let window = &candidates[start..end];
    let allowed = state
        .pipeline
        .would_allow(&engine, &a.chain, &a.call, window, a.now);
    let results: Vec<Value> = window
        .iter()
        .zip(allowed)
        .filter(|(_, allow)| *allow)
        .map(|(tool, _)| json!({ "name": tool, "properties": { "server": server } }))
        .collect();
    let next_token = if end < candidates.len() {
        super::page::encode_search(end as u64, &binding)
    } else {
        String::new()
    };
    // One record per answered search, not per candidate (SR-117): the arguments are the call's,
    // as an evaluation of the same `context.input` digests them, and the counts of this page.
    // Not a decision: no decision metric, no charge, no approval. A failed append fails the
    // search, as it fails an issuance: nothing is answered that the log does not show.
    let mut call = a.call.clone();
    call.server.clone_from(&server);
    call.tool = SEARCH_AUDIT_TOOL.to_string();
    let record = attenuo_core::DecisionRecord::new(
        a.now,
        attenuo_core::Decision::Allow,
        attenuo_core::REASON_SEARCH_ANSWERED,
        &a.chain,
        &call,
        Vec::new(),
    )
    .with_kind(attenuo_core::RecordKind::Search)
    .with_search(attenuo_core::SearchInfo {
        evaluated: window.len() as u64,
        permitted: results.len() as u64,
    });
    super::append_audit(state, record)?;
    // The log line says that a search ran, for whom, and how much it looked at. `server` is
    // the caller's: Debug-format it so a newline cannot forge a log line (SR-18, SR-115).
    tracing::info!(
        chain_id = attenuo_core::chain_id_of(&a.chain).unwrap_or_default(),
        server = ?server,
        evaluated = window.len(),
        permitted = results.len(),
        "AuthZEN action search"
    );
    Ok(json!({
        "page": { "next_token": next_token, "count": results.len() },
        "results": results,
    }))
}

/// `options.evaluations_semantic` of a batch (AuthZEN 1.0 section 7.1.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Semantic {
    /// Decide every entry and answer every one (the default).
    ExecuteAll,
    /// Decide in order and stop after the first deny; a failed entry counts as a deny.
    DenyOnFirstDeny,
    /// Decide in order and stop after the first permit.
    PermitOnFirstPermit,
}

impl Semantic {
    /// The semantic the request names, `execute_all` when it names none. An unknown name, or
    /// a value that is not a string, is 400 `invalid_request` before anything is decided.
    fn from_options(options: Option<&Value>) -> Result<Self, ApiError> {
        match options.and_then(|o| o.get("evaluations_semantic")) {
            None | Some(Value::Null) => Ok(Self::ExecuteAll),
            Some(Value::String(s)) => match s.as_str() {
                "execute_all" => Ok(Self::ExecuteAll),
                "deny_on_first_deny" => Ok(Self::DenyOnFirstDeny),
                "permit_on_first_permit" => Ok(Self::PermitOnFirstPermit),
                other => Err(ApiError::bad_request(
                    "invalid_request",
                    format!(
                        "evaluations_semantic `{other}` is not supported; use `execute_all`, \
                         `deny_on_first_deny` or `permit_on_first_permit`"
                    ),
                )),
            },
            Some(_) => Err(ApiError::bad_request(
                "invalid_request",
                "evaluations_semantic must be a string",
            )),
        }
    }

    /// Whether the batch stops after an entry with this decision. The entries after it are not
    /// decided, not audited and not answered: the answer is shorter than the request, as in the
    /// section 7.1.2.1 examples.
    fn stops_at(self, decision: bool) -> bool {
        match self {
            Self::ExecuteAll => false,
            Self::DenyOnFirstDeny => !decision,
            Self::PermitOnFirstPermit => decision,
        }
    }
}

fn item_error(e: &ApiError) -> Value {
    e.debug_check();
    json!({
        "decision": false,
        "context": { "error": { "status": e.status.as_u16(), "code": e.stable_code(), "message": e.detail } },
    })
}

/// The request identifier header of the AuthZEN HTTPS binding (AuthZEN 1.0 section 10.1.3).
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Middleware for the AuthZEN routes: a request that carries `X-Request-ID` gets the same value
/// back on its response, whatever the status (AuthZEN 1.0 section 10.1.3: the PDP MUST echo
/// it). Only the first value is echoed; a header value cannot hold a line break, so it cannot
/// split the response.
pub async fn echo_request_id(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let id = req.headers().get(REQUEST_ID_HEADER).cloned();
    let mut resp = next.run(req).await;
    if let Some(id) = id {
        resp.headers_mut()
            .insert(header::HeaderName::from_static(REQUEST_ID_HEADER), id);
    }
    resp
}

fn with_challenge(mut resp: Response) -> Response {
    if resp.status() == StatusCode::UNAUTHORIZED
        && !resp.headers().contains_key(header::WWW_AUTHENTICATE)
    {
        resp.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"attenuo\""),
        );
    }
    resp
}

/// The `Authorization` header split into its scheme and value.
fn authorization(headers: &HeaderMap) -> Result<Option<(String, &str)>, ApiError> {
    let Some(raw) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let raw = raw.to_str().map_err(|_| {
        ApiError::unauthorized(REASON_INVALID_TOKEN, "authorization header is not ASCII")
    })?;
    match raw.split_once(' ') {
        Some((scheme, value)) if !value.trim().is_empty() => {
            Ok(Some((scheme.to_ascii_lowercase(), value.trim())))
        }
        _ => Err(ApiError::unauthorized(
            REASON_INVALID_TOKEN,
            "expected `Authorization: Bearer <token>`",
        )),
    }
}

/// The first step of an evaluation: parse it and check the bearer.
fn evaluate_bearer(
    state: &AppState,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<(Value, Option<Bearer>), ApiError> {
    let value = parse_json(body)?;
    let bearer = bearer_auth(state, headers, "/access/v1/evaluation")?;
    Ok((value, bearer))
}

fn evaluate(
    state: &AppState,
    headers: &HeaderMap,
    mut value: Value,
    bearer: Option<Bearer>,
    peps: &PepKeys,
) -> Result<EvaluationResponse, ApiError> {
    let clients = &peps.clients;
    caller_may_authenticate(state, bearer.as_ref())?;
    let pep = pep_assertion(
        state,
        &clients.peps,
        &peps.fetched,
        &peps.cert,
        headers,
        &mut value,
    )?;
    evaluate_value(
        state,
        &clients.peps,
        headers,
        &peps.cert,
        bearer.as_ref(),
        pep.as_deref(),
        value,
    )
}

/// A PEP's `private_key_jwt` client assertion (`client_assertion_type` and
/// `client_assertion` at the top level of the body), verified against `[[peps]]` and used
/// once: the PEP's id, or `None` when the body has no assertion. The fields are removed from
/// the body. `pep_id`, when sent, must equal the assertion's `sub`; a `pep_secret` or HTTP
/// Basic credentials alongside it are `multiple_client_auth`.
fn pep_assertion(
    state: &AppState,
    peps: &clientauth::Clients,
    fetched: &clientauth::FetchedKey,
    cert: &ConnCert,
    headers: &HeaderMap,
    body: &mut Value,
) -> Result<Option<String>, ApiError> {
    let Some(obj) = body.as_object_mut() else {
        return Ok(None);
    };
    let Some(assertion) = clientauth::take_client_assertion(obj)? else {
        return Ok(None);
    };
    let field = |k: &str| obj.get(k).and_then(Value::as_str);
    let now = state.now();
    let pep = peps.authenticate_with(
        headers,
        field("pep_id"),
        field("pep_secret"),
        Some(&assertion),
        fetched,
        cert.get(),
        now,
    )?;
    pep.commit(&state.replay, now).map(Some)
}

/// The `[[agents]]` and `[[peps]]` one AuthZEN request is checked against, the key of its
/// client assertion when the PEP's entry has `jwks_url` (fetched on the async side, before
/// the request goes to the blocking pool, where it is checked: [`pep_assertion`]), and the
/// TLS client certificate of its connection.
struct PepKeys {
    clients: Arc<clientauth::ClientSets>,
    fetched: clientauth::FetchedKey,
    /// Set by the accept loop only ([`crate::listen`]), never from a header.
    cert: ConnCert,
}

/// The TLS client certificate of an AuthZEN request's connection, and the PEP ids it has
/// authenticated during this request. A batch's entries share one request: the first entry
/// that authenticates a `pep_id` by the certificate makes the check (a thumbprint compare,
/// and a webpki check and a signature verification in [`ClientCertificate::check_usable`]),
/// and later entries with the same `pep_id` reuse its result. A refusal is not kept: it
/// refuses the whole request (401), so no later entry is decided. One request takes one
/// snapshot of the lists ([`PepKeys`]), so the result cannot go stale within it.
pub(crate) struct ConnCert {
    cert: Option<ClientCertificate>,
    authenticated: std::sync::Mutex<Vec<String>>,
}

impl ConnCert {
    pub(crate) fn new(cert: Option<ClientCertificate>) -> Self {
        Self {
            cert,
            authenticated: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn get(&self) -> Option<&ClientCertificate> {
        self.cert.as_ref()
    }

    /// The PEP `pep_id`, authenticated by `check` the first time this request asks for it
    /// and taken from the earlier result after that. `check` returns the id and whether it
    /// authenticated by the certificate; only such a result is kept (the request's headers,
    /// and so a Basic credential, are the same for every entry).
    pub(crate) fn authenticate_once(
        &self,
        pep_id: &str,
        check: impl FnOnce() -> Result<(String, bool), ApiError>,
    ) -> Result<String, ApiError> {
        let mut done = self
            .authenticated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if done.iter().any(|id| id == pep_id) {
            return Ok(pep_id.to_owned());
        }
        let (id, by_cert) = check()?;
        if by_cert && id == pep_id {
            done.push(id.clone());
        }
        Ok(id)
    }
}

impl PepKeys {
    /// The lists in force, and the key of the body's assertion, fetched only when `wanted`.
    async fn fetch(
        state: &AppState,
        body: &Bytes,
        wanted: bool,
        cert: Option<ClientCertificate>,
    ) -> Self {
        /// The top-level `client_assertion` of a body, the only place it may be.
        #[derive(serde::Deserialize)]
        struct Top {
            client_assertion: Option<Value>,
        }
        let clients = state.clients.snapshot();
        let fetched = if wanted && clients.peps.fetches_keys() {
            // A body that does not parse is refused later, by the check that parses it.
            let top = serde_json::from_slice::<Top>(body).ok();
            let assertion = top
                .as_ref()
                .and_then(|t| t.client_assertion.as_ref())
                .and_then(Value::as_str);
            clients.peps.fetch_key(assertion).await
        } else {
            clientauth::FetchedKey::none()
        };
        Self {
            clients,
            fetched,
            cert: ConnCert::new(cert),
        }
    }
}

/// The bearer's chain and DPoP binding, checked once per HTTP request: a batch's entries share
/// it, and a DPoP proof can be used only once.
struct Bearer {
    chain: DelegationChain,
    dpop_bound: bool,
    /// The token's `cnf.jkt` when `dpop_bound`.
    jkt: Option<String>,
}

/// Verify the `Authorization: Bearer` (or `DPoP`) token and its DPoP proof, if the request has
/// one. `Ok(None)` without a bearer (no header, or HTTP Basic for a PEP).
fn bearer_auth(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
) -> Result<Option<Bearer>, ApiError> {
    let auth = authorization(headers)?;
    let token = match &auth {
        Some((scheme, token)) if scheme == "bearer" || scheme == "dpop" => *token,
        Some((scheme, _)) if scheme == "basic" => return Ok(None),
        Some(_) => {
            return Err(ApiError::unauthorized(
                REASON_INVALID_TOKEN,
                "expected `Authorization: Bearer <token>`",
            ))
        }
        None => return Ok(None),
    };
    let now = state.now();
    let v = state
        .keys()
        .verifier
        .verify(token, now)
        .map_err(|e| ApiError::bad_token(&e))?;
    let dpop_bound = state.dpop.check_presented(
        v.claims.cnf.as_ref(),
        token,
        crate::dpop::header_proof(headers)?,
        "POST",
        &state.dpop.expected_url_for(headers, path),
        now,
    )?;
    let jkt = dpop_bound
        .then(|| v.claims.cnf.as_ref().map(|c| c.jkt.clone()))
        .flatten();
    Ok(Some(Bearer {
        chain: v.chain,
        dpop_bound,
        jkt,
    }))
}

/// An evaluation request whose caller is authenticated and whose chain is the bearer's, or a
/// PEP's unsigned chain this server issued ([`admit`]).
struct Admitted {
    req: EvaluationRequest,
    chain: DelegationChain,
    /// The call, with `dpop_bound` set from the bearer.
    call: attenuo_core::ToolCall,
    /// The caller proved it is a `[[peps]]` entry, which decides whether it sees diagnostics.
    pep_authenticated: bool,
    /// The time the request was admitted at; the decision is made as of it too.
    now: time::OffsetDateTime,
}

/// Authenticate the caller of one evaluation and settle its chain and call, deciding nothing:
/// the bearer's chain (checked against a body chain), or with `[authzen] allow_unsigned_chain`
/// a PEP's unsigned body chain checked against what this server issued. `pep_by_assertion` is
/// the PEP a client assertion of the request authenticated ([`pep_assertion`]); without one, a
/// PEP authenticates with its secret. Shared by the evaluation endpoints and action search, so
/// the three admit exactly the same callers.
#[allow(clippy::too_many_arguments)]
fn admit(
    state: &AppState,
    peps: &clientauth::Clients,
    headers: &HeaderMap,
    conn: &ConnCert,
    bearer: Option<&Bearer>,
    pep_by_assertion: Option<&str>,
    raw: Value,
) -> Result<Admitted, ApiError> {
    let cert = conn.get();
    if raw.get("client_assertion").is_some() || raw.get("client_assertion_type").is_some() {
        // Only the request's top level may carry an assertion (see `pep_assertion`).
        return Err(clientauth::invalid_request(
            "malformed_request",
            "client_assertion goes at the top level of the request, not in an evaluation",
        ));
    }
    let pep_field = |k: &str| raw.get(k).and_then(Value::as_str).map(str::to_owned);
    let (pep_id, pep_secret) = (pep_field("pep_id"), pep_field("pep_secret"));
    if pep_by_assertion.is_some() && pep_secret.is_some() {
        return Err(clientauth::invalid_request(
            "multiple_client_auth",
            "use either pep_secret or client_assertion, not both (RFC 6749 §2.3)",
        ));
    }
    let mut req: EvaluationRequest = serde_json::from_value(raw)
        .map_err(|e| ApiError::bad_request("invalid_request", e.to_string()))?;
    let now = state.now();

    // `body_chain_pep`: the PEP whose unsigned body chain is used. `pep_authenticated`: the
    // caller proved it is a `[[peps]]` entry, which decides whether it sees diagnostics.
    let (body_chain_pep, pep_authenticated) = match bearer {
        Some(b) => {
            attach_chain(&mut req, &b.chain)?;
            // A PEP forwarding an agent's token may authenticate itself in the body (the
            // `Authorization` header holds the bearer) to receive diagnostics.
            // Or with its TLS client certificate and `pep_id` (RFC 8705).
            let pep = match (pep_by_assertion, pep_secret.as_deref()) {
                (Some(pep), _) => Some(pep.to_owned()),
                (None, Some(secret)) => Some(
                    peps.authenticate(headers, pep_id.as_deref(), Some(secret), None, cert, now)?
                        .commit(&state.replay, now)?,
                ),
                (None, None) if pep_id.is_some() && cert.is_some() => Some(by_certificate(
                    state,
                    peps,
                    headers,
                    conn,
                    pep_id.as_deref(),
                    now,
                )?),
                (None, None) => None,
            };
            (None, pep.is_some())
        }
        None => {
            if !state.authzen_allow_unsigned_chain {
                return Err(missing_bearer());
            }
            let id = match pep_by_assertion {
                Some(pep) => pep.to_owned(),
                None if pep_secret.is_none() && pep_id.is_some() && cert.is_some() => {
                    by_certificate(state, peps, headers, conn, pep_id.as_deref(), now)?
                }
                None => peps
                    .authenticate(
                        headers,
                        pep_id.as_deref(),
                        pep_secret.as_deref(),
                        None,
                        cert,
                        now,
                    )?
                    .commit(&state.replay, now)?,
            };
            (Some(id), true)
        }
    };

    let (chain_value, call) = authzen::to_chain_and_call(&req)
        .map_err(|e| ApiError::bad_request("invalid_request", e.to_string()))?;
    if let Some(pep) = body_chain_pep {
        chain_value
            .validate_at(now, state.keys().verifier.max_depth())
            .map_err(|e| {
                // The code `POST /admin/policies/check` answers a chain that does not validate.
                ApiError::bad_request("invalid_request", e.to_string()).with_code(INVALID_CHAIN)
            })?;
        check_issued(state, &chain_value).map_err(|detail| {
            tracing::warn!(pep = ?pep, detail = ?detail, "AuthZEN body chain was not issued here");
            ApiError::new(StatusCode::FORBIDDEN, CHAIN_NOT_ISSUED, detail)
        })?;
        tracing::debug!(pep = ?pep, "AuthZEN body chain accepted from an authenticated PEP");
    }
    let call = call.with_dpop_bound(bearer.is_some_and(|b| b.dpop_bound));
    Ok(Admitted {
        req,
        chain: chain_value,
        call,
        pep_authenticated,
        now,
    })
}

/// A PEP that names itself with `pep_id` and sends no `pep_secret` and no assertion, over a
/// connection with a TLS client certificate: authenticated as [`clientauth::Clients::authenticate`]
/// decides (Basic credentials, if any, decide instead of the certificate), at most once per
/// request and `pep_id` ([`ConnCert::authenticate_once`]).
fn by_certificate(
    state: &AppState,
    peps: &clientauth::Clients,
    headers: &HeaderMap,
    conn: &ConnCert,
    pep_id: Option<&str>,
    now: time::OffsetDateTime,
) -> Result<String, ApiError> {
    let check = || {
        let a = peps.authenticate(headers, pep_id, None, None, conn.get(), now)?;
        let by_cert = a.client_cert_audit().is_some();
        Ok((a.commit(&state.replay, now)?, by_cert))
    };
    match pep_id {
        Some(id) => conn.authenticate_once(id, check),
        None => check().map(|(id, _)| id),
    }
}

/// Decide one evaluation: [`admit`], then the pipeline's decision.
fn evaluate_value(
    state: &AppState,
    peps: &clientauth::Clients,
    headers: &HeaderMap,
    cert: &ConnCert,
    bearer: Option<&Bearer>,
    pep_by_assertion: Option<&str>,
    raw: Value,
) -> Result<EvaluationResponse, ApiError> {
    let Admitted {
        req,
        chain: chain_value,
        call,
        pep_authenticated,
        now,
    } = admit(state, peps, headers, cert, bearer, pep_by_assertion, raw)?;
    let approval_token = match req.context.as_ref().and_then(|c| c.get("approval_token")) {
        None | Some(Value::Null) => None,
        Some(Value::String(t)) => Some(t.clone()),
        Some(_) => {
            return Err(ApiError::bad_request(
                "invalid_request",
                "context.approval_token must be a string",
            ))
        }
    };
    let ctx = attenuo_proxy::CallContext {
        approval_token,
        jkt: bearer.and_then(|b| b.jkt.clone()),
    };
    let mut d = state.pipeline.decide_with(&chain_value, &call, &ctx, now);
    let allow = d.is_allow();
    // Diagnostics name effective capabilities, lease ids and Cedar errors: reconnaissance for
    // anyone holding a token. Only PEPs get them unless configured otherwise (SR-17).
    let diagnostics = if state.authzen_diagnostics.allows(pep_authenticated) {
        std::mem::take(&mut d.diagnostics)
    } else {
        Vec::new()
    };
    let mut context = json!({
        "reason": d.reason,
        "policy_ids": d.policy_ids,
        "diagnostics": diagnostics,
        "decision_id": d.decision_id,
    });
    if d.reason == attenuo_policy::REASON_APPROVAL_REQUIRED {
        // What an approval is bound to (ADR-0009), as the proxy's `-32008` carries it.
        context["call_hash"] = json!(call.call_hash());
        if let Some(a) = &d.approval {
            context["approval_id"] = json!(a.approval_id);
            context["expires_at"] = json!(a
                .expires_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default());
        }
    }
    if let Some((id, by)) = &d.consumed_approval {
        context["approval"] = json!({ "id": id, "by": by });
        if d.approval_by_token {
            context["approval"]["presented"] = json!("token");
        }
    }
    // Run limits (ADR-0010): an evaluation is charged as a proxied call is. Only when a limit
    // matched, so answers about unlimited calls are unchanged.
    if d.budget.limited {
        context["budget"] = crate::authz::budget_json(&d.budget);
    }
    if let Some(hit) = &d.limit {
        context["limit"] = hit.to_json();
    }
    if let Some(charged) = &d.charged {
        context["charged"] = json!(charged.charged);
    }
    // Run usage (run-limits design section 3.5): only for a destructive tool, as on the
    // decision record, so answers about other tools are unchanged.
    if let Some(u) = &d.usage {
        context["usage"] = crate::authz::usage_json(u);
    }
    // Argument-level taint (ADR-0009 phase 2): only when an argument matched, so other
    // answers are unchanged.
    if !d.untrusted_args.is_empty() {
        context["untrusted_args"] = crate::authz::untrusted_args_json(&d.untrusted_args);
    }
    Ok(EvaluationResponse {
        decision: allow,
        context: Some(context),
    })
}

/// Every hop's lease must be bound to the digest of the chain up to that hop.
fn check_issued(state: &AppState, chain: &DelegationChain) -> Result<(), String> {
    for (i, hop) in chain.hops.iter().enumerate() {
        let expected = chain
            .prefix_digest(i)
            .ok_or_else(|| format!("hop {i} is out of range"))?;
        let bound = state
            .leases
            .binding(&hop.lease)
            .map_err(|e| format!("lease registry error: {e}"))?;
        if bound.as_deref() != Some(expected.as_str()) {
            return Err(format!(
                "hop {i} does not match the chain this server issued for its lease"
            ));
        }
    }
    Ok(())
}

/// Put the verified chain into `subject.properties.chain`, or check the one already there.
pub(crate) fn attach_chain(
    req: &mut EvaluationRequest,
    chain: &DelegationChain,
) -> Result<(), ApiError> {
    if req.subject.id.is_empty() {
        req.subject.id = chain
            .current_agent()
            .map(|a| a.0.clone())
            .unwrap_or_default();
    }
    let props = req
        .subject
        .properties
        .get_or_insert_with(|| Value::Object(Default::default()));
    let Some(obj) = props.as_object_mut() else {
        return Err(ApiError::bad_request(
            "invalid_request",
            "subject.properties must be an object",
        ));
    };
    match obj.get("chain") {
        None => {
            let v = serde_json::to_value(chain).map_err(ApiError::internal)?;
            obj.insert("chain".into(), v);
        }
        Some(given) => {
            let given: DelegationChain = serde_json::from_value(given.clone()).map_err(|e| {
                ApiError::bad_request("invalid_request", format!("subject.properties.chain: {e}"))
            })?;
            if &given != chain {
                return Err(ApiError::bad_request(
                    "chain_mismatch",
                    "subject.properties.chain differs from the bearer token's chain",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A batch checks a PEP's certificate once per `pep_id`: later entries reuse the result. A
    /// refusal, or an id that did not authenticate by the certificate, is not kept.
    #[test]
    fn a_certificate_is_checked_once_per_request_and_pep() {
        let conn = ConnCert::new(None);
        let calls = Cell::new(0);
        let ok = |id: &str, by_cert: bool| {
            calls.set(calls.get() + 1);
            Ok((id.to_owned(), by_cert))
        };
        for _ in 0..5 {
            assert_eq!(
                conn.authenticate_once("gw", || ok("gw", true)).unwrap(),
                "gw"
            );
        }
        assert_eq!(calls.get(), 1);
        // Another id makes its own check.
        assert_eq!(
            conn.authenticate_once("gw2", || ok("gw2", true)).unwrap(),
            "gw2"
        );
        assert_eq!(
            conn.authenticate_once("gw2", || ok("gw2", true)).unwrap(),
            "gw2"
        );
        assert_eq!(calls.get(), 2);
        // Not by the certificate (Basic decided): checked every time.
        for _ in 0..3 {
            conn.authenticate_once("basic", || ok("basic", false))
                .unwrap();
        }
        assert_eq!(calls.get(), 5);
        // A refusal is not kept: the next call checks again.
        let refused = || -> Result<(String, bool), ApiError> {
            calls.set(calls.get() + 1);
            Err(ApiError::unauthorized("invalid_client", "no"))
        };
        assert!(conn.authenticate_once("bad", refused).is_err());
        assert!(conn.authenticate_once("bad", refused).is_err());
        assert_eq!(calls.get(), 7);
    }
}
