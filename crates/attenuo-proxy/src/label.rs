//! Output labelling at the proxy (ADR-0009).
//!
//! Every response the upstream gives to an allowed mediated call (`tools/call`,
//! `resources/read`, `prompts/get`, `completion/complete`), JSON-RPC errors included, is
//! handed to [`Authorizer::record_result`] before it is relayed. The server's authorizer
//! appends a `tool_result` audit record and, for an untrusted result, labels the delegation
//! run. When that fails, the response is replaced by a JSON-RPC error with reason
//! `label_error`: the call ran upstream, but its result never reaches the agent.
//!
//! Responses are found the way list results are: a message with no string `method` whose `id`
//! matches the id of an allowed call of the same HTTP request, in a JSON body (single or
//! batch) or in the events of an SSE body, event by event. Every matching response is
//! recorded, so an upstream that answers one id twice gets two records, not one unlabelled
//! answer.
//!
//! An upstream may also answer on the `GET` listen stream: after answering the `POST` with
//! `202`, or when the client resumes a `POST` stream that broke off (`Last-Event-ID`). So the
//! proxy also remembers each allowed call before it forwards it, keyed by upstream,
//! `Mcp-Session-Id`, run (`chain_id`) and request id. An answer in the `POST`'s own
//! body strikes the entry; a response on a `GET` stream of the same upstream, session and run
//! claims it and is recorded (and withheld on failure) exactly like a `POST` answer, with the
//! chain and `decision_id` of the call. When the map is full, the run holding the most calls
//! gives up its oldest (SR-86), so one run cannot push out the calls of the others. So does a response in the body of a *later* `POST` of
//! the same upstream, session and run (SR-85): clients route a response by its id whatever
//! stream or body it arrives in, so an upstream could otherwise answer call 1 inside its
//! answer to a `ping`, or to call 2, and get it to the agent unrecorded. The map is bounded ([`MAX_AWAITED_RESULTS`],
//! [`MAX_AWAITED_RESULTS_PER_SESSION`]) and entries expire after [`AWAITED_RESULT_TTL`]. A
//! response on the listen stream that claims no entry (an unknown id, one already answered on
//! the `POST`, or one that expired or was evicted) and every notification or server request
//! passes through unchanged.
//!
//! List requests (`tools/list` and the other three list methods) are remembered in the same
//! map, under the same scope, bounds and expiry, with their [`ListKind`] instead of a decision
//! (SR-87): an upstream that answers one with `202` and puts the answer in the body of a later
//! `POST` gets it filtered there, through `ListAnswers`, like an answer in its own body.
//! Calls and list requests are kept apart, so neither replaces nor claims the other. An answer
//! on the listen stream or in the request's own body strikes the entry. A list answer that
//! claims nothing in a `POST` body (another run's, an expired one, or a second answer to an id
//! already claimed) is not filtered there; the listen stream filters every list answer by
//! shape.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use attenuo_core::{DelegationChain, ToolCall};
use axum::body::Bytes;
use futures_util::{Stream, StreamExt};
use serde_json::Value;
use time::OffsetDateTime;
use tracing::Instrument;
use uuid::Uuid;

use crate::auth::{Authorizer, REASON_LABEL_ERROR};
use crate::filter::{same_id, ListKind};
use crate::jsonrpc::{self, denied_response, id_of};

/// The methods whose responses are labelled.
pub const LABELLED_METHODS: &[&str] = &[
    jsonrpc::METHOD_TOOLS_CALL,
    jsonrpc::METHOD_RESOURCES_READ,
    jsonrpc::METHOD_PROMPTS_GET,
    jsonrpc::METHOD_COMPLETION_COMPLETE,
];

/// An allowed call whose response must be labelled before it is relayed.
#[derive(Debug, Clone)]
pub(crate) struct PendingResult {
    /// The JSON-RPC id of the request.
    pub id: Value,
    pub call: ToolCall,
    pub decision_id: Uuid,
    /// The trace context of the request that made the call, when tracing is on: a result
    /// recorded after that request returned (on a stream) links its span to it.
    pub origin: Option<crate::traceparent::TraceParent>,
}

/// How long an allowed call is remembered for an answer on the `GET` listen stream. An answer
/// that arrives later passes through unlabelled, like any response with an unknown id.
pub const AWAITED_RESULT_TTL: Duration = Duration::from_secs(10 * 60);

/// Most allowed calls remembered for the listen stream, over all sessions. When full, expired
/// entries are dropped, then the oldest entry of the run (`chain_id`) that holds the most
/// (SR-86).
pub const MAX_AWAITED_RESULTS: usize = 10_000;

/// Most allowed calls remembered for one upstream session and run. One more drops that
/// session's oldest entry, so one session cannot push out the calls of the others.
pub const MAX_AWAITED_RESULTS_PER_SESSION: usize = 256;

/// Where an answer on the listen stream may come from: the upstream, the `Mcp-Session-Id`
/// (none for a sessionless upstream) and the run (`chain_id`). The proxy binds a session id to
/// the run's root lease (SR-11), so a `GET` that passed the session gate has the same scope as
/// the `POST`s of its session.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ResultScope {
    server: String,
    session: Option<String>,
    run: Option<String>,
}

impl ResultScope {
    pub(crate) fn new(server: &str, session: Option<&str>, chain: &DelegationChain) -> Self {
        Self {
            server: server.to_owned(),
            session: session.map(str::to_owned),
            run: attenuo_core::chain_id_of(chain),
        }
    }
}

/// What an [`Awaited`] entry waits for an answer to.
enum Waiting {
    /// An allowed call, labelled with its own chain and decision when answered.
    Call {
        pending: PendingResult,
        chain: Arc<DelegationChain>,
    },
    /// A list request (SR-87): its answer is filtered for whoever's body it arrives in.
    List { id: Value, kind: ListKind },
}

impl Waiting {
    fn id(&self) -> &Value {
        match self {
            Waiting::Call { pending, .. } => &pending.id,
            Waiting::List { id, .. } => id,
        }
    }

    fn is_call(&self) -> bool {
        matches!(self, Waiting::Call { .. })
    }
}

struct Awaited {
    what: Waiting,
    expires: Instant,
    /// Insertion order, for evicting the oldest when the map is full.
    seq: u64,
}

#[derive(Default)]
struct AwaitedInner {
    scopes: HashMap<ResultScope, Vec<Awaited>>,
    len: usize,
    next_seq: u64,
}

impl AwaitedInner {
    fn drop_expired(&mut self, now: Instant) {
        let mut len = 0;
        self.scopes.retain(|_, v| {
            v.retain(|a| a.expires > now);
            len += v.len();
            !v.is_empty()
        });
        self.len = len;
    }

    /// Drop the oldest call of the run that holds the most calls (SR-86). Evicting the oldest
    /// call overall let one run, with many sessions and calls whose answers never come, push
    /// out every other run's calls, so a late answer to them passed the listen stream
    /// unlabelled. A run that fills the map now evicts its own calls first.
    fn evict_oldest(&mut self) {
        // Per run: how many calls it holds, and its oldest call's (seq, scope).
        let mut runs: HashMap<&Option<String>, (usize, u64, &ResultScope)> = HashMap::new();
        for (k, v) in &self.scopes {
            let Some(first) = v.first() else { continue };
            let e = runs.entry(&k.run).or_insert((0, first.seq, k));
            e.0 += v.len();
            if first.seq < e.1 {
                (e.1, e.2) = (first.seq, k);
            }
        }
        let victim = runs
            .into_values()
            .max_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)))
            .map(|(_, _, k)| k.clone());
        if let Some(key) = victim {
            self.remove_at(&key, 0);
        }
    }

    fn remove_at(&mut self, scope: &ResultScope, index: usize) -> Option<Awaited> {
        let entries = self.scopes.get_mut(scope)?;
        let removed = entries.remove(index);
        if entries.is_empty() {
            self.scopes.remove(scope);
        }
        self.len -= 1;
        Some(removed)
    }

    /// The unexpired call (`call`) or list request (not `call`) in `scope` that `id`
    /// answers. Calls and list requests are kept apart, so a list request never replaces or
    /// claims a call with the same id, nor the other way round.
    fn position(&self, scope: &ResultScope, id: &Value, call: bool, now: Instant) -> Option<usize> {
        self.scopes
            .get(scope)?
            .iter()
            .position(|a| a.expires > now && a.what.is_call() == call && same_id(a.what.id(), id))
    }

    /// Remember `what` in `scope`, replacing an entry of the same kind and id, within the
    /// bounds of the module docs.
    fn insert(&mut self, scope: &ResultScope, what: Waiting, now: Instant) {
        if let Some(i) = self.position(scope, what.id(), what.is_call(), now) {
            self.remove_at(scope, i);
        }
        if let Some(v) = self.scopes.get_mut(scope) {
            let before = v.len();
            v.retain(|a| a.expires > now);
            let dropped = before - v.len();
            let emptied = v.is_empty();
            self.len -= dropped;
            if emptied {
                self.scopes.remove(scope);
            }
        }
        if self
            .scopes
            .get(scope)
            .is_some_and(|v| v.len() >= MAX_AWAITED_RESULTS_PER_SESSION)
        {
            self.remove_at(scope, 0);
        }
        if self.len >= MAX_AWAITED_RESULTS {
            self.drop_expired(now);
            if self.len >= MAX_AWAITED_RESULTS {
                tracing::warn!("awaited results full; forgetting the oldest entry");
                self.evict_oldest();
            }
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.scopes.entry(scope.clone()).or_default().push(Awaited {
            what,
            expires: now + AWAITED_RESULT_TTL,
            seq,
        });
        self.len += 1;
    }

    /// Is an unexpired entry of this kind remembered in `scope`?
    fn any(&self, scope: &ResultScope, call: bool, now: Instant) -> bool {
        self.scopes.get(scope).is_some_and(|v| {
            v.iter()
                .any(|a| a.expires > now && a.what.is_call() == call)
        })
    }
}

/// Allowed calls and list requests whose answers may still arrive on the `GET` listen stream
/// or in a later `POST` body. Bounded and expiring; see the module docs.
#[derive(Default)]
pub(crate) struct AwaitedResults {
    inner: Mutex<AwaitedInner>,
}

impl AwaitedResults {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, AwaitedInner> {
        // A panic while holding the lock leaves the map consistent enough to keep using.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Remember `calls` of `chain` in `scope`, until answered or [`AWAITED_RESULT_TTL`]. A call
    /// with the id of one already remembered in the scope replaces it.
    pub(crate) fn remember(
        &self,
        scope: &ResultScope,
        chain: &DelegationChain,
        calls: &[PendingResult],
        now: Instant,
    ) {
        let chain = Arc::new(chain.clone());
        let mut inner = self.lock();
        for call in calls {
            let what = Waiting::Call {
                pending: call.clone(),
                chain: chain.clone(),
            };
            inner.insert(scope, what, now);
        }
    }

    /// Remember the list requests `lists` (id and kind) in `scope`, until answered or
    /// [`AWAITED_RESULT_TTL`], under the same bounds as calls (SR-87). A list request with the
    /// id of one already remembered in the scope replaces it.
    pub(crate) fn remember_lists(
        &self,
        scope: &ResultScope,
        lists: &[(Value, ListKind)],
        now: Instant,
    ) {
        let mut inner = self.lock();
        for (id, kind) in lists {
            let what = Waiting::List {
                id: id.clone(),
                kind: *kind,
            };
            inner.insert(scope, what, now);
        }
    }

    /// Remove and return the unexpired list request in `scope` that `id` answers.
    pub(crate) fn take_list(
        &self,
        scope: &ResultScope,
        id: &Value,
        now: Instant,
    ) -> Option<(Value, ListKind)> {
        let mut inner = self.lock();
        let i = inner.position(scope, id, false, now)?;
        match inner.remove_at(scope, i)?.what {
            Waiting::List { id, kind } => Some((id, kind)),
            Waiting::Call { .. } => None,
        }
    }

    /// Is an unexpired list request remembered in `scope`?
    pub(crate) fn any_list_in(&self, scope: &ResultScope) -> bool {
        self.lock().any(scope, false, Instant::now())
    }

    /// Remove and return the unexpired call in `scope` that `id` answers.
    pub(crate) fn take(
        &self,
        scope: &ResultScope,
        id: &Value,
        now: Instant,
    ) -> Option<(PendingResult, Arc<DelegationChain>)> {
        let mut inner = self.lock();
        let i = inner.position(scope, id, true, now)?;
        match inner.remove_at(scope, i)?.what {
            Waiting::Call { pending, chain } => Some((pending, chain)),
            Waiting::List { .. } => None,
        }
    }

    /// Is an unexpired call with this `id` remembered in `scope`?
    pub(crate) fn awaits(&self, scope: &ResultScope, id: &Value, now: Instant) -> bool {
        self.lock().position(scope, id, true, now).is_some()
    }

    /// Is an unexpired call remembered in `scope`? Lets the listen stream skip parsing events.
    pub(crate) fn any_call_in(&self, scope: &ResultScope) -> bool {
        self.lock().any(scope, true, Instant::now())
    }

    /// How many calls are remembered, expired ones included until they are dropped.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().len
    }
}

/// The list requests whose answers the list filter and list screen of one `POST` body apply
/// to: the `POST`'s own, and those of earlier requests of its scope that the body answers
/// (SR-87). An upstream may answer a `tools/list` with `202` and put the answer in the body of
/// a later `POST`; clients route it by id, so it is filtered there as the answer to that list
/// request. Ids match as in the list filter ([`same_id`]).
pub(crate) struct ListAnswers {
    own: Vec<(Value, ListKind)>,
    awaited: Option<(Arc<AwaitedResults>, ResultScope)>,
    /// Earlier list requests this body answered, taken from `awaited`.
    claimed: Mutex<Vec<(Value, ListKind)>>,
}

impl ListAnswers {
    /// The list requests of one `POST`.
    pub(crate) fn new(own: Vec<(Value, ListKind)>) -> Self {
        Self {
            own,
            awaited: None,
            claimed: Mutex::new(Vec::new()),
        }
    }

    /// Also claim the list requests remembered in `scope`, and strike the `POST`'s own when
    /// its body answers them.
    pub(crate) fn claiming(mut self, awaited: Arc<AwaitedResults>, scope: ResultScope) -> Self {
        self.awaited = Some((awaited, scope));
        self
    }

    /// Could a body hold a list answer: the `POST` has list requests of its own, or earlier
    /// ones of its scope are awaited?
    pub(crate) fn may_answer(&self) -> bool {
        !self.own.is_empty()
            || self
                .awaited
                .as_ref()
                .is_some_and(|(a, scope)| a.any_list_in(scope))
    }

    /// Take the remembered list requests that the responses in `body` (a message or a batch)
    /// answer. An answer to one of the `POST`'s own strikes it; an answer to an earlier one
    /// claims it, so it is filtered here and is not awaited any more. Call it on each body or
    /// event before [`pending`](Self::pending).
    pub(crate) fn claim(&self, body: &Value) {
        let Some((awaited, scope)) = &self.awaited else {
            return;
        };
        let messages: Vec<&Value> = match body {
            Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        let now = Instant::now();
        for msg in messages {
            if jsonrpc::method_of(msg).is_some() {
                continue;
            }
            let Some(id) = msg.get("id") else { continue };
            let Some(taken) = awaited.take_list(scope, id, now) else {
                continue;
            };
            if !self.own.iter().any(|(own, _)| same_id(own, id)) {
                self.lock_claimed().push(taken);
            }
        }
    }

    /// The list requests to filter for: the `POST`'s own and those claimed so far.
    pub(crate) fn pending(&self) -> Vec<(Value, ListKind)> {
        let mut all = self.own.clone();
        all.extend(self.lock_claimed().iter().cloned());
        all
    }

    /// Does a response with `id` answer a `tools/list` of [`pending`](Self::pending)?
    pub(crate) fn answers_tools(&self, id: &Value) -> bool {
        let is = |(pid, k): &(Value, ListKind)| *k == ListKind::Tools && same_id(pid, id);
        self.own.iter().any(is) || self.lock_claimed().iter().any(is)
    }

    fn lock_claimed(&self) -> std::sync::MutexGuard<'_, Vec<(Value, ListKind)>> {
        self.claimed.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// What the response part of a message is: its `result`, or its `error` (`true`). A message
/// with both or neither is taken whole, so nothing in it goes unrecorded.
fn result_part(msg: &Value) -> (&Value, bool) {
    match (msg.get("result"), msg.get("error")) {
        (Some(r), None) => (r, false),
        (None, Some(e)) => (e, true),
        _ => (msg, false),
    }
}

/// Which calls a [`Labeller`] looks for.
#[derive(Clone)]
enum Calls {
    /// The allowed calls of one `POST`. An answer found is also struck from `awaited`, so it
    /// is not expected on the listen stream any more; an answer to an earlier call remembered
    /// in `awaited` claims it, as on the listen stream (SR-85).
    Request {
        chain: Arc<DelegationChain>,
        pending: Arc<Vec<PendingResult>>,
        awaited: Option<(Arc<AwaitedResults>, ResultScope)>,
    },
    /// A `GET` listen stream: answers claim the calls remembered in `scope`.
    Listen {
        awaited: Arc<AwaitedResults>,
        scope: ResultScope,
    },
}

/// Labels the responses to allowed calls: those of one HTTP request, or those remembered for
/// a listen stream.
#[derive(Clone)]
pub(crate) struct Labeller {
    authorizer: Arc<dyn Authorizer>,
    calls: Calls,
}

impl Labeller {
    /// A labeller for the answers to the allowed calls of one `POST`.
    pub(crate) fn new(
        authorizer: Arc<dyn Authorizer>,
        chain: DelegationChain,
        pending: Vec<PendingResult>,
    ) -> Self {
        Self {
            authorizer,
            calls: Calls::Request {
                chain: Arc::new(chain),
                pending: Arc::new(pending),
                awaited: None,
            },
        }
    }

    /// Strike each call answered in the `POST`'s own body from `awaited` (where the proxy
    /// remembered it under `scope` before forwarding).
    pub(crate) fn striking(mut self, awaited: Arc<AwaitedResults>, scope: ResultScope) -> Self {
        if let Calls::Request { awaited: slot, .. } = &mut self.calls {
            *slot = Some((awaited, scope));
        }
        self
    }

    /// A labeller for a `GET` listen stream in `scope`, or for the body of a `POST` in
    /// `scope` that has no allowed call of its own while earlier calls are awaited (SR-85).
    pub(crate) fn listen(
        authorizer: Arc<dyn Authorizer>,
        awaited: Arc<AwaitedResults>,
        scope: ResultScope,
    ) -> Self {
        Self {
            authorizer,
            calls: Calls::Listen { awaited, scope },
        }
    }

    /// The id of `msg` if it is a response: no `method`, or one that is not a string, which no
    /// client reads as a request (SR-69).
    fn response_id(msg: &Value) -> Option<&Value> {
        if jsonrpc::method_of(msg).is_some() {
            return None;
        }
        msg.get("id")
    }

    /// Does `msg` answer a call this labeller looks for?
    fn matches(&self, msg: &Value) -> bool {
        let Some(id) = Self::response_id(msg) else {
            return false;
        };
        match &self.calls {
            Calls::Request {
                pending, awaited, ..
            } => {
                pending.iter().any(|p| same_id(&p.id, id))
                    || awaited
                        .as_ref()
                        .is_some_and(|(a, scope)| a.awaits(scope, id, Instant::now()))
            }
            Calls::Listen { awaited, scope } => awaited.awaits(scope, id, Instant::now()),
        }
    }

    /// The call `msg` answers and the chain it was decided for. On a listen stream this takes
    /// the call out of the awaited map, so a second answer to it passes unlabelled.
    fn claim(&self, msg: &Value) -> Option<(PendingResult, Arc<DelegationChain>)> {
        let id = Self::response_id(msg)?;
        match &self.calls {
            Calls::Request {
                chain,
                pending,
                awaited,
            } => {
                let taken = awaited
                    .as_ref()
                    .and_then(|(awaited, scope)| awaited.take(scope, id, Instant::now()));
                match pending.iter().find(|p| same_id(&p.id, id)) {
                    Some(found) => Some((found.clone(), chain.clone())),
                    // An answer to an earlier call of the same session and run, in the body
                    // of this one (SR-85): the client routes it by id, so it is that call's
                    // answer and is labelled as such.
                    None => taken,
                }
            }
            Calls::Listen { awaited, scope } => awaited.take(scope, id, Instant::now()),
        }
    }

    /// Could any event of this stream answer a call? False on a listen stream with nothing
    /// remembered for its scope, so its events are relayed without being parsed.
    fn may_answer(&self) -> bool {
        match &self.calls {
            Calls::Request { .. } => true,
            Calls::Listen { awaited, scope } => awaited.any_call_in(scope),
        }
    }

    /// Does `body` (a message or a batch) hold a response to a call?
    fn answers_any(&self, body: &Value) -> bool {
        match body {
            Value::Array(items) => items.iter().any(|m| self.matches(m)),
            other => self.matches(other),
        }
    }

    /// Record one message if it answers a call; replace it with a `label_error` denial when
    /// that fails. Returns whether it was replaced.
    async fn label_message(&self, msg: &mut Value) -> bool {
        let Some((pending, chain)) = self.claim(msg) else {
            return false;
        };
        let (part, is_error) = result_part(msg);
        // The exported `attenuo.record_result` span: a child of the response span when the
        // body is buffered, or (on a stream, after the request returned) a new span linked to
        // the request that made the call. The authorizer fills in the label and the audit seq.
        let span = tracing::info_span!(
            target: crate::traceparent::OTEL_TARGET,
            "attenuo.record_result",
            attenuo.decision_id = %pending.decision_id,
            attenuo.result.label = tracing::field::Empty,
            attenuo.audit.seq = tracing::field::Empty,
            attenuo.reason = tracing::field::Empty,
        );
        if let (Some(hook), Some(origin)) = (self.authorizer.trace(), pending.origin) {
            hook.link_detached(&span, origin);
        }
        let recorded = self
            .authorizer
            .record_result(
                &chain,
                &pending.call,
                pending.decision_id,
                part,
                is_error,
                OffsetDateTime::now_utc(),
            )
            .instrument(span.clone())
            .await;
        match recorded {
            Ok(()) => false,
            Err(reason) => {
                span.record("attenuo.reason", reason.as_str());
                // The tool name is the caller's: Debug-format it (SR-18).
                tracing::error!(
                    tool = ?pending.call.tool,
                    decision_id = %pending.decision_id,
                    reason = ?reason,
                    "result could not be labelled; withheld"
                );
                *msg = denied_response(id_of(msg), &reason, pending.decision_id);
                true
            }
        }
    }

    /// Label every response in `body` (a message or a batch). Returns how many were replaced.
    pub(crate) async fn label_value(&self, body: &mut Value) -> usize {
        match body {
            Value::Array(items) => {
                let mut replaced = 0;
                for m in items.iter_mut() {
                    replaced += usize::from(self.label_message(m).await);
                }
                replaced
            }
            other => usize::from(self.label_message(other).await),
        }
    }

    /// Label the events of an SSE chunk that holds whole events. An event whose data answers
    /// a pending call is recorded; if any of its messages had to be replaced it is emitted
    /// again as one `message` event with the new data, otherwise byte for byte. An event with
    /// data the proxy cannot parse is dropped (SR-79).
    pub(crate) async fn label_events(&self, chunk: &[u8]) -> Vec<u8> {
        if !self.may_answer() {
            return chunk.to_vec();
        }
        let mut out = Vec::with_capacity(chunk.len());
        for event in crate::sse::split_events(chunk) {
            match crate::sse::event_json(event) {
                Some(mut v) if self.answers_any(&v) => {
                    if self.label_value(&mut v).await > 0 {
                        out.extend_from_slice(&crate::sse::message_event(&v));
                    } else {
                        out.extend_from_slice(event);
                    }
                }
                // Data the proxy cannot parse may still be JSON to a client whose parser
                // differs (nesting deeper than `serde_json` allows, for one): it may be an
                // answer, so it is not relayed unlabelled (SR-79).
                None if crate::sse::has_data(event) => {
                    tracing::warn!(
                        bytes = event.len(),
                        "upstream SSE event the proxy cannot parse withheld while an answer is awaited"
                    );
                }
                _ => out.extend_from_slice(event),
            }
        }
        out
    }

    /// One `label_error` denial per pending call, for an upstream body the proxy cannot read
    /// (JSON that does not parse, or a content type that is neither JSON nor SSE).
    pub(crate) fn failure_replies(&self) -> Vec<Value> {
        match &self.calls {
            Calls::Request { pending, .. } => pending
                .iter()
                .map(|p| denied_response(p.id.clone(), REASON_LABEL_ERROR, p.decision_id))
                .collect(),
            Calls::Listen { .. } => Vec::new(),
        }
    }
}

/// Run every chunk of `inner` (whole SSE events) through [`Labeller::label_events`].
pub(crate) fn label_stream<S>(
    inner: S,
    labeller: Labeller,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static
where
    S: Stream<Item = Result<Bytes, io::Error>> + Send + 'static,
{
    inner.then(move |chunk| {
        let labeller = labeller.clone();
        async move {
            match chunk {
                Ok(bytes) => Ok(Bytes::from(labeller.label_events(&bytes).await)),
                Err(e) => Err(e),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{test_chain, StaticAuthorizer};
    use attenuo_core::Capability;
    use serde_json::json;

    fn labeller(auth: Arc<StaticAuthorizer>) -> Labeller {
        let chain = test_chain("user:a", "agent:a", [Capability::new("s", "*")]);
        Labeller::new(
            auth,
            chain,
            vec![PendingResult {
                id: json!(1),
                call: ToolCall::new("s", "read", json!({})),
                decision_id: Uuid::nil(),
                origin: None,
            }],
        )
    }

    #[test]
    fn result_part_picks_result_or_error() {
        let r = json!({"id": 1, "result": {"a": 1}});
        assert_eq!(result_part(&r), (&json!({"a": 1}), false));
        let e = json!({"id": 1, "error": {"code": 1}});
        assert_eq!(result_part(&e), (&json!({"code": 1}), true));
        let both = json!({"id": 1, "result": 1, "error": 2});
        assert_eq!(result_part(&both).0, &both);
    }

    #[tokio::test]
    async fn responses_are_recorded_and_failures_withheld() {
        let auth = Arc::new(StaticAuthorizer::new());
        let l = labeller(auth.clone());
        // A batch: the response to id 1 (as 1.0), a notification and an unrelated id.
        let mut body = json!([
            {"jsonrpc": "2.0", "id": 1.0, "result": {"content": []}},
            {"jsonrpc": "2.0", "method": "notifications/progress"},
            {"jsonrpc": "2.0", "id": 9, "result": {}},
        ]);
        assert_eq!(l.label_value(&mut body).await, 0);
        assert_eq!(auth.recorded_results().len(), 1);

        auth.fail_results(true);
        let mut msg = json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "x"}});
        assert_eq!(l.label_value(&mut msg).await, 1);
        assert_eq!(msg["error"]["code"], jsonrpc::CODE_DENIED);
        assert_eq!(msg["error"]["data"]["reason"], REASON_LABEL_ERROR);
        assert_eq!(msg["id"], 1);
    }

    #[tokio::test]
    async fn a_null_method_does_not_hide_a_result_from_labelling_sr69() {
        // An upstream (A3) that adds `"method": null` to its answer must not get it past the
        // labeller: a client such as the Python MCP SDK still reads it as the response.
        let auth = Arc::new(StaticAuthorizer::new());
        let l = labeller(auth.clone());
        let mut msg = json!({"jsonrpc": "2.0", "id": 1, "method": null, "result": {"content": []}});
        l.label_value(&mut msg).await;
        assert_eq!(auth.recorded_results().len(), 1, "recorded and labelled");

        auth.fail_results(true);
        let mut msg = json!({"jsonrpc": "2.0", "id": 1, "method": 7, "result": {"content": []}});
        assert_eq!(
            l.label_value(&mut msg).await,
            1,
            "withheld when the label fails"
        );
        assert_eq!(msg["error"]["data"]["reason"], REASON_LABEL_ERROR);
    }

    #[tokio::test]
    async fn sse_events_are_labelled_one_by_one() {
        let auth = Arc::new(StaticAuthorizer::new());
        let l = labeller(auth.clone());
        let chunk = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n\
id: 4\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        let out = l.label_events(chunk).await;
        assert_eq!(out, chunk.to_vec(), "recorded events pass byte for byte");
        assert_eq!(auth.recorded_results().len(), 1);

        auth.fail_results(true);
        let out = String::from_utf8(l.label_events(chunk).await).unwrap();
        assert!(out.starts_with("event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\""));
        assert!(out.contains("label_error"), "{out}");
        assert!(!out.contains("\"result\""), "{out}");
    }

    fn pending(id: Value) -> PendingResult {
        PendingResult {
            id,
            call: ToolCall::new("s", "read", json!({})),
            decision_id: Uuid::new_v4(),
            origin: None,
        }
    }

    fn chain() -> DelegationChain {
        test_chain("user:a", "agent:a", [Capability::new("s", "*")])
    }

    #[test]
    fn awaited_calls_are_scoped_claimed_once_and_expire() {
        let awaited = AwaitedResults::new();
        let c = chain();
        let scope = ResultScope::new("s", Some("sess"), &c);
        let other = ResultScope::new("s", Some("other"), &c);
        let now = Instant::now();
        awaited.remember(&scope, &c, &[pending(json!(1)), pending(json!("b"))], now);
        assert_eq!(awaited.len(), 2);
        assert!(
            awaited.take(&other, &json!(1), now).is_none(),
            "another session"
        );
        assert!(
            awaited.take(&scope, &json!(1.0), now).is_some(),
            "1.0 answers 1"
        );
        assert!(
            awaited.take(&scope, &json!(1), now).is_none(),
            "claimed once"
        );
        // A new call with the id of a remembered one replaces it.
        let newer = pending(json!("b"));
        awaited.remember(&scope, &c, std::slice::from_ref(&newer), now);
        assert_eq!(awaited.len(), 1);
        let (got, _) = awaited.take(&scope, &json!("b"), now).unwrap();
        assert_eq!(got.decision_id, newer.decision_id);
        assert!(!awaited.any_call_in(&scope));
        // Past the TTL it is gone.
        awaited.remember(&scope, &c, &[pending(json!(2))], now);
        let later = now + AWAITED_RESULT_TTL + Duration::from_secs(1);
        assert!(!awaited.awaits(&scope, &json!(2), later));
        assert!(awaited.take(&scope, &json!(2), later).is_none());
    }

    #[test]
    fn awaited_calls_are_bounded() {
        let awaited = AwaitedResults::new();
        let c = chain();
        let now = Instant::now();
        let scope = ResultScope::new("s", Some("sess"), &c);
        let calls: Vec<_> = (0..MAX_AWAITED_RESULTS_PER_SESSION + 5)
            .map(|i| pending(json!(i)))
            .collect();
        awaited.remember(&scope, &c, &calls, now);
        assert_eq!(awaited.len(), MAX_AWAITED_RESULTS_PER_SESSION);
        assert!(
            !awaited.awaits(&scope, &json!(0), now),
            "oldest of the session dropped"
        );
        assert!(awaited.awaits(&scope, &json!(MAX_AWAITED_RESULTS_PER_SESSION + 4), now));

        // Over all sessions: at most MAX_AWAITED_RESULTS, the oldest evicted first.
        let per = MAX_AWAITED_RESULTS_PER_SESSION;
        for n in 0..(MAX_AWAITED_RESULTS / per + 2) {
            let s = ResultScope::new("s", Some(&format!("s{n}")), &c);
            let calls: Vec<_> = (0..per).map(|i| pending(json!(i))).collect();
            awaited.remember(&s, &c, &calls, now);
        }
        assert_eq!(awaited.len(), MAX_AWAITED_RESULTS);
        assert!(
            !awaited.any_call_in(&scope),
            "the first session's calls were the oldest"
        );
    }

    #[test]
    fn a_run_that_fills_the_map_evicts_its_own_calls_sr86() {
        let awaited = AwaitedResults::new();
        let now = Instant::now();
        // The victim's run remembers one call first, so it is the oldest in the map.
        let victim = test_chain("user:v", "agent:v", [Capability::new("s", "*")]);
        let victim_scope = ResultScope::new("s", Some("victim"), &victim);
        awaited.remember(&victim_scope, &victim, &[pending(json!(1))], now);
        // Another run fills the map over many sessions, with calls that are never answered.
        let flood = chain();
        let per = MAX_AWAITED_RESULTS_PER_SESSION;
        for n in 0..(MAX_AWAITED_RESULTS / per + 2) {
            let s = ResultScope::new("s", Some(&format!("f{n}")), &flood);
            let calls: Vec<_> = (0..per).map(|i| pending(json!(i))).collect();
            awaited.remember(&s, &flood, &calls, now);
        }
        assert_eq!(awaited.len(), MAX_AWAITED_RESULTS);
        assert!(
            awaited.awaits(&victim_scope, &json!(1), now),
            "the flooding run pushed out another run's call"
        );
        assert!(
            !awaited.awaits(&ResultScope::new("s", Some("f0"), &flood), &json!(0), now),
            "the flooding run's oldest call went first"
        );
    }

    #[test]
    fn awaited_lists_are_kept_apart_from_calls_and_claimed_once_sr87() {
        let awaited = Arc::new(AwaitedResults::new());
        let c = chain();
        let scope = ResultScope::new("s", Some("sess"), &c);
        let other_run = ResultScope::new(
            "s",
            Some("sess"),
            &test_chain("user:b", "agent:b", [Capability::new("s", "*")]),
        );
        let other_server = ResultScope::new("t", Some("sess"), &c);
        let now = Instant::now();
        // A call and a list request with the same id do not replace or claim each other.
        awaited.remember(&scope, &c, &[pending(json!(1))], now);
        awaited.remember_lists(&scope, &[(json!(1), ListKind::Tools)], now);
        assert_eq!(awaited.len(), 2);
        assert!(awaited.any_call_in(&scope) && awaited.any_list_in(&scope));
        assert!(awaited.take_list(&other_run, &json!(1), now).is_none());
        assert!(awaited.take_list(&other_server, &json!(1), now).is_none());
        assert_eq!(
            awaited.take_list(&scope, &json!(1.0), now),
            Some((json!(1), ListKind::Tools))
        );
        assert!(awaited.take_list(&scope, &json!(1), now).is_none());
        assert!(
            awaited.take(&scope, &json!(1), now).is_some(),
            "the call stayed"
        );
        // A list request alone does not make the listen stream parse for calls.
        awaited.remember_lists(&scope, &[(json!(2), ListKind::Prompts)], now);
        assert!(!awaited.any_call_in(&scope));
        let later = now + AWAITED_RESULT_TTL + Duration::from_secs(1);
        assert!(
            awaited.take_list(&scope, &json!(2), later).is_none(),
            "expired"
        );
        assert!(awaited.take_list(&scope, &json!(2), now).is_some());

        // A POST's list answers: its own request is struck, an earlier one is claimed.
        awaited.remember_lists(
            &scope,
            &[(json!(3), ListKind::Tools), (json!(4), ListKind::Tools)],
            now,
        );
        let lists = ListAnswers::new(vec![(json!(4), ListKind::Tools)])
            .claiming(awaited.clone(), scope.clone());
        assert!(lists.may_answer());
        assert!(!lists.answers_tools(&json!(3)));
        lists.claim(&json!([
            {"jsonrpc": "2.0", "id": 3, "result": {"tools": []}},
            {"jsonrpc": "2.0", "id": 4, "result": {"tools": []}},
            {"jsonrpc": "2.0", "id": 9, "method": "x", "result": {"tools": []}},
        ]));
        assert!(lists.answers_tools(&json!(3)) && lists.answers_tools(&json!(4)));
        assert_eq!(lists.pending().len(), 2);
        assert!(!awaited.any_list_in(&scope));
    }

    #[tokio::test]
    async fn listen_stream_labels_claimed_answers_only() {
        let auth = Arc::new(StaticAuthorizer::new());
        let awaited = Arc::new(AwaitedResults::new());
        let c = chain();
        let scope = ResultScope::new("s", Some("sess"), &c);
        let l = Labeller::listen(auth.clone(), awaited.clone(), scope.clone());
        let chunk = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        // Nothing remembered: relayed unchanged, nothing recorded.
        assert_eq!(l.label_events(chunk).await, chunk.to_vec());
        assert!(auth.recorded_results().is_empty());

        let call = pending(json!(1));
        awaited.remember(&scope, &c, std::slice::from_ref(&call), Instant::now());
        assert_eq!(l.label_events(chunk).await, chunk.to_vec());
        let recorded = auth.recorded_results();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].decision_id, call.decision_id);
        // A second answer to the same id is not the call's any more.
        assert_eq!(l.label_events(chunk).await, chunk.to_vec());
        assert_eq!(auth.recorded_results().len(), 1);

        // A POST answer strikes the remembered call.
        awaited.remember(&scope, &c, std::slice::from_ref(&call), Instant::now());
        let post = Labeller::new(auth.clone(), c.clone(), vec![call.clone()])
            .striking(awaited.clone(), scope.clone());
        let mut msg = json!({"jsonrpc": "2.0", "id": 1, "result": {}});
        assert_eq!(post.label_value(&mut msg).await, 0);
        assert!(!awaited.any_call_in(&scope));
    }
}
