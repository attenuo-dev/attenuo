//! Output labelling at the proxy (ADR-0009).
//!
//! Every response the upstream gives to an allowed mediated call (`tools/call`,
//! `resources/read`, `prompts/get`, `completion/complete`), JSON-RPC errors included, is
//! handed to [`Authorizer::record_result`] before it is relayed. The server's authorizer
//! appends a `tool_result` audit record and, for an untrusted result, labels the delegation
//! run. When that fails, the response is replaced by a JSON-RPC error with reason
//! `label_error`: the call ran upstream, but its result never reaches the agent.
//!
//! Responses are found the way list results are: a message with no `method` whose `id`
//! matches the id of an allowed call of the same HTTP request, in a JSON body (single or
//! batch) or in the events of an SSE body, event by event. Every matching response is
//! recorded, so an upstream that answers one id twice gets two records, not one unlabelled
//! answer.

use std::io;
use std::sync::Arc;

use attenuo_core::{DelegationChain, ToolCall};
use axum::body::Bytes;
use futures_util::{Stream, StreamExt};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::{Authorizer, REASON_LABEL_ERROR};
use crate::filter::same_id;
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

/// Labels the responses to the allowed calls of one HTTP request.
#[derive(Clone)]
pub(crate) struct Labeller {
    authorizer: Arc<dyn Authorizer>,
    chain: DelegationChain,
    pending: Arc<Vec<PendingResult>>,
}

impl Labeller {
    pub fn new(
        authorizer: Arc<dyn Authorizer>,
        chain: DelegationChain,
        pending: Vec<PendingResult>,
    ) -> Self {
        Self {
            authorizer,
            chain,
            pending: Arc::new(pending),
        }
    }

    /// The pending call `msg` answers, if it is a response to one.
    fn matching(&self, msg: &Value) -> Option<&PendingResult> {
        if msg.get("method").is_some() {
            return None;
        }
        let id = msg.get("id")?;
        self.pending.iter().find(|p| same_id(&p.id, id))
    }

    /// Does `body` (a message or a batch) hold a response to a pending call?
    fn answers_any(&self, body: &Value) -> bool {
        match body {
            Value::Array(items) => items.iter().any(|m| self.matching(m).is_some()),
            other => self.matching(other).is_some(),
        }
    }

    /// Record one message if it answers a pending call; replace it with a `label_error`
    /// denial when that fails. Returns whether it was replaced.
    async fn label_message(&self, msg: &mut Value) -> bool {
        let Some(pending) = self.matching(msg) else {
            return false;
        };
        let (part, is_error) = result_part(msg);
        let recorded = self
            .authorizer
            .record_result(
                &self.chain,
                &pending.call,
                pending.decision_id,
                part,
                is_error,
                OffsetDateTime::now_utc(),
            )
            .await;
        match recorded {
            Ok(()) => false,
            Err(reason) => {
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
    pub async fn label_value(&self, body: &mut Value) -> usize {
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
    /// again as one `message` event with the new data, otherwise byte for byte.
    pub async fn label_events(&self, chunk: &[u8]) -> Vec<u8> {
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
                _ => out.extend_from_slice(event),
            }
        }
        out
    }

    /// One `label_error` denial per pending call, for an upstream body the proxy cannot read
    /// (JSON that does not parse, or a content type that is neither JSON nor SSE).
    pub fn failure_replies(&self) -> Vec<Value> {
        self.pending
            .iter()
            .map(|p| denied_response(p.id.clone(), REASON_LABEL_ERROR, p.decision_id))
            .collect()
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
}
