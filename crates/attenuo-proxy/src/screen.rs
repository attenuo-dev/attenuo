//! The policy screen of `tools/list` answers (`[proxy] list_filter = "policy"`, ADR-0011).
//!
//! The capability filter ([`crate::filter`]) runs first and is unchanged. With
//! [`ListFilterMode::Policy`] the tools it keeps are then put to
//! [`Authorizer::screen_tools`], which hides a tool only when
//! no call to it could be allowed for the chain (the server's authorizer partially evaluates
//! the Cedar policy set; see `attenuo_policy::PolicyEngine::screen_tools`). The screen is
//! advisory: a hidden tool that is called anyway is decided and recorded like any other call.
//! It applies to `tools/list` answers wherever they arrive (a JSON body, a batch, an SSE event
//! of a `POST` answer, the `GET` listen stream); resources, templates and prompts are not
//! screened. A screen that answers the wrong number of verdicts keeps every entry.

use std::collections::HashSet;
use std::io;
use std::sync::Arc;

use attenuo_core::DelegationChain;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::Authorizer;
use crate::filter::{list_kinds_by_shape, same_id, ListKind};

/// `[proxy] list_filter`: how list answers are filtered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListFilterMode {
    /// By capability shape only (the default, and the only behaviour before ADR-0011).
    #[default]
    Capabilities,
    /// By capability shape, then `tools/list` entries through
    /// [`Authorizer::screen_tools`].
    Policy,
}

/// Which messages of a body answer a `tools/list`: those answering a pending request of this
/// HTTP request, or on the listen stream any response shaped like a tools list.
#[derive(Clone)]
pub(crate) enum ToolsAnswers {
    Pending(Arc<Vec<(Value, ListKind)>>),
    ByShape,
}

impl ToolsAnswers {
    fn answers_tools(&self, msg: &Value) -> bool {
        if crate::jsonrpc::method_of(msg).is_some() {
            return false;
        }
        match self {
            ToolsAnswers::Pending(pending) => msg.get("id").is_some_and(|id| {
                pending
                    .iter()
                    .any(|(pid, k)| *k == ListKind::Tools && same_id(pid, id))
            }),
            ToolsAnswers::ByShape => list_kinds_by_shape(msg)
                .iter()
                .any(|(_, k)| *k == ListKind::Tools),
        }
    }

    /// Does any message of `body` (a message or a batch) answer a `tools/list`?
    fn any_in(&self, body: &Value) -> bool {
        match body {
            Value::Array(items) => items.iter().any(|m| self.answers_tools(m)),
            other => self.answers_tools(other),
        }
    }
}

/// The `tools` arrays of the messages in `body` that answer a `tools/list`.
fn tools_arrays<'a>(answers: &ToolsAnswers, body: &'a mut Value) -> Vec<&'a mut Vec<Value>> {
    let messages: Vec<&mut Value> = match body {
        Value::Array(items) => items.iter_mut().collect(),
        other => vec![other],
    };
    messages
        .into_iter()
        .filter(|m| answers.answers_tools(m))
        .filter_map(|m| {
            m.get_mut("result")
                .and_then(|r| r.get_mut("tools"))
                .and_then(Value::as_array_mut)
        })
        .collect()
}

/// Screen the `tools/list` answers in `body` (after the capability filter) and remove the
/// tools the authorizer hides. Returns how many entries were removed.
pub(crate) async fn screen_body(
    authorizer: &dyn Authorizer,
    chain: &DelegationChain,
    server: &str,
    answers: &ToolsAnswers,
    body: &mut Value,
) -> usize {
    let mut names: Vec<String> = Vec::new();
    for tools in tools_arrays(answers, body) {
        names.extend(
            tools
                .iter()
                .filter_map(|t| t.get("name").and_then(Value::as_str))
                .map(str::to_owned),
        );
    }
    if names.is_empty() {
        return 0;
    }
    names.sort_unstable();
    names.dedup();
    let verdicts = authorizer.screen_tools(chain, server, &names).await;
    if verdicts.len() != names.len() {
        tracing::warn!(
            asked = names.len(),
            answered = verdicts.len(),
            "list screen answered the wrong number of verdicts; every tool kept"
        );
        return 0;
    }
    let hidden: HashSet<&str> = names
        .iter()
        .zip(&verdicts)
        .filter(|(_, keep)| !**keep)
        .map(|(n, _)| n.as_str())
        .collect();
    if hidden.is_empty() {
        return 0;
    }
    let mut removed = 0;
    for tools in tools_arrays(answers, body) {
        let before = tools.len();
        tools.retain(|t| {
            t.get("name")
                .and_then(Value::as_str)
                .is_none_or(|n| !hidden.contains(n))
        });
        removed += before - tools.len();
    }
    removed
}

/// What an SSE stream's screen stage needs.
#[derive(Clone)]
pub(crate) struct StreamScreen {
    pub(crate) authorizer: Arc<dyn Authorizer>,
    pub(crate) chain: DelegationChain,
    pub(crate) server: String,
    pub(crate) answers: ToolsAnswers,
}

impl StreamScreen {
    /// Screen the events of a chunk that holds whole events (as [`crate::sse::rewrite_stream`]
    /// emits them, after the capability filter). An event that answers a `tools/list` and
    /// loses entries is written again with its other lines kept; every other event is passed
    /// on byte for byte.
    async fn screen_events(&self, chunk: &[u8]) -> Result<Vec<u8>, io::Error> {
        let mut out = Vec::with_capacity(chunk.len());
        for event in crate::sse::split_events(chunk) {
            let Some(mut v) = crate::sse::event_json(event).filter(|v| self.answers.any_in(v))
            else {
                out.extend_from_slice(event);
                continue;
            };
            let removed = screen_body(
                self.authorizer.as_ref(),
                &self.chain,
                &self.server,
                &self.answers,
                &mut v,
            )
            .await;
            if removed == 0 {
                out.extend_from_slice(event);
                continue;
            }
            tracing::debug!(removed, "list screen hid tools in an SSE event");
            let mut screened = Some(v);
            crate::sse::rewrite_event(
                event,
                &mut |m: &mut Value| {
                    if let Some(s) = screened.take() {
                        *m = s;
                    }
                },
                &mut out,
            )?;
        }
        Ok(out)
    }
}

/// Run every chunk of `inner` (whole SSE events) through [`StreamScreen::screen_events`].
pub(crate) fn screen_stream<S>(
    inner: S,
    screen: StreamScreen,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static
where
    S: Stream<Item = Result<Bytes, io::Error>> + Send + 'static,
{
    inner.then(move |chunk| {
        let screen = screen.clone();
        async move {
            match chunk {
                Ok(bytes) => screen.screen_events(&bytes).await.map(Bytes::from),
                Err(e) => Err(e),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn list_filter_mode_parses_lowercase_names_only() {
        let p = |s: &str| serde_json::from_value::<ListFilterMode>(json!(s));
        assert_eq!(p("capabilities").unwrap(), ListFilterMode::Capabilities);
        assert_eq!(p("policy").unwrap(), ListFilterMode::Policy);
        assert!(p("Policy").is_err());
        assert!(p("cedar").is_err());
        assert_eq!(ListFilterMode::default(), ListFilterMode::Capabilities);
    }

    #[test]
    fn only_tools_answers_are_screened() {
        let pending = ToolsAnswers::Pending(Arc::new(vec![
            (json!(1), ListKind::Tools),
            (json!(2), ListKind::Prompts),
        ]));
        assert!(pending.answers_tools(&json!({"id": 1.0, "result": {"tools": []}})));
        assert!(!pending.answers_tools(&json!({"id": 2, "result": {"tools": []}})));
        assert!(!pending.answers_tools(&json!({"id": 1, "method": "x", "result": {"tools": []}})));
        assert!(ToolsAnswers::ByShape.answers_tools(&json!({"id": 9, "result": {"tools": []}})));
        assert!(!ToolsAnswers::ByShape.answers_tools(&json!({"id": 9, "result": {"prompts": []}})));
    }
}
