//! The list screen (ADR-0011): may a listed tool ever be allowed for a chain?
//!
//! A `tools/call` decision depends on facts that do not exist when the agent lists tools: the
//! arguments (`context.input`), the run's taint and the call's argument labels
//! (`context.session`, `args_contain_untrusted`, `untrusted_args`), a taken approval
//! (`context.approval`), run limits and usage (`context.budget`, `context.usage`), the clock
//! (`context.now_unix`) and the MCP session (`context.session_id`). What is fixed is the chain
//! (principal, hops, leases, originating user), the server, the tool and its catalog
//! attributes. [`PolicyEngine::screen_tool`] evaluates the policy set with the fixed facts
//! concrete and the others Cedar unknowns (cedar-policy's experimental `partial-eval`), and
//! hides a tool only when Cedar answers a definite deny: no value the unknowns can take makes a
//! call to it allowed. Anything else (an allow, a residual, an evaluation error) keeps it.
//!
//! - The `@obligation("approval")` forbids are lifted, as the engine's relaxed set does to tell
//!   `approval_required` from `policy_deny`: a call denied only by them creates the pending
//!   approval, so such a tool must stay listed. Every other forbid stays in.
//! - `session_id` is the one optional context member, and `context has session_id` is false
//!   for a call without one. When some policy reads it, the tool is hidden only when it is
//!   denied both with an unknown `session_id` and with none.
//! - The stages before Cedar that decide on fixed facts are screened exactly: a name outside
//!   [`attenuo_core::names`] (`invalid_name`), a tool missing from the catalog under
//!   [`UnknownTools::Deny`] (`tool_not_in_catalog`), and an originating-user attribute of the
//!   wrong type (`attribute_type_mismatch`). The capability stage is the proxy's own list
//!   filter, which runs first; run limits are run state and are not screened.
//!
//! The screen is sound, not complete: Cedar does not check residuals for satisfiability, so
//! `context.input.n > 5 && context.input.n < 3` keeps its tool listed. It never writes an
//! audit record, takes an approval, charges a counter or reads run state, and it does not use
//! the request cache, so it cannot change a `tools/call` decision.

use attenuo_core::DelegationChain;
use cedar_policy::Decision as CedarDecision;

use crate::request::{check_user_attributes, ScreenBase};
use crate::{PolicyEngine, ToolAttrs};

/// Hide reason: the tool's name breaks [`attenuo_core::names`].
pub const HIDE_INVALID_NAME: &str = "invalid_name";
/// Hide reason: the tool is not in the catalog and [`crate::UnknownTools::Deny`] is in force.
pub const HIDE_NOT_IN_CATALOG: &str = "not_in_catalog";
/// Hide reason: the policy set (approval forbids lifted) denies every possible call, or an
/// originating-user attribute has the wrong type.
pub const HIDE_POLICY: &str = "policy";

/// What the list screen says about one tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListScreen {
    /// Some call to the tool may be allowed, or the screen could not tell.
    Keep,
    /// No call to the tool can be allowed for this chain; the reason is one of
    /// [`HIDE_INVALID_NAME`], [`HIDE_NOT_IN_CATALOG`] or [`HIDE_POLICY`].
    Hide(&'static str),
}

impl ListScreen {
    /// Whether the tool stays listed.
    pub fn keeps(self) -> bool {
        self == ListScreen::Keep
    }
}

/// The screen's per-list state: the chain and server parts shared by every tool, or the
/// verdict every tool gets when they cannot be built.
pub(crate) enum Prepared {
    Base(Box<ScreenBase>),
    /// The originating user's attributes break their declared types: every call is denied.
    AllDenied,
    /// The chain could not be translated: keep everything (the screen fails open).
    Failed,
}

impl PolicyEngine {
    /// The list screen for one tool, uncached (see the [module docs](self)): `(server, tool)`
    /// for the agent at the end of `chain`.
    pub fn screen_tool(&self, chain: &DelegationChain, server: &str, tool: &str) -> ListScreen {
        let base = self.screen_prepare(chain, server);
        self.screen_one(&base, server, tool)
    }

    /// [`screen_tool`](Self::screen_tool) for every name in `tools`, sharing the chain's parts.
    pub fn screen_tools_uncached(
        &self,
        chain: &DelegationChain,
        server: &str,
        tools: &[String],
    ) -> Vec<ListScreen> {
        let base = self.screen_prepare(chain, server);
        tools
            .iter()
            .map(|t| self.screen_one(&base, server, t))
            .collect()
    }

    pub(crate) fn screen_prepare(&self, chain: &DelegationChain, server: &str) -> Prepared {
        if check_user_attributes(&chain.originating_user, &self.user_attrs).is_err() {
            return Prepared::AllDenied;
        }
        match ScreenBase::build(chain, server) {
            Ok(base) => Prepared::Base(Box::new(base)),
            // Every call of this chain is denied with `policy_error`, whose diagnostics say
            // why; the screen keeps the entries (it fails open, the list is advisory).
            Err(_) => Prepared::Failed,
        }
    }

    pub(crate) fn screen_one(&self, base: &Prepared, server: &str, tool: &str) -> ListScreen {
        if attenuo_core::names::check_server_name(server).is_err()
            || attenuo_core::names::check_call_name(tool).is_err()
        {
            return ListScreen::Hide(HIDE_INVALID_NAME);
        }
        let Some(attrs) = self.effective_attrs(server, tool) else {
            return ListScreen::Hide(HIDE_NOT_IN_CATALOG);
        };
        match base {
            Prepared::AllDenied => ListScreen::Hide(HIDE_POLICY),
            Prepared::Failed => ListScreen::Keep,
            Prepared::Base(base) => self.screen_cedar(base, tool, &attrs),
        }
    }

    /// The Cedar part: hide only on a definite deny with no evaluation error, under every
    /// `session_id` shape a policy can tell apart.
    pub(crate) fn screen_cedar(
        &self,
        base: &ScreenBase,
        tool: &str,
        attrs: &ToolAttrs,
    ) -> ListScreen {
        let shapes: &[bool] = if self.policies_read_session_id {
            &[true, false]
        } else {
            &[true]
        };
        for &with_session_id in shapes {
            if !self.denied_for_every_call(base, tool, attrs, with_session_id) {
                return ListScreen::Keep;
            }
        }
        ListScreen::Hide(HIDE_POLICY)
    }

    fn denied_for_every_call(
        &self,
        base: &ScreenBase,
        tool: &str,
        attrs: &ToolAttrs,
        with_session_id: bool,
    ) -> bool {
        let Ok((request, entities)) =
            base.partial_request(tool, attrs, self.legacy_bare_actions, with_session_id)
        else {
            return false;
        };
        let policies = self
            .obligations
            .without_approval
            .as_ref()
            .unwrap_or(&self.policies);
        let response = self
            .authorizer
            .is_authorized_partial(&request, policies, &entities);
        response.definitely_errored().next().is_none()
            && response.decision() == Some(CedarDecision::Deny)
    }
}
