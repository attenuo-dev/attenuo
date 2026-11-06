//! The run's taint labels and argument taint a call is decided with (ADR-0009).

use attenuo_audit::ApprovalLabel;
use attenuo_core::{RecordLabels, UntrustedArg};
use attenuo_policy::{ArgLabels, SessionLabels};
use serde_json::Value;

/// What [`Pipeline::run_labels`] found for a call's delegation run.
///
/// [`Pipeline::run_labels`]: super::Pipeline::run_labels
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunLabels {
    /// What Cedar sees as `context.session`.
    pub session: SessionLabels,
    /// What the decision record carries: the `seq` of the first untrusted result of each
    /// source.
    pub record: RecordLabels,
    /// The same labels with their sources, for a pending approval.
    pub sources: Vec<ApprovalLabel>,
    /// Set when the taint state could not be read (the run then counts as tainted).
    pub error: Option<String>,
}

/// Most `untrusted_args` entries a decision carries. One entry per argument, result and kind,
/// so a long argument copied from many results could otherwise make a large record; the
/// Cedar context still names every matching argument.
pub const MAX_UNTRUSTED_ARG_ENTRIES: usize = 64;

/// What [`Pipeline::arg_taint`] found for a call (ADR-0009 phase 2).
///
/// [`Pipeline::arg_taint`]: super::Pipeline::arg_taint
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgTaint {
    /// What Cedar sees as `context.args_contain_untrusted` and `context.untrusted_args`.
    pub context: ArgLabels,
    /// What the decision record carries as `labels.untrusted_args`, at most
    /// [`MAX_UNTRUSTED_ARG_ENTRIES`].
    pub record: Vec<UntrustedArg>,
    /// Set when the span index could not be read (every unpinned argument then counts).
    pub error: Option<String>,
}

/// `labels.untrusted_args` as JSON: `[{arg, seq, kind}]`, `seq` omitted for `unreadable`. What
/// the `-32008` / `-32003` error data and AuthZEN answers carry when it is non-empty.
pub fn untrusted_args_json(args: &[UntrustedArg]) -> Value {
    serde_json::to_value(args).unwrap_or_default()
}
