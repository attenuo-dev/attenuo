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

/// Most `(argument, fingerprint)` pairs [`Pipeline::arg_taint`] looks up for one call: four
/// arguments at the per-value cap ([`MAX_FINGERPRINTS_PER_VALUE`]). Counted before
/// duplicates are merged, so it bounds both the lookups (one per distinct fingerprint) and
/// the entries the hits expand to (at most [`MAX_SEQS_PER_PROBE`] results per fingerprint,
/// times the arguments that carry it). An ordinary call is far below it: a long message body
/// is one argument. A call past it is not looked up at all and fails closed: every unpinned
/// argument with a fingerprint counts as untrusted, kind `unreadable` (SR-91).
///
/// [`Pipeline::arg_taint`]: super::Pipeline::arg_taint
/// [`MAX_FINGERPRINTS_PER_VALUE`]: attenuo_core::fingerprint::MAX_FINGERPRINTS_PER_VALUE
/// [`MAX_SEQS_PER_PROBE`]: attenuo_audit::MAX_SEQS_PER_PROBE
pub const MAX_ARG_PROBES: usize = 4 * attenuo_core::fingerprint::MAX_FINGERPRINTS_PER_VALUE;

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
    /// Set when the span index could not be read, or the call carries more than
    /// [`MAX_ARG_PROBES`] fingerprints (every unpinned argument then counts).
    pub error: Option<String>,
}

/// `labels.untrusted_args` as JSON: `[{arg, seq, kind}]`, `seq` omitted for `unreadable`. What
/// the `-32008` / `-32003` error data and AuthZEN answers carry when it is non-empty.
pub fn untrusted_args_json(args: &[UntrustedArg]) -> Value {
    serde_json::to_value(args).unwrap_or_default()
}
