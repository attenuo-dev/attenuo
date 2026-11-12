//! Core types for `attenuo`, the delegation-aware authorization plane for AI agents.
//!
//! This crate is deliberately free of I/O. It defines:
//!
//! - [`Capability`] and [`CapabilitySet`]: what an agent may call, including argument constraints.
//! - [`DelegationChain`]: the originating user plus every agent hop, with the invariant that
//!   capabilities only narrow from one hop to the next (monotonic attenuation).
//! - [`ToolCall`]: a normalized tool invocation to authorize.
//! - [`limits`]: run limits on a capability (`calls`, `sum`, `calls_per`, `distinct`) and the
//!   charges a call makes against them (ADR-0010).
//! - [`clock`]: the time source of TTL and window checks, injectable for tests.
//! - [`windows`]: per-user windows across runs (run limits phase 3), read by policies as
//!   `context.usage.user_window`.
//! - [`names`]: what server and tool names may contain (one rule for every boundary).
//! - [`fingerprint`]: fingerprints of results and arguments for argument-level taint
//!   (ADR-0009, phase 2).
//! - [`authorization`]: the `Bearer` / `DPoP` `Authorization` header, read one way by the
//!   proxy and the server.
//! - [`jsonrpc`]: the JSON-RPC error codes the proxy sends and the CLI reads.
//! - [`jcs`]: RFC 8785 canonical JSON, the encoding of everything that is hashed or signed.
//! - [`Decision`] and [`DecisionRecord`]: the outcome of authorization and the record that the
//!   audit log stores.
//!
//! Everything that signs, stores, or evaluates lives in sibling crates.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(unreachable_pub)]
#![warn(clippy::missing_errors_doc)]
#![warn(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

pub mod authorization;
pub mod call;
pub mod capability;
pub mod chain;
pub mod clock;
pub mod decision;
pub mod digest;
pub mod error;
pub mod fingerprint;
pub mod jcs;
pub mod jsonrpc;
pub mod limits;
pub mod names;
pub mod windows;

pub use call::ToolCall;
pub use capability::{
    as_long, ArgConstraint, Capability, CapabilitySet, ConstraintError, PathError, RangeError,
};
pub use chain::{AgentId, DelegationChain, Hop, LeaseId, OriginatingUser};
pub use clock::{Clock, ManualClock, SystemClock};
pub use decision::{
    chain_id_of, ApprovalInfo, BudgetCharge, Decision, DecisionRecord, OutputLabel, RecordBudget,
    RecordKind, RecordLabels, RecordUsage, RecordUserWindow, RecordWindow, ResultInfo,
    UntrustedArg, UntrustedKind, REASON_APPROVAL_DECLINED, REASON_APPROVAL_GRANTED,
    REASON_APPROVAL_INVALID, REASON_APPROVAL_REQUESTED, REASON_TOOL_RESULT,
};
pub use error::{AttenuationError, ChainError};
pub use limits::{ArgLimit, Charge, Derive, LimitKind, Limits};
pub use names::{NameError, NameKind};
pub use windows::{WindowCharge, WindowKind, WindowMeasure};
