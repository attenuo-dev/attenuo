//! Core types for `onbehalf`, the delegation-aware authorization plane for AI agents.
//!
//! This crate is deliberately free of I/O. It defines:
//!
//! - [`Capability`] and [`CapabilitySet`]: what an agent may call, including argument constraints.
//! - [`DelegationChain`]: the originating user plus every agent hop, with the invariant that
//!   capabilities only narrow from one hop to the next (monotonic attenuation).
//! - [`ToolCall`]: a normalized tool invocation to authorize.
//! - [`Decision`] and [`DecisionRecord`]: the outcome of authorization and the record that the
//!   audit log stores.
//!
//! Everything that signs, stores, or evaluates lives in sibling crates.

pub mod call;
pub mod capability;
pub mod chain;
pub mod decision;
pub mod digest;
pub mod error;

pub use call::ToolCall;
pub use capability::{ArgConstraint, Capability, CapabilitySet};
pub use chain::{AgentId, DelegationChain, Hop, LeaseId, OriginatingUser};
pub use decision::{Decision, DecisionRecord};
pub use error::{AttenuationError, ChainError};
