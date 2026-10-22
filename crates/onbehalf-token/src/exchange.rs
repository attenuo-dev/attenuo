//! Wire shapes for a token-exchange HTTP endpoint (RFC 8693 §2.1 / §2.2).
//!
//! A request carries the parent token as `subject_token`, the agent that will act as `actor`,
//! and the requested capabilities in `authorization_details` (RFC 9396 rich authorization
//! requests, with `type` = [`AUTHORIZATION_DETAILS_TYPE`]). A response is a standard token
//! response with `issued_token_type` = `urn:ietf:params:oauth:token-type:jwt`.
//!
//! ```json
//! {
//!   "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
//!   "subject_token": "<parent jwt>",
//!   "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
//!   "actor": "agent:coder",
//!   "authorization_details": [
//!     { "type": "onbehalf_capabilities", "capabilities": [ { "server": "github", "tool": "read_*" } ] }
//!   ],
//!   "requested_ttl_seconds": 600
//! }
//! ```

use onbehalf_core::{AgentId, CapabilitySet, LeaseId};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::claims::JWT_TOKEN_TYPE_URN;
use crate::error::TokenError;
use crate::issuer::{IssuedToken, Issuer};

/// RFC 8693 §2.1 grant type.
pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// `type` of the RFC 9396 authorization-details entry that carries capabilities.
pub const AUTHORIZATION_DETAILS_TYPE: &str = "onbehalf_capabilities";

/// A token-exchange request.
///
/// Serializes to and from the RFC 8693 JSON shape shown in the module docs. Deserialization
/// rejects a wrong `grant_type` or `subject_token_type`, and merges every
/// `onbehalf_capabilities` entry of `authorization_details` into `requested`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "ExchangeRequestWire", try_from = "ExchangeRequestWire")]
pub struct ExchangeRequest {
    /// The parent delegation token.
    pub subject_token: String,
    /// The agent that will act under the new token.
    pub actor: AgentId,
    /// Capabilities requested for `actor`; must be covered by the parent's.
    pub requested: CapabilitySet,
    /// Requested lifetime; clamped to the parent's expiry and defaulting to the issuer's TTL.
    pub ttl_seconds: Option<u64>,
}

impl ExchangeRequest {
    /// Perform the exchange with `issuer` as of `now`.
    pub fn execute(
        &self,
        issuer: &Issuer,
        now: OffsetDateTime,
    ) -> Result<ExchangeResponse, TokenError> {
        let ttl = self
            .ttl_seconds
            .map(|s| Duration::seconds(i64::try_from(s).unwrap_or(i64::MAX)));
        let issued = issuer.exchange(
            &self.subject_token,
            self.actor.clone(),
            self.requested.clone(),
            ttl,
            now,
        )?;
        Ok(ExchangeResponse::from_issued(&issued, now))
    }
}

/// RFC 9396 authorization-details entry carrying capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthorizationDetail {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    capabilities: CapabilitySet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExchangeRequestWire {
    grant_type: String,
    subject_token: String,
    subject_token_type: String,
    actor: AgentId,
    #[serde(default)]
    authorization_details: Vec<AuthorizationDetail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requested_ttl_seconds: Option<u64>,
}

impl From<ExchangeRequest> for ExchangeRequestWire {
    fn from(req: ExchangeRequest) -> Self {
        Self {
            grant_type: TOKEN_EXCHANGE_GRANT_TYPE.to_owned(),
            subject_token: req.subject_token,
            subject_token_type: JWT_TOKEN_TYPE_URN.to_owned(),
            actor: req.actor,
            authorization_details: vec![AuthorizationDetail {
                kind: AUTHORIZATION_DETAILS_TYPE.to_owned(),
                capabilities: req.requested,
            }],
            requested_ttl_seconds: req.ttl_seconds,
        }
    }
}

impl TryFrom<ExchangeRequestWire> for ExchangeRequest {
    type Error = String;

    fn try_from(wire: ExchangeRequestWire) -> Result<Self, Self::Error> {
        if wire.grant_type != TOKEN_EXCHANGE_GRANT_TYPE {
            return Err(format!("unsupported grant_type `{}`", wire.grant_type));
        }
        if wire.subject_token_type != JWT_TOKEN_TYPE_URN {
            return Err(format!(
                "unsupported subject_token_type `{}`",
                wire.subject_token_type
            ));
        }
        let requested = wire
            .authorization_details
            .into_iter()
            .filter(|d| d.kind == AUTHORIZATION_DETAILS_TYPE)
            .flat_map(|d| d.capabilities.0.into_iter())
            .collect();
        Ok(Self {
            subject_token: wire.subject_token,
            actor: wire.actor,
            requested,
            ttl_seconds: wire.requested_ttl_seconds,
        })
    }
}

/// A token-exchange response (RFC 8693 §2.2.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExchangeResponse {
    /// The child delegation token.
    pub access_token: String,
    /// Always `urn:ietf:params:oauth:token-type:jwt`.
    pub issued_token_type: String,
    /// Always `Bearer`.
    pub token_type: String,
    /// Seconds until `access_token` expires, measured from the exchange time.
    pub expires_in: u64,
    /// Lease of the new hop, for revocation.
    pub lease: LeaseId,
}

impl ExchangeResponse {
    /// Build the response for a token minted at `now`.
    pub fn from_issued(issued: &IssuedToken, now: OffsetDateTime) -> Self {
        let expires_in = (issued.expires_at - now).whole_seconds().max(0) as u64;
        Self {
            access_token: issued.token.clone(),
            issued_token_type: JWT_TOKEN_TYPE_URN.to_owned(),
            token_type: "Bearer".to_owned(),
            expires_in,
            lease: issued.lease.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use onbehalf_core::Capability;
    use serde_json::json;

    #[test]
    fn request_round_trips_through_rfc8693_shape() {
        let req = ExchangeRequest {
            subject_token: "a.b.c".into(),
            actor: AgentId::new("agent:coder"),
            requested: CapabilitySet::from_iter([Capability::new("github", "read_*")]),
            ttl_seconds: Some(600),
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["grant_type"], json!(TOKEN_EXCHANGE_GRANT_TYPE));
        assert_eq!(v["subject_token_type"], json!(JWT_TOKEN_TYPE_URN));
        assert_eq!(
            v["authorization_details"][0]["type"],
            json!(AUTHORIZATION_DETAILS_TYPE)
        );
        assert_eq!(v["requested_ttl_seconds"], json!(600));
        let back: ExchangeRequest = serde_json::from_value(v).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn request_rejects_wrong_grant_type() {
        let v = json!({
            "grant_type": "client_credentials",
            "subject_token": "x",
            "subject_token_type": JWT_TOKEN_TYPE_URN,
            "actor": "a",
        });
        assert!(serde_json::from_value::<ExchangeRequest>(v).is_err());
    }

    #[test]
    fn request_without_details_has_empty_capabilities() {
        let v = json!({
            "grant_type": TOKEN_EXCHANGE_GRANT_TYPE,
            "subject_token": "x",
            "subject_token_type": JWT_TOKEN_TYPE_URN,
            "actor": "a",
        });
        let req: ExchangeRequest = serde_json::from_value(v).unwrap();
        assert!(req.requested.is_empty());
        assert_eq!(req.ttl_seconds, None);
    }
}
