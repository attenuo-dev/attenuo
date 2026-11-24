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
//!     { "type": "attenuo_capabilities", "capabilities": [ { "server": "github", "tool": "read_*" } ] }
//!   ],
//!   "requested_ttl_seconds": 600,
//!   "may_act": { "sub": ["agent:reviewer"] }
//! }
//! ```
//!
//! `may_act` is optional: it becomes the child token's RFC 8693 §4.4 `may_act` claim, the
//! agents allowed to exchange the child next. Actor authentication (`actor_token`, client
//! credentials) is the server's business and not part of this type.

use attenuo_core::{AgentId, CapabilitySet, LeaseId};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::claims::{MayAct, JWT_TOKEN_TYPE_URN};
use crate::dpop::Confirmation;
use crate::error::TokenError;
use crate::issuer::{IssueOptions, IssuedToken, Issuer};

/// RFC 8693 §2.1 grant type.
pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// `type` of the RFC 9396 authorization-details entry that carries capabilities.
pub const AUTHORIZATION_DETAILS_TYPE: &str = "attenuo_capabilities";

/// A token-exchange request.
///
/// Serializes to and from the RFC 8693 JSON shape shown in the module docs. Deserialization
/// rejects a wrong `grant_type` or `subject_token_type`, and merges every
/// `attenuo_capabilities` entry of `authorization_details` into `requested`.
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
    /// `may_act` for the child token: who may exchange it next.
    pub may_act: Option<MayAct>,
}

impl ExchangeRequest {
    /// Perform the exchange with `issuer` as of `now`.
    ///
    /// # Errors
    ///
    /// As [`Issuer::exchange`].
    pub fn execute(
        &self,
        issuer: &Issuer,
        now: OffsetDateTime,
    ) -> Result<ExchangeResponse, TokenError> {
        self.execute_until(issuer, now, None)
    }

    /// As [`ExchangeRequest::execute`], with the child's expiry also capped at `not_after`
    /// (for example the `exp` of the actor token that authenticated the request).
    ///
    /// # Errors
    ///
    /// As [`Issuer::exchange`] (so a key-bound subject token fails with
    /// [`TokenError::BindingRequired`]), plus [`TokenError::NoLifetimeLeft`] when `not_after`
    /// is less than a second after `now`.
    pub fn execute_until(
        &self,
        issuer: &Issuer,
        now: OffsetDateTime,
        not_after: Option<OffsetDateTime>,
    ) -> Result<ExchangeResponse, TokenError> {
        self.execute_with(issuer, now, not_after, None)
    }

    /// As [`ExchangeRequest::execute_until`], with the child bound to a key (`cnf`) when given.
    /// The caller has verified a DPoP proof for that key and, when the subject token is bound,
    /// possession of the subject token's key; see [`IssueOptions::cnf`].
    ///
    /// # Errors
    ///
    /// As [`Issuer::exchange_with`]: the subject token's verification error,
    /// [`TokenError::ActorNotPermitted`], [`TokenError::BindingRequired`],
    /// [`TokenError::NoLifetimeLeft`], [`TokenError::Chain`] when the hop cannot be added, and
    /// [`TokenError::Malformed`] for a `cnf` that is not a SHA-256 thumbprint.
    pub fn execute_with(
        &self,
        issuer: &Issuer,
        now: OffsetDateTime,
        not_after: Option<OffsetDateTime>,
        cnf: Option<Confirmation>,
    ) -> Result<ExchangeResponse, TokenError> {
        let ttl = self
            .ttl_seconds
            .map(|s| Duration::seconds(i64::try_from(s).unwrap_or(i64::MAX)));
        let issued = issuer.exchange_with(
            &self.subject_token,
            self.actor.clone(),
            self.requested.clone(),
            ttl,
            now,
            &IssueOptions {
                may_act: self.may_act.clone(),
                not_after,
                cnf,
            },
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    may_act: Option<MayAct>,
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
            may_act: req.may_act,
        }
    }
}

/// Why a JSON value is not an [`ExchangeRequest`] ([`ExchangeRequest::from_json`]). The
/// variant tells the cases apart; the text is for people. Deserializing through `serde` gives
/// the same text, with the variant lost.
#[derive(Debug, thiserror::Error)]
pub enum ExchangeRequestError {
    /// A field is missing or does not have its type.
    #[error("{0}")]
    Malformed(serde_json::Error),
    /// `grant_type` is not [`TOKEN_EXCHANGE_GRANT_TYPE`].
    #[error("unsupported grant_type `{0}`")]
    UnsupportedGrantType(String),
    /// `subject_token_type` is not the JWT token type URN.
    #[error("unsupported subject_token_type `{0}`")]
    UnsupportedSubjectTokenType(String),
}

impl ExchangeRequest {
    /// Read a request from its RFC 8693 JSON shape, saying why when it is not one.
    ///
    /// # Errors
    ///
    /// [`ExchangeRequestError::Malformed`] for a missing or ill-typed field, else
    /// [`ExchangeRequestError::UnsupportedGrantType`] or
    /// [`ExchangeRequestError::UnsupportedSubjectTokenType`].
    pub fn from_json(value: serde_json::Value) -> Result<Self, ExchangeRequestError> {
        let wire: ExchangeRequestWire =
            serde_json::from_value(value).map_err(ExchangeRequestError::Malformed)?;
        Self::try_from(wire)
    }
}

impl TryFrom<ExchangeRequestWire> for ExchangeRequest {
    type Error = ExchangeRequestError;

    fn try_from(wire: ExchangeRequestWire) -> Result<Self, Self::Error> {
        if wire.grant_type != TOKEN_EXCHANGE_GRANT_TYPE {
            return Err(ExchangeRequestError::UnsupportedGrantType(wire.grant_type));
        }
        if wire.subject_token_type != JWT_TOKEN_TYPE_URN {
            return Err(ExchangeRequestError::UnsupportedSubjectTokenType(
                wire.subject_token_type,
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
            may_act: wire.may_act,
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
    /// `DPoP` for a token bound to a DPoP key (RFC 9449 §5), `Bearer` otherwise: a token bound
    /// to a TLS client certificate is sent as a bearer token over mutual TLS (RFC 8705 §3).
    pub token_type: String,
    /// Seconds until `access_token` expires, measured from the exchange time.
    pub expires_in: u64,
    /// Lease of the new hop, for revocation.
    pub lease: LeaseId,
}

impl ExchangeResponse {
    /// Build the response for a token minted at `now`.
    pub fn from_issued(issued: &IssuedToken, now: OffsetDateTime) -> Self {
        let expires_in = u64::try_from((issued.expires_at - now).whole_seconds()).unwrap_or(0);
        Self {
            access_token: issued.token.clone(),
            issued_token_type: JWT_TOKEN_TYPE_URN.to_owned(),
            token_type: if issued
                .cnf
                .as_ref()
                .is_some_and(|c| c.key_thumbprint().is_some())
            {
                "DPoP"
            } else {
                "Bearer"
            }
            .to_owned(),
            expires_in,
            lease: issued.lease.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attenuo_core::Capability;
    use serde_json::json;

    #[test]
    fn request_round_trips_through_rfc8693_shape() {
        let req = ExchangeRequest {
            subject_token: "a.b.c".into(),
            actor: AgentId::new("agent:coder"),
            requested: CapabilitySet::from_iter([Capability::new("github", "read_*")]),
            ttl_seconds: Some(600),
            may_act: Some(MayAct::new(["agent:reviewer"])),
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["may_act"], json!({"sub": ["agent:reviewer"]}));
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
        assert!(serde_json::from_value::<ExchangeRequest>(v.clone()).is_err());
        assert!(matches!(
            ExchangeRequest::from_json(v),
            Err(ExchangeRequestError::UnsupportedGrantType(g)) if g == "client_credentials"
        ));
    }

    /// `from_json` names the case by its variant, with the text `serde` gives; a field whose
    /// own error quotes another case's text is still malformed.
    #[test]
    fn from_json_tells_the_cases_apart_by_type() {
        let base = json!({
            "grant_type": TOKEN_EXCHANGE_GRANT_TYPE,
            "subject_token": "x",
            "subject_token_type": JWT_TOKEN_TYPE_URN,
            "actor": "a",
        });
        let with = |k: &str, v: serde_json::Value| {
            let mut b = base.clone();
            b[k] = v;
            b
        };
        let cases = [
            with("subject_token_type", json!("urn:example:saml")),
            with("grant_type", json!("password")),
            with("requested_ttl_seconds", json!("unsupported grant_type")),
        ];
        for v in cases {
            let serde_text = serde_json::from_value::<ExchangeRequest>(v.clone())
                .unwrap_err()
                .to_string();
            let e = ExchangeRequest::from_json(v).unwrap_err();
            assert_eq!(e.to_string(), serde_text);
        }
        assert!(matches!(
            ExchangeRequest::from_json(with("subject_token_type", json!("t"))),
            Err(ExchangeRequestError::UnsupportedSubjectTokenType(t)) if t == "t"
        ));
        assert!(matches!(
            ExchangeRequest::from_json(with(
                "requested_ttl_seconds",
                json!("unsupported grant_type")
            )),
            Err(ExchangeRequestError::Malformed(_))
        ));
        assert!(ExchangeRequest::from_json(base).is_ok());
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
        assert_eq!(req.may_act, None);
    }
}
