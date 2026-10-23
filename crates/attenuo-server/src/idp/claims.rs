//! Mapping verified IdP claims onto attenuo's model.
//!
//! - [`originating_user`]: the `OriginatingUser` block for hop 0, the same for both
//!   credential types.
//! - [`map_id_jag`]: the ID-JAG-specific claims. The ID-JAG draft
//!   (draft-ietf-oauth-identity-assertion-authz-grant, -04 at the time of writing) is still
//!   changing; everything that depends on its claim names is in that one function.

use std::collections::BTreeMap;

use attenuo_core::OriginatingUser;
use serde_json::{Map, Value};
use time::OffsetDateTime;

use super::{numeric_date, IntakeError, VerifiedAssertion};

/// Name of the derived attribute that says whether the user authenticated with more than one
/// factor.
pub const MFA_ATTRIBUTE: &str = "mfa";

/// `amr` values (RFC 8176) that count as multi-factor: `mfa` itself, a one-time password, and a
/// proof of possession of a hardware or software key. Anything else (`pwd`, `face`, `sms`, ...)
/// on its own does not set `mfa`.
pub const MFA_AMR_VALUES: &[&str] = &["mfa", "otp", "hwk", "swk"];

/// Build the originating user from a verified credential.
///
/// - `subject` = `sub`, `issuer` = `iss`;
/// - `authenticated_at` = `auth_time` if present, else `iat`;
/// - `attributes` = every claim named in the IdP's `attribute_claims` that is present and not
///   null, copied verbatim, plus `mfa: bool` from `amr` ([`MFA_AMR_VALUES`]). The derived `mfa`
///   overrides a claim of the same name.
pub fn originating_user(v: &VerifiedAssertion) -> Result<OriginatingUser, IntakeError> {
    let at = numeric_date(&v.claims, "auth_time")
        .or_else(|| numeric_date(&v.claims, "iat"))
        .ok_or(IntakeError::MissingClaim("iat"))?;
    let authenticated_at =
        OffsetDateTime::from_unix_timestamp(at).map_err(|_| IntakeError::MissingClaim("iat"))?;
    let mut attributes: BTreeMap<String, Value> = v
        .attribute_claims
        .iter()
        .filter_map(|name| {
            v.claims
                .get(name)
                .filter(|val| !val.is_null())
                .map(|val| (name.clone(), val.clone()))
        })
        .collect();
    attributes.insert(MFA_ATTRIBUTE.into(), Value::Bool(mfa_from_amr(&v.claims)));
    Ok(OriginatingUser {
        subject: v.subject.clone(),
        issuer: v.issuer.clone(),
        authenticated_at,
        attributes,
    })
}

/// `true` when `amr` contains one of [`MFA_AMR_VALUES`].
pub fn mfa_from_amr(claims: &Map<String, Value>) -> bool {
    claims
        .get("amr")
        .and_then(Value::as_array)
        .is_some_and(|amr| {
            amr.iter()
                .filter_map(Value::as_str)
                .any(|m| MFA_AMR_VALUES.contains(&m))
        })
}

/// The ID-JAG claims attenuo uses beyond the common ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdJagClaims {
    /// `client_id`: the client the IdP issued the assertion to. It must be the agent that
    /// presents it, and becomes the root hop's agent.
    pub client_id: String,
}

/// Read the ID-JAG-specific claims (draft -04 §3): `client_id` is required.
///
/// The draft's `resource` and `scope` claims are not used: the capabilities of the root token
/// come from `[[root_grants]]` and the request, not from the IdP. If a later draft renames or
/// adds required claims, this is the function to change.
pub fn map_id_jag(claims: &Map<String, Value>) -> Result<IdJagClaims, IntakeError> {
    match claims.get("client_id").and_then(Value::as_str) {
        Some(c) if !c.is_empty() => Ok(IdJagClaims {
            client_id: c.to_owned(),
        }),
        _ => Err(IntakeError::MissingClaim("client_id")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idp::CredentialKind;
    use serde_json::json;

    fn assertion(claims: Value) -> VerifiedAssertion {
        VerifiedAssertion {
            kind: CredentialKind::IdToken,
            issuer: "https://idp".into(),
            subject: "alice".into(),
            claims: claims.as_object().unwrap().clone(),
            attribute_claims: vec!["email".into(), "groups".into(), "amr".into()],
            expires_at: 0,
            clock_skew_seconds: 0,
        }
    }

    #[test]
    fn user_block_from_claims() {
        let u = originating_user(&assertion(json!({
            "iat": 2000, "auth_time": 1000, "email": "a@x", "groups": ["dev"],
            "amr": ["pwd", "otp"], "phone": "secret", "mfa": false,
        })))
        .unwrap();
        assert_eq!(u.subject, "alice");
        assert_eq!(u.authenticated_at.unix_timestamp(), 1000);
        assert_eq!(u.attributes["email"], json!("a@x"));
        assert_eq!(u.attributes["groups"], json!(["dev"]));
        assert_eq!(u.attributes[MFA_ATTRIBUTE], json!(true));
        assert!(!u.attributes.contains_key("phone"));
    }

    #[test]
    fn mfa_needs_a_second_factor_value() {
        let m = |amr: Value| mfa_from_amr(json!({ "amr": amr }).as_object().unwrap());
        assert!(!m(json!(["pwd"])));
        assert!(!m(json!("mfa")));
        assert!(m(json!(["hwk"])));
        assert!(m(json!(["pwd", "swk"])));
        let u = originating_user(&assertion(json!({"iat": 5}))).unwrap();
        assert_eq!(u.authenticated_at.unix_timestamp(), 5);
        assert_eq!(u.attributes[MFA_ATTRIBUTE], json!(false));
    }

    #[test]
    fn id_jag_requires_client_id() {
        let c = |v: Value| map_id_jag(v.as_object().unwrap());
        assert_eq!(
            c(json!({"client_id": "planner"})).unwrap().client_id,
            "planner"
        );
        assert_eq!(
            c(json!({})).unwrap_err(),
            IntakeError::MissingClaim("client_id")
        );
    }
}
