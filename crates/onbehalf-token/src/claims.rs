//! JWT claim set of a delegation token.

use onbehalf_core::{DelegationChain, OriginatingUser};
use serde::{Deserialize, Serialize};

/// Value of the JWT header `typ` and of the `typ` claim. Verifiers reject anything else, so a
/// delegation token can never be confused with an ordinary access token for the same audience.
pub const TOKEN_TYPE: &str = "onbehalf+jwt";

/// RFC 8693 §3 token type identifier for the tokens this crate issues and accepts.
pub const JWT_TOKEN_TYPE_URN: &str = "urn:ietf:params:oauth:token-type:jwt";

/// The `act` (actor) claim, nested as in RFC 8693 §4.1.
///
/// The outermost `ActClaim` is the agent currently acting (the last hop of the chain); each
/// nested `act` is the party that delegated to it, down to the root agent that received the
/// grant directly from the user, whose `act` is `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActClaim {
    /// Agent identifier of this actor.
    pub sub: String,
    /// The actor that delegated to this one, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<ActClaim>>,
}

impl ActClaim {
    /// Build the nested actor claim from a chain (last hop outermost, root hop innermost).
    ///
    /// Returns `None` for a chain with no hops.
    pub fn from_chain(chain: &DelegationChain) -> Option<ActClaim> {
        chain.hops.iter().fold(None, |inner, hop| {
            Some(ActClaim {
                sub: hop.agent.0.clone(),
                act: inner.map(Box::new),
            })
        })
    }

    /// Depth of the nesting: number of actors represented.
    pub fn depth(&self) -> usize {
        1 + self.act.as_deref().map(ActClaim::depth).unwrap_or(0)
    }
}

/// The claims of a delegation token.
///
/// The authoritative content is `chain`; `sub` and `act` are derived from it so that generic
/// RFC 8693 consumers can read who is acting for whom without understanding `chain`. Verifiers
/// check that they agree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer identifier of the onbehalf token service.
    pub iss: String,
    /// Intended audience (the proxy or resource that will evaluate the chain).
    pub aud: String,
    /// Subject of the originating user (`chain.originating_user.subject`).
    pub sub: String,
    /// Current actor with nested parents; innermost is the root agent.
    pub act: ActClaim,
    /// Unique token id.
    pub jti: String,
    /// Issued-at, seconds since the Unix epoch.
    pub iat: i64,
    /// Expiry, seconds since the Unix epoch. Always equal to the last hop's `expires_at`.
    pub exp: i64,
    /// The delegation chain this token carries.
    pub chain: DelegationChain,
    /// Always [`TOKEN_TYPE`].
    pub typ: String,
    /// Detached issuer signature over the canonical JSON of `chain.originating_user`, base64url.
    ///
    /// It is produced once, at root issuance, and copied unchanged through every exchange. A
    /// verifier recomputes the canonical encoding and checks the signature, so an exchanged token
    /// whose user block was edited fails even if its outer JWT signature is valid under a
    /// different legitimate issuer key (multi-issuer deployments). In v0 both signatures use the
    /// same key; the separate field keeps the user block independently verifiable when that
    /// changes.
    pub ou_sig: String,
    /// RFC 8693 §4.4 `may_act`: the agents allowed to act on this token in the next exchange.
    ///
    /// When present, [`crate::Issuer::exchange`] refuses an `actor` that is not listed
    /// ([`crate::TokenError::ActorNotPermitted`]). Absent means any actor may exchange it, subject
    /// to the server's actor authentication. It is not inherited: a child carries only the
    /// `may_act` its own exchange asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub may_act: Option<MayAct>,
}

/// The RFC 8693 §4.4 `may_act` claim, restricted to agent ids.
///
/// Serialized as `{"sub": ["agent:a", "agent:b"]}`. A single `{"sub": "agent:a"}` (the RFC's
/// own example shape), a bare list, or a bare string are accepted on input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MayAct {
    /// Agent ids that may act. An empty list means nobody may exchange the token.
    pub sub: Vec<String>,
}

impl MayAct {
    /// Build from agent ids, dropping duplicates while keeping order.
    pub fn new<I, S>(agents: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut sub: Vec<String> = Vec::new();
        for a in agents {
            let a = a.into();
            if !sub.contains(&a) {
                sub.push(a);
            }
        }
        Self { sub }
    }

    /// Is `agent` allowed to act?
    pub fn permits(&self, agent: &str) -> bool {
        self.sub.iter().any(|s| s == agent)
    }

    /// Is every agent of `self` also in `ceiling`?
    pub fn is_within(&self, ceiling: &MayAct) -> bool {
        self.sub.iter().all(|s| ceiling.permits(s))
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl From<OneOrMany> for Vec<String> {
    fn from(v: OneOrMany) -> Self {
        match v {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum MayActWire {
    Object { sub: OneOrMany },
    Bare(OneOrMany),
}

impl<'de> Deserialize<'de> for MayAct {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let agents: Vec<String> = match MayActWire::deserialize(d)? {
            MayActWire::Object { sub } => sub.into(),
            MayActWire::Bare(v) => v.into(),
        };
        if agents.iter().any(String::is_empty) {
            return Err(serde::de::Error::custom(
                "may_act: agent ids must not be empty",
            ));
        }
        Ok(MayAct::new(agents))
    }
}

/// Canonical byte encoding of the originating-user block that `ou_sig` signs.
///
/// Canonical means `serde_json` compact output with map keys in `BTreeMap` order; the core types
/// are `BTreeMap`-backed, so re-serializing a decoded block yields the same bytes.
pub fn canonical_user_bytes(user: &OriginatingUser) -> Vec<u8> {
    serde_json::to_vec(user).expect("OriginatingUser serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn may_act_accepts_the_rfc_shapes_and_serializes_as_a_list() {
        for v in [
            json!({"sub": "coder"}),
            json!({"sub": ["coder"]}),
            json!(["coder", "coder"]),
            json!("coder"),
        ] {
            let m: MayAct = serde_json::from_value(v.clone()).unwrap();
            assert_eq!(m, MayAct::new(["coder"]), "{v}");
        }
        let m = MayAct::new(["a", "b"]);
        assert_eq!(
            serde_json::to_value(&m).unwrap(),
            json!({"sub": ["a", "b"]})
        );
        assert!(m.permits("a") && !m.permits("c"));
        assert!(MayAct::new(["a"]).is_within(&m) && !m.is_within(&MayAct::new(["a"])));
        assert!(serde_json::from_value::<MayAct>(json!({"sub": [""]})).is_err());
        assert!(serde_json::from_value::<MayAct>(json!({"sub": 3})).is_err());
    }
}
