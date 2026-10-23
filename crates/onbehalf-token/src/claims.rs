//! JWT claim set of a delegation token.

use onbehalf_core::{AgentId, CapabilitySet, DelegationChain, Hop, LeaseId, OriginatingUser};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::dpop::Confirmation;

/// Value of the JWT header `typ` and of the `typ` claim. Verifiers reject anything else, so a
/// delegation token can never be confused with an ordinary access token for the same audience.
pub const TOKEN_TYPE: &str = "onbehalf+jwt";

/// RFC 8693 §3 token type identifier for the tokens this crate issues and accepts.
pub const JWT_TOKEN_TYPE_URN: &str = "urn:ietf:params:oauth:token-type:jwt";

/// The only `ou_sig` construction verifiers accept (the `ou_sig_v` claim). Version 1, a bare
/// signature over the user block, is refused (SR-14). Version 2 had the framing of version 3
/// but encoded the user block and root hop with `serde_json`, whose nested objects keep their
/// insertion order (`preserve_order`) and whose numbers keep their spelling, so a verifier
/// built differently computed other bytes; it is refused too (SR-20).
pub const OU_SIG_VERSION: u32 = 3;

/// Domain-separation context of an `ou_sig` v3 signature (see [`ou_sig_payload`]).
pub const OU_SIG_CONTEXT: &str = "onbehalf-ou-v3";

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
    /// Detached issuer signature binding the originating user to this chain's issuer and root
    /// hop, base64url (construction version `ou_sig_v`, see [`ou_sig_payload`]).
    ///
    /// It is produced once, at root issuance, and copied unchanged through every exchange. A
    /// verifier recomputes the signed bytes from `iss`, `chain.originating_user` and
    /// `chain.hops[0]` and checks the signature under the key named by `ou_kid`, so an
    /// exchanged token whose user block or root hop was edited fails even if its outer JWT
    /// signature is valid under another trusted key (rotation, multi-issuer), and a signature
    /// lifted from one chain does not verify in a chain with another root hop or issuer.
    pub ou_sig: String,
    /// Version of the `ou_sig` construction. Verifiers accept only [`OU_SIG_VERSION`]; a token
    /// without this claim (version 1) is refused with [`crate::TokenError::UnsupportedOuSig`].
    #[serde(default)]
    pub ou_sig_v: u32,
    /// `kid` of the key that made `ou_sig`. It can differ from the JWT header `kid` when the
    /// root was minted before a key rotation and the token after it.
    #[serde(default)]
    pub ou_kid: String,
    /// RFC 8693 §4.4 `may_act`: the agents allowed to act on this token in the next exchange.
    ///
    /// When present, [`crate::Issuer::exchange`] refuses an `actor` that is not listed
    /// ([`crate::TokenError::ActorNotPermitted`]). Absent means any actor may exchange it, subject
    /// to the server's actor authentication. It is not inherited: a child carries only the
    /// `may_act` its own exchange asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub may_act: Option<MayAct>,
    /// RFC 9449 §6.1 / RFC 7800 confirmation: the thumbprint of the key the holder must prove
    /// possession of with a DPoP proof on every use ([`crate::dpop`]). Absent for a bearer
    /// token. A child of a bound token is always bound ([`crate::TokenError::BindingRequired`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,
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

/// Canonical byte encoding of the originating-user block that `ou_sig` signs: its RFC 8785
/// canonical JSON ([`onbehalf_core::jcs`]), so the bytes depend only on the values (nested
/// attribute objects in any member order, `2` or `2.0`), never on how they were decoded.
pub fn canonical_user_bytes(user: &OriginatingUser) -> Vec<u8> {
    onbehalf_core::jcs::to_vec(user).expect("OriginatingUser has a canonical JSON form")
}

/// The hop-0 fields `ou_sig` covers. `expires_at` is left out on purpose: it is already
/// bounded by the outer token's `exp` and every hop's expiry check, and the user signs for who
/// acts first, with what, from when, under which lease.
#[derive(Serialize)]
struct RootHopView<'a> {
    agent: &'a AgentId,
    capabilities: &'a CapabilitySet,
    #[serde(with = "time::serde::rfc3339")]
    issued_at: OffsetDateTime,
    lease: &'a LeaseId,
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    let len = u32::try_from(field.len()).expect("ou_sig field shorter than 4 GiB");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
}

/// The payload `ou_sig` v3 signs, before domain separation.
///
/// It is three length-prefixed fields (`u32` big-endian length, then the bytes): `iss`, the
/// RFC 8785 canonical JSON of the originating user ([`canonical_user_bytes`]) and the RFC 8785
/// canonical JSON of hop 0 restricted to `agent`, `capabilities`, `issued_at` and `lease`.
/// The length prefixes keep the three fields apart; canonical JSON makes each field's bytes a
/// function of its value alone (SR-20). The issuer signs
/// `len(OU_SIG_CONTEXT) || OU_SIG_CONTEXT || payload` (the framing of
/// [`crate::detached`]) with Ed25519, so the signature is bound to the issuer and to this
/// chain's root hop, and cannot be confused with a token signature or another detached
/// signature.
pub fn ou_sig_payload(iss: &str, user: &OriginatingUser, root: &Hop) -> Vec<u8> {
    let user = canonical_user_bytes(user);
    let hop = onbehalf_core::jcs::to_vec(&RootHopView {
        agent: &root.agent,
        capabilities: &root.capabilities,
        issued_at: root.issued_at,
        lease: &root.lease,
    })
    .expect("hop has a canonical JSON form");
    let mut out = Vec::with_capacity(12 + iss.len() + user.len() + hop.len());
    push_field(&mut out, iss.as_bytes());
    push_field(&mut out, &user);
    push_field(&mut out, &hop);
    out
}

/// The exact bytes an `ou_sig` v3 signature is made over: [`ou_sig_payload`] framed under
/// [`OU_SIG_CONTEXT`].
///
/// # Panics
///
/// If `user` or `root` holds a time RFC 3339 cannot write (a year outside 0..=9999). A chain
/// decoded from JSON never does; [`crate::Issuer::issue_root`] refuses such a chain first.
pub fn ou_sig_message(iss: &str, user: &OriginatingUser, root: &Hop) -> Vec<u8> {
    crate::detached::frame(OU_SIG_CONTEXT, &ou_sig_payload(iss, user, root))
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

    #[test]
    fn ou_sig_payload_is_length_prefixed_and_covers_each_part() {
        use onbehalf_core::Capability;
        use time::macros::datetime;
        let user = OriginatingUser {
            subject: "u".into(),
            issuer: "https://idp".into(),
            authenticated_at: datetime!(2026-10-23 10:00 UTC),
            attributes: Default::default(),
        };
        let hop = Hop {
            agent: AgentId::new("a"),
            capabilities: CapabilitySet::from_iter([Capability::new("s", "t")]),
            issued_at: datetime!(2026-10-23 10:01 UTC),
            expires_at: datetime!(2026-10-23 10:11 UTC),
            lease: LeaseId::new("l"),
        };
        let base = ou_sig_payload("iss", &user, &hop);
        assert_eq!(&base[..7], b"\0\0\0\x03iss");
        let msg = ou_sig_message("iss", &user, &hop);
        assert!(msg.starts_with(b"\0\0\0\x0eonbehalf-ou-v3"));
        assert!(msg.ends_with(&base));
        // Every covered field changes the payload; `expires_at` does not.
        let mut later = hop.clone();
        later.expires_at = datetime!(2026-10-23 10:12 UTC);
        assert_eq!(ou_sig_payload("iss", &user, &later), base);
        assert_ne!(ou_sig_payload("isS", &user, &hop), base);
        let edits: [fn(&mut Hop); 4] = [
            |h| h.agent = AgentId::new("b"),
            |h| h.capabilities = CapabilitySet::from_iter([Capability::new("s", "*")]),
            |h| h.issued_at = datetime!(2026-10-23 10:02 UTC),
            |h| h.lease = LeaseId::new("m"),
        ];
        for edit in edits {
            let mut h = hop.clone();
            edit(&mut h);
            assert_ne!(ou_sig_payload("iss", &user, &h), base);
        }
        let mut u = user.clone();
        u.subject = "v".into();
        assert_ne!(ou_sig_payload("iss", &u, &hop), base);
    }
}
