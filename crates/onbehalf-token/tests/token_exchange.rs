//! Integration tests for the delegation-token layer: issue, exchange, verify, and the ways a
//! token must be rejected.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use onbehalf_core::{
    AgentId, ArgConstraint, AttenuationError, Capability, CapabilitySet, ChainError,
    OriginatingUser,
};
use onbehalf_token::{
    Claims, ExchangeRequest, ExchangeResponse, IssueOptions, IssuedToken, Issuer, IssuerConfig,
    MayAct, TokenError, Verifier, JWT_TOKEN_TYPE_URN, OU_SIG_VERSION, TOKEN_TYPE,
};
use serde_json::json;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

const ISS: &str = "https://onbehalf.example";
const AUD: &str = "mcp-proxy";

fn t0() -> OffsetDateTime {
    datetime!(2026-10-22 21:00 UTC)
}

fn config() -> IssuerConfig {
    IssuerConfig {
        issuer: ISS.into(),
        audience: AUD.into(),
        max_depth: 4,
        default_ttl: Duration::minutes(10),
    }
}

fn issuer() -> Issuer {
    Issuer::generate(config())
}

fn user() -> OriginatingUser {
    OriginatingUser {
        subject: "user:mudit".into(),
        issuer: "https://idp.example".into(),
        authenticated_at: datetime!(2026-10-22 20:00 UTC),
        attributes: BTreeMap::from([("mfa".to_string(), json!(true))]),
    }
}

fn caps(v: impl IntoIterator<Item = Capability>) -> CapabilitySet {
    CapabilitySet::from_iter(v)
}

fn root(issuer: &Issuer) -> IssuedToken {
    issuer
        .issue_root(
            user(),
            AgentId::new("agent:planner"),
            caps([
                Capability::new("github", "read_*"),
                Capability::new("github", "create_issue")
                    .with_constraint("repo", ArgConstraint::Prefix("acme/".into())),
            ]),
            Some(Duration::hours(1)),
            t0(),
        )
        .unwrap()
}

/// Split a compact JWS into its three segments.
fn segments(token: &str) -> (String, String, String) {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    (parts[0].into(), parts[1].into(), parts[2].into())
}

fn decode_payload(token: &str) -> serde_json::Value {
    let (_, payload, _) = segments(token);
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

/// Rebuild a token with `payload` substituted and the original signature kept.
fn with_payload(token: &str, payload: &serde_json::Value) -> String {
    let (h, _, s) = segments(token);
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
    format!("{h}.{p}.{s}")
}

#[test]
fn root_issue_verify_round_trip_and_claims_shape() {
    let issuer = issuer();
    let issued = root(&issuer);
    assert_eq!(issued.expires_at, t0() + Duration::hours(1));
    assert_eq!(issued.chain.depth(), 1);
    assert_eq!(issued.chain.hops[0].lease, issued.lease);

    let verified = issuer
        .verifier()
        .verify(&issued.token, t0() + Duration::minutes(5))
        .unwrap();
    assert_eq!(verified.chain, issued.chain);
    let c: &Claims = &verified.claims;
    assert_eq!(c.iss, ISS);
    assert_eq!(c.aud, AUD);
    assert_eq!(c.sub, "user:mudit");
    assert_eq!(c.typ, TOKEN_TYPE);
    assert_eq!(c.iat, t0().unix_timestamp());
    assert_eq!(c.exp, issued.expires_at.unix_timestamp());
    assert_eq!(c.act.sub, "agent:planner");
    assert!(c.act.act.is_none());
    assert!(!c.jti.is_empty());
    assert!(!c.ou_sig.is_empty());
    assert_eq!(c.ou_sig_v, OU_SIG_VERSION);
    assert_eq!(c.ou_kid, issuer.key_id());

    // header has the expected alg and typ
    let header = jsonwebtoken::decode_header(&issued.token).unwrap();
    assert_eq!(header.alg, Algorithm::EdDSA);
    assert_eq!(header.typ.as_deref(), Some(TOKEN_TYPE));

    // the raw payload has the claim names RFC 8693 consumers expect
    let payload = decode_payload(&issued.token);
    for key in [
        "iss", "aud", "sub", "act", "jti", "iat", "exp", "chain", "typ", "ou_sig", "ou_sig_v",
        "ou_kid",
    ] {
        assert!(payload.get(key).is_some(), "missing claim {key}");
    }
}

#[test]
fn act_nesting_for_three_hops_matches_rfc8693() {
    let issuer = issuer();
    let r = root(&issuer);
    let h1 = issuer
        .exchange(
            &r.token,
            AgentId::new("agent:coder"),
            caps([Capability::new("github", "read_*")]),
            None,
            t0() + Duration::minutes(1),
        )
        .unwrap();
    let h2 = issuer
        .exchange(
            &h1.token,
            AgentId::new("agent:reviewer"),
            caps([Capability::new("github", "read_file")]),
            None,
            t0() + Duration::minutes(2),
        )
        .unwrap();
    let v = issuer
        .verifier()
        .verify(&h2.token, t0() + Duration::minutes(3))
        .unwrap();
    assert_eq!(v.chain.depth(), 3);
    // outermost act = current actor; innermost = root agent
    let act = &v.claims.act;
    assert_eq!(act.sub, "agent:reviewer");
    let parent = act.act.as_ref().unwrap();
    assert_eq!(parent.sub, "agent:coder");
    let grandparent = parent.act.as_ref().unwrap();
    assert_eq!(grandparent.sub, "agent:planner");
    assert!(grandparent.act.is_none());
    assert_eq!(act.depth(), 3);
    assert_eq!(
        decode_payload(&h2.token)["act"],
        json!({"sub": "agent:reviewer", "act": {"sub": "agent:coder", "act": {"sub": "agent:planner"}}})
    );
    // the user block signature travels unchanged
    assert_eq!(
        decode_payload(&h2.token)["ou_sig"],
        decode_payload(&r.token)["ou_sig"]
    );
}

#[test]
fn exchange_cannot_widen_capabilities() {
    let issuer = issuer();
    let r = root(&issuer);
    // new tool
    let err = issuer
        .exchange(
            &r.token,
            AgentId::new("agent:coder"),
            caps([Capability::new("github", "delete_repo")]),
            None,
            t0(),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        TokenError::Chain(ChainError::AttenuationViolated {
            index: 1,
            parent: 0,
            source: AttenuationError::NotCovered { .. }
        })
    ));
    // dropping an argument constraint widens too
    let err = issuer
        .exchange(
            &r.token,
            AgentId::new("agent:coder"),
            caps([Capability::new("github", "create_issue")]),
            None,
            t0(),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        TokenError::Chain(ChainError::AttenuationViolated { .. })
    ));
    // empty request is refused as well
    let err = issuer
        .exchange(&r.token, AgentId::new("agent:coder"), caps([]), None, t0())
        .unwrap_err();
    assert!(matches!(
        err,
        TokenError::Chain(ChainError::AttenuationViolated {
            source: AttenuationError::Empty,
            ..
        })
    ));
}

#[test]
fn exchange_ttl_is_clamped_to_parent_expiry() {
    let issuer = issuer();
    let r = root(&issuer);
    let child = issuer
        .exchange(
            &r.token,
            AgentId::new("agent:coder"),
            caps([Capability::new("github", "read_file")]),
            Some(Duration::hours(24)),
            t0() + Duration::minutes(30),
        )
        .unwrap();
    assert_eq!(child.expires_at, r.expires_at);
    assert_eq!(child.chain.hops[1].expires_at, r.expires_at);
    let v = issuer
        .verifier()
        .verify(&child.token, t0() + Duration::minutes(31))
        .unwrap();
    assert_eq!(v.claims.exp, r.expires_at.unix_timestamp());

    // a shorter ttl is honoured
    let short = issuer
        .exchange(
            &r.token,
            AgentId::new("agent:coder"),
            caps([Capability::new("github", "read_file")]),
            Some(Duration::minutes(5)),
            t0(),
        )
        .unwrap();
    assert_eq!(short.expires_at, t0() + Duration::minutes(5));
}

#[test]
fn expired_token_is_rejected() {
    let issuer = issuer();
    let r = root(&issuer);
    let v = issuer.verifier();
    assert!(v.verify(&r.token, t0() + Duration::minutes(59)).is_ok());
    assert!(matches!(
        v.verify(&r.token, t0() + Duration::hours(1)),
        Err(TokenError::Expired)
    ));
    assert!(matches!(
        v.verify(&r.token, t0() + Duration::days(1)),
        Err(TokenError::Expired)
    ));
    // an expired parent cannot be exchanged
    assert!(matches!(
        issuer.exchange(
            &r.token,
            AgentId::new("agent:coder"),
            caps([Capability::new("github", "read_file")]),
            None,
            t0() + Duration::hours(2),
        ),
        Err(TokenError::Expired)
    ));
}

#[test]
fn wrong_audience_and_issuer_are_rejected() {
    let issuer = issuer();
    let r = root(&issuer);
    let pem = issuer.public_key_pem();
    let wrong_aud = Verifier::from_public_pem(ISS, "other-audience", 4, &pem).unwrap();
    assert!(matches!(
        wrong_aud.verify(&r.token, t0()),
        Err(TokenError::WrongAudience)
    ));
    let wrong_iss = Verifier::from_public_pem("https://evil.example", AUD, 4, &pem).unwrap();
    assert!(matches!(
        wrong_iss.verify(&r.token, t0()),
        Err(TokenError::WrongIssuer)
    ));
    let right = Verifier::from_public_pem(ISS, AUD, 4, &pem).unwrap();
    assert!(right.verify(&r.token, t0()).is_ok());
}

#[test]
fn flipped_payload_byte_is_rejected() {
    let issuer = issuer();
    let r = root(&issuer);
    let (h, p, s) = segments(&r.token);
    let mut bytes = p.into_bytes();
    let i = bytes.len() / 2;
    bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
    let tampered = format!("{h}.{}.{s}", String::from_utf8(bytes).unwrap());
    assert!(matches!(
        issuer.verifier().verify(&tampered, t0()),
        Err(TokenError::InvalidSignature | TokenError::Malformed(_))
    ));
}

#[test]
fn token_signed_by_another_key_is_rejected() {
    let a = issuer();
    let b = issuer();
    let from_b = root(&b);
    // The token names b's kid, which a does not trust.
    assert!(matches!(
        a.verifier().verify(&from_b.token, t0()),
        Err(TokenError::UnknownKeyId(_))
    ));
    assert!(matches!(
        a.exchange(
            &from_b.token,
            AgentId::new("agent:coder"),
            caps([Capability::new("github", "read_file")]),
            None,
            t0(),
        ),
        Err(TokenError::UnknownKeyId(_))
    ));
    // Without a kid the signature itself is what fails.
    let payload = decode_payload(&from_b.token);
    let resigned = resign_with_issuer_key(&b, &payload);
    assert!(matches!(
        a.verifier().verify(&resigned, t0()),
        Err(TokenError::InvalidSignature)
    ));
}

fn header_of(token: &str) -> serde_json::Value {
    let h = token.split('.').next().unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).unwrap()).unwrap()
}

#[test]
fn tokens_carry_a_kid_derived_from_the_public_key() {
    let a = issuer();
    let t = root(&a);
    let kid = header_of(&t.token)["kid"].as_str().unwrap().to_string();
    assert_eq!(kid, a.key_id());
    assert_eq!(kid.len(), 22);
    assert_eq!(a.verifier().key_ids(), vec![kid]);
    assert_ne!(a.key_id(), issuer().key_id());
}

/// `new` replaces `old` as the signing key; `old` stays trusted for verification only.
fn rotated(old: &Issuer) -> Issuer {
    let mut new = issuer();
    new.trust_previous_key(&old.public_key_pem()).unwrap();
    new
}

#[test]
fn token_from_the_retired_key_still_verifies_during_overlap() {
    let old = issuer();
    let from_old = root(&old);
    let new = rotated(&old);
    let v = new.verifier();
    assert_eq!(v.key_ids().len(), 2);
    assert!(v.verify(&from_old.token, t0()).is_ok());
    // New tokens use the new kid.
    let from_new = root(&new);
    assert_eq!(header_of(&from_new.token)["kid"], new.key_id());
    assert!(v.verify(&from_new.token, t0()).is_ok());
    // The old issuer does not trust the new key (rotation is one-way).
    assert!(old.verifier().verify(&from_new.token, t0()).is_err());
}

#[test]
fn exchange_of_an_old_key_parent_is_signed_by_the_new_key_and_verifies() {
    let old = issuer();
    let from_old = root(&old);
    let new = rotated(&old);
    let child = new
        .exchange(
            &from_old.token,
            AgentId::new("agent:coder"),
            caps([Capability::new("github", "read_file")]),
            None,
            t0(),
        )
        .unwrap();
    assert_eq!(header_of(&child.token)["kid"], new.key_id());
    // ou_sig was made by the old key; the verifier accepts it because that key is trusted.
    let verified = new.verifier().verify(&child.token, t0()).unwrap();
    assert_eq!(verified.claims.ou_kid, old.key_id());
    assert_eq!(verified.claims.ou_sig_v, OU_SIG_VERSION);
    // A grandchild minted by the new key still carries the old-key v2 signature.
    let grandchild = new
        .exchange(
            &child.token,
            AgentId::new("agent:reviewer"),
            caps([Capability::new("github", "read_file")]),
            None,
            t0(),
        )
        .unwrap();
    assert!(new.verifier().verify(&grandchild.token, t0()).is_ok());
    // A verifier that dropped the old key rejects the child's user block.
    let only_new = Verifier::from_public_pem(ISS, AUD, 4, &new.public_key_pem()).unwrap();
    assert!(matches!(
        only_new.verify(&child.token, t0()),
        Err(TokenError::InvalidSignature)
    ));
}

#[test]
fn retired_key_is_dropped_when_not_listed_and_kid_mismatch_is_rejected() {
    let old = issuer();
    let from_old = root(&old);
    let new = issuer();
    assert!(matches!(
        new.verifier().verify(&from_old.token, t0()),
        Err(TokenError::UnknownKeyId(k)) if k == old.key_id()
    ));
    // A forged kid pointing at a trusted key does not help: the signature must match it.
    let new_with_old = rotated(&old);
    let mut payload = decode_payload(&from_old.token);
    payload["sub"] = json!("user:mudit");
    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some(TOKEN_TYPE.into());
    header.kid = Some(old.key_id());
    let key = EncodingKey::from_ed_pem(new.private_key_pem().as_bytes()).unwrap();
    let forged = jsonwebtoken::encode(&header, &payload, &key).unwrap();
    assert!(matches!(
        new_with_old.verifier().verify(&forged, t0()),
        Err(TokenError::InvalidSignature)
    ));
}

#[test]
fn trust_previous_key_accepts_private_or_public_pem_and_ignores_the_current_key() {
    let old = issuer();
    let mut new = issuer();
    new.trust_previous_key(&old.private_key_pem()).unwrap();
    new.trust_previous_key(&old.public_key_pem()).unwrap();
    new.trust_previous_key(&new.public_key_pem()).unwrap();
    assert_eq!(new.trusted_public_keys().len(), 2);
    assert_eq!(new.trusted_public_keys()[0].0, new.key_id());
    assert!(new.trust_previous_key("garbage").is_err());
    let pem_only = Verifier::from_public_pem(ISS, AUD, 4, &new.public_key_pem())
        .unwrap()
        .with_public_pem(&old.public_key_pem())
        .unwrap();
    assert_eq!(pem_only.key_ids().len(), 2);
}

#[test]
fn edited_chain_without_key_is_rejected() {
    let issuer = issuer();
    let r = root(&issuer);
    let mut payload = decode_payload(&r.token);
    payload["chain"]["hops"][0]["capabilities"]
        .as_array_mut()
        .unwrap()
        .push(json!({"server": "github", "tool": "delete_repo"}));
    let tampered = with_payload(&r.token, &payload);
    assert!(matches!(
        issuer.verifier().verify(&tampered, t0()),
        Err(TokenError::InvalidSignature)
    ));
    // stretching exp without the key fails the same way
    let mut payload = decode_payload(&r.token);
    payload["exp"] = json!((t0() + Duration::days(30)).unix_timestamp());
    let tampered = with_payload(&r.token, &payload);
    assert!(matches!(
        issuer
            .verifier()
            .verify(&tampered, t0() + Duration::hours(2)),
        Err(TokenError::InvalidSignature)
    ));
}

#[test]
fn malformed_tokens_are_rejected() {
    let issuer = issuer();
    let v = issuer.verifier();
    assert!(matches!(v.verify("", t0()), Err(TokenError::Malformed(_))));
    assert!(matches!(
        v.verify("not.a.jwt", t0()),
        Err(TokenError::Malformed(_))
    ));
    let r = root(&issuer);
    let (h, p, _) = segments(&r.token);
    assert!(matches!(
        v.verify(&format!("{h}.{p}"), t0()),
        Err(TokenError::Malformed(_))
    ));
}

#[test]
fn max_depth_exceeded_is_rejected() {
    let issuer = issuer(); // max_depth = 4
    let mut tok = root(&issuer);
    for i in 1..4 {
        tok = issuer
            .exchange(
                &tok.token,
                AgentId::new(format!("agent:{i}")),
                caps([Capability::new("github", "read_*")]),
                None,
                t0(),
            )
            .unwrap();
    }
    assert_eq!(tok.chain.depth(), 4);
    assert!(issuer.verifier().verify(&tok.token, t0()).is_ok());
    assert!(matches!(
        issuer.exchange(
            &tok.token,
            AgentId::new("agent:overflow"),
            caps([Capability::new("github", "read_*")]),
            None,
            t0(),
        ),
        Err(TokenError::Chain(ChainError::TooDeep { depth: 5, max: 4 }))
    ));
    // a verifier configured with a smaller bound rejects a deeper (but validly signed) chain
    let strict = Verifier::from_public_pem(ISS, AUD, 2, &issuer.public_key_pem()).unwrap();
    assert!(matches!(
        strict.verify(&tok.token, t0()),
        Err(TokenError::Chain(ChainError::TooDeep { depth: 4, max: 2 }))
    ));
}

/// Re-sign `payload` with the issuer's own key: simulates a hop that holds a legitimate signing
/// key (multi-issuer setup) and tries to change the originating-user block.
fn resign_with_issuer_key(issuer: &Issuer, payload: &serde_json::Value) -> String {
    let key = EncodingKey::from_ed_pem(issuer.private_key_pem().as_bytes()).unwrap();
    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some(TOKEN_TYPE.into());
    jsonwebtoken::encode(&header, payload, &key).unwrap()
}

#[test]
fn originating_user_tamper_is_caught_by_ou_sig() {
    let issuer = issuer();
    let r = root(&issuer);

    // sanity: re-signing the untouched payload still verifies
    let payload = decode_payload(&r.token);
    let resigned = resign_with_issuer_key(&issuer, &payload);
    assert!(issuer.verifier().verify(&resigned, t0()).is_ok());

    // adding an attribute to the user block (e.g. escalating a role) is caught
    let mut payload = decode_payload(&r.token);
    payload["chain"]["originating_user"]["attributes"]["role"] = json!("admin");
    let tampered = resign_with_issuer_key(&issuer, &payload);
    assert!(matches!(
        issuer.verifier().verify(&tampered, t0()),
        Err(TokenError::InvalidSignature)
    ));

    // swapping the subject (keeping `sub` consistent) is caught as well
    let mut payload = decode_payload(&r.token);
    payload["chain"]["originating_user"]["subject"] = json!("user:ceo");
    payload["sub"] = json!("user:ceo");
    let tampered = resign_with_issuer_key(&issuer, &payload);
    assert!(matches!(
        issuer.verifier().verify(&tampered, t0()),
        Err(TokenError::InvalidSignature)
    ));

    // an ou_sig signed over a different user block does not transfer. (`ou_sig` attests the
    // block's content: a signature over a byte-identical block would verify, which is correct,
    // since the issuer did attest exactly that block.)
    let other_user = OriginatingUser {
        subject: "user:ceo".into(),
        authenticated_at: datetime!(2026-10-22 19:00 UTC),
        ..user()
    };
    let other = issuer
        .issue_root(
            other_user,
            AgentId::new("agent:planner"),
            caps([Capability::new("github", "read_*")]),
            None,
            t0(),
        )
        .unwrap();
    let mut payload = decode_payload(&r.token);
    payload["chain"]["originating_user"]["subject"] = json!("user:ceo");
    payload["sub"] = json!("user:ceo");
    payload["ou_sig"] = decode_payload(&other.token)["ou_sig"].clone();
    let tampered = resign_with_issuer_key(&issuer, &payload);
    assert!(matches!(
        issuer.verifier().verify(&tampered, t0()),
        Err(TokenError::InvalidSignature)
    ));
}

#[test]
fn inconsistent_sub_or_act_is_rejected() {
    let issuer = issuer();
    let r = root(&issuer);
    let mut payload = decode_payload(&r.token);
    payload["act"]["sub"] = json!("agent:impostor");
    let tampered = resign_with_issuer_key(&issuer, &payload);
    assert!(matches!(
        issuer.verifier().verify(&tampered, t0()),
        Err(TokenError::Malformed(_))
    ));
    let mut payload = decode_payload(&r.token);
    payload["typ"] = json!("JWT");
    let tampered = resign_with_issuer_key(&issuer, &payload);
    assert!(matches!(
        issuer.verifier().verify(&tampered, t0()),
        Err(TokenError::WrongType)
    ));
}

#[test]
fn wrong_header_typ_is_rejected() {
    let issuer = issuer();
    let r = root(&issuer);
    let payload = decode_payload(&r.token);
    let key = EncodingKey::from_ed_pem(issuer.private_key_pem().as_bytes()).unwrap();
    let plain = jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), &payload, &key).unwrap();
    assert!(matches!(
        issuer.verifier().verify(&plain, t0()),
        Err(TokenError::WrongType)
    ));
}

#[test]
fn issuer_from_pem_round_trip() {
    let a = issuer();
    let b = Issuer::from_pem(config(), &a.private_key_pem()).unwrap();
    assert_eq!(a.public_key_pem(), b.public_key_pem());
    let from_a = root(&a);
    assert!(b.verifier().verify(&from_a.token, t0()).is_ok());
    let child = b
        .exchange(
            &from_a.token,
            AgentId::new("agent:coder"),
            caps([Capability::new("github", "read_file")]),
            None,
            t0(),
        )
        .unwrap();
    assert!(a.verifier().verify(&child.token, t0()).is_ok());
    assert!(matches!(
        Issuer::from_pem(config(), "garbage"),
        Err(TokenError::Key(_))
    ));
}

#[test]
fn exchange_request_response_shapes() {
    let issuer = issuer();
    let r = root(&issuer);
    let req_json = json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": r.token,
        "subject_token_type": JWT_TOKEN_TYPE_URN,
        "actor": "agent:coder",
        "authorization_details": [{
            "type": "onbehalf_capabilities",
            "capabilities": [{"server": "github", "tool": "read_file"}]
        }],
        "requested_ttl_seconds": 120
    });
    let req: ExchangeRequest = serde_json::from_value(req_json).unwrap();
    assert_eq!(req.actor, AgentId::new("agent:coder"));
    let now = t0() + Duration::minutes(1);
    let resp: ExchangeResponse = req.execute(&issuer, now).unwrap();
    assert_eq!(resp.token_type, "Bearer");
    assert_eq!(resp.issued_token_type, JWT_TOKEN_TYPE_URN);
    assert_eq!(resp.expires_in, 120);
    let v = issuer.verifier().verify(&resp.access_token, now).unwrap();
    assert_eq!(v.chain.hops[1].lease, resp.lease);
    assert_eq!(v.claims.act.sub, "agent:coder");
    let out = serde_json::to_value(&resp).unwrap();
    assert_eq!(out["token_type"], json!("Bearer"));
    assert_eq!(out["expires_in"], json!(120));

    // widening through the HTTP shape fails the same way
    let wide = ExchangeRequest {
        subject_token: r.token.clone(),
        actor: AgentId::new("agent:coder"),
        requested: caps([Capability::new("*", "*")]),
        ttl_seconds: None,
        may_act: None,
    };
    assert!(matches!(
        wide.execute(&issuer, now),
        Err(TokenError::Chain(ChainError::AttenuationViolated { .. }))
    ));
}

/// SR-06: `requested_ttl_seconds` = u64::MAX used to panic inside the exchange (`now + ttl`
/// overflow). It must be clamped to the parent's expiry like any other long TTL.
#[test]
fn exchange_with_maximal_requested_ttl_is_clamped_not_a_panic() {
    let issuer = issuer();
    let parent = root(&issuer);
    let req = ExchangeRequest {
        subject_token: parent.token.clone(),
        actor: AgentId::new("agent:coder"),
        requested: caps([Capability::new("github", "read_file")]),
        ttl_seconds: Some(u64::MAX),
        may_act: None,
    };
    let resp = req.execute(&issuer, t0()).unwrap();
    let child = issuer.verifier().verify(&resp.access_token, t0()).unwrap();
    assert_eq!(child.chain.hops[1].expires_at, parent.expires_at);
    assert_eq!(resp.expires_in, 3600);
}

/// RFC 8693 §4.4: `may_act` on the parent names who may exchange it.
#[test]
fn may_act_on_the_parent_limits_the_next_actor() {
    let issuer = issuer();
    let read = || caps([Capability::new("github", "read_file")]);
    let r = issuer
        .issue_root_with(
            user(),
            AgentId::new("agent:planner"),
            caps([Capability::new("github", "read_*")]),
            None,
            t0(),
            &IssueOptions {
                may_act: Some(MayAct::new(["agent:coder"])),
                not_after: None,
            },
        )
        .unwrap();
    let claims = issuer.verifier().verify(&r.token, t0()).unwrap().claims;
    assert_eq!(claims.may_act, Some(MayAct::new(["agent:coder"])));

    // A listed actor may exchange; the child carries no may_act unless asked for.
    let child = issuer
        .exchange(&r.token, AgentId::new("agent:coder"), read(), None, t0())
        .unwrap();
    let c = issuer.verifier().verify(&child.token, t0()).unwrap().claims;
    assert_eq!(c.may_act, None);
    // An unlisted one is refused.
    let err = issuer
        .exchange(&r.token, AgentId::new("agent:sneaky"), read(), None, t0())
        .unwrap_err();
    assert!(
        matches!(&err, TokenError::ActorNotPermitted(a) if a == "agent:sneaky"),
        "{err}"
    );
    // An empty list means nobody.
    let closed = issuer
        .exchange_with(
            &child.token,
            AgentId::new("agent:reviewer"),
            read(),
            None,
            t0(),
            &IssueOptions {
                may_act: Some(MayAct::new(Vec::<String>::new())),
                not_after: None,
            },
        )
        .unwrap();
    assert!(matches!(
        issuer.exchange(&closed.token, AgentId::new("agent:x"), read(), None, t0()),
        Err(TokenError::ActorNotPermitted(_))
    ));
    // Without may_act (the default), any actor may exchange, as before.
    let open = root(&issuer);
    assert_eq!(
        issuer
            .verifier()
            .verify(&open.token, t0())
            .unwrap()
            .claims
            .may_act,
        None
    );
    issuer
        .exchange(
            &open.token,
            AgentId::new("agent:anyone"),
            read(),
            None,
            t0(),
        )
        .unwrap();
}

/// `not_after` caps the child's expiry below the parent's and the requested TTL.
#[test]
fn not_after_caps_the_child_expiry() {
    let issuer = issuer();
    let r = root(&issuer);
    let limit = t0() + Duration::minutes(2);
    let child = issuer
        .exchange_with(
            &r.token,
            AgentId::new("agent:coder"),
            caps([Capability::new("github", "read_file")]),
            Some(Duration::minutes(30)),
            t0(),
            &IssueOptions {
                may_act: None,
                not_after: Some(limit),
            },
        )
        .unwrap();
    assert_eq!(child.expires_at, limit);
    let err = issuer
        .exchange_with(
            &r.token,
            AgentId::new("agent:coder"),
            caps([Capability::new("github", "read_file")]),
            None,
            t0(),
            &IssueOptions {
                may_act: None,
                not_after: Some(t0()),
            },
        )
        .unwrap_err();
    assert!(matches!(err, TokenError::NoLifetimeLeft(_)), "{err}");
}

/// SR-14: `ou_sig` v2 binds the user to the issuer and to the root hop, so a signature lifted
/// from one chain does not start another.
#[test]
fn ou_sig_cannot_be_lifted_into_a_chain_with_another_root_hop() {
    let issuer = issuer();
    // The same user, two chains: a narrow one the attacker saw, and one they want.
    let narrow = issuer
        .issue_root(
            user(),
            AgentId::new("agent:planner"),
            caps([Capability::new("github", "read_file")]),
            None,
            t0(),
        )
        .unwrap();
    let wide = issuer
        .issue_root(
            OriginatingUser {
                subject: "user:someone-else".into(),
                ..user()
            },
            AgentId::new("agent:evil"),
            caps([Capability::new("github", "*")]),
            None,
            t0(),
        )
        .unwrap();
    // Graft the user block and its ou_sig from `narrow` onto `wide`'s root hop, re-signed by a
    // trusted key (the multi-issuer / rotation threat).
    let narrow_p = decode_payload(&narrow.token);
    let mut payload = decode_payload(&wide.token);
    payload["chain"]["originating_user"] = narrow_p["chain"]["originating_user"].clone();
    payload["sub"] = narrow_p["sub"].clone();
    for k in ["ou_sig", "ou_sig_v", "ou_kid"] {
        payload[k] = narrow_p[k].clone();
    }
    let lifted = resign_with_issuer_key(&issuer, &payload);
    assert!(matches!(
        issuer.verifier().verify(&lifted, t0()),
        Err(TokenError::InvalidSignature)
    ));

    // Widening the root hop of a real chain in place fails too, although the chain itself
    // stays valid (only hop 0 grows).
    let mut payload = decode_payload(&narrow.token);
    payload["chain"]["hops"][0]["capabilities"] = json!([{"server": "github", "tool": "*"}]);
    let widened = resign_with_issuer_key(&issuer, &payload);
    assert!(matches!(
        issuer.verifier().verify(&widened, t0()),
        Err(TokenError::InvalidSignature)
    ));
    // So does swapping the root agent or the root lease.
    for (field, value) in [
        ("agent", json!("agent:evil")),
        ("lease", json!("other-lease")),
    ] {
        let mut payload = decode_payload(&narrow.token);
        payload["chain"]["hops"][0][field] = value;
        payload["act"] = json!({"sub": payload["chain"]["hops"][0]["agent"]});
        let edited = resign_with_issuer_key(&issuer, &payload);
        assert!(
            matches!(
                issuer.verifier().verify(&edited, t0()),
                Err(TokenError::InvalidSignature)
            ),
            "{field}"
        );
    }
}

#[test]
fn ou_sig_is_bound_to_the_issuer() {
    // Two issuers sharing one key (a multi-issuer deployment that reuses keys, or an operator
    // mistake): a chain started under one `iss` cannot be relabelled to the other.
    let a = issuer();
    let b = Issuer::from_pem(
        IssuerConfig {
            issuer: "https://other-onbehalf.example".into(),
            ..config()
        },
        &a.private_key_pem(),
    )
    .unwrap();
    let from_b = root(&b);
    assert!(b.verifier().verify(&from_b.token, t0()).is_ok());
    let mut payload = decode_payload(&from_b.token);
    payload["iss"] = json!(ISS);
    let relabelled = resign_with_issuer_key(&a, &payload);
    assert!(matches!(
        a.verifier().verify(&relabelled, t0()),
        Err(TokenError::InvalidSignature)
    ));
}

#[test]
fn ou_sig_v1_and_unknown_versions_or_kids_are_refused() {
    let issuer = issuer();
    let r = root(&issuer);
    // A v1 token has no `ou_sig_v` claim.
    let mut payload = decode_payload(&r.token);
    payload.as_object_mut().unwrap().remove("ou_sig_v");
    let v1 = resign_with_issuer_key(&issuer, &payload);
    let err = issuer.verifier().verify(&v1, t0()).unwrap_err();
    assert!(matches!(err, TokenError::UnsupportedOuSig(1)), "{err:?}");
    assert!(err.to_string().contains("re-issue"), "{err}");

    let mut payload = decode_payload(&r.token);
    payload["ou_sig_v"] = json!(3);
    let v3 = resign_with_issuer_key(&issuer, &payload);
    assert!(matches!(
        issuer.verifier().verify(&v3, t0()),
        Err(TokenError::UnsupportedOuSig(3))
    ));

    // `ou_kid` must name a trusted key, and that key must have made the signature.
    let other = Issuer::generate(config());
    let mut trusting_both = Issuer::generate(config());
    trusting_both
        .trust_previous_key(&other.public_key_pem())
        .unwrap();
    trusting_both
        .trust_previous_key(&issuer.public_key_pem())
        .unwrap();
    assert!(trusting_both.verifier().verify(&r.token, t0()).is_ok());
    for kid in [json!("nope"), json!(other.key_id()), json!("")] {
        let mut payload = decode_payload(&r.token);
        payload["ou_kid"] = kid.clone();
        let tok = resign_with_issuer_key(&issuer, &payload);
        assert!(
            matches!(
                trusting_both.verifier().verify(&tok, t0()),
                Err(TokenError::InvalidSignature)
            ),
            "{kid}"
        );
    }
}

#[test]
fn ou_sig_stops_verifying_once_its_key_is_dropped() {
    let old = issuer();
    let from_old = root(&old);
    let new = rotated(&old);
    let child = new
        .exchange(
            &from_old.token,
            AgentId::new("agent:coder"),
            caps([Capability::new("github", "read_file")]),
            None,
            t0(),
        )
        .unwrap();
    // While listed: verifies. Once dropped: the user signature no longer does.
    assert!(new.verifier().verify(&child.token, t0()).is_ok());
    let dropped = Issuer::from_pem(config(), &new.private_key_pem()).unwrap();
    assert!(matches!(
        dropped.verifier().verify(&child.token, t0()),
        Err(TokenError::InvalidSignature)
    ));
}
