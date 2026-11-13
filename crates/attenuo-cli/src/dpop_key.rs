//! DPoP keys on disk (SR-24): `attenuo key gen --dpop <path>` and every `--dpop-key`.
//!
//! A key file holds one private JWK: Ed25519 (`{"kty":"OKP","crv":"Ed25519","x":..,"d":..}`)
//! as generated here, or a P-256 key (`"kty":"EC"`) made elsewhere. The Python and TypeScript
//! SDKs read the same format.

use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context, Result};
use attenuo_token::DpopKey;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;
use time::OffsetDateTime;

/// Generate an Ed25519 key and write it to `path` as a private JWK, mode 0600 on Unix. An
/// existing file is never overwritten.
pub(crate) fn generate(path: &Path) -> Result<DpopKey> {
    let key = DpopKey::generate().context("generating a DPoP key")?;
    write_new(path, &key.private_jwk())?;
    Ok(key)
}

/// Write the private JWK `jwk` to a new file at `path`, mode 0600 on Unix. An existing file is
/// never overwritten.
pub(crate) fn write_new(path: &Path, jwk: &Value) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path).with_context(|| {
        format!(
            "creating {} (an existing key file is never overwritten)",
            path.display()
        )
    })?;
    let mut text = serde_json::to_string_pretty(jwk)?;
    text.push('\n');
    file.write_all(text.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Read a private JWK from `path`.
pub(crate) fn load(path: &Path) -> Result<DpopKey> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading DPoP key {}", path.display()))?;
    let jwk: Value = serde_json::from_str(&text)
        .with_context(|| format!("DPoP key {} is not JSON (a private JWK)", path.display()))?;
    DpopKey::from_jwk(&jwk).with_context(|| format!("DPoP key {}", path.display()))
}

pub(crate) fn load_opt(path: Option<&Path>) -> Result<Option<DpopKey>> {
    path.map(load).transpose()
}

/// `cnf.jkt` of a token, read from its payload without verification.
pub(crate) fn token_jkt(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    claims["cnf"]["jkt"].as_str().map(str::to_owned)
}

/// The `DPoP` header and the `subject_token_dpop` sign-off of an exchange of `subject` at
/// `url` for `actor`. `key` binds the new token; `subject_key` is the parent's key when it
/// differs; `sign_off_given` says that a sign-off made elsewhere (`attenuo token sign-off`)
/// goes in the body instead.
///
/// `nonce` is the server's latest `DPoP-Nonce` for the header proof (the sign-off needs none).
///
/// - The header proof covers the subject token (`ath`) when `key` is the one the subject token
///   is bound to.
/// - A bound subject token with another `key` needs a sign-off by its key, naming `key` and
///   `actor` (SR-40): made here from `subject_key`, or given.
pub(crate) fn exchange_proofs(
    url: &str,
    subject: &str,
    actor: &str,
    key: Option<&Path>,
    subject_key: Option<&Path>,
    sign_off_given: bool,
    nonce: Option<&str>,
) -> Result<(Option<String>, Option<String>)> {
    let now = OffsetDateTime::now_utc();
    let key = load_opt(key)?;
    let subject_key = load_opt(subject_key)?;
    let parent_jkt = token_jkt(subject);
    let same = |k: &DpopKey| parent_jkt.as_deref() == Some(k.thumbprint());
    let header = key.as_ref().map(|k| {
        let ath = same(k).then_some(subject);
        k.proof_with_nonce("POST", url, ath, nonce, now)
    });
    let sign_off = match (&parent_jkt, &key, &subject_key) {
        (_, None, Some(_)) => bail!(
            "--subject-dpop-key signs off on binding the new token to another key: pass that \
             key as --dpop-key"
        ),
        (_, Some(k), Some(sk)) => {
            if parent_jkt.is_some() && !same(sk) {
                bail!("--subject-dpop-key is not the key the subject token is bound to");
            }
            Some(sk.sign_off(url, subject, k.thumbprint(), actor, now))
        }
        (Some(_), None, None) => bail!(
            "the subject token is bound to a DPoP key: pass --dpop-key (and \
             --subject-dpop-key or --subject-token-dpop-file when the new token gets another \
             key)"
        ),
        (Some(_), Some(k), None) if !same(k) && !sign_off_given => bail!(
            "--dpop-key is not the key the subject token is bound to: pass the parent's \
             sign-off with --subject-token-dpop-file (made by `attenuo token sign-off`), or the \
             parent's key as --subject-dpop-key"
        ),
        _ => None,
    };
    Ok((header, sign_off))
}

/// `attenuo token sign-off`: the parent holder's consent (`subject_token_dpop`) to an
/// exchange of `subject` at `url` that binds the new token to the key `child_jkt` and gives it
/// to `actor`, made with the parent's key at `key` (SR-40).
pub(crate) fn sign_off(
    url: &str,
    subject: &str,
    key: &Path,
    child_jkt: &str,
    actor: &str,
) -> Result<String> {
    let key = load(key)?;
    if token_jkt(subject).is_some_and(|jkt| jkt != key.thumbprint()) {
        bail!("--dpop-key is not the key the subject token is bound to");
    }
    if !attenuo_token::Confirmation::jkt(child_jkt).is_well_formed() {
        bail!("--child-jkt must be a key thumbprint (43 base64url characters, as `attenuo key gen --dpop` prints)");
    }
    Ok(key.sign_off(url, subject, child_jkt, actor, OffsetDateTime::now_utc()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fake_token(jkt: Option<&str>) -> String {
        let claims = match jkt {
            Some(j) => json!({"cnf": {"jkt": j}}),
            None => json!({}),
        };
        format!(
            "e30.{}.sig",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        )
    }

    #[test]
    fn generated_key_is_private_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dpop.jwk");
        let key = generate(&path).unwrap();
        assert_eq!(load(&path).unwrap().thumbprint(), key.thumbprint());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(generate(&path).is_err());
        assert_eq!(load(&path).unwrap().thumbprint(), key.thumbprint());
    }

    #[test]
    fn exchange_proofs_follow_the_binding_rule() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        let (ka, kb) = (generate(&a).unwrap(), generate(&b).unwrap());
        let url = "http://127.0.0.1:8080/token";
        let bound = fake_token(Some(ka.thumbprint()));
        let unbound = fake_token(None);
        let check = |p: &str, token: Option<&str>| {
            attenuo_token::dpop::verify_proof(
                p,
                &attenuo_token::dpop::ProofCheck {
                    method: "POST",
                    url,
                    access_token: token,
                    now: OffsetDateTime::now_utc(),
                    max_age: time::Duration::seconds(60),
                },
            )
            .unwrap()
        };
        let proofs = |token: &str, key, subject_key, given| {
            exchange_proofs(url, token, "coder", key, subject_key, given, None)
        };
        // Same key: one proof, covering the parent.
        let (h, s) = proofs(&bound, Some(&a), None, false).unwrap();
        check(&h.unwrap(), Some(&bound));
        assert!(s.is_none());
        // New key: the parent's key signs off, naming the new key and the actor (SR-40).
        let (h, s) = proofs(&bound, Some(&b), Some(&a), false).unwrap();
        check(&h.unwrap(), None);
        let s = check(&s.unwrap(), Some(&bound));
        assert_eq!(s.child_jkt.as_deref(), Some(kb.thumbprint()));
        assert_eq!(s.child_actor.as_deref(), Some("coder"));
        // ... or the sign-off was made elsewhere.
        let (h, s) = proofs(&bound, Some(&b), None, true).unwrap();
        assert!(h.is_some() && s.is_none());
        let made = sign_off(url, &bound, &a, kb.thumbprint(), "coder").unwrap();
        assert_eq!(
            check(&made, Some(&bound)).child_jkt.as_deref(),
            Some(kb.thumbprint())
        );
        assert!(sign_off(url, &bound, &b, kb.thumbprint(), "coder").is_err());
        assert!(sign_off(url, &bound, &a, "short", "coder").is_err());
        // Missing or wrong keys fail before any request.
        assert!(proofs(&bound, None, None, false).is_err());
        assert!(proofs(&bound, Some(&b), None, false).is_err());
        assert!(proofs(&bound, Some(&b), Some(&b), false).is_err());
        assert!(proofs(&bound, None, Some(&a), false).is_err());
        // An unbound parent: the key only binds the child.
        let (h, s) = proofs(&unbound, Some(&b), None, false).unwrap();
        assert!(h.is_some() && s.is_none());
        assert_eq!(proofs(&unbound, None, None, false).unwrap(), (None, None));
    }
}
