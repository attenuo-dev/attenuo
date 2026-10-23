//! DPoP keys on disk (SR-24): `onbehalf key gen --dpop <path>` and every `--dpop-key`.
//!
//! A key file holds one private JWK: Ed25519 (`{"kty":"OKP","crv":"Ed25519","x":..,"d":..}`)
//! as generated here, or a P-256 key (`"kty":"EC"`) made elsewhere. The Python and TypeScript
//! SDKs read the same format.

use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use onbehalf_token::DpopKey;
use serde_json::Value;
use time::OffsetDateTime;

/// Generate an Ed25519 key and write it to `path` as a private JWK, mode 0600 on Unix. An
/// existing file is never overwritten.
pub fn generate(path: &Path) -> Result<DpopKey> {
    let key = DpopKey::generate().context("generating a DPoP key")?;
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
    let mut text = serde_json::to_string_pretty(&key.private_jwk())?;
    text.push('\n');
    file.write_all(text.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(key)
}

/// Read a private JWK from `path`.
pub fn load(path: &Path) -> Result<DpopKey> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading DPoP key {}", path.display()))?;
    let jwk: Value = serde_json::from_str(&text)
        .with_context(|| format!("DPoP key {} is not JSON (a private JWK)", path.display()))?;
    DpopKey::from_jwk(&jwk).with_context(|| format!("DPoP key {}", path.display()))
}

pub fn load_opt(path: Option<&Path>) -> Result<Option<DpopKey>> {
    path.map(load).transpose()
}

/// `cnf.jkt` of a token, read from its payload without verification.
pub fn token_jkt(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    claims["cnf"]["jkt"].as_str().map(str::to_owned)
}

/// The `DPoP` header and the `subject_token_dpop` sign-off of an exchange of `subject` at
/// `url`. `key` binds the new token; `subject_key` is the parent's key when it differs.
///
/// - The header proof covers the subject token (`ath`) when `key` is the one the subject token
///   is bound to.
/// - A bound subject token with another `key` needs `subject_key`, which must be its key.
pub fn exchange_proofs(
    url: &str,
    subject: &str,
    key: Option<&Path>,
    subject_key: Option<&Path>,
) -> Result<(Option<String>, Option<String>)> {
    let now = OffsetDateTime::now_utc();
    let key = load_opt(key)?;
    let subject_key = load_opt(subject_key)?;
    let parent_jkt = token_jkt(subject);
    let same = |k: &DpopKey| parent_jkt.as_deref() == Some(k.thumbprint());
    let header = key.as_ref().map(|k| {
        let ath = same(k).then_some(subject);
        k.proof("POST", url, ath, now)
    });
    let sign_off = match (&parent_jkt, &key, &subject_key) {
        (_, _, Some(sk)) => {
            if parent_jkt.is_some() && !same(sk) {
                bail!("--subject-dpop-key is not the key the subject token is bound to");
            }
            Some(sk.proof("POST", url, Some(subject), now))
        }
        (Some(_), None, None) => bail!(
            "the subject token is bound to a DPoP key: pass --dpop-key (and \
             --subject-dpop-key when the new token gets another key)"
        ),
        (Some(_), Some(k), None) if !same(k) => bail!(
            "--dpop-key is not the key the subject token is bound to: pass the parent's key as \
             --subject-dpop-key"
        ),
        _ => None,
    };
    Ok((header, sign_off))
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
        let (ka, _kb) = (generate(&a).unwrap(), generate(&b).unwrap());
        let url = "http://127.0.0.1:8080/token";
        let bound = fake_token(Some(ka.thumbprint()));
        let unbound = fake_token(None);
        let check = |p: &str, token: Option<&str>| {
            onbehalf_token::dpop::verify_proof(
                p,
                &onbehalf_token::dpop::ProofCheck {
                    method: "POST",
                    url,
                    access_token: token,
                    now: OffsetDateTime::now_utc(),
                    max_age: time::Duration::seconds(60),
                },
            )
            .unwrap()
        };
        // Same key: one proof, covering the parent.
        let (h, s) = exchange_proofs(url, &bound, Some(&a), None).unwrap();
        check(&h.unwrap(), Some(&bound));
        assert!(s.is_none());
        // New key: the parent's key signs off.
        let (h, s) = exchange_proofs(url, &bound, Some(&b), Some(&a)).unwrap();
        check(&h.unwrap(), None);
        check(&s.unwrap(), Some(&bound));
        // Missing or wrong keys fail before any request.
        assert!(exchange_proofs(url, &bound, None, None).is_err());
        assert!(exchange_proofs(url, &bound, Some(&b), None).is_err());
        assert!(exchange_proofs(url, &bound, Some(&b), Some(&b)).is_err());
        // An unbound parent: the key only binds the child.
        let (h, s) = exchange_proofs(url, &unbound, Some(&b), None).unwrap();
        assert!(h.is_some() && s.is_none());
        assert_eq!(
            exchange_proofs(url, &unbound, None, None).unwrap(),
            (None, None)
        );
    }
}
