//! The issuer's own keys: the signing key and the verifying set, held as one snapshot
//! ([`SharedKeys`]) that `POST /admin/keys/reload` swaps in whole, the JWK Set of the public
//! keys (RFC 7517, OKP keys per RFC 8037) served at `GET /.well-known/jwks.json`, and the strict
//! reading of key files a reload does ([`read_key_files`]). The cache of identity-provider keys
//! is a different module, `idp::jwks`.
//!
//! # What follows a key reload
//!
//! Everything that signs or verifies with the issuer key reads it from the snapshot in force:
//! token minting and exchange, token verification (with the proxy's verified-token cache, whose
//! entries are tied to the snapshot that verified them), approval tokens, the JWKS, the keys
//! `GET /admin/audit/verify` checks with, and the signer of audit checkpoints and prune anchors.
//! A request takes one snapshot and uses it throughout: it signs and re-reads a token with the
//! same keys.
//!
//! Two uses of the startup private key do not follow, until a restart: the key of the DPoP
//! nonces (`[token] dpop_nonce`) and of the subject digests (`[telemetry]`,
//! `[logging] redact_subjects`). Neither is published or checked by anyone else; re-keying
//! them on a reload would refuse every nonce handed out before it and break the join of logs
//! and traces by digest.

use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use attenuo_audit::CheckpointKeys;
use attenuo_token::{Issuer, IssuerConfig, Verifier};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Value};

/// The issuer's keys in force, as one value: requests take it whole, so a token is never
/// signed with one key and checked or published with another set.
pub struct IssuerKeys {
    /// Mints and exchanges tokens with the signing key.
    pub issuer: Issuer,
    /// Verifies delegation and approval tokens against the signing key and the retired ones.
    pub verifier: Verifier,
    /// The `/.well-known/jwks.json` body: the signing key first, then the retired ones.
    pub jwks: Value,
    /// The same keys, by `kid`, for checking audit checkpoints and anchors.
    pub checkpoint_keys: CheckpointKeys,
    /// Counts the swaps: what the proxy's verified-token cache ties its entries to.
    generation: u64,
    /// The key files these keys were read from, as configured.
    paths: KeyPaths,
}

/// The key files of an [`IssuerKeys`], as the configuration named them (after environment
/// overrides): what an agents reload compares the file with, to tell that the keys there are
/// not the keys in force.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyPaths {
    /// `[issuer] private_key_pem_path` (none for an ephemeral key).
    pub signing: Option<PathBuf>,
    /// `[issuer] previous_key_paths`.
    pub previous: Vec<PathBuf>,
}

impl KeyPaths {
    /// The key files `config` names.
    pub fn of(config: &crate::config::IssuerSection) -> Self {
        Self {
            signing: config.private_key_pem_path.clone(),
            previous: config.previous_key_paths.clone(),
        }
    }
}

impl std::fmt::Debug for IssuerKeys {
    /// The `kid`s only.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuerKeys")
            .field("signing_kid", &self.issuer.key_id())
            .field("verifying_kids", &self.kids())
            .finish_non_exhaustive()
    }
}

impl IssuerKeys {
    /// The verifier, JWKS and checkpoint keys of `issuer`.
    ///
    /// # Errors
    ///
    /// When the JWKS cannot be built from the issuer's keys, which its types do not allow in
    /// practice.
    pub fn new(issuer: Issuer) -> anyhow::Result<Self> {
        let verifier = issuer.verifier();
        let jwks = jwks_from_keys(&issuer.trusted_public_keys())?;
        let checkpoint_keys = CheckpointKeys::from_jwks(&jwks)?;
        Ok(Self {
            issuer,
            verifier,
            jwks,
            checkpoint_keys,
            generation: 0,
            paths: KeyPaths::default(),
        })
    }

    /// The same keys, read from `paths`.
    #[must_use]
    pub fn with_paths(mut self, paths: KeyPaths) -> Self {
        self.paths = paths;
        self
    }

    /// The key files these keys were read from (empty unless set by
    /// [`with_paths`](Self::with_paths)).
    pub fn paths(&self) -> &KeyPaths {
        &self.paths
    }

    /// The `kid` of every key that verifies: the signing key first, then the retired ones.
    pub fn kids(&self) -> Vec<String> {
        self.issuer
            .trusted_public_keys()
            .into_iter()
            .map(|(kid, _)| kid)
            .collect()
    }

    /// How many swaps came before this snapshot (0 at startup).
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// The [`IssuerKeys`] in force, swapped in whole by `POST /admin/keys/reload`. Clones share
/// the same keys.
#[derive(Clone)]
pub struct SharedKeys {
    current: Arc<RwLock<Arc<IssuerKeys>>>,
}

impl std::fmt::Debug for SharedKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.snapshot().fmt(f)
    }
}

impl SharedKeys {
    /// Put `keys` in force.
    pub fn new(keys: IssuerKeys) -> Self {
        Self {
            current: Arc::new(RwLock::new(Arc::new(keys))),
        }
    }

    /// The keys in force now. They stay usable, unchanged, after a later swap.
    pub fn snapshot(&self) -> Arc<IssuerKeys> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Put `keys` in force, one generation after the keys they replace, and return those.
    pub fn swap(&self, mut keys: IssuerKeys) -> Arc<IssuerKeys> {
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        keys.generation = current.generation + 1;
        std::mem::replace(&mut *current, Arc::new(keys))
    }
}

/// Where a checker of tokens gets its [`Verifier`]: a fixed one, or the [`SharedKeys`] in
/// force at each check (the server's own, which a key reload swaps).
#[derive(Clone)]
pub enum VerifierSource {
    /// Always this verifier (tests, benches, embedders).
    Fixed(Arc<Verifier>),
    /// The verifier of the keys in force when a check starts.
    Shared(SharedKeys),
}

impl From<Verifier> for VerifierSource {
    fn from(v: Verifier) -> Self {
        Self::Fixed(Arc::new(v))
    }
}

impl From<SharedKeys> for VerifierSource {
    fn from(k: SharedKeys) -> Self {
        Self::Shared(k)
    }
}

impl VerifierSource {
    /// The verifier to check one token with, and the generation of its keys (0 for a fixed
    /// verifier).
    pub fn current(&self) -> CurrentVerifier {
        match self {
            Self::Fixed(v) => CurrentVerifier::Fixed(Arc::clone(v)),
            Self::Shared(k) => CurrentVerifier::Shared(k.snapshot()),
        }
    }
}

/// A [`Verifier`] from a [`VerifierSource`], held for one check.
pub enum CurrentVerifier {
    /// From [`VerifierSource::Fixed`].
    Fixed(Arc<Verifier>),
    /// From [`VerifierSource::Shared`]: the whole snapshot.
    Shared(Arc<IssuerKeys>),
}

impl CurrentVerifier {
    /// The generation of the keys (0 for a fixed verifier).
    pub fn generation(&self) -> u64 {
        match self {
            Self::Fixed(_) => 0,
            Self::Shared(k) => k.generation,
        }
    }
}

impl std::ops::Deref for CurrentVerifier {
    type Target = Verifier;
    fn deref(&self) -> &Verifier {
        match self {
            Self::Fixed(v) => v,
            Self::Shared(k) => &k.verifier,
        }
    }
}

/// Why a key file was refused by a reload (`key_file_unreadable`, `key_file_invalid`,
/// `key_duplicate`). Each names the file by its path and never quotes what is in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyFileError {
    /// The file cannot be read (missing, no permission, not UTF-8): `key_file_unreadable`.
    Unreadable {
        /// The file.
        path: PathBuf,
        /// The I/O error, which says nothing of the content.
        why: String,
    },
    /// The file is not a key of the kind wanted (another type or curve, a public key where the
    /// signing key is wanted, no PEM block, a damaged one), or not a regular file of a key's
    /// size: `key_file_invalid`.
    Invalid {
        /// The file.
        path: PathBuf,
        /// What is wrong, in fixed words.
        why: &'static str,
        /// The parser's own reason, when there is one (`invalid PEM base64`, the DER fault).
        /// It is in fixed words too and never quotes the file.
        cause: Option<String>,
    },
    /// Two of the files hold the same key: `key_duplicate`.
    Duplicate {
        /// The key's `kid`.
        kid: String,
        /// The file listed first.
        first: PathBuf,
        /// The file that repeats it.
        second: PathBuf,
    },
}

impl std::fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable { path, why } => {
                write!(f, "the key file {} cannot be read: {why}", path.display())
            }
            Self::Invalid {
                path,
                why,
                cause: None,
            } => write!(f, "the key file {} {why}", path.display()),
            Self::Invalid {
                path,
                why,
                cause: Some(cause),
            } => write!(f, "the key file {} {why} ({cause})", path.display()),
            Self::Duplicate { kid, first, second } => write!(
                f,
                "the key files {} and {} hold the same key (kid `{kid}`); list each key once",
                first.display(),
                second.display()
            ),
        }
    }
}

impl std::error::Error for KeyFileError {}

/// PEM labels of keys that are not what the issuer takes, named in a refusal. Only these fixed
/// words are ever shown, never a label read from the file.
const OTHER_KEY_LABELS: [&str; 5] = [
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "CERTIFICATE",
];

/// Why `pem` holds no key the issuer takes, given that parsing it as one failed.
fn invalid_why(pem: &str, signing: bool) -> &'static str {
    let has = |label: &str| pem.contains(&format!("-----BEGIN {label}-----"));
    if has("PRIVATE KEY") {
        return "holds a `PRIVATE KEY` that is not an Ed25519 PKCS#8 key (a key of another \
                type or curve, or a damaged file)";
    }
    if has("PUBLIC KEY") {
        return if signing {
            "holds a public key only: the signing key must be an Ed25519 private key (PKCS#8 \
             `PRIVATE KEY`)"
        } else {
            "holds a `PUBLIC KEY` that is not an Ed25519 key (a key of another type or \
             curve, or a damaged file)"
        };
    }
    match OTHER_KEY_LABELS.into_iter().find(|l| has(l)) {
        Some("RSA PRIVATE KEY") => {
            "holds an RSA key: the issuer key must be Ed25519 (PKCS#8 `PRIVATE KEY`)"
        }
        Some("EC PRIVATE KEY") => {
            "holds an EC (ECDSA) key: the issuer key must be Ed25519 (PKCS#8 `PRIVATE KEY`)"
        }
        Some("OPENSSH PRIVATE KEY") => {
            "holds an OpenSSH key: convert it to PKCS#8 `PRIVATE KEY` PEM"
        }
        Some("ENCRYPTED PRIVATE KEY") => {
            "holds an encrypted key: the issuer reads unencrypted PKCS#8 `PRIVATE KEY` PEM only"
        }
        Some(_) => "holds a certificate, not a key",
        None if signing => "has no `PRIVATE KEY` PEM block",
        None => "has no `PRIVATE KEY` or `PUBLIC KEY` PEM block",
    }
}

/// The signing key of `path`, read from `pem`.
///
/// # Errors
///
/// [`KeyFileError::Invalid`] when `pem` is not an Ed25519 PKCS#8 `PRIVATE KEY`.
pub fn signing_key(config: IssuerConfig, path: &Path, pem: &str) -> Result<Issuer, KeyFileError> {
    Issuer::from_pem(config, pem).map_err(|e| KeyFileError::Invalid {
        path: path.to_owned(),
        why: invalid_why(pem, true),
        cause: Some(e.to_string()),
    })
}

/// The `kid` of the retired key in `pem` (a private or a public key) of `path`.
///
/// # Errors
///
/// [`KeyFileError::Invalid`] when `pem` holds no Ed25519 key the issuer takes.
pub fn previous_key_id(path: &Path, pem: &str) -> Result<String, KeyFileError> {
    Issuer::previous_key_id(pem).map_err(|e| KeyFileError::Invalid {
        path: path.to_owned(),
        why: invalid_why(pem, false),
        cause: Some(e.to_string()),
    })
}

/// The most a key file may hold. An Ed25519 PEM is under 200 bytes; this leaves room for
/// comments and a certificate chain someone kept beside the key, and stops a reload from
/// reading a large file someone pointed it at by mistake.
pub const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// Read one key file as text: a regular file (a link to one is fine) of at most
/// [`MAX_KEY_FILE_BYTES`].
async fn read_key_file(path: &Path) -> Result<String, KeyFileError> {
    use tokio::io::AsyncReadExt;
    let unreadable = |e: std::io::Error| KeyFileError::Unreadable {
        path: path.to_owned(),
        // The kind only: an `InvalidData` error of a file that is not UTF-8 says no more.
        why: e.to_string(),
    };
    let invalid = |why| KeyFileError::Invalid {
        path: path.to_owned(),
        why,
        cause: None,
    };
    let file = tokio::fs::File::open(path).await.map_err(unreadable)?;
    let meta = file.metadata().await.map_err(unreadable)?;
    if !meta.is_file() {
        return Err(invalid("is not a regular file"));
    }
    let too_big = "is larger than 64 KiB, far more than a key";
    if meta.len() > MAX_KEY_FILE_BYTES {
        return Err(invalid(too_big));
    }
    // Bounded again while reading, in case the file grows after the check.
    let mut bytes = Vec::new();
    file.take(MAX_KEY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(unreadable)?;
    if bytes.len() as u64 > MAX_KEY_FILE_BYTES {
        return Err(invalid(too_big));
    }
    String::from_utf8(bytes).map_err(|_| KeyFileError::Unreadable {
        path: path.to_owned(),
        why: "it is not UTF-8 text".into(),
    })
}

/// Read the signing key at `signing` and the retired keys at `previous` for a key reload,
/// more strictly than startup does: nothing is generated, and two files that hold the same
/// key (the signing key listed as retired too, or a retired key twice) are refused rather
/// than merged. The files are read in order and the first fault is returned.
///
/// # Errors
///
/// [`KeyFileError`]: a file that cannot be read, one that holds no key of the kind wanted,
/// or a key in two files.
pub async fn read_key_files(
    config: IssuerConfig,
    signing: &Path,
    previous: &[PathBuf],
) -> Result<Issuer, KeyFileError> {
    let pem = read_key_file(signing).await?;
    let mut issuer = signing_key(config, signing, &pem)?;
    let mut seen: Vec<(String, &Path)> = vec![(issuer.key_id(), signing)];
    for path in previous {
        let pem = read_key_file(path).await?;
        let kid = previous_key_id(path, &pem)?;
        if let Some((_, first)) = seen.iter().find(|(k, _)| *k == kid) {
            return Err(KeyFileError::Duplicate {
                kid,
                first: first.to_path_buf(),
                second: path.clone(),
            });
        }
        // Parsed just above, so this does not fail.
        issuer
            .trust_previous_key(&pem)
            .map_err(|e| KeyFileError::Invalid {
                path: path.clone(),
                why: invalid_why(&pem, false),
                cause: Some(e.to_string()),
            })?;
        seen.push((kid, path));
    }
    Ok(issuer)
}

/// Length of an Ed25519 SubjectPublicKeyInfo DER: a 12-byte prefix plus the 32-byte key.
const ED25519_SPKI_LEN: usize = 44;

/// Decode a `PUBLIC KEY` PEM to its SPKI DER bytes.
pub(crate) fn spki_der_from_pem(pem: &str) -> anyhow::Result<Vec<u8>> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect();
    let der = STANDARD.decode(b64)?;
    if der.len() != ED25519_SPKI_LEN {
        anyhow::bail!("not an Ed25519 SubjectPublicKeyInfo ({} bytes)", der.len());
    }
    Ok(der)
}

/// `{"keys": [ { kty: OKP, crv: Ed25519, alg: EdDSA, use: sig, kid, x } ]}` for each
/// `(kid, PUBLIC KEY PEM)`: the signing key first, then any retired keys still trusted.
pub(crate) fn jwks_from_keys(keys: &[(String, String)]) -> anyhow::Result<Value> {
    let mut out = Vec::with_capacity(keys.len());
    for (kid, pem) in keys {
        let der = spki_der_from_pem(pem)?;
        let raw = &der[ED25519_SPKI_LEN - 32..];
        out.push(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "kid": kid,
            "x": URL_SAFE_NO_PAD.encode(raw),
        }));
    }
    Ok(json!({ "keys": out }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use attenuo_token::{Issuer, IssuerConfig};

    fn issuer() -> Issuer {
        Issuer::generate(IssuerConfig {
            issuer: "i".into(),
            audience: "a".into(),
            max_depth: 4,
            default_ttl: time::Duration::minutes(5),
        })
    }

    #[test]
    fn jwk_x_matches_pem_key() {
        let issuer = issuer();
        let pem = issuer.public_key_pem();
        let jwks = jwks_from_keys(&issuer.trusted_public_keys()).unwrap();
        let k = &jwks["keys"][0];
        assert_eq!(k["crv"], "Ed25519");
        assert_eq!(k["kid"].as_str().unwrap(), issuer.key_id());
        assert_eq!(k["kid"].as_str().unwrap().len(), 22);
        let x = URL_SAFE_NO_PAD.decode(k["x"].as_str().unwrap()).unwrap();
        assert_eq!(x.len(), 32);
        assert_eq!(&spki_der_from_pem(&pem).unwrap()[12..], &x[..]);
        assert!(jwks_from_keys(&[(
            "k".into(),
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----".into()
        )])
        .is_err());
    }

    #[test]
    fn jwks_lists_current_then_retired_keys() {
        let old = issuer();
        let mut new = issuer();
        new.trust_previous_key(&old.public_key_pem()).unwrap();
        let jwks = jwks_from_keys(&new.trusted_public_keys()).unwrap();
        let kids: Vec<&str> = jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap())
            .collect();
        assert_eq!(kids, [new.key_id(), old.key_id()]);
    }

    /// The strict reading of a reload: a signing key and retired keys in order; a key in two
    /// files, a public key as the signing key, a file of another kind and a missing file are
    /// each refused with the file named and its content never quoted.
    #[tokio::test]
    async fn read_key_files_is_strict() {
        let dir = tempfile::tempdir().unwrap();
        let p = |n: &str| dir.path().join(n);
        let (a, b) = (issuer(), issuer());
        std::fs::write(p("a.pem"), a.private_key_pem()).unwrap();
        std::fs::write(p("a.pub"), a.public_key_pem()).unwrap();
        std::fs::write(p("b.pem"), b.private_key_pem()).unwrap();
        std::fs::write(p("junk.pem"), "secret-junk").unwrap();
        let cfg = || a.config().clone();

        let got = read_key_files(cfg(), &p("b.pem"), &[p("a.pub")])
            .await
            .unwrap();
        let keys = IssuerKeys::new(got).unwrap();
        assert_eq!(keys.kids(), [b.key_id(), a.key_id()]);
        assert_eq!(kids_of(&keys.jwks), keys.kids());
        assert_eq!(keys.generation(), 0);

        let err = read_key_files(cfg(), &p("b.pem"), &[p("a.pem"), p("a.pub")])
            .await
            .unwrap_err();
        assert_eq!(
            err,
            KeyFileError::Duplicate {
                kid: a.key_id(),
                first: p("a.pem"),
                second: p("a.pub"),
            }
        );
        let err = read_key_files(cfg(), &p("b.pem"), &[p("b.pem")])
            .await
            .unwrap_err();
        assert!(matches!(err, KeyFileError::Duplicate { .. }), "{err}");
        let err = read_key_files(cfg(), &p("a.pub"), &[]).await.unwrap_err();
        assert!(err.to_string().contains("public key only"), "{err}");
        let err = read_key_files(cfg(), &p("b.pem"), &[p("junk.pem")])
            .await
            .unwrap_err();
        assert!(matches!(err, KeyFileError::Invalid { .. }), "{err}");
        assert!(err.to_string().contains("junk.pem"), "{err}");
        assert!(!err.to_string().contains("secret-junk"), "{err}");
        let err = read_key_files(cfg(), &p("nope.pem"), &[])
            .await
            .unwrap_err();
        assert!(matches!(err, KeyFileError::Unreadable { .. }), "{err}");
    }

    /// A directory, a file over 64 KiB and a file that is not UTF-8 are refused before any
    /// parsing, and a damaged key keeps the parser's reason without quoting the file.
    #[tokio::test]
    async fn read_key_files_refuses_what_is_not_a_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = |n: &str| dir.path().join(n);
        let a = issuer();
        std::fs::write(p("a.pem"), a.private_key_pem()).unwrap();
        let mut big = a.private_key_pem();
        big.push_str(&"#".repeat(usize::try_from(MAX_KEY_FILE_BYTES).unwrap()));
        std::fs::write(p("big.pem"), big).unwrap();
        std::fs::write(p("bin.pem"), [0xff, 0xfe, 0x00]).unwrap();
        std::fs::write(
            p("bad64.pem"),
            "-----BEGIN PRIVATE KEY-----\nsecret!!\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        let cfg = || a.config().clone();

        let err = read_key_files(cfg(), dir.path(), &[]).await.unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err}");
        let err = read_key_files(cfg(), &p("a.pem"), &[p("big.pem")])
            .await
            .unwrap_err();
        assert!(
            matches!(&err, KeyFileError::Invalid { path, .. } if *path == p("big.pem")),
            "{err}"
        );
        assert!(err.to_string().contains("64 KiB"), "{err}");
        let err = read_key_files(cfg(), &p("bin.pem"), &[]).await.unwrap_err();
        assert!(matches!(err, KeyFileError::Unreadable { .. }), "{err}");
        let err = read_key_files(cfg(), &p("bad64.pem"), &[])
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("(key error: invalid PEM base64)"), "{text}");
        assert!(!text.contains("secret"), "{text}");
    }

    fn kids_of(jwks: &Value) -> Vec<String> {
        jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap().to_string())
            .collect()
    }

    /// A swap moves to the next generation; a snapshot taken before keeps the old keys.
    #[test]
    fn a_swap_keeps_earlier_snapshots() {
        let (a, b) = (issuer(), issuer());
        let (ka, kb) = (a.key_id(), b.key_id());
        let shared = SharedKeys::new(IssuerKeys::new(a).unwrap());
        let before = shared.snapshot();
        let old = shared.swap(IssuerKeys::new(b).unwrap());
        assert_eq!(old.issuer.key_id(), ka);
        assert_eq!(before.issuer.key_id(), ka);
        assert_eq!(shared.snapshot().issuer.key_id(), kb);
        assert_eq!(shared.snapshot().generation(), 1);
        assert!(!format!("{shared:?}").contains("PRIVATE"));
    }
}
