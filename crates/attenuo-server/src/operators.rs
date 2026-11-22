//! Admin credentials and roles (ADR-0016).
//!
//! The admin API accepts a bearer token from one of these credentials:
//!
//! - `[[admin.operators]]` entries, each a `name`, the SHA-256 of its token (`token_sha256`)
//!   and a [`AdminRole`]. The configuration never holds an operator's token itself;
//!   `attenuo admin operator new` generates one and prints the entry.
//! - The legacy `[admin] token` (or `ATTENUO_ADMIN_TOKEN`), which is the operator named
//!   [`LEGACY_OPERATOR`] (`admin`) with role [`AdminRole::Admin`].
//!
//! [`AdminCredentials::authenticate`] hashes the presented bearer and compares the digest in
//! constant time against every credential, without stopping at a match; only then does it
//! check the matched operator's `expires_at`. The route a request may reach is decided by
//! [`required_role`], from the one table [`ROUTE_ROLES`]; a route missing from the table
//! requires [`AdminRole::Admin`].
//!
//! The credentials in force are a [`SharedAdminCredentials`]: `POST /admin/operators/reload`
//! re-reads `[[admin.operators]]` from the config file ([`operators_from_toml`]), validates the
//! new list against the `[admin] token` in force ([`AdminCredentials::with_operators`]) and
//! swaps it in whole. `[admin] token` itself is never reloaded.
//!
//! Plain SHA-256 is enough here because the tokens are not passwords: the CLI generates them
//! from 32 random bytes, so there is nothing for a slow hash to protect against guessing.

use std::fmt;
use std::sync::{Arc, PoisonError, RwLock};

use axum::http::Method;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::AdminOperator;
use crate::routes::ADMIN_SUBJECT;

/// The name of the operator that `[admin] token` authenticates. Reserved: no
/// `[[admin.operators]]` entry may use it.
pub const LEGACY_OPERATOR: &str = "admin";

/// Longest operator name.
pub const MAX_OPERATOR_NAME: usize = 64;

/// What an admin credential may do. Ordered: each role may do everything the roles below it
/// may.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdminRole {
    /// Read-only routes: lists, the audit log and its export, the policy dry run.
    Viewer,
    /// A viewer that may also revoke leases and decide approvals.
    Operator,
    /// Every admin route.
    Admin,
}

impl AdminRole {
    /// The configuration and wire name: `viewer`, `operator` or `admin`.
    pub fn as_str(self) -> &'static str {
        match self {
            AdminRole::Viewer => "viewer",
            AdminRole::Operator => "operator",
            AdminRole::Admin => "admin",
        }
    }

    /// Parse a role name.
    ///
    /// # Errors
    ///
    /// When `s` is not `viewer`, `operator` or `admin`.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "viewer" => Ok(AdminRole::Viewer),
            "operator" => Ok(AdminRole::Operator),
            "admin" => Ok(AdminRole::Admin),
            _ => Err(format!(
                "unknown role `{s}`: expected viewer, operator or admin"
            )),
        }
    }
}

impl fmt::Display for AdminRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Who sent an admin request: put into the request's extensions by
/// [`crate::routes::admin::require_admin`] once the bearer matched a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminIdentity {
    /// The operator's name (`admin` for `[admin] token`).
    pub name: String,
    /// The operator's role.
    pub role: AdminRole,
    /// When the credential stops authenticating (`expires_at` of its entry); `None` for one
    /// that does not expire, `[admin] token` included.
    pub expires_at: Option<OffsetDateTime>,
}

impl AdminIdentity {
    /// The identity of `[admin] token`.
    pub fn legacy() -> Self {
        Self {
            name: LEGACY_OPERATOR.to_string(),
            role: AdminRole::Admin,
            expires_at: None,
        }
    }

    /// The subject the audit log and approvals record for this operator: `urn:attenuo:admin`
    /// for `[admin] token` (as before operators existed, so old and new records of it read
    /// the same), `urn:attenuo:admin:<name>` for a named operator. Both are under the reserved
    /// `urn:attenuo:` prefix, which no user can have (SR-34).
    pub fn subject(&self) -> String {
        if self.name == LEGACY_OPERATOR {
            ADMIN_SUBJECT.to_string()
        } else {
            format!("{ADMIN_SUBJECT}:{}", self.name)
        }
    }
}

/// SHA-256 of a bearer token's bytes.
pub fn token_sha256(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// [`token_sha256`] as 64 lowercase hex characters, the form `token_sha256` takes in the
/// configuration.
pub fn token_sha256_hex(token: &str) -> String {
    hex::encode(token_sha256(token))
}

/// Check an operator name: 1 to [`MAX_OPERATOR_NAME`] characters of `a-z`, `0-9`, `_` and
/// `-`, and not the reserved [`LEGACY_OPERATOR`].
///
/// # Errors
///
/// When the name breaks one of those rules; the message says which.
pub fn check_operator_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > MAX_OPERATOR_NAME {
        return Err(format!(
            "operator name `{name}` must be 1 to {MAX_OPERATOR_NAME} characters"
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err(format!(
            "operator name `{name}` may hold only a-z, 0-9, `_` and `-`"
        ));
    }
    if name == LEGACY_OPERATOR {
        return Err(format!(
            "operator name `{LEGACY_OPERATOR}` is reserved for [admin] token"
        ));
    }
    Ok(())
}

/// Parse a `token_sha256` value: exactly 64 lowercase hex characters.
///
/// # Errors
///
/// When `s` is not 64 characters of `0-9a-f`. The message never repeats the value.
pub fn parse_token_sha256(s: &str) -> Result<[u8; 32], String> {
    let well_formed = s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let bad = || "token_sha256 must be 64 lowercase hex characters (the SHA-256 of the token)";
    if !well_formed {
        return Err(bad().to_string());
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).map_err(|_| bad().to_string())?;
    Ok(out)
}

/// Check a list of `[[admin.operators]]` entries (ADR-0016), at startup and on a reload:
/// every name passes [`check_operator_name`] and is unique, every `token_sha256` is 64
/// lowercase hex characters, no two operators share a digest, and no operator's digest is
/// `legacy`, the SHA-256 of the `[admin] token` in force.
///
/// # Errors
///
/// On the first entry that breaks one of those rules; the message names the entry, never a
/// digest or a token.
pub fn check_operators(ops: &[AdminOperator], legacy: Option<[u8; 32]>) -> anyhow::Result<()> {
    let mut seen: Vec<(&str, [u8; 32])> = Vec::with_capacity(ops.len());
    for op in ops {
        check_operator_name(&op.name).map_err(|e| anyhow::anyhow!("[[admin.operators]]: {e}"))?;
        let digest = parse_token_sha256(&op.token_sha256)
            .map_err(|e| anyhow::anyhow!("[[admin.operators]] `{}`: {e}", op.name))?;
        if seen.iter().any(|(name, _)| *name == op.name) {
            anyhow::bail!(
                "[[admin.operators]]: the name `{}` is used twice; names must be unique",
                op.name
            );
        }
        if let Some((other, _)) = seen.iter().find(|(_, d)| *d == digest) {
            anyhow::bail!(
                "[[admin.operators]] `{}` and `{other}` have the same token_sha256; give \
                 each operator a token of its own",
                op.name
            );
        }
        if legacy == Some(digest) {
            anyhow::bail!(
                "[[admin.operators]] `{}`: token_sha256 is the digest of [admin] token; \
                 give the operator a token of its own",
                op.name
            );
        }
        seen.push((&op.name, digest));
    }
    Ok(())
}

/// The `[[admin.operators]]` array of a config file's text, and nothing else of it: what
/// `POST /admin/operators/reload` reads. The other sections are not looked at (they are not
/// reloaded), but the text must be TOML. A file without `[admin]` or without operators gives
/// an empty list.
///
/// # Errors
///
/// When the text is not TOML, `admin` is not a table, or an entry does not have the shape of
/// [`AdminOperator`] (an unknown key, a missing one, an unknown role, an `expires_at` that is
/// not an RFC 3339 time with an offset).
pub fn operators_from_toml(text: &str) -> anyhow::Result<Vec<AdminOperator>> {
    // Only the error's message and line: its default rendering quotes the line, which can be
    // `[admin] token = "..."`.
    let mut file: toml::Table = text
        .parse()
        .map_err(|e: toml::de::Error| anyhow::anyhow!(crate::config::toml_error_text(text, &e)))?;
    let Some(admin) = file.remove("admin") else {
        return Ok(Vec::new());
    };
    let toml::Value::Table(mut admin) = admin else {
        anyhow::bail!("`admin` is not a table");
    };
    match admin.remove("operators") {
        None => Ok(Vec::new()),
        Some(ops) => ops
            .try_into::<Vec<AdminOperator>>()
            .map_err(|e| anyhow::anyhow!("[[admin.operators]]: {}", e.message())),
    }
}

#[derive(Clone)]
struct Credential {
    identity: AdminIdentity,
    sha256: [u8; 32],
}

/// Why [`AdminCredentials::authenticate`] refused a bearer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFailure {
    /// The token is no credential's.
    Unknown,
    /// The token is the credential of this operator, whose `expires_at` has passed.
    Expired {
        /// The operator's name.
        name: String,
    },
}

/// Every admin credential the server accepts, by the SHA-256 of its token. Built at startup
/// ([`AdminCredentials::from_config`]) and rebuilt by an operators reload
/// ([`AdminCredentials::with_operators`]); the set in force is a [`SharedAdminCredentials`].
#[derive(Default, Clone)]
pub struct AdminCredentials {
    creds: Vec<Credential>,
}

impl fmt::Debug for AdminCredentials {
    /// Names and roles only, never a digest.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(
                self.creds
                    .iter()
                    .map(|c| (&c.identity.name, c.identity.role)),
            )
            .finish()
    }
}

/// What an operators reload changed, by operator name (never a digest). `[admin] token` is
/// never in it: it is not reloaded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OperatorChanges {
    /// Operators in the new list and not in the old one.
    pub added: Vec<String>,
    /// Operators in the old list and not in the new one: their tokens stop working.
    pub removed: Vec<String>,
    /// Operators in both whose role, `token_sha256` or `expires_at` differs.
    pub changed: Vec<String>,
}

impl AdminCredentials {
    /// The credentials of `[admin]`: `token` (as the operator `admin`, role `admin`) and each
    /// `[[admin.operators]]` entry.
    ///
    /// # Errors
    ///
    /// When an operator's `token_sha256` does not parse. The other rules are checked by
    /// [`crate::config::Config::check_admin_operators`].
    pub fn from_config(admin: &crate::config::AdminSection) -> anyhow::Result<Self> {
        let mut creds = Vec::with_capacity(admin.operators.len() + 1);
        if let Some(token) = admin.token.as_deref() {
            creds.push(Credential {
                identity: AdminIdentity::legacy(),
                sha256: token_sha256(token),
            });
        }
        Self::push_operators(&mut creds, &admin.operators)?;
        Ok(Self { creds })
    }

    fn push_operators(creds: &mut Vec<Credential>, ops: &[AdminOperator]) -> anyhow::Result<()> {
        for op in ops {
            let sha256 = parse_token_sha256(&op.token_sha256)
                .map_err(|e| anyhow::anyhow!("[[admin.operators]] `{}`: {e}", op.name))?;
            creds.push(Credential {
                identity: AdminIdentity {
                    name: op.name.clone(),
                    role: op.role,
                    expires_at: op.expires_at,
                },
                sha256,
            });
        }
        Ok(())
    }

    /// The SHA-256 of `[admin] token`, when one is configured.
    fn legacy_sha256(&self) -> Option<[u8; 32]> {
        self.creds
            .iter()
            .find(|c| c.identity.name == LEGACY_OPERATOR)
            .map(|c| c.sha256)
    }

    /// These credentials with `[[admin.operators]]` replaced by `ops`, checked as at startup
    /// ([`check_operators`], against the `[admin] token` kept from `self`). `[admin] token` is
    /// kept as it is.
    ///
    /// # Errors
    ///
    /// As [`check_operators`].
    pub fn with_operators(&self, ops: &[AdminOperator]) -> anyhow::Result<Self> {
        let legacy = self.legacy_sha256();
        check_operators(ops, legacy)?;
        let mut creds: Vec<Credential> = self
            .creds
            .iter()
            .filter(|c| c.identity.name == LEGACY_OPERATOR)
            .cloned()
            .collect();
        Self::push_operators(&mut creds, ops)?;
        Ok(Self { creds })
    }

    /// No credential is configured: the admin API answers 403 `admin_disabled`.
    pub fn is_empty(&self) -> bool {
        self.creds.is_empty()
    }

    /// Is there a credential with role `admin` that has not expired at `now`: `[admin] token`
    /// or an operator? An operators reload that would leave none is refused, so that a typo
    /// cannot lock everyone out of the admin routes until a restart.
    pub fn has_live_admin(&self, now: OffsetDateTime) -> bool {
        self.creds.iter().any(|c| {
            c.identity.role == AdminRole::Admin && c.identity.expires_at.is_none_or(|t| now < t)
        })
    }

    /// The operators whose `expires_at` is at or before `now`, with it: their tokens are
    /// refused with `admin_credential_expired`. Logged as warnings at startup and on a reload.
    pub fn expired(&self, now: OffsetDateTime) -> Vec<(&str, OffsetDateTime)> {
        self.creds
            .iter()
            .filter_map(|c| {
                c.identity
                    .expires_at
                    .filter(|t| *t <= now)
                    .map(|t| (c.identity.name.as_str(), t))
            })
            .collect()
    }

    /// Log a warning for each operator [`expired`](Self::expired) at `now`, naming it. `when`
    /// says where the list was read (`at startup`, `by the reload`).
    pub fn warn_expired(&self, now: OffsetDateTime, when: &str) {
        for (name, at) in self.expired(now) {
            let at = at.format(&Rfc3339).unwrap_or_else(|_| at.to_string());
            tracing::warn!(
                operator = %name,
                expires_at = %at,
                "[[admin.operators]] `{name}` expired at {at} and its token is refused; the \
                 entry was accepted {when}: remove it from the config file"
            );
        }
    }

    /// What changed from `self` to `new`, by operator name; `[admin] token` is left out.
    pub fn changes_to(&self, new: &Self) -> OperatorChanges {
        let ops = |s: &Self| -> Vec<Credential> {
            s.creds
                .iter()
                .filter(|c| c.identity.name != LEGACY_OPERATOR)
                .cloned()
                .collect()
        };
        let (old, new) = (ops(self), ops(new));
        let mut out = OperatorChanges::default();
        for n in &new {
            match old.iter().find(|o| o.identity.name == n.identity.name) {
                None => out.added.push(n.identity.name.clone()),
                Some(o) => {
                    if o.identity.role != n.identity.role
                        || o.identity.expires_at != n.identity.expires_at
                        || !ct_eq32(&o.sha256, &n.sha256)
                    {
                        out.changed.push(n.identity.name.clone());
                    }
                }
            }
        }
        for o in &old {
            if !new.iter().any(|n| n.identity.name == o.identity.name) {
                out.removed.push(o.identity.name.clone());
            }
        }
        out.added.sort();
        out.removed.sort();
        out.changed.sort();
        out
    }

    /// The identity whose token is `token`, if it has not expired at `now`.
    ///
    /// The token is hashed once, and the digest is compared with every credential in constant
    /// time; the loop never stops early, so the time taken does not tell which credential
    /// matched or whether one did. Only then is the matched credential's `expires_at`
    /// compared with `now`. The startup and reload checks refuse two credentials with one
    /// digest, so at most one matches.
    ///
    /// # Errors
    ///
    /// [`AuthFailure::Unknown`] when the token matches no credential, and
    /// [`AuthFailure::Expired`] when it matches one whose `expires_at` is at or before `now`.
    pub fn authenticate(
        &self,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<AdminIdentity, AuthFailure> {
        let presented = token_sha256(token);
        // 1 + the index of the match, 0 for none, selected without a branch on the result.
        let mut found = 0usize;
        for (i, c) in self.creds.iter().enumerate() {
            let hit = usize::from(ct_eq32(&presented, &c.sha256));
            found |= hit.wrapping_neg() & (i + 1);
        }
        let identity = found
            .checked_sub(1)
            .and_then(|i| self.creds.get(i))
            .map(|c| c.identity.clone())
            .ok_or(AuthFailure::Unknown)?;
        match identity.expires_at {
            Some(at) if at <= now => Err(AuthFailure::Expired {
                name: identity.name,
            }),
            _ => Ok(identity),
        }
    }
}

/// The admin credentials in force, swapped whole by `POST /admin/operators/reload`, the way
/// [`crate::authz::SharedPolicy`] holds the policy engine. A request takes one
/// [`snapshot`](Self::snapshot) in [`crate::routes::admin::require_admin`] and authenticates
/// against it; a reload builds the new set with no lock held and [`swap`](Self::swap)s it in.
/// The lock is held only to copy or replace the pointer, so a request that was admitted before
/// a swap completes, and none sees half of two sets.
///
/// The lock guards a single `Arc` replaced in one store, so a panic cannot leave it
/// half-written: poisoning is ignored.
#[derive(Debug, Default)]
pub struct SharedAdminCredentials {
    current: RwLock<Arc<AdminCredentials>>,
}

impl SharedAdminCredentials {
    /// Put `creds` in force.
    pub fn new(creds: AdminCredentials) -> Self {
        Self {
            current: RwLock::new(Arc::new(creds)),
        }
    }

    /// The credentials in force now. They stay usable, unchanged, after a later swap.
    pub fn snapshot(&self) -> Arc<AdminCredentials> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Put `creds` in force and return the set they replace.
    pub fn swap(&self, creds: Arc<AdminCredentials>) -> Arc<AdminCredentials> {
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        std::mem::replace(&mut *current, creds)
    }
}

/// Constant-time equality of two digests.
fn ct_eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The least role each admin route needs, by method and route template (the path as
/// registered with axum, `{param}` included). The one place this is decided: a route that is
/// not listed here needs [`AdminRole::Admin`] ([`required_role`]), and a test checks that
/// every admin route the server mounts is listed.
///
/// - viewer: reads, including `GET /admin/audit/checkpoint` (it signs a checkpoint of the
///   head when it has none, which records no new fact) and the `POST /admin/policies/evaluate`
///   dry run (writes nothing);
/// - operator: revoking leases (by id or by selector, the `?preview=true` dry run included)
///   and deciding approvals;
/// - admin: everything else (policy reload, operators reload, agents reload, budget refunds,
///   the dev root mint, and the audit retention routes: the prune plan, the prune and the
///   anchors).
pub const ROUTE_ROLES: &[(&str, &str, AdminRole)] = &[
    ("GET", "/admin/whoami", AdminRole::Viewer),
    ("GET", "/admin/leases/{lease_id}", AdminRole::Viewer),
    ("GET", "/admin/leases/{lease_id}/tree", AdminRole::Viewer),
    ("GET", "/admin/audit", AdminRole::Viewer),
    ("GET", "/admin/audit/verify", AdminRole::Viewer),
    ("GET", "/admin/audit/entries/{seq}", AdminRole::Viewer),
    ("GET", "/admin/audit/records/{id}", AdminRole::Viewer),
    ("GET", "/admin/audit/checkpoints", AdminRole::Viewer),
    ("GET", "/admin/audit/checkpoint", AdminRole::Viewer),
    ("GET", "/admin/audit/export", AdminRole::Viewer),
    ("GET", "/admin/policies", AdminRole::Viewer),
    ("GET", "/admin/policies/check", AdminRole::Viewer),
    ("POST", "/admin/policies/evaluate", AdminRole::Viewer),
    ("GET", "/admin/approvals", AdminRole::Viewer),
    ("GET", "/admin/approvals/{id}", AdminRole::Viewer),
    (
        "POST",
        "/admin/leases/{lease_id}/revoke",
        AdminRole::Operator,
    ),
    ("POST", "/admin/leases/revoke", AdminRole::Operator),
    ("POST", "/admin/approvals/{id}", AdminRole::Operator),
    ("POST", "/admin/budgets/refund", AdminRole::Admin),
    ("POST", "/admin/policies/reload", AdminRole::Admin),
    ("POST", "/admin/operators/reload", AdminRole::Admin),
    ("POST", "/admin/agents/reload", AdminRole::Admin),
    ("POST", "/admin/root-token", AdminRole::Admin),
    ("GET", "/admin/audit/prune/plan", AdminRole::Admin),
    ("POST", "/admin/audit/prune", AdminRole::Admin),
    ("GET", "/admin/audit/anchors", AdminRole::Admin),
];

/// The least role a request needs: its entry in [`ROUTE_ROLES`], or [`AdminRole::Admin`] when
/// there is none or the route template is unknown (fail closed). `HEAD` is looked up as `GET`,
/// as axum serves it.
pub fn required_role(method: &Method, route: Option<&str>) -> AdminRole {
    let method = if method == Method::HEAD {
        "GET"
    } else {
        method.as_str()
    };
    route
        .and_then(|route| {
            ROUTE_ROLES
                .iter()
                .find(|(m, p, _)| *m == method && *p == route)
        })
        .map_or(AdminRole::Admin, |(_, _, role)| *role)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AdminOperator, AdminSection};

    fn op(name: &str, token: &str, role: AdminRole) -> AdminOperator {
        AdminOperator {
            name: name.into(),
            token_sha256: token_sha256_hex(token),
            role,
            expires_at: None,
        }
    }

    #[test]
    fn every_credential_authenticates_as_itself() {
        let admin = AdminSection {
            token: Some("legacy-token".into()),
            operators: vec![
                op("alice", "alice-token", AdminRole::Viewer),
                op("bob", "bob-token", AdminRole::Operator),
            ],
            ..AdminSection::default()
        };
        let creds = AdminCredentials::from_config(&admin).unwrap();
        let now = OffsetDateTime::now_utc();
        assert_eq!(
            creds.authenticate("legacy-token", now),
            Ok(AdminIdentity::legacy())
        );
        let alice = creds.authenticate("alice-token", now).unwrap();
        assert_eq!(
            (alice.name.as_str(), alice.role),
            ("alice", AdminRole::Viewer)
        );
        let bob = creds.authenticate("bob-token", now).unwrap();
        assert_eq!((bob.name.as_str(), bob.role), ("bob", AdminRole::Operator));
        for wrong in ["", "alice", "alice-token ", "Legacy-token"] {
            assert_eq!(
                creds.authenticate(wrong, now),
                Err(AuthFailure::Unknown),
                "{wrong:?}"
            );
        }
        assert_eq!(
            AdminCredentials::default().authenticate("x", now),
            Err(AuthFailure::Unknown)
        );
        // Debug shows names and roles, never a digest.
        let shown = format!("{creds:?}");
        assert!(shown.contains("alice") && !shown.contains(&token_sha256_hex("alice-token")));
    }

    fn at(s: &str) -> OffsetDateTime {
        OffsetDateTime::parse(s, &Rfc3339).unwrap()
    }

    fn expiring(name: &str, token: &str, role: AdminRole, expires_at: &str) -> AdminOperator {
        AdminOperator {
            expires_at: Some(at(expires_at)),
            ..op(name, token, role)
        }
    }

    /// `expires_at` is compared with the `now` passed in: valid before it, refused from it on,
    /// with the operator named in the failure. Other credentials are unaffected.
    #[test]
    fn an_operator_authenticates_until_its_expiry() {
        let admin = AdminSection {
            token: Some("legacy-token".into()),
            operators: vec![
                expiring(
                    "alice",
                    "alice-token",
                    AdminRole::Operator,
                    "2026-11-13T12:00:00Z",
                ),
                op("bob", "bob-token", AdminRole::Viewer),
            ],
            ..AdminSection::default()
        };
        let creds = AdminCredentials::from_config(&admin).unwrap();
        let before = at("2026-11-13T11:59:59Z");
        let alice = creds.authenticate("alice-token", before).unwrap();
        assert_eq!(alice.expires_at, Some(at("2026-11-13T12:00:00Z")));
        for when in [
            "2026-11-13T12:00:00Z",
            "2026-11-13T12:00:01Z",
            "2030-01-01T00:00:00Z",
        ] {
            assert_eq!(
                creds.authenticate("alice-token", at(when)),
                Err(AuthFailure::Expired {
                    name: "alice".into()
                }),
                "{when}"
            );
            // The others still authenticate, and a wrong token is still unknown.
            assert!(creds.authenticate("bob-token", at(when)).is_ok());
            assert!(creds.authenticate("legacy-token", at(when)).is_ok());
            assert_eq!(
                creds.authenticate("alice-token-x", at(when)),
                Err(AuthFailure::Unknown)
            );
        }
        assert_eq!(
            creds.expired(at("2026-11-13T12:00:00Z")),
            vec![("alice", at("2026-11-13T12:00:00Z"))]
        );
        assert!(creds.expired(before).is_empty());
    }

    #[test]
    fn expires_at_parses_as_a_string_or_a_toml_datetime_with_an_offset() {
        let digest = token_sha256_hex("t");
        let parse = |expires: &str| {
            operators_from_toml(&format!(
                "[server]\nlisten = \"127.0.0.1:0\"\n[admin]\ntoken = \"x\"\n\
                 [[admin.operators]]\nname = \"alice\"\ntoken_sha256 = \"{digest}\"\n\
                 role = \"viewer\"\nexpires_at = {expires}\n"
            ))
        };
        let want = at("2026-11-13T10:00:00Z");
        for ok in [
            "\"2026-11-13T10:00:00Z\"",
            "\"2026-11-13T12:00:00+02:00\"",
            "2026-11-13T10:00:00Z",
            "2026-11-13 12:00:00+02:00",
        ] {
            let ops = parse(ok).unwrap();
            assert_eq!(ops[0].expires_at, Some(want), "{ok}");
        }
        for bad in [
            "\"2026-11-13\"",
            "\"2026-11-13T10:00:00\"",
            "\"tomorrow\"",
            "2026-11-13T10:00:00",
            "2026-11-13",
            "1700000000",
        ] {
            let err = parse(bad).unwrap_err().to_string();
            assert!(err.contains("expires_at"), "{bad}: {err}");
        }
        // Without the key, no expiry.
        let ops = operators_from_toml(&format!(
            "[[admin.operators]]\nname = \"a\"\ntoken_sha256 = \"{digest}\"\nrole = \"admin\"\n"
        ))
        .unwrap();
        assert_eq!(ops[0].expires_at, None);
    }

    /// The reload reads `[[admin.operators]]` and nothing else; a file that is not TOML is
    /// refused without quoting its lines (one may be `[admin] token`).
    #[test]
    fn the_reload_reads_only_the_operators() {
        assert!(operators_from_toml("").unwrap().is_empty());
        assert!(operators_from_toml("[admin]\ntoken = \"x\"\n")
            .unwrap()
            .is_empty());
        // Other sections are not looked at, even ones the server would refuse.
        let ops = operators_from_toml(&format!(
            "[server]\nno_such_key = 1\n[[admin.operators]]\nname = \"a\"\n\
             token_sha256 = \"{}\"\nrole = \"admin\"\n",
            token_sha256_hex("t")
        ))
        .unwrap();
        assert_eq!(ops.len(), 1);
        let err = operators_from_toml("[admin]\ntoken = \"secret-admin-token\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("line 2"), "{err}");
        assert!(!err.contains("secret-admin-token"), "{err}");
        assert!(operators_from_toml("admin = 1\n").is_err());
        let err = operators_from_toml(
            "[[admin.operators]]\nname = \"a\"\ntoken_sha256 = \"x\"\nrole = \"root\"\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("root"), "{err}");
    }

    /// A reload keeps `[admin] token`, checks the new list as at startup against it, and
    /// reports what changed by name.
    #[test]
    fn with_operators_keeps_the_legacy_token_and_reports_changes() {
        let admin = AdminSection {
            token: Some("legacy-token".into()),
            operators: vec![
                op("alice", "alice-token", AdminRole::Viewer),
                op("bob", "bob-token", AdminRole::Operator),
                op("carol", "carol-token", AdminRole::Admin),
                op("dave", "dave-token", AdminRole::Viewer),
                op("erin", "erin-token", AdminRole::Viewer),
            ],
            ..AdminSection::default()
        };
        let old = AdminCredentials::from_config(&admin).unwrap();
        let now = at("2026-11-13T12:00:00Z");
        let new = old
            .with_operators(&[
                // unchanged
                op("alice", "alice-token", AdminRole::Viewer),
                // role changed
                op("bob", "bob-token", AdminRole::Viewer),
                // digest changed
                op("carol", "carol-token-2", AdminRole::Admin),
                // expiry added
                expiring(
                    "dave",
                    "dave-token",
                    AdminRole::Viewer,
                    "2027-01-01T00:00:00Z",
                ),
                // added; erin removed
                op("frank", "frank-token", AdminRole::Operator),
            ])
            .unwrap();
        assert_eq!(
            old.changes_to(&new),
            OperatorChanges {
                added: vec!["frank".into()],
                removed: vec!["erin".into()],
                changed: vec!["bob".into(), "carol".into(), "dave".into()],
            }
        );
        assert_eq!(
            new.authenticate("legacy-token", now),
            Ok(AdminIdentity::legacy())
        );
        assert_eq!(
            new.authenticate("erin-token", now),
            Err(AuthFailure::Unknown)
        );
        assert_eq!(
            new.authenticate("carol-token", now),
            Err(AuthFailure::Unknown)
        );
        assert!(new.authenticate("carol-token-2", now).is_ok());
        assert_eq!(
            new.authenticate("bob-token", now).unwrap().role,
            AdminRole::Viewer
        );
        // Nothing changed: empty lists.
        assert_eq!(new.changes_to(&new), OperatorChanges::default());
        // The startup rules, against the token kept.
        let err = old
            .with_operators(&[op("x", "legacy-token", AdminRole::Viewer)])
            .unwrap_err()
            .to_string();
        assert!(err.contains("[admin] token"), "{err}");
        let err = old
            .with_operators(&[
                op("x", "a", AdminRole::Viewer),
                op("x", "b", AdminRole::Viewer),
            ])
            .unwrap_err()
            .to_string();
        assert!(err.contains("used twice"), "{err}");
        assert!(old
            .with_operators(&[op("admin", "a", AdminRole::Viewer)])
            .is_err());
    }

    #[test]
    fn a_live_admin_is_the_legacy_token_or_an_unexpired_admin_operator() {
        let now = at("2026-11-13T12:00:00Z");
        let none = AdminCredentials::default();
        assert!(!none.has_live_admin(now));
        let legacy = AdminCredentials::from_config(&AdminSection {
            token: Some("legacy-token".into()),
            ..AdminSection::default()
        })
        .unwrap();
        assert!(legacy.has_live_admin(now));
        // Without the legacy token: only viewers, an expired admin, then a live one.
        let empty = AdminCredentials::default();
        let viewers = empty
            .with_operators(&[
                op("v", "v", AdminRole::Viewer),
                op("o", "o", AdminRole::Operator),
            ])
            .unwrap();
        assert!(!viewers.has_live_admin(now));
        let expired = empty
            .with_operators(&[expiring("a", "a", AdminRole::Admin, "2026-11-13T12:00:00Z")])
            .unwrap();
        assert!(!expired.has_live_admin(now));
        let live = empty
            .with_operators(&[expiring("a", "a", AdminRole::Admin, "2026-11-13T12:00:01Z")])
            .unwrap();
        assert!(live.has_live_admin(now));
    }

    /// A snapshot taken before a swap keeps the old set; the next one sees the new set.
    #[test]
    fn a_snapshot_outlives_a_swap() {
        let now = OffsetDateTime::now_utc();
        let shared = SharedAdminCredentials::new(
            AdminCredentials::default()
                .with_operators(&[op("a", "a-token", AdminRole::Admin)])
                .unwrap(),
        );
        let before = shared.snapshot();
        let old = shared.swap(Arc::new(
            AdminCredentials::default()
                .with_operators(&[op("b", "b-token", AdminRole::Admin)])
                .unwrap(),
        ));
        assert!(before.authenticate("a-token", now).is_ok());
        assert!(old.authenticate("a-token", now).is_ok());
        assert_eq!(
            shared.snapshot().authenticate("a-token", now),
            Err(AuthFailure::Unknown)
        );
        assert!(shared.snapshot().authenticate("b-token", now).is_ok());
    }

    #[test]
    fn subjects_keep_the_legacy_form() {
        assert_eq!(AdminIdentity::legacy().subject(), "urn:attenuo:admin");
        let alice = AdminIdentity {
            name: "alice".into(),
            role: AdminRole::Viewer,
            expires_at: None,
        };
        assert_eq!(alice.subject(), "urn:attenuo:admin:alice");
        assert!(crate::routes::is_reserved_subject(&alice.subject()));
    }

    #[test]
    fn names_and_digests_are_checked() {
        for ok in ["a", "alice", "ops-1", "on_call", &"x".repeat(64)] {
            check_operator_name(ok).unwrap();
        }
        for bad in ["", "admin", "Alice", "a b", "a.b", "é", &"x".repeat(65)] {
            assert!(check_operator_name(bad).is_err(), "{bad:?}");
        }
        let good = token_sha256_hex("t");
        assert_eq!(parse_token_sha256(&good).unwrap(), token_sha256("t"));
        for bad in [
            String::new(),
            good[..63].to_string(),
            format!("{good}0"),
            good.to_uppercase(),
            "g".repeat(64),
        ] {
            let err = parse_token_sha256(&bad).unwrap_err();
            // The message never repeats the value.
            assert!(bad.is_empty() || !err.contains(&bad), "{err}");
        }
    }

    #[test]
    fn roles_are_ordered_and_parse() {
        assert!(AdminRole::Viewer < AdminRole::Operator && AdminRole::Operator < AdminRole::Admin);
        for r in [AdminRole::Viewer, AdminRole::Operator, AdminRole::Admin] {
            assert_eq!(AdminRole::parse(r.as_str()).unwrap(), r);
        }
        assert!(AdminRole::parse("root").is_err());
    }

    #[test]
    fn an_unlisted_route_needs_admin() {
        assert_eq!(
            required_role(&Method::GET, Some("/admin/audit")),
            AdminRole::Viewer
        );
        assert_eq!(
            required_role(&Method::HEAD, Some("/admin/audit")),
            AdminRole::Viewer
        );
        assert_eq!(
            required_role(&Method::POST, Some("/admin/approvals/{id}")),
            AdminRole::Operator
        );
        for (method, route) in [
            (Method::GET, Some("/admin/something-new")),
            (Method::DELETE, Some("/admin/audit")),
            (Method::POST, Some("/admin/audit")),
            (Method::GET, None),
        ] {
            assert_eq!(required_role(&method, route), AdminRole::Admin, "{route:?}");
        }
    }

    #[test]
    fn the_route_table_has_no_duplicates() {
        for (i, (m, p, _)) in ROUTE_ROLES.iter().enumerate() {
            assert!(
                !ROUTE_ROLES[..i]
                    .iter()
                    .any(|(m2, p2, _)| m == m2 && p == p2),
                "{m} {p} listed twice"
            );
        }
    }

    /// Every `.route("/admin/...", <method router>)` in the files that mount admin routes,
    /// as (method, path) pairs. The console's own asset routes (`/admin/ui...`) sit outside
    /// `require_admin` and are left out.
    fn mounted_admin_routes() -> Vec<(String, String)> {
        let sources = [include_str!("lib.rs"), include_str!("admin_ui.rs")];
        let mut out = Vec::new();
        for src in sources {
            let mut rest = src;
            while let Some(at) = rest.find(".route(") {
                rest = &rest[at + ".route(".len()..];
                let trimmed = rest.trim_start();
                let Some(after_quote) = trimmed.strip_prefix('"') else {
                    continue;
                };
                let Some(end) = after_quote.find('"') else {
                    continue;
                };
                let path = &after_quote[..end];
                if !path.starts_with("/admin/") || path.starts_with("/admin/ui") {
                    continue;
                }
                // The method router: up to the parenthesis that closes `.route(`.
                let body = &after_quote[end + 1..];
                let mut depth = 1usize;
                let mut close = body.len();
                for (i, ch) in body.char_indices() {
                    match ch {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                close = i;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let router = &body[..close];
                let mut methods = 0;
                for (token, method) in [
                    ("get(", "GET"),
                    ("post(", "POST"),
                    ("put(", "PUT"),
                    ("patch(", "PATCH"),
                    ("delete(", "DELETE"),
                ] {
                    let mut from = 0;
                    while let Some(i) = router[from..].find(token) {
                        let pos = from + i;
                        let before = router[..pos].chars().next_back();
                        if !before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                            out.push((method.to_string(), path.to_string()));
                            methods += 1;
                        }
                        from = pos + token.len();
                    }
                }
                assert!(methods > 0, "no method found for the route {path}");
            }
        }
        out
    }

    /// Fail closed is the fallback, not the plan: every admin route the server mounts has
    /// its own entry in [`ROUTE_ROLES`], and every entry is mounted somewhere.
    #[test]
    fn every_mounted_admin_route_has_an_explicit_role() {
        let mounted = mounted_admin_routes();
        // A sanity floor, so a parser that finds nothing cannot pass.
        assert!(mounted.len() >= ROUTE_ROLES.len(), "{mounted:?}");
        for (method, path) in &mounted {
            assert!(
                ROUTE_ROLES.iter().any(|(m, p, _)| m == method && p == path),
                "{method} {path} is mounted but has no entry in ROUTE_ROLES"
            );
        }
        for (m, p, _) in ROUTE_ROLES {
            assert!(
                mounted.iter().any(|(m2, p2)| m == m2 && p == p2),
                "{m} {p} is in ROUTE_ROLES but not mounted"
            );
        }
    }
}
