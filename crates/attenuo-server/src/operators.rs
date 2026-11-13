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
//! constant time against every credential, without stopping at a match. The route a request
//! may reach is decided by [`required_role`], from the one table [`ROUTE_ROLES`]; a route
//! missing from the table requires [`AdminRole::Admin`].
//!
//! Plain SHA-256 is enough here because the tokens are not passwords: the CLI generates them
//! from 32 random bytes, so there is nothing for a slow hash to protect against guessing.

use std::fmt;

use axum::http::Method;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
}

impl AdminIdentity {
    /// The identity of `[admin] token`.
    pub fn legacy() -> Self {
        Self {
            name: LEGACY_OPERATOR.to_string(),
            role: AdminRole::Admin,
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

struct Credential {
    identity: AdminIdentity,
    sha256: [u8; 32],
}

/// Every admin credential the server accepts, by the SHA-256 of its token. Built once at
/// startup ([`AdminCredentials::from_config`]); a change takes a restart.
#[derive(Default)]
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
        for op in &admin.operators {
            let sha256 = parse_token_sha256(&op.token_sha256)
                .map_err(|e| anyhow::anyhow!("[[admin.operators]] `{}`: {e}", op.name))?;
            creds.push(Credential {
                identity: AdminIdentity {
                    name: op.name.clone(),
                    role: op.role,
                },
                sha256,
            });
        }
        Ok(Self { creds })
    }

    /// No credential is configured: the admin API answers 403 `admin_disabled`.
    pub fn is_empty(&self) -> bool {
        self.creds.is_empty()
    }

    /// The identity whose token is `token`, or `None`.
    ///
    /// The token is hashed once, and the digest is compared with every credential in constant
    /// time; the loop never stops early, so the time taken does not tell which credential
    /// matched or whether one did. The startup check refuses two credentials with one digest,
    /// so at most one matches.
    pub fn authenticate(&self, token: &str) -> Option<AdminIdentity> {
        let presented = token_sha256(token);
        // 1 + the index of the match, 0 for none, selected without a branch on the result.
        let mut found = 0usize;
        for (i, c) in self.creds.iter().enumerate() {
            let hit = usize::from(ct_eq32(&presented, &c.sha256));
            found |= hit.wrapping_neg() & (i + 1);
        }
        found
            .checked_sub(1)
            .and_then(|i| self.creds.get(i))
            .map(|c| c.identity.clone())
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
/// - admin: everything else (policy reload, budget refunds, the dev root mint).
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
    ("POST", "/admin/root-token", AdminRole::Admin),
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
        assert_eq!(
            creds.authenticate("legacy-token"),
            Some(AdminIdentity::legacy())
        );
        let alice = creds.authenticate("alice-token").unwrap();
        assert_eq!(
            (alice.name.as_str(), alice.role),
            ("alice", AdminRole::Viewer)
        );
        let bob = creds.authenticate("bob-token").unwrap();
        assert_eq!((bob.name.as_str(), bob.role), ("bob", AdminRole::Operator));
        for wrong in ["", "alice", "alice-token ", "Legacy-token"] {
            assert_eq!(creds.authenticate(wrong), None, "{wrong:?}");
        }
        assert!(AdminCredentials::default().authenticate("x").is_none());
        // Debug shows names and roles, never a digest.
        let shown = format!("{creds:?}");
        assert!(shown.contains("alice") && !shown.contains(&token_sha256_hex("alice-token")));
    }

    #[test]
    fn subjects_keep_the_legacy_form() {
        assert_eq!(AdminIdentity::legacy().subject(), "urn:attenuo:admin");
        let alice = AdminIdentity {
            name: "alice".into(),
            role: AdminRole::Viewer,
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
