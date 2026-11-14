//! One paging style for every list route (audit finding K-7).
//!
//! `GET /admin/audit`, `GET /admin/audit/checkpoints` and `GET /admin/approvals` all take
//! `limit` and `cursor` and answer with their items and `next_cursor`:
//!
//! - `limit`: how many items a page holds at most. Each route documents its default and
//!   maximum; 0 or a value above the maximum is a 400 `invalid_request`, never clamped.
//! - `cursor`: the `next_cursor` of the previous page, sent back unchanged together with the
//!   same filters and `order`. Omitted for the first page.
//! - `next_cursor`: a string to fetch the following page with, or `null` when there is
//!   nothing after this page. A page can hold fewer than `limit` items (a filtered audit page
//!   reads a bounded range of the log) while `next_cursor` is still set: keep following it
//!   until it is `null`.
//!
//! **Format.** A cursor is the unpadded base64url form of 11 bytes: a format version (1), the
//! list it belongs to, the direction it pages in, and a position (`u64`, big-endian). The
//! position is the keyset key of the list, never an offset: the next seq to read for the
//! audit log oldest first, the seq bound below which to read for newest first, the checkpoint
//! seq bound for checkpoints, and the store's approval position (see
//! `attenuo_audit::ApprovalStore::approvals`) for approvals. Items appended or created while a
//! client pages therefore never shift the items it has not read yet, so each item that
//! existed when paging started is returned exactly once.
//!
//! **Validation.** A cursor that is not base64url, has another length or version, names
//! another list or another direction, or carries position 0 is a 400 `invalid_cursor`. The
//! `detail` says which check failed and never quotes the cursor.
//!
//! **No integrity tag.** An admin list cursor holds only a position in a list the caller is
//! already allowed to read in full, not a subject, a filter value, a query or anything else
//! from the data. Forging one can only start a page at another position, which the caller
//! could reach anyway by paging, so a MAC would protect nothing; what is checked is that it
//! is well-formed and meant for this list. Clients must still treat it as opaque: the
//! encoding may change in another format version.
//!
//! **Action search** (`POST /access/v1/search/action`) carries a longer cursor as AuthZEN's
//! `page.token` / `page.next_token` (format version 1, list 4, 35 bytes, 47 characters): the
//! same 11 bytes, whose position is an offset into the sorted candidate tools rather than a
//! keyset key, followed by a [`SearchBinding`] of 24 bytes, three 8-byte truncated SHA-256
//! digests of the query the token was issued for: the delegation chain the search is
//! evaluated for, the MCP server it names, and its `context` (RFC 8785 canonical JSON). AuthZEN
//! 1.0 section 8.2 says a PDP should refuse a page token sent with a changed request; the
//! server recomputes the digests from the presented request and refuses a token whose digests
//! differ ([`SearchCursor::position_for`]). `page.limit` is not bound: a client may change the
//! page size between pages. Neither is the policy or the catalog, which may be reloaded
//! between pages (8.2 allows repeats or skips then). The digests are not a MAC either, for
//! the reason above: they are computed from the request alone, so a caller able to compute
//! them could have sent that request anyway, and a forged token still only moves the caller
//! within the candidates of its own query. The token holds no chain, server or context data,
//! only the digests. Its `limit` is clamped to `[authzen] max_batch` rather than refused,
//! because a generic AuthZEN client cannot know the maximum.

use attenuo_core::DelegationChain;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::ApiError;

/// `error` of a refused `cursor`.
pub const INVALID_CURSOR: &str = "invalid_cursor";

/// The cursor format this server writes and reads.
const CURSOR_VERSION: u8 = 1;
/// Bytes of an encoded-then-decoded cursor: version, list, direction, position.
const CURSOR_BYTES: usize = 11;
/// Bytes of one digest of a [`SearchBinding`].
const BINDING_PART: usize = 8;
/// Bytes of a [`SearchBinding`]: the chain, server and context digests.
const BINDING_BYTES: usize = 3 * BINDING_PART;
/// Bytes of an action search cursor: a cursor, then its [`SearchBinding`].
const BOUND_CURSOR_BYTES: usize = CURSOR_BYTES + BINDING_BYTES;
/// Longest `cursor` value read at all (an admin list cursor is 15 characters, an action
/// search cursor 47).
const MAX_CURSOR_CHARS: usize = 64;

/// The list a cursor belongs to; a cursor of one list is refused by another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum List {
    /// `GET /admin/audit`.
    Audit = 1,
    /// `GET /admin/audit/checkpoints`.
    Checkpoints = 2,
    /// `GET /admin/approvals`.
    Approvals = 3,
    /// `POST /access/v1/search/action`, whose `page.token` is a cursor of this format followed
    /// by a [`SearchBinding`]: the position is the index of the next candidate tool, an offset
    /// (see `routes::authzen::search_action`).
    ActionSearch = 4,
}

impl List {
    /// Bytes of a decoded cursor of this list: action search cursors carry a
    /// [`SearchBinding`] after the position.
    fn cursor_bytes(self) -> usize {
        match self {
            Self::ActionSearch => BOUND_CURSOR_BYTES,
            Self::Audit | Self::Checkpoints | Self::Approvals => CURSOR_BYTES,
        }
    }
}

/// The direction a cursor pages in; one written for `order=asc` is refused with `order=desc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Oldest first: the position is the first key of the next page.
    Ascending = 1,
    /// Newest first: the position is the key every item of the next page is below.
    Descending = 2,
}

impl Direction {
    fn name(self) -> &'static str {
        match self {
            Self::Ascending => "asc",
            Self::Descending => "desc",
        }
    }
}

/// The opaque `next_cursor` for `position` in `list`, paging in `dir`.
///
/// # Panics
///
/// For [`List::ActionSearch`], whose cursors are made by [`encode_search`].
pub fn encode(list: List, dir: Direction, position: u64) -> String {
    assert_eq!(
        list.cursor_bytes(),
        CURSOR_BYTES,
        "{list:?} cursors carry a binding"
    );
    URL_SAFE_NO_PAD.encode(head(list, dir, position))
}

/// The opaque `page.next_token` of action search for the candidate at `position`, bound to
/// the query `binding` digests.
pub fn encode_search(position: u64, binding: &SearchBinding) -> String {
    let mut bytes = [0u8; BOUND_CURSOR_BYTES];
    bytes[..CURSOR_BYTES].copy_from_slice(&head(
        List::ActionSearch,
        Direction::Ascending,
        position,
    ));
    bytes[CURSOR_BYTES..].copy_from_slice(&binding.0);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The version, list, direction and position bytes every cursor starts with.
fn head(list: List, dir: Direction, position: u64) -> [u8; CURSOR_BYTES] {
    let mut bytes = [0u8; CURSOR_BYTES];
    bytes[0] = CURSOR_VERSION;
    bytes[1] = list as u8;
    bytes[2] = dir as u8;
    bytes[3..].copy_from_slice(&position.to_be_bytes());
    bytes
}

/// The position in a `cursor` the client sent, checked to belong to `list` and `dir`.
/// `Ok(None)` when no cursor was sent.
///
/// # Errors
///
/// 400 [`INVALID_CURSOR`] for an empty, malformed, foreign or zero-position cursor.
///
/// # Panics
///
/// For [`List::ActionSearch`], whose cursors are read by [`decode_search`].
pub fn decode(cursor: Option<&str>, list: List, dir: Direction) -> Result<Option<u64>, ApiError> {
    assert_eq!(
        list.cursor_bytes(),
        CURSOR_BYTES,
        "{list:?} cursors carry a binding"
    );
    Ok(decode_bytes("cursor", cursor, list, dir)?.map(|(p, _)| p))
}

/// An action search `page.token` as sent, read but not yet checked against the request
/// ([`SearchCursor::position_for`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchCursor {
    position: u64,
    binding: SearchBinding,
}

impl SearchCursor {
    /// The position this token holds, once its binding is checked to equal `expected`, the
    /// binding of the request it was sent with.
    ///
    /// # Errors
    ///
    /// 400 [`INVALID_CURSOR`] when the token was issued for another chain, server or
    /// `context`; the `detail` names which, and quotes neither the token nor the request.
    pub fn position_for(&self, expected: &SearchBinding) -> Result<u64, ApiError> {
        if let Some(what) = self.binding.differs_from(expected) {
            return Err(ApiError::bad_request(
                INVALID_CURSOR,
                format!(
                    "`page.token` was issued for a search with another {what}; send it with the \
                     request it came from, or leave it out to start again from the first page"
                ),
            ));
        }
        Ok(self.position)
    }
}

/// An action search `page.token` (named `field` in a refusal), read and checked for shape,
/// list and position, but not yet against the request. `Ok(None)` when none was sent.
///
/// # Errors
///
/// 400 [`INVALID_CURSOR`] as [`decode`], including a token in the shorter format of an admin
/// list cursor (which action search tokens had before they were bound to their query).
pub fn decode_search(field: &str, cursor: Option<&str>) -> Result<Option<SearchCursor>, ApiError> {
    Ok(
        decode_bytes(field, cursor, List::ActionSearch, Direction::Ascending)?.map(
            |(position, rest)| {
                let mut binding = [0u8; BINDING_BYTES];
                binding.copy_from_slice(&rest);
                SearchCursor {
                    position,
                    binding: SearchBinding(binding),
                }
            },
        ),
    )
}

/// The checks every cursor goes through, for a cursor sent in a member named `field`: the
/// position, and the bytes after it (a [`SearchBinding`] for action search, else none).
fn decode_bytes(
    field: &str,
    cursor: Option<&str>,
    list: List,
    dir: Direction,
) -> Result<Option<(u64, Vec<u8>)>, ApiError> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    let refuse = |why: &str| ApiError::bad_request(INVALID_CURSOR, format!("`{field}` {why}"));
    if cursor.is_empty() {
        return Err(refuse("must not be empty; leave it out for the first page"));
    }
    let bytes = (cursor.len() <= MAX_CURSOR_CHARS)
        .then(|| URL_SAFE_NO_PAD.decode(cursor).ok())
        .flatten()
        .filter(|b| b.len() == CURSOR_BYTES || b.len() == BOUND_CURSOR_BYTES)
        .ok_or_else(|| refuse("is not a cursor this server issued"))?;
    if bytes[0] != CURSOR_VERSION {
        return Err(refuse("has a format version this server does not read"));
    }
    if bytes[1] != list as u8 {
        return Err(refuse(
            "belongs to another list; send the `next_cursor` of this route",
        ));
    }
    if bytes.len() != list.cursor_bytes() {
        return Err(refuse("is not a cursor this server issued"));
    }
    if bytes[2] != dir as u8 {
        let other = match dir {
            Direction::Ascending => Direction::Descending,
            Direction::Descending => Direction::Ascending,
        };
        return Err(refuse(&format!(
            "was issued for `order={}`; send the same `order` with it",
            other.name()
        )));
    }
    let mut pos = [0u8; 8];
    pos.copy_from_slice(&bytes[3..CURSOR_BYTES]);
    match u64::from_be_bytes(pos) {
        0 => Err(refuse("is not a cursor this server issued")),
        p => Ok(Some((p, bytes[CURSOR_BYTES..].to_vec()))),
    }
}

/// What an action search `page.token` is bound to: truncated SHA-256 digests of the
/// delegation chain the search is evaluated for, of the MCP server it names, and of its
/// `context`, each over the RFC 8785 canonical JSON of a label and the value. Digests, never
/// the values, so a token carries no chain, server or context data.
///
/// The whole chain is bound, not only its run (root lease): it fixes the run, every hop, the
/// current agent (which `subject.id` must equal) and the effective capabilities (which decide
/// the candidate list), so `subject` needs no binding of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchBinding([u8; BINDING_BYTES]);

impl SearchBinding {
    /// The binding of a search for `chain`, on `server`, with `context` (absent is `null`).
    pub fn new(chain: &DelegationChain, server: &str, context: Option<&Value>) -> Self {
        let mut bytes = [0u8; BINDING_BYTES];
        let context = context.unwrap_or(&Value::Null);
        bytes[..BINDING_PART].copy_from_slice(&part("chain", chain));
        bytes[BINDING_PART..2 * BINDING_PART].copy_from_slice(&part("server", server));
        bytes[2 * BINDING_PART..].copy_from_slice(&part("context", context));
        Self(bytes)
    }

    /// The first member `self` was issued for that differs in `other`, named for a `detail`.
    fn differs_from(&self, other: &Self) -> Option<&'static str> {
        let names = [
            "subject (delegation chain)",
            "resource (MCP server)",
            "context",
        ];
        self.0
            .chunks(BINDING_PART)
            .zip(other.0.chunks(BINDING_PART))
            .zip(names)
            .find(|((a, b), _)| a != b)
            .map(|(_, name)| name)
    }
}

/// The first [`BINDING_PART`] bytes of SHA-256 over the canonical JSON of `[label, value]`.
fn part<T: Serialize + ?Sized>(label: &str, value: &T) -> [u8; BINDING_PART] {
    let label = format!("attenuo/search-action/page.token/{label}");
    // Nothing decoded from JSON, and no chain, lacks a canonical form (see
    // `attenuo_core::digest::sha256_json`).
    let bytes = attenuo_core::jcs::to_vec(&(label.as_str(), value))
        .expect("a search request has a canonical JSON form");
    let digest = Sha256::digest(&bytes);
    let mut out = [0u8; BINDING_PART];
    out.copy_from_slice(&digest[..BINDING_PART]);
    out
}

/// The page size from a request's `limit`: `default` when absent.
///
/// # Errors
///
/// 400 `invalid_request` when `limit` is 0 or above `max`.
pub fn limit(requested: Option<usize>, default: usize, max: usize) -> Result<usize, ApiError> {
    match requested {
        None => Ok(default),
        Some(n) if (1..=max).contains(&n) => Ok(n),
        Some(_) => Err(ApiError::bad_request(
            "invalid_request",
            format!("`limit` must be between 1 and {max}"),
        )),
    }
}

/// A 400 for a paging parameter this server no longer reads, naming what replaced it, so an
/// old client is told instead of silently getting the first page again.
pub fn removed(name: &str, instead: &str) -> ApiError {
    ApiError::bad_request(
        "invalid_request",
        format!("`{name}` was removed; {instead}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(e: &ApiError) -> &str {
        &e.code
    }

    #[test]
    fn round_trip_and_opaque_shape() {
        for list in [List::Audit, List::Checkpoints, List::Approvals] {
            for dir in [Direction::Ascending, Direction::Descending] {
                for pos in [1, 2, 4096, u64::MAX] {
                    let c = encode(list, dir, pos);
                    assert_eq!(c.len(), 15);
                    assert!(c
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
                    assert_eq!(decode(Some(&c), list, dir).unwrap(), Some(pos));
                }
            }
        }
        assert_eq!(
            decode(None, List::Audit, Direction::Ascending).unwrap(),
            None
        );
    }

    #[test]
    fn foreign_and_malformed_cursors_are_refused() {
        let asc = encode(List::Audit, Direction::Ascending, 7);
        let mut bad: Vec<String> = vec![
            String::new(),
            "not base64!".into(),
            "AAAA".into(),
            "x".repeat(65),
            encode(List::Approvals, Direction::Ascending, 7),
            encode(List::Audit, Direction::Descending, 7),
            URL_SAFE_NO_PAD.encode([0u8; CURSOR_BYTES]),
            // Padded, or one byte too long.
            format!("{asc}="),
            URL_SAFE_NO_PAD.encode([1u8; CURSOR_BYTES + 1]),
        ];
        let mut v2 = URL_SAFE_NO_PAD.decode(&asc).unwrap();
        v2[0] = 2;
        bad.push(URL_SAFE_NO_PAD.encode(&v2));
        let mut zero = v2.clone();
        zero[0] = 1;
        zero[3..].fill(0);
        bad.push(URL_SAFE_NO_PAD.encode(&zero));
        for c in &bad {
            let e = decode(Some(c), List::Audit, Direction::Ascending).unwrap_err();
            assert_eq!(code(&e), INVALID_CURSOR, "{c:?}");
            assert!(c.is_empty() || !e.detail.contains(c.as_str()), "{c:?}");
        }
        let e = decode(
            Some(&encode(List::Audit, Direction::Descending, 3)),
            List::Audit,
            Direction::Ascending,
        )
        .unwrap_err();
        assert!(e.detail.contains("order=desc"), "{}", e.detail);
    }

    fn chain(lease: &str) -> DelegationChain {
        use attenuo_core::{AgentId, Capability, CapabilitySet, LeaseId, OriginatingUser};
        let now = time::OffsetDateTime::UNIX_EPOCH;
        DelegationChain::root(
            OriginatingUser {
                subject: "alice".into(),
                issuer: "idp".into(),
                authenticated_at: now,
                attributes: Default::default(),
            },
            AgentId::new("planner"),
            CapabilitySet::from_iter([Capability::new("github", "*")]),
            now,
            time::Duration::hours(1),
            LeaseId::new(lease),
        )
        .unwrap()
    }

    #[test]
    fn search_tokens_round_trip_bound_to_their_query() {
        let ctx = serde_json::json!({"input": {"repo": "acme/api"}, "session_id": "s1"});
        let b = SearchBinding::new(&chain("L1"), "github", Some(&ctx));
        for pos in [1, 2, 4096, u64::MAX] {
            let t = encode_search(pos, &b);
            assert_eq!(t.len(), 47);
            assert!(t
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
            // Only digests: no chain, server or context data in the token.
            let raw = URL_SAFE_NO_PAD.decode(&t).unwrap();
            for needle in [&b"github"[..], b"acme", b"planner", b"L1", b"s1"] {
                assert!(!raw.windows(needle.len()).any(|w| w == needle));
            }
            let c = decode_search("page.token", Some(&t)).unwrap().unwrap();
            assert_eq!(c.position_for(&b).unwrap(), pos);
        }
        assert_eq!(decode_search("page.token", None).unwrap(), None);
        // Member order and an absent versus a null context do not change the binding.
        let reordered: Value =
            serde_json::from_str(r#"{"session_id":"s1","input":{"repo":"acme/api"}}"#).unwrap();
        assert_eq!(
            b,
            SearchBinding::new(&chain("L1"), "github", Some(&reordered))
        );
        assert_eq!(
            SearchBinding::new(&chain("L1"), "github", None),
            SearchBinding::new(&chain("L1"), "github", Some(&Value::Null))
        );
    }

    #[test]
    fn search_tokens_of_another_query_are_refused_naming_what_differs() {
        let ctx = serde_json::json!({"input": {"repo": "acme/api"}});
        let issued = SearchBinding::new(&chain("L1"), "github", Some(&ctx));
        let token = encode_search(3, &issued);
        let cursor = decode_search("page.token", Some(&token)).unwrap().unwrap();
        let other_ctx = serde_json::json!({"input": {"repo": "acme/web"}});
        for (presented, what) in [
            (
                SearchBinding::new(&chain("L2"), "github", Some(&ctx)),
                "subject",
            ),
            (
                SearchBinding::new(&chain("L1"), "gitlab", Some(&ctx)),
                "resource",
            ),
            (
                SearchBinding::new(&chain("L1"), "github", Some(&other_ctx)),
                "context",
            ),
            (SearchBinding::new(&chain("L1"), "github", None), "context"),
        ] {
            let e = cursor.position_for(&presented).unwrap_err();
            assert_eq!(code(&e), INVALID_CURSOR);
            assert!(
                e.detail.contains(&format!("another {what}")),
                "{}",
                e.detail
            );
            assert!(!e.detail.contains(&token), "{}", e.detail);
            assert!(!e.detail.contains("acme"), "{}", e.detail);
        }
    }

    #[test]
    fn search_and_admin_cursors_do_not_cross() {
        // An action search token from before tokens were bound: the 11-byte admin format.
        let old = URL_SAFE_NO_PAD.encode(head(List::ActionSearch, Direction::Ascending, 2));
        assert_eq!(old, "AQQBAAAAAAAAAAI");
        let e = decode_search("page.token", Some(&old)).unwrap_err();
        assert_eq!(code(&e), INVALID_CURSOR);
        assert!(e.detail.contains("not a cursor this server issued"));
        // A search token is refused by every admin list, and an admin cursor by search.
        let b = SearchBinding::new(&chain("L1"), "github", None);
        let search = encode_search(2, &b);
        for list in [List::Audit, List::Checkpoints, List::Approvals] {
            for dir in [Direction::Ascending, Direction::Descending] {
                let e = decode(Some(&search), list, dir).unwrap_err();
                assert_eq!(code(&e), INVALID_CURSOR);
                let admin = encode(list, dir, 2);
                let e = decode_search("page.token", Some(&admin)).unwrap_err();
                assert_eq!(code(&e), INVALID_CURSOR);
                assert!(e.detail.contains("another list"), "{}", e.detail);
            }
        }
        // An admin-length cursor body under a search token's list byte, or the reverse.
        let mut long = URL_SAFE_NO_PAD.decode(&search).unwrap();
        long[1] = List::Audit as u8;
        let e = decode(
            Some(&URL_SAFE_NO_PAD.encode(&long)),
            List::Audit,
            Direction::Ascending,
        )
        .unwrap_err();
        assert!(e.detail.contains("not a cursor this server issued"));
        // A zero position is refused as for every list.
        let zero = encode_search(0, &b);
        assert!(decode_search("page.token", Some(&zero)).is_err());
    }

    #[test]
    fn admin_cursor_format_is_unchanged() {
        // The exact bytes of an admin cursor, as clients holding one from before see them.
        assert_eq!(
            encode(List::Audit, Direction::Ascending, 1),
            "AQEBAAAAAAAAAAE"
        );
        assert_eq!(
            encode(List::Approvals, Direction::Descending, 258),
            URL_SAFE_NO_PAD.encode([1, 3, 2, 0, 0, 0, 0, 0, 0, 1, 2])
        );
    }

    #[test]
    #[should_panic(expected = "carry a binding")]
    fn search_cursors_need_their_binding() {
        let _ = encode(List::ActionSearch, Direction::Ascending, 1);
    }

    #[test]
    fn limit_bounds_are_refused_not_clamped() {
        assert_eq!(limit(None, 100, 1000).unwrap(), 100);
        assert_eq!(limit(Some(1), 100, 1000).unwrap(), 1);
        assert_eq!(limit(Some(1000), 100, 1000).unwrap(), 1000);
        for n in [0, 1001, usize::MAX] {
            let e = limit(Some(n), 100, 1000).unwrap_err();
            assert_eq!(code(&e), "invalid_request");
            assert!(e.detail.contains("between 1 and 1000"));
        }
    }
}
