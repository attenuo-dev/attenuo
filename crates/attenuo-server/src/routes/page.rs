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
//! **No integrity tag.** A cursor holds only a position in a list the caller is already
//! allowed to read in full (every admin list route; for AuthZEN action search, the candidate
//! tools of the caller's own query), not a subject, a filter value, a query or anything else
//! from the data. Forging one can only start a page at another position, which the caller
//! could reach anyway by paging, so a MAC would protect nothing; what is checked is that it
//! is well-formed and meant for this list. Clients must still treat it as opaque: the
//! encoding may change in another format version.
//!
//! **Action search** (`POST /access/v1/search/action`) carries the same cursor as AuthZEN's
//! `page.token` / `page.next_token`, but its position is an offset into the sorted candidate
//! tools, not a keyset key, and its `limit` is clamped to `[authzen] max_batch` rather than
//! refused, because a generic AuthZEN client cannot know the maximum.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::error::ApiError;

/// `error` of a refused `cursor`.
pub const INVALID_CURSOR: &str = "invalid_cursor";

/// The cursor format this server writes and reads.
const CURSOR_VERSION: u8 = 1;
/// Bytes of an encoded-then-decoded cursor: version, list, direction, position.
const CURSOR_BYTES: usize = 11;
/// Longest `cursor` value read at all (a version 1 cursor is 15 characters).
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
    /// `POST /access/v1/search/action`, whose `page.token` is a cursor of this format: the
    /// position is the index of the next candidate tool, an offset (see
    /// `routes::authzen::search_action`).
    ActionSearch = 4,
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
pub fn encode(list: List, dir: Direction, position: u64) -> String {
    let mut bytes = [0u8; CURSOR_BYTES];
    bytes[0] = CURSOR_VERSION;
    bytes[1] = list as u8;
    bytes[2] = dir as u8;
    bytes[3..].copy_from_slice(&position.to_be_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The position in a `cursor` the client sent, checked to belong to `list` and `dir`.
/// `Ok(None)` when no cursor was sent.
///
/// # Errors
///
/// 400 [`INVALID_CURSOR`] for an empty, malformed, foreign or zero-position cursor.
pub fn decode(cursor: Option<&str>, list: List, dir: Direction) -> Result<Option<u64>, ApiError> {
    decode_named("cursor", cursor, list, dir)
}

/// [`decode`] for a cursor sent in a member named `field` (`page.token` for AuthZEN search),
/// which the refusal's `detail` names.
///
/// # Errors
///
/// As [`decode`].
pub fn decode_named(
    field: &str,
    cursor: Option<&str>,
    list: List,
    dir: Direction,
) -> Result<Option<u64>, ApiError> {
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
        .filter(|b| b.len() == CURSOR_BYTES)
        .ok_or_else(|| refuse("is not a cursor this server issued"))?;
    if bytes[0] != CURSOR_VERSION {
        return Err(refuse("has a format version this server does not read"));
    }
    if bytes[1] != list as u8 {
        return Err(refuse(
            "belongs to another list; send the `next_cursor` of this route",
        ));
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
    pos.copy_from_slice(&bytes[3..]);
    match u64::from_be_bytes(pos) {
        0 => Err(refuse("is not a cursor this server issued")),
        p => Ok(Some(p)),
    }
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
        for list in [
            List::Audit,
            List::Checkpoints,
            List::Approvals,
            List::ActionSearch,
        ] {
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
