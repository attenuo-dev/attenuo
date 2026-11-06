//! Server and tool names: what they may contain, checked once at every boundary.
//!
//! The Cedar resource id of a call is `"<server>/<tool>"` and its action id is
//! `Action::"<server>/<tool>"`, so a name must never be able to make two different
//! `(server, tool)` pairs look alike (SR-13), and two spellings of one name must never reach
//! different rules (SR-25). The rules:
//!
//! - A **segment** is 1 or more ASCII letters, digits, `_`, `.` or `-` (`[A-Za-z0-9_.-]+`).
//!   No spaces, no `/`, no `:` (the capability separator), no `*` (the glob), no control
//!   characters and nothing outside ASCII, so there are no look-alike or differently
//!   normalized forms of one name.
//! - A **server name** is one segment.
//! - A **tool name**, as an MCP server lists it in `tools/list` and a client sends it in
//!   `tools/call` `params.name`, is one segment. This is the character set the MCP
//!   specification recommends for tool names.
//! - A **call name** is what [`ToolCall::tool`](crate::ToolCall::tool) and a capability's `tool`
//!   hold: a tool name, or an MCP method name made of segments joined by single `/`
//!   (`resources/read`, `prompts/get`, `vendor/x`), which the proxy uses for methods other than
//!   `tools/call`. A `tools/call` can never produce such a name, because its `params.name` must
//!   be a tool name, so a tool cannot pose as a method.
//!
//! With no `/` in server names, `"<server>/<call name>"` splits at its first `/` into exactly
//! one pair.
//!
//! Every name is at most [`MAX_NAME_LEN`] bytes.
//!
//! Names are compared exactly (case-sensitively, byte for byte). Nothing is normalized:
//! `Delete_Repo` and `delete_repo` are different names. An upstream that resolves names
//! case-insensitively could still run `delete_repo` for a call to `Delete_Repo`; the proxy
//! closes that by refusing a `tools/call` whose name the upstream did not list
//! (`[proxy] require_listed_tools`).

use serde::{Deserialize, Serialize};

/// Longest server, tool or call name accepted, in bytes.
pub const MAX_NAME_LEN: usize = 128;

/// Which kind of name a [`NameError`] is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameKind {
    /// An MCP server (upstream) name.
    Server,
    /// A tool name, or a call name such as `resources/read`.
    Tool,
}

impl std::fmt::Display for NameKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            NameKind::Server => "server",
            NameKind::Tool => "tool",
        })
    }
}

/// Why a name was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    /// The name is the empty string.
    #[error("{kind} name is empty")]
    Empty {
        /// What sort of name it is.
        kind: NameKind,
    },
    /// The name is longer than [`MAX_NAME_LEN`] bytes.
    #[error("{kind} name is longer than {MAX_NAME_LEN} bytes")]
    TooLong {
        /// What sort of name it is.
        kind: NameKind,
    },
    /// A character outside the allowed set (see the module docs). `name` is the offending
    /// name, escaped for display.
    #[error("{kind} name {name} contains {found}, which is not allowed")]
    InvalidChar {
        /// What sort of name it is.
        kind: NameKind,
        /// The refused name, escaped for display.
        name: String,
        /// The first character outside the allowed set, escaped for display.
        found: String,
    },
}

/// Is `c` allowed inside one name segment: `[A-Za-z0-9_.-]`?
pub fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')
}

fn invalid(kind: NameKind, name: &str, c: char) -> NameError {
    NameError::InvalidChar {
        kind,
        name: format!("{name:?}"),
        found: format!("{c:?}"),
    }
}

fn check_len(kind: NameKind, name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty { kind });
    }
    if name.len() > MAX_NAME_LEN {
        return Err(NameError::TooLong { kind });
    }
    Ok(())
}

fn check_segment_chars(kind: NameKind, name: &str, segment: &str) -> Result<(), NameError> {
    match segment.chars().find(|c| !is_name_char(*c)) {
        Some(c) => Err(invalid(kind, name, c)),
        None => Ok(()),
    }
}

/// Check a server name: one segment of allowed characters, 1 to [`MAX_NAME_LEN`] bytes.
///
/// # Errors
///
/// [`NameError::Empty`], [`NameError::TooLong`], or [`NameError::InvalidChar`] for the first
/// character outside `[A-Za-z0-9_.-]` (a `/` included).
pub fn check_server_name(name: &str) -> Result<(), NameError> {
    check_len(NameKind::Server, name)?;
    check_segment_chars(NameKind::Server, name, name)
}

/// Check a tool name as MCP carries it (`tools/list`, `tools/call`): one segment, no `/`.
///
/// # Errors
///
/// [`NameError::Empty`], [`NameError::TooLong`], or [`NameError::InvalidChar`] for the first
/// character outside `[A-Za-z0-9_.-]` (a `/` included).
pub fn check_tool_name(name: &str) -> Result<(), NameError> {
    check_len(NameKind::Tool, name)?;
    check_segment_chars(NameKind::Tool, name, name)
}

/// Check a call name: a tool name, or method-style segments joined by single `/`.
///
/// # Errors
///
/// [`NameError::Empty`] or [`NameError::TooLong`]; [`NameError::InvalidChar`] reporting `/`
/// for an empty segment (a leading, trailing or doubled `/`), or the first other character
/// outside the set.
pub fn check_call_name(name: &str) -> Result<(), NameError> {
    check_len(NameKind::Tool, name)?;
    for segment in name.split('/') {
        if segment.is_empty() {
            return Err(invalid(NameKind::Tool, name, '/'));
        }
        check_segment_chars(NameKind::Tool, name, segment)?;
    }
    Ok(())
}

/// Check a capability's server pattern: `*`, `<prefix>*`, or a server name.
///
/// # Errors
///
/// [`NameError::Empty`] or [`NameError::TooLong`]; [`NameError::InvalidChar`] for a `*`
/// before the end or any character outside the server name set. `*` alone never fails.
pub fn check_server_pattern(pattern: &str) -> Result<(), NameError> {
    check_pattern(NameKind::Server, pattern, |p| {
        check_segment_chars(NameKind::Server, pattern, p)
    })
}

/// Check a capability's tool pattern: `*`, `<prefix>*`, or a call name. A prefix may end in
/// `/` (`resources/*`).
///
/// # Errors
///
/// [`NameError::Empty`] or [`NameError::TooLong`]; [`NameError::InvalidChar`] for a `*`
/// before the end, an empty segment other than the tail after a trailing `/`, or a character
/// outside the name set. `*` alone never fails.
pub fn check_call_pattern(pattern: &str) -> Result<(), NameError> {
    check_pattern(NameKind::Tool, pattern, |prefix| {
        for (i, segment) in prefix.split('/').enumerate() {
            // An empty segment is only fine as the (empty) tail after a trailing `/`.
            let last = i == prefix.split('/').count() - 1;
            if segment.is_empty() && !(last && i > 0) {
                return Err(invalid(NameKind::Tool, pattern, '/'));
            }
            check_segment_chars(NameKind::Tool, pattern, segment)?;
        }
        Ok(())
    })
}

fn check_pattern(
    kind: NameKind,
    pattern: &str,
    prefix_ok: impl Fn(&str) -> Result<(), NameError>,
) -> Result<(), NameError> {
    if pattern == "*" {
        return Ok(());
    }
    check_len(kind, pattern)?;
    match pattern.strip_suffix('*') {
        Some(prefix) => {
            if prefix.contains('*') {
                return Err(invalid(kind, pattern, '*'));
            }
            prefix_ok(prefix)
        }
        None => match kind {
            NameKind::Server => check_server_name(pattern),
            NameKind::Tool => check_call_name(pattern),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash_is_refused_in_server_and_tool_names() {
        assert!(check_server_name("github").is_ok());
        assert!(matches!(
            check_server_name("a/b"),
            Err(NameError::InvalidChar { .. })
        ));
        assert!(check_tool_name("read_file").is_ok());
        assert!(check_tool_name("resources/read").is_err());
        assert!(check_tool_name("").is_err());
        assert!(check_server_name("").is_err());
        assert!(check_tool_name(&"x".repeat(MAX_NAME_LEN)).is_ok());
        assert_eq!(
            check_tool_name(&"x".repeat(MAX_NAME_LEN + 1)),
            Err(NameError::TooLong {
                kind: NameKind::Tool
            })
        );
    }

    #[test]
    fn call_names_allow_method_segments_only() {
        for ok in [
            "read_file",
            "resources/read",
            "notifications/resources/list_changed",
        ] {
            assert!(check_call_name(ok).is_ok(), "{ok}");
        }
        for bad in ["/read", "read/", "a//b", "/", ""] {
            assert!(check_call_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_ascii_letters_digits_underscore_dot_and_dash_sr25() {
        for ok in ["read_file", "read-file", "v1.list", "A_Z-09"] {
            assert!(check_tool_name(ok).is_ok(), "{ok}");
            assert!(check_server_name(ok).is_ok(), "{ok}");
        }
        for bad in [
            "read file",
            "read\nfile",
            "read:file",
            "read*file",
            "re\u{0430}d_file",    // Cyrillic a
            "\u{FF44}elete_repo",  // fullwidth d
            "delete_repo\u{200B}", // zero-width space
            "caf\u{E9}",
            "a\u{0}b",
        ] {
            assert!(
                matches!(check_tool_name(bad), Err(NameError::InvalidChar { .. })),
                "{bad:?}"
            );
            assert!(check_server_name(bad).is_err(), "{bad:?}");
            assert!(check_call_name(bad).is_err(), "{bad:?}");
        }
        // The error escapes the name, so it is safe to log.
        let e = check_tool_name("a\nb").unwrap_err().to_string();
        assert!(!e.contains('\n'), "{e}");
    }

    #[test]
    fn patterns() {
        for ok in ["*", "git*", "github"] {
            assert!(check_server_pattern(ok).is_ok(), "{ok}");
        }
        for bad in ["a/b", "a/*", "**", "a*b*", ""] {
            assert!(check_server_pattern(bad).is_err(), "{bad}");
        }
        for ok in ["*", "read_*", "resources/*", "resources/read", "res*"] {
            assert!(check_call_pattern(ok).is_ok(), "{ok}");
        }
        for bad in ["/*", "a//*", "a*b*", "/x", ""] {
            assert!(check_call_pattern(bad).is_err(), "{bad}");
        }
    }
}
