//! The name rules of `onbehalf_core::names`: never panic, and the accepted sets nest the way
//! the module documents (a server name is a tool name is a call name; every accepted name is
//! short, ASCII and free of the separators).
#![no_main]

use libfuzzer_sys::fuzz_target;
use onbehalf_core::names::{
    check_call_name, check_call_pattern, check_server_name, check_server_pattern, check_tool_name,
    is_name_char, MAX_NAME_LEN,
};

fuzz_target!(|s: &str| {
    let server = check_server_name(s).is_ok();
    let tool = check_tool_name(s).is_ok();
    let call = check_call_name(s).is_ok();
    let server_pat = check_server_pattern(s).is_ok();
    let call_pat = check_call_pattern(s).is_ok();

    // Server and tool names share one rule.
    assert_eq!(server, tool);
    if tool {
        assert!(call, "a tool name must be a call name: {s:?}");
        assert!(!s.contains('/'));
    }
    if server {
        assert!(
            server_pat,
            "a server name must be a valid server pattern: {s:?}"
        );
    }
    if call {
        assert!(call_pat, "a call name must be a valid call pattern: {s:?}");
        assert!(!s.is_empty() && s.len() <= MAX_NAME_LEN);
        assert!(s.chars().all(|c| is_name_char(c) || c == '/'));
        assert!(!s.starts_with('/') && !s.ends_with('/') && !s.contains("//"));
        // `<server>/<call>` must split back into exactly this pair (SR-13).
        let joined = format!("srv/{s}");
        let (a, b) = joined.split_once('/').unwrap();
        assert_eq!((a, b), ("srv", s));
    }
    if server_pat || call_pat {
        // A pattern is `*`, `<prefix>*` or a name: a `*` may only be the last character.
        if let Some(i) = s.find('*') {
            assert_eq!(i, s.len() - 1, "`*` inside a pattern: {s:?}");
        }
        assert!(s.len() <= MAX_NAME_LEN);
    }
    if server_pat {
        assert!(!s.contains('/'));
    }
});
