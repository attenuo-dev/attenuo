//! The `Authorization` request header (RFC 9110 §11.6.2), as the proxy and the server read it.
//!
//! Both accept the `Bearer` (RFC 6750 §2.1) and `DPoP` (RFC 9449 §7.1) schemes and nothing
//! else. Whether a token needs a proof depends on the token, not on the scheme, so the parser
//! does not say which scheme it saw. Each caller maps a `None` to its own error type, and
//! handles an absent or non-ASCII header itself.

/// The token of an `Authorization` header value of the form `<scheme> <token>`, where
/// `<scheme>` is `Bearer` or `DPoP` in any letter case. `None` when the value has no space,
/// names another scheme, or carries an empty token.
///
/// The value is split at its first space. The token is everything after it with leading and
/// trailing whitespace trimmed; a token with inner spaces is returned as it is and fails
/// verification later. The scheme is not trimmed, so a leading space is a malformed value.
#[must_use]
pub fn token_of(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    let known = scheme.eq_ignore_ascii_case("bearer") || scheme.eq_ignore_ascii_case("dpop");
    let token = token.trim();
    (known && !token.is_empty()).then_some(token)
}

#[cfg(test)]
mod tests {
    use super::token_of;

    #[test]
    fn both_schemes_in_any_case() {
        for value in [
            "Bearer abc",
            "bearer abc",
            "BEARER abc",
            "DPoP abc",
            "dpop abc",
        ] {
            assert_eq!(token_of(value), Some("abc"), "{value}");
        }
    }

    #[test]
    fn token_is_trimmed() {
        assert_eq!(token_of("bearer abc "), Some("abc"));
        assert_eq!(token_of("Bearer   abc\t"), Some("abc"));
        assert_eq!(token_of("DPoP a.b.c"), Some("a.b.c"));
    }

    #[test]
    fn inner_spaces_stay_in_the_token() {
        assert_eq!(token_of("Bearer a b"), Some("a b"));
    }

    #[test]
    fn malformed_values_are_rejected() {
        for value in [
            "",
            "abc",
            "Bearer",
            "Bearer ",
            "Bearer   ",
            "Basic abc",
            "Token abc",
            " Bearer abc",
            "Bearer\tabc",
            "Bearerabc",
            "Bearer-x abc",
        ] {
            assert_eq!(token_of(value), None, "{value:?}");
        }
    }
}
