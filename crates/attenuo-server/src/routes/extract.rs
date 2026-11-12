//! Extractors that refuse in the JSON error shape of [`crate::error`] (K-10).
//!
//! axum's own `Query`, `Path` and `Bytes` extractors answer a refusal as `text/plain`
//! (`Failed to deserialize query string: ...`, `Invalid URL: Cannot parse "abc" to a u64`,
//! `Failed to buffer the request body: length limit exceeded`), which is neither the documented
//! `{"error", "detail"}` shape nor safe to show: the text quotes the request. These wrappers run
//! the same extraction and turn a refusal into an [`ApiError`]:
//!
//! | Refusal | Status | `error` |
//! | --- | --- | --- |
//! | a query parameter that does not parse | 400 | `invalid_request` |
//! | a path parameter that does not parse or is not UTF-8 | 400 | `invalid_request` |
//! | a body over the limit (axum's default, 2 MiB) | 413 | `request_too_large` |
//! | a body that cannot be read | 400 | `invalid_request` |
//!
//! `detail` names the parameter (a name from the route or the query struct, never a value from
//! the request) and the expected type; it never quotes what was sent. A route-definition error
//! (a handler that asks for parameters the route does not have) is a 500, as in axum.
//!
//! Every REST and AuthZEN route uses these instead of axum's. A JSON body is read as [`Body`]
//! and parsed with `routes::parse_json`, which already answers in this shape.

use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, PathRejection};
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::StatusCode;
use serde::de::DeserializeOwned;

use crate::error::ApiError;

/// `error` of a body over the size limit.
pub const REQUEST_TOO_LARGE: &str = "request_too_large";

/// A name from the request that is safe to repeat in `detail`: a short identifier.
fn printable_name(name: &str) -> Option<&str> {
    (!name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
    .then_some(name)
}

/// The query string, deserialized as `T`. A value that does not parse is 400 `invalid_request`
/// naming the parameter.
#[derive(Debug, Clone, Copy, Default)]
pub struct Query<T>(pub T);

impl<T> std::ops::Deref for Query<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: DeserializeOwned> Query<T> {
    /// Deserialize `query` (the part of the URI after `?`, or empty).
    ///
    /// # Errors
    ///
    /// 400 `invalid_request` when `query` does not deserialize as `T`.
    pub fn parse(query: &str) -> Result<Self, ApiError> {
        let de = serde_urlencoded::Deserializer::new(form_urlencoded::parse(query.as_bytes()));
        serde_path_to_error::deserialize(de)
            .map(Query)
            .map_err(|e| {
                let path = e.path().to_string();
                tracing::debug!(error = ?e.inner().to_string(), param = ?path, "query string refused");
                let detail = match printable_name(&path) {
                    Some(p) => format!("the query parameter `{p}` has an invalid value"),
                    None => "the query string is invalid".to_string(),
                };
                ApiError::bad_request("invalid_request", detail)
            })
    }
}

impl<T: DeserializeOwned, S: Send + Sync> FromRequestParts<S> for Query<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        Self::parse(parts.uri.query().unwrap_or_default())
    }
}

/// The route's path parameters, deserialized as `T`. A parameter that does not parse or is not
/// UTF-8 is 400 `invalid_request` naming the parameter.
#[derive(Debug, Clone, Copy, Default)]
pub struct Path<T>(pub T);

impl<T> std::ops::Deref for Path<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

/// The [`ApiError`] for a refused path. `only_key` is the route's parameter when it has exactly
/// one, to name it when the rejection does not (a path deserialized into a single value).
pub fn path_rejection(rejection: PathRejection, only_key: Option<&str>) -> ApiError {
    use axum::extract::path::ErrorKind as K;
    let PathRejection::FailedToDeserializePathParams(e) = rejection else {
        // `MissingPathParams`: the handler is mounted on a route without parameters.
        return ApiError::internal(rejection.body_text());
    };
    let detail = match e.kind() {
        K::ParseErrorAtKey {
            key, expected_type, ..
        } => format!("the path parameter `{key}` is not a valid {expected_type}"),
        K::ParseErrorAtIndex {
            index,
            expected_type,
            ..
        } => format!("path parameter {index} is not a valid {expected_type}"),
        K::ParseError { expected_type, .. } => match only_key {
            Some(key) => format!("the path parameter `{key}` is not a valid {expected_type}"),
            None => format!("a path parameter is not a valid {expected_type}"),
        },
        K::InvalidUtf8InPathParam { key } => {
            format!("the path parameter `{key}` is not valid UTF-8")
        }
        K::DeserializeError { key, .. } => format!("the path parameter `{key}` is invalid"),
        // Route-definition errors, as axum classes them.
        K::WrongNumberOfParameters { .. } | K::UnsupportedType { .. } => {
            return ApiError::internal(e.body_text())
        }
        _ => "a path parameter is invalid".to_string(),
    };
    tracing::debug!(error = ?e.body_text(), "path refused");
    ApiError::bad_request("invalid_request", detail)
}

impl<T: DeserializeOwned + Send, S: Send + Sync> FromRequestParts<S> for Path<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        match axum::extract::Path::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Path(t)) => Ok(Path(t)),
            Err(rejection) => {
                // The route template's parameter names, never the request's values.
                let keys: Vec<String> =
                    axum::extract::RawPathParams::from_request_parts(parts, state)
                        .await
                        .map(|raw| raw.iter().map(|(k, _)| k.to_string()).collect())
                        .unwrap_or_default();
                let only_key = match keys.as_slice() {
                    [k] => Some(k.as_str()),
                    _ => None,
                };
                Err(path_rejection(rejection, only_key))
            }
        }
    }
}

/// The request body, read whole. Over the size limit it is 413 `request_too_large`; a body that
/// cannot be read is 400 `invalid_request`. Parse it with `routes::parse_json`.
#[derive(Debug, Clone, Default)]
pub struct Body(pub Bytes);

impl std::ops::Deref for Body {
    type Target = Bytes;
    fn deref(&self) -> &Bytes {
        &self.0
    }
}

/// The [`ApiError`] for a body that could not be read.
pub fn body_rejection(rejection: BytesRejection) -> ApiError {
    tracing::debug!(error = ?rejection.body_text(), "request body refused");
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            REQUEST_TOO_LARGE,
            "the request body is over the size limit",
        )
    } else {
        ApiError::bad_request("invalid_request", "the request body could not be read")
    }
}

impl<S: Send + Sync> FromRequest<S> for Body {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        Bytes::from_request(req, state)
            .await
            .map(Body)
            .map_err(body_rejection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, serde::Deserialize)]
    struct Q {
        #[allow(dead_code)]
        from: Option<u64>,
    }

    #[test]
    fn a_query_refusal_names_the_parameter_not_the_value() {
        let e = Query::<Q>::parse("from=%3Cscript%3E").unwrap_err();
        assert_eq!(e.status, StatusCode::BAD_REQUEST);
        assert_eq!(e.code, "invalid_request");
        assert_eq!(e.detail, "the query parameter `from` has an invalid value");
        assert!(Query::<Q>::parse("").is_ok());
        assert!(Query::<Q>::parse("from=3&other=x").is_ok());
    }

    #[test]
    fn only_short_identifiers_are_repeated() {
        assert_eq!(printable_name("max_nodes"), Some("max_nodes"));
        assert_eq!(printable_name("."), None);
        assert_eq!(printable_name("a\nb"), None);
        assert_eq!(printable_name(&"a".repeat(65)), None);
        assert_eq!(printable_name(""), None);
    }
}
