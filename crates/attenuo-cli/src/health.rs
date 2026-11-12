//! `attenuo health`: a liveness or readiness probe that needs nothing but this binary, so a
//! container image can run it as its `HEALTHCHECK` without `curl`.

use reqwest::StatusCode;
use serde_json::Value;

/// The path `attenuo health` asks: `/readyz` with `--ready`, else `/healthz`.
pub(crate) fn path(ready: bool) -> &'static str {
    if ready {
        "/readyz"
    } else {
        "/healthz"
    }
}

/// Judge one answer from [`path`]. `Ok` carries the line to print (and the body, for
/// `--json`); `Err` the reason the server is not healthy (or ready).
///
/// Healthy is a 200 whose JSON body says `"status": "ok"` (`/healthz`) or `"ready": true`
/// (`/readyz`): a 200 from something that is not an attenuo server (another service on the
/// port, a proxy's default page) does not count.
pub(crate) fn judge(
    ready: bool,
    status: StatusCode,
    body: &str,
) -> Result<(String, Value), String> {
    let what = path(ready);
    let parsed: Option<Value> = serde_json::from_str(body).ok();
    if status != StatusCode::OK {
        // /readyz says which check failed; pass that on.
        let checks = parsed
            .as_ref()
            .and_then(|v| v.get("checks"))
            .map(|c| format!(" {c}"))
            .unwrap_or_default();
        return Err(format!("{what} answered {status}{checks}"));
    }
    let Some(v) = parsed else {
        return Err(format!("{what} answered 200 but not with JSON"));
    };
    if ready {
        if v["ready"] != Value::Bool(true) {
            return Err(format!("{what} answered 200 without \"ready\": true"));
        }
        Ok((format!("ready {}", v["checks"]), v))
    } else {
        if v["status"] != "ok" {
            return Err(format!("{what} answered 200 without \"status\": \"ok\""));
        }
        let version = v["version"].as_str().unwrap_or("unknown").to_string();
        Ok((format!("ok (attenuo-server {version})"), v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthz_ok_needs_200_and_status_ok() {
        let (line, _) = judge(
            false,
            StatusCode::OK,
            r#"{"status":"ok","version":"0.1.0"}"#,
        )
        .unwrap();
        assert_eq!(line, "ok (attenuo-server 0.1.0)");
        assert!(judge(false, StatusCode::OK, "<html>it works</html>").is_err());
        assert!(judge(false, StatusCode::OK, r#"{"status":"starting"}"#).is_err());
        let err = judge(false, StatusCode::NOT_FOUND, "").unwrap_err();
        assert_eq!(err, "/healthz answered 404 Not Found");
    }

    #[test]
    fn readyz_names_the_failing_check() {
        let ok = r#"{"ready":true,"checks":{"audit":"ok","audit_append":"ok","leases":"ok"}}"#;
        assert!(judge(true, StatusCode::OK, ok).is_ok());
        let bad = r#"{"ready":false,"checks":{"audit":"ok","audit_append":"error","leases":"ok"}}"#;
        let err = judge(true, StatusCode::SERVICE_UNAVAILABLE, bad).unwrap_err();
        assert!(err.starts_with("/readyz answered 503"), "{err}");
        assert!(err.contains(r#""audit_append":"error""#), "{err}");
        // A 200 that does not say ready is not ready.
        assert!(judge(true, StatusCode::OK, r#"{"ready":false}"#).is_err());
    }
}
