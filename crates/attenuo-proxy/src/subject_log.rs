//! How a user subject is written into a log line (`[logging] redact_subjects`).
//!
//! Log lines carry the originating user's subject (`subject=...`), which is usually personal
//! data (an email address, an employee id). A [`SubjectLog`] writes it either as it is,
//! Debug-formatted like every caller-controlled string (SR-18), or as a keyed digest
//! (`hmac:` and 16 hex digits). The digest function comes from the server, which uses the
//! same HMAC as the exported `attenuo.subject_digest` span attribute, so a log line and a
//! trace of the same user carry the same 16 hex digits. The proxy reaches the setting through
//! [`crate::Authorizer::subject_log`]. Only log output is affected: the audit record keeps
//! the real subject.

use std::fmt;
use std::sync::Arc;

type DigestFn = dyn Fn(&str) -> String + Send + Sync;

/// How user subjects appear in log lines: in clear (the default) or as a keyed digest.
#[derive(Clone, Default)]
pub struct SubjectLog(Option<Arc<DigestFn>>);

/// The clear form, for [`crate::Authorizer::subject_log`]'s default.
pub(crate) static CLEAR: SubjectLog = SubjectLog(None);

impl SubjectLog {
    /// Subjects are logged as they are.
    pub fn clear() -> Self {
        Self(None)
    }

    /// Subjects are logged as `hmac:<digest(subject)>`.
    pub fn digest(digest: impl Fn(&str) -> String + Send + Sync + 'static) -> Self {
        Self(Some(Arc::new(digest)))
    }

    /// Whether subjects are replaced by their digest.
    pub fn redacts(&self) -> bool {
        self.0.is_some()
    }

    /// The log form of `subject`, for a `subject = ?...` field.
    pub fn show<'a>(&'a self, subject: &'a str) -> LoggedSubject<'a> {
        LoggedSubject { log: self, subject }
    }
}

impl fmt::Debug for SubjectLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.redacts() {
            "SubjectLog(digest)"
        } else {
            "SubjectLog(clear)"
        })
    }
}

/// A subject as a log line shows it ([`SubjectLog::show`]). Its `Debug` form is the subject
/// Debug-formatted (quoted and escaped), or `hmac:` and the digest.
pub struct LoggedSubject<'a> {
    log: &'a SubjectLog,
    subject: &'a str,
}

impl fmt::Debug for LoggedSubject<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.log.0 {
            None => fmt::Debug::fmt(self.subject, f),
            Some(d) => write!(f, "hmac:{}", d(self.subject)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_is_debug_formatted_and_digest_replaces_the_subject() {
        let clear = SubjectLog::clear();
        assert!(!clear.redacts());
        assert_eq!(format!("{:?}", clear.show("a\"b")), r#""a\"b""#);
        let d = SubjectLog::digest(|s| format!("{:016x}", s.len()));
        assert!(d.redacts());
        let shown = format!("{:?}", d.show("alice@example.com"));
        assert_eq!(shown, "hmac:0000000000000011");
        assert!(!shown.contains("alice"));
    }
}
