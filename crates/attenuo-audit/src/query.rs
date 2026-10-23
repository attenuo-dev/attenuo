//! Filters for reading the audit log ([`SqliteAudit::entries_matching`]).
//!
//! [`EntryFilter`] is what `GET /admin/audit` accepts. It is separate from
//! [`RecordFilter`], which is the `filter` member of an export header and so part of a file
//! format: widening that would change what an export says about itself. A `RecordFilter`
//! converts into an `EntryFilter` with the same meaning.
//!
//! Every field is an exact match. Nothing here is a pattern: a `%` or `_` in a value is that
//! character, and `agent = "l1"` does not match an agent called `l10`.
//!
//! [`SqliteAudit::entries_matching`]: crate::SqliteAudit::entries_matching

use attenuo_core::{AgentId, Decision, DecisionRecord, LeaseId, RecordKind};
use time::OffsetDateTime;

use crate::export::RecordFilter;

/// Which audit entries a query wants. An empty (default) filter matches every entry; each
/// field that is set must hold.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EntryFilter {
    /// The record's `kind` is one of these. Empty means any kind.
    pub kinds: Vec<RecordKind>,
    /// The record's `decision`.
    pub decision: Option<Decision>,
    /// The record's `reason` (for example `policy_deny`).
    pub reason: Option<String>,
    /// The record's `originating_subject`.
    pub subject: Option<String>,
    /// One of the record's `agents`.
    pub agent: Option<AgentId>,
    /// One of the record's `leases`.
    pub lease: Option<LeaseId>,
    /// The record's `server`.
    pub server: Option<String>,
    /// The record's `tool`.
    pub tool: Option<String>,
    /// The record's `chain_id`.
    pub chain_id: Option<String>,
    /// The record's `at` is at or after this instant.
    pub since: Option<OffsetDateTime>,
    /// The record's `at` is strictly before this instant, so `since` and `until` describe a
    /// half-open window and adjacent windows do not share an entry.
    pub until: Option<OffsetDateTime>,
}

impl EntryFilter {
    /// True when no field is set, so the filter matches every entry.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Does `record` pass? This is the authoritative check: the SQL that
    /// [`SqliteAudit::entries_matching`](crate::SqliteAudit::entries_matching) runs only
    /// narrows the rows down, and every row it returns is checked here again.
    pub fn matches(&self, record: &DecisionRecord) -> bool {
        (self.kinds.is_empty() || self.kinds.contains(&record.kind))
            && self.decision.as_ref().is_none_or(|d| *d == record.decision)
            && self.reason.as_ref().is_none_or(|r| *r == record.reason)
            && self
                .subject
                .as_ref()
                .is_none_or(|s| *s == record.originating_subject)
            && self
                .agent
                .as_ref()
                .is_none_or(|a| record.agents.contains(a))
            && self
                .lease
                .as_ref()
                .is_none_or(|l| record.leases.contains(l))
            && self.server.as_ref().is_none_or(|s| *s == record.server)
            && self.tool.as_ref().is_none_or(|t| *t == record.tool)
            && self
                .chain_id
                .as_ref()
                .is_none_or(|c| record.chain_id.as_ref() == Some(c))
            && self.since.is_none_or(|t| record.at >= t)
            && self.until.is_none_or(|t| record.at < t)
    }
}

impl From<&RecordFilter> for EntryFilter {
    fn from(f: &RecordFilter) -> Self {
        Self {
            kinds: f.kind.into_iter().collect(),
            chain_id: f.chain_id.clone(),
            ..Self::default()
        }
    }
}

/// The order entries come back in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Order {
    /// Oldest first (ascending `seq`).
    #[default]
    Ascending,
    /// Newest first (descending `seq`).
    Descending,
}

/// `value` as a `LIKE` pattern that matches any text containing it literally: `\`, `%` and
/// `_` are escaped with `\` (use `ESCAPE '\'`), and the result is wrapped in `%`.
pub(crate) fn like_contains(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{escaped}%")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_patterns_escape_wildcards() {
        assert_eq!(like_contains(r#""a_b%c""#), r#"%"a\_b\%c"%"#);
        assert_eq!(like_contains(r"x\y"), r"%x\\y%");
    }

    #[test]
    fn a_record_filter_converts_with_the_same_meaning() {
        let rf = RecordFilter {
            kind: Some(RecordKind::Exchange),
            chain_id: Some("root".into()),
        };
        let ef = EntryFilter::from(&rf);
        assert_eq!(ef.kinds, vec![RecordKind::Exchange]);
        assert_eq!(ef.chain_id.as_deref(), Some("root"));
        assert!(EntryFilter::from(&RecordFilter::default()).is_empty());
    }
}
