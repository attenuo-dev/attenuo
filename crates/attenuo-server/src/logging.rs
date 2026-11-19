//! The log output (`[logging]`, `ATTENUO_LOG_FORMAT`): its format, colour, and whether user
//! subjects appear in it.
//!
//! **Format.** `text` (the default) is the `tracing` human-readable line; `json` is one JSON
//! object per line with `timestamp`, `level`, `target`, `message`, the event's own fields at
//! the top level, and the spans the event happened in: `span` (the innermost, with its fields)
//! and `spans` (all of them, outermost first), which is what the text format prints before
//! the message. `ATTENUO_LOG_FORMAT` overrides `[logging] format`, so one image or config file
//! can log text on a laptop and JSON in a cluster. An unknown value stops the server.
//!
//! **Colour.** ANSI colour only in the text format, only when standard output is a terminal,
//! and never when `NO_COLOR` is set to a non-empty value ([`ansi_enabled`]).
//!
//! **Subjects.** With `[logging] redact_subjects = true`, every log line that names a user
//! (the decision line, token issuance, approvals, the proxy's request span and stream lines)
//! carries `hmac:` and the same 16-hex-digit digest the trace export puts in
//! `attenuo.subject_digest` ([`crate::telemetry::SubjectDigest`]) instead of the subject. The
//! audit log is not affected: it keeps the real subject, which is how an operator finds the
//! user behind a digest. See [`attenuo_proxy::SubjectLog`].

use std::io::IsTerminal;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub use attenuo_proxy::OTEL_TARGET;

/// Environment variable that sets the log format, over `[logging] format`.
pub const LOG_FORMAT_ENV: &str = "ATTENUO_LOG_FORMAT";

/// `[logging]`: the log output's format and what it says about users.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingSection {
    /// `"text"` (default) or `"json"`. `ATTENUO_LOG_FORMAT` takes precedence.
    #[serde(default)]
    pub format: LogFormat,
    /// Write user subjects into log lines as a keyed digest instead of in clear. Default
    /// `false`. The audit log always keeps the subject.
    #[serde(default)]
    pub redact_subjects: bool,
}

impl LoggingSection {
    /// The format to log in: `ATTENUO_LOG_FORMAT` when it is set and not empty, else
    /// [`format`](Self::format).
    ///
    /// # Errors
    ///
    /// When `ATTENUO_LOG_FORMAT` holds anything but `text` or `json`.
    pub fn resolve_format(&self) -> anyhow::Result<LogFormat> {
        self.resolve_format_with(std::env::var(LOG_FORMAT_ENV).ok().as_deref())
    }

    /// [`resolve_format`](Self::resolve_format) with the environment value given.
    ///
    /// # Errors
    ///
    /// When `env` is set, not empty, and neither `text` nor `json`.
    pub fn resolve_format_with(&self, env: Option<&str>) -> anyhow::Result<LogFormat> {
        match env.filter(|v| !v.is_empty()) {
            None => Ok(self.format),
            Some(v) => v
                .parse()
                .map_err(|e: UnknownLogFormat| anyhow::anyhow!("{LOG_FORMAT_ENV}: {e}")),
        }
    }
}

/// How log lines are written.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable lines (the default).
    #[default]
    Text,
    /// One JSON object per line.
    Json,
}

/// A log format name that is neither `text` nor `json`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown log format {0:?}: expected \"text\" or \"json\"")]
pub struct UnknownLogFormat(pub String);

impl FromStr for LogFormat {
    type Err = UnknownLogFormat;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => Err(UnknownLogFormat(other.to_owned())),
        }
    }
}

/// Whether log lines get ANSI colour codes: only for `text`, only on a terminal, and not when
/// `no_color` (the `NO_COLOR` variable) is set to a non-empty value.
pub fn ansi_enabled(format: LogFormat, is_terminal: bool, no_color: Option<&str>) -> bool {
    format == LogFormat::Text && is_terminal && no_color.is_none_or(str::is_empty)
}

/// [`ansi_enabled`] for standard output, where the log goes, and this process's `NO_COLOR`.
pub fn ansi_for_stdout(format: LogFormat) -> bool {
    ansi_enabled(
        format,
        std::io::stdout().is_terminal(),
        std::env::var("NO_COLOR").ok().as_deref(),
    )
}

/// The subscriber's log layer in `format`, writing to `writer`: the `fmt` layer under
/// `RUST_LOG` (default `info`), which never sees spans in [`OTEL_TARGET`], so log lines read
/// as they did without telemetry.
pub fn layer<S, W>(
    format: LogFormat,
    ansi: bool,
    writer: W,
) -> Box<dyn tracing_subscriber::Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    W: for<'w> tracing_subscriber::fmt::MakeWriter<'w> + Send + Sync + 'static,
{
    use tracing_subscriber::filter::FilterExt;
    use tracing_subscriber::Layer;
    let env = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let filter = env.and(tracing_subscriber::filter::filter_fn(|m| {
        m.target() != OTEL_TARGET
    }));
    let fmt = tracing_subscriber::fmt::layer().with_writer(writer);
    match format {
        LogFormat::Text => fmt.with_ansi(ansi).with_filter(filter).boxed(),
        LogFormat::Json => fmt
            .json()
            .with_ansi(false)
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(true)
            .with_filter(filter)
            .boxed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_the_default_and_the_environment_wins() {
        let file = LoggingSection::default();
        assert_eq!(file.resolve_format_with(None).unwrap(), LogFormat::Text);
        assert_eq!(file.resolve_format_with(Some("")).unwrap(), LogFormat::Text);
        assert_eq!(
            file.resolve_format_with(Some("json")).unwrap(),
            LogFormat::Json
        );
        let json = LoggingSection {
            format: LogFormat::Json,
            ..Default::default()
        };
        assert_eq!(json.resolve_format_with(None).unwrap(), LogFormat::Json);
        assert_eq!(
            json.resolve_format_with(Some("text")).unwrap(),
            LogFormat::Text
        );
    }

    #[test]
    fn an_unknown_format_is_refused_with_the_accepted_values() {
        for bad in ["xml", "JSON", " json", "pretty"] {
            let e = LoggingSection::default()
                .resolve_format_with(Some(bad))
                .unwrap_err()
                .to_string();
            assert!(e.contains(LOG_FORMAT_ENV), "{e}");
            assert!(e.contains(&format!("{bad:?}")), "{e}");
            assert!(e.contains("\"text\" or \"json\""), "{e}");
        }
    }

    #[test]
    fn the_config_key_parses_and_refuses_unknown_values() {
        let s: LoggingSection =
            toml::from_str("format = \"json\"\nredact_subjects = true").unwrap();
        assert_eq!(s.format, LogFormat::Json);
        assert!(s.redact_subjects);
        let e = toml::from_str::<LoggingSection>("format = \"xml\"")
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("xml") && e.contains("text") && e.contains("json"),
            "{e}"
        );
    }

    #[test]
    fn colour_only_for_text_on_a_terminal_without_no_color() {
        assert!(ansi_enabled(LogFormat::Text, true, None));
        assert!(ansi_enabled(LogFormat::Text, true, Some("")));
        assert!(!ansi_enabled(LogFormat::Text, true, Some("1")));
        assert!(!ansi_enabled(LogFormat::Text, false, None));
        assert!(!ansi_enabled(LogFormat::Json, true, None));
        assert!(!ansi_enabled(LogFormat::Json, false, None));
    }
}
