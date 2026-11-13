//! Configuration overrides from the environment: `ATTENUO__<SECTION>__<KEY>=value` (audit O-5).
//!
//! The variables are applied to the parsed TOML table of the file before it is turned into a
//! [`Config`], so the startup checks see the final values. The rules, documented in
//! `docs/reference/config.md#environment-overrides`:
//!
//! - The prefix is `ATTENUO__`, with two underscores, and segments are separated by two
//!   underscores: `ATTENUO__SERVER__LISTEN`, `ATTENUO__TELEMETRY__TRACES__SAMPLE_RATIO`. A
//!   variable with one underscore after `ATTENUO` (`ATTENUO_SERVER`, `ATTENUO_ADMIN_TOKEN`) is
//!   never read as an override. Section and key are matched against the real keys without
//!   regard to case.
//! - Only scalar keys (string, integer, float, bool, and the strings that stand for an
//!   address, a path or a choice) can be set. Lists, tables of names (`[policy.catalog]`,
//!   `headers`, ...), arrays of tables (`[[agents]]`, `[[upstreams]]`, ...) and optional
//!   sections absent from the file (`[audit.sink]`, `[approvals.notify]`) cannot.
//! - The value is typed by the key it replaces: `true` or `false` for a bool, a decimal
//!   integer for an integer, a number for a float, the text as is for a string.
//! - `[dev]` keys are refused: the unverified root mint is switched on in the file, where a
//!   review sees it, or not at all.
//! - Anything else is an error that stops the server and names the variable, never its value:
//!   an unknown key, a value of the wrong type, an empty value, two variables for one key, and
//!   a variable that sets the same key as `ATTENUO_ADMIN_TOKEN` or `ATTENUO_LOG_FORMAT`.

use std::ffi::OsString;

use serde_json::Value as Json;

use super::{Config, ADMIN_TOKEN_ENV};
use crate::logging::LOG_FORMAT_ENV;

/// Prefix of a configuration override variable: `ATTENUO` and two underscores.
pub const OVERRIDE_PREFIX: &str = "ATTENUO__";

/// Separator of the segments of an override variable's name.
const SEPARATOR: &str = "__";

/// Keys whose value is a table of names chosen by the operator (server names, header names,
/// attribute names), not a section with fixed keys. They cannot be overridden.
const NAME_TABLES: &[&[&str]] = &[
    &["policy", "catalog"],
    &["policy", "user_attributes"],
    &["telemetry", "resource_attributes"],
    &["approvals", "notify", "headers"],
];

/// One key that an environment variable set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvOverride {
    /// The variable, as it was named in the environment.
    pub variable: String,
    /// The key it set, as `[section] key` (`[telemetry.traces] sample_ratio`).
    pub key: String,
}

impl std::fmt::Display for EnvOverride {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.key, self.variable)
    }
}

/// The type a key's value has in the effective configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    String,
    Integer,
    Float,
    Bool,
    /// An optional key that is unset: its type is whatever deserializes.
    Unset,
}

/// A resolved override: where it goes and what type it takes.
struct Target {
    variable: String,
    /// Real key names, from the section down to the key.
    path: Vec<String>,
    kind: Kind,
}

fn display_key(path: &[String]) -> String {
    match path.split_last() {
        Some((key, [])) => key.clone(),
        Some((key, sections)) => format!("[{}] {key}", sections.join(".")),
        None => String::new(),
    }
}

fn section_name(path: &[String]) -> String {
    format!("[{}]", path.join("."))
}

/// Does `name` start with [`OVERRIDE_PREFIX`], ignoring case?
fn has_prefix(name: &str) -> bool {
    name.get(..OVERRIDE_PREFIX.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(OVERRIDE_PREFIX))
}

/// The override variables of `env`, sorted by name, and the two older variables that set the
/// same keys.
struct Collected {
    vars: Vec<(String, String)>,
    admin_token: bool,
    log_format: bool,
    errors: Vec<String>,
}

fn collect<I, K, V>(env: I) -> Collected
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<OsString>,
    V: Into<OsString>,
{
    let mut out = Collected {
        vars: Vec::new(),
        admin_token: false,
        log_format: false,
        errors: Vec::new(),
    };
    for (name, value) in env {
        let (name, value): (OsString, OsString) = (name.into(), value.into());
        let Some(name) = name.to_str() else {
            let lossy = name.to_string_lossy();
            if has_prefix(&lossy) {
                out.errors
                    .push(format!("{lossy}: the variable's name is not valid UTF-8"));
            }
            continue;
        };
        let non_empty = !value.is_empty();
        if name == ADMIN_TOKEN_ENV {
            out.admin_token = non_empty;
            continue;
        }
        if name == LOG_FORMAT_ENV {
            out.log_format = non_empty;
            continue;
        }
        if !has_prefix(name) {
            continue;
        }
        match value.into_string() {
            Ok(v) => out.vars.push((name.to_owned(), v)),
            Err(_) => out
                .errors
                .push(format!("{name}: the value is not valid UTF-8")),
        }
    }
    out.vars.sort();
    out
}

fn in_name_table(path: &[String]) -> bool {
    NAME_TABLES
        .iter()
        .any(|t| t.len() == path.len() && t.iter().zip(path).all(|(a, b)| *a == b))
}

/// Find the key `variable` names in `schema` (the effective configuration as JSON, unset keys
/// as `null`).
fn resolve(schema: &Json, variable: &str) -> Result<Target, String> {
    let rest = &variable[OVERRIDE_PREFIX.len()..];
    let segments: Vec<&str> = rest.split(SEPARATOR).collect();
    if segments.iter().any(|s| s.is_empty()) {
        return Err(
            "is malformed: write ATTENUO__<SECTION>__<KEY>, with segments separated by two \
             underscores and none empty"
                .into(),
        );
    }
    if segments[0].eq_ignore_ascii_case("dev") {
        return Err(
            "[dev] keys cannot be set from the environment: the development-only switches \
             are set in the config file, where a review sees them"
                .into(),
        );
    }
    let mut node = schema;
    let mut path: Vec<String> = Vec::new();
    for (i, segment) in segments.iter().enumerate() {
        let Json::Object(map) = node else {
            unreachable!("only objects are descended into");
        };
        let Some((name, value)) = map.iter().find(|(k, _)| k.eq_ignore_ascii_case(segment)) else {
            return Err(if path.is_empty() {
                format!("names no section of the config (`{segment}`)")
            } else {
                format!("{} has no key `{segment}`", section_name(&path))
            });
        };
        path.push(name.clone());
        let last = i + 1 == segments.len();
        if in_name_table(&path) {
            return Err(format!(
                "{} is a table of names; it cannot be set from the environment",
                display_key(&path)
            ));
        }
        match value {
            Json::Array(items) => {
                let what = if path.len() == 1 {
                    format!(
                        "[[{name}]] is an array of tables; its entries cannot be set from the \
                         environment"
                    )
                } else if items.iter().any(Json::is_object) {
                    format!(
                        "{} is an array of tables; it cannot be set from the environment",
                        display_key(&path)
                    )
                } else {
                    format!(
                        "{} is a list; lists cannot be set from the environment",
                        display_key(&path)
                    )
                };
                return Err(what);
            }
            Json::Object(_) if last => {
                return Err(format!(
                    "{} is a section; name one of its keys: {}__<KEY>",
                    section_name(&path),
                    variable
                ));
            }
            Json::Object(_) => node = value,
            Json::Null if !last => {
                return Err(format!(
                    "{} is not in the config file, and an optional section is not created from \
                     the environment: add it to the file to override its keys",
                    section_name(&path)
                ));
            }
            _ if !last => {
                return Err(format!("{} is a key, not a section", display_key(&path)));
            }
            Json::Null => {
                return Ok(Target {
                    variable: variable.to_owned(),
                    path,
                    kind: Kind::Unset,
                })
            }
            Json::Bool(_) => return Ok(target(variable, path, Kind::Bool)),
            Json::Number(n) if n.is_f64() => return Ok(target(variable, path, Kind::Float)),
            Json::Number(_) => return Ok(target(variable, path, Kind::Integer)),
            Json::String(_) => return Ok(target(variable, path, Kind::String)),
        }
    }
    let first = segments[0];
    Err(format!(
        "names a section, not a key: write {OVERRIDE_PREFIX}{first}__<KEY>"
    ))
}

fn target(variable: &str, path: Vec<String>, kind: Kind) -> Target {
    Target {
        variable: variable.to_owned(),
        path,
        kind,
    }
}

fn parse_integer(value: &str) -> Option<toml::Value> {
    value.parse::<i64>().ok().map(toml::Value::Integer)
}

fn parse_float(value: &str) -> Option<toml::Value> {
    value
        .parse::<f64>()
        .ok()
        .filter(|f| f.is_finite())
        .map(toml::Value::Float)
}

fn parse_bool(value: &str) -> Option<toml::Value> {
    match value {
        "true" => Some(toml::Value::Boolean(true)),
        "false" => Some(toml::Value::Boolean(false)),
        _ => None,
    }
}

/// The TOML values `value` may stand for, for a key of type `kind`, most likely first.
fn candidates(kind: Kind, value: &str) -> Result<Vec<toml::Value>, &'static str> {
    let one = |v: Option<toml::Value>, expected| v.map(|v| vec![v]).ok_or(expected);
    match kind {
        Kind::Integer => one(parse_integer(value), "expected a decimal integer"),
        Kind::Float => one(parse_float(value), "expected a number"),
        Kind::Bool => one(parse_bool(value), "expected true or false"),
        // A string first; the other forms for a key whose type takes them too (an unset
        // optional key, or a choice such as `track_usage` that is `"auto"` or `true`).
        Kind::String | Kind::Unset => Ok(std::iter::once(toml::Value::String(value.to_owned()))
            .chain(parse_integer(value))
            .chain(parse_bool(value))
            .chain(parse_float(value))
            .collect()),
    }
}

fn set(table: &mut toml::Table, path: &[String], value: toml::Value) {
    let (key, sections) = path.split_last().expect("a target has a key");
    let mut table = table;
    for section in sections {
        let entry = table
            .entry(section.clone())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        table = match entry {
            toml::Value::Table(t) => t,
            // The file deserialized as a config, so every section on the path is a table.
            _ => unreachable!("a config section is a table"),
        };
    }
    table.insert(key.clone(), value);
}

/// What a deserialization error says the key expects, when that part cannot hold the value.
/// serde's messages are `invalid type: <value>, expected <what>` and the like, where only
/// `<what>` comes from the type; anything else, and anything that contains the value, is
/// dropped.
fn expected_part(error: &toml::de::Error, value: &str) -> Option<String> {
    let message = error.message();
    let (_, expected) = message.split_once(", expected ")?;
    let expected = expected.lines().next()?.trim();
    (!expected.is_empty() && (value.is_empty() || !expected.contains(value)))
        .then(|| format!("expected {expected}"))
}

/// Apply the `ATTENUO__...` variables of `env` to `file` (the config file's TOML table, which
/// `base` was deserialized from) and deserialize the result.
///
/// # Errors
///
/// Every problem with a variable, one line each, naming the variable and never its value.
pub(super) fn apply<I, K, V>(
    file: toml::Table,
    base: Config,
    env: I,
) -> anyhow::Result<(Config, Vec<EnvOverride>)>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<OsString>,
    V: Into<OsString>,
{
    let collected = collect(env);
    let mut errors = collected.errors;
    if collected.vars.is_empty() && errors.is_empty() {
        return Ok((base, Vec::new()));
    }
    let schema = serde_json::to_value(&base)
        .map_err(|e| anyhow::anyhow!("environment overrides: describing the config: {e}"))?;
    let mut chosen: Vec<(Target, toml::Value)> = Vec::new();
    for (variable, value) in &collected.vars {
        let t = match resolve(&schema, variable) {
            Ok(t) => t,
            Err(e) => {
                errors.push(format!("{variable}: {e}"));
                continue;
            }
        };
        let key = display_key(&t.path);
        if let Some((other, _)) = chosen.iter().find(|(o, _)| o.path == t.path) {
            errors.push(format!(
                "{variable}: {} sets {key} too; set only one",
                other.variable
            ));
            continue;
        }
        let legacy = match t.path.iter().map(String::as_str).collect::<Vec<_>>()[..] {
            ["admin", "token"] if collected.admin_token => Some(ADMIN_TOKEN_ENV),
            ["logging", "format"] if collected.log_format => Some(LOG_FORMAT_ENV),
            _ => None,
        };
        if let Some(legacy) = legacy {
            errors.push(format!(
                "{variable}: {legacy} sets {key} too; set only one of the two"
            ));
            continue;
        }
        if value.is_empty() {
            errors.push(format!(
                "{variable}: the value is empty; unset the variable to keep the file's {key}"
            ));
            continue;
        }
        let candidates = match candidates(t.kind, value) {
            Ok(c) => c,
            Err(expected) => {
                errors.push(format!(
                    "{variable}: not a valid value for {key} ({expected}; the value is not shown)"
                ));
                continue;
            }
        };
        // Each candidate is tried alone on the file, so the error names this variable.
        let mut first_error = None;
        let picked = candidates.into_iter().find(|candidate| {
            let mut table = file.clone();
            set(&mut table, &t.path, candidate.clone());
            match table.try_into::<Config>() {
                Ok(_) => true,
                Err(e) => {
                    first_error.get_or_insert(e);
                    false
                }
            }
        });
        match picked {
            Some(v) => chosen.push((t, v)),
            None => {
                let detail = first_error
                    .as_ref()
                    .and_then(|e| expected_part(e, value))
                    .map(|e| format!("{e}; "))
                    .unwrap_or_default();
                errors.push(format!(
                    "{variable}: not a valid value for {key} ({detail}the value is not shown)"
                ));
            }
        }
    }
    if !errors.is_empty() {
        anyhow::bail!(
            "environment overrides refused (values are not shown):\n  {}",
            errors.join("\n  ")
        );
    }
    let mut table = file;
    let mut applied = Vec::with_capacity(chosen.len());
    for (t, v) in chosen {
        set(&mut table, &t.path, v);
        applied.push(EnvOverride {
            key: display_key(&t.path),
            variable: t.variable,
        });
    }
    let config = table.try_into::<Config>().map_err(|_| {
        let names: Vec<&str> = applied.iter().map(|o| o.variable.as_str()).collect();
        anyhow::anyhow!(
            "environment overrides refused: {} together do not give a valid config (values are \
             not shown)",
            names.join(", ")
        )
    })?;
    Ok((config, applied))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"
        [server]
        listen = "127.0.0.1:8080"

        [admin]
        token = "file-admin-token-0123456789abcdef0123"

        [audit]
        checkpoint_every = 10

        [[agents]]
        id = "planner"
        secret_sha256 = "00"
    "#;

    fn env(vars: &[(&str, &str)]) -> Vec<(String, String)> {
        vars.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn load(text: &str, vars: &[(&str, &str)]) -> anyhow::Result<(Config, Vec<EnvOverride>)> {
        Config::from_toml_with_env(text, env(vars))
    }

    fn refused(text: &str, vars: &[(&str, &str)]) -> String {
        load(text, vars).unwrap_err().to_string()
    }

    #[test]
    fn no_variables_gives_the_file_unchanged() {
        let (cfg, applied) = load(FILE, &[]).unwrap();
        assert_eq!(cfg, Config::from_toml(FILE).unwrap());
        assert!(applied.is_empty());
    }

    #[test]
    fn the_environment_wins_over_the_file() {
        let (cfg, applied) = load(
            FILE,
            &[
                ("ATTENUO__SERVER__LISTEN", "0.0.0.0:9000"),
                ("ATTENUO__AUDIT__CHECKPOINT_EVERY", "25"),
            ],
        )
        .unwrap();
        assert_eq!(cfg.server.listen.to_string(), "0.0.0.0:9000");
        assert_eq!(cfg.audit.checkpoint_every, 25);
        // Untouched keys keep the file's value.
        assert_eq!(
            cfg.admin.token.as_deref(),
            Some("file-admin-token-0123456789abcdef0123")
        );
        assert_eq!(cfg.agents.len(), 1);
        assert_eq!(
            applied,
            vec![
                EnvOverride {
                    variable: "ATTENUO__AUDIT__CHECKPOINT_EVERY".into(),
                    key: "[audit] checkpoint_every".into(),
                },
                EnvOverride {
                    variable: "ATTENUO__SERVER__LISTEN".into(),
                    key: "[server] listen".into(),
                },
            ]
        );
    }

    #[test]
    fn each_scalar_type_is_typed_by_its_key() {
        let (cfg, _) = load(
            "",
            &[
                // string
                ("ATTENUO__ISSUER__AUDIENCE", "other-audience"),
                // unset optional string
                ("ATTENUO__SERVER__PUBLIC_URL", "https://attenuo.example.com"),
                // unset optional address
                ("ATTENUO__ADMIN__LISTEN", "127.0.0.1:9102"),
                // unset optional path
                (
                    "ATTENUO__POLICY__POLICIES_PATH",
                    "/etc/attenuo/policy.cedar",
                ),
                // integer
                ("ATTENUO__ISSUER__MAX_DEPTH", "4"),
                // bool
                ("ATTENUO__METRICS__ENABLED", "true"),
                ("ATTENUO__TOKEN__REQUIRE_ACTOR_AUTH", "false"),
                // a choice (an enum, written as a string)
                ("ATTENUO__TOKEN__DPOP", "required"),
                // float, in a nested section
                ("ATTENUO__TELEMETRY__TRACES__SAMPLE_RATIO", "0.25"),
            ],
        )
        .unwrap();
        assert_eq!(cfg.issuer.audience, "other-audience");
        assert_eq!(
            cfg.server.public_url.as_deref(),
            Some("https://attenuo.example.com")
        );
        assert_eq!(cfg.admin.listen.unwrap().to_string(), "127.0.0.1:9102");
        assert_eq!(
            cfg.policy.policies_path.as_deref(),
            Some(std::path::Path::new("/etc/attenuo/policy.cedar"))
        );
        assert_eq!(cfg.issuer.max_depth, 4);
        assert!(cfg.metrics.enabled);
        assert!(!cfg.token.require_actor_auth);
        assert_eq!(cfg.token.dpop, super::super::DpopMode::Required);
        assert!((cfg.telemetry.traces.sample_ratio - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn a_string_key_takes_text_that_looks_like_a_number() {
        let (cfg, _) = load(
            "",
            &[
                ("ATTENUO__ISSUER__AUDIENCE", "12345"),
                ("ATTENUO__APPROVALS__CLIENT_ID", "true"),
                // A choice that is a string or `true`: the string fails, `true` is taken.
                ("ATTENUO__POLICY__TRACK_USAGE", "true"),
            ],
        )
        .unwrap();
        assert_eq!(cfg.issuer.audience, "12345");
        assert_eq!(cfg.approvals.client_id.as_deref(), Some("true"));
        assert_eq!(cfg.policy.track_usage, attenuo_policy::TrackUsage::Always);
    }

    #[test]
    fn a_float_key_takes_an_integer() {
        let (cfg, _) = load("", &[("ATTENUO__TELEMETRY__TRACES__SAMPLE_RATIO", "1")]).unwrap();
        assert!((cfg.telemetry.traces.sample_ratio - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn section_and_key_ignore_case() {
        let (cfg, applied) = load(
            "",
            &[
                ("attenuo__server__listen", "127.0.0.1:1"),
                ("ATTENUO__Admin_Ui__Enabled", "true"),
            ],
        )
        .unwrap();
        assert_eq!(cfg.server.listen.port(), 1);
        assert!(cfg.admin_ui.enabled);
        assert_eq!(applied[0].key, "[admin_ui] enabled");
    }

    #[test]
    fn a_nested_section_is_created_when_the_file_lacks_it() {
        let (cfg, applied) = load(
            "[telemetry]\nenabled = false\n",
            &[("ATTENUO__TELEMETRY__TRACES__MAX_QUEUE_SPANS", "100")],
        )
        .unwrap();
        assert_eq!(cfg.telemetry.traces.max_queue_spans, 100);
        assert_eq!(applied[0].key, "[telemetry.traces] max_queue_spans");
        // A key of an optional section that the file has.
        let (cfg, _) = load(
            "[audit.sink]\nkind = \"file\"\npath = \"/var/log/cp.jsonl\"\n",
            &[("ATTENUO__AUDIT__SINK__MAX_LAG_SECONDS", "60")],
        )
        .unwrap();
        assert_eq!(cfg.audit.sink.unwrap().max_lag_seconds, 60);
    }

    #[test]
    fn an_unknown_section_or_key_is_refused() {
        let e = refused("", &[("ATTENUO__SERVR__LISTEN", "127.0.0.1:1")]);
        assert!(
            e.contains("ATTENUO__SERVR__LISTEN: names no section"),
            "{e}"
        );
        let e = refused("", &[("ATTENUO__SERVER__LISTN", "127.0.0.1:1")]);
        assert!(
            e.contains("ATTENUO__SERVER__LISTN: [server] has no key `LISTN`"),
            "{e}"
        );
        let e = refused("", &[("ATTENUO__SERVER__LISTEN__PORT", "1")]);
        assert!(e.contains("is a key, not a section"), "{e}");
        let e = refused("", &[("ATTENUO__SERVER", "x")]);
        assert!(e.contains("[server] is a section"), "{e}");
        let e = refused("", &[("ATTENUO__SERVER____LISTEN", "x")]);
        assert!(e.contains("is malformed"), "{e}");
        let e = refused("", &[("ATTENUO__SERVER__LISTEN__", "x")]);
        assert!(e.contains("is malformed"), "{e}");
        let e = refused("", &[("ATTENUO__", "x")]);
        assert!(e.contains("is malformed"), "{e}");
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        let e = refused(
            "",
            &[
                ("ATTENUO__SERVR__LISTEN", "x"),
                ("ATTENUO__METRICS__ENABLED", "yes"),
            ],
        );
        assert!(e.contains("ATTENUO__SERVR__LISTEN"), "{e}");
        assert!(e.contains("ATTENUO__METRICS__ENABLED"), "{e}");
    }

    #[test]
    fn a_value_of_the_wrong_type_is_refused_without_echoing_it() {
        for (var, value, expected) in [
            (
                "ATTENUO__METRICS__ENABLED",
                "yes-please",
                "expected true or false",
            ),
            (
                "ATTENUO__METRICS__ENABLED",
                "TRUE",
                "expected true or false",
            ),
            (
                "ATTENUO__AUDIT__CHECKPOINT_EVERY",
                "lots-of-them",
                "expected a decimal integer",
            ),
            (
                "ATTENUO__AUDIT__CHECKPOINT_EVERY",
                "1.5",
                "expected a decimal integer",
            ),
            (
                "ATTENUO__TELEMETRY__TRACES__SAMPLE_RATIO",
                "half-of-them",
                "expected a number",
            ),
            ("ATTENUO__AUDIT__CHECKPOINT_EVERY", "-7777", "expected u64"),
            ("ATTENUO__TOKEN__DPOP", "sometimes-maybe", "expected one of"),
            (
                "ATTENUO__SERVER__LISTEN",
                "not-an-address",
                "the value is not shown",
            ),
            (
                "ATTENUO__ADMIN__LISTEN",
                "not-an-address",
                "the value is not shown",
            ),
        ] {
            let e = refused("", &[(var, value)]);
            assert!(e.contains(&format!("{var}: not a valid value")), "{e}");
            assert!(e.contains(expected), "{var}: {e}");
            assert!(!e.contains(value), "{var} echoed its value: {e}");
        }
    }

    #[test]
    fn dev_keys_are_refused() {
        for var in [
            "ATTENUO__DEV__ALLOW_ROOT_MINT",
            "ATTENUO__DEV__ALLOW_ROOT_MINT_OFF_LOOPBACK",
            "attenuo__dev__allow_root_mint",
            "ATTENUO__DEV__NO_SUCH_KEY",
        ] {
            let e = refused("", &[(var, "true")]);
            assert!(
                e.contains(&format!(
                    "{var}: [dev] keys cannot be set from the environment"
                )),
                "{e}"
            );
        }
        // Even false, and even when the file has the switch on: the file decides.
        let (cfg, _) = load("[dev]\nallow_root_mint = true\n", &[]).unwrap();
        assert!(cfg.dev.allow_root_mint);
        assert!(load(
            "[dev]\nallow_root_mint = true\n",
            &[("ATTENUO__DEV__ALLOW_ROOT_MINT", "false")]
        )
        .is_err());
    }

    #[test]
    fn lists_tables_of_names_and_arrays_of_tables_are_refused() {
        for (var, says) in [
            ("ATTENUO__AGENTS__ID", "[[agents]] is an array of tables"),
            (
                "ATTENUO__UPSTREAMS__URL",
                "[[upstreams]] is an array of tables",
            ),
            ("ATTENUO__IDPS", "[[idps]] is an array of tables"),
            (
                "ATTENUO__ROOT_GRANTS__AGENT",
                "[[root_grants]] is an array of tables",
            ),
            ("ATTENUO__ISSUER__PREVIOUS_KEY_PATHS", "is a list"),
            // ADR-0016: operators are file-only.
            (
                "ATTENUO__ADMIN__OPERATORS",
                "cannot be set from the environment",
            ),
            (
                "ATTENUO__ADMIN__OPERATORS__NAME",
                "cannot be set from the environment",
            ),
            (
                "ATTENUO__POLICY__CATALOG__GITHUB__READ__READONLY",
                "is a table of names",
            ),
            (
                "ATTENUO__POLICY__USER_ATTRIBUTES__TEAM",
                "is a table of names",
            ),
            (
                "ATTENUO__TELEMETRY__RESOURCE_ATTRIBUTES",
                "is a table of names",
            ),
        ] {
            let e = refused(FILE, &[(var, "x")]);
            assert!(e.contains(var) && e.contains(says), "{var}: {e}");
        }
    }

    #[test]
    fn an_optional_section_missing_from_the_file_is_not_created() {
        let e = refused("", &[("ATTENUO__AUDIT__SINK__URL", "https://sink.example")]);
        assert!(e.contains("[audit.sink] is not in the config file"), "{e}");
        let e = refused(
            "",
            &[("ATTENUO__APPROVALS__NOTIFY__URL", "https://n.example")],
        );
        assert!(
            e.contains("[approvals.notify] is not in the config file"),
            "{e}"
        );
    }

    #[test]
    fn an_empty_value_is_refused() {
        let e = refused(FILE, &[("ATTENUO__SERVER__PUBLIC_URL", "")]);
        assert!(
            e.contains("ATTENUO__SERVER__PUBLIC_URL: the value is empty"),
            "{e}"
        );
    }

    #[test]
    fn two_variables_for_one_key_are_refused() {
        let e = refused(
            "",
            &[
                ("ATTENUO__SERVER__LISTEN", "127.0.0.1:1"),
                ("attenuo__server__listen", "127.0.0.1:2"),
            ],
        );
        assert!(e.contains("sets [server] listen too"), "{e}");
    }

    #[test]
    fn secrets_are_never_echoed() {
        let secret = "s3cr3t-admin-token-0123456789abcdef0123456789";
        // Accepted: the result names the key, never the value.
        let (cfg, applied) = load(FILE, &[("ATTENUO__ADMIN__TOKEN", secret)]).unwrap();
        assert_eq!(cfg.admin.token.as_deref(), Some(secret));
        let listed: Vec<String> = applied.iter().map(ToString::to_string).collect();
        assert_eq!(listed, ["[admin] token (ATTENUO__ADMIN__TOKEN)"]);
        // Refused for every reason that can apply to it: none echoes it.
        let sink = "[audit.sink]\nkind = \"webhook\"\nurl = \"https://sink.example\"\n";
        for (text, vars) in [
            (
                FILE,
                vec![
                    ("ATTENUO__ADMIN__TOKEN", secret),
                    ("ATTENUO_ADMIN_TOKEN", "x"),
                ],
            ),
            (FILE, vec![("ATTENUO__ADMIN__TOKN", secret)]),
            (
                FILE,
                vec![
                    ("ATTENUO__ADMIN__TOKEN", secret),
                    ("attenuo__admin__token", secret),
                ],
            ),
            (sink, vec![("ATTENUO__AUDIT__SINK__BEARER_TOKN", secret)]),
            (FILE, vec![("ATTENUO__AUDIT__SINK__BEARER_TOKEN", secret)]),
            (FILE, vec![("ATTENUO__ADMIN__TOKEN__X", secret)]),
        ] {
            let e = refused(text, &vars);
            assert!(!e.contains(secret), "{e}");
        }
        let (cfg, _) = load(sink, &[("ATTENUO__AUDIT__SINK__BEARER_TOKEN", secret)]).unwrap();
        assert_eq!(
            cfg.audit.sink.unwrap().bearer_token.as_deref(),
            Some(secret)
        );
    }

    #[test]
    fn the_older_variables_are_not_overrides_and_conflict_when_both_are_set() {
        // ATTENUO_ADMIN_TOKEN and ATTENUO_LOG_FORMAT alone change nothing here: they keep
        // applying where they did (`Config::apply_env`, `LoggingSection::resolve_format`).
        let (cfg, applied) = load(
            FILE,
            &[
                (
                    "ATTENUO_ADMIN_TOKEN",
                    "env-admin-token-0123456789abcdef0123",
                ),
                ("ATTENUO_LOG_FORMAT", "json"),
                ("ATTENUO_CONFIG", "/etc/attenuo/config.toml"),
                ("ATTENUO_AUDIT_SINK_TOKEN", "t"),
            ],
        )
        .unwrap();
        assert_eq!(cfg, Config::from_toml(FILE).unwrap());
        assert!(applied.is_empty());
        let e = refused(
            FILE,
            &[
                ("ATTENUO__LOGGING__FORMAT", "json"),
                ("ATTENUO_LOG_FORMAT", "text"),
            ],
        );
        assert!(
            e.contains("ATTENUO__LOGGING__FORMAT: ATTENUO_LOG_FORMAT sets [logging] format too"),
            "{e}"
        );
        // Empty counts as unset for the older variables, as it always has.
        let (cfg, _) = load(
            FILE,
            &[
                ("ATTENUO__LOGGING__FORMAT", "json"),
                ("ATTENUO_LOG_FORMAT", ""),
            ],
        )
        .unwrap();
        assert_eq!(cfg.logging.format, crate::logging::LogFormat::Json);
    }

    #[test]
    fn single_underscore_variables_are_never_read() {
        let (cfg, applied) = load(
            FILE,
            &[
                ("ATTENUO_SERVER", "http://127.0.0.1:9999"),
                ("ATTENUO_TOKEN", "eyJhbGciOi"),
                ("ATTENUO_CLIENT_SECRET", "x"),
                ("ATTENUO_SERVER__LISTEN", "0.0.0.0:1"),
                ("ATTENUO_INTEGRATION", "1"),
                ("ATTENUOX__SERVER__LISTEN", "0.0.0.0:1"),
                ("PATH", "/usr/bin"),
            ],
        )
        .unwrap();
        assert_eq!(cfg, Config::from_toml(FILE).unwrap());
        assert!(applied.is_empty());
    }

    #[test]
    fn the_startup_checks_see_the_overridden_value() {
        // A weak admin token from the environment is refused off loopback like one in the
        // file.
        let (cfg, _) = load(
            "",
            &[
                ("ATTENUO__SERVER__LISTEN", "0.0.0.0:8080"),
                ("ATTENUO__ADMIN__TOKEN", "change-me"),
            ],
        )
        .unwrap();
        assert!(cfg.check_admin_token().is_err());
        // A value out of range parses, and the range check refuses it.
        let (cfg, _) = load("", &[("ATTENUO__LIMITS__HEADER_READ_TIMEOUT_SECONDS", "0")]).unwrap();
        assert!(cfg.limits.check().is_err());
    }

    #[test]
    fn a_bad_file_fails_as_before() {
        let e = refused(
            "[server]\nlistn = 1\n",
            &[("ATTENUO__SERVER__LISTEN", "127.0.0.1:1")],
        );
        assert!(e.contains("listn"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn names_and_values_that_are_not_utf8_are_refused() {
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![b'A', 0xff]);
        let e = Config::from_toml_with_env(
            "",
            vec![(OsString::from("ATTENUO__SERVER__LISTEN"), bad.clone())],
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("ATTENUO__SERVER__LISTEN: the value is not valid UTF-8"),
            "{e}"
        );
        let mut name = b"ATTENUO__SERVER__".to_vec();
        name.push(0xff);
        let e = Config::from_toml_with_env("", vec![(OsString::from_vec(name), bad.clone())])
            .unwrap_err()
            .to_string();
        assert!(e.contains("not valid UTF-8"), "{e}");
        // Other variables that are not UTF-8 are none of our business.
        assert!(Config::from_toml_with_env("", vec![(OsString::from("LANG"), bad)]).is_ok());
    }

    /// Every table of names (a map from names the operator chooses) must be in
    /// [`NAME_TABLES`], or a variable could reach into it. A map is an empty object in the
    /// defaults, and a section never is.
    #[test]
    fn every_table_of_names_is_listed() {
        let mut cfg = Config::default();
        cfg.audit.sink = Some(super::super::SinkSection::new(super::super::SinkKind::File));
        cfg.approvals.notify = Some(super::super::NotifySection::new("https://n.example"));
        let schema = serde_json::to_value(&cfg).unwrap();
        fn walk(node: &Json, path: &mut Vec<String>, found: &mut Vec<Vec<String>>) {
            if let Json::Object(map) = node {
                if map.is_empty() {
                    found.push(path.clone());
                }
                for (k, v) in map {
                    path.push(k.clone());
                    walk(v, path, found);
                    path.pop();
                }
            }
        }
        let mut found = Vec::new();
        walk(&schema, &mut Vec::new(), &mut found);
        for path in &found {
            assert!(
                in_name_table(path),
                "{path:?} is a table of names; add it to NAME_TABLES"
            );
        }
        assert_eq!(found.len(), NAME_TABLES.len(), "{found:?}");
    }
}
