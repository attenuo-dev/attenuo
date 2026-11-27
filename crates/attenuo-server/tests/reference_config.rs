//! `docs/reference/config.md` documents every key of the config file, under the heading of
//! its section, and no key the server does not accept.
//!
//! The server reads one TOML file into [`Config`], whose structs all carry
//! `deny_unknown_fields`. The proxy has no file of its own: its settings are the server's
//! `[proxy]` and `[[upstreams]]` (`attenuo_proxy::UpstreamConfig`). The CLI reads no config
//! file (`attenuo policy lint --config` reads the server's). So the keys of [`Config`] are
//! every key there is.
//!
//! How the keys are found, without reading Rust source:
//!
//! 1. [`FULL`] is a config with every section, every optional key and one entry of every
//!    array of tables set. It is serialized to JSON (as the environment overrides do), and
//!    the JSON is walked: an object is a section, anything else a key.
//! 2. That walk could miss a key that is not serialized (`skip_serializing_if`) and is unset
//!    in [`FULL`]. So every section is also asked for its fields: an unknown key is put into
//!    it and the deserializer's refusal (`unknown field ..., expected one of ...`) lists every
//!    field the struct accepts. A field the walk did not see fails the test, as does a
//!    section that accepts an unknown key (it lacks `deny_unknown_fields`, or it is a table
//!    of names missing from [`NAME_TABLES`]).
//! 3. A `null`, an empty array or an empty table in the walk fails the test too: it would
//!    hide the keys of a section that [`FULL`] does not set.
//!
//! Not covered: the members of a capability in `[[root_grants]] capabilities` (the token's
//! capability format, documented with the token) and the values a key takes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use attenuo_server::config::Config;
use serde_json::Value as Json;

const PAGE: &str = "docs/reference/config.md";

/// Keys whose value is a table of names chosen by the operator, not a section with fixed
/// keys, with the placeholder the page uses for an entry's name when the entries are
/// sections themselves (`[policy.catalog.<server>.<tool>]`). A table of names whose entries
/// are values (`headers`) is one key of its section. `*` matches any one name.
const NAME_TABLES: &[(&str, Option<&str>)] = &[
    ("policy.catalog", Some("<server>")),
    ("policy.catalog.*", Some("<tool>")),
    ("policy.catalog.*.*.inputs", None),
    ("policy.user_attributes", None),
    ("telemetry.resource_attributes", None),
    ("approvals.notify.headers", None),
    ("leases.notify.headers", None),
    ("idps.client_ids", None),
    ("idps.id_jag_ceiling.resources", None),
    ("idps.id_jag_ceiling.scopes", None),
    ("root_grants.attributes", None),
];

/// Keys whose value has a shape of its own that the page explains in prose, not keys of a
/// section: a capability is a string or the token's capability object.
const OPAQUE: &[&str] = &["root_grants.capabilities"];

/// A config that sets every section and every key, so that the walk sees all of them.
const FULL: &str = r#"
[server]
public_url = "https://attenuo.example.com"

[server.tls]
cert_pem_path = "server.crt"
key_pem_path = "server.key"
client_certificates = "optional"

[server.forwarded_client_cert]
listen = "127.0.0.1:8444"
trusted_peers = ["127.0.0.1/32"]

[issuer]
private_key_pem_path = "issuer.pem"
previous_key_paths = ["old.pem"]

[policy]
policies_path = "policies.cedar"
catalog_path = "catalog.json"
schema_path = "schema.cedarschema"
user_attributes = { department = "string" }

[policy.catalog.github.read_file]
destructive = false
output = "trusted"
inputs = { repo = "string" }
amount = "amount"
destination = "to"
outbound = ["url#host"]

[audit.sink]
kind = "webhook"
url = "https://sink.example/checkpoints"
bearer_token = "t"
path = "checkpoints.jsonl"
endpoint = "https://s3.example"
bucket = "b"
region = "r"
prefix = "p/"
access_key_id = "a"
secret_access_key = "s"
session_token = "s"
ca_pem_path = "sink-ca.pem"

[audit.retention]
prune = "auto"
keep_seconds = 7776000
interval_seconds = 3600
archive_dir = "/var/lib/attenuo/audit-archive"
max_entries_per_run = 1000000

[admin]
token = "t"
listen = "127.0.0.1:9102"

[[admin.operators]]
name = "alice"
token_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
role = "viewer"
expires_at = "2030-01-01T00:00:00Z"

[token]
dpop_future_skew_seconds = 10

[approvals]
client_id = "approver"

[approvals.notify]
url = "https://notify.example/hook"
headers = { X-Team = "ops" }

[leases.notify]
url = "https://notify.example/revoked"
headers = { X-Team = "ops" }

[[upstreams]]
name = "github"
url = "http://127.0.0.1:3001/mcp"

[[ext_authz]]
server = "github"
secret_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
dpop_url = "https://gateway.example/mcp"

[[idps]]
issuer = "https://idp.example"
jwks_url = "https://idp.example/jwks"
ca_pem_path = "idp-ca.pem"
client_ids = { planner = "planner-app" }
tenant = "t"
credentials = ["id-jag"]

[idps.id_jag_ceiling]
resources = { "https://mcp.example/github" = ["github"] }
scopes = { "repo.read" = ["github:read_file"] }

[[agents]]
id = "planner"
secret_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
jwks = "{}"
jwks_url = "https://keys.example/planner.json"
jwks_ttl_seconds = 300
ca_pem_path = "/etc/attenuo/client-ca.pem"
tls_client_cert_sha256 = ["0000000000000000000000000000000000000000000000000000000000000000"]
tls_client_ca_pem_path = "/etc/attenuo/agents-ca.pem"
tls_client_auth_san_uri = "spiffe://example.org/ns/agents/sa/planner"
tls_client_auth_san_dns = "planner.agents.internal"
tls_client_crl_paths = ["/etc/attenuo/agents-ca.crl"]
tls_client_crl_issuer_pem_path = "/etc/attenuo/agents-intermediates.pem"
tls_client_crl_stale = "refuse"
tls_client_crl_missing = "allow"

[[peps]]
id = "pep"
secret_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
jwks = "{}"
jwks_url = "https://keys.example/pep.json"
jwks_ttl_seconds = 300
ca_pem_path = "/etc/attenuo/client-ca.pem"
tls_client_cert_sha256 = ["0000000000000000000000000000000000000000000000000000000000000000"]
tls_client_ca_pem_path = "/etc/attenuo/agents-ca.pem"
tls_client_auth_san_uri = "spiffe://example.org/ns/agents/sa/planner"
tls_client_auth_san_dns = "planner.agents.internal"
tls_client_crl_paths = ["/etc/attenuo/agents-ca.crl"]
tls_client_crl_issuer_pem_path = "/etc/attenuo/agents-intermediates.pem"
tls_client_crl_stale = "refuse"
tls_client_crl_missing = "allow"

[[root_grants]]
issuer = "https://idp.example"
agent = "planner"
subject = "alice"
capabilities = ["github:*"]
attributes = { mfa = false }
may_act = ["coder"]

[[actor_trust]]
issuer = "https://spiffe.example"
jwks_url = "https://spiffe.example/jwks"
spiffe_trust_domain = "example.org"
spiffe_bundle_url = "https://spiffe.example/bundle"
ca_pem_path = "spire-ca.pem"
audience = "attenuo"
"#;

fn page() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(PAGE);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// `a.b.c` matches the pattern `a.*.c`. The index of an array entry (`idps.0.client_ids`)
/// is not part of the path a pattern names.
fn matches(pattern: &str, path: &[String]) -> bool {
    let p: Vec<&str> = pattern.split('.').collect();
    let path: Vec<&String> = path
        .iter()
        .filter(|s| !s.bytes().all(|b| b.is_ascii_digit()))
        .collect();
    p.len() == path.len() && p.iter().zip(path).all(|(a, b)| *a == "*" || a == b)
}

fn name_table(path: &[String]) -> Option<Option<&'static str>> {
    NAME_TABLES
        .iter()
        .find(|(p, _)| matches(p, path))
        .map(|(_, placeholder)| *placeholder)
}

fn opaque(path: &[String]) -> bool {
    OPAQUE.iter().any(|p| matches(p, path))
}

/// What the walk finds: each section (by the path the page writes, `policy.catalog.<server>.
/// <tool>`) with its keys, and the real path of one instance of it (for the probe).
#[derive(Default)]
struct Found {
    sections: BTreeMap<String, (BTreeSet<String>, Vec<String>)>,
    problems: Vec<String>,
}

fn walk(node: &Json, real: &mut Vec<String>, shown: &mut Vec<String>, found: &mut Found) {
    let Json::Object(map) = node else {
        unreachable!("only sections are walked")
    };
    let mut keys = BTreeSet::new();
    let mut subsections = Vec::new();
    for (k, v) in map {
        real.push(k.clone());
        let key_path = real.clone();
        match v {
            _ if opaque(&key_path) => {
                keys.insert(k.clone());
            }
            Json::Null => found.problems.push(format!(
                "`{}` is unset in FULL; give it a value so that its keys, if it has any, are seen",
                key_path.join(".")
            )),
            Json::Array(items) if items.is_empty() => found.problems.push(format!(
                "`{}` is an empty array in FULL; give it an entry",
                key_path.join(".")
            )),
            Json::Array(items) if items.iter().all(Json::is_object) => {
                subsections.push((k.clone(), v.clone()));
            }
            Json::Array(_) => {
                keys.insert(k.clone());
            }
            Json::Object(m) => match name_table(&key_path) {
                Some(None) => {
                    keys.insert(k.clone());
                }
                Some(Some(_)) if m.is_empty() => found.problems.push(format!(
                    "`{}` has no entry in FULL; give it one",
                    key_path.join(".")
                )),
                _ if m.is_empty() => found.problems.push(format!(
                    "`{}` is an empty table in FULL; if it is a table of names, add it to \
                     NAME_TABLES",
                    key_path.join(".")
                )),
                _ => subsections.push((k.clone(), v.clone())),
            },
            _ => {
                keys.insert(k.clone());
            }
        }
        real.pop();
    }
    found
        .sections
        .entry(shown.join("."))
        .or_insert_with(|| (BTreeSet::new(), real.clone()))
        .0
        .extend(keys);
    for (k, v) in subsections {
        real.push(k.clone());
        match &v {
            Json::Array(items) => {
                shown.push(k.clone());
                real.push("0".into());
                walk(&items[0], real, shown, found);
                real.pop();
                shown.pop();
            }
            Json::Object(m) => match name_table(real) {
                Some(Some(placeholder)) => {
                    // One entry stands for all: walk the first under the placeholder.
                    let (first, inner) = m.iter().next().expect("checked non-empty");
                    shown.push(k.clone());
                    shown.push(placeholder.to_string());
                    real.push(first.clone());
                    if let Some(Some(inner_placeholder)) = name_table(real) {
                        let Json::Object(im) = inner else {
                            panic!("{} is not a table", real.join("."))
                        };
                        let (ifirst, iv) = im.iter().next().unwrap_or_else(|| {
                            panic!("`{}` has no entry in FULL; give it one", real.join("."))
                        });
                        shown.push(inner_placeholder.to_string());
                        real.push(ifirst.clone());
                        walk(iv, real, shown, found);
                        real.pop();
                        shown.pop();
                    } else {
                        walk(inner, real, shown, found);
                    }
                    real.pop();
                    shown.pop();
                    shown.pop();
                }
                _ => {
                    shown.push(k.clone());
                    walk(&v, real, shown, found);
                    shown.pop();
                }
            },
            _ => unreachable!(),
        }
        real.pop();
    }
}

fn full() -> (toml::Value, Json) {
    let value: toml::Value = toml::from_str(FULL).expect("FULL is TOML");
    let cfg: Config = value
        .clone()
        .try_into()
        .unwrap_or_else(|e| panic!("FULL is not a valid config: {e}"));
    (value, serde_json::to_value(&cfg).unwrap())
}

/// The fields the struct at `real` (a path into [`FULL`]) accepts, from the refusal of an
/// unknown key put into it.
fn probe(value: &toml::Value, real: &[String]) -> Result<BTreeSet<String>, String> {
    const PROBE: &str = "zz_not_a_key";
    let mut v = value.clone();
    let mut node = &mut v;
    for seg in real {
        node = match node {
            // A section FULL leaves at its defaults is created empty.
            toml::Value::Table(t) => Some(
                t.entry(seg.as_str())
                    .or_insert_with(|| toml::Value::Table(toml::Table::new())),
            ),
            toml::Value::Array(a) => seg.parse::<usize>().ok().and_then(|i| a.get_mut(i)),
            _ => None,
        }
        .unwrap_or_else(|| panic!("FULL has no `{}`", real.join(".")));
    }
    let toml::Value::Table(t) = node else {
        panic!("`{}` is not a table in FULL", real.join("."))
    };
    t.insert(PROBE.into(), toml::Value::Integer(0));
    let err = match v.try_into::<Config>() {
        Ok(_) => {
            return Err(format!(
                "[{}] accepted an unknown key: give its struct `#[serde(deny_unknown_fields)]`, \
                 or, if it is a table of names, add it to NAME_TABLES",
                real.join(".")
            ))
        }
        Err(e) => e.to_string(),
    };
    let marker = format!("unknown field `{PROBE}`");
    let Some(at) = err.find(&marker) else {
        return Err(format!(
            "[{}] refused an unknown key, but not as an unknown field: {err}",
            real.join(".")
        ));
    };
    let rest = &err[at + marker.len()..];
    let rest = rest.lines().next().unwrap_or("");
    Ok(rest
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect())
}

/// The sections of the page (`## \`[audit]\``, `### \`[[admin.operators]]\``) with the keys
/// of their tables: the backticked names of the first cell of each row.
fn documented() -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in page().lines() {
        if line.starts_with('#') {
            let h = line.trim_start_matches('#').trim();
            current = h
                .strip_prefix('`')
                .and_then(|h| h.strip_suffix('`'))
                .map(|h| h.trim_start_matches('[').trim_end_matches(']').to_string());
            if let Some(c) = &current {
                assert!(
                    out.insert(c.clone(), BTreeSet::new()).is_none(),
                    "{PAGE}: two headings for `[{c}]`"
                );
            }
            continue;
        }
        let (Some(section), Some(row)) = (&current, line.strip_prefix('|')) else {
            continue;
        };
        let first = row.split('|').next().unwrap_or("").trim();
        if first.starts_with('`') {
            let keys = out.get_mut(section).expect("inserted at the heading");
            for (i, part) in first.split('`').enumerate() {
                if i % 2 == 1 {
                    keys.insert(part.to_string());
                }
            }
        }
    }
    out
}

fn found() -> (toml::Value, Found) {
    let (value, json) = full();
    let mut found = Found::default();
    walk(&json, &mut Vec::new(), &mut Vec::new(), &mut found);
    (value, found)
}

/// [`FULL`] really sets everything, and every section's fields are the ones the walk saw.
#[test]
fn the_walk_sees_every_field() {
    let (value, found) = found();
    let mut problems = found.problems.clone();
    for (shown, (keys, real)) in &found.sections {
        match probe(&value, real) {
            Ok(fields) => {
                // The walk's keys of this section, its subsections included.
                let prefix = if shown.is_empty() {
                    String::new()
                } else {
                    format!("{shown}.")
                };
                let mut seen: BTreeSet<String> = keys.clone();
                for other in found.sections.keys() {
                    if let Some(rest) = other.strip_prefix(&prefix).filter(|r| !r.is_empty()) {
                        seen.insert(rest.split('.').next().unwrap().to_string());
                    }
                }
                for f in fields.difference(&seen) {
                    problems.push(format!(
                        "[{shown}] accepts `{f}`, which FULL does not set; set it in FULL"
                    ));
                }
            }
            Err(e) => problems.push(e),
        }
    }
    assert!(
        problems.is_empty(),
        "the config guard's FULL config is incomplete:\n  {}",
        problems.join("\n  ")
    );
    assert!(found.sections.len() > 25, "{:?}", found.sections.keys());
}

/// Every section of the config has a heading on the page and every key a row in its table;
/// the page has no heading or row the config does not accept.
#[test]
fn every_key_is_documented_and_every_documented_key_exists() {
    let (_, found) = found();
    let doc = documented();
    let mut problems = Vec::new();
    for (shown, (keys, _)) in &found.sections {
        if shown.is_empty() {
            continue;
        }
        let Some(rows) = doc.get(shown) else {
            problems.push(format!(
                "the section `[{shown}]` has no heading (`## \\`[{shown}]\\``)"
            ));
            continue;
        };
        for k in keys.difference(rows) {
            problems.push(format!("`[{shown}] {k}` has no row in the section's table"));
        }
        for k in rows.difference(keys) {
            problems.push(format!(
                "`[{shown}] {k}` is documented but the config has no such key"
            ));
        }
    }
    for section in doc.keys() {
        if !found.sections.contains_key(section) {
            problems.push(format!(
                "the heading `[{section}]` names a section the config does not have"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "{PAGE} does not match the config keys (fix the page):\n  {}",
        problems.join("\n  ")
    );
}

/// The smallest config with one entry of every array of tables and every optional section:
/// only the keys that have no default are set, so everything else takes its default.
const MINIMAL: &str = r#"
[policy.catalog.github.read_file]

[audit.sink]
kind = "file"

[[admin.operators]]
name = "alice"
token_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
role = "viewer"

[approvals.notify]
url = "https://notify.example/hook"

[leases.notify]
url = "https://notify.example/revoked"

[[upstreams]]
name = "github"
url = "http://127.0.0.1:3001/mcp"

[[idps]]
issuer = "https://idp.example"

[[agents]]
id = "planner"

[[peps]]
id = "pep"

[[root_grants]]
issuer = "https://idp.example"
agent = "planner"
capabilities = ["github:*"]

[[actor_trust]]
audience = "attenuo"
"#;

/// The default a table cell states, when it states one plainly: a bare number or boolean
/// (`1000`), or backticked values only, separated by commas, optionally followed by a
/// parenthesis (`` `16777216` (16 MiB) ``). Quotes around a string are dropped. Anything
/// else (prose, "none", a computed default) gives `None` and is not checked.
fn stated_default(cell: &str) -> Option<Vec<String>> {
    let cell = cell.trim();
    let cell = match cell.find(" (") {
        Some(i) if cell.ends_with(')') => &cell[..i],
        _ => cell,
    };
    if cell == "true"
        || cell == "false"
        || (!cell.is_empty() && cell.parse::<f64>().is_ok() && !cell.contains(['e', 'E']))
    {
        return Some(vec![cell.to_string()]);
    }
    let mut values = Vec::new();
    for part in cell.split(", ") {
        let v = part.strip_prefix('`')?.strip_suffix('`')?;
        if v.contains('`') {
            return None;
        }
        values.push(v.trim_matches('"').to_string());
    }
    (!values.is_empty()).then_some(values)
}

/// The value of a key at its default, as the page would write it.
fn as_stated(v: &Json) -> Option<Vec<String>> {
    match v {
        Json::String(s) => Some(vec![s.clone()]),
        Json::Number(n) => Some(vec![n.to_string()]),
        Json::Bool(b) => Some(vec![b.to_string()]),
        Json::Object(m) if m.is_empty() => Some(vec!["{}".into()]),
        Json::Array(items) => items
            .iter()
            .map(|i| i.as_str().map(str::to_string))
            .collect(),
        // Unset: the page states what applies instead (an environment variable, a
        // computed value), which is not checked here.
        _ => None,
    }
}

/// Where the default of `[section] key` is in the JSON of [`MINIMAL`]: an array of tables
/// is its first entry, a placeholder the first name.
fn lookup<'a>(json: &'a Json, section: &str, key: &str) -> Option<&'a Json> {
    let mut node = json;
    for seg in section.split('.').chain(std::iter::once(key)) {
        if let Json::Array(items) = node {
            node = items.first()?;
        }
        node = match node {
            Json::Object(m) if seg.starts_with('<') => m.values().next()?,
            Json::Object(m) => m.get(seg)?,
            _ => return None,
        };
    }
    Some(node)
}

/// A default the page states plainly (`` | `listen` | `127.0.0.1:8080` | ``) is the default
/// the server applies: the value an empty key takes when [`MINIMAL`] is read.
#[test]
fn stated_defaults_are_the_real_defaults() {
    let cfg: Config = toml::from_str(MINIMAL).unwrap_or_else(|e| panic!("MINIMAL: {e}"));
    let json = serde_json::to_value(&cfg).unwrap();
    let mut checked = 0;
    let mut problems = Vec::new();
    let mut section: Option<String> = None;
    let mut has_default_column = false;
    for line in page().lines() {
        if line.starts_with('#') {
            let h = line.trim_start_matches('#').trim();
            section = h
                .strip_prefix('`')
                .and_then(|h| h.strip_suffix('`'))
                .map(|h| h.trim_start_matches('[').trim_end_matches(']').to_string());
            continue;
        }
        let Some(row) = line.strip_prefix('|') else {
            continue;
        };
        let cells: Vec<&str> = row.split('|').map(str::trim).collect();
        if cells.first() == Some(&"Key") {
            has_default_column = cells.get(1) == Some(&"Default");
            continue;
        }
        let (Some(section), true) = (&section, has_default_column) else {
            continue;
        };
        let (Some(key), Some(cell)) = (cells.first(), cells.get(1)) else {
            continue;
        };
        let Some(key) = key.strip_prefix('`').and_then(|k| k.strip_suffix('`')) else {
            continue;
        };
        if key.contains('`') {
            continue;
        }
        let Some(stated) = stated_default(cell) else {
            continue;
        };
        let Some(real) = lookup(&json, section, key).and_then(as_stated) else {
            continue;
        };
        checked += 1;
        if stated != real {
            problems.push(format!(
                "`[{section}] {key}`: the page says the default is {stated:?}, the server's is \
                 {real:?}"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "{PAGE} states defaults the server does not apply (fix the page):\n  {}",
        problems.join("\n  ")
    );
    // A sanity floor, so a parser that finds nothing cannot pass.
    assert!(checked > 100, "only {checked} defaults were checked");
}
