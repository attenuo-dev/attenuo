//! The metrics table of `docs/reference/http-api.md` (`## Metrics`) lists every series the
//! server writes, with its type, and no series it does not write.
//!
//! The series are read from a fresh [`attenuo_server::metrics::Metrics`]'s text and from the
//! `audit_wal_*` series, which appear only when the WAL checkpointer runs (the page says so in
//! prose). A row is a table line whose first cell is a backticked name.

use std::collections::BTreeMap;
use std::path::Path;

const PAGE: &str = "docs/reference/http-api.md";

/// Series written only when a source is set; their rows are checked against the page alone.
const CONDITIONAL: &[(&str, &str)] = &[
    ("audit_wal_checkpoints_total", "counter"),
    ("audit_wal_locked_passes_total", "counter"),
    ("audit_wal_backstops_total", "counter"),
    ("audit_wal_presyncs_total", "counter"),
    ("audit_wal_frames", "gauge"),
    ("audit_wal_last_complete_timestamp_seconds", "gauge"),
];

/// `name -> type` of the page's metrics table.
fn documented() -> BTreeMap<String, String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(PAGE);
    let text = std::fs::read_to_string(path).unwrap();
    let section = text
        .split("\n## Metrics\n")
        .nth(1)
        .expect("no ## Metrics section");
    let section = section.split("\n## ").next().unwrap();
    let mut rows = BTreeMap::new();
    for line in section.lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() < 4 || !cells[1].starts_with('`') {
            continue;
        }
        let name = cells[1].trim_matches('`').to_string();
        assert!(
            rows.insert(name.clone(), cells[2].to_string()).is_none(),
            "{name} is listed twice in {PAGE}"
        );
    }
    rows
}

/// `name -> type` of the series a fresh server writes, from the `# TYPE` lines.
fn written() -> BTreeMap<String, String> {
    let text = attenuo_server::metrics::Metrics::new().render();
    text.lines()
        .filter_map(|l| l.strip_prefix("# TYPE attenuo_"))
        .map(|l| {
            let (name, kind) = l.split_once(' ').unwrap();
            (name.to_string(), kind.to_string())
        })
        .collect()
}

#[test]
fn the_metrics_table_matches_the_series() {
    let documented = documented();
    let mut written = written();
    for (name, kind) in CONDITIONAL {
        assert!(
            written
                .insert((*name).to_string(), (*kind).to_string())
                .is_none(),
            "{name} is written without its source; take it out of CONDITIONAL"
        );
    }
    for (name, kind) in &written {
        match documented.get(name) {
            None => panic!("{name} ({kind}) is not in the metrics table of {PAGE}"),
            Some(doc) => assert_eq!(doc, kind, "{name}: the type in {PAGE}"),
        }
    }
    for name in documented.keys() {
        assert!(
            written.contains_key(name),
            "{PAGE} lists {name}, which the server does not write"
        );
    }
}
