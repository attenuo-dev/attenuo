//! `attenuo policy test --watch`: rerun when an input file changes. A polling loop over file
//! modification times and sizes, so it needs no file-notification dependency and works the same
//! on every platform and filesystem.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use attenuo_policy::testing::TestFile;

/// How often the files are looked at.
pub const POLL: Duration = Duration::from_millis(250);
/// How long the files must stay unchanged after a change before the rerun, so that an editor
/// writing several files (or one file in several steps) causes one run, not several.
pub const DEBOUNCE: Duration = Duration::from_millis(200);

/// Clears the terminal and moves the cursor home (ANSI), printed before each run.
pub const CLEAR: &str = "\x1b[2J\x1b[H";

/// What was seen of each watched file: its modification time and size, or `None` when it
/// could not be read (missing, for instance). A file that appears, disappears or changes
/// either value counts as changed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snapshot(BTreeMap<PathBuf, Option<(SystemTime, u64)>>);

impl Snapshot {
    pub fn take(paths: &[PathBuf]) -> Self {
        Self(
            paths
                .iter()
                .map(|p| {
                    let seen = std::fs::metadata(p)
                        .ok()
                        .and_then(|m| Some((m.modified().ok()?, m.len())));
                    (p.clone(), seen)
                })
                .collect(),
        )
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// The files a `policy test` run reads: the test files, and for each one that parses, its
/// policy file, catalog or server config, and base schema file (`schema_file` overrides the
/// config's). Worked out again before every run, since an edit can point a test file at
/// another policy file.
pub fn watched_paths(files: &[PathBuf], schema_file: Option<&Path>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = files.to_vec();
    for f in files {
        if let Ok(tf) = TestFile::load(f) {
            let tf = match schema_file {
                Some(s) => tf.with_schema_file(s),
                None => tf,
            };
            out.extend(tf.input_paths());
        }
    }
    if let Some(s) = schema_file {
        out.push(s.to_path_buf());
    }
    out.sort();
    out.dedup();
    out
}

/// Wait until a snapshot differs from `seen`, then until two snapshots [`DEBOUNCE`] apart are
/// equal, and return the settled one. `take` looks at the files and `sleep` waits; both are
/// parameters so the logic can be tested without a clock.
pub fn wait_for_change(
    seen: &Snapshot,
    mut take: impl FnMut() -> Snapshot,
    mut sleep: impl FnMut(Duration),
) -> Snapshot {
    let mut now = loop {
        sleep(POLL);
        let now = take();
        if now != *seen {
            break now;
        }
    };
    loop {
        sleep(DEBOUNCE);
        let again = take();
        if again == now {
            return again;
        }
        now = again;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_see_edits_creation_and_removal() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a.yaml");
        let b = d.path().join("b.cedar");
        std::fs::write(&a, "one").unwrap();
        let paths = vec![a.clone(), b.clone()];
        let first = Snapshot::take(&paths);
        assert_eq!(first.len(), 2);
        assert_eq!(first, Snapshot::take(&paths), "nothing changed");

        std::fs::write(&a, "a longer body").unwrap();
        let edited = Snapshot::take(&paths);
        assert_ne!(edited, first, "size changed");

        std::fs::write(&b, "permit(principal, action, resource);").unwrap();
        let created = Snapshot::take(&paths);
        assert_ne!(created, edited, "file appeared");

        std::fs::remove_file(&a).unwrap();
        assert_ne!(Snapshot::take(&paths), created, "file disappeared");
    }

    fn snap(n: u64) -> Snapshot {
        Snapshot(BTreeMap::from([(
            PathBuf::from("f"),
            Some((SystemTime::UNIX_EPOCH, n)),
        )]))
    }

    #[test]
    fn waits_for_a_change_then_for_it_to_settle() {
        // Unchanged twice, then three writes in a row, then quiet.
        let mut seq = vec![snap(0), snap(0), snap(1), snap(2), snap(3), snap(3)].into_iter();
        let mut slept = Vec::new();
        let settled = wait_for_change(&snap(0), || seq.next().unwrap(), |d| slept.push(d));
        assert_eq!(settled, snap(3));
        assert_eq!(
            slept,
            vec![POLL, POLL, POLL, DEBOUNCE, DEBOUNCE, DEBOUNCE],
            "three polls to see the change, then debounce until two looks agree"
        );
        assert!(seq.next().is_none());
    }

    #[test]
    fn watched_paths_include_what_each_test_file_reads() {
        let d = tempfile::tempdir().unwrap();
        let t = d.path().join("t.yaml");
        std::fs::write(
            &t,
            "policies: ./p.cedar\ncatalog: c.toml\ncases:\n  - name: x\n    call: { server: s, tool: t }\n    expect: deny\n",
        )
        .unwrap();
        std::fs::write(
            d.path().join("c.toml"),
            "[policy]\nschema_path = \"base.cedarschema\"\n",
        )
        .unwrap();
        let broken = d.path().join("broken.yaml");
        std::fs::write(&broken, "cases: [").unwrap();
        let got = watched_paths(&[t.clone(), broken.clone()], None);
        let names: Vec<String> = got
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec![
                "base.cedarschema",
                "broken.yaml",
                "c.toml",
                "p.cedar",
                "t.yaml"
            ]
        );
        // `--schema-file` replaces the config's schema.
        let other = d.path().join("other.cedarschema");
        let got = watched_paths(std::slice::from_ref(&t), Some(&other));
        assert!(got.contains(&other));
        assert!(!got.iter().any(|p| p.ends_with("base.cedarschema")));
    }
}
