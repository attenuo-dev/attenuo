//! `docs/reference/cli.md` names every subcommand and every long flag of `attenuo`, each in
//! its command's section, and names no subcommand or flag that does not exist.
//!
//! The commands and flags come from the real clap tree ([`Cli::command`]), walked
//! recursively, so a new subcommand or flag fails here until the page has it. Commands and
//! flags that clap marks hidden are exempt from the "must be documented" direction (the page
//! may still mention them, for example a deprecated spelling). `--help` and `--version` are
//! clap's own and exempt.
//!
//! How the page is read:
//!
//! - Each `###` heading under `## Commands` is one section. The command paths it covers are
//!   the leading words of each backticked span of the heading (`` `lease revoke <ID>` ``); a
//!   span that is a single word that is not a top-level command is a sibling of the previous
//!   span (`` `approval list` / `show` ``).
//! - A long flag of a command must appear as `--flag` in a section that covers the command
//!   (a flag of a command with subcommands: in a section of one of them). The flags of the
//!   top level (`--server`) and the global flags must appear under `## Global options`.
//! - A `--flag` the page writes must exist. Inside a command section, it must be a flag of
//!   the command the text names: the command path the backticked span or code line starts
//!   with (`` `audit show --id` ``, `attenuo token exchange --actor ...`), or else one of the
//!   section's commands. The flags of a command's ancestors and the global flags count for it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use clap::{Command, CommandFactory};

use crate::cli::Cli;

const PAGE: &str = "docs/reference/cli.md";

/// One command of the tree (keyed by its path from the top, empty for `attenuo` itself):
/// whether it is hidden, the long flags help shows (visible aliases included), every long
/// flag it accepts (hidden ones and every alias included), and its subcommands.
struct Node {
    hidden: bool,
    visible_flags: BTreeSet<String>,
    all_flags: BTreeSet<String>,
    children: BTreeSet<String>,
}

fn collect(cmd: &Command, path: Vec<String>, hidden: bool, out: &mut BTreeMap<Vec<String>, Node>) {
    let mut node = Node {
        hidden,
        visible_flags: BTreeSet::new(),
        all_flags: BTreeSet::new(),
        children: BTreeSet::new(),
    };
    for arg in cmd.get_arguments() {
        let Some(long) = arg.get_long() else {
            continue;
        };
        if matches!(long, "help" | "version") {
            continue;
        }
        let mut names = vec![long.to_string()];
        let visible: Vec<String> = arg
            .get_visible_aliases()
            .unwrap_or_default()
            .into_iter()
            .map(str::to_string)
            .collect();
        let all: Vec<String> = arg
            .get_all_aliases()
            .unwrap_or_default()
            .into_iter()
            .map(str::to_string)
            .collect();
        if !arg.is_hide_set() && !hidden {
            node.visible_flags.insert(long.to_string());
            node.visible_flags.extend(visible);
        }
        names.extend(all);
        node.all_flags.extend(names);
    }
    for sub in cmd.get_subcommands() {
        if sub.get_name() == "help" {
            continue;
        }
        node.children.insert(sub.get_name().to_string());
        let mut p = path.clone();
        p.push(sub.get_name().to_string());
        collect(sub, p, hidden || sub.is_hide_set(), out);
    }
    out.insert(path, node);
}

/// The clap tree and the global flags (defined at the top, usable after any subcommand).
fn tree() -> (BTreeMap<Vec<String>, Node>, BTreeSet<String>) {
    let cmd = Cli::command();
    let globals = cmd
        .get_arguments()
        .filter(|a| a.is_global_set())
        .filter_map(|a| a.get_long().map(str::to_string))
        .collect();
    let mut out = BTreeMap::new();
    collect(&cmd, Vec::new(), false, &mut out);
    (out, globals)
}

fn page() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(PAGE);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Every inline code span of `line`: the text before it since the previous span, and the
/// text between its backticks.
fn spans_with_gaps(line: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find('`') {
        // A run of backticks opens a span closed by the same run.
        let ticks = rest[start..].chars().take_while(|c| *c == '`').count();
        let open = &rest[start..start + ticks];
        let body = &rest[start + ticks..];
        let Some(end) = body.find(open) else {
            break;
        };
        out.push((&rest[..start], &body[..end]));
        rest = &body[end + ticks..];
    }
    out
}

/// The text between the backticks of every inline code span of `line`.
fn spans(line: &str) -> Vec<&str> {
    spans_with_gaps(line).into_iter().map(|(_, s)| s).collect()
}

/// Is `gap`, the text between two spans, only a list separator (`, `, ` or `, ` / `)?
fn is_list_gap(gap: &str) -> bool {
    gap.split(|c: char| c.is_whitespace() || c == ',' || c == '/')
        .all(|w| w.is_empty() || w == "or" || w == "and")
}

/// Every `--flag` written in `text`.
fn flags_in(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while let Some(at) = text[i..].find("--") {
        let pos = i + at;
        i = pos + 2;
        let before_ok =
            pos == 0 || !(bytes[pos - 1].is_ascii_alphanumeric() || bytes[pos - 1] == b'-');
        let name: String = text[pos + 2..]
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
            .collect();
        if before_ok && name.starts_with(|c: char| c.is_ascii_lowercase()) {
            let name = name.trim_end_matches('-').to_string();
            i = pos + 2 + name.len();
            out.push(name);
        }
    }
    out
}

/// The command path that `words` names from the top, walking subcommand names and skipping
/// anything else (options and their values). With `leading_options` false (inline code),
/// the first word must be a command; on a command line, top-level options may come first.
fn path_of(
    words: &[&str],
    tree: &BTreeMap<Vec<String>, Node>,
    leading_options: bool,
) -> Option<Vec<String>> {
    let mut path: Vec<String> = Vec::new();
    for w in words {
        if tree[&path].children.contains(*w) {
            path.push((*w).to_string());
        } else if path.is_empty() && !leading_options {
            return None;
        }
    }
    (!path.is_empty()).then_some(path)
}

/// One `###` section under `## Commands`: the command paths its heading names and its text
/// (heading included).
struct Section {
    heading: String,
    commands: Vec<Vec<String>>,
    text: String,
}

fn parse_page(text: &str, tree: &BTreeMap<Vec<String>, Node>) -> (String, Vec<Section>) {
    let mut global = String::new();
    let mut sections: Vec<Section> = Vec::new();
    let mut part = "";
    for line in text.lines() {
        if let Some(h) = line.strip_prefix("## ") {
            part = if h.trim() == "Global options" {
                "global"
            } else if h.trim() == "Commands" {
                "commands"
            } else {
                ""
            };
            continue;
        }
        if part == "global" {
            global.push_str(line);
            global.push('\n');
            continue;
        }
        if part != "commands" {
            continue;
        }
        if let Some(h) = line.strip_prefix("### ") {
            let mut commands: Vec<Vec<String>> = Vec::new();
            for span in spans(h) {
                let words: Vec<&str> = span
                    .split_whitespace()
                    .take_while(|w| !w.starts_with(['-', '<', '[']))
                    .collect();
                let path = if words.len() == 1 && !tree[&Vec::new()].children.contains(words[0]) {
                    commands.last().map(|prev| {
                        let mut p = prev[..prev.len() - 1].to_vec();
                        p.push(words[0].to_string());
                        p
                    })
                } else {
                    Some(words.iter().map(|w| (*w).to_string()).collect())
                };
                let Some(path) = path else {
                    panic!("{PAGE}: the heading `### {h}` names no command");
                };
                assert!(
                    tree.contains_key(&path),
                    "{PAGE}: the heading `### {h}` documents `attenuo {}`, which is not a \
                     command of the CLI; remove the section or fix the name",
                    path.join(" ")
                );
                if !commands.contains(&path) {
                    commands.push(path);
                }
            }
            assert!(
                !commands.is_empty(),
                "{PAGE}: the heading `### {h}` names no command in backticks"
            );
            sections.push(Section {
                heading: h.to_string(),
                commands,
                text: format!("{line}\n"),
            });
            continue;
        }
        if let Some(s) = sections.last_mut() {
            s.text.push_str(line);
            s.text.push('\n');
        }
    }
    (global, sections)
}

fn has_flag(text: &str, flag: &str) -> bool {
    flags_in(text).iter().any(|f| f == flag)
}

/// Every subcommand of the CLI has a section, and every flag a command takes is written in
/// one of its sections (the top-level and global flags under `## Global options`).
#[test]
fn every_command_and_flag_is_documented() {
    let text = page();
    let (tree, globals) = tree();
    let (global, sections) = parse_page(&text, &tree);
    assert!(
        sections.len() > 20,
        "{PAGE}: found only {} sections",
        sections.len()
    );
    let mut missing = Vec::new();
    for (path, node) in &tree {
        if node.hidden {
            continue;
        }
        if path.is_empty() {
            for flag in &node.visible_flags {
                if !has_flag(&global, flag) {
                    missing.push(format!(
                        "the top-level flag `--{flag}` is not under `## Global options`"
                    ));
                }
            }
            continue;
        }
        // The sections of this command, or of its descendants when it has subcommands.
        let own: Vec<&Section> = sections
            .iter()
            .filter(|s| s.commands.iter().any(|c| c.starts_with(path)))
            .collect();
        let name = path.join(" ");
        if node.children.is_empty() && !sections.iter().any(|s| s.commands.contains(path)) {
            missing.push(format!(
                "`attenuo {name}` has no `### `{name}`` section under `## Commands`"
            ));
            continue;
        }
        for flag in &node.visible_flags {
            if globals.contains(flag) {
                continue;
            }
            if !own.iter().any(|s| has_flag(&s.text, flag)) {
                missing.push(format!(
                    "`attenuo {name} --{flag}` is not written in the `{name}` section"
                ));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "{PAGE} is missing what the CLI accepts (add each to the page):\n  {}",
        missing.join("\n  ")
    );
}

/// The flags of `path`, its ancestors and the global flags: every flag that may follow the
/// command on a command line.
fn usable_flags(
    path: &[String],
    tree: &BTreeMap<Vec<String>, Node>,
    globals: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut out = globals.clone();
    for n in 0..=path.len() {
        if let Some(node) = tree.get(&path[..n]) {
            out.extend(node.all_flags.iter().cloned());
        }
    }
    out
}

/// Every flag the page writes exists, on the command the text is about.
#[test]
fn every_documented_flag_exists() {
    let text = page();
    let (tree, globals) = tree();
    let (_, sections) = parse_page(&text, &tree);
    let anywhere: BTreeSet<String> = tree
        .values()
        .flat_map(|n| n.all_flags.iter().cloned())
        .chain(globals.iter().cloned())
        .chain(["help".to_string(), "version".to_string()])
        .collect();
    let mut stale = Vec::new();
    for flag in flags_in(&text) {
        if !anywhere.contains(&flag) {
            stale.push(format!("`--{flag}` is not a flag of any command"));
        }
    }
    for s in &sections {
        let section_flags: BTreeSet<String> = s
            .commands
            .iter()
            .flat_map(|c| usable_flags(c, &tree, &globals))
            .collect();
        let mut in_code = false;
        for line in s.text.lines() {
            if line.trim_start().starts_with("```") {
                in_code = !in_code;
                continue;
            }
            // (text, the command it names if any)
            let mut pieces: Vec<(&str, Option<Vec<String>>)> = Vec::new();
            if in_code {
                // A command line: what follows `attenuo` names the command.
                let words: Vec<&str> = line.split_whitespace().collect();
                let named = words
                    .iter()
                    .position(|w| *w == "attenuo")
                    .and_then(|i| path_of(&words[i + 1..], &tree, true));
                pieces.push((line, named));
            } else {
                // Inline code spans; a flag outside one is only checked to exist (above). A
                // span names a command when it starts with a whole command path
                // (`` `audit show --id` ``; a lone word such as `admin` is often a role or a
                // value, not the command). A span of flags alone that continues a list
                // started by a span naming a command with a flag belongs to that command
                // (`` `audit export --kind`, `--tool` or `--decision` ``); any other belongs
                // to the section.
                let mut last: Option<Vec<String>> = None;
                for (gap, span) in spans_with_gaps(line) {
                    if !is_list_gap(gap) {
                        last = None;
                    }
                    let words: Vec<&str> = span.split_whitespace().collect();
                    let words = match words.first() {
                        Some(&"attenuo") => &words[1..],
                        _ => &words[..],
                    };
                    let named =
                        path_of(words, &tree, false).filter(|p| tree[p].children.is_empty());
                    if named.is_some() && !flags_in(span).is_empty() {
                        last.clone_from(&named);
                    }
                    pieces.push((span, named.or_else(|| last.clone())));
                }
            }
            for (piece, named) in pieces {
                let allowed = match &named {
                    Some(path) => usable_flags(path, &tree, &globals),
                    None => section_flags.clone(),
                };
                for flag in flags_in(piece) {
                    if anywhere.contains(&flag) && !allowed.contains(&flag) {
                        let whose = match &named {
                            Some(p) => format!("`attenuo {}`", p.join(" ")),
                            None => format!("the section's command(s) `### {}`", s.heading),
                        };
                        stale.push(format!(
                            "`--{flag}` in the section `### {}` is not a flag of {whose}: `{}`",
                            s.heading,
                            piece.trim()
                        ));
                    }
                }
            }
        }
    }
    assert!(
        stale.is_empty(),
        "{PAGE} documents flags the CLI does not accept there (fix or remove each):\n  {}",
        stale.join("\n  ")
    );
}
