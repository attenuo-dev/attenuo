//! `docs/reference/http-api.md` lists every route the server mounts, on any of its listeners
//! (main, `[admin] listen`, the `[admin_ui]` console, `[metrics]`), and no route it does not
//! mount.
//!
//! axum cannot list the routes of a built `Router`, so the routes are read from the sources,
//! as the `ROUTE_ROLES` test in `src/operators.rs` reads the admin routes: every
//! `.route("<path>", <method router>)` of the server and proxy crates outside their unit
//! tests, with the methods of the method router (`get(..).post(..)`). To keep that complete:
//!
//! - a `.route(` whose path is not a string literal or a `&str` constant of the same file, or
//!   whose method router has a call this file does not know (`any(..)`, `on(..)`), fails;
//! - mounting a route any other way (`.nest(`, `.nest_service(`, `.route_service(`,
//!   `.fallback_service(`) fails, so it cannot pass unseen;
//! - the admin routes found must be exactly `attenuo_server::operators::ROUTE_ROLES`.
//!
//! On the page, a route is a backticked `METHOD /path` anywhere (the query, `?limit&cursor`,
//! is dropped). `` `GET /admin/audit...` `` stands for the `GET` routes under that prefix.
//! Not checked: which listener serves a route, and the conditions under which it is mounted
//! (`POST /admin/root-token` only with `[dev] allow_root_mint`); the page says those in prose.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use attenuo_server::operators::ROUTE_ROLES;

const PAGE: &str = "docs/reference/http-api.md";

/// The crates whose sources mount routes on the server's listeners.
const CRATES: &[&str] = &["crates/attenuo-server/src", "crates/attenuo-proxy/src"];

/// The method routers this file reads; anything else at the top of a method router fails.
const METHODS: &[(&str, &str)] = &[
    ("get", "GET"),
    ("post", "POST"),
    ("put", "PUT"),
    ("patch", "PATCH"),
    ("delete", "DELETE"),
];

/// Calls on a method router that add no method.
const LAYERS: &[&str] = &["layer", "route_layer", "with_state"];

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every `.rs` file under `dir`, recursively, without its unit test modules.
fn sources(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "rs") {
                let name = p.file_name().unwrap().to_string_lossy();
                // A fake upstream and the proxy's test doubles, not routes of the server.
                if name == "testing.rs" || name == "tests.rs" || name.ends_with("_tests.rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&p).unwrap();
                let kept = without_test_modules(&text);
                assert!(
                    !kept.contains("#[test]") && !kept.contains("#[tokio::test"),
                    "{}: a unit test is left after removing the test modules",
                    p.display()
                );
                out.push((p, kept));
            }
        }
    }
    out.sort();
    out
}

/// `text` without its `#[cfg(test)] mod <name> { ... }` modules (unit tests mount routes of
/// their own, such as a slow handler).
fn without_test_modules(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("#[cfg(test)]\nmod ") {
        out.push_str(&rest[..at]);
        let module = &rest[at..];
        let open = module.find('{').unwrap_or(module.len());
        if let Some(semi) = module[..open].find(';') {
            // `mod name;`: a file of its own, which `sources` leaves out by its name.
            let name = module["#[cfg(test)]\nmod ".len()..semi].trim();
            assert!(
                name == "tests" || name.ends_with("_tests"),
                "the test module `{name}` is a file whose name this test does not skip"
            );
            rest = &module[semi + 1..];
            continue;
        }
        // Match braces, skipping string literals and the char literals `'{'` and `'}'`.
        let bytes = module.as_bytes();
        let (mut depth, mut i, mut in_str) = (0usize, open, false);
        while i < bytes.len() {
            match bytes[i] {
                b'\\' if in_str => i += 1,
                b'"' => in_str = !in_str,
                b'\'' if !in_str && bytes.get(i + 2) == Some(&b'\'') => i += 2,
                b'{' if !in_str => depth += 1,
                b'}' if !in_str => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        rest = &module[(i + 1).min(module.len())..];
    }
    out.push_str(rest);
    out
}

/// `text` with every run of whitespace turned into one space.
fn squash(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The string literal at the start of `s`, if there is one, and what follows it.
fn literal_at(s: &str) -> Option<(&str, &str)> {
    let s = s.strip_prefix('"')?;
    let end = s.find('"')?;
    Some((&s[..end], &s[end + 1..]))
}

/// The value of `const NAME: &str = "..."` in `text`.
fn constant(text: &str, name: &str) -> Option<String> {
    let marker = format!("const {name}: &str = ");
    let at = text.find(&marker)?;
    literal_at(&text[at + marker.len()..]).map(|(v, _)| v.to_string())
}

/// The text up to the parenthesis that closes the one already open, and the text after it.
fn until_close(s: &str) -> (&str, &str) {
    let mut depth = 1usize;
    for (i, ch) in s.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return (&s[..i], &s[i + 1..]);
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced parentheses: {s}")
}

/// The methods of a method router: the calls at its top level (`post(a).get(b)`), each a
/// method or a layer.
fn methods_of(router: &str, file: &Path, path: &str) -> Vec<&'static str> {
    let mut out = Vec::new();
    let mut rest = router.trim().trim_end_matches(',').trim_end();
    while !rest.is_empty() {
        rest = rest.strip_prefix('.').unwrap_or(rest).trim_start();
        let Some(open) = rest.find('(') else {
            panic!(
                "{}: the method router of `{path}` ends in `{rest}`, which this test cannot read",
                file.display()
            );
        };
        let name = rest[..open].trim();
        let name = name.rsplit("::").next().unwrap_or(name);
        if let Some((_, m)) = METHODS.iter().find(|(f, _)| *f == name) {
            out.push(*m);
        } else if !LAYERS.contains(&name) {
            panic!(
                "{}: the method router of `{path}` calls `{name}(..)`; teach \
                 tests/reference_http_api.rs which methods it routes",
                file.display()
            );
        }
        let (_, after) = until_close(&rest[open + 1..]);
        rest = after.trim_start();
    }
    assert!(
        !out.is_empty(),
        "{}: no method found for the route `{path}`",
        file.display()
    );
    out
}

/// Every (method, path) the sources mount.
fn mounted() -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for dir in CRATES {
        for (file, text) in sources(&workspace().join(dir)) {
            let text = squash(&text);
            for other in [
                ".nest(",
                ".nest_service(",
                ".route_service(",
                ".fallback_service(",
            ] {
                assert!(
                    !text.contains(other),
                    "{}: a route is mounted with `{other}..)`, which \
                     tests/reference_http_api.rs does not read; teach it, so that the route \
                     is checked against {PAGE}",
                    file.display()
                );
            }
            let mut rest = text.as_str();
            while let Some(at) = rest.find(".route(") {
                rest = &rest[at + ".route(".len()..];
                let (args, after) = until_close(rest);
                rest = after;
                let args = args.trim();
                let (path, router) = if let Some((lit, after)) = literal_at(args) {
                    (lit.to_string(), after)
                } else {
                    let (name, after) = args.split_once(',').unwrap_or((args, ""));
                    let name = name.trim();
                    let value = constant(&text, name).unwrap_or_else(|| {
                        panic!(
                            "{}: `.route({name}, ..)`: the path is neither a string literal \
                             nor a `&str` constant of the file",
                            file.display()
                        )
                    });
                    (value, after)
                };
                let router = router.trim_start().strip_prefix(',').unwrap_or(router);
                for m in methods_of(router, &file, &path) {
                    out.insert((m.to_string(), path.clone()));
                }
            }
        }
    }
    out
}

/// Every backticked `METHOD /path` on the page, without its query.
fn documented() -> BTreeSet<(String, String)> {
    let path = workspace().join(PAGE);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut out = BTreeSet::new();
    for (i, span) in text.split('`').enumerate() {
        if i % 2 == 0 {
            continue;
        }
        let Some((method, route)) = span.split_once(' ') else {
            continue;
        };
        if !METHODS.iter().any(|(_, m)| *m == method) || !route.starts_with('/') {
            continue;
        }
        let route = route.split('?').next().unwrap_or(route);
        out.insert((method.to_string(), route.to_string()));
    }
    out
}

/// Every mounted route is on the page, and every route on the page is mounted.
#[test]
fn every_route_is_documented_and_every_documented_route_is_mounted() {
    let mounted = mounted();
    let documented = documented();
    // A sanity floor, so a parser that finds nothing cannot pass.
    assert!(mounted.len() > 30, "{mounted:?}");
    let mut problems = Vec::new();
    for (m, p) in &mounted {
        if !documented.contains(&(m.clone(), p.clone())) {
            problems.push(format!(
                "`{m} {p}` is mounted but the page does not list it"
            ));
        }
    }
    for (m, p) in &documented {
        let found = match p.strip_suffix("...") {
            Some(prefix) => mounted
                .iter()
                .any(|(m2, p2)| m2 == m && p2.starts_with(prefix)),
            None => mounted.contains(&(m.clone(), p.clone())),
        };
        if !found {
            problems.push(format!(
                "`{m} {p}` is on the page but no listener mounts it"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "{PAGE} does not match the mounted routes (fix the page):\n  {}",
        problems.join("\n  ")
    );
}

/// The admin routes found here are the routes of `ROUTE_ROLES`, which `src/operators.rs`
/// checks against the admin routers on its own: the two readings of the sources agree.
#[test]
fn admin_routes_are_route_roles() {
    let found: BTreeSet<(String, String)> = mounted()
        .into_iter()
        .filter(|(_, p)| p.starts_with("/admin/") && !p.starts_with("/admin/ui"))
        .collect();
    let roles: BTreeSet<(String, String)> = ROUTE_ROLES
        .iter()
        .map(|(m, p, _)| (m.to_string(), p.to_string()))
        .collect();
    assert_eq!(found, roles);
}
