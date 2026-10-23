//! Where CLI secrets come from (SR-35).
//!
//! A secret given as an argument is readable by every local user through `/proc/<pid>/cmdline`
//! and `ps`, and lands in shell history and CI logs that echo commands. The flags stay for
//! compatibility and print a warning; the environment variable, `--…-file` and `--…-stdin` are
//! the supported ways.

use std::ffi::OsString;
use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context, Result};

/// Long-lived secrets that have a flag, and what to use instead. Delegation tokens
/// (`--token`, `--subject-token`) expire and have `ONBEHALF_TOKEN`; they are not warned about.
const ARGV_SECRETS: &[(&str, &str)] = &[
    (
        "--admin-token",
        "ONBEHALF_ADMIN_TOKEN, --admin-token-stdin or --admin-token-file",
    ),
    (
        "--client-secret",
        "ONBEHALF_CLIENT_SECRET, --client-secret-stdin or --client-secret-file",
    ),
];

/// One warning line for each secret flag present in `args` (the first item is the program
/// name), in the order the flags first appear. Only exact `--flag` and `--flag=value` tokens
/// count, so `--token-stdin` does not.
pub fn argv_warnings<I>(args: I) -> Vec<String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut out: Vec<String> = Vec::new();
    for arg in args.into_iter().skip(1) {
        let Some(arg) = arg.to_str() else { continue };
        if arg == "--" {
            break;
        }
        let name = arg.split_once('=').map_or(arg, |(n, _)| n);
        if let Some((flag, instead)) = ARGV_SECRETS.iter().find(|(f, _)| *f == name) {
            let line = format!(
                "warning: {flag} on the command line is visible to other local users (ps, \
                 /proc) and ends up in shell history; use {instead}"
            );
            if !out.contains(&line) {
                out.push(line);
            }
        }
    }
    out
}

/// Reads stdin at most once per process: two `--…-stdin` flags would otherwise race for it.
#[derive(Debug, Default)]
pub struct Stdin {
    used: bool,
}

impl Stdin {
    /// The first line of `reader`, without the line ending. Errors when stdin was already
    /// taken or the value is empty.
    pub fn secret(&mut self, what: &str, reader: impl Read) -> Result<String> {
        if self.used {
            bail!("{what}: standard input was already read for another value");
        }
        self.used = true;
        let mut buf = String::new();
        reader
            .take(64 * 1024)
            .read_to_string(&mut buf)
            .with_context(|| format!("reading {what} from standard input"))?;
        clean(what, &buf)
    }
}

/// The first line of `path`, without the line ending.
pub fn from_file(what: &str, path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {what} from {}", path.display()))?;
    clean(what, &text)
}

fn clean(what: &str, text: &str) -> Result<String> {
    let value = text.lines().next().unwrap_or("").trim_end_matches('\r');
    if value.is_empty() {
        bail!("{what} is empty");
    }
    Ok(value.to_string())
}

/// Pick the secret: `--…-stdin` or `--…-file` win over the flag or environment value (clap
/// makes the three mutually exclusive on the command line).
pub fn resolve(
    what: &str,
    literal: Option<String>,
    stdin: bool,
    file: Option<&Path>,
    input: &mut Stdin,
) -> Result<Option<String>> {
    if stdin {
        return input.secret(what, std::io::stdin().lock()).map(Some);
    }
    if let Some(path) = file {
        return from_file(what, path).map(Some);
    }
    Ok(literal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn warns_once_per_flag_with_the_alternative() {
        let w = argv_warnings(os(&[
            "onbehalf",
            "--admin-token",
            "t",
            "token",
            "exchange",
            "--client-secret=s",
            "--client-secret",
            "s2",
        ]));
        assert_eq!(w.len(), 2);
        assert!(w[0].starts_with("warning: --admin-token on the command line"));
        assert!(w[0].contains("ONBEHALF_ADMIN_TOKEN"));
        assert!(w[1].contains("--client-secret-stdin"));
        // One line each, and the secret itself is never echoed.
        assert!(w.iter().all(|l| !l.contains('\n') && !l.contains("s2")));
    }

    #[test]
    fn warns_only_for_the_long_lived_secrets_and_not_their_safe_forms() {
        // Delegation tokens expire and have ONBEHALF_TOKEN; no warning for them.
        assert!(argv_warnings(os(&["onbehalf", "call", "--token", "J"])).is_empty());
        assert!(
            argv_warnings(os(&["onbehalf", "token", "exchange", "--subject-token=J"])).is_empty()
        );
        assert!(argv_warnings(os(&[
            "onbehalf",
            "--admin-token-stdin",
            "--client-secret-file",
            "/run/s",
            "--admin-token-file=/x",
            "call",
            "--arg",
            "token=x",
        ]))
        .is_empty());
        // After `--` nothing is a flag.
        assert!(argv_warnings(os(&["onbehalf", "--", "--token", "x"])).is_empty());
    }

    #[test]
    fn stdin_takes_the_first_line_once() {
        let mut input = Stdin::default();
        assert_eq!(
            input.secret("a", "s3cret\r\nignored\n".as_bytes()).unwrap(),
            "s3cret"
        );
        let e = input.secret("b", "x".as_bytes()).unwrap_err();
        assert!(e.to_string().contains("already read"), "{e}");
        assert!(Stdin::default().secret("a", "".as_bytes()).is_err());
        assert!(Stdin::default().secret("a", "\n".as_bytes()).is_err());
    }

    #[test]
    fn file_secret_is_trimmed_and_errors_name_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secret");
        std::fs::write(&p, "hunter2\n").unwrap();
        assert_eq!(from_file("client secret", &p).unwrap(), "hunter2");
        std::fs::write(&p, "\n").unwrap();
        assert!(from_file("client secret", &p).is_err());
        let missing = dir.path().join("nope");
        let e = from_file("client secret", &missing).unwrap_err();
        assert!(format!("{e:#}").contains("nope"), "{e:#}");
    }

    #[test]
    fn resolve_prefers_file_over_the_literal() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s");
        std::fs::write(&p, "from-file").unwrap();
        let mut input = Stdin::default();
        assert_eq!(
            resolve("x", Some("env".into()), false, Some(&p), &mut input).unwrap(),
            Some("from-file".into())
        );
        assert_eq!(
            resolve("x", Some("env".into()), false, None, &mut input).unwrap(),
            Some("env".into())
        );
        assert_eq!(resolve("x", None, false, None, &mut input).unwrap(), None);
    }
}
