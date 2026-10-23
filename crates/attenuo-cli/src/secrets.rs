//! Where CLI secrets come from (SR-35).
//!
//! A secret given as an argument is readable by every local user through `/proc/<pid>/cmdline`
//! and `ps`, and lands in shell history and CI logs that echo commands. The flags stay for
//! compatibility and print a warning; the environment variable, `--…-file` and stdin
//! (`--…-stdin`, or `-` as the value of `--token` / `--subject-token`) are the supported ways.
//!
//! The environment variables are read here, not by clap: clap counts a value from the
//! environment as given, so `ATTENUO_TOKEN` in the environment would make `--token-file` a
//! conflict instead of an override.

use std::ffi::OsString;
use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context, Result};

/// Environment variable for the admin token.
pub const ADMIN_TOKEN_ENV: &str = "ATTENUO_ADMIN_TOKEN";
/// Environment variable for the agent's client secret.
pub const CLIENT_SECRET_ENV: &str = "ATTENUO_CLIENT_SECRET";
/// Environment variable for the delegation token (`--token`, `--subject-token`).
pub const TOKEN_ENV: &str = "ATTENUO_TOKEN";

/// Secrets that have a flag, and what to use instead.
const ARGV_SECRETS: &[(&str, &str)] = &[
    (
        "--admin-token",
        "ATTENUO_ADMIN_TOKEN, --admin-token-stdin or --admin-token-file",
    ),
    (
        "--client-secret",
        "ATTENUO_CLIENT_SECRET, --client-secret-stdin or --client-secret-file",
    ),
    (
        "--token",
        "ATTENUO_TOKEN, --token-file or `--token -` (stdin)",
    ),
    (
        "--subject-token",
        "ATTENUO_TOKEN, --subject-token-file or `--subject-token -` (stdin)",
    ),
];

/// One warning line for each secret flag present in `args` (the first item is the program
/// name) with a literal value, in the order the flags first appear. Only exact `--flag value`
/// and `--flag=value` forms count, so `--token-file` does not, and the value `-` (read stdin)
/// is not a secret on the command line.
pub fn argv_warnings<I>(args: I) -> Vec<String>
where
    I: IntoIterator<Item = OsString>,
{
    let args: Vec<OsString> = args.into_iter().skip(1).collect();
    let mut out: Vec<String> = Vec::new();
    for (i, arg) in args.iter().enumerate() {
        let Some(arg) = arg.to_str() else { continue };
        if arg == "--" {
            break;
        }
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (arg, None),
        };
        let Some((flag, instead)) = ARGV_SECRETS.iter().find(|(f, _)| *f == name) else {
            continue;
        };
        let value = inline.or_else(|| args.get(i + 1).and_then(|v| v.to_str()));
        if value == Some("-") {
            continue;
        }
        let line = format!(
            "warning: {flag} on the command line is visible to other local users (ps, /proc) \
             and ends up in shell history; use {instead}"
        );
        if !out.contains(&line) {
            out.push(line);
        }
    }
    out
}

/// Reads stdin at most once per process: two values read from stdin would otherwise race
/// for it.
#[derive(Debug, Default)]
pub struct Stdin {
    used: bool,
}

impl Stdin {
    /// The first line of `reader`, without the line ending. Errors when stdin was already
    /// taken or the value is empty.
    pub fn secret(&mut self, what: &str, reader: impl Read) -> Result<String> {
        self.claim(what)?;
        let mut buf = String::new();
        reader
            .take(64 * 1024)
            .read_to_string(&mut buf)
            .with_context(|| format!("reading {what} from standard input"))?;
        clean(what, &buf)
    }

    /// Reserve stdin for `what`, which reads it itself. Errors when it was already taken.
    pub fn claim(&mut self, what: &str) -> Result<()> {
        if self.used {
            bail!("{what}: standard input was already read for another value");
        }
        self.used = true;
        Ok(())
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

/// The value of the environment variable `env`, if it is set and not empty.
fn from_env(env: &str) -> Option<String> {
    std::env::var(env).ok().filter(|v| !v.is_empty())
}

/// Pick the secret: stdin, then the file, then the flag, then the environment variable `env`
/// (clap makes stdin, file and flag mutually exclusive on the command line).
pub fn resolve(
    what: &str,
    literal: Option<String>,
    stdin: bool,
    file: Option<&Path>,
    env: &str,
    input: &mut Stdin,
) -> Result<Option<String>> {
    if stdin {
        return input.secret(what, std::io::stdin().lock()).map(Some);
    }
    if let Some(path) = file {
        return from_file(what, path).map(Some);
    }
    Ok(literal.or_else(|| from_env(env)))
}

/// A delegation token from `--token` (or `--subject-token`; `-` reads the first line of
/// stdin), its `--…-file` form or [`TOKEN_ENV`]. Errors when none of them gives one.
pub fn resolve_token(
    flag: &str,
    literal: Option<String>,
    file: Option<&Path>,
    input: &mut Stdin,
) -> Result<String> {
    let stdin = literal.as_deref() == Some("-");
    let literal = literal.filter(|_| !stdin);
    resolve("delegation token", literal, stdin, file, TOKEN_ENV, input)?.ok_or_else(|| {
        anyhow::anyhow!(
            "a delegation token is required: set {TOKEN_ENV}, or pass {flag}-file <PATH> or \
             `{flag} -` to read it from stdin"
        )
    })
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
            "attenuo",
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
        assert!(w[0].contains("ATTENUO_ADMIN_TOKEN"));
        assert!(w[1].contains("--client-secret-stdin"));
        // One line each, and the secret itself is never echoed.
        assert!(w.iter().all(|l| !l.contains('\n') && !l.contains("s2")));
    }

    /// SR-35: delegation tokens given as arguments warn too, but not when read from stdin.
    #[test]
    fn warns_for_delegation_tokens_unless_read_from_stdin() {
        let w = argv_warnings(os(&["attenuo", "call", "--token", "J.W.T"]));
        assert_eq!(w.len(), 1);
        assert!(w[0].starts_with("warning: --token on the command line"));
        assert!(w[0].contains("--token-file") && !w[0].contains("J.W.T"));
        let w = argv_warnings(os(&["attenuo", "token", "exchange", "--subject-token=J"]));
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("--subject-token-file"));
        for quiet in [
            ["attenuo", "call", "--token", "-"].as_slice(),
            ["attenuo", "call", "--token=-"].as_slice(),
            ["attenuo", "token", "exchange", "--subject-token", "-"].as_slice(),
            ["attenuo", "call", "--token-file", "/run/t"].as_slice(),
        ] {
            assert!(argv_warnings(os(quiet)).is_empty(), "{quiet:?}");
        }
    }

    #[test]
    fn no_warning_for_the_safe_forms() {
        assert!(argv_warnings(os(&[
            "attenuo",
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
        assert!(argv_warnings(os(&["attenuo", "--", "--token", "x"])).is_empty());
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
        assert!(input.claim("c").is_err());
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

    const UNSET: &str = "ATTENUO_TEST_VARIABLE_THAT_IS_NEVER_SET";

    #[test]
    fn resolve_prefers_file_over_the_literal() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s");
        std::fs::write(&p, "from-file").unwrap();
        let mut input = Stdin::default();
        assert_eq!(
            resolve("x", Some("flag".into()), false, Some(&p), UNSET, &mut input).unwrap(),
            Some("from-file".into())
        );
        assert_eq!(
            resolve("x", Some("flag".into()), false, None, UNSET, &mut input).unwrap(),
            Some("flag".into())
        );
        assert_eq!(
            resolve("x", None, false, None, UNSET, &mut input).unwrap(),
            None
        );
        // The environment is the last resort, below the file.
        assert_eq!(
            resolve("x", None, false, None, "PATH", &mut input).unwrap(),
            std::env::var("PATH").ok()
        );
        assert_eq!(
            resolve("x", None, false, Some(&p), "PATH", &mut input).unwrap(),
            Some("from-file".into())
        );
    }

    #[test]
    fn token_from_file_or_flag() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t");
        std::fs::write(&p, "a.b.c\n").unwrap();
        let mut input = Stdin::default();
        assert_eq!(
            resolve_token("--token", None, Some(&p), &mut input).unwrap(),
            "a.b.c"
        );
        assert_eq!(
            resolve_token("--token", Some("x.y.z".into()), None, &mut input).unwrap(),
            "x.y.z"
        );
        // `-` claims stdin; a second reader is refused.
        input.claim("other").unwrap();
        let e = resolve_token("--token", Some("-".into()), None, &mut input).unwrap_err();
        assert!(e.to_string().contains("already read"), "{e}");
    }
}
