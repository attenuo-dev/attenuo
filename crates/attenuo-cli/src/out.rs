//! Standard output for every command: `out!` and `outln!` in place of `print!` and `println!`.
//!
//! `println!` panics when a write fails, so `attenuo audit tail | head -1` used to end in a
//! panic message and a backtrace once `head` had read its line and gone. Here a closed reader
//! (`BrokenPipe`) ends the output quietly: the write and every later one do nothing, the
//! command finishes and exits with the status it would have had, and a streaming command
//! (`audit tail --follow`, `policy test --watch`) asks [`closed`] and stops. Any other write
//! error (a full disk, `> /dev/full`) is returned, so the command fails with `error: writing
//! to standard output: ...`.
//!
//! Each write is flushed, so an error surfaces at the write that hit it rather than at exit,
//! where the standard library drops it.
//!
//! Standard error has the same layer: `err!` and `errln!` in place of `eprint!` and
//! `eprintln!`, which panic on a failed write too (`attenuo policy test cases.yaml 2>&1 |
//! head -1`). A closed reader ends the stderr output quietly; any other stderr write error is
//! dropped, since there is nowhere left to report it. Neither changes the exit status, and
//! neither touches stdout's state: stdout and stderr may be different pipes.

use std::fmt;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};

/// Set once a write found the reader gone.
static CLOSED: AtomicBool = AtomicBool::new(false);

/// Whether the reader of standard output has gone away.
pub(crate) fn closed() -> bool {
    CLOSED.load(Ordering::Relaxed)
}

/// What `out!` calls.
pub(crate) fn write_fmt(args: fmt::Arguments<'_>) -> Result<()> {
    write_with(|w| w.write_fmt(args))
}

/// Standard output as an [`io::Write`], for code that writes through one (`audit export`):
/// once the reader has gone it takes every byte and drops it, like `out!`.
pub(crate) struct Stdout;

impl Write for Stdout {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        write_with(|w| w.write_all(buf)).map_err(|e| io::Error::other(format!("{e:#}")))?;
        Ok(buf.len())
    }

    /// Each write is already flushed.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_with(f: impl FnOnce(&mut io::StdoutLock<'static>) -> io::Result<()>) -> Result<()> {
    if closed() {
        return Ok(());
    }
    let mut stdout = io::stdout().lock();
    settle(f(&mut stdout).and_then(|()| stdout.flush()))
}

/// A closed reader is the end of the output, not an error; anything else is.
fn settle(res: io::Result<()>) -> Result<()> {
    match res {
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
            CLOSED.store(true, Ordering::Relaxed);
            Ok(())
        }
        res => res.context("writing to standard output"),
    }
}

/// Set once a write to standard error found the reader gone.
static ERR_CLOSED: AtomicBool = AtomicBool::new(false);

/// What `err!` calls. A broken pipe ends stderr output; any other error is dropped.
pub(crate) fn err_write_fmt(args: fmt::Arguments<'_>) {
    if ERR_CLOSED.load(Ordering::Relaxed) {
        return;
    }
    let mut stderr = io::stderr().lock();
    settle_err(stderr.write_fmt(args).and_then(|()| stderr.flush()));
}

/// A closed reader ends stderr output; any other stderr error has nowhere to go.
fn settle_err(res: io::Result<()>) {
    if let Err(e) = res {
        if e.kind() == io::ErrorKind::BrokenPipe {
            ERR_CLOSED.store(true, Ordering::Relaxed);
        }
    }
}

/// `print!` that ends quietly when the reader has gone and returns any other write error.
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::out::write_fmt(format_args!($($arg)*))
    };
}

/// `println!` that ends quietly when the reader has gone and returns any other write error.
macro_rules! outln {
    () => {
        $crate::out::write_fmt(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::out::write_fmt(format_args!("{}\n", format_args!($($arg)*)))
    };
}

/// `eprint!` that ends quietly when the reader has gone and never panics on a write error.
macro_rules! err {
    ($($arg:tt)*) => {
        $crate::out::err_write_fmt(format_args!($($arg)*))
    };
}

/// `eprintln!` that ends quietly when the reader has gone and never panics on a write error.
macro_rules! errln {
    () => {
        $crate::out::err_write_fmt(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::out::err_write_fmt(format_args!("{}\n", format_args!($($arg)*)))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The broken pipe itself is covered by `tests/broken_pipe.rs`, against the binary: here
    /// it would set the flag for every test in the process.
    #[test]
    fn another_write_error_is_returned() {
        let full = io::Error::new(io::ErrorKind::StorageFull, "no space left on device");
        let err = settle(Err(full)).unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            "writing to standard output: no space left on device"
        );
        assert!(!closed());
    }

    /// Another stderr error is dropped and does not end stderr output; the broken pipe is
    /// covered by `tests/broken_pipe.rs`, for the same reason as above.
    #[test]
    fn another_stderr_write_error_is_dropped() {
        settle_err(Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "no space left on device",
        )));
        assert!(!ERR_CLOSED.load(Ordering::Relaxed));
    }
}
