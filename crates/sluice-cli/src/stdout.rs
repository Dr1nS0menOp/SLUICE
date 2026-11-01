//! Printing to standard output that survives a reader who stops reading.
//!
//! `println!` panics when standard output is a closed pipe, as in `sluice analyze … | head`.
//! Rust ignores `SIGPIPE`, and restoring the signal needs `unsafe`, which the workspace forbids.
//! So every line goes through [`line()`]: once the reader has gone, printing stops quietly and the
//! command goes on, so every file it writes is still written.

use std::fmt;
use std::io::{self, ErrorKind, Write};
use std::sync::atomic::{AtomicBool, Ordering};

static READER_GONE: AtomicBool = AtomicBool::new(false);

/// Prints a line to standard output, like `println!`, without a panic on a closed pipe.
macro_rules! out {
    () => {
        $crate::stdout::line(format_args!(""))
    };
    ($($arg:tt)*) => {
        $crate::stdout::line(format_args!($($arg)*))
    };
}
pub(crate) use out;

/// Writes `args` and a newline. See the module documentation.
pub(crate) fn line(args: fmt::Arguments<'_>) {
    write(&mut io::stdout().lock(), args, "\n");
}

/// Writes `text` as it is, without a newline.
pub(crate) fn text(text: &str) {
    write(&mut io::stdout().lock(), format_args!("{text}"), "");
}

fn write(out: &mut impl Write, args: fmt::Arguments<'_>, end: &str) {
    if READER_GONE.load(Ordering::Relaxed) {
        return;
    }
    let result = out
        .write_fmt(args)
        .and_then(|()| out.write_all(end.as_bytes()));
    if let Err(error) = result {
        READER_GONE.store(true, Ordering::Relaxed);
        if error.kind() != ErrorKind::BrokenPipe {
            eprintln!("warning: cannot print to standard output: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ClosedPipe;

    impl Write for ClosedPipe {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_closed_pipe_stops_printing_without_a_panic() {
        write(&mut ClosedPipe, format_args!("first"), "\n");
        assert!(READER_GONE.load(Ordering::Relaxed));
        let mut later = Vec::new();
        write(&mut later, format_args!("second"), "\n");
        assert!(
            later.is_empty(),
            "nothing is printed once the reader has gone"
        );
    }
}
