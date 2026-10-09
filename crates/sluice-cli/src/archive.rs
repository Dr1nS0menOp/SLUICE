//! `sluice search` and `sluice replay` over the full-fidelity archive.

use std::io::{self, BufWriter, ErrorKind, Write};

use anyhow::{Context, Result};
use sluice_archive::{Query, Scan, Stats, parse_time};
use sluice_core::ids::SourceId;

use crate::cli::{ReplayArgs, SearchArgs, SelectArgs};

pub(crate) fn search(args: &SearchArgs) -> Result<()> {
    let mut scan = scan(&args.select)?;
    let limit = args.limit.unwrap_or(u64::MAX);
    if args.count {
        let found = scan.by_ref().take(clamp(limit)).count();
        println!("{found}");
    } else {
        let mut out = BufWriter::new(io::stdout().lock());
        for record in scan.by_ref().take(clamp(limit)) {
            let written = serde_json::to_writer(&mut out, &record.fields)
                .map_err(io::Error::from)
                .and_then(|()| out.write_all(b"\n"));
            match written {
                // The reader went away, as with `| head`: not an error.
                Err(error) if error.kind() == ErrorKind::BrokenPipe => return Ok(()),
                other => other.context("writing to stdout")?,
            }
        }
        match out.flush() {
            Err(error) if error.kind() == ErrorKind::BrokenPipe => return Ok(()),
            other => other.context("writing to stdout")?,
        }
    }
    summarize(scan.stats());
    Ok(())
}

pub(crate) fn replay(args: &ReplayArgs) -> Result<()> {
    let mut scan = scan(&args.select)?;
    let sent = sluice_archive::replay(&mut scan, &args.url, args.batch)?;
    eprintln!("replayed {sent} events to {}", args.url);
    summarize(scan.stats());
    Ok(())
}

fn scan(args: &SelectArgs) -> Result<Scan> {
    let query = Query {
        sources: args.sources.iter().map(SourceId::new).collect(),
        from: args.from.as_deref().map(parse_time).transpose()?,
        to: args.to.as_deref().map(parse_time).transpose()?,
        conditions: args
            .conditions
            .iter()
            .map(|c| c.parse())
            .collect::<Result<_, _>>()?,
    };
    Scan::new(&args.archive, query)
        .with_context(|| format!("reading the archive {}", args.archive.display()))
}

fn clamp(limit: u64) -> usize {
    usize::try_from(limit).unwrap_or(usize::MAX)
}

/// Reports on stderr how complete the answer is, keeping stdout for the events.
fn summarize(stats: &Stats) {
    eprintln!(
        "{} matched of {} events in {} files",
        stats.matched, stats.lines, stats.files
    );
    if stats.bad_lines > 0 {
        eprintln!("warning: {} lines were not JSON objects", stats.bad_lines);
    }
    for (path, reason) in &stats.incomplete {
        eprintln!(
            "warning: {} ended early ({reason}); it is still being written or damaged",
            path.display()
        );
    }
}
