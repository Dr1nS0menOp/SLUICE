//! Sending archived events on to a destination.

use crate::error::ArchiveError;
use crate::scan::Scan;

/// Posts every event `scan` yields to `url` as newline-delimited JSON, `batch` events per
/// request, and returns how many were sent. Events go out exactly as archived.
///
/// # Errors
///
/// Returns [`ArchiveError::Replay`] on the first failed request, with the number of events
/// already delivered. Nothing is retried: the operator decides whether to resend.
pub fn replay(scan: &mut Scan, url: &str, batch: usize) -> Result<u64, ArchiveError> {
    let batch = batch.max(1);
    let mut sent = 0u64;
    let mut body = Vec::new();
    let mut pending = 0usize;
    loop {
        let record = scan.next();
        if let Some(record) = &record {
            serde_json::to_writer(&mut body, &record.fields)
                .map_err(|e| failed(url, sent, &e.to_string()))?;
            body.push(b'\n');
            pending += 1;
        }
        if pending > 0 && (record.is_none() || pending >= batch) {
            ureq::post(url)
                .header("Content-Type", "application/x-ndjson")
                .send(&body[..])
                .map_err(|e| failed(url, sent, &e.to_string()))?;
            sent += pending as u64;
            body.clear();
            pending = 0;
        }
        if record.is_none() {
            return Ok(sent);
        }
    }
}

fn failed(url: &str, sent: u64, reason: &str) -> ArchiveError {
    ArchiveError::Replay {
        url: url.to_owned(),
        sent,
        reason: reason.to_owned(),
    }
}
