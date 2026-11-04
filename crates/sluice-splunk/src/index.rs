//! The proof's index: added and removed one at a time, and used only once it is ready.
//!
//! Splunk adds and removes indexes in the background and does not do two of them at once: an
//! index added while another is removed may stay unusable until Splunk restarts ("Unable to
//! reload indexer after adding … Restart required"). So this process adds and removes indexes
//! one at a time ([`ADMIN`]), waits until a new one is ready, and asks Splunk to load its
//! indexes again when one is slow.

use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::SplunkError;
use crate::client::{Rest, content};
use crate::engine::{LATEST, NAMES, POLL, STALLED};
use crate::hec::truthy;

/// How long a new index may take before the proof asks Splunk to load its indexes again.
const RELOAD: Duration = Duration::from_secs(5);

/// Held while this process adds or removes an index.
static ADMIN: Mutex<()> = Mutex::new(());

/// A new, empty, ready index. Splunk removes an index in the background, and a new one of the
/// same name would hold the old one's events, so every name is new: this process, the time and
/// a count.
pub(crate) fn create(rest: &Rest) -> Result<String, SplunkError> {
    let _admin = ADMIN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    for _ in 0..10 {
        let name = format!(
            "sluice_proof_{}_{seconds}_{}",
            std::process::id(),
            NAMES.fetch_add(1, Ordering::Relaxed)
        );
        // Events from years ago must stay searchable, not be frozen at once.
        let answer = rest.send(
            "POST",
            "/services/data/indexes",
            &[
                ("name", &name),
                ("frozenTimePeriodInSecs", &LATEST.to_string()),
            ],
        )?;
        match answer.status {
            200 | 201 => {
                return match ready(rest, &name) {
                    Ok(()) => Ok(name),
                    Err(error) => {
                        remove(rest, &name);
                        Err(error)
                    }
                };
            }
            409 => {}
            status => {
                return Err(SplunkError::Rejected {
                    status,
                    message: answer.body,
                });
            }
        }
    }
    Err(SplunkError::Response(
        "every index name tried exists already".to_owned(),
    ))
}

/// Waits until a new index is ready: until then, Splunk drops the events sent to it, though the
/// collector says it took them. An index Splunk could not load at once (it was busy with
/// another) is loaded when Splunk loads its indexes again, which the proof asks for.
fn ready(rest: &Rest, index: &str) -> Result<(), SplunkError> {
    let path = path(index);
    let started = Instant::now();
    let mut reloaded = Instant::now();
    loop {
        let answer = rest.json("GET", &path, &[])?;
        let settings = content(&answer);
        if truthy(&settings["isReady"]) && !truthy(&settings["disabled"]) {
            return Ok(());
        }
        if started.elapsed() > STALLED {
            return Err(SplunkError::Response(format!(
                "index {index} was not ready after {} seconds",
                STALLED.as_secs()
            )));
        }
        if reloaded.elapsed() > RELOAD {
            let _ = rest.send("POST", "/services/data/indexes/_reload", &[]);
            reloaded = Instant::now();
        }
        std::thread::sleep(POLL);
    }
}

/// Removes an index, one admin call at a time.
pub(crate) fn delete(rest: &Rest, index: &str) {
    let _admin = ADMIN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    remove(rest, index);
}

/// Removes an index; one left behind is only a leftover, so a failure is not reported.
fn remove(rest: &Rest, index: &str) {
    let _ = rest.send("DELETE", &path(index), &[]);
}

fn path(index: &str) -> String {
    format!(
        "/services/data/indexes/{}",
        sluice_http::percent_encode(index)
    )
}
