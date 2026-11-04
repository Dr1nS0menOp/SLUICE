//! Splunk's saved searches run in a real Splunk, for the proof (ADR 0037): the alerts they raise
//! on full and on reduced events must be the same.
//!
//! The engine creates an index of its own when it connects and removes it when it is dropped.
//! Each evaluation is a run in it: the events go to the index through the HTTP Event Collector,
//! each event's body as its JSON, with its id ([`EVENT_FIELD`]) and the run's number
//! ([`RUN_FIELD`]) beside it as indexed fields. The proof waits until Splunk can search exactly
//! that many events of the run, then runs every search on them (`oneshot`, over all time). A
//! search runs as the reader reads it: on every source, whatever index, sourcetype, source or
//! time range it names ([`crate::scope`]). Each result row is an alert: a row that is an event,
//! by the event's id; any other row (a count, a table) by its content.
//!
//! One index for all runs, because Splunk adds and removes indexes in the background and does
//! not do two of them at once ([`crate::index`]).
//!
//! A search Splunk refuses on an empty run (an unknown command, a lookup or data model the
//! proof's Splunk does not have) is set aside with its reason ([`SplunkEngine::skipped`]), and
//! so is a generating search (`| tstats …`), which runs on Splunk's own data rather than the
//! events, and one that writes or sends something (`collect`, `outputlookup`, `sendemail`, …),
//! which the proof never runs. Their requirements alone protect what they read.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;
use sluice_core::alert::{Alert, EngineError, RuleEngine};
use sluice_core::event::Event;
use sluice_core::ids::RuleId;

use crate::SplunkError;
use crate::answer::{Outcome, alerts, max_rows, outcome};
use crate::client::{Auth, Rest, content};
use crate::hec::{self, Hec};
use crate::index::{create, delete};
use crate::scope::prepare;

/// The indexed field that carries an event's id: kept beside the event, never in it, so a
/// search sees the event exactly as it is.
pub const EVENT_FIELD: &str = "sluice_event";

/// The indexed field that carries the number of the evaluation an event was sent for.
pub const RUN_FIELD: &str = "sluice_run";

/// The sourcetype the events are sent with: one Splunk has no settings for, so it extracts the
/// fields of a JSON event at search time (`KV_MODE = auto`).
pub const SOURCETYPE: &str = "sluice:proof";

/// The latest time Splunk searches, the end of 32-bit time.
pub(crate) const LATEST: i64 = 2_147_483_647;

/// Searches run at once. Splunk allows 6 plus one per CPU at a time; the proof leaves room.
const PARALLEL: usize = 4;

/// Events per request to the collector, and the most bytes a request carries.
const BATCH: usize = 1_000;
const BATCH_BYTES: usize = 4 * 1024 * 1024;

/// How long Splunk may go without making one more event searchable, or a new index ready.
pub(crate) const STALLED: Duration = Duration::from_secs(60);
pub(crate) const POLL: Duration = Duration::from_millis(250);

pub(crate) const TIMEOUT: Duration = Duration::from_secs(600);

/// Indices and collector tokens this process created, for unique names.
pub(crate) static NAMES: AtomicU64 = AtomicU64::new(0);

/// Where the proof's Splunk is, and how to reach it.
#[derive(Debug, Clone)]
pub struct Proof<'a> {
    /// The management port, such as `https://127.0.0.1:8089`. A Splunk for the proof, not the
    /// production one: the proof creates an index there, sends the sample to it (which counts
    /// against Splunk's licence) and removes it afterwards.
    pub url: &'a str,
    /// The HTTP Event Collector, such as `https://127.0.0.1:8088`; by default the management
    /// port's host with the collector's port and scheme as Splunk reports them.
    pub hec: Option<&'a str>,
    /// The credentials: a user who may create indexes and collector tokens, and search.
    pub auth: &'a Auth,
    /// Accept a self-signed certificate (Splunk's default). Only on a trusted network path.
    pub insecure: bool,
}

/// Runs Splunk saved searches in a real Splunk.
#[derive(Debug)]
pub struct SplunkEngine {
    rest: Rest,
    hec: Hec,
    index: String,
    /// The last run's number; run 0 is the check of the searches, on no events.
    runs: AtomicU64,
    version: String,
    max_rows: usize,
    searches: Vec<(RuleId, String)>,
    skipped: Vec<(RuleId, String)>,
}

/// Searches kept and set aside, each set-aside one with the reason.
type Checked = (Vec<(RuleId, String)>, Vec<(RuleId, String)>);

impl SplunkEngine {
    /// Connects to the Splunk `proof` names, makes an index and a collector token for the
    /// proof, and keeps the searches (each as `(id, SPL)`, macros expanded) that run there on no
    /// events. Those Splunk refuses, and generating searches and those that write, are set aside
    /// with the reason ([`SplunkEngine::skipped`]).
    ///
    /// # Errors
    ///
    /// [`SplunkError`] if Splunk cannot be reached, refuses the credentials, has its HTTP Event
    /// Collector turned off, or cannot create an index or a token.
    pub fn connect(proof: &Proof<'_>, searches: &[(RuleId, String)]) -> Result<Self, SplunkError> {
        let rest = Rest::new(proof.url, proof.auth, proof.insecure, TIMEOUT);
        let info = rest.json("GET", "/services/server/info", &[])?;
        let version = content(&info)["version"]
            .as_str()
            .unwrap_or("unknown")
            .to_owned();
        let max_rows = max_rows(&rest)?;
        let hec = Hec::create(&rest, proof)?;
        let index = match create(&rest) {
            Ok(index) => index,
            Err(error) => {
                hec.remove(&rest);
                return Err(error);
            }
        };
        let mut engine = Self {
            rest,
            hec,
            index,
            runs: AtomicU64::new(0),
            version,
            max_rows,
            searches: Vec::new(),
            skipped: Vec::new(),
        };
        let (kept, skipped) = engine.check(searches)?;
        engine.searches = kept;
        engine.skipped = skipped;
        Ok(engine)
    }

    /// The Splunk version the proof runs in.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The searches the proof runs.
    pub fn searches(&self) -> impl Iterator<Item = &RuleId> {
        self.searches.iter().map(|(id, _)| id)
    }

    /// The searches set aside, with the reason.
    #[must_use]
    pub fn skipped(&self) -> &[(RuleId, String)] {
        &self.skipped
    }

    /// The events of `run`, as a search's first terms.
    fn scope(&self, run: u64) -> String {
        format!("index={} {RUN_FIELD}::{run}", self.index)
    }

    /// Splits `searches` into those that run on no events (run 0) and those set aside.
    fn check(&self, searches: &[(RuleId, String)]) -> Result<Checked, SplunkError> {
        let scope = self.scope(0);
        let mut runnable = Vec::new();
        let mut skipped = Vec::new();
        for (id, search) in searches {
            match prepare(search, &scope) {
                Ok(_) => runnable.push((id.clone(), search.clone())),
                Err(why) => skipped.push((id.clone(), why.to_string())),
            }
        }
        let outcomes = self.run_all(&scope, &runnable);
        let mut kept = Vec::new();
        for ((id, search), outcome) in runnable.into_iter().zip(outcomes) {
            match outcome? {
                Outcome::Rows(_) => kept.push((id, search)),
                Outcome::Refused(why) => skipped.push((id, why)),
            }
        }
        skipped.sort();
        Ok((kept, skipped))
    }

    /// Sends `events` as `run` and waits until Splunk can search exactly as many of the run:
    /// the collector drops what it cannot index without saying so.
    fn load(&self, run: u64, events: &[&Event]) -> Result<(), SplunkError> {
        if let Some(event) = events
            .iter()
            .find(|e| !(0..=LATEST).contains(&e.timestamp.0))
        {
            return Err(SplunkError::Response(format!(
                "event {} has a time Splunk does not search ({}): the proof needs times from \
                 1970 to 2038",
                event.id, event.timestamp.0
            )));
        }
        let mut body = String::new();
        let mut count = 0;
        for event in events {
            body.push_str(&hec::event(&self.index, run, event).to_string());
            count += 1;
            if count == BATCH || body.len() >= BATCH_BYTES {
                self.hec.send(&body)?;
                body.clear();
                count = 0;
            }
        }
        if !body.is_empty() {
            self.hec.send(&body)?;
        }
        let expected = events.len();
        let (mut last, mut progress) = (0, Instant::now());
        loop {
            let searchable = self.count(run)?;
            if searchable == expected {
                return Ok(());
            }
            if searchable > expected {
                return Err(SplunkError::Response(format!(
                    "Splunk holds {searchable} events of run {run} in {}, {expected} were sent",
                    self.index
                )));
            }
            if searchable > last {
                (last, progress) = (searchable, Instant::now());
            } else if progress.elapsed() > STALLED {
                return Err(SplunkError::Response(format!(
                    "Splunk can search {searchable} of the {expected} events sent to {}, and no \
                     more for {} seconds: it dropped the others",
                    self.index,
                    STALLED.as_secs()
                )));
            }
            std::thread::sleep(POLL);
        }
    }

    /// The events of `run` Splunk can search.
    fn count(&self, run: u64) -> Result<usize, SplunkError> {
        let search = format!(
            "| tstats count where index={} {RUN_FIELD}={run}",
            self.index
        );
        match self.oneshot(&search)? {
            Outcome::Rows(rows) => Ok(rows
                .first()
                .and_then(|row| row.get("count"))
                .and_then(Value::as_str)
                .and_then(|c| c.parse().ok())
                .unwrap_or(0)),
            Outcome::Refused(why) => Err(SplunkError::Response(format!(
                "Splunk cannot count the events in {}: {why}",
                self.index
            ))),
        }
    }

    /// Every search's outcome in `scope`, in the order given, at most [`PARALLEL`] at a time.
    /// An outcome that did not arrive (a worker that failed) is an error, never a missing row.
    fn run_all(
        &self,
        scope: &str,
        searches: &[(RuleId, String)],
    ) -> Vec<Result<Outcome, SplunkError>> {
        let next = AtomicUsize::new(0);
        let outcomes: Mutex<Vec<Option<Result<Outcome, SplunkError>>>> =
            Mutex::new((0..searches.len()).map(|_| None).collect());
        std::thread::scope(|threads| {
            for _ in 0..PARALLEL.min(searches.len()) {
                threads.spawn(|| {
                    loop {
                        let at = next.fetch_add(1, Ordering::Relaxed);
                        let Some((_, search)) = searches.get(at) else {
                            break;
                        };
                        let outcome = match prepare(search, scope) {
                            Ok(spl) => self.oneshot(&spl),
                            Err(why) => Ok(Outcome::Refused(why.to_string())),
                        };
                        if let Ok(mut all) = outcomes.lock() {
                            all[at] = Some(outcome);
                        }
                    }
                });
            }
        });
        let outcomes = match outcomes.into_inner() {
            Ok(all) => all,
            Err(poisoned) => poisoned.into_inner(),
        };
        outcomes
            .into_iter()
            .map(|o| {
                o.unwrap_or_else(|| {
                    Err(SplunkError::Response(
                        "a search's outcome went missing".to_owned(),
                    ))
                })
            })
            .collect()
    }

    /// Runs `spl` over all time and returns every result row, or why Splunk refused it.
    fn oneshot(&self, spl: &str) -> Result<Outcome, SplunkError> {
        let answer = self.rest.send(
            "POST",
            "/services/search/jobs",
            &[
                ("search", spl),
                ("exec_mode", "oneshot"),
                ("count", "0"),
                ("earliest_time", "0"),
                ("latest_time", &LATEST.to_string()),
            ],
        )?;
        outcome(answer.status, &answer.body, self.max_rows)
    }
}

impl RuleEngine for SplunkEngine {
    fn alerts_refs(&self, events: &[&Event]) -> Result<BTreeSet<Alert>, EngineError> {
        let failed = |e: SplunkError| EngineError(e.to_string());
        let run = self.runs.fetch_add(1, Ordering::Relaxed) + 1;
        self.load(run, events).map_err(failed)?;
        let mut found = BTreeSet::new();
        let outcomes = self.run_all(&self.scope(run), &self.searches);
        for ((rule, _), outcome) in self.searches.iter().zip(outcomes) {
            match outcome.map_err(failed)? {
                Outcome::Rows(rows) => found.extend(alerts(rule, &rows, &self.index)),
                Outcome::Refused(why) => {
                    return Err(EngineError(format!(
                        "Splunk refused {rule} on the sample: {why}"
                    )));
                }
            }
        }
        Ok(found)
    }
}

impl Drop for SplunkEngine {
    fn drop(&mut self) {
        delete(&self.rest, &self.index);
        self.hec.remove(&self.rest);
    }
}
