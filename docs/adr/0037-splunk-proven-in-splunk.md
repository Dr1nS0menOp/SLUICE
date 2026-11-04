# ADR 0037: Splunk returns, proven in Splunk

- Status: Accepted
- Date: 2026-11-03
- Supersedes: [ADR 0034](0034-no-splunk.md); restores [ADR 0026](0026-splunk-saved-searches.md)

## Context

ADR 0034 removed Splunk because nothing proved what Sluice did with it: no engine ran Splunk's
searches in the proof, and the fetch had run only against a stand-in. Both needed a real
Splunk, whose image starts only with the Splunk General Terms accepted. ADR 0034 left the way
back open: a new decision on the licence, with a Splunk engine for the proof from the start.

On 2026-11-03 the maintainer decided that Sluice may run Splunk Enterprise (the
`splunk/splunk` image, under the Splunk General Terms and its trial licence) to prove the
analysis. Everything below was built against Splunk Enterprise 10.6.1.1.

## Decision

1. **ADR 0026 comes back as it was.** The SPL reader (saved searches, macros, `props` and
   `transforms`), `--splunk-rules`, `sluice rules fetch splunk`, `Engine::Splunk` and the field
   conventions `schema: splunk` and `schema: cim`. One change: a macro without its definition is
   reported as a function without its source (`unknown_function`), as a Sentinel function is,
   and the report says where macros come from.
2. **The proof runs Splunk's searches in Splunk** (`sluice analyze --splunk URL`; the crate
   `sluice-splunk`'s `SplunkEngine`). The reader keeps every search whose macros it could
   expand, as Splunk would run it (`SplunkRules::queries`).
   - **One index per analysis.** The engine creates `sluice_proof_<process>_<time>_<n>` when it
     connects and removes it when it is done, with a collector token of its own. Each evaluation
     (full events, forwarded events, again after a rollback) is a *run* in it.
   - **Events go in through the HTTP Event Collector**, each body as its JSON, under the
     sourcetype `sluice:proof`, which Splunk has no settings for, so it extracts a JSON event's
     key paths at search time. Two indexed fields ride beside the body, never in it:
     `sluice_event` (the event's id) and `sluice_run` (the run). The proof waits until Splunk can
     search exactly as many events of the run as were sent: the collector says it took events
     it then drops, and fewer or more is an error, never a smaller proof.
   - **A search runs as the reader reads it: on every source.** The reader widens `index`,
     `sourcetype`, `source`, `host`, `eventtype`, `tag` and time modifiers to `true`. The proof
     does the same in the base search, in every `search` command and in every subsearch. Each
     such test becomes `*` where it counts as it is, and a test no event passes where a `NOT`
     turns it around, so the search keeps the most events it could. The search then gets
     `index=<proof index> sluice_run::<n>` in front and `| eval sluice_event=sluice_event` at
     the end. Splunk returns only the fields a search names, an indexed one too. The searches
     run with `oneshot`, over all time, four at a time.
   - **An alert is a result row.** A row that is an event alerts on that event, by its id. Any
     other row (a count, a table) alerts by its content: its fields but Splunk's own (`_cd`,
     `_raw`, …; `_time` stays) and the run's number, numbered so that identical rows stay
     distinct, as ES|QL's rows are (ADR 0025).
   - **What the proof does not run is set aside, with the reason:** a search Splunk refuses on
     no events (an unknown command, a lookup or data model the proof's Splunk does not have), a
     generating search (`| tstats`, `| inputlookup`), which runs on Splunk's own data rather
     than the events, and a search with a command that writes or sends something (`collect`,
     `outputlookup`, `sendemail`, `sendalert`, `map`, …). Their requirements alone protect what
     they read, as for Elastic's rules Elasticsearch refuses.
   - **Splunk's limits are the proof's.** `oneshot` caps its rows at `maxresultrows` (50,000)
     with no more than a warning: a search that reaches the cap fails the evaluation. An event's
     time must be within 1970 to 2038.
3. **The fetch is tested against a real Splunk**, which creates a scheduled search and its
   macro, fetches them and reads them back.
4. **The checks run where the image is.** `scripts/splunk-check.sh` starts a throwaway Splunk
   (`splunk/splunk:10.6.1.1`, on 127.0.0.1 only) and runs the engine's tests, the fetch's and
   `sluice analyze --splunk` end to end. It accepts nothing on anyone's behalf: it starts Splunk
   only when the person running it has set the image's own `SPLUNK_GENERAL_TERMS` variable. The
   image is 6.8 GB, so, like the Kusto emulator's, it is not pulled in CI.

## Consequences

- Splunk is supported as Sentinel and Elastic are: read from the SIEM, and its rules run in its
  own engine for the proof. The proof for a Splunk destination is decided by Splunk.
- **Measured on the demo** (`sluice demo --scale 25`, its example rules written as three saved
  searches, sources declared `schema: splunk`, `--rules-complete`), 2026-11-03: without
  `--splunk` the proof had no alert to compare, so it showed nothing about the detections. With
  it, Splunk raised 778 alerts on the full sample and the same 778 on what the plan forwards:
  73.9 % of the bytes saved, 9,782 events counted into 7,092 summary records.
- Splunk adds and removes indexes in the background and refuses to do two at once: an index
  added while another is removed stayed unusable until a later reload ("Unable to reload
  indexer after adding … Restart required"). So the proof uses one index for all runs, adds and
  removes indexes one at a time within a process, waits until a new index is ready, and asks
  Splunk to reload its indexes when it is slow. Two analyses at once on one Splunk can still
  meet this; give each its own Splunk.
- Splunk extracts a JSON event's fields from its first 10,240 characters only (`[kv] maxchars`).
  The proof reproduces this, as it runs Splunk itself: an event made smaller can show Splunk a
  field it did not see before, and a search on it then alerts differently, which rolls the
  saving back.
- **`--splunk` is a Splunk for the proof, not the production one.** The proof indexes the
  sample there, which counts against that Splunk's licence (the trial's is 500 MB a day), and it
  creates and removes an index and a collector token. It never runs a search that writes or
  sends, so a production Splunk given by mistake keeps its data, but it does get the sample.
- A search over a data model (most of Splunk's own ESCU content uses `tstats`) is still read as
  reading anything anywhere (ADR 0026) and is not run: it blocks every saving on the sources it
  reaches. Running it needs the data models and the add-ons that fill them in the proof's
  Splunk, which is left for later.
- Generating code for Splunk's own ingestion (ingest actions, `props` and `transforms`, or
  `INGEST_EVAL`) is not part of this decision. `vector.yaml` works in front of Splunk's
  collector as for any destination.
