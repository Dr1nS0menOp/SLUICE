# ADR 0006: Archive search and replay without a query engine

- Status: Accepted
- Date: 2026-10-09

## Context

Contract rule 2 keeps every event at full fidelity before any cut. The archive is only worth
something if an analyst can get events back out: to look at what was cut during an incident,
and to send a slice to a SIEM after all (`sluice replay`). The plan proposed DuckDB over the
archive.

The archive is what Vector's `file` sink writes: gzip NDJSON, one file per source and UTC hour
(`<archive_dir>/<source>/<YYYY-MM-DD>/<HH>.ndjson.gz`, ADR 0005).

## Decision

1. **A streaming scan, no engine.** `sluice-archive` lists the files whose source and hour can
   match, decompresses them in order and filters each event. Memory use is flat, and the code is
   a few hundred lines with `flate2` as its only new dependency (already in the tree).
2. **A small, closed filter language**: sources, a half-open time range, and `field=value`,
   `field!=value` and `field~text` conditions that must all hold. Fields are dotted paths into
   nested objects, and values compare as text, which matches how analysts type them.
3. **Time is when Vector received the event** (its `timestamp` field), the same clock as the
   path layout. Source event times vary per format and can be absent or wrong, which is common in
   exactly the data an incident is about.
4. **Incomplete files do not fail a scan.** The newest hour is always mid-write. Every file that
   ends early is reported on stderr with its reason, so an answer is never silently partial.
5. **Replay is HTTP NDJSON in batches.** `sluice replay --url` posts to any endpoint, typically a
   Vector `http_server` source in front of the operator's SIEM sink, so replay reuses the
   operator's existing delivery, auth and buffering. On a failed request it stops and reports how
   many events were sent.

## Consequences

- A search reads every selected hour completely, so its cost grows with the selected volume, not
  with the number of matches. For the incident use (narrow source and time range) this is fine. Heavy analytics belong in the SIEM or
  a later Parquet archive (PLAN v0.2+), where DuckDB can be reconsidered without changing this
  interface.
- Rerunning a replay after a partial failure resends the batches that did arrive. The replay
  target must tolerate duplicates, or the operator narrows the range.
- Archived events carry Vector's `path`, `source_type` and `timestamp` fields; a replay target
  that is itself an `http_server` source overwrites them with its own.
- `scripts/replay-smoke.sh` (run by `scripts/live-smoke.sh`) checks against a real Vector that a
  filtered replay delivers exactly the events the same search selects, unchanged.
