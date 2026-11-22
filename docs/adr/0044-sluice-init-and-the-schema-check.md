# ADR 0044: `sluice init`, and a check of the declared schema

- Status: Accepted
- Date: 2026-11-22

## Context

Describing the sources (`sources.yaml`) is the step new users find hardest. A wrong `schema` is
also the one mistake the proof cannot notice: rules that test names the records lack match
nothing on either side, so the alerts are equal (none), while Sluice may cut what the SIEM's
rules read under the right names (architecture, "Field names").

## Decision

1. **`sluice init --input DIR [--out sources.yaml]`** reads the first 2,000 events of each
   `<source>.ndjson` and proposes per source:
   - its format: text when a line field (`message`, `event.original`, `_raw`, `log`) holds a
     string in nine in ten records and the record has no top-level field outside a shipper's
     envelope; JSON otherwise;
   - for text, the parser pack that parses the most lines, at least nine in ten. Of packs that
     parse alike, one whose product the record's file or module names wins (nginx and Apache
     write the same line), then one that includes others. The pack also gives the log source and
     the convention;
   - for JSON, the log source its records name: `Channel` or `winlog.channel`, a Sentinel
     table's `Type`, `event.dataset`, `event.module`, or CloudTrail's fields;
   - the convention its field names follow, by `Schema::guess`.

   It writes the file with a comment above each source on how it came to it, never overwrites
   one, and prints the same per source. It is a proposal: nothing it guesses is trusted until a
   person keeps it.
2. **`Schema::guess`** recognises OCSF, UDM, ASIM, Sentinel tables, Windows names (even in a
   Beats envelope that names an ECS version), ECS (two in five names in its field sets), Splunk,
   and Sigma's taxonomy for firewalls and proxies. It returns `None` when the names say nothing.
3. **The schema check.** For each JSON source with a declared `schema`, the rules surely meant
   for it (every log source attribute they name, the source names alike) and written in that
   convention name the fields they read. A rule that applies only because the source leaves an
   attribute unknown, such as a Sysmon rule on the Security channel, does not count: it may well
   read fields this data never has. When at least three are named
   and at most a quarter of them occur in the source's records, the report and the command line
   say the schema looks wrong, which fields are missing, and what the names look like instead.

## Consequences

- On the demo's samples, `init` proposes what the demo declares for five of six sources. For the
  DNS source it says that no field names its product and the names fit no convention: an honest
  gap, not a wrong guess.
- The check costs nothing when the schema fits. It does not change any saving; it tells a person
  to look.
