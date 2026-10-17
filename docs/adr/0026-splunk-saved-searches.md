# ADR 0026: Splunk saved searches as requirements

- Status: Accepted
- Date: 2026-10-17

## Context

PLAN.md M12: requirements extractors for each SIEM's own rule language, Elastic first (ADR
0025), then Splunk SPL (correlation searches). Splunk detects with saved searches: scheduled
alerts, and Enterprise Security's correlation searches, which are saved searches with
`action.correlationsearch.enabled`. Their SPL leans on macros (`` `sysmon` ``,
`` `security_content_ctime(firstTime)` ``) and on data models (`tstats`).

Running the searches for the proof needs Splunk itself, whose image needs the Splunk General
Terms accepted; that is the maintainer's decision and not taken. Reading them needs no licence.

## Decision

1. **Input: Splunk's own configuration** (`sluice_rules::SplunkRules`, `--splunk-rules DIR` for
   `analyze`, `up` and `rules requirements`): `savedsearches.conf` and `macros.conf` (an app's
   `default` and `local`, later files overriding earlier ones), or the REST API's JSON answers
   (`saved/searches`, `admin/macros`), which carry the same settings per entry. A stanza with a
   `definition` is a macro, one with a `search` a saved search.
2. **Only searches that run on their own count** (ADR 0021): scheduled ones (`enableSched`,
   `is_scheduled`) and correlation searches, unless `disabled`. A report someone runs by hand
   raises no alert.
3. **Macros are expanded** as Splunk does, by text, with `$argument$`s filled in (`name(n)` for
   one with `n` arguments). A macro that is not among the files, an `iseval` macro, or macros
   nesting deeper than 32 make the search one that may read anything anywhere.
4. **The base search is parsed** (`splunk/spl.rs`) into a superset pre-filter: `field=value`
   becomes an equality ignoring case, a pattern the containment of its literal parts, a number
   the containment of its digits (Splunk compares numbers as numbers, so `4624` matches
   `4624.0`; an exponent is let through too). `OR`, `AND`, `IN` and parentheses keep their
   structure, with Splunk's precedence: `OR` binds tighter than `AND`, so `a b OR c` is
   `a AND (b OR c)`. Splunk knows them in capitals only, so `or` is a term. Comments
   (```` ```text``` ````) are dropped before macros are expanded. `NOT`, `!=`, comparisons,
   non-ASCII values and the fields Splunk keeps beside the event (`index`, `sourcetype`,
   `host`, time modifiers) widen to `true`. A bare term searches `_raw`: the search reads the
   raw event. A backslash other than `\\` and `\"` is read as a wildcard, as its meaning varies
   between commands.
5. **The rest of the pipeline is not parsed.** Every name in it may be a field the search reads
   (`| search` is parsed as a filter for its fields only), a command that counts, orders or
   joins events (`stats`, `transaction`, `streamstats`, `dedup`, …) makes the search stateful,
   and `rex`, `spath` and other extractions read the raw event. What cannot be bounded may
   read any field: a subsearch (`[…]`), a generating command (`tstats`, `datamodel`,
   `inputlookup`, …), a wildcard field name or a `*` after the base search, and an array path
   (`a{}.b`).
6. **Fields are named as Splunk extracts them** (`field_names: splunk`, a new `Schema`): for a
   JSON event, its key paths. A source declares `schema: splunk` only when its sourcetype adds
   no aliases or calculated fields (`props.conf`) that rules read, as those names are in no
   record. On sources in another convention the searches are read as widely as can be (ADR
   0018). Searches are not scoped by `index` or `sourcetype`; their pre-filter bounds them.
7. **No proof runs them.** Their requirements constrain the guardrails only, like Wazuh rules
   without `logtest`. A Splunk engine for the proof waits on the licence decision.

## Consequences

- On Splunk's ES Content Update app (`DA-ESS-ContentUpdate` v6.8.0, Apache-2.0, all 2,223
  scheduled searches enabled as a test; `crates/sluice-rules/tests/splunk_escu.rs` with
  `SLUICE_SPLUNK_RULES`, fetched by `scripts/real-data/fetch-splunk-escu.sh`): every macro
  resolves; 845 searches are bounded in their fields, 1,378 may read any field (1,140
  `tstats`/data models, 125 array paths, 57 wildcards after the base search, 42 subsearches,
  14 wildcard field names), 1,293 may match any event, 2,193 are stateful.
- Searches over data models (most of Splunk's own ESCU detections use `tstats`) may read
  anything, and one that applies everywhere blocks every saving on the sources it reaches: fail
  closed, and listed in the report. Raw searches over the events themselves can save.
- Without the macros, nearly every search of Splunk's content uses one Sluice does not know:
  pass `macros.conf` (or `admin/macros`) along.
- A Splunk destination's `sluice_rules` may name `splunk` (`sluice up`).
