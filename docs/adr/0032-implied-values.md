# ADR 0032: Implied values are removed only while they hold, and can be put back exactly

- Status: Proposed (branch `study/field-value`)
- Date: 2026-10-25

## Context

The field-value study (`docs/notes/field-value.md`, sources in `docs/credits.md`) asked what can
go from Windows and Linux events beyond what rules and queries read. Much of an event is a value
that follows from what kind of event it is: every Windows Security event says `Channel:
Security`, and on a 4624 logon `RestrictedAdminMode` is `-` unless `LogonType` is 10. Sending
such a value tells the SIEM nothing it could not work out, and recipes (ADR 0002) cannot name
them: they depend on the data, not on the rules.

Removing a field because it "usually" holds a value would lose the events where it does not. A
removal must lose nothing, and a reader of the forwarded data must be able to see what was there.

## Decision

1. **A reduction of its own (L1).** `drop_implied` lists *implied values*: a field, a value, and
   optionally another field and the value it must hold (`when`). A field is removed only while it
   holds exactly that value, of that type (`0` is not `0.0`, not `"0"`), and while `when` holds,
   after every other removal. Any other value is sent as it is. The guardrails treat it as any
   field removal: a field a rule reads stays on the events that rule could match, rare kinds of
   event are left alone, and the proof runs on the result.
2. **Learned from the sample.** The autopilot learns them per frequent JSON kind of event, over
   fields every key set of it carries, never a field that names the kind of event or a column a
   Sentinel workspace adds itself. A value is learned when the kind of event alone implies it, or
   when another field implies it. That other field must be a category: 2 to 32 values, 20 events
   each, no new value late in the sample, and no name that marks an identifier. A field that
   implies another is never removed. A recipe file may carry implied values too, which is the
   route for documented ones.
3. **Every engine, tested as VRL tests.** Vector removes them. So do the Sentinel data collection
   rule (within the characters a rule takes; the most worthwhile values go first), the
   Elasticsearch ingest pipeline, the Fluent Bit filter and the collector's statements. Each is
   proven in its own engine. An agent leaves a value tested against a whole number in place: Lua
   holds `3` and `3.0` alike, and the collector's JSON parser reads every number as a float.
4. **Put back exactly.** `plan.json` lists every implied value (`remove_implied`).
   `--sentinel-native` writes `<Table>Full.kql`, a workspace function that puts them back when a
   query runs; it reads a GUID column as text, as a query sees it. `--elastic-native` writes
   `SOURCE.runtime.json`: runtime fields of the field's type that shadow each field and give its
   value back. Their logic is a Painless function, proven on the sample through `_simulate`
   without writing to the cluster. The ingest pipeline keeps an empty field that may go as
   implied, unlike Vector, so that a missing field has one meaning.
5. **Modes.** `--mode rules,implied` picks the recipes' savings, the implied values, or both (the
   default). The report, the summary and `plan.json` (`saved_by_mode`) give the saving of each.

## Consequences

- Measured savings with implied values:
  - a Windows PC with all of SigmaHQ: 25.0 % → 42.4 %;
  - four machines of OTRF's APT29 data with all of SigmaHQ: 58.8 % and 58.7 % saved, about 26 %
    by implied values;
  - every alert the same in each run.
  - In a Sentinel workspace, Azure billed 30.7 % less on 100 records, as predicted. On the Azure
    Monitor Agent's stream too, a rule may empty `Activity` and `EventLevelName`, and Azure bills
    exactly the bytes left (`docs/notes/sentinel-dcr.md`).
- An analyst who queries the table itself for `RestrictedAdminMode == "-"` finds nothing. The
  Sentinel function and the Elasticsearch runtime fields read the data as before; Splunk, Wazuh
  and other destinations have no such step. Wazuh needs none: with its stock ruleset loaded,
  nothing is removed.
- Outside the sample, a put-back step can guess. A record of a known kind that arrived without the
  field (a variant the sample lacked) gets the implied value. So does, in Sentinel, a record whose
  column was empty to begin with. The proof on the sample rules it out there only.
- On a sample from one machine, its name looks implied. That costs no data, since a value guard
  keeps any other name, but it overstates the saving. The report names, per source, the values
  that are the same on every kind of event, and how much of the saving they make.
