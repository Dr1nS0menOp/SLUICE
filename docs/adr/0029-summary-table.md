# ADR 0029: Summaries in a table of their own

- Status: Accepted
- Date: 2026-10-17

## Context

Events Sluice counts instead of sends (L2, L3) become summary records: per window of 60
seconds, per source, kind of event and summary keys, the count (`sluice_summary`,
`sluice_source`, `sluice_template`, `sluice_keys`, `sluice_count`). Every destination got them
next to the events. A Sentinel destination sends to a data collection rule stream of one shape
(`SecurityEvent`, a custom table), whose rule passes only the columns the stream declares: the
summary records lost every field there, and the counts were gone. PLAN.md M10/M12: "summaries as
a table of their own with counting helpers".

## Decision

1. **A destination says which records it takes** (`sluice_records: [events]`, `[summaries]`, or
   both, the default), removed before Vector sees the sink, like `sluice_formats` and
   `sluice_sources`.
2. **`sluice connect sentinel --summary-table`** writes the table `SluiceSummary_CL`
   (`TimeGenerated`, `sluice_source`, `sluice_template`, `sluice_keys` as `dynamic`,
   `sluice_count`), its data collection rule (stream `Custom-SluiceSummary`, stamped with the time
   of ingestion) and a second destination for it with `sluice_records: [summaries]`. The
   destination `connect` writes for a table of one shape (`--standard-table`, `--sample`) takes
   `[events]` only.
3. **`SluiceCounts`**, the workspace function `connect` writes, reads the table as `Source`,
   `Template`, `Keys` and `Count`, so a query that counts events can add what was counted
   instead: `union (SecurityEvent | where EventID == 5156 | summarize Count = count() by
   bin(TimeGenerated, 1h)), (SluiceCounts | where Template startswith "windows-security:5156:" |
   summarize Count = sum(Count) by bin(TimeGenerated, 1h)) | summarize Count = sum(Count) by
   TimeGenerated`. A test runs it in the Kusto emulator on the table as defined.

## Consequences

- Configurations written before keep sending summaries to every destination; one for a Sentinel
  table of one shape should add `sluice_records: [events]` and a summaries destination.
- Splunk and Elastic store summary records as events of their own and need no table; their
  counting helpers (a Splunk macro) are still to come.
