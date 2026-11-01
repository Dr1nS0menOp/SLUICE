# Testing Sluice on your own SIEM

Sluice's savings are proven on a sample: the rules run on the full and the reduced sample and
must raise the same alerts. This page is for trying it on a real SIEM, step by step, so that
the proof is checked against what actually happens over days of live data. Every step reads
first and changes something only where it says so, and every change can be undone.

Sluice itself never changes your environment ([ADR 0030](adr/0030-advice-only.md)): you deploy
what it writes. Run the steps in a test workspace or index first if you have one. For how it
works, see [how Sluice saves](how-sluice-saves.md); for every option, [usage](usage.md).

## What a field test answers

1. **Do the savings hold on live data?** The percentage on the sample, compared with what the
   SIEM bills after deployment.
2. **Does every detection still fire?** Alerts per rule over the same days of the week, before
   and after.
3. **Does what was learned on one day hold on the next?** Values learned from a sample may stop
   holding. Sluice loses nothing when they do, since a value is removed only where it holds, but
   the saving shrinks.
4. **Is everything still there to search?** Each event, whole, in the archive.

## 1. Baseline: a week before

Before changing anything, write down a week of ingest and alerts. In Microsoft Sentinel (Logs):

```kql
// Billable ingest per table, in GB per day
Usage
| where TimeGenerated > ago(7d) and IsBillable
| summarize GB = sum(Quantity) / 1024 by DataType, bin(TimeGenerated, 1d)

// Alerts per analytics rule
SecurityAlert
| where TimeGenerated > ago(7d)
| summarize Alerts = count() by AlertName
```

In Elastic, Stack Monitoring (or `GET _cat/indices?v`) gives the ingest per index, and the
Alerts page in Security gives the alerts per rule. In Wazuh, the `wazuh-alerts-*` indices give
alerts per `rule.id`.

## 2. Two samples, two days

Take a sample of a busy hour on two different days, with the exporters in
`scripts/real-data/` ([usage, step 2](usage.md#2-find-out-what-you-would-save-on-your-own-logs)).
Keep them outside any repository: they are real records.

```sh
scripts/real-data/collect-sentinel.sh /subscriptions/…/workspaces/NAME day1/ 1 20000 SecurityEvent
# the next day
scripts/real-data/collect-sentinel.sh /subscriptions/…/workspaces/NAME day2/ 1 20000 SecurityEvent
```

Fetch every rule the SIEM runs (`sluice rules fetch`), so the inventory is complete and the
proof runs your own rules.

## 3. Analyze day 1, prove on day 2

The source's id in `sources.yaml` is the sample file's name (`SecurityEvent`), and
`dcr/SecurityEvent.dcr.json` is the data collection rule the records go through, as Azure gives
it.

```sh
sluice analyze --input day1/ --sources sources.yaml --sentinel-rules inventory/sentinel \
  --kusto http://127.0.0.1:8090 --sentinel-table SecurityEvent=SecurityEvent \
  --native sentinel --sentinel-dcr dcr/SecurityEvent.dcr.json --out out/
sluice prove --config out/vector.yaml --input day2/ --sources sources.yaml \
  --sentinel-rules inventory/sentinel --kusto http://127.0.0.1:8090 \
  --sentinel-table SecurityEvent=SecurityEvent
```

`sluice prove` runs what was learned on day 1 on day 2's records, which it has never seen. It
must list no `missing` or `extra` alert (it fails otherwise), and the saving it prints is what
day 1's plan saves on day 2.

A proof without alerts shows little: if the sample raised none, `sluice prove` says so and
fails. Take the sample from an hour in which your rules fire, or run a few harmless attack
simulations in that hour (for example [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
tests on a test machine). `--allow-no-alerts` accepts the proof anyway.

Read `out/report.html` before deploying anything, and look at three places in it:

- **Problems**: rules read broadly, and functions or parsers whose source Sluice lacks. Each
  costs savings, never safety, and the report says what to give Sluice to read them.
- **Values the same on every kind of event** ("check these"): they may be one machine's, such as
  its name. They are removed only where they hold, but decide whether you expect them to.
- **The events the SIEM still receives**: per source, records as they would arrive. Check that
  an analyst could still work with them.

## 4. Deploy, with the way back ready

Save the current configuration before you change it: the data collection rule as Azure gives it
(`az monitor data-collection rule show`), the ingest pipeline, the agent's configuration, or
the Vector configuration. Putting it back is the rollback.

- **Sentinel.** Create the archive table first (`out/sentinel/*Archive_CL.table.json`, Auxiliary
  plan), then update the rule with `out/sentinel/dcr.json`, and save
  `out/sentinel/<Table>Full.kql` as a workspace function where implied values are removed.
  `scripts/real-data/deploy-dcr-native.sh` does the same on a few records and checks that each
  arrives whole in the archive and transformed in the table; it restores the rule afterwards.
  `scripts/real-data/try-dcr-native.sh` checks that Azure and the emulator make the same of
  each record.
- **Elastic, Fluent Bit, OpenTelemetry Collector.** Add the pipeline or filter Sluice wrote for
  one source first ([usage, step 3](usage.md#3-carry-out-the-savings)).
- **Vector.** Point `vector.yaml`'s sources and sinks at your own, and run
  `vector validate --no-environment out/vector.yaml && vector test out/vector.yaml` first.

Start with one source and one week. A Sentinel data collection rule takes five to ten minutes
to apply a change.

## 5. Measure a week after

Run the queries of step 1 again for the week after, and compare:

- **Ingest per table** against the baseline and against the report's percentage. Real traffic
  varies between weeks, so compare the busy hours, or the same day of the week.
- **Alerts per rule.** A rule that fired every week and now fires much less is worth a look:
  compare its query on the archive table (everything whole) with its alerts. A rule that fires
  on the archive and not on the table is a bug; report it.
- **The archive.** Every event is in it, whole: compare its count per hour with the source's.
- **Implied values.** Query `<Table>Full` instead of the table for a day: every value is back.

Sentinel puts each table's billed size in `_BilledSize`, per record:

```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| summarize Records = count(), MB = sum(_BilledSize) / 1e6 by EventID
| order by MB desc
```

## 6. Undo

Put back the saved configuration. Nothing Sluice proposed removes data from the archive, so
what was left out of the table in the meantime can still be read there.

## Known limits to watch

- **Counting needs a pipeline tool.** Sentinel's data collection rule can leave whole events
  out of the table and keep them in the archive
  ([ADR 0036](adr/0036-route-to-the-archive.md)), but it cannot count them. Routing was proven
  in the Kusto emulator, not yet on a live workspace. If your sources have high-volume kinds of
  event that a recipe counts (Windows 5156, Sysmon 3, 7 and 10, firewall passes), checking that
  they arrive in the archive and not in the table is a useful finding.
- **Custom tables (`_CL`) are read broadly.** A data collection rule may put any source in them
  under any column name, so a rule over a custom table protects every record in it, and nothing
  in it is counted or routed.
- **Nested fields.** A data collection rule recognises a kind of event by its top-level columns
  only, so records told apart by a nested field (`event.dataset`) are sent unchanged there.
- **A sample of an hour may miss rare events.** Kinds of event with fewer than 100 events, or
  under 0.1 % of the source, are never changed; a kind that is rare in the sample and common later
  stays unchanged until the next analysis.
- **Rules change.** A rule added after the analysis is not protected until you fetch the rules
  and analyze again. Run both regularly, for example weekly in CI
  ([usage, step 7](usage.md#7-review-every-change-in-git)).

## Reporting back

Findings help most as an issue on [GitHub](https://github.com/Dr1nS0menOp/SLUICE/issues), with
numbers only, never records:

- the SIEM, its version, and the sources (product and service, not host names);
- the report's saving per source and the measured saving per table after a week;
- alerts per rule before and after, for any rule that changed;
- `plan.json`'s `problems`, and what `sluice prove` said on day 2;
- anything that surprised you in the report.

A report written with `--no-examples` leaves the sample's values out and can be shared.
