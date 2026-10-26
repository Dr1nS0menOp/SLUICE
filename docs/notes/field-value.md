# What a field is worth beyond the rules (study)

Status: branch `study/field-value`, 2026-10-23: the study, and a first build of implied values
(see "Built on this branch"). Not on `main`.
The people and projects this builds on are credited in [credits](../credits.md).

## The question

Sluice removes what no loaded rule needs. That leaves a second question: is there data in a
Windows event or a Linux log line that no SOC needs, whatever the rules say, because it can
always be looked up or rebuilt? An EventID's description is the obvious example: Windows renders
it into every event, but it is the same text for every 4624 everywhere.

The answer must still respect the safety contract: an archive keeps every event whole, a field a
rule reads stays on the events that rule could match, and the proof checks the result.

## What others found

| Source | Who | What it says | What Sluice takes from it |
|---|---|---|---|
| [NIST SP 800-92](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-92.pdf), Guide to Computer Security Log Management (2006) | Karen Kent, Murugiah Souppaya (NIST) | Names the practice: *event reduction* removes unneeded data fields from all log entries, and is often done together with archiving. | The vocabulary, and the pairing of reduction with an archive, which is safety contract rule 2. |
| [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) and [event 4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688) reference | Microsoft | What every field holds, when it is a placeholder (see "Implied values" below), and which fields to monitor: for NTLM logons a *Key Length* other than 128 and a *Package Name* other than NTLM V2; *Restricted Admin Mode* for logon type 10; *Token Elevation Type* and *Mandatory Label* for 4688. | The field-by-field facts below, and which apparent placeholders are signals. |
| [Windows security event sets for Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/windows-security-event-id-reference) | Microsoft | The *Minimal* and *Common* sets: which event IDs matter for breach detection and which only for an audit trail. 4634 (logoff) is "not meaningful for breach detection and has relatively high volume". | A reference for which kinds of event a SOC can count rather than send, when no rule needs them. |
| [Appendix L: Events to Monitor](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor) | Microsoft | A potential criticality (low, medium, high) per event ID. | The same, per event. |
| [Azure Monitor Logs cost calculations](https://learn.microsoft.com/azure/azure-monitor/logs/cost-logs) | Microsoft | The billed size of a record counts every column, including those added during ingestion, except `Type` and the `_` standard columns. | Do not count a saving on `Type`; do count Sentinel's own added columns. |
| [Cribl Stream: Windows XML events](https://docs.cribl.io/stream/usecase-win-xml/) and the [cribl-windows-events](https://github.com/criblpacks/cribl-windows-events) pack (Apache-2.0) | Cribl; the pack by David Maislin | Parsing XML to key-value and dropping the values `0`, `0x0` and `-` shrank one event by 51 %, the whole pipeline by 63 %; the pack expects up to 70 % on classic events and 25 to 50 % on XML. | Confirmation that placeholders and rendered text are most of the fat, and a counterexample: see below. |
| [Top 4 tricks to reduce SIEM data volume](https://axoflow.com/blog/top-4-tricks-to-reduce-siem-data-volume) (2025) | Balázs Scheidler (Axoflow) | In Windows XML, "practically the entire message is duplicated in the RenderedText field"; removing it shrinks events significantly. | The same finding for the rendered `Message`, which Sluice's community recipes already drop. |
| [Pre-SIEM log filtering and log reduction](https://nxlog.co/news-and-blog/posts/pre-siem-log-filtering-and-log-reduction) | NXLog | Trimming by an allowlist of fields to keep; drop an event only when no detection, investigation or compliance need depends on it. | The caution, which is Sluice's rule inventory and proof. |
| [Pass the Hash Activity 2](https://detection.fyi/sigmahq/sigma/windows/builtin/security/account_management/win_security_pass_the_hash_2/) (SigmaHQ) | Dave Kennedy, Jeff Warren (method), David Vassallo (rule) | On 4624 it tests `KeyLength` 0 and `SubjectUserSid` `S-1-0-0` with logon type 3 and `NtLmSsp`. | The counterexample: a blanket "drop `0` and `-`" removes exactly the values this detection tests. |
| [Detecting Lateral Movement through Tracking Event Logs](https://blogs.jpcert.or.jp/en/2017/12/research-report-released-detecting-lateral-movement-through-tracking-event-logs-version-2.html) (2017) | JPCERT/CC | Which events and artefacts 49 attacker tools and commands leave on Windows, and that many are not logged by default. | Which kinds of event must stay whole for incident response, beyond the loaded rules. |
| [Event Forwarding Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance) | NSA | Which events to forward to find an adversary. | The same, as an event-level reference. |
| [Windows Event Forwarding for Network Defense](https://blog.palantir.com/windows-event-forwarding-for-network-defense-cb208d5ff86f) | Palantir | Open-sourced subscriptions that select security-relevant events. | The same. |
| [Windows Logging Cheat Sheets](https://www.malwarearchaeology.com/cheat-sheets) | Michael Gough (Malware Archaeology) | Which audit settings and events matter most, such as 4688 with command lines and 4104. | The same. |
| [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) | Mark Russinovich, Thomas Garnier (Microsoft) | `ProcessGuid` exists to correlate events "even when Windows reuses process IDs"; event timestamps are UTC. | Keep the GUIDs: they are the correlation keys. |
| [systemd.journal-fields](https://www.freedesktop.org/software/systemd/man/latest/systemd.journal-fields.html) | systemd project | `_MACHINE_ID`, `_BOOT_ID` and `_HOSTNAME` are fixed per host or boot; `_SOURCE_REALTIME_TIMESTAMP` is only present when it differs from the reception time. | Host and boot fields are constants per source; the journal itself already drops a timestamp when it repeats. |
| [Understanding audit log files](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files) | Red Hat | `msg=audit(time:serial)` ties the records of one event together; `arch` is the CPU architecture in hex. | `arch` is a host constant; the serial is a correlation key and stays. |
| [LAUREL](https://github.com/threathunters-io/laurel) (GPL-3.0) | Hilko Bengen, Sergej Schmidt | Turns auditd's records into one enriched JSON event per audit event, with arguments decoded. | Shaping auditd before analysis; the arguments are what detections read. |
| [Neo23x0/auditd](https://github.com/Neo23x0/auditd) (Apache-2.0) | Florian Roth and contributors | A rule set that keeps high-value telemetry and filters noise at the source, such as `auid>=1000` for interactive sessions. | Volume belongs at the source first; Sluice works on what arrives. |
| Drain, *An Online Log Parsing Approach with Fixed Depth Tree*, ICWS 2017 | Pinjia He, Jieming Zhu, Zibin Zheng, Michael R. Lyu | Groups log lines into templates and parameters. | Already Sluice's template discovery for text ([notes](drain.md)). |
| [Logzip](https://arxiv.org/abs/1910.00409), ASE 2019 | Jinyang Liu, Jieming Zhu, Shilin He, Pinjia He, Zibin Zheng, Michael R. Lyu | Extracting the templates of logs halves storage on average against traditional compressors. | The text of a template is a constant of the template. |
| [CLP](https://www.usenix.org/conference/osdi21/presentation/rodrigues), OSDI 2021 | Kirk Rodrigues, Yu Luo, Ding Yuan | Lossless compression of text logs as template plus variables, searchable without decompressing. | The same idea for the archive. A SIEM's rules need the whole line, so it does not apply to what is sent. |

The two lists of the literature that matter most here:

1. **The rendered text repeats the event.** Every source agrees: `Message`, `RenderedText` and
   Sentinel's `Activity` repeat what the structured fields and the EventID already say. Sluice's
   community recipes drop `Message` already.
2. **"Placeholder" is not the same as "worthless".** The blanket rule of dropping `-`, `0` and
   `0x0` would break SigmaHQ's pass-the-hash rule, and Microsoft itself recommends watching
   *Key Length* on NTLM logons. Whether a placeholder can go depends on the other fields of the
   event, which is the idea below.

## What the real samples say

Measured on this project's own samples (one Windows 11 PC, one Linux server; the samples stay
outside the repository). `scripts/study/field-value.py` lists per kind of event and field the
bytes, constants and implications; `scripts/study/implied-bytes.py` gives the totals below.
Shares of all bytes:

| Source | Events | Rendered text or XML | Schema constants per kind of event | 4624: implied placeholders |
|---|---:|---:|---:|---:|
| `SecurityEvent` read from Sentinel | 20,323 | 43.8 % | 13.6 % | 8.1 % of 4624's bytes |
| Security channel, Vector's `windows_event_log` | 20,000 | 38.0 % | 19.6 % | 5.6 % of 4624's bytes |
| System, Application, PowerShell, same shape | 42,344 | 33.0 % | 19.5 % | |
| System, Sigma's names | 20,000 | 31.5 % | 17.7 % | |
| Application, Sigma's names | 20,000 | 43.2 % | 11.8 % | |

- *Schema constants* counts only the envelope fields whose value is fixed by the provider and
  the event ID (`Channel`, provider name and GUID, `Task`, `Opcode`, `Level`, `Keywords`, task
  and keyword names, Sentinel's `Activity` and `EventLevelName`) and that had one value per kind
  of event in the sample. Fields that were constant only because the sample has one host
  (`Computer`, the user, `TenantId`) are left out; across a fleet they vary.
- In `SecurityEvent`, `EventData` is counted as rendered, but it is not all repetition: it holds
  every field of the event, and Sentinel gives only some of them a column of their own.
- The Linux samples show little of this kind: a syslog line's fields are the host, the program,
  the PID and the text. Its redundancy is the fixed text of the template, which a SIEM's rules
  read, and its volume is whole kinds of event (66,258 of 66,665 `auth.log` lines are `CRON`
  sessions), which Sluice already counts instead of sending when no rule needs them.

## Field by field

Five classes, from safest to never:

| Class | Can go | Examples (Windows) | Examples (Linux) |
|---|---|---|---|
| **A. Repeats the event** | Yes, lossless: it can be rendered again from the rest. | `Message`, XML `RenderedText`, Sentinel's `Activity` (event ID and description), `EventLevelName` (repeats `Level`), `keyword_names` (repeats `keywords`), Sentinel's `Account` (a domain and user name pair the event already holds). | Little: a syslog line carries no rendered copy of itself. |
| **B. Fixed by the schema** | Yes, lossless when removed only while it holds the fixed value. | `Channel`, provider name and GUID, `Task`, `Opcode`, `Level`, `Keywords` for an event ID that only succeeds (or only fails). | `arch` in auditd records, `_MACHINE_ID` and `_HOSTNAME` per source, `_BOOT_ID` per boot. |
| **C. Implied by another field** | Yes, lossless when removed only while the other field implies it. | 4624: `RestrictedAdminMode` is `-` unless `LogonType` is 10; `TargetOutboundUserName` and `TargetOutboundDomainName` are `-` unless `LogonType` is 9; `LmPackageName` is `-` unless the package is NTLM; `KeyLength` is always 0 for Kerberos; `TransmittedServices` is `-` outside S4U; `LogonGuid` is all zeros when not captured; `TargetLinkedLogonId` is `0x0` without a linked session. | `_SOURCE_REALTIME_TIMESTAMP` equal to the reception time (the journal drops it itself). |
| **D. Low value, not implied** | Only on a team's explicit choice, never by default. | `SystemThreadId`, the reporting `SystemProcessId`, `IpPort` of a network logon. | The PID of a one-line program. |
| **E. Keep** | No. | Who (SIDs, names, domains), the logon IDs and GUIDs that correlate events, `LogonType`, the process and its command line, addresses, hashes, `ProcessGuid`, `EventRecordId` (a gap can show deleted records), `KeyLength` on NTLM logons. | The user, the host, the command, the audit serial, `auid` and `ses`. |

Class C needs the condition. `KeyLength` 0 says nothing on a Kerberos logon, and on an NTLM
network logon it is the pass-the-hash signal.

## The algorithm: implied values

The idea that turns this from a list into something that sees it by itself:

> A value can be removed when it is **implied**: by the kind of event alone (class B), or by the
> value of another field of the same event (class C). It is removed **only while it equals the
> implied value**, so every event can be rebuilt exactly, and any other value is kept.

1. **A dictionary of implied values.** Per kind of event, the values implied by the event ID
   (`Keywords` = `0x8020000000000000` on 4624) and by another field (`RestrictedAdminMode` = `-`
   when `LogonType` ≠ 10). It starts from the vendors' documentation, credited per entry.
2. **Learned from the sample.** For each kind of event, a field with one value is a candidate
   constant; a field whose value is fixed for every value of a low-cardinality field (with
   enough events per value) is a candidate implication. The measurements above are this step.
3. **Guarded by value.** The generated code removes a field only when it holds the implied
   value: in VRL `if .KeyLength == "0" && .AuthenticationPackageName == "Kerberos" {
   del(.KeyLength) }`. A wrong or incomplete dictionary entry then costs savings, never data:
   a value that differs stays.
4. **Rebuildable.** `plan.json` carries the dictionary, so a reader of the forwarded data can put
   every removed value back, and the archive keeps the original anyway.
5. **Still checked.** The guardrails keep every field a rule reads on the events that rule could
   match, so SigmaHQ's `KeyLength: 0` test keeps `KeyLength`; the proof runs the rules on the
   result; the report says per field "implied by …".

What this does not do: decide that a field is worthless because people say so. Class D stays a
team's explicit choice.

## Built on this branch (2026-10-23)

`sluice analyze` and `sluice demo` now learn implied values from the sample, as the mode
`implied` next to the mode `rules` (the recipes); `--mode` picks either or both, and the report
gives the saving of each:

- **Core.** A reduction `drop_implied` (L1, lossless) with values of the form "field = value",
  optionally "when other field = value". The guardrails treat it as any field removal: a field a
  rule reads stays on the events that rule could match, and rare kinds of event are left alone.
  A recipe file may carry it too, which is the route for documented implications.
- **Learning** (`sluice-autopilot`, `implied.rs`), per frequent JSON kind of event, over fields
  every variant of it carries, never a field that names the kind of event, and, read from
  Sentinel, never a column the workspace adds itself (`Type`, `TenantId`, `_…`):
  - a field with one value on every event is a constant of the kind;
  - a field with one value for each value of another field (at most 32 values, 20 events
    each) is implied by it, if that other field is a category: every value in the later half
    of the sample already occurs in the earlier half, and its name does not mark it as an
    identifier (`…Id`, `…Guid`). Without these two checks, one PC's few thread and logon IDs
    looked like categories and inflated the measured saving from 38 % to 46 %;
  - a field that implies another is never removed itself, and at most 64 values per kind.
- **Vector.** `if .field == value && .other == value { del(.field) }`, after the other
  removals, so a field is only removed while what implies it is still in the event.
- **Plan and report.** `plan.json` lists them as `remove_implied`, the dictionary to put every
  removed value back; the report says per kind of event which fields are implied, and by what.
- **Sentinel.** The data collection rule of `--sentinel-native` empties implied values too, as
  a test per column (`tostring(column) == value`, and the implying column's value), after the
  other removals. In the table an emptied column and an empty one look alike, so it empties a
  value only where the `<Table>Full` function it writes can put it back by the record's event
  ID alone: every kind of event with that ID always has the column. A rule takes at most 15,360
  characters; the most worthwhile values go first (the kind's own before conditional ones,
  longer before shorter) and the rest is left to Vector. On the test workspace's sample, with
  its rules in the emulator: 4.3 % saved by the rule before, 30.8 % with implied values, every
  emptied column also removed by Vector.
- **The report** lists per kind of event every removed field: events, bytes, why it may go
  (the recipe's reasoning, empty, always this value, or this value whenever that field holds
  that one) and where its removal can run.
- **The other engines.** Elasticsearch's ingest pipeline, Fluent Bit's Lua filter and the
  collector's transform statements remove implied values too, each proven against Vector in
  the real engine; the agents leave a value tested against a whole number in place, since they
  cannot tell `3` from `3.0`.
- **Elasticsearch puts them back.** `--elastic-native` also writes `SOURCE.runtime.json`:
  runtime fields (`keyword`, `long` or `boolean`) that shadow each implied field and give its value back on a document the
  pipeline took it from (its kind of event, the implying field's value, a key set the pipeline
  can have left). The pipeline keeps an empty field that may go as implied, so its absence has
  one meaning. Proven on the sample in Elasticsearch: on the demo, 41 fields of
  `windows-security` read every forwarded document as the full one.
- **Emptied objects go too** (2026-10-26). When every field of a nested object goes, the object
  went on as `{}`: on the demo's Windows logoff (4634), 34 of the 262 bytes sent were
  `"agent":{},"ecs":{},"host":{"os":{}}`. Every generator that removes nested fields (Vector,
  the ingest pipeline, the Lua filter, the collector) now removes such an object after its
  removals, deepest first (`Plan::emptiable_objects`). It is lossless: a rule that reads an
  object keeps its fields, so no rule can tell. An object that came empty with the event stays:
  Vector, Painless and Lua note before the removals whether the object held a field; the
  collector needs no note, as its exact recognition never takes a record with an extra empty
  object. Sentinel's transformation removes whole columns only, so nothing changes there; the
  put-back steps read a missing parent as a missing field, as before (ADR 0033).
- **The report** shows per source up to 10 events as they are sent, with what was left out and
  why, and says in plain words what an implied value is.

Measured with the real rules (the project's real-data runs, `scripts/real-data/run.sh`):

| Sample and rules | Without | With implied values | Alerts, full = forwarded |
|---|---:|---:|---|
| Windows System, Application, PowerShell; all 3,152 SigmaHQ rules | 25.0 % | 42.3 % | 236 = 236 |
| Linux `auth.log` and `syslog`; SigmaHQ | 25.7 % | 25.7 % | 0 = 0 |
| Sentinel `SecurityEvent` and `WindowsEvent`; the Windows Security Events solution and SigmaHQ | 0.0 % | 0.0 % | 1,706 = 1,706 |
| Sentinel `SecurityEvent` of the test workspace; its own two rules | 4.1 % | 37.9 % | 0 = 0 |
| `sluice demo --scale 100`; the example rules | 67.9 % | 78.8 % | 41 = 41 |
| OTRF Security-Datasets APT29 day 1, Security and Sysmon of **four machines**; the example rules (summary records counted, 2026-10-26) | 61.2 % (the rules' share) | 77.7 % (implied 16.5 %) | 0 = 0 |
| The same four machines; all 3,152 SigmaHQ rules (again on 2026-10-26) | 32.8 % (the rules' share) | 58.3 % (implied 25.5 %) | 29,555 = 29,555 |
| OTRF APT3 Empire (Shire, a domain controller and three workstations), Security and Sysmon, renamed to Sigma's names; the example rules | 58.3 % (the rules' share) | 69.7 % (implied 11.4 %) | 112 = 112 |
| The same; all 3,152 SigmaHQ rules | 0.0 % (the rules' share) | 24.7 % (implied 24.7 %) | 15,806 = 15,806 |
| APT29 day 2, the same four machines, Security; all SigmaHQ (again on 2026-10-26) | 35.2 % (the rules' share) | 62.8 % (implied 27.7 %) | 287 = 287 |
| APT29 day 2, Sysmon (407,265 events, 812 MB); all SigmaHQ (again on 2026-10-26, 139 s, 4.6 GB peak) | 32.6 % (the rules' share) | 57.7 % (implied 25.1 %) | 8,431 = 8,431 |

- On Linux nothing changes, as predicted: its lines are text.
- With SigmaHQ on records in Sentinel's names, SigmaHQ's rules may read any field (ADR 0018),
  so the guardrails keep every field, implied or not: the new saving is held to the same rule.
- The single-host samples include host constants (`Computer`, the one user). They are removed
  losslessly but save on that host only; across a fleet they vary and are not learned. The
  Windows figures are therefore an upper bound until a sample spans hosts.

## Open questions before this becomes a feature

- **Queries, not only rules.** An analyst who queries `RestrictedAdminMode == "-"` finds nothing
  once it is removed. Sentinel's query log (`--query-log-days`) covers what was run: its queries
  join the inventory as rules, and implied values go through the same `allowed_drops` as every
  other removal (`guard.rs`, tested by `c3_an_implied_value_a_rule_reads_stays_on_the_events_it_could_match`),
  so a field a logged query reads stays. Documenting that the value is implied by absence, and
  `<Table>Full`, cover the rest.
- **Billing per SIEM.** Measured for Sentinel on 2026-10-24 (`docs/notes/sentinel-dcr.md`):
  through the Logs Ingestion API a rule empties `Activity`, `EventLevelName` and the other
  implied columns, Azure bills 30.7 % less on 100 real records (the analysis predicted 30.8 %),
  and `SecurityEventFull` puts every value back. On the Azure Monitor Agent's stream (measured
  2026-10-25) a rule sees `Activity`, `EventLevelName`, `Channel` and `Keywords` too, may empty
  them, and Azure bills exactly the bytes left. What the others document (read 2026-10-26, not
  measured):
  - *Elastic Security Serverless* meters ingest as "the fully enriched normalized data size at
    the end of the ingest pipeline", "before Elasticsearch compression is performed"
    ([billing dimensions](https://www.elastic.co/docs/deploy-manage/cloud-organization/billing/security-billing-dimensions)).
    So the fields `--elastic-native`'s pipeline removes, implied values and emptied objects
    included, are not billed; a field the pipeline adds would be.
  - *Splunk*: data that ingest actions filter or route "such that the data does not get added
    to an index" is not licensed volume
    ([license implications](https://help.splunk.com/en/data-management/perform-basic-data-processing/license-implications)).
    The page says nothing on fields removed from an event that is indexed, so whether a
    smaller event costs less stays to be measured (Splunk is parked).
  - Wazuh is self-hosted: nothing is billed per byte, only disk and the indexer's load.
- **Versions.** `Version`, `Task` and `Keywords` can change between Windows builds. A
  value-guarded removal stays exact; only the savings vary. Microsoft's page on 4624 (read
  2026-10-26, [event-4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624))
  lists event version 0 for Windows Server 2008 and Vista, 1 for Server 2012 and Windows 8
  (which added `ImpersonationLevel`), and 2 for Windows 10 (which added `RestrictedAdminMode`,
  `VirtualAccount`, `ElevatedToken`, `TargetLinkedLogonId` and the outbound account fields). On
  a fleet of mixed versions, `Version` holds more than one value on one kind of event, so it is
  no constant there; the learner may still find it implied by another field, such as
  `Computer` (each machine runs one version), which is exact as long as a machine is not
  upgraded, and after an upgrade the field is simply sent again. A rare version's key set keeps
  a template of its own (ADR 0019) and learns nothing, as rare kinds of event never do.
- **The learning step needs a fleet.** One PC makes `Computer` look constant. That costs no
  data (a value guard keeps any other host's name), but it overstates the saving. Nothing in
  one machine's data tells its name from a value the kind of event fixes, so the report says per
  source which implied values are the same on every kind of event that has them, and how much
  of the saving they make. On the test workspace's sample: `Channel`, `Computer`,
  `EventLevelName`, `EventSourceName` and two more, 3.6 MB of 12.8 MB saved. On the demo's
  `windows-security`, from five machines, the list holds no machine name: only values the fleet
  shares (`Channel`, `Keywords`, the agent's and the OS's versions, the domain).
  On OTRF's APT29 day 1 (four real machines, 184,886 Security and Sysmon events, 2026-10-24)
  implied values save 16.5 %, no machine name is learned as a constant (`Hostname` only as
  implied by another field), and the list holds only what the four share, such as `host`,
  there the address of the log collector. With all of SigmaHQ: 58.3 % saved, 25.5 % by implied
  values, 29,555 = 29,555 alerts (measured again on 2026-10-26, after the identifier rule below);
  on day 2 (a second attack) every alert the same as well.
  A second network, OTRF's APT3 Empire scenario in the Shire environment (2026-10-26: a domain
  controller and three workstations, 85,441 Security and Sysmon events in winlogbeat 6's names,
  renamed to Sigma's before the run, values untouched): with all of SigmaHQ 24.7 % saved, all by
  implied values, 15,806 = 15,806 alerts. A machine's name is learned as a constant only on two
  kinds of event that only the domain controller logs, which is right; `host.name` holds the
  event collector the four share. That run also found a weakness, now closed: fields named as
  identifiers (`ExecutionThreadID`, `ExecutionProcessID`, `ProviderGuid`; the demo's
  `agent.ephemeral_id`) were learned as implied per `Computer`, true for the one thread or agent
  run each machine kept through the sample, and false after its next restart. A field named as
  an identifier is now implied by the kind of event only (a `SubjectLogonId` that is always
  `0x0`), never by another field. That costs the demo 0.8 points (79.6 % → 78.8 %) and APT3 4.5
  points, savings that would not have lasted.
- **Analysts see an absent field.** A removed value is implied, not gone, but a query on the
  table itself for `RestrictedAdminMode == "-"` finds nothing. For Sentinel, `<Table>Full`
  reads as before; analytics rules keep querying the table, and the guardrails keep every field
  they read. For Elasticsearch, the runtime fields of `SOURCE.runtime.json` do the same in a
  search or a data view. Splunk has no such step yet (parked). **Wazuh needs none:** with its
  stock ruleset loaded (4,652 rules) the demo saves 0.0 %, implied values included (78.8 %
  without them, measured 2026-10-24 and recounted 2026-10-26 with the summary records and the
  emptied objects), because raw-text rules such as 1002 read the whole JSON
  line (`docs/notes/wazuh.md`), and Windows data reaches Wazuh through its agent, not through
  Sluice. Nothing is removed, so nothing needs putting back.
- **Out of the sample, a rebuild can guess.** `<Table>Full` and the runtime fields recognise a
  record by its kind of event; a record of that kind that arrived without the field (a variant
  the sample did not have), or with it empty in Sentinel, where an emptied and an empty column
  look alike, gets the implied value. The proof on the sample rules this out there only.
- **Linux text lines.** Template text is the bulk of a line, and rules read it whole. Saving there
  stays with counting kinds of event no rule needs, and with archives that compress by template
  (as CLP does).
