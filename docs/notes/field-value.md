# What a field is worth beyond the rules (study)

Status: research on branch `study/field-value`, 2026-10-23. Nothing here is in the product yet.
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

## Open questions before this becomes a feature

- **Queries, not only rules.** An analyst who queries `RestrictedAdminMode == "-"` finds nothing
  once it is removed. Sentinel's query log (`--query-log-days`) covers what was run; documenting
  that the value is implied by absence covers the rest.
- **Billing per SIEM.** Sentinel bills the columns it adds during ingestion (`Activity`,
  `EventLevelName`, `Account`), but a data collection rule may not see them: whether a
  transformation can remove them needs a test in the workspace, with `_BilledSize` before and
  after.
- **Versions.** `Version`, `Task` and `Keywords` can change between Windows builds. A
  value-guarded removal stays exact; only the savings vary.
- **The learning step needs a fleet.** One PC makes `Computer` look constant. Learned candidates
  must be limited to envelope fields and documented implications until a sample spans hosts.
- **Linux text lines.** Template text is the bulk of a line, and rules read it whole. Saving there
  stays with counting kinds of event no rule needs, and with archives that compress by template
  (as CLP does).
