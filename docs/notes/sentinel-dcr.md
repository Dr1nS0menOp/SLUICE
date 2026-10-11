# Sentinel: data collection rule transformations

Facts for the native Sentinel backend (PLAN.md, M5). Verified on 2026-10-10 against the Microsoft
Learn page "Supported KQL features in Azure Monitor transformations" (updated 2026-07-28) and the
Kusto emulator (`mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest`, digest
`sha256:e176ca3e…`, 4.5 GB).

## What a transformation can do

- It runs per record: only operators that take one row and return at most one are allowed.
  `summarize` is not, so a DCR cannot build Sluice's summaries. Natively, Sentinel can only get
  L1 reductions (removing fields); L2 (summarize the rest) still needs Vector.
- Tabular operators: `extend`, `project`, `print`, `where`, `parse`, `project-away`,
  `project-rename`, `datatable`, `columnifexists`. Statements: `let` (scalar functions only).
- String operators: `==`, `!=`, `=~`, `!~`, `contains`, `contains_cs`, `has`, `has_cs`,
  `startswith`(`_cs`), `endswith`(`_cs`) and their negations, `matches regex`, `in`, `!in`.
- Dynamic functions: only `array_concat`, `array_length`, `pack`, `pack_array`, `parse_json`,
  `parse_xml`, `zip`. **`bag_remove_keys`, `bag_keys`, `bag_merge` and `pack_all` are not
  supported**, so a transformation cannot remove a key from a dynamic object or list an object's
  keys. Fields can only be removed as whole columns: `project-away` for every row, or
  `extend Col = iff(cond, <empty>, Col)` per row.
- Type and conditional functions: `gettype`, `isnull`, `isnotnull`, `isempty`, `isnotempty`,
  `iif`/`iff`, `case`, conversion (`tostring`, `toint`, `tolong`, …).

## KQL semantics checked in the emulator

| Expression | Result | Consequence |
|---|---|---|
| `tostring(ev.Missing) =~ ""` | `true` | an equality test must check presence first |
| `tostring(ev.EventID) =~ "4624"` (number) | `true` | numbers compare as their decimal text |
| `"LSASS.exe" =~ "lsass.exe"`, `contains`/`startswith`/`endswith` | case-insensitive | matches Sigma's default for ASCII |
| `"LSASS.exe" == "lsass.exe"` | `false` | `==` and `_cs` operators are case-sensitive |
| `matches regex "(?i)LOGGED\\s+ON"` | `true` | RE2; inline flags work |
| `isempty("")`, `isempty(null)` | `true` | VRL's "empty" is null or `""` |
| `isempty(dynamic([]))` | `false` | an empty array is not empty for either engine |
| `parse_json('{"t":"2026-10-10T08:00:22.000Z"}').t` | type `datetime` | `tostring` prints `2026-10-10T08:00:22Z`, not the original text: datetime, timespan and GUID values widen |
| `strcat_delim` with more than 64 arguments | query rejected (400) | keyword tests nest `strcat_delim` in groups |

**Differential result (scripts/kql-check.sh, 2026-10-10):** 1,324 predicates (field tests from
real sample values in every operator and case, keyword tests, and the example Sigma rules'
pre-filters) on 62 synthetic events: VRL matched 14,658 times, and KQL matched every one of
those. KQL also matched 9,695 times where VRL did not (keywords over joined columns, widened
types): safe, but it keeps more whole than Vector would.

The emulator runs full KQL, so it accepts functions a DCR rejects (`bag_remove_keys` worked
there). Generated transformations must therefore stay inside the list above; the emulator only
proves their semantics.

## Ingest without the Azure Monitor Agent

Checked 2026-10-11. The Logs Ingestion API (any HTTPS client, a DCR and an app registration)
accepts the standard Sentinel tables, not only custom `_CL` tables: `SecurityEvent`,
`WindowsEvent`, `Event`, `Syslog`, `CommonSecurityLog` and the ASIM tables
(`ASimNetworkSessionLogs`, `ASimDnsActivityLogs`, `ASimProcessEventLogs`,
`ASimAuthenticationEventLogs`, …) all have the API column checked in "Azure Monitor Logs table
feature support". `SecurityEvent` also supports the Auxiliary plan, a low-cost archive target.
So an open-source agent can feed built-in analytics rules, as long as its records match the
table schema; the DCR transformation can then stay `source`.

| Agent | License | Logs Ingestion API | Windows Event Log | Notes |
|---|---|---|---|---|
| Vector | MPL-2.0 | `azure_logs_ingestion` sink | `windows_event_log` source (beta) | what Sluice runs and proves |
| Fluent Bit | Apache-2.0 | `azure_logs_ingestion` output | `winevtlog` input | small footprint |
| Logstash + Microsoft plugin | plugin MIT | `microsoft-sentinel-log-analytics-logstash-output-plugin` | via Winlogbeat | Microsoft calls it public preview |
| OpenTelemetry Collector | Apache-2.0 | no Log Analytics exporter found | `windowseventlog` receiver | `azuremonitor` exporter targets Application Insights |

The legacy HTTP Data Collector API (used by older Fluentd/Logstash plugins) ended support on
2026-09-14; do not build on it.

## Billing

**Measured 2026-10-11** in a test workspace (`rg-sluice-test`/`sluice-test`, Sentinel on): the
same 43 real logon records (EventID 4624, shaped by Sluice) sent three times through the Logs
Ingestion API into `SecurityEvent`:

| Variant | Average `_BilledSize` |
|---|---|
| full | 1,694 bytes |
| `EventData` and four more columns set to `""` | 322 bytes |
| the same five columns left out | 322 bytes |

An empty string column is not billed: emptying a column per row (all a DCR transformation can
do) saves exactly as much as removing it. It also shows how large the `EventData` XML is: most
of a `SecurityEvent` record repeats, as XML, values the record already has as columns.

## Writing into the real tables

- In a workspace without Sentinel, `SecurityEvent` and `WindowsEvent` do not exist yet (the
  tables API answers `SolutionNotActive`); onboarding Sentinel creates them (232 and 24
  columns).
- Azure validates a DCR's output types against the table: five `SecurityEvent` columns are
  `guid` (`LogonGuid`, `TargetLogonGuid`, `SubcategoryGuid`, `InterfaceUuid`,
  `SourceComputerId`). A stream cannot declare `guid`, so Sluice declares them `string` and the
  DCR converts them with `toguid()`, which accepts Windows' braces (`{…}`) and turns anything
  invalid into null. Verified: they arrive as GUIDs without braces.
- Records sent through the API were queryable after about four minutes.

## Running analytics rules in the emulator

Verified 2026-10-11 on the same emulator image, for `sluice_kql::KustoEngine` (ADR 0015):

- `.create database <name> volatile` works and `.drop database <name> ifexists` removes it. A
  database per evaluation lets rule queries run unchanged on tables named `SecurityEvent` and
  `WindowsEvent`, with no table renaming that could also rewrite a string literal.
- `.ingest inline into table T with (format='multijson') <| …` takes one JSON object per line and
  maps keys to columns by name. Keys that are not columns are ignored; `"4624"` is converted to
  an `int` column; GUIDs with Windows' braces load as GUIDs; strings keep newlines and quotes
  (CSV would need quoting for those). A missing string column reads as `""`, a missing typed
  column as null.
- The tables API leaves out `Type` and the hidden columns (`_ResourceId`, `_SubscriptionId`);
  rules read them, so the engine adds them.
- A rule that reads a table the database lacks fails with HTTP 400 even on empty tables. Of the
  105 Microsoft rules on `SecurityEvent`/`WindowsEvent` (commit `55296e6`), 91 run and 14 do not
  (other tables, watchlists, workspace functions).
- End to end: `sluice up` with `--sentinel-rules` and `--kusto`, fed the 154 real Security events
  and two planted ones (a cleared log, a base64 PE command line), proved 5 = 5 alerts; Microsoft's
  `NRT_SecurityEventLogCleared` and `NRT_base64_encoded_pefile` each returned their row on the
  forwarded `SecurityEvent` records.

## Custom tables for other sources

Verified 2026-10-11 in the test workspace (tables API `2022-10-01`, DCR API `2023-03-11`, Logs
Ingestion API `2023-01-01`), for `sluice connect sentinel --sample`:

- A column name must start with a letter, have at least two characters, and use only ASCII
  letters, digits and `_`. Refused: `src-ip`, `event.code`, `1abc`, `with space`, `_hidden`,
  `Ünïcode`, one-letter names (`S`), and `Type`. Accepted: `Message`, `Computer`, `id`,
  `TenantId`, a 50-character name. All of `string`, `int`, `long`, `real`, `boolean`,
  `dynamic`, `guid` and `datetime` are valid types.
- A DCR stream declaration accepts the field names as they are (`@timestamp`), so the
  transformation renames them: `project-rename F_timestamp = ['@timestamp']`. Sluice keeps the
  name of every field that is already a valid column and renames only the others, into names
  nobody holds, so one rename never moves a column another one needs.
- `TimeGenerated` can come from a record field: `extend TimeGenerated = todatetime(['@timestamp'])`.
- A DCR that targets a table created a moment earlier may be refused for a short while; retrying
  after 20 seconds worked.
- End to end: 131 OPNsense filterlog, 71 Linux auth and 61 DNS records (synthetic, `sluice
  demo`) went into `SluiceFirewall_CL`, `SluiceLinuxAuth_CL` and `SluiceDns_CL` with every
  column filled as sent; nested objects arrived as `dynamic`. They were queryable after about
  six and a half minutes.
- A DCR stream passes only the columns it declares: a field that was not in the sample does not
  reach the table. Generate from a sample that covers the source, and again when it changes.

## Syslog into the standard table

Verified 2026-10-11 end to end: a `sluice up` source with `shape: sentinel_syslog`, Vector's
`azure_logs_ingestion` sink and the DCR from `sluice connect sentinel --standard-table syslog` (stream
`Custom-SluiceSyslog` → `Microsoft-Syslog`, transformation `source`):

- `Syslog` has 16 columns; Sluice fills `TimeGenerated`, `EventTime`, `Computer`, `HostName`,
  `Facility`, `SeverityLevel`, `ProcessName`, `ProcessID` (`int`) and `SyslogMessage`.
- Lines with a priority (`<86>…`) arrived with `Facility` (`authpriv`, `auth`, `cron`) and
  `SeverityLevel` (`info`) as the Azure Monitor Agent writes them: VRL's `parse_syslog` uses the
  same keyword names. Lines without one (Filebeat's `message`) have no facility or severity, so
  rules that filter on `Facility` do not see them; send syslog with its priority.
- An RFC 3164 line's own time and host win over the shipper's: `parse_syslog` read `bastion01`
  and yesterday's `Oct 10 08:00:55` from Filebeat lines that were sent today.

## Firewalls into CommonSecurityLog

Verified 2026-10-11 the same way (`shape: sentinel_common_security_log`,
`sluice connect sentinel --standard-table common-security-log`, stream
`Custom-SluiceCommonSecurityLog` → `Microsoft-CommonSecurityLog`): 131 OPNsense filterlog
records (synthetic) arrived with `DeviceVendor`/`DeviceProduct` (`Deciso`/`OPNsense`),
`DeviceAction`, `CommunicationDirection` (`Inbound`/`Outbound`), `Protocol` (`TCP`, `UDP`),
`SourceIP`/`SourcePort`/`DestinationIP`/`DestinationPort` (ports as `int`), the interface in
`DeviceInboundInterface` or `DeviceOutboundInterface`, the rule number in
`DeviceEventClassID` and the original line in `Message`. The table has 158 columns; Sluice fills
the 18 a parsed firewall record carries.
The same 131 firewall records as raw `filterlog` lines inside syslog, through
`shape: sentinel_asim_network_session` and `--standard-table asim-network-session` (stream
`Custom-SluiceASimNetworkSession` → `Microsoft-ASimNetworkSessionLogs`), arrived parsed:
`DvcAction` `Allow`/`Deny` with `EventResult` `Success`/`Failure`, `NetworkDirection`,
`NetworkProtocol`, addresses, ports, the interface and `NetworkRuleNumber`, with `EventType`
`NetworkSession` and `EventSchemaVersion` `0.2.6` (2026-10-11). That run showed
`NetworkProtocolVersion` empty for raw lines; the parser now passes the IP version on.
DNS the same way (2026-10-11): 61 query records (ECS fields, synthetic) through
`shape: sentinel_asim_dns` and `--standard-table asim-dns` (stream `Custom-SluiceASimDns` →
`Microsoft-ASimDnsActivityLogs`) arrived with `DnsQuery`, `DnsQueryType`/`DnsQueryTypeName`
(`A` 1, `AAAA` 28, `HTTPS` 65), `DnsResponseCode` 0 with `EventResult` `Success` and
`EventResultDetails` `NOERROR`, the client address and port, the answers in `DnsResponseName`,
`DnsFlags` and `TransactionIdHex`, with `EventType` `Query` and `EventSchemaVersion` `0.1.7`.
Web sessions the same way (2026-10-11): 84 nginx access records (Filebeat JSON with the
combined-format line in `message`, synthetic) through `shape: sentinel_asim_web_session` and
`--standard-table asim-web-session` (stream `Custom-SluiceASimWebSession` →
`Microsoft-ASimWebSessionLogs`) arrived with `Url`, `HttpRequestMethod`, `HttpVersion` `1.1`,
`EventResultDetails` (`200`, `302`, `304`, `404`) with `EventResult` `Failure` from 400 up,
`SrcIpAddr`, `HttpUserAgent`, `DstBytes`, and `EventType` `WebServerSession` with
`EventSchemaVersion` `0.2.6`. The table has no `HttpStatusCode` column; Microsoft's Apache parser
puts the code in `EventResultDetails` too.
Account columns (2026-10-11): after the DCR was updated with `Account` and `AccountType`, 40 real
Security events shaped by `sluice up` arrived with `Account`, `AccountType`, `SubjectAccount`
and `TargetAccount` filled (`NT AUTHORITY\SYSTEM`, `DESKTOP-…\ward`, `WORKGROUP\DESKTOP-…$`).
The way Microsoft's rules read them works: `split(Account, @'\')[1]` gives the name and
`AccountType == "User"` matches.
