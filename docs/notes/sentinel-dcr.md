# Sentinel: data collection rule transformations

Facts for the native Sentinel backend (PLAN.md, M5). Verified on 2026-10-10 against the Microsoft
Learn page "Supported KQL features in Azure Monitor transformations" (updated 2026-07-28) and the
Kusto emulator (`mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest`, digest
`sha256:e176ca3e…`, 4.5 GB).

Some end-to-end checks below ran through `sluice up`, `sluice agent windows` and `sluice connect
sentinel --standard-table`, which are archived since [ADR 0030](../adr/0030-advice-only.md) (the
last on 2026-10-18, with the shaping VRL); what they found about Azure still holds.

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

## Limits found while deploying a transformation (2026-10-17)

- **`transformKql` takes at most 15,360 characters.** A longer one is refused when the rule is
  saved: `InvalidTransform: 'TransformKql' length should be 15360 characters or less`.
- **A transformation sees only its stream's columns.** Naming a column the stream does not
  declare is an error (the emulator answers 400). The stream of `sluice agent windows --dcr` has
  218 of `SecurityEvent`'s 232 columns. `columnifexists("X", default)` reads a column that may be
  missing; the default's type need not match the column's.
- A rule's own transformation runs on the stream's types: `toguid()` takes the `string` GUID
  columns the stream declares, and refuses a `guid`.
- Records sent with a value of the wrong type for a stream column (a number for a `string`
  column) arrive with that column empty.
- A 9,630-character transformation from `sluice analyze --sentinel-native --sentinel-dcr` was
  accepted by Azure in the `sluice-windows` rule of the test workspace. On 150 real Security
  records sent through it (`scripts/real-data/try-dcr-native.sh`), Azure and the emulator
  agreed on every record: `EventData` emptied on 7 of 50 4672 and 16 of 50 4798 records (the
  others have another key set or a rule that may match keeps them whole), none of 50 4624.
  Average `_BilledSize`: 4672 1,076 bytes and 4798 786, where the full records of the same
  workspace average 1,168 and 1,029.
- A marker for test records must not touch a column the transformation recognises records by:
  an `EventRecordId` changed for that broke recognition, and nothing was emptied. Azure's own
  `TimeGenerated` works.

## The archive flow (2026-10-17)

The rule `sluice analyze --sentinel-native --sentinel-dcr` writes has, next to the transformed
flow into `SecurityEvent`, an untransformed flow of the same stream into
`SluiceSecurityEventArchive_CL` on the Auxiliary plan (`scripts/real-data/deploy-dcr-native.sh`).

- **Create the table first, and wait.** The tables API (`2023-01-01-preview`, `"plan":
  "Auxiliary"`) answers before the table is ready: its `provisioningState` is `Updating` for a
  while, and a rule naming it is refused until then (`InvalidOutputTable: Table for output
  stream … is not available`). A table that is `Updating` cannot be deleted either.
- An Auxiliary table took the 218 columns of the stream, `guid` types included.
- **A changed rule with a new output table took more than two minutes to apply.** Records sent
  two minutes after the `PUT` still went through the old rule: nothing emptied, nothing
  archived. Ten minutes was enough.
- **Read an Auxiliary table through `/search`, not `/query`.** `POST
  /v1/workspaces/{id}/query` answers a query on it with no rows and no error;
  `/search?timespan=PT6H` returns them.
- Records with a three- or nine-decimal `TimeGenerated` (Vector writes nine) arrived in the
  Auxiliary table, although the table documentation asks for six. **An Auxiliary table keeps
  the time to the microsecond** (`…09.456789123Z` is stored as `…09.4567890Z`), an Analytics
  table to 100 ns, so the same record cannot be matched across the two on `TimeGenerated ==`.
- Result: of 150 real Security records, all 150 arrived in `SecurityEvent` with `EventData`
  emptied on 7 of 50 4672 and 16 of 50 4798 (as with the transformation alone), and all 150
  arrived whole in the archive table, in each of four runs.

## Exporting the rule with the Azure CLI (2026-10-22)

`az monitor data-collection rule show` (Azure CLI 2.91.0, extension `monitor-control-service`)
does not print the rule as the Resource Manager API returns it: it moves everything under
`properties` to the top level (`dataFlows`, `streamDeclarations`, …) and adds `resourceGroup`.
`--sentinel-dcr` read only the API's shape and refused that export with "the data collection rule
has no data flow into Microsoft-SecurityEvent". It now reads both shapes and writes the API's,
without `resourceGroup`, which is what `az rest --method put` sends back. The first run of that
command installs the extension and prints a warning about preview extensions; that is harmless.

**The README's Sentinel guide, end to end (2026-10-22).** Followed as written on the test
workspace, from a fresh clone: fetch (1 analytics rule, 1 Fusion rule, 860 tables), a sample of
20,154 `SecurityEvent` records of the last day, the analysis (4.1 % saved, 0 = 0 alerts), the
native analysis with the exported rule (`EventData` of 4672 and 4798), then the two `az rest`
calls. Of 100 records sent through the deployed rule (20 each of 4624, 4672, 4688, 4798 and
5379), all 100 arrived in `SecurityEvent` and all 100 whole in `SluiceSecurityEventArchive_CL`;
4672 and 4798 arrived with `EventData` emptied (12,960 and 10,527 bytes against 25,180 and 22,114
in the archive), the other three unchanged.

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
do) saves exactly as much as removing it.

**Implied values, measured 2026-10-24** in the same workspace with
`scripts/real-data/try-dcr-implied.sh`: 100 real records (20 each of 4624, 4672, 4688, 4798 and
5379) sent through the rule as it is and again through Sluice's transformation (15,310
characters, from `sluice analyze --sentinel-native` on the workspace's 20,154-record sample).
Each batch was checked against the emulator's run of the rule version meant for it.

| EventID | Full | With Sluice's transformation | Less |
|---|---:|---:|---:|
| 4624 (implied values only) | 1,769 bytes | 1,600 bytes | 9.6 % |
| 4672 (`EventData` and implied values) | 1,179 | 421 | 64.3 % |
| 4688 (no kind of event of the sample) | 1,006 | 1,006 | 0 % |
| 4798 (`EventData` and implied values) | 1,031 | 276 | 73.2 % |
| 5379 (implied values only) | 954 | 813 | 14.8 % |
| all 100 | 118,776 | 82,309 | 30.7 % |

- The analysis predicted 30.8 % for the rule on the sample; Azure billed 30.7 % less here.
- **The columns Sentinel shows as its own can be emptied and are then not billed:** `Activity`,
  `EventLevelName`, `Channel`, `EventSourceName`, `Keywords` and `Level` arrived empty, and the
  records cost less. This holds for records sent through the Logs Ingestion API, whose stream
  declares those columns. Whether a rule on the Azure Monitor Agent's stream sees them is not
  checked.
- `int(null)` (for `Task`, `KeyLength`) and `guid(null)` (for `LogonGuid`) empty a typed column
  in a transformation.
- `SecurityEventFull` put back every emptied implied value: 700 values in 22 columns on the 100
  records, each equal to the full record's.
- **A changed rule took five to ten minutes to apply, and so did putting it back.** Records go
  through the rule in force when Azure processes them, which can be minutes after they were
  sent: send a batch only after the rule has been in force for ten minutes, and change the rule
  again only once the batch has arrived. Earlier runs that did not wait compared two batches
  that had gone through the same version and showed no difference at all. It also shows how large the `EventData` XML is: most
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
- **A query reads those `guid` columns as `string`** (2026-10-24, the test workspace):
  `SecurityEvent | getschema` gives `LogonGuid` as `System.String`, `gettype(LogonGuid)` is
  `string`, and `case(…, toguid("…"), LogonGuid)` is refused with `SEM0525 case: return types
  are not compatible … UniqueId,StringBuffer`, while a string value works. The tables API and
  the emulator's table (built from it) say `guid`. A query Sluice writes for the table, such as
  `<Table>Full`, reads such a column with `tostring()` and gives text back.

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
and `TargetAccount` filled (`NT AUTHORITY\SYSTEM`, `DESKTOP-…\user`, `WORKGROUP\DESKTOP-…$`).
The way Microsoft's rules read them works: `split(Account, @'\')[1]` gives the name and
`AccountType == "User"` matches.

## The emulator and custom tables (2026-10-17)

- **The emulator's column names are narrower than a stream's.** `.create table` refuses
  `BadRequest_EntityNameIsNotValid` for a name with `@`, `:` or `/` (`@timestamp`, even
  bracket-quoted); letters, digits, `_`, `.`, `-` and spaces pass. A DCR stream declaration takes
  `@timestamp` (see above), so `run_transformations` loads such a column under an alias and
  rewrites `['@timestamp']` and `columnifexists('@timestamp'` in the transformation to it.
- **`now()` differs between queries.** A custom table's rule sets `TimeGenerated = now()`, so the
  records with and without Sluice's part must come from one query (`union kind=outer`, `now()`
  is fixed within a query), or every row differs in `TimeGenerated` and every alert looks
  changed.
- A transformation written before the flow's own one can empty a column the flow then renames:
  the rename keeps the emptied value.

## The emulator does not say why a query fails (2026-10-18)

Every semantic error comes back as HTTP 400 with the same text, `General_BadRequest: Request is
invalid and cannot be executed`, and a request id: a call to a function that does not exist
(`print my_parser()`) as much as a known one called wrongly (`print tostring()`), a keyword
(`print inner()`) or an aggregation outside `summarize` (`print count()`). `/v1/rest/query` and
`/v2/rest/query` answer alike (kustainer-linux, engine 1.0.9779.30528). So the emulator cannot
tell Sluice which lower-case names are KQL's own functions; a fetched workspace can, since
`sluice rules fetch sentinel` reads every function in it (ADR 0031). `.show functions` lists only
functions created in the emulator's database, and `.show plugins` the `evaluate` plugins.
