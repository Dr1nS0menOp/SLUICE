# ADR 0015: Sentinel analytics rules as rules, proven on the Kusto engine

- Status: Proposed
- Date: 2026-10-11

## Context

Sluice proves reductions against Sigma rules. For a Sentinel destination that is a proxy: the
SIEM runs its own analytics rules in KQL. The proxy breaks exactly where the money is. In a real
workspace (docs/notes/sentinel-dcr.md) the `EventData` XML is about 80% of a `SecurityEvent`
record, no Sigma rule reads it, and yet Microsoft's own rules do.

A scan of Microsoft's rules (Azure/Azure-Sentinel, MIT, commit `55296e6`, 2026-10-09; 2,452
rules with a query) found 103 rules on `SecurityEvent` and 39 on `WindowsEvent`. 74 of the
`SecurityEvent` rules read `EventData`, mostly to parse fields that have no column; 71 of those
first filter on specific `EventID`s (56 distinct ones, such as 4624, 4688, 4662, 5136), and 3 do
not. 63 rules call ASIM parsers, which read the tables indirectly.

## Decision

1. **Rule requirements from KQL, superset as always.** A `sluice-rules` adapter reads
   analytics rule files (`query`, `requiredDataConnectors`, table names) into
   `RuleRequirements`:
   - **Log source:** the tables a query reads, mapped to the sources whose `shape` produces
     them (`SecurityEvent` ↔ `sentinel_security_event`).
   - **Fields:** every identifier in the query that names a column of a table it reads, plus
     `EventData` and its dynamic paths; `search`, `union *`, `pack_all()`, unresolved functions
     (ASIM parsers until their source is read too) and anything not understood make the fields
     unknown.
   - **Pre-filter:** for each reference to a table, the first `where` after it, parsed into
     `and`/`or` over `EventID == N` / `EventID in (…)`. Every other condition is `true`, and a
     reference without such a `where` is unbounded. Rows a reference's first `where` drops
     never reach the rest of the query, so this is a superset of the rows the rule can see.
   - **Stateful:** `summarize`, `join`, `make-series` and time windows (rules are evaluated
     over a lookback period), so ADR 0004's routing rules apply.
2. **The proof runs the real rules.** Where the Kusto emulator is available (ADR 0013), the
   proof for a Sentinel profile loads the window as the destination tables (full, then
   forwarded) and runs each analytics rule's query on both. Same rows out means no detection
   changed, decided by Microsoft's engine and Microsoft's rules. Without the emulator, the
   guardrails above still hold and the profile states that its proof covered Sigma only.
3. **No rule content in the repo.** As with SigmaHQ, `sluice rules fetch sentinel` clones the
   rules into a user cache; operators add their own workspace's rules the same way.

## Consequences

- A Sentinel destination can be proven against what Sentinel actually runs, which no Sigma
  translation can promise.
- With the requirements in place, a recipe may drop `EventData` from `SecurityEvent` for event
  types no applicable rule parses it for; on the real sample that is three of the four event
  types (all but 4624).
- KQL parsing is approximate by design; every approximation widens. The emulator proof is what
  catches a wrong extraction.
- The emulator runs a rule's query over the sample, not over the rule's real lookback; rules
  that need days of history are checked on the window Sluice has, like Sigma correlations.

## Steps

1. Requirements extraction with unit tests on real rule shapes, and a coverage report over the
   fetched rules (how many get bounded pre-filters and known fields). **Done 2026-10-11**:
   `sluice_rules::SentinelRules`, `sluice rules requirements --sentinel-rules DIR`. On the
   2,454 rules with a query, 105 read `SecurityEvent` or `WindowsEvent`: 89 get an `EventID`
   pre-filter, 103 known fields (2 call functions whose body is not known), 59 are stateful, and
   75 read `EventData`, 14 of those with an unbounded pre-filter (`let` lists and `union`s are
   not resolved yet).
2. The emulator proof for a Sentinel profile. Spike 2026-10-11: the Kusto emulator, given
   `SecurityEvent` with the real workspace schema and the 154 real Security events, ran 73 of
   Microsoft's 103 `SecurityEvent` rules; dropping `EventData` from every event type but 4624
   (27% of the bytes) changed no rule's output. None of the rules returned rows on that benign
   sample, so the comparison is trivial until the sample holds events the rules fire on:
   planted, as the demo does for Sigma. **Done 2026-10-11**: `sluice_kql::KustoEngine` loads
   each evaluation into a fresh volatile database with the real table names and column types,
   and turns every result row into an alert identified by its content, so a changed column in a
   rule's output fails the proof as surely as a missing row. Rules that fail on empty tables are
   set aside and listed. `sluice up --sentinel-rules DIR --kusto URL` adds the rule set
   `sentinel` that destinations name in `sluice_rules`; its engine joins the proof
   (`sluice_core::alert::Engines`). The env-gated test `crates/sluice-kql/tests/rules.rs` shows
   the proof catching a dropped column a rule groups by, a dropped `EventData` a rule parses,
   and a summarized event that brings a count under its threshold, while passing a drop no rule
   reads. On the real sample, 91 of the 105 rules ran, and two planted events fired two of
   Microsoft's rules on the forwarded records (docs/notes/sentinel-dcr.md).
3. ASIM parsers: read their source, or keep their callers unknown. **Fail-closed part done
   2026-10-11**: a rule that reads an ASIM parser (`imProcessCreate`, `_Im_Dns(…)`, `ASimDns`,
   `_ASim_RegistryEvent`, with or without parentheses) or calls a workspace function now
   applies to every Windows source, with unknown fields and no pre-filter. Before, such a rule
   named no Windows table and counted as a rule on other tables, so the fields it reads through
   the parser were not protected (fail open). `_GetWatchlist` reads a watchlist only, and
   `ASim…Logs` names are tables. On the whole repository 247 rules now apply to Windows sources
   (105 before), 146 of them with unknown fields, so nothing is cut there; the "Windows
   Security Events" solution is unaffected. **Resolution done the same day**: parser files
   (`Parsers/ASim*/Parsers/*.yaml`: `ParserName`, `EquivalentBuiltInParser`, `ParserQuery`) and
   ASIM helpers (`ASIM/lib/functions/*.yaml`: `FunctionName`, `EquivalentBuiltInFunction`,
   `FunctionQuery`) among the rule files are read as functions, and a rule reads what the
   functions it uses read, resolved recursively (an unknown or recursive one stays fail
   closed). Getting there needed more of KQL: names a query assigns itself (`let`, `extend
   X = …`) are not parsers, `ASimMatching…` names are output fields, `let` lists of `EventID`
   literals resolve, a lambda's tabular parameter named `SecurityEvent` is not the table,
   `where`s after projections and `extend`s that leave the filtered columns alone still
   filter, and columns named as strings (`column_ifexists('X', …)`, `['X']`) are read. On the
   whole repository with its parsers: 186 rules apply to Windows sources, 143 with a bounded
   pre-filter, 21 with unknown fields (unknown helpers and workspace functions), and 21 read
   `EventData` without a bound (most match threat intelligence against every event).
4. Recipes for `SecurityEvent` and `WindowsEvent` that this makes safe (`EventData` per
   event type). Started 2026-10-11: recipes drop `EventData` for 4672 and 4798, whose every
   named data item has its own column (checked on real events; for 4624 and 5379 it does not
   hold, so they get no such recipe). The extraction now reads `EventID`s written as strings
   (`== '4656'`, `in ("4723")`, `in~`), which KQL converts to `int` (checked in the emulator):
   rules reading `EventData` without an `EventID` bound went from 14 to 5, and those 5 really
   read it on every event (threat-intelligence matching, AD FS, auditpol). Rule files with
   several YAML documents are read per document; before, five such files in Azure/Azure-Sentinel
   became rules that may read anything and blocked every cut; many files there also start
   with a byte order mark, which the multi-document reader does not skip. Equality on
   `EventSourceName`, `Channel` and `Provider` bounds a reference too (only those columns: the
   same shape on a `let` variable is not a test on the record). End to end on the real sample
   with the rules of the "Windows Security Events" solution and SigmaHQ: `EventData` was
   dropped from 4672 (enforced, 43% of its bytes) and 4798, 11% of the window, with the same
   alerts in the emulator. With every Microsoft rule loaded, rules that read `EventData` on any
   event keep it everywhere, as they should: point `--sentinel-rules` at the rules the
   workspace runs.
5. Other shaped tables. **`Syslog` done 2026-10-11**: a `Syslog` reference is bounded to records
   that have `SyslogMessage` (every `sentinel_syslog` record does, no other shape does), and its
   rules apply to every product, since a Linux host and a firewall both send syslog. A rule that
   may read any table (an unknown function, `search`, `union *`) applies to every product too,
   bounded to records of the shapes Sluice sends to Sentinel (`EventID`, `Channel` or
   `SyslogMessage` present). Rules on Windows tables only keep `product: windows`.
   **`CommonSecurityLog` the same day**, bounded by `DeviceVendor`, which the shape always sets,
   **`ASimNetworkSessionLogs`**, bounded by `EventSchemaVersion`, and **`ASimDnsActivityLogs`**,
   bounded by `DnsQuery`, and **`ASimWebSessionLogs`**, bounded by `Url`. Every ASIM record has
   `EventSchemaVersion`, so network session rules also apply to DNS and web records: a superset,
   sound but less precise. Authentication and process events get no table of their own:
   Microsoft's ASIM parsers already read them from `Syslog` (`ASimAuthenticationSshd`),
   `SecurityEvent` and Sysmon's `WindowsEvent`, so a second copy would only duplicate data.
6. **Custom tables (`<Name>_CL`), 2026-10-17.** `sluice connect sentinel --sample` sends any
   JSON source to a custom table, so a rule on one applies to every product, reads the columns
   it names, and may match any row: a data collection rule may rename columns, so a `where` on
   them bounds no record. Before, such a rule counted as a rule on other tables, which no
   source has, and the fields it reads were not protected. Other tables Azure fills itself
   (`SigninLogs`, `AuditLogs`) stay rules on other tables. A column the table's rule renamed
   (`sluice connect` writes `user_agent` for `user-agent`, `F_timestamp` for `@timestamp`,
   `ProcessId2` for a second `ProcessId`) protects the names it may come from as well: `_`
   read as `-`, `.`, ` `, `@`, `:` or `/`, without a leading `F` or a trailing number. A name
   that mixes those characters (`a-b.c`) is not covered; with `--kusto` the proof covers it, as
   the emulator holds the table as the rule fills it. Columns of the retired HTTP Data
   Collector API (`name_s`, flattened nested names) are not mapped back to the record.
