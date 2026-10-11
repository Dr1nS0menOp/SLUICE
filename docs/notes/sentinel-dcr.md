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

## Billing

Not verified yet: whether an empty string or null column costs ingestion. The Log Analytics
`_BilledSize` of a record with emptied columns has to be measured in a real workspace before
Sluice reports native savings as anything but an estimate.
