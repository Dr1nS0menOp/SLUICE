# ADR 0031: A fetched Sentinel workspace bounds its rules by the tables and functions it has

- Status: Accepted
- Date: 2026-10-18

## Context

A Sentinel rule's query names tables, and may call workspace functions whose bodies name more.
Sluice reads both to learn what each rule needs (ADR 0015). Two gaps were left:

- **Tables the workspace does not have.** Any source may be sent to a custom table (`*_CL`), and
  a data collection rule may rename its columns, so a reference to one keeps every row of every
  source (2026-10-18, review). Many rules and parsers name custom tables most workspaces never
  have: ASIM parsers union a branch per vendor (`CiscoMeraki_CL`, `Corelight_CL`, …) with
  `isfuzzy=true`, which tolerates the missing ones. Each such branch made every rule that uses
  the parser apply to every source with no row bound, which costs savings everywhere.
- **Lower-case workspace functions.** KQL's own functions are all lower case, and Sluice took a
  call with an upper-case letter for a workspace function. A lower-case one called where an
  expression may stand (`let events = my_parser();`) was taken for KQL's own. If its source was
  also missing, what it reads was not protected: fail open. A closed list of KQL's functions
  would have to be kept up to date, and the Kusto emulator cannot be asked: it answers a call to
  a function it does not know with the same `General_BadRequest` as any other mistake
  (docs/notes/sentinel-dcr.md).

The workspace itself knows both. `sluice rules fetch sentinel` already reads every function
(`savedSearches` with a `functionAlias`); the Log Analytics `tables` API lists every table the
workspace has: each Microsoft table, whether or not data came in, and each custom table that was
created (856 in the test workspace: 851 Microsoft, 5 custom).

## Decision

1. `sluice rules fetch sentinel` also writes `tables.json`, the names the `tables` API lists. If
   it cannot read them (a role without `Microsoft.OperationalInsights/workspaces/tables/read`),
   the fetch notes that in its manifest and goes on: without the list, every table counts as
   existing.
2. With `tables.json`, a reference to a table that is not in it reads nothing: no record of any
   source reaches the rule through it. The tables `--sentinel-table SOURCE=TABLE` names count as
   existing, since the analysed sources are sent there.
3. In a complete Sentinel fetch, a lower-case call that is none of the fetched functions, not
   defined with `let` in the query and not ASIM's, is KQL's own (`FetchedNames`). An upper-case
   call that is not among them still widens the rule: Microsoft's built-in parsers (`_Im_*`,
   `_ASim_*`) are no saved searches.
4. Rules read from files without a fetch have no workspace to ask. A lower-case call is read as
   KQL's own, as before, except where only a table can stand (cb035ad); the report lists the
   names it could not check in one problem (`Unchecked`) and says how to make sure: fetch, or put
   the function's source next to the rules.
5. A function whose source is missing is reported once per calling rule
   (`ProblemKind::UnknownFunction`); the report lists each function with the rules that call it,
   and shows how to give its source.

## Consequences

- Savings that rules over absent custom tables blocked come back, on fetched inventories. The
  real-data runs measure how much (docs/testing-plan.md).
- A new assumption, like the one for rules (ADR 0021): a table created after the fetch does not
  exist for Sluice. Data sent to a new custom table, or a parser branch that starts to find a
  table, is protected from the next `sluice rules fetch` and analysis on. Until then a deployed
  configuration may remove what a rule over the new table needs. Name a new destination table
  with `--sentinel-table` to count it before it exists.
- The fail-open gap for lower-case workspace functions closes for fetched inventories. For rules
  from files it stays, visible in the report.
- No list of KQL's functions to maintain.
