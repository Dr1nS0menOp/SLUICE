# ADR 0021: The rule inventory comes from the SIEM, and only a complete one allows L2 and L3

- Status: Accepted
- Date: 2026-10-13

## Context

Everything Sluice protects, it protects because a rule says so. Until now the rules came from
directories the operator pointed at (`--rules`, `--wazuh-rules`, `--sentinel-rules`), and a
destination's `sluice_rules` defaulted to every loaded set. That treats "loaded" as "complete".
The review of 2026-10-11 (PLAN.md) named the consequence: a rule Sluice was not given does not
exist for it. A rule-guided or semantic cut (L2, L3) forwards only what the known rules could
match, so a missing rule is a missed detection. A lossless cut (L1) drops only fields no known
rule reads, so it fails the same way but costs much less when it does: the event still arrives.

A SIEM runs more than its analytics rules. Sentinel also has hunting queries, workspace
functions that rules call, workbooks and whatever people type into Logs; a dashboard that counts
events breaks when events become summaries, even though no alert changes.

## Decision

1. **`sluice rules fetch` reads the inventory from the SIEM, read-only**, into a directory the
   existing loaders read, plus an `inventory.json` manifest (system, where from, when, counts,
   and what could not be modeled):
   - `sentinel --workspace RESOURCE_ID`: enabled `Scheduled` and `NRT` analytics rules
     (`Microsoft.SecurityInsights/alertRules`), hunting queries and workspace functions
     (`savedSearches`; a function is written as `FunctionName`/`FunctionQuery`, so rules that
     call it read what it reads), and with `--queries-days N` the distinct queries people ran
     (`LAQueryLogs`), each as a rule whose result must not change. Credentials come from the
     environment (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`), never from flags.
   - `wazuh --api URL --user USER`: the enabled rule and decoder files (`/rules/files`,
     `/decoders/files`, raw), exactly as the manager loads them.
   - Rule kinds without a query cannot be bounded. `Fusion` and
     `MicrosoftSecurityIncidentCreation` correlate alerts, not records, and are listed in the
     manifest as such. `MLBehaviorAnalytics` and `ThreatIntelligence` read records in ways that
     are not published; each becomes a rule that may read anything (fail closed).
2. **A destination's rules are complete only when said so.** A rule set is complete when its
   directory holds an `inventory.json` from `sluice rules fetch` or when the operator claims it:
   `--rules-complete` for `sluice analyze`, `rules_complete: true` on a destination of
   `sluice up`. Sigma rules have no SIEM API of their own, so for them it is always a claim.
3. **Without a complete inventory, no L2 or L3.** The guardrails refuse rule-guided forwarding
   and summaries with `Reason::RulesNotComplete` (contract rule 3) and keep L1. The report shows
   how many bytes each held-back template has, so the saving a complete inventory would unlock
   is visible.
4. **Queries are rules.** Hunting queries, workspace queries from the query log and workbook
   queries go through the same KQL extractor and the same emulator proof as analytics rules:
   "same alerts" becomes "same rows". A query that counts events keeps them forwarded, because
   its pre-filter covers them; a query Sluice cannot bound blocks cuts in its scope.

## Consequences

- `sluice analyze` without `--rules-complete` saves less than before: L1 only. That is the
  honest default, and the hint names the flag. `sluice demo` runs on its own synthetic rules,
  which are complete by construction.
- A Sentinel workspace can be guarded by exactly what it runs, refreshed by fetching again; a
  new rule protects its data from the next analysis on.
- Fetching is read-only: the service principal needs Microsoft Sentinel Reader (or Reader) on
  the workspace and, for the query log, Log Analytics Reader with `LAQueryLogs` enabled.
- Splunk, Elastic, Chronicle and QRadar inventories follow with their query languages (M12);
  until then their destinations need the operator's claim for L2 and L3.
- Tests named after contract rule 3 cover the gate (`sluice-core` guard tests), the manifests
  and the fetchers against recorded API responses (`sluice-cli`, `sluice-wazuh`).
