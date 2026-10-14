# Rule inventory APIs (ADR 0021)

Verified 2026-10-14. `sluice rules fetch` uses only the calls below, all read-only.

## Microsoft Sentinel

Verified against the test workspace (`rg-sluice-test`/`sluice-test`) with a service principal
using the client credentials flow
(`POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`, form-encoded,
`scope=https://management.azure.com/.default`).

- **Analytics rules:** `GET {workspace}/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-09-01`.
  `2025-06-01` answers the same shape. Each item has `name` (the rule's GUID), `kind`
  (`Scheduled`, `NRT`, `Fusion`, `MicrosoftSecurityIncidentCreation`, `MLBehaviorAnalytics`,
  `ThreatIntelligence`, …) and `properties` (`displayName`, `enabled`, and `query` for
  `Scheduled` and `NRT`). A fresh Sentinel workspace has one rule: `Fusion` ("Advanced
  Multistage Attack Detection"), enabled, without a query. Lists page with `nextLink`.
- **Saved searches:** `GET {workspace}/savedSearches?api-version=2020-08-01`. A fresh
  workspace carries 39 example searches (category `Log Management` and others) that nobody
  runs, which is why only `Hunting Queries` and functions are read by default. A function has
  `properties.functionAlias`; its `query` is the body.
- **Creating test content** (how the test workspace was seeded): `PUT
  .../alertRules/{guid}?api-version=2024-09-01` with `kind: Scheduled` returns 201;
  `PUT .../savedSearches/{id}?api-version=2020-08-01` returns 200.
- **Query log:** `GET {workspace}?api-version=2022-10-01` gives `properties.customerId`; then
  `POST https://api.loganalytics.io/v1/workspaces/{customerId}/query` with a token for
  `https://api.loganalytics.io/.default` and `{"query": "LAQueryLogs | …"}`. The answer is
  `tables[0].columns` and `tables[0].rows`. On the test workspace, without query auditing
  configured, the query succeeded with no rows: an empty log does not fail, so `sluice rules
  fetch` says so in the manifest.

## Wazuh

Verified against the Wazuh 4.x manager of the homelab (user `wazuh-wui`) and the 4.12 OpenAPI
spec:

- `GET /rules/files?status=enabled&limit=500&offset=N` and `GET /decoders/files?…` list
  `data.affected_items[]` with `filename`, `relative_dirname` (`ruleset/rules`, `etc/rules`,
  …) and `status`; `data.total_affected_items` is the total for paging.
- `GET /rules/files/{filename}?raw=true&relative_dirname=ruleset%2Frules` returns the file as
  plain text. Errors still come back as JSON with an `error` field.
- That manager loads 168 rule files and 121 decoder files.
