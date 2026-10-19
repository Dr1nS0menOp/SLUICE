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
- **Fusion reads alerts, not records.** Every scenario in Microsoft's Fusion scenario reference
  (checked 2026-10-14, page updated 2026-05-14) lists alert sources only: Microsoft Entra ID
  Protection, Defender for Cloud Apps, Defender for Endpoint, Defender for Cloud and "Microsoft
  Sentinel (scheduled analytics rule)". Scenarios that name Palo Alto VPN or Cisco firewall
  logs consume the alerts of scheduled rules on those logs, and those rules are in the fetched
  inventory themselves. So `sluice rules fetch` lists Fusion as reading no records.
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
- **Tables** (2026-10-18): `GET {workspace}/tables?api-version=2022-10-01` lists every table
  the workspace has, in one page: 856 on the test workspace, 851 with
  `properties.schema.tableType` `Microsoft` (every standard table, whether or not data came in:
  `SecurityEvent`, `Syslog`, `CommonSecurityLog`, `ASimDnsActivityLogs`, `SigninLogs`) and 5
  `CustomLog` (the `_CL` tables that were created). `properties.plan` is `Analytics`, or
  `Auxiliary` for the archive table. A custom table nobody created (`CiscoMeraki_CL`) is not
  listed, which is what ADR 0031 relies on. The test app read them with the role it has on the
  workspace; the action is `Microsoft.OperationalInsights/workspaces/tables/read`.

## Wazuh

Verified against the Wazuh 4.x manager of the homelab (user `wazuh-wui`) and the 4.12 OpenAPI
spec:

- `GET /rules/files?status=enabled&limit=500&offset=N` and `GET /decoders/files?…` list
  `data.affected_items[]` with `filename`, `relative_dirname` (`ruleset/rules`, `etc/rules`,
  …) and `status`; `data.total_affected_items` is the total for paging.
- `GET /rules/files/{filename}?raw=true&relative_dirname=ruleset%2Frules` returns the file as
  plain text. Errors still come back as JSON with an `error` field.
- That manager loads 168 rule files and 121 decoder files.

A read-only user, verified 2026-10-19 against `wazuh/wazuh-manager:4.14.0` (the README's steps):

- `POST /security/users` creates the user (the password needs upper and lower case, a digit and
  a symbol); `POST /security/users/{id}/roles?role_ids=…` gives it roles.
- The stock role `readonly` (id 2) reads the rule and decoder files. It cannot run `logtest`,
  restart the manager or change users (403).
- `logtest:run` is in the stock policy `logtest_all_logtest` (id 33, resources `*:*:*`), which
  only `administrator` holds. Creating a policy with the same body answers 4009 ("already
  exists"), so a role of one's own links that one: `POST /security/roles/{id}/policies?policy_ids=33`.
- A change to a user's roles revokes the tokens issued in that second: a fetch right after it
  answered 401 "Invalid token". A token taken a second later works.
- The API allows 300 requests a minute by default (`max_request_per_minute`), and answers 429
  beyond them. A fetch of the stock ruleset takes 292 requests (one per file, the listings and
  the login), so a second fetch within the minute ran into the limit. The fetch now waits a
  minute and sends the request again, up to three times; the first of two fetches in a row took
  64 s, the second 4 s.
