# Wazuh rules: how Sluice reads them

These notes cover `crates/sluice-rules/src/wazuh/` and were written on 2026-10-09.

## Assumption: JSON in, same names out

Sluice forwards JSON to Wazuh. Wazuh's JSON decoder exposes keys under their dotted names, so
`<field name="a.b">` and static fields such as `<srcip>` and `<user>` refer to event fields of the
same name. If a deployment decodes differently (for example agent `eventchannel` data under
`win.eventdata.*`), the rules must be written against those names, or a field mapping has to be
added. That mapping isn't built yet.

## How tags map to requirements

| Tag | Requirement |
|---|---|
| `<field name>`, static fields | Field is read. A plain literal value becomes a case-insensitive "contains" test; anything else widens to `Always`. |
| `<match>`, `<regex>`, `<program_name>`, `<hostname>` | Raw text is read; `Always`. |
| `frequency`/`timeframe`, `<if_matched_*>`, `<same_*>`/`<different_*>` | The rule is stateful. Compared body fields are read. |
| `<if_sid>`, `<decoded_as>`, `<group>`, `<description>`, … | Neutral. Ignoring a scope only widens. |
| Any other tag | Every field is read, raw text is read, the condition is `Always`, and a problem is reported. |

A "plain literal" contains only letters, digits, space, `_-:@,`. Every `OS_Regex`/`OS_Match`
operator, including `.`, `\`, `|`, `^`, `$` and `!`, disqualifies a value, so "contains" is
always a superset of what Wazuh matches.

## Known limit: Wazuh rules are unscoped

Wazuh rules carry no Sigma-style log source, so every Wazuh rule applies to every template. A
single stateful or raw-text Wazuh rule therefore blocks L2 (rule-guided) reduction everywhere.
That is safe, but it costs savings. Planned improvement, in the guardrails and for every engine:

- A rule applies to a template only if its pre-filter can be satisfied on that template's fields.
  A rule that requires `EventID` cannot fire on DNS logs.
- For Wazuh, follow `<if_sid>` chains, so a child inherits its parent's scope.

## Verification with `logtest` (crates/sluice-wazuh)

`sluice analyze --wazuh-api https://manager:55000 --wazuh-user <user> [--wazuh-insecure]` (password
in `WAZUH_API_PASSWORD`) spot-checks the selected recipes against the manager's real decoders and
rules:

- For every template with an enforced recipe, up to 5 forwarded and 5 summarized events are sent
  to `PUT /logtest` as JSON (`log_format: json`, `location: sluice`).
- A forwarded event must fire the same alerting rule as its original. A summarized event must
  fire none.
- Any difference rolls back that template's recipe (`Reason::StatelessRulesChanged`, contract
  rule 5), and the Sigma proof is re-run.

**API facts** (from the Wazuh 4.12 OpenAPI spec, verified 2026-10-09):

- **Authentication:** `POST /security/user/authenticate` with basic auth returns `data.token` (a
  JWT, valid 900 s).
- **Request:** `PUT /logtest` with body `{event, log_format, location, token?}`.
- **Response:** `data.{token, output.rule.{id, level}, alert, codemsg, messages}`. Only
  `alert: true` counts. `rule.id` is a number in the spec example and a string in live
  responses, and both are handled.
- **Ending a session:** `DELETE /logtest/sessions/{token}`.
- **Wazuh 5:** the `main` branch spec no longer contains `/logtest`, so this targets 4.x.
- **State:** `logtest` keeps no frequency state, so stateful rules aren't exercised.

**Not yet run live.** No API credentials or SSH keys are available on the development machine.
Ward's Wazuh (192.168.1.9) uses `wazuh-logtest` over SSH; the API password is in the homelab sops
file.
