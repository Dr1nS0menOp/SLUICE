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

## Known limit: Wazuh rules carry no log source

Wazuh rules carry no Sigma-style log source, so every Wazuh rule applies to every source. A rule
is scoped per template by its pre-filter instead (ADR 0009), which these sharpen:

- **Decoders** (`--wazuh-decoders`): `<decoded_as>sshd</decoded_as>` becomes a keyword test for
  the decoder's `program_name` literals (`^sshd`, `^apache2|^httpd`), inherited through
  `<parent>`. A `prematch` that starts with a literal of two or more characters (`^ossec: `,
  `^SU \S+`) bounds the same way. A decoder bounds only if *every* definition of that name
  does: the stock `su` decoder has two (`program_name ^su$` and `prematch ^SU`). A decoder
  that selects by a regex or a plugin (JSON, Windows eventchannel) bounds nothing.
- **`<category>`** is the decoder `<type>`: bounded by the union of all decoders of that type.
- **`<if_sid>` chains**: a child's pre-filter is its own conditions and any parent's; it also
  takes its parents' fields, raw-text use and statefulness. A missing or cyclic parent adds
  nothing.

**Measured on the stock ruleset (Wazuh 4.14.8, 4,654 rules, 2026-10-10):** decoders and chains
bound 1,051 more rules, but 2,799 stay unbounded, mostly Windows rule chains rooted in
`<category>windows</category>` or the eventchannel decoder, and `if_group` chains. An unbounded
rule applies to every template, so with the full stock ruleset loaded Sluice reduces nothing:
the fail-closed outcome. Bounding those needs knowledge of which log formats reach Wazuh (the
eventchannel format never comes through Sluice), which is a deployment fact rather than a rule
fact; it is left open on purpose.

- **`<if_fts/>`** ("first time seen") is stateful and reads the union of every decoder's `<fts>`
  names (stock: `srcip`, `user`, `id`, `extra_data`, `srcuser`, `system_name`, `dstip`; `name`
  and `location` are not body fields, `hostname`/`program_name` mean raw text). Its history only
  takes events that passed the rule's other conditions, so ADR 0004 applies. Without decoder
  files it stays "reads every field".

**After prematch, category and `if_fts` (same ruleset):** 657 rules stay unbounded, and none
reads unknown fields any more. Real Windows plus Linux data with SigmaHQ and the stock Wazuh
ruleset: 0.1% saved, 206 = 206 alerts.

**JSON lines never reach syslog decoders** (verified with `logtest`, Wazuh 4.14.8, 2026-10-10).
A JSON line gets no pre-decoding (empty `predecoder`, so no program name) and the `json` decoder,
with `log_format` `json` and also `syslog`, even when a field holds a full `sshd`/`pam`/`su` line.
So a rule whose decoder tests `program_name`, or anchors its `prematch` on a letter or `\(` (a
JSON line starts with `{`), never sees a JSON event: `RuleRequirements::text_lines_only`, inherited
through decoder `<parent>` and rule `<if_sid>` (every parent must have it). The guard skips such
rules for JSON (key-set) templates and keeps them for every text template, because Wazuh may
recognise headers Sluice's discovery does not. Stock ruleset: 427+ rules. Raw-text rules
without such a decoder (1002 "bad words" fired on a JSON line in the same probe) still protect
the whole line.

**Result:** real Windows plus Linux data, SigmaHQ plus the stock Wazuh ruleset: 1.3% saved,
206 = 206 alerts. The rest is held by raw-text rules without a decoder bound and the cost cap.

## Lenient rule files

The stock rule files are not strict XML: `<regex>` holds `</\/\w+\>` and bare `&&`, which a
strict parser rejects. Sluice reads them as Wazuh does, escaping `<` that does not start markup
and `&` that does not start an entity. A file that still cannot be read becomes one opaque rule
(it may read anything, everywhere) and is reported; before, one such file stopped the load.

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

## Live run against Wazuh 4.14.8 (2026-10-10)

Verified on a real manager (all-in-one 4.14.8) through `PUT /logtest` with the `wazuh-wui` API
user:

- **`alert` is the level gate, not "a rule matched".** A rule with level 0 still appears in
  `output.rule` (for example 5521 for a cron PAM session) but `data.alert` is `false`. Sluice
  counts only `alert: true`, which matches what the manager would write to `alerts.json`.
- **Text sources must be sent as the raw line with `log_format: syslog`.** Pre-decoding then
  finds `program_name`, `hostname` and `timestamp`, and the `sshd`/`pam` decoders and rules run
  (a synthetic `Failed password` line fired rule 5760). Wrapped in JSON the same line matches
  nothing. `EventRules::fired_line` exists for this.
- **Windows events sent as JSON match no Windows rule,** not even in the agent's
  `win.system`/`win.eventdata` shape: the Windows ruleset hangs off the `eventchannel` log format
  of the agent. A logtest spot check of JSON Windows events against Wazuh therefore proves
  nothing, and Windows data reduced by Sluice should reach Wazuh through the agent, not as a JSON
  `localfile`.
- Result on the demo sample (scale 40): only the two cron-session templates are reduced
  (summarized); every sampled original was a level-0 match, so Wazuh agrees no alert is lost.
  The `sshd` templates are forwarded unchanged and need no check. `sluice analyze` reports the
  number of checked events that fired a rule, so an all-quiet check is visible as such.
- **Delivery** (verified end to end the same day): `sluice connect wazuh` emits two file
  destinations. `sluice_formats: [json]` takes JSON sources and all summary records; the
  `_lines` one takes text sources with Vector's `text` codec, which writes the `message` field,
  so the file holds the original syslog lines. Read them with `log_format: json` and
  `log_format: syslog` respectively. A `Failed password` line written by `sluice up` that way
  fired rule 5710 in logtest. `sluice up` refuses a text destination when a text source keeps
  its line outside `message`.
