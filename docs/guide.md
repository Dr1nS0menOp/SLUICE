# Sluice user guide

This guide explains how Sluice decides what to cut, how to describe your data, and every command.
The [README](../README.md) is the short version, [Using Sluice](usage.md) walks through each use
case, [architecture](architecture.md) explains the parts and the technologies, and the
[ADRs](adr/) explain why things are built the way they are.

## How Sluice decides

1. **Templates.** Sluice groups events by shape. A JSON event's template is its set of field
   names plus a few discriminating values, such as `EventID=4624`. A text line's template comes
   from [Drain](notes/drain.md): `sshd Failed password for <*> from <NUM>…`. Template ids are
   hashes of that shape, so the same kind of event gets the same id every time.
2. **Recipes.** A recipe proposes reductions for a kind of event, at one of three levels:
   - **L1, lossless:** drop fields that repeat others (a rendered `Message`) or are empty.
   - **L2, rule-guided:** forward in full every event a rule could match; summarize the rest.
   - **L3, semantic:** summarize a template no rule cares about.

   Proposals come from the community recipes in [`recipes/`](../recipes/), your own recipes
   (`--recipes DIR`), or an AI model (`--llm`). None of them is trusted.
3. **Guardrails.** For each template, Sluice works out which of your rules could see it (by log
   source, and by the template's fixed values) and what each rule reads. A field a rule reads is
   never removed from an event that rule could match; such events are forwarded whole (ADR
   0009). Rare templates are never cut, and nothing is cut without an archive.
4. **Proof.** Sluice runs your rules over the sample twice (Sigma, and Microsoft Sentinel's
   analytics rules in the Kusto emulator when `--kusto` is given), on the full events and on
   what the reduced pipeline would forward. Only if both raise exactly the same alerts is a
   recipe kept; otherwise it is rolled back, per template. The proof runs the same VRL code
   Vector will run.
5. **Live.** With `sluice up`, a proven recipe waits in shadow (24 hours and 3 proofs by
   default) before Vector enforces it, and every cycle proves the enforced set again.

## Describing your sources

`sluice analyze` reads a sources file; `sluice up` reads the same entries under `sources:`.

```yaml
sources:
  - id: windows-system                 # your name for it; also the archive directory
    logsource: { product: windows, service: system, complete: true }
    format: { kind: json }             # JSON objects
  - id: linux-auth
    logsource: { product: linux, service: auth }
    format: { kind: text, field: message }   # one log line per event, in `message`
```

- `logsource` uses Sigma's attributes `product`, `service` and `category`. A rule applies to a
  source unless one of its attributes provably differs.
- An attribute you leave out counts as **unknown**, so rules that name it still apply. Add
  `complete: true` when the attributes you give are all there are. That is right for a single
  channel such as Windows System or Linux auth.log, and wrong for Sysmon or the Windows Security
  channel, onto which Sigma maps categories such as `process_creation`.
- `sluice analyze` prints a **hint** for each source where undeclared attributes keep rules in
  scope, with the number of rules involved.

## Commands

| Command | What it does |
|---------|--------------|
| `sluice demo` | Generates an hour of synthetic traffic with planted attacks and runs the whole autopilot on it. |
| `sluice analyze --input DIR --sources FILE --rules DIR` | Runs the autopilot on your sample (`DIR/<source>.ndjson`), writes `report.html` and `vector.yaml` (with Vector unit tests). `--wazuh-rules` (with `--wazuh-decoders` to bound them), `--wazuh-api` (logtest spot check), `--recipes`, `--llm` are optional. |
| `sluice up --config FILE --rules DIR` | Runs the control plane and Vector live: tap, shadow, promote, verify, roll back. `--check` validates the configuration and prints the Vector configuration instead of starting. `--wazuh-rules`, `--sentinel-rules DIR` and `--kusto URL` add the SIEMs' own rules. |
| `sluice status` | The live control plane's status: savings, proof, stage per template, recent transitions. |
| `sluice search --archive DIR [--source S] [--from T] [--to T] [--where C]…` | Prints archived events (full fidelity) as NDJSON; `--count`, `--limit`. |
| `sluice replay … --url URL` | Sends archived events to an HTTP endpoint as NDJSON. |
| `sluice connect TARGET` | Prints a destination for `sluice up`: `splunk`, `elastic`, `sentinel`, `chronicle`, `wazuh`, `http`. For `sentinel`, `--standard-table syslog\|common-security-log\|asim-network-session\|asim-dns\|asim-web-session --out DIR` writes the data collection rule for a standard table, and `--sample FILE --table NAME --out DIR` a custom table and its rule. |
| `sluice agent windows --to URL [--events-to URL] [--channel C]...` | Prints the Vector configuration for a Windows host that sends its event logs to `sluice up`; `--dcr FILE --workspace ID` also writes the Sentinel data collection rule for them. |
| `sluice mcp [--archive DIR] [--allow-replay] [--allow-actions] [--http ADDR]` | An MCP server for AI assistants, over stdio or bearer-token HTTP. `--allow-actions` offers the operator actions (ADR 0016). |
| `sluice recipes [schema \| export --out DIR]` | Lists the built-in recipes, prints their JSON Schema, or exports them to edit. |
| `sluice rules requirements --rules DIR` | Prints, as JSON, what each rule needs: log source, fields, raw text, state. Also for Wazuh (`--wazuh-rules`) and Sentinel (`--sentinel-rules`) rules. |

Conditions for `search` and `replay` are `field=value`, `field!=value` and `field~text`
(contains, ignoring case); times are RFC 3339 or a `YYYY-MM-DD` date (UTC).

## The `sluice up` configuration

```yaml
listen: 127.0.0.1:8686          # control plane API (default)
vector_binary: vector           # default: found on PATH
vector_config: /var/lib/sluice/vector.yaml
archive_dir: /var/lib/sluice/archive
data_dir: /var/lib/sluice/vector-data
tap_rate: 10                    # keep 1 in 10 events for analysis (default)
cycle_secs: 300                 # seconds between cycles (default)
window: { max_events_per_source: 20000, max_age_secs: 3600 }   # defaults
promotion: { shadow_secs: 86400, min_proofs: 3, approval: false }   # defaults; approval: true = no recipe without an operator's approval
sources:
  - id: windows-system
    logsource: { product: windows, service: system, complete: true }
    format: { kind: json }
    vector: { type: http_server, address: 0.0.0.0:9101, decoding: { codec: json } }
destinations:                   # Vector sinks; Sluice sets their inputs
  siem: { type: splunk_hec_logs, endpoint: https://splunk:8088, default_token: "SECRET[siem.splunk_hec_token]", encoding: { codec: json } }
vector_secrets:                 # Vector secret backends for destination credentials
  siem: { type: directory, path: /run/secrets/siem }   # one file per secret
```

- `vector:` is any Vector source configuration that produces JSON objects (one line of text in
  `message` for text sources).
- A destination may carry `sluice_formats: [json]` or `[text]` to take only events of those
  source formats; Sluice removes the key before Vector sees it. `sluice connect wazuh` uses this
  to write JSON sources to one file and raw text lines to another.
- A source may carry `shape` to send its records as a Sentinel table's rows, after the archive
  keeps them as they arrived: `sentinel_security_event` and `sentinel_windows_event` for Windows
  hosts running `sluice agent windows`, `sentinel_syslog` for Linux hosts and network devices
  (Vector's `syslog` source or raw lines), `sentinel_common_security_log` or
  `sentinel_asim_network_session` for firewall records (raw `filterlog` lines or parsed),
  `sentinel_asim_dns` for DNS query records, `sentinel_asim_web_session` for web server access
  logs. `sluice connect sentinel --standard-table
  syslog|common-security-log|asim-network-session|asim-dns|asim-web-session --out DIR` writes
  the data collection rule for the table.
- A destination may carry `sluice_sources: [id, …]` to take only those sources. A SIEM table
  takes one shape of record: Windows hosts running `sluice agent windows` send Sentinel
  `SecurityEvent` and `WindowsEvent` records to two sources, and each Sentinel destination names
  its own (`examples/up/sluice-windows.yaml`).
- A destination may carry `sluice_rules`: the rules its SIEM runs, any of `sigma`, `wazuh` and
  `sentinel` (Microsoft Sentinel analytics rules, loaded with `--sentinel-rules DIR`, such as a
  clone of Azure/Azure-Sentinel).
  Without it, every loaded rule set applies. Each distinct set is a *rule profile* with its own
  proof, recipes and pipeline, so a Sentinel destination is not held back by Wazuh rules that
  only the Wazuh destination runs. The archive and the tap stay one per source.
  `sluice status --profile sigma+wazuh`, the console's profile picker and the MCP `status`
  tool's `profile` parameter show each one (`GET /status?profile=sigma%2Bwazuh`;
  [ADR 0012](adr/0012-per-destination-proofs.md)).

  ```yaml
  destinations:
    sentinel: { type: azure_logs_ingestion, …, sluice_rules: [sigma] }
    wazuh:    { type: file, path: /var/log/sluice/wazuh.ndjson, encoding: { codec: json }, sluice_rules: [wazuh] }
  ```
- **Sentinel rules in the proof.** With `--kusto URL` (a Kusto emulator; `scripts/kql-check.sh`
  starts one in Docker), each cycle loads the window, full and forwarded, into the emulator as
  `SecurityEvent` and `WindowsEvent` records (from the sources' `shape`) and runs every rule's
  query on both. Any difference in the result rows fails the proof. Rules that cannot run in
  the emulator are listed at startup; without `--kusto`, their requirements still constrain
  every cut, but the proof covers Sigma and Wazuh only. Point `--sentinel-rules` at the rules
  your workspace actually runs: a rule that reads `EventData` on every event keeps it on every
  event. Include the ASIM parsers (`Parsers/ASim*/Parsers` and `ASIM/lib/functions` from
  Azure/Azure-Sentinel) in the same directory: rules that use a parser are then bounded by what
  the parser reads, instead of by every Windows table ([ADR 0015](adr/0015-sentinel-analytics-rules.md)).
- Credentials go in secret files, referenced as `SECRET[backend.key]` through `vector_secrets`
  ([ADR 0010](adr/0010-secrets-and-control-plane-access.md)). Vector 0.59 does not expand
  `${VAR}` in its configuration, so environment references do not work.
- **Control plane access.** With `SLUICE_CONTROL_TOKEN` set (at least 32 characters), every
  route but `/healthz` needs `Authorization: Bearer <token>`; `sluice status` and `sluice mcp`
  send it from the same variable. Without a token, `sluice up` only listens on loopback.
- The archive is gzip NDJSON per source and UTC hour; nothing in it is ever reduced.

## Operator actions

The console's template page, and `POST /actions` with a JSON body, let an operator steer Sluice
for one rule profile ([ADR 0016](adr/0016-operator-actions.md)):

| Action | Body | Effect |
|---|---|---|
| Hold | `{"action": "hold", "template": "…"}` | The template is forwarded unchanged until released; its recipe stops now. |
| Release | `{"action": "release", "template": "…"}` | Ends a hold; the recipe starts over in shadow. |
| Approve | `{"action": "approve", "template": "…"}` | A recipe in shadow is enforced at its next proof. Required for every recipe with `promotion.approval: true`. |
| Keep / unkeep | `{"action": "keep", "source": "…", "field": "…"}` | The field is never removed from that source's events. |
| Acknowledge | `{"action": "acknowledge", "template": "…", "at": 1791742558}` | Marks a rollback as seen. |

Add `"profile"` for a profile other than the first, and `"reason"` for the audit log. To have
the audit log name people, give each operator their own token in `operators_file` (in the
`sluice up` configuration): a file of `name token` lines, tokens of at least 32 characters, only
readable by its owner (`chmod 600`). Each operator then signs in to the console, or calls the API,
with their own token.

For single sign-on with your organization's identity provider (Entra ID, Keycloak, Authentik,
Google, any OIDC provider), register Sluice as a client with the redirect URL
`https://<console>/auth/callback` and add:

```yaml
oidc:
  issuer: https://login.microsoftonline.com/<tenant>/v2.0   # exactly as the provider states it
  client_id: <client id>
  client_secret_file: /run/secrets/sluice/oidc_client_secret # only for confidential clients
  redirect_url: https://sluice.example.org/auth/callback
  name_claim: email                                          # or preferred_username
  operators: [alice@example.org, bob@example.org]            # who may sign in
```

The console then offers **Sign in with single sign-on**. `SLUICE_CONTROL_TOKEN` stays required:
Vector uses it for the tap. Details and caveats: [notes/oidc.md](notes/oidc.md). Every
action goes into the profile's history and into `audit.ndjson` in the data directory; holds and
kept fields are stored in `operator.json` there and survive a restart. None of them can weaken
the safety contract: holds and kept fields only add protection, and an approved recipe still has
to pass the proof on the cycle it is enforced in.

```sh
curl -X POST http://127.0.0.1:8686/actions -H "Authorization: Bearer $SLUICE_CONTROL_TOKEN" \
  -H 'Content-Type: application/json' -d '{"action":"hold","template":"dns:8570167c963a","reason":"IR"}'
```

## Why is nothing cut?

The report lists, per template, every reduction that was refused or narrowed, and why. The
common reasons:

- **"no recipe"**: no community or own recipe matches the template. Write one
  ([recipes/README.md](../recipes/README.md)) or use `--llm`.
- **"rare … so never cut"**: the template has fewer than 100 events, or less than 0.1 % of its
  source, in the sample. A larger sample or a longer live window fixes this.
- **"may read any field"** or **"could match any event"**: a rule whose fields or matches cannot
  be bounded (an unparsable rule, or a keyword search Sluice cannot narrow) applies to the
  template. Check the **hints**: often the rule only applies because the source's log source is
  incomplete.
- **"kept: … rule tests could apply"**: so many rules apply that testing them per event would
  cost more than it saves. Describing the source more precisely reduces the number.
