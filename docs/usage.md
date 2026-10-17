# Using Sluice

This page walks through what you can do with Sluice, from a first look to running it in front of
your SIEM. Each section is a complete path you can follow. For every command and setting, see
the [user guide](guide.md); for how it works inside, see [architecture](architecture.md).

Sluice runs on Linux (x86_64, aarch64), including WSL2. Everything below assumes the `sluice`
binary is on your `PATH`, and for live use, Vector 0.59 (`scripts/install-vector.sh`).

## 1. See it work in two minutes

```sh
sluice demo --scale 100
```

The demo generates an hour of traffic from a small company network: Windows Security, Sysmon,
Linux auth, a firewall, DNS and nginx, with six planted attacks. It then runs the whole
autopilot with example Sigma rules and prints what it would save and whether every alert
survived:

```
80,536 events from 6 sources, 29 templates
  ingest  121.0 MB → 29.8 MB  (75.3% saved, 44,562 events summarized)
  proof   41 alerts on full data, 41 on forwarded data  ✓ no detection changed
```

Open `out/report.html` to see, per kind of event, what was cut, what was kept and why.
`out/vector.yaml` is the pipeline that would do it.

## 2. Find out what you would save on your own logs

You need an hour or a day of your logs, and the rules your SIEM runs. Nothing is sent anywhere.

1. **Export a sample** per source as NDJSON (one JSON object per line), for example
   `samples/windows-security.ndjson` and `samples/firewall.ndjson`. Text logs go one line per
   event in a `message` field.
2. **Describe the sources** in `sources.yaml`, with the Sigma log source of each. Be as precise
   as you can, since anything left out counts as unknown and keeps more rules in scope:

   ```yaml
   sources:
     - id: windows-security
       logsource: { product: windows, service: security }
       format: { kind: json }
       schema: sigma
     - id: firewall
       logsource: { product: opnsense, service: filterlog }
       format: { kind: json }
       schema: sigma
   ```

   `schema` says which field names the records use. Say `sigma` when they carry the names your
   Sigma rules use, as Windows event logs do. Without it Sluice cuts nothing a Sigma rule could
   read from that source, because it cannot tell whether the rule's `Image` is the record's
   `process.executable` ([guide](guide.md#field-names)). For records in another convention, such
   as ECS, declare it (`schema: ecs`) and give the pySigma pipeline your SIEM converts Sigma
   with: `--sigma-pipeline ecs=ecs_windows`.

3. **Point Sluice at your rules.** Sigma rules (for example a clone of SigmaHQ), and if you use
   them, your Wazuh rules and decoders:

   ```sh
   sluice analyze --input samples/ --sources sources.yaml --rules sigma/rules \
     --wazuh-rules wazuh/rules --wazuh-decoders wazuh/decoders
   ```

   Sluice only summarizes events (L2, L3) when the rules are **every** rule and query your SIEM
   runs: a rule it was not given could match what it summarizes. Read them from the SIEM, or
   say they are complete:

   ```sh
   # Wazuh: the rule and decoder files the manager loads (password in WAZUH_API_PASSWORD)
   sluice rules fetch --out inventory/wazuh wazuh --api https://manager:55000 --user reader
   # Sentinel: enabled analytics rules, hunting queries and functions
   # (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET; Microsoft Sentinel Reader)
   sluice rules fetch --out inventory/sentinel sentinel \
     --workspace /subscriptions/…/resourceGroups/…/providers/Microsoft.OperationalInsights/workspaces/…
   # Elastic Security: the detection rules of a Kibana space (KIBANA_API_KEY, or KIBANA_USER
   # and KIBANA_PASSWORD)
   sluice rules fetch --out inventory/elastic elastic --kibana https://kibana:5601
   # Splunk: the saved searches and macros of every app (SPLUNK_TOKEN, or SPLUNK_USER and
   # SPLUNK_PASSWORD)
   sluice rules fetch --out inventory/splunk splunk --api https://splunk:8089
   ```

   Then pass `--wazuh-rules inventory/wazuh/rules --wazuh-decoders inventory/wazuh/decoders`,
   `--sentinel-rules inventory/sentinel`, `--elastic-rules inventory/elastic` (with
   `--elasticsearch URL` the proof runs them too) or `--splunk-rules inventory/splunk`. Sigma rules have no SIEM API to read them from: pass
   `--rules-complete` when the directory holds every Sigma rule your SIEM runs. Without either,
   Sluice makes lossless cuts only and says so (ADR 0021).

4. **Read the report.** `report.html` shows the saving per source and template, the proof, and
   for every template that was not cut the reason (a rule reads that field, the template is rare,
   no recipe matches). `sluice analyze` also prints hints when a vague source description keeps
   rules in scope. The same decisions are in `plan.json`, for tools: per kind of event what may be
   removed or counted, which events keep every field, and whether the saving can run in the
   SIEM's own ingestion or needs a pipeline tool (ADR 0023).

If you run Wazuh, `--wazuh-api https://manager:55000` additionally checks single events with the
manager's own `logtest`, the exact engine your detections run on.

## 3. Run it in front of your SIEM

`sluice up` runs Vector with a pipeline Sluice writes, and the control plane next to it.

1. **Write the configuration.** List your sources (any Vector source that produces JSON objects)
   and your SIEM as a destination. `sluice connect` prints a destination block to start from:

   ```sh
   sluice connect splunk --endpoint https://splunk:8088 >> sluice.yaml
   ```

   Credentials go in secret files (`vector_secrets`), never in the configuration.
2. **Check it** without starting anything:

   ```sh
   sluice up --config sluice.yaml --rules sigma/rules --check > vector.yaml
   vector validate --no-environment vector.yaml
   ```

3. **Start it:**

   ```sh
   export SLUICE_CONTROL_TOKEN=$(openssl rand -hex 32)   # needed to listen beyond localhost
   sluice up --config sluice.yaml --rules sigma/rules
   ```

From then on, Vector archives every event and sends everything to your SIEM unchanged. Sluice
analyzes a sample every cycle. A recipe that proves safe goes into **shadow** (24 hours and
3 proofs by default), then into the **proposal** in `<data_dir>/proposals`: a `vector.yaml`
and its proof. Nothing changes until you deploy it by writing it over `vector_config` (section
10). From then on every cycle proves what runs, and if a proof ever fails Sluice switches Vector
back to the safe configuration at once, which sends everything unchanged. With `auto_apply:
true` (demos and labs) Sluice applies its proposals itself and rolls back a failing recipe.

Follow it with `sluice status`, or open `http://127.0.0.1:8686/` for the web console: the proof,
the saving per source and template, why each field was kept, each recipe's history, and a search
over the archive.

You can steer it from the console too. On a template's page, **Hold** forwards it unchanged
until you release it, **Approve** enforces its recipe at the next proof instead of after the full
shadow period, and **Keep field** protects a field your analysts rely on even though no rule
reads it. Give a reason: every action is written to the audit log (`audit.ndjson`). A team that
wants a person to agree before anything is cut sets `promotion: { approval: true }`.

## 4. Microsoft Sentinel

Sentinel's built-in analytics rules expect data in its standard tables, in their exact shape.
Sluice can deliver that shape itself, and prove its cuts against the rules your workspace runs.

### Windows hosts

Run Vector on each Windows host with a configuration Sluice generates. It reads the event logs
and sends them, unchanged, to `sluice up`:

```sh
sluice agent windows --to http://sluice-host:9110 --events-to http://sluice-host:9111 \
  --channel Security --channel System --channel Application > agent.yaml
```

On the central side, give the two sources a `shape`, so their events become `SecurityEvent` and
`WindowsEvent` records after the archive (see `examples/up/sluice-windows.yaml`).
`sluice agent windows --dcr dcr.json --workspace <resource id>` writes the data collection rule
that stores them.

### Linux, firewalls and DNS

| Your data | `shape` on the source | Sentinel table | Data collection rule |
|---|---|---|---|
| Linux and network syslog (Vector's `syslog` source, or raw lines) | `sentinel_syslog` | `Syslog` | `--standard-table syslog` |
| Firewall logs (raw OPNsense/pfSense `filterlog`, or parsed) | `sentinel_common_security_log` | `CommonSecurityLog` | `--standard-table common-security-log` |
| The same firewall logs, normalized | `sentinel_asim_network_session` | `ASimNetworkSessionLogs` | `--standard-table asim-network-session` |
| DNS queries (ECS fields) | `sentinel_asim_dns` | `ASimDnsActivityLogs` | `--standard-table asim-dns` |
| Web server access logs (nginx combined lines, or ECS) | `sentinel_asim_web_session` | `ASimWebSessionLogs` | `--standard-table asim-web-session` |

Authentication and process events need no table of their own: Microsoft's ASIM parsers already
derive them from `Syslog` (sshd), `SecurityEvent` and Sysmon's `WindowsEvent`, which the shapes
above deliver.

```sh
sluice connect sentinel --standard-table syslog --out dcr/ \
  --workspace /subscriptions/…/workspaces/my-workspace
```

This writes `dcr/Syslog.dcr.json` and prints the `azure_logs_ingestion` destination with the
right `stream_name`. Create the rule in Azure, put its immutable id and endpoint in the
destination, and give your app registration *Monitoring Metrics Publisher* on it. Syslog should
carry its priority (`<86>…`); without it, `Facility` stays empty.

### Any other source

For data with no standard table, Sluice derives a custom table from a sample:

```sh
sluice connect sentinel --sample samples/nginx.ndjson --table Nginx --time-field @timestamp \
  --out dcr/ --workspace /subscriptions/…/workspaces/my-workspace
```

You get `Nginx_CL.table.json` (one typed column per field, invalid names made valid) and
`Nginx.dcr.json`. A data collection rule only passes the columns it declares, so use a sample
that covers the source, and generate again when the source changes.

### Proving against Sentinel's own rules

Give `sluice up` the analytics rules your workspace runs, and name `sentinel` in the
destination's `sluice_rules`:

```sh
sluice up --config sluice.yaml --rules sigma/rules \
  --sentinel-rules sentinel-rules/ --kusto http://127.0.0.1:8090
```

- The directory holds your rules as YAML. `sluice rules fetch sentinel` writes exactly what the
  workspace runs, hunting queries and workspace functions included, and marks it complete;
  `--query-log-days 30` adds every query people ran in Logs (with query auditing on). Rules
  you copy from [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) yourself need
  `--rules-complete` to allow summaries. Add the ASIM parsers
  (`Parsers/ASim*/Parsers` and `ASIM/lib/functions` from the same repository), so rules that use
  a parser are bounded by what the parser reads.
- With `--kusto`, every cycle runs those rules in the [Kusto
  emulator](https://learn.microsoft.com/azure/data-explorer/kusto-emulator-overview) on the
  full and the forwarded records, and only the same rows count as proof. `scripts/kql-check.sh`
  starts the emulator in Docker.
- Point it at the rules you actually run. A rule that reads `EventData` on every event keeps
  `EventData` on every event, which is right for that rule and costly if you never enabled it.
- `sluice analyze` proves the same way on a sample, offline: add `--sentinel-rules DIR --kusto
  http://127.0.0.1:8090 --sentinel-table windows-security=SecurityEvent` (one `SOURCE=TABLE`
  per source whose sample records are stored as that table).

## 5. Several SIEMs at once

When the same data goes to two SIEMs, each may run different rules. Name them per destination:

```yaml
destinations:
  sentinel: { type: azure_logs_ingestion, …, sluice_rules: [sigma, sentinel] }
  wazuh:    { type: file, path: /var/log/sluice/wazuh.ndjson, sluice_rules: [wazuh] }
```

Sluice proves each set of rules separately and builds a pipeline per destination, so cuts that
are safe for one SIEM are not held back by the other's rules. `sluice status --profile
sentinel+sigma` shows one of them (profile names list the rule sets alphabetically). `sluice_sources` limits a destination to some sources.

## 6. Get back what was cut

Nothing is ever lost: every event is in the archive as it arrived.

```sh
sluice search --archive /var/lib/sluice/archive --source windows-security \
  --where EventID=4624 --where TargetUserName~admin --from 2026-10-09
sluice replay --archive /var/lib/sluice/archive --source firewall \
  --from 2026-10-09T08:00:00Z --to 2026-10-09T09:00:00Z --url http://siem-ingest:9000
```

Use it for an investigation that needs the full events, or to load a slice into another tool.

## 7. Ask your AI assistant

`sluice mcp` lets an assistant answer "what did Sluice cut, why, and does it still hold?" from
the live status, and look up original events in the archive:

```sh
claude mcp add sluice -- sluice mcp --archive /var/lib/sluice/archive
```

Replay is only offered with `--replay-to URL` (repeatable), and sends only to those endpoints: an instruction hidden in a log line the assistant reads cannot send your archive elsewhere. The operator actions (hold, approve, keep a
field, acknowledge a rollback) only with `--allow-actions`; the control plane audits them like
actions from the console. For a remote assistant, `sluice mcp --http 127.0.0.1:8687` serves MCP
over HTTP with a bearer token (`SLUICE_MCP_TOKEN`).

## 8. Let AI propose recipes

For kinds of events no community recipe covers, an AI model can propose one:

```sh
sluice analyze … --llm anthropic                         # needs ANTHROPIC_API_KEY
sluice analyze … --llm lmstudio:qwen/qwen3.5-9b               # a local model in LM Studio
```

Samples are redacted before they leave, the answer must fit a narrow schema, and the proposal
goes through the same guardrails and proof as every other recipe. You can also write recipes
yourself: `sluice recipes export --out my-recipes`, edit, and pass `--recipes my-recipes`.

## 9. Deploy it

| Where | How |
|---|---|
| A Linux server or VM | The static release binary and Vector 0.59, with `sluice up` under systemd. |
| Docker | `docker compose -f examples/docker/compose.yaml up --build` runs Sluice and Vector with demo traffic. The image bundles the verified Vector release. |
| Kubernetes | `helm install sluice deploy/helm/sluice --set controlToken.secretName=sluice-token` |
| Your own Vector fleet | `sluice analyze` writes a proven `vector.yaml`; roll it out with your own tooling (Git, CI, Ansible, Kubernetes). Sluice does not run your nodes ([ADR 0017](adr/0017-remote-data-plane.md)). |

Before it handles real data:

- Set `SLUICE_CONTROL_TOKEN` (32 characters or more). Without it, the control plane only listens
  on localhost.
- Keep SIEM credentials in secret files, referenced as `SECRET[backend.key]`.
- Give each person who steers Sluice their own identity: single sign-on with your provider
  (`oidc`), or their own token in `operators_file`, so the audit log names them.
- Size the archive: it holds everything, gzip-compressed, per source and hour.
- Leave the promotion defaults (24 hours of shadow, 3 proofs) unless you are testing.

## 10. Review every change in Git

Sluice's product is a configuration and its proof ([ADR 0022](adr/0022-configs-as-the-product.md)).
`sluice up` proposes; it does not apply. Each newly proven configuration lands in
`<data_dir>/proposals` (or `proposals_dir`, such as a checkout your tooling commits from) as
`vector.yaml` with `proposal.json`: the proof of exactly what it saves, whether that proof is
empty, what the rules' completeness rests on, bytes in and out. Next to them, a
`plan-<profile>.json` per rule profile is the savings plan of exactly what the proposal enforces
(`sluice.plan/1`, [ADR 0023](adr/0023-savings-plan.md)), for tools other than Vector. Vector keeps running the safe
configuration, which sends everything unchanged, until you deploy a proposal by writing its
`vector.yaml` over `vector_config`. On the next cycle Sluice proves what you deployed, loads it
into Vector, and keeps proving it every cycle; the moment a proof fails, it switches Vector back
to the safe configuration and `sluice status` and the console say why.

```yaml
proposals_dir: /srv/git/siem-pipeline/sluice   # optional
```

In CI, `sluice prove` checks the file in the pull request, whoever edited it, and fails when
it would change a detection:

```sh
sluice prove --config sluice/vector.yaml --input samples/ --sources sources.yaml \
  --rules sigma/rules        # add --sentinel-rules DIR --kusto URL --sentinel-table S=T for KQL
```

On GitHub:

```yaml
- uses: <owner>/sluice@v0.1.0
  with:
    config: sluice/vector.yaml
    input: samples
    sources: sources.yaml
    rules: sigma/rules
```

The action installs the matching release binary (SHA-256 checked), writes the proof and the
savings to the job summary, and fails the job when the proof fails. `sluice prove` refuses a
configuration whose wiring around Sluice's programs was changed (a filter in front of them, a
route that forwards less, an output that goes nowhere): it can only vouch for what it models.

`scripts/load-test.sh CONFIG SAMPLES SOURCES [RULES]` measures the same configuration on a
stock Vector: events per second per source, next to the savings and the proof.

## When nothing is cut

That is Sluice being careful, and the report says why for each template. The usual reasons are a
rule that may read any field, a template too rare to touch, or a source description so vague that
every rule applies. [The guide](guide.md#why-is-nothing-cut) lists them with what to do about
each.
