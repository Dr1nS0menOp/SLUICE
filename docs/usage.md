# Using Sluice

This page walks through what you can do with Sluice, from a first look to the configurations
that carry out the savings in the tools you run. Each section is a complete path you can follow.
The [README](../README.md) has a short guide per SIEM (Microsoft Sentinel, Wazuh, Elastic
Security), with the read-only account each needs; this page goes into more depth. For every
command and file, see the [user guide](guide.md); for how it works inside, see
[architecture](architecture.md).

Sluice reads and writes files. It never sits in your data path and changes nothing in your
environment: you deploy what it writes ([ADR 0030](adr/0030-advice-only.md)).

Sluice runs on Linux (x86_64, aarch64), including WSL2. Everything below assumes the `sluice`
binary is on your `PATH`. To run the Vector configuration it writes, you need Vector 0.59
(`scripts/install-vector.sh`).

## 1. See it work in two minutes

```sh
sluice demo --scale 100
```

The demo generates an hour of traffic from a small company network: Windows Security, Sysmon,
Linux auth, a firewall, DNS and nginx, with six planted attacks. It then runs the whole
analysis with example Sigma rules and prints what it would save and whether every alert
survived:

```
80,536 events from 6 sources, 76 templates
  ingest  121.0 MB → 26.0 MB  (78.5% saved, 41,562 events summarized into 17,161 records)
  modes   rules 67.5%, implied 11.0%
  proof   41 alerts on full data, 41 on forwarded data  ✓ no detection changed
```

Open `out/report.html`, the advice: it says first what the report means, then shows the largest
savings first, each with the fields it removes and why that is safe, and folds the smaller ones
away. `out/vector.yaml` is the pipeline that would do it, and `out/plan.json` holds the same
decisions for other tools.

## 2. Find out what you would save on your own logs

You need an hour or a day of your logs, and the rules your SIEM runs. Nothing is sent anywhere.

1. **Export a sample** per source as NDJSON (one JSON object per line), for example
   `samples/windows-security.ndjson` and `samples/firewall.ndjson`. Text logs go one line per
   event in a `message` field. `scripts/real-data/` has exporters, each read-only:
   - `collect-sentinel.sh`: a Log Analytics workspace's tables;
   - `collect-elastic.sh`: an Elasticsearch index pattern;
   - `collect-linux.sh`: a Linux host's `auth.log` and `syslog`, over SSH;
   - `collect-windows.ps1`: a Windows host's event logs, in Sigma's field names.
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
   Sigma rules use, as Windows event logs do. Without it Sluice removes nothing a Sigma rule could
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
   ```

   Then pass `--wazuh-rules inventory/wazuh/rules --wazuh-decoders inventory/wazuh/decoders`,
   `--sentinel-rules inventory/sentinel` or `--elastic-rules inventory/elastic` (with
   `--elasticsearch URL` the proof runs them too). Sigma
   rules have no SIEM API to read them from: pass `--rules-complete` when the directory holds
   every Sigma rule your SIEM runs. Without either, Sluice makes only savings that keep every
   event, and says so (ADR 0021).

4. **Read the report.** `report.html` is the advice ([an example](example-report.html), for
   OTRF's APT29 attack data). It starts with a paragraph on what it means, for readers without context such as a
   manager, and the saving at a glance, per mode. *What "implied" means* explains implied values
   with the sample's largest one, and names per source the values that are the same on every
   kind of event, which may be one machine's rather than the kind of event's. Then the largest
   savings first: per kind of event what to change, the fields removed on the sample with their
   bytes, why each may go and where it can run, and, where events are counted, how many summary
   records they become. Savings by source follow, and the smaller savings, the kinds of event
   sent unchanged (each with its reason: a rule reads that field, the kind of event is rare, no
   recipe matches), the rules and the problems are folded away. *What the SIEM still receives*
   shows per source up to 10 events as they are sent, as a table that scrolls sideways: one
   column per field, each cell the value sent, the value left out with its reason, or a dot, and
   each event's JSON folded below. Those are your sample's real values: `--no-examples` leaves
   them out before you share the report. `--mode rules` or `--mode implied` makes only one kind
   of saving; the report gives the saving of each. `sluice analyze` also prints hints when a
   vague source description keeps rules in scope. The same decisions are in `plan.json`, for
   tools: per kind of event what may be removed or counted, the implied values
   (`remove_implied`), which events keep every field, and whether the saving can run in the
   SIEM's own ingestion or an agent, or needs a pipeline tool (ADR 0023).

If you run Wazuh, `--wazuh-api https://manager:55000` additionally checks single events with the
manager's own `logtest`, the exact engine your detections run on.

Keep the rules current. A rule added in the SIEM protects its data from the next `sluice rules
fetch` and analysis on; until then, a configuration you deployed earlier knows nothing of it.
Fetching again replaces the directory.

## 3. Carry out the savings

Sluice writes a configuration for each tool it can prove a saving in. Pick the ones you run, and
deploy them with the tooling you already use (Git, CI, Ansible, Kubernetes).

**Vector** gets every saving, counting included: `vector.yaml` is always written. Per source it
reads a file and has three sinks: the archive, which gets every event as it arrived, what is
forwarded, and the summaries. Point the sources and sinks at your own. Its Vector unit tests are
drawn from your sample, so `vector validate` and `vector test` show that your Vector does what
was proven:

```sh
vector validate --no-environment out/vector.yaml && vector test out/vector.yaml
```

**Without a pipeline tool**, a SIEM's ingestion or an agent can carry out the field removals
(L1). Counting needs state across events, so it stays with Vector. Each generator runs its output
in the real engine on your sample and writes it only when it removes nothing the proven Vector
configuration keeps and the rules raise the same alerts. What it cannot express (text templates,
counting) is listed and left unchanged.

```sh
sluice analyze … --elasticsearch http://127.0.0.1:9200 --elastic-native   # writes out/elastic/
sluice analyze … --fluent-bit fluent-bit --fluent-bit-native             # out/fluent-bit/
sluice analyze … --otel-collector otelcol-contrib --otel-native          # out/otel/
```

- **Elasticsearch** ([ADR 0024](adr/0024-elastic-ingest-pipelines.md)): one ingest pipeline per
  source. The sample must be documents as the index stores them (`_source`), the way a
  `@custom` pipeline at the end of an integration's pipeline sees them. Where the pipeline
  removes implied values, `out/elastic/SOURCE.runtime.json` holds runtime fields that put them
  back in a search (`runtime_mappings`) or a Kibana data view (ADR 0032).
  `scripts/elastic-check.sh` starts an Elasticsearch in Docker.
- **Fluent Bit** ([ADR 0027](adr/0027-fluent-bit-lua-filters.md)): a Lua filter per source,
  for records as the agent reads them. Add each section of `filters.conf` to the agent's
  configuration, with `Match` set to the tag of that source's input. `--fluent-bit` takes the
  binary or a wrapper that runs it in a container (`scripts/fluentbit-check.sh` writes one).
- **OpenTelemetry Collector** ([ADR 0028](adr/0028-otel-transform-statements.md)): a
  `transform` processor per source, for records whose body is the parsed JSON record (the
  `filelog` receiver's `json_parser` with `parse_to: body`). `--otel-collector` takes the
  contrib distribution or a wrapper (`scripts/otel-check.sh` writes one).
- **Microsoft Sentinel**: a data collection rule transformation, in section 4.

## 4. Microsoft Sentinel

Sentinel's analytics rules expect data in its tables, in their exact shape. Sluice proves its
savings against the rules your workspace runs, and writes the tables and data collection rules
(DCRs) that carry them out in Sentinel's own ingestion.

### Proving against Sentinel's own rules

Fetch what the workspace runs and give it to `sluice analyze` with the Kusto emulator:

```sh
sluice rules fetch --out inventory/sentinel sentinel --workspace /subscriptions/…/workspaces/…
sluice analyze --input samples/ --sources sources.yaml --sentinel-rules inventory/sentinel \
  --kusto http://127.0.0.1:8090 --sentinel-table windows-security=SecurityEvent
```

- The fetch writes exactly what the workspace runs, hunting queries and workspace functions
  included, and marks it complete; `--query-log-days 30` adds every query people ran in Logs
  (with query auditing on). Rules you copy from
  [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) yourself need
  `--rules-complete` to allow summaries. Add the ASIM parsers (`Parsers/ASim*/Parsers` and
  `ASIM/lib/functions` from the same repository), so rules that use a parser are bounded by what
  the parser reads.
- The fetch also lists the workspace's tables (`tables.json`). A rule, or an ASIM parser's
  branch, over a table the workspace does not have reads nothing, so it no longer keeps every
  source whole (ADR 0031). Fetch again after creating a table.
- A rule that calls a function whose source Sluice does not have keeps every column of every
  record. The report lists each such function with the rules that call it. `sluice rules fetch
  sentinel` reads every function of the workspace; for rules from files, save the function next
  to them, with its query from the Azure portal (Logs, Functions):

  ```yaml
  FunctionName: my_parser
  FunctionQuery: |
    SecurityEvent
    | where EventID in (4624, 4625)
  ```

- `--sentinel-table SOURCE=TABLE` names the table each source's sample records are stored in.
  With `--kusto`, the [Kusto
  emulator](https://learn.microsoft.com/azure/data-explorer/kusto-emulator-overview) runs those
  rules on the full and the forwarded records, and only the same rows count as proof.
  `scripts/kql-check.sh` starts the emulator in Docker.
- Point it at the rules you actually run. A rule that reads `EventData` on every event keeps
  `EventData` on every event, which is right for that rule and costly if you never enabled it.

### Savings in Sentinel's own ingestion

To have the data collection rule carry the savings, without a pipeline tool in the path, add
`--sentinel-native` and the rule the records go through (L1 only: whole top-level columns):

```sh
sluice analyze --input samples/ --sources sources.yaml --sentinel-rules inventory/sentinel \
  --kusto http://127.0.0.1:8090 --sentinel-table nginx=Nginx_CL \
  --sentinel-native --sentinel-dcr dcr/Nginx.dcr.json --out out/
```

Use records read back from the table as the sample (an empty field and a missing one are the
same there). `--sentinel-dcr` is the rule as Azure gives it, or as `sluice connect sentinel`
wrote it. `out/sentinel/dcr.json` is that rule with the proven transformation and an
untransformed flow into an Auxiliary archive table, defined in
`out/sentinel/SluiceNginxArchive_CL.table.json`: create that table first, then update the rule.
Without `--sentinel-dcr`, Sluice proves the transformation but writes nothing. Where the rule
empties implied values, `out/sentinel/<Table>Full.kql` is a workspace function that puts them
back: save it in the workspace, and query `<Table>Full` instead of the table to read every
value as before (ADR 0032).

### Tables and rules for your own data

`sluice connect sentinel` writes the Sentinel side for data you send through the Logs Ingestion
API, for example with Vector's `azure_logs_ingestion` sink. It writes files only.

For data with no standard table, it derives a custom table from a sample:

```sh
sluice connect sentinel --sample samples/nginx.ndjson --table Nginx --time-field @timestamp \
  --out dcr/ --workspace /subscriptions/…/workspaces/my-workspace
```

You get `Nginx_CL.table.json` (one typed column per field, invalid names made valid) and
`Nginx.dcr.json`. A data collection rule only passes the columns it declares, so use a sample
that covers the source, and generate again when the source changes.

Create each rule in Azure and give the app registration that sends *Monitoring Metrics
Publisher* on it.

### Summaries

Events Sluice counts instead of sends become summary records, which a table of one shape cannot
hold. `sluice connect sentinel --summary-table --out dcr/` writes the table `SluiceSummary_CL`,
its data collection rule, and `SluiceCounts.kql`, a function to save in the workspace that
queries add counted events with (ADR 0029). Send the summaries sink of `vector.yaml` to that
rule, not to the events' table.

## 5. Let AI propose recipes

For kinds of events no community recipe covers, an AI model can propose one:

```sh
sluice analyze … --llm anthropic                         # needs ANTHROPIC_API_KEY
sluice analyze … --llm lmstudio:qwen/qwen3.5-9b          # a local model in LM Studio
```

Samples are redacted before they leave, the answer must fit a narrow schema, and the proposal
goes through the same guardrails and proof as every other recipe. The recipes the proof kept are
written to `out/ai-recipes`; `sluice recipes contribute --from out/ai-recipes --into REPO`
copies them, checked, into a clone of a recipe repository for a pull request. Review each one
first: its pattern and rationale come from your logs.

You can also write recipes yourself: `sluice recipes export --out my-recipes`, edit, and pass
`--recipes my-recipes`.

## 6. Review every change in Git

Sluice's product is a configuration and its proof ([ADR 0022](adr/0022-configs-as-the-product.md)).
Keep what `sluice analyze` writes in a repository, so a new analysis arrives as a reviewable
diff. In CI, `sluice prove` checks the Vector configuration in a pull request as it is, whoever
edited it, and fails when it would change a detection:

```sh
sluice prove --config sluice/vector.yaml --input samples/ --sources sources.yaml \
  --rules sigma/rules        # add --sentinel-rules DIR --kusto URL --sentinel-table S=T for KQL
```

On GitHub:

```yaml
- uses: Dr1nS0menOp/SLUICE@v0.1.0
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
Sources and sinks are yours to change.

## When nothing is saved

That is Sluice being careful, and the report says why for each template. The usual reasons are a
rule that may read any field, a template too rare to touch, or a source description so vague that
every rule applies. [The guide](guide.md#why-is-nothing-saved) lists them with what to do about
each.
