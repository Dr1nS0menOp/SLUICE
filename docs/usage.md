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

4. **Read the report.** `report.html` shows the saving per source and template, the proof, and
   for every template that was not cut the reason (a rule reads that field, the template is rare,
   no recipe matches). `sluice analyze` also prints hints when a vague source description keeps
   rules in scope.

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
3 proofs by default), then is **enforced**: Sluice rewrites the pipeline and reloads Vector.
Every cycle proves the whole set again, and a recipe that fails is **rolled back** at once.

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

- The directory holds your rules as YAML (exported from your workspace, or the ones you use from
  [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel)). Add the ASIM parsers
  (`Parsers/ASim*/Parsers` and `ASIM/lib/functions` from the same repository), so rules that use
  a parser are bounded by what the parser reads.
- With `--kusto`, every cycle runs those rules in the [Kusto
  emulator](https://learn.microsoft.com/azure/data-explorer/kusto-emulator-overview) on the
  full and the forwarded records, and only the same rows count as proof. `scripts/kql-check.sh`
  starts the emulator in Docker.
- Point it at the rules you actually run. A rule that reads `EventData` on every event keeps
  `EventData` on every event, which is right for that rule and costly if you never enabled it.

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

Replay is only offered with `--allow-replay`, and the operator actions (hold, approve, keep a
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

## When nothing is cut

That is Sluice being careful, and the report says why for each template. The usual reasons are a
rule that may read any field, a template too rare to touch, or a source description so vague that
every rule applies. [The guide](guide.md#why-is-nothing-cut) lists them with what to do about
each.
