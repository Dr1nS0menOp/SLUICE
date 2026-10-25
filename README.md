# Sluice

**Sluice looks at the rules your SIEM runs and a sample of your data, works out where you can send
less without changing a single detection, and writes the configurations that make the saving:
for Vector, Microsoft Sentinel, Elasticsearch, Fluent Bit and the OpenTelemetry Collector. It
proves every saving on your own data and rules. Sluice itself changes nothing: you decide what
runs.**

> **Alpha (0.1).** The analysis and its proof are tested on real data and in the real engines;
> the commands, `plan.json` and the report may still change. See [Status: alpha](#status-alpha).

## The idea

Security teams pay for every byte their SIEM ingests, yet much of that data is padding: rendered
boilerplate, empty fields, duplicates, and high-volume events no rule will ever match. Pipeline
tools can remove it, but a person still has to decide what to remove, build the pipeline and
maintain it. Sluice does the deciding and the proving, and hands you the result:

1. **It reads your rules** from the SIEM, with a read-only account.
2. **It sorts a sample of your traffic** into kinds of events.
3. **It proposes savings:**
   - padding it can drop without losing anything;
   - values the kind of event already implies, such as `Channel: Security` on every Windows
     Security event, removed only while they hold and put back exactly when a query runs
     ([ADR 0032](docs/adr/0032-implied-values.md));
   - events no rule could match, which it counts instead of sending;
   - with AI, more.
4. **It proves** on your sample that your rules raise exactly the same alerts on what would still
   be sent as on everything.
5. **It writes** the savings plan, a report, and the configurations that carry the plan out. You
   review them and deploy them with your own tooling.

Sluice never sits in your data path ([ADR 0030](docs/adr/0030-advice-only.md)).

## Safety contract

These rules are enforced in code, and AI output can never override them:

1. Unknown data passes through untouched.
2. A full copy is kept before any saving. `vector.yaml` archives every event, and a Sentinel rule
   gets an untransformed flow into an archive table. An Elasticsearch pipeline or an agent filter
   cannot write a second copy, so keep one where you send the data from.
3. Anything a rule could match is sent in full.
4. Rare events are never saved on.
5. Every saving is proven before it is proposed, and `sluice prove` proves a configuration again
   when it changes.
6. AI proposes; the guardrails decide.

When Sluice cannot read part of a rule, it assumes the rule reads everything. That costs savings,
never a detection. The report lists every rule next to what Sluice made of it.

## Status: alpha

**Proven against the real product:**

- **Microsoft Sentinel.** The fetch, the sample and the deploy step were followed as written
  below on a live workspace, and the deployed data collection rule was checked by sending records
  through it. The rules run in the Kusto emulator for the proof.
- **Elastic Security.** The fetch and the sample against Kibana and Elasticsearch 9.1. Ingest
  pipelines are proven in Elasticsearch.
- **Wazuh.** The fetch and the `logtest` spot check against a Wazuh 4.14 manager.
- **Vector, Fluent Bit and the OpenTelemetry Collector.** Every configuration is run in the real
  engine in every test run.

**Experimental:**

- **Splunk.** The fetch is written against Splunk's documented API but has not run against a
  real Splunk, and no engine runs Splunk's searches in the proof.
- **Rules read from files** instead of fetched from the SIEM. A file cannot say that it holds
  every rule the SIEM runs, or what a workspace's functions do, so Sluice saves less and the
  report lists what it could not check.

Please report where you get stuck in an
[issue](https://github.com/Dr1nS0menOp/SLUICE/issues): that is what the alpha is for.

## 1. Install

Sluice runs on Linux (x86_64 and aarch64), including WSL2 on Windows. It is one static binary
with no dependencies. This is an alpha: see
[what is proven and what is experimental](#status-alpha).

**Download a release.** Each [release](https://github.com/Dr1nS0menOp/SLUICE/releases) has a
binary per architecture and its SHA-256 sum:

```sh
version=0.1.0
file=sluice-$version-$(uname -m)-unknown-linux-musl
curl -fLO "https://github.com/Dr1nS0menOp/SLUICE/releases/download/v$version/$file"
curl -fLO "https://github.com/Dr1nS0menOp/SLUICE/releases/download/v$version/$file.sha256"
sha256sum --check "$file.sha256"
mkdir -p ~/.local/bin && install -m 0755 "$file" ~/.local/bin/sluice
sluice --version
```

`~/.local/bin` is on the `PATH` of most distributions; if `sluice --version` is not found, add it.
The guides below also use the scripts in the repository and Docker, for the engines the proof runs
your rules in:

```sh
git clone https://github.com/Dr1nS0menOp/SLUICE.git ~/sluice
```

**Or build it from source.** On Debian or Ubuntu:

```sh
sudo apt install -y build-essential git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
git clone https://github.com/Dr1nS0menOp/SLUICE.git ~/sluice
cd ~/sluice && cargo install --locked --path crates/sluice-cli
```

That puts `sluice` in `~/.cargo/bin`. The repository pins the Rust version, and rustup installs
it on the first build.

## 2. See it work

```sh
sluice demo --scale 100
```

The demo generates an hour of synthetic traffic from a small company network: Windows Security,
Sysmon, Linux auth, a firewall, DNS and nginx, with six planted attacks. It then runs Sluice with
example Sigma rules:

```
80,536 events from 6 sources, 76 templates
  ingest  121.0 MB → 25.2 MB  (79.2% saved, 41,562 events summarized into 17,161 records)
  modes   rules 67.5%, implied 11.7%
  proof   41 alerts on full data, 41 on forwarded data  ✓ no detection changed
```

It writes into `out/`:
- `report.html`: the advice, for people. It opens with what the report means, then the largest
  savings first, each with the fields it removes, why that is safe, and the proof. Every
  analysis writes one; it is a single page you can mail or open offline.
- `plan.json`: the same decisions, for tools;
- `vector.yaml`: a [Vector](https://vector.dev) 0.59 configuration that archives all 80,536
  events, sends the 38,974 the proof sent, and counts the other 41,562 into summary records;
- `rules.json`: every rule, and what Sluice made of it;
- `samples/` and `sluice.yaml`: the synthetic sample and its source descriptions, so you can run
  `sluice analyze` on them yourself.

## 3. Use it with your SIEM

> **Use a read-only account, never an administrator.** Sluice only reads. It needs an account
> that may read the rules and, for the sample, the data, and nothing else. Each guide below
> creates such an account. Deploy what Sluice writes yourself, with your own account, after you
> have reviewed it.

Every guide takes the same steps. Run them in a working directory of your own, such as
`mkdir ~/sluice-work && cd ~/sluice-work`:

1. Create the read-only account.
2. Fetch the rules: `sluice rules fetch` reads what the SIEM runs into a directory.
3. Export a sample: an hour or a day of the data you want to save on, one NDJSON file per
   source, in `samples/`. These are real logs: keep them outside any repository.
4. Describe the sources in `sources.yaml`.
5. Analyze: `sluice analyze` writes `out/report.html`, `out/plan.json` and the configurations.
6. Read the report, then deploy what you want with your own tooling.

Sluice saves what no rule needs. A sample needs at least 100 events of a kind of event before
Sluice saves anything on it, so a day of data usually shows more than an hour.

### Microsoft Sentinel (Azure)

You need the [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli), logged in
(`az login`) as someone who may create an app registration and assign roles on the workspace. You
also need Docker, with about 6 GB free for the Kusto emulator the proof runs Sentinel's rules in.

**1. A read-only app registration.** Fill in your resource group and workspace:

```sh
WORKSPACE_ID=$(az monitor log-analytics workspace show \
  --resource-group my-resource-group --workspace-name my-workspace --query id -o tsv)
az ad sp create-for-rbac --name sluice-reader \
  --role "Microsoft Sentinel Reader" --scopes "$WORKSPACE_ID"
```

This prints `appId`, `password` and `tenant`. Reading the sample and the workspace's tables also
needs Log Analytics Reader, which is read-only too:

```sh
az role assignment create --assignee <appId> --role "Log Analytics Reader" --scope "$WORKSPACE_ID"
export AZURE_TENANT_ID=<tenant> AZURE_CLIENT_ID=<appId> AZURE_CLIENT_SECRET='<password>'
```

**2. Fetch the rules.** The fetch reads three things: the workspace's enabled analytics rules,
its hunting queries and functions, and the list of its tables. A rule over a table the workspace
does not have then reads nothing ([ADR 0031](docs/adr/0031-sentinel-workspace-tables-and-functions.md)).

```sh
sluice rules fetch --out sentinel-rules sentinel --workspace "$WORKSPACE_ID"
```

Add `--query-log-days 30` to also protect what people queried in the last 30 days. That needs
query auditing on the workspace.

**3. A sample.** This takes up to 50,000 records of the last day from `SecurityEvent`. Name more
tables at the end of the command:

```sh
bash ~/sluice/scripts/real-data/collect-sentinel.sh "$WORKSPACE_ID" samples 1 50000 SecurityEvent
```

**4. Describe the source.** The source's `id` is the file name, and `schema: sentinel` says the
records carry Sentinel's column names:

```yaml
# sources.yaml
sources:
  - id: SecurityEvent
    logsource: { product: windows, service: security }
    format: { kind: json }
    schema: sentinel
```

**5. Analyze.** Start the [Kusto emulator](https://learn.microsoft.com/azure/data-explorer/kusto-emulator-overview),
wait a minute, and run Sentinel's own rules in it on the full and on the reduced records:

```sh
docker run -d --name sluice-kusto -e ACCEPT_EULA=Y -m 4G -p 127.0.0.1:8090:8080 \
  mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
sluice analyze --input samples --sources sources.yaml --sentinel-rules sentinel-rules \
  --kusto http://127.0.0.1:8090 --sentinel-table SecurityEvent=SecurityEvent --out out
```

**6. Deploy.** `out/report.html` shows what can be saved and why. The data collection rule
(DCR) your records come in through can carry the field removals itself. Counting events needs a
pipeline tool: deploy `out/vector.yaml` for that. To prove and write the DCR, export it and
analyze again with it:

The first `az monitor data-collection rule …` command installs the Azure CLI's
`monitor-control-service` extension.

```sh
az monitor data-collection rule show --resource-group my-resource-group --name my-dcr > dcr.json
sluice analyze --input samples --sources sources.yaml --sentinel-rules sentinel-rules \
  --kusto http://127.0.0.1:8090 --sentinel-table SecurityEvent=SecurityEvent \
  --sentinel-native --sentinel-dcr dcr.json --out out
```

`out/sentinel/dcr.json` is that rule with the proven transformation, plus an untransformed flow
into an archive table. With your own account, not Sluice's, first create the archive table, then
update the rule:

```sh
az rest --method put --body @out/sentinel/SluiceSecurityEventArchive_CL.table.json \
  --url "https://management.azure.com$WORKSPACE_ID/tables/SluiceSecurityEventArchive_CL?api-version=2023-01-01-preview"
DCR_ID=$(az monitor data-collection rule show --resource-group my-resource-group --name my-dcr --query id -o tsv)
az rest --method put --body @out/sentinel/dcr.json \
  --url "https://management.azure.com$DCR_ID?api-version=2023-03-11"
```

The table's name is in the file name under `out/sentinel/`. A new table takes a moment to be
created: if the rule's update answers `InvalidOutputTable`, wait a minute and run it again. A
changed rule can take up to ten minutes before records go through it. If the report lists
functions whose source Sluice does not have, fetch again; the report shows how to give their
source. Remove the emulator when you are done: `docker rm -f sluice-kusto`.

### Wazuh (on premises)

You need the manager's API, usually on port 55000, and an administrator account for it. The
installer creates `wazuh-wui`. To take a sample, you also need SSH access to the hosts whose logs
Wazuh receives.

**1. A read-only API user.** Wazuh's built-in `readonly` role may read the rules and decoders. A
role with the built-in `logtest_all_logtest` policy lets Sluice run single events through the
manager's own rules (`logtest`), which changes nothing on the manager. The password needs 8 or
more characters with upper and lower case, a digit and a symbol. `-k` accepts the manager's
self-signed certificate: use it only on a network you trust.

```sh
API=https://wazuh-manager.example:55000
TOKEN=$(curl -sk -u wazuh-wui -X POST "$API/security/user/authenticate?raw=true")
wazuh() { curl -sk -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; echo; }
wazuh -X POST "$API/security/users" -d '{"username":"sluice","password":"<a strong password>"}'
wazuh -X POST "$API/security/roles" -d '{"name":"sluice_logtest"}'
wazuh "$API/security/roles?search=readonly"            # the id of the role named readonly
wazuh "$API/security/policies?search=logtest"          # the id of logtest_all_logtest
wazuh -X POST "$API/security/roles/<sluice_logtest id>/policies?policy_ids=<logtest_all_logtest id>"
wazuh -X POST "$API/security/users/<sluice id>/roles?role_ids=<readonly id>,<sluice_logtest id>"
```

The ids are in each answer's `affected_items`. `curl -u wazuh-wui` asks for the administrator's
password.

**2. Fetch the rules** and decoders the manager loads:

```sh
export WAZUH_API_PASSWORD='<the password>'
sluice rules fetch --out wazuh-rules wazuh --api "$API" --user sluice --insecure
```

The manager accepts 300 API requests a minute by default, and the fetch reads one file per
request. If it reaches that limit, it waits a minute and goes on.

**3. A sample.** For a Linux host, this copies the last lines of `auth.log` and `syslog` over SSH.
It needs a key and `sudo` for `tail` without a password:

```sh
bash ~/sluice/scripts/real-data/collect-linux.sh admin@host.example samples
```

Or turn a log file you copied yourself into NDJSON, one line per event:

```sh
python3 -c 'import json,sys; [print(json.dumps({"message": l.rstrip("\n")})) for l in sys.stdin if l.strip()]' \
  < auth.log > samples/linux-auth.ndjson
```

**4. Describe the sources.** `complete: true` says the attributes given are all there are, which
is right for a single log such as `auth.log`:

```yaml
# sources.yaml
sources:
  - id: linux-auth
    logsource: { product: linux, service: auth, complete: true }
    format: { kind: text, field: message }
  - id: linux-syslog
    logsource: { product: linux, service: syslog, complete: true }
    format: { kind: text, field: message }
```

**5. Analyze.** `--wazuh-api` checks single events with the manager's `logtest`:

```sh
sluice analyze --input samples --sources sources.yaml \
  --wazuh-rules wazuh-rules/rules --wazuh-decoders wazuh-rules/decoders \
  --wazuh-api "$API" --wazuh-user sluice --wazuh-insecure --out out
```

**6. Deploy.** Wazuh has no ingest-time transformation of its own, so the saving runs before the
data reaches the manager. Use one of these:
- Vector, with `out/vector.yaml`;
- Fluent Bit, where it collects the logs, with `--fluent-bit-native`;
- the OpenTelemetry Collector, where it collects the logs, with `--otel-native`.

Mind one thing. With Wazuh's standard ruleset, Sluice saves almost nothing on the data Wazuh
itself receives, because generic rules such as 1002 read every line whole. The savings are on
data that also goes to another SIEM, or with a tuned ruleset.

### Elastic Security (self-managed or Elastic Cloud)

You need Kibana's and Elasticsearch's URLs. On Elastic Cloud, they are on your deployment's page.
You also need an administrator account to create a role, and Docker for the proof's own
Elasticsearch.

```sh
KIBANA=https://kibana.example:5601
ELASTICSEARCH=https://elasticsearch.example:9200
```

**1. A read-only role and user.** The role reads two things: Kibana's Security solution, for the
detection rules, and your log indices, for the sample. Change `logs-*` to the index patterns your
data is in. In Kibana you can do the same under Stack Management, Roles and Users, with the
Security feature set to Read. `curl -u elastic` asks for the administrator's password.

```sh
curl -u elastic -X PUT "$KIBANA/api/security/role/sluice-reader" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d '{
  "elasticsearch": {"indices": [{"names": ["logs-*"], "privileges": ["read", "view_index_metadata"]}]},
  "kibana": [{"base": [], "feature": {"siemV3": ["read"]}, "spaces": ["*"]}]}'
curl -u elastic -X POST "$ELASTICSEARCH/_security/user/sluice" \
  -H 'Content-Type: application/json' -d '{"password": "<a strong password>", "roles": ["sluice-reader"]}'
```

`siemV3` is the Security feature in Kibana 9.1. In 9.0 and 8.18 it is `siemV2`, and before that
`siem`; `GET $KIBANA/api/features` lists them.

**2. Fetch the rules** of the default space. Add `--space NAME` for another one.

```sh
export KIBANA_USER=sluice KIBANA_PASSWORD='<the password>'
sluice rules fetch --out elastic-rules elastic --kibana "$KIBANA"
```

**3. A sample.** This takes up to 50,000 documents of the last 24 hours, as the index stores them.
For a self-managed cluster with its own certificate authority, also set
`ELASTIC_CA_CERT=http_ca.crt`.

```sh
export ELASTIC_USER=sluice ELASTIC_PASSWORD='<the password>'
bash ~/sluice/scripts/real-data/collect-elastic.sh "$ELASTICSEARCH" 'logs-system.security-*' \
  samples/windows-security.ndjson 24 50000
```

**4. Describe the source.** `schema: ecs` says the documents use Elastic's field names:

```yaml
# sources.yaml
sources:
  - id: windows-security
    logsource: { product: windows, service: security }
    format: { kind: json }
    schema: ecs
```

**5. Analyze.** The proof runs Elastic's rules and the pipelines it writes in an Elasticsearch of
its own. Sluice creates indices and pipelines there, so never point `--elasticsearch` at your
cluster:

```sh
docker run -d --name sluice-elastic -p 127.0.0.1:9201:9200 -e discovery.type=single-node \
  -e xpack.security.enabled=false -e ES_JAVA_OPTS="-Xms1g -Xmx1g" \
  docker.elastic.co/elasticsearch/elasticsearch:9.1.0
sluice analyze --input samples --sources sources.yaml --elastic-rules elastic-rules \
  --elasticsearch http://127.0.0.1:9201 --elastic-native --out out
```

**6. Deploy.** `out/elastic/windows-security.pipeline.json` is an ingest pipeline that makes the
field removals in Elasticsearch itself. Integrations call `<type>-<dataset>@custom` last, so with
your own account, install the pipeline and call it from there:

```sh
curl -u elastic -X PUT "$ELASTICSEARCH/_ingest/pipeline/sluice-windows-security" \
  -H 'Content-Type: application/json' --data-binary @out/elastic/windows-security.pipeline.json
curl -u elastic -X PUT "$ELASTICSEARCH/_ingest/pipeline/logs-system.security@custom" \
  -H 'Content-Type: application/json' -d '{"processors": [{"pipeline": {"name": "sluice-windows-security"}}]}'
```

If the `@custom` pipeline exists already, add the `pipeline` processor to it rather than
replacing it. Counting events needs `out/vector.yaml`. Remove the proof's Elasticsearch when you
are done: `docker rm -f sluice-elastic`.

### Splunk (not yet tested against a real Splunk)

`sluice rules fetch --out splunk-rules splunk --api https://splunk.example:8089` reads three
things: the saved searches, macros, and the `props` and `transforms` of every app. Give it a
read-only account's token in `SPLUNK_TOKEN`. Then pass `--splunk-rules splunk-rules` to `sluice
analyze`. No engine runs Splunk's searches in the proof yet: what they read still limits every
saving.

### Any other SIEM: Sigma rules

For a SIEM whose rules Sluice cannot read yet, Sigma rules stand in: `--rules sigma-rules`. A
Sigma directory has no API that says it is complete, so add `--rules-complete` only when it holds
every rule your SIEM runs. Without that, Sluice makes only savings that keep every event.
Records in another field convention than Sigma's need the pipeline your SIEM converts Sigma with,
such as `--sigma-pipeline ecs=ecs_windows`. [Using Sluice](docs/usage.md) has the details.

On this project's development machine, with all 3,152 SigmaHQ rules declared complete:
- Windows System, Application and PowerShell logs (42,335 events): 25.0 % less ingest, with
  236 = 236 alerts.
- A Linux server's `auth.log` and `syslog` (166,665 lines): 25.7 % less.

## 4. Where the savings run

Sluice proves each configuration in the engine it is for before it writes it:

| Where the saving runs | What `sluice analyze` writes | Proven in |
|---|---|---|
| [Vector](https://vector.dev) | `vector.yaml`, always: every saving, counting included | the `vrl` crate Vector embeds; its tests let `vector test` check Vector itself |
| Microsoft Sentinel's ingestion | with `--sentinel-native --sentinel-dcr RULE.json`: that data collection rule with a `transformKql` per table and an untransformed flow into an archive table | the Kusto emulator |
| Elasticsearch's ingestion | with `--elastic-native`: an ingest pipeline per source | Elasticsearch |
| Fluent Bit | with `--fluent-bit-native`: a Lua filter per source | Fluent Bit |
| OpenTelemetry Collector | with `--otel-native`: `transform` statements per source | the collector |

Outside Vector, only field removals run: counting needs state across events, which only a
pipeline tool keeps. `plan.json` says for each kind of event where its saving can run.

`vector.yaml` reads files and writes files. Point its sources and sinks at your own, and roll it
out with the tooling you already use (Git, CI, Ansible, Kubernetes). In CI, `sluice prove` proves
the configuration in a pull request as it is. It fails when the configuration would change a
detection, or when the sample raises no alert at all (`action.yml` runs it on GitHub; ADR 0022).

For data you send to Sentinel yourself, `sluice connect sentinel` writes two kinds of tables
with their data collection rules: a custom table derived from a sample (`--sample`), and a table
for summaries with a function that counts them in (`--summary-table`).

Until 2026-10-17, Sluice could also run Vector itself (`sluice up`), with a live control plane,
archive search and replay, and an MCP server. That code was removed and stays in the Git history
([ADR 0030](docs/adr/0030-advice-only.md)).

## Building and testing

Sluice is a Rust workspace; the toolchain is pinned in `rust-toolchain.toml`.

```sh
cargo build --release
bash scripts/check.sh        # every quality gate; with Docker also the real engines
bash scripts/install-zig.sh && bash scripts/build-release.sh   # static binaries for both architectures
```

On Windows, run the same commands in WSL2. macOS is not supported: use a Linux VM or container
([ADR 0003](docs/adr/0003-linux-only.md)).

## Documentation

- [Using Sluice](docs/usage.md): step by step, from a first look to the configurations for your
  SIEM and your tools
- [User guide](docs/guide.md): concepts, source descriptions, every command and what it writes
- [Architecture and technologies](docs/architecture.md): diagrams of the analysis and of what
  each configuration does, one event followed step by step, the parts, and what each is built on
- [Glossary](docs/glossary.md): the terms Sluice uses
- [Architecture decisions](docs/adr/)
- [Compatibility](docs/compatibility.md)
- [Credits](docs/credits.md): the people and research Sluice builds on
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)

## License

Sluice is licensed under the [GNU Affero General Public License v3.0 only](LICENSE)
(AGPL-3.0-only). You may use, modify and sell it, but if you distribute a modified version or
offer it to others over a network, you must publish its complete source under the same license.
[ADR 0008](docs/adr/0008-license.md) explains the choice.
