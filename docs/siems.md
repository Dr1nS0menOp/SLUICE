# Sluice with your SIEM

A guide per SIEM, from a read-only account to the configuration to deploy. For what Sluice
does and how to install it, see the [README](../README.md); for every option,
[usage](usage.md).

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
   It makes all three kinds of saving; `--mode duplicates` or `--mode duplicates,implied`
   sends every event ([choose what to save](../README.md#choose-what-to-save)).
6. Read the report, then deploy what you want with your own tooling.

Sluice saves what no rule needs. A sample needs at least 100 events of a kind of event before
Sluice saves anything on it, so a day of data usually shows more than an hour.

## Microsoft Sentinel (Azure)

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
does not have then reads nothing ([ADR 0031](adr/0031-sentinel-workspace-tables-and-functions.md)).

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
  --native sentinel --sentinel-dcr dcr.json --out out
```

`out/sentinel/dcr.json` is that rule with the proven transformation, plus an untransformed flow
into an archive table. Where the rule empties implied values, `out/sentinel/SecurityEventFull.kql`
is a function that puts them back: save it in the workspace and query `SecurityEventFull` to read
every value as before. With your own account, not Sluice's, first create the archive table, then
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

## Wazuh (on premises)

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
- Fluent Bit, where it collects the logs, with `--native fluent-bit`;
- the OpenTelemetry Collector, where it collects the logs, with `--native otel`.

Mind one thing. With Wazuh's standard ruleset, Sluice saves almost nothing on the data Wazuh
itself receives, because generic rules such as 1002 read every line whole. The savings are on
data that also goes to another SIEM, or with a tuned ruleset.

## Elastic Security (self-managed or Elastic Cloud)

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
  --elasticsearch http://127.0.0.1:9201 --native elastic --out out
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
replacing it. Where the pipeline removes implied values, `out/elastic/windows-security.runtime.json`
holds runtime fields that put them back: add them to a Kibana data view, or to a search as
`runtime_mappings`. Counting events needs `out/vector.yaml`. Remove the proof's Elasticsearch when you
are done: `docker rm -f sluice-elastic`.

## Splunk Enterprise

You need Splunk's management port (8089), an account that sees the saved searches, and Docker for
the proof's own Splunk. Sluice reads JSON events with the fields Splunk extracts from their keys
(`KV_MODE = json`, or a sourcetype such as `_json`).

```sh
SPLUNK=https://splunk.example:8089
```

**1. An account that reads the searches.** The fetch reads the saved searches, macros, `props`
and `transforms` of every app the account may read. Splunk hides another user's private searches
from an account, though it runs them when they are scheduled: share them with their app, or fetch
with an account that sees them. Create an authentication token for the account (Settings,
Tokens).

**2. Fetch the rules.** Add `--insecure` if the management port has Splunk's default self-signed
certificate and the network path is trusted.

```sh
export SPLUNK_TOKEN='<the token>'
sluice rules fetch --out splunk-rules splunk --api "$SPLUNK"
```

**3. A sample.** Up to 50,000 events of one sourcetype from the last 24 hours, as Splunk stores
them. The account must be allowed to search that index:

```sh
mkdir -p samples
curl -fsS -H "Authorization: Bearer $SPLUNK_TOKEN" "$SPLUNK/services/search/v2/jobs/export" \
  --data-urlencode 'search=search index=windows sourcetype=_json | head 50000' \
  -d earliest_time=-24h -d output_mode=raw > samples/windows-security.ndjson
```

**4. Describe the source.** `schema: splunk` says the records' fields are named as Splunk
extracts them:

```yaml
# sources.yaml
sources:
  - id: windows-security
    logsource: { product: windows, service: security }
    format: { kind: json }
    schema: splunk
```

**5. Analyze.** The proof runs the searches in a Splunk of its own: Sluice creates an index
there, sends the sample to it and removes the index afterwards, so never point `--splunk` at your
Splunk. Its credentials are separate from the fetch's. Starting Splunk's image means you accept
the [Splunk General Terms](https://www.splunk.com/en_us/legal/splunk-general-terms.html) and
Splunk's licence (the trial's: 500 MB a day):

```sh
docker run -d --name sluice-splunk -p 127.0.0.1:18089:8089 -p 127.0.0.1:18088:8088 \
  -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
  -e SPLUNK_PASSWORD='<a password for the proof>' splunk/splunk:10.6.1.1
# Wait until `docker ps` shows it as healthy: a minute or two.
export SPLUNK_PROOF_PASSWORD='<the same password>'
sluice analyze --input samples --sources sources.yaml --splunk-rules splunk-rules \
  --splunk https://127.0.0.1:18089 --splunk-hec https://127.0.0.1:18088 --splunk-insecure \
  --out out
```

`sluice analyze` says how many searches ran in the proof's Splunk, and why it set others aside:
a generating search (`tstats`), one that writes (`collect`, `outputlookup`), or one that needs a
lookup or data model the proof's Splunk does not have. What those read is kept anyway. Remove the
proof's Splunk when you are done: `docker rm -f sluice-splunk`.

**6. Deploy.** Sluice writes no configuration in Splunk's own language yet. `out/vector.yaml`
carries the savings out in front of Splunk's HTTP Event Collector, with Vector's
`splunk_hec_logs` sink in place of its file sink.

## Any other SIEM: Sigma rules

For a SIEM whose rules Sluice cannot read yet, Sigma rules stand in: `--rules sigma-rules`. A
Sigma directory has no API that says it is complete, so add `--rules-complete` only when it holds
every rule your SIEM runs. Without that, Sluice makes only savings that keep every event.
Records in another field convention than Sigma's need the pipeline your SIEM converts Sigma with,
such as `--sigma-pipeline ecs=ecs_windows`. [Using Sluice](usage.md) has the details.

On this project's development machine, with all 3,152 SigmaHQ rules declared complete:
- Windows System, Application and PowerShell logs (42,335 events): 43.4 % less ingest, 19.1 %
  of it by implied values, with 236 = 236 alerts.
- A Linux server's `auth.log` and `syslog` (166,665 lines): 25.7 % less.
