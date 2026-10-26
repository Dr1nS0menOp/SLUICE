# Sluice user guide

This guide explains how Sluice decides where to save, how to describe your data, and every
command and what it writes. The [README](../README.md) is the short version,
[Using Sluice](usage.md) walks through each use case, [architecture](architecture.md) explains
the parts and the technologies, and the [ADRs](adr/) explain why things are built the way they
are.

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

   Sluice also proposes **implied values** itself (L1): per kind of event, a field that always
   holds one value (Windows' `Channel`, `Keywords`), or holds one value whenever another field
   holds a given one (4624's `RestrictedAdminMode` is `-` unless `LogonType` is 10). Such a
   field is removed only while it holds that value, so every removed value can be put back from
   `plan.json`. They are learned from the sample, only from fields that are categories, and a
   field named as an identifier (`ExecutionThreadID`, `agent.ephemeral_id`) is never implied by
   another field: its value changes at the next restart. Vector removes them, and so does the
   data collection rule of `--sentinel-native`, which also writes `sentinel/<Table>Full.kql`: a
   workspace function that puts them back, so a query reads the table as before. The ingest
   pipeline of `--elastic-native` removes them too, with runtime fields that put them back, and
   so do the agents, except values tested against a whole number. The report says per field why
   it may go and where ([field value study](notes/field-value.md)). An object whose every field
   went is not sent as `{}`; one that came empty is (ADR 0033).

   The two kinds of saving are **modes**, and both run unless `--mode` names fewer:
   `--mode rules` uses the recipes only (remove what no rule or query reads, empty fields,
   counting), `--mode implied` the implied values only. The report and `plan.json`
   (`saved_by_mode`) give the saving of each side by side. With both, implied values are
   credited with what they save after the recipes: on the demo, `rules` 67.5 % and `implied`
   11.0 % together, while `implied` alone saves 30.9 %.
3. **Guardrails.** For each template, Sluice works out which of your rules could see it (by log
   source, and by the template's fixed values) and what each rule reads. A field a rule reads is
   never removed from an event that rule could match; such events are forwarded whole (ADR
   0009). Nothing is saved on rare templates, and nothing at all without an archive.
4. **Proof.** Sluice runs your rules over the sample twice, on the full events and on what the
   reduced pipeline would forward: Sigma rules always, Microsoft Sentinel's analytics rules in
   the Kusto emulator when `--kusto` is given, and Elastic's detection rules in Elasticsearch
   when `--elasticsearch` is given. Only if both raise exactly the same alerts is a recipe kept;
   otherwise it is rolled back, per template. The proof runs the same VRL code Vector will run,
   and counts in bytes what would be sent: the forwarded events and the summary records that
   counted events become (one per minute per summary group).
5. **Advice.** Sluice writes down what it decided ([What Sluice writes](#what-sluice-writes)) and
   changes nothing itself. You review the configurations and deploy them
   ([ADR 0030](adr/0030-advice-only.md)).

## Describing your sources

`sluice analyze` and `sluice prove` read a sources file:

```yaml
sources:
  - id: windows-system                 # your name for it; also the archive directory
    logsource: { product: windows, service: system, complete: true }
    format: { kind: json }             # JSON objects
    schema: sigma                      # the field names the records use (see "Field names")
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

### Kinds of event

A template is one kind of event in one source, and the rarity floor counts per template. For
JSON, Sluice reads the kind from `EventID`, `event.code`, `event.action` and `action`, plus
defaults for some products: `aws` (`eventSource`, `eventName`), `okta` (`eventType`), `m365`
(`Workload`, `Operation`), `azure` (`category`, `operationName`), `gcp`
(`protoPayload.serviceName`, `protoPayload.methodName`) and `kubernetes` (`verb`,
`objectRef.resource`). Add your own with `event_type`:

```yaml
  - id: idp
    logsource: { product: keycloak }
    format: { kind: json }
    event_type: [type, details.auth_method]
```

More fields only split templates further, which never makes Sluice remove more. For text lines,
Sluice splits a template wherever only a few words alternate (`Accepted`, `Failed`), so a rare
outcome keeps a template of its own (ADR 0019).

### Field names

A rule names the fields it reads in one convention, and a SIEM stores them in another. Sigma says
`Image`; Elastic's ECS says `process.executable`. A SIEM converts a Sigma rule with a mapping
(pySigma's processing pipelines), and Sluice can apply the same one. So each JSON source says
which names its records follow, with `schema`:

| `schema` | The records use |
|---|---|
| `sigma` | The names Sigma rules use: Windows event data (`Image`, `TargetUserName`) and whatever names your own rules were written against. |
| `ecs`, `cim`, `asim`, `ocsf`, `udm` | Elastic's, Splunk's, Sentinel's ASIM, OCSF's or Google's names. |
| `sentinel` | The columns of a Sentinel table that is not ASIM (`Syslog`, `CommonSecurityLog`). |
| `splunk` | The fields as Splunk extracts them: a JSON event's key paths (ADR 0026). |
| (left out) | Not declared. |

A Sigma rule is compared with a source whose `schema` is `sigma`, or one for which you load a
processing pipeline (ADR 0020):

```sh
sluice analyze ... --sigma-pipeline ecs=ecs_windows            # built into rsigma
sluice analyze ... --sigma-pipeline cim=./splunk-windows.yml   # a pySigma pipeline file
```

Use the pipeline your SIEM converts Sigma rules with: Sluice then proves the rule the SIEM runs.
The built-in names are `ecs_windows`, `sysmon` and `fibratus_windows`; at most one pipeline per
`schema`, and pipelines that depend on the source (`${source.*}`) are refused.

For any other source, a Sigma rule that applies to it (by its log source) is read as reading
every field of every event, so no field it could read is removed from that source: the report says
`names its fields as sigma does, the records use ecs`. This is the safe direction. Declaring
`sigma` for records that use other names is not: a rule would then look as if it read nothing,
and Sluice would remove what it reads. The same holds for a pipeline other than the SIEM's.
Elastic's detection rules name ECS fields and Splunk's searches the fields Splunk extracts, so
they are compared with sources that declare `ecs` or `splunk`, and on any other source read as
reading every field of every event (ADR 0025, ADR 0026). Wazuh and Sentinel rules relate their
own field names to the data and are not affected.

Text sources have no field names until the SIEM parses the line. A Sigma rule that tests a named
field therefore keeps every line of its log source whole (`fields the SIEM parses out of the
line`); a keyword rule is matched against the line as it is.

## Commands

| Command | What it does |
|---------|--------------|
| `sluice demo` | Generates an hour of synthetic traffic with planted attacks and runs the whole analysis on it. `--elastic-native`, `--fluent-bit-native`, `--otel-native`, `--llm` and `--mode` as for `analyze`. |
| `sluice analyze --input DIR --sources FILE --rules DIR` | Runs the analysis on your sample (`DIR/<source>.ndjson`) and writes the files below. `--wazuh-rules` (with `--wazuh-decoders` to bound them), `--wazuh-api` (logtest spot check), `--sentinel-rules` with `--kusto` and `--sentinel-table` (proof in the Kusto emulator; add `--sentinel-native` for a proven DCR `transformKql` per table, and `--sentinel-dcr RULE.json` to have it written into that rule together with an untransformed flow into an Auxiliary archive table, ADR 0013), `--elasticsearch URL` (runs the Elastic rules in the proof, ADR 0025) with `--elastic-native` (an ingest pipeline per source, proven there, ADR 0024), `--fluent-bit CMD --fluent-bit-native` (a Fluent Bit Lua filter per source, proven in Fluent Bit, ADR 0027), `--otel-collector CMD --otel-native` (OpenTelemetry Collector transform statements per source, proven in the collector, ADR 0028), `--elastic-rules DIR` (Elastic Security detection rules as Kibana exports them, ADR 0025), `--splunk-rules DIR` (Splunk's `savedsearches.conf` and `macros.conf`, ADR 0026), `--sigma-pipeline`, `--recipes`, `--llm` are optional, and `--mode` picks the kinds of saving (`rules`, `implied` or both, the default), and `--no-examples` leaves the sample's events out of the report. Summaries need a complete rule set: fetched, or `--rules-complete`. |
| `sluice prove --config FILE --input DIR --sources FILE --rules DIR` | Proves a Vector configuration as it is, on a sample: exit 1 when the rules' alerts on what it forwards differ from those on the full sample, or when the sample raises no alert (`--allow-no-alerts` accepts that). `--json` for CI; `--sentinel-rules`, `--kusto` and `--sentinel-table` as for `analyze` (ADR 0022). |
| `sluice connect sentinel --out DIR …` | Writes Sentinel tables and data collection rules as files; it changes nothing in Azure. `--sample FILE --table NAME` (with `--time-field F` for `TimeGenerated`) derives a custom table `NAME_CL` and its rule; `--summary-table` writes the table `SluiceSummary_CL`, its rule and the function `SluiceCounts.kql` (ADR 0029). `--workspace ID` and `--location` fill in the rules. |
| `sluice recipes [schema \| export --out DIR \| contribute --from DIR --into REPO]` | Lists the built-in recipes, prints their JSON Schema, exports them to edit, or copies the recipes an AI proposed and the proof kept (`OUT/ai-recipes` from `analyze --llm`) into a recipe repository, checked. |
| `sluice rules fetch --out DIR sentinel\|wazuh\|elastic\|splunk …` | Reads the rules a SIEM runs from its API, read-only, into `DIR` with an `inventory.json` that marks them complete (ADR 0021). For Sentinel also every workspace function, and `tables.json`, the tables the workspace has: a rule reads nothing through any other (ADR 0031). Fetching again replaces the directory. |
| `sluice rules requirements --rules DIR` | Prints, as JSON, what each rule needs: log source, fields, raw text, state. Also for Wazuh (`--wazuh-rules`), Sentinel (`--sentinel-rules`), Elastic (`--elastic-rules`) and Splunk (`--splunk-rules`) rules. |

## What Sluice writes

`sluice analyze` and `sluice demo` write into `--out` (default `out/`):

| File | What it is |
|---|---|
| `report.html` | The advice, as one page without scripts ([an example](example-report.html), for OTRF's APT29 attack data and eight rules written for it). A paragraph on what it means, for readers without context; the saving at a glance, per mode, with how many summary records counted events become; what "implied" means, with this sample's largest implied value and, per source, the values that are the same on every kind of event (to check on a one-machine sample); the kinds of event that make 90 % of the saving, largest first, each with what to change, the fields removed on the sample with their bytes, why each may go and where it can run, and how counting works where events are counted; savings by source; what the SIEM still receives: per source up to 10 events as they are sent, one of each kind of event first, as a table that scrolls sideways with one column per field, each cell the value sent, the value left out with its reason (implied, repeats the event, empty) or a dot, and each event's JSON folded below (from your own logs these are your real values, long text cut; `--no-examples` leaves them out before you share the report); and, folded away, the smaller savings, the kinds of event sent unchanged with their reasons, every rule next to what Sluice made of it, and the problems. |
| `rules.json` | That list of rules, for tools. |
| `plan.json` | The savings plan (`sluice.plan/1`): per source and kind of event what may be removed or counted, the implied values (`remove_implied`: a field absent from a forwarded event holds the value given), which events keep every field, where the saving can run (`runs_in`), and the proof (ADR 0023). |
| `vector.yaml` | A Vector configuration that carries out the whole plan, with Vector unit tests drawn from the sample. Per source it reads a file and has three sinks: the archive, what is forwarded, and the summaries. |
| `sentinel/` | With `--sentinel-native --sentinel-dcr RULE.json`: `dcr.json`, that rule with each proven `transformKql` and an untransformed flow into an Auxiliary archive table; the archive tables (`*.table.json`); each transformation (`*.transform.kql`); and, where the rule empties implied values, `<Table>Full.kql`, a function to save in the workspace that puts them back. |
| `elastic/SOURCE.pipeline.json` | With `--elastic-native`: an ingest pipeline per source. |
| `elastic/SOURCE.runtime.json` | With `--elastic-native`, where the pipeline removes implied values: runtime fields that put them back when a query runs, each shadowing the field of its name. Use them as a search's `runtime_mappings` or as runtime fields of a Kibana data view, and query the field itself (`Mode`, not `Mode.keyword`). Proven on the sample: they read every forwarded document as they read the full one. Each has the type of its values: `keyword`, `long` or `boolean`. |
| `fluent-bit/SOURCE.lua`, `fluent-bit/filters.conf` | With `--fluent-bit-native`: a Lua filter per source, and the filter sections to add to the agent's configuration. |
| `otel/processors.yaml` | With `--otel-native`: a `transform` processor per source. |
| `ai-recipes/` | With `--llm`: the recipes the AI proposed and the proof kept, for `sluice recipes contribute`. |

A native configuration is written only for sources where it removes something, and only after
its engine showed that it removes nothing the proven Vector configuration keeps and that the
rules raise the same alerts. What it cannot express (text templates, counting) is listed and
left to a pipeline tool.

## Sentinel rules in the proof

With `--sentinel-rules DIR --kusto URL --sentinel-table SOURCE=TABLE` (a Kusto emulator;
`scripts/kql-check.sh` starts one in Docker), the proof loads the sample of each named source,
full and forwarded, into the emulator as that table's records and runs every rule's query on
both. Any difference in the result rows fails the proof. Rules that cannot run in the emulator
are listed. Without `--kusto`, their requirements still constrain every saving, but the proof
runs only the other engines (Sigma, and Elastic's rules with `--elasticsearch`).

Point `--sentinel-rules` at the rules your workspace actually runs: a rule that reads
`EventData` on every event keeps it on every event. Include the ASIM parsers
(`Parsers/ASim*/Parsers` and `ASIM/lib/functions` from Azure/Azure-Sentinel) in the same
directory: rules that use a parser are then bounded by what the parser reads, instead of by
every Windows table ([ADR 0015](adr/0015-sentinel-analytics-rules.md)).

## Why is nothing saved?

The report lists, per kind of event, every reduction that was refused or narrowed, and why
(open the kind of event; those with no saving at all are under "Sent unchanged"). The common
reasons:

- **"no recipe"**: no community or own recipe matches the template. Write one
  ([recipes/README.md](../recipes/README.md)) or use `--llm`.
- **"rare … so nothing is saved on it"**: the template has fewer than 100 events, or less than
  0.1 % of its source, in the sample. A larger sample fixes this.
- **"may read any field"** or **"could match any event"**: a rule whose fields or matches cannot
  be bounded (an unparsable rule, or a keyword search Sluice cannot narrow) applies to the
  template. Check the **hints**: often the rule only applies because the source's log source is
  incomplete.
- **"kept: … rule tests could apply"**: so many rules apply that testing them per event would
  cost more than it saves. Describing the source more precisely reduces the number.
- **"not summarized: the rules are not known to be complete"**: Sluice was not told that its
  rules are every rule and query the SIEM runs, so it only makes savings that keep every event.
  Fetch them
  with `sluice rules fetch`, or pass `--rules-complete` (ADR 0021).
- **"fields the SIEM parses out of the line"**: a Sigma rule tests named fields on a text
  source; Sluice cannot see how the SIEM parses the line, so the lines stay whole (ADR 0020).
