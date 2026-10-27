# Glossary

The words the [architecture](architecture.md) and the report use, with the name the code and the
configuration use in brackets where it differs.

## Data and configurations

| Term | Meaning |
|---|---|
| **Source** (`source`) | A log stream you describe in the sources file, such as `windows-security`. It has a log source (Sigma's `product`, `service`, `category`), a format (JSON or text) and the field naming convention of its records (`schema`). |
| **Sample** (`--input`) | The events an analysis works on: one NDJSON file per source, an hour or a day of them. |
| **Analysis** (`sluice analyze`) | Sluice looks at the sample and the rules once and decides what the configurations do, steps A to F. It changes nothing itself. |
| **Data path** (data plane) | What your tool does with each single event, following the configuration Sluice wrote: in Vector, steps 1 to 5. Sluice is never in it. |
| **Archive** | A full copy of every event, written before anything changes it: in `vector.yaml`, a file per source and hour; in a Sentinel data collection rule, an untransformed flow into an Auxiliary table. An ingest pipeline or an agent filter cannot write one, so the copy is kept where the data is sent from (ADR 0024). Safety contract rule 2. |
| **Route** (`forward`, `summarize`) | What the generated program does with an event: forward it, whole or trimmed, or count it into a summary. |
| **Summary** | A count per minute, per template and per combination of the recipe's key fields. Rules never see summaries; the originals are in the archive. |
| **Summary record** (`sluice_count`) | What the SIEM receives for counted events: one record per summary, with the number of events it stands for. Its bytes count in what is sent, and the report gives how many there are. |
| **MCP** (`sluice mcp`) | The Model Context Protocol: how an AI assistant calls Sluice's tools, to read an analysis's advice and to prove what it drafts before a person deploys it (ADR 0035). |
| **Savings plan** (`plan.json`) | Per source and kind of event, what may be removed or counted, which events keep every field, where the saving can run (`runs_in`), the proof, and the problems reading the rules. Every configuration is built from the same proven selection. |
| **Native configuration** | A configuration in a tool's own language: a data collection rule `transformKql`, an Elasticsearch ingest pipeline, a Fluent Bit Lua filter or OpenTelemetry Collector `transform` statements. Field removals only, each proven in that tool. |

## Deciding

| Term | Meaning |
|---|---|
| **Template** | One kind of event in one source, such as `windows-security:5156:…`. For JSON: the values of its event-type fields and the key sets it comes in. For text: a Drain cluster, split where a few words alternate. Recipes target templates and the rarity floor counts them. |
| **Event-type fields** (`event_type`) | Fields whose value names the kind of event: `EventID`, `event.code`, `event.action`, `action`, product defaults such as CloudTrail's `eventName`, and a source's own. |
| **Drain** | An online algorithm that groups log lines into patterns; positions that differ become `<*>`, numbers `<NUM>`. |
| **Recipe** (`recipes/*.yaml`) | A proposal in YAML: which reductions for which kind of event. From the community, your own, or the AI advisor. Never trusted. |
| **L1, L2, L3** (`drop_fields`, `forward_matching`, `summarize`) | L1 removes fields or empty fields. L2 forwards what a rule could match and counts the rest. L3 only counts, for templates no rule sees. |
| **Implied value** (`drop_implied`, `remove_implied`) | A value the kind of event, or another field of the event, implies: `Channel: Security` on a Windows Security event. Removed only while the field holds exactly it (L1), so `plan.json`, Sentinel's `<Table>Full` and Elasticsearch's runtime fields can put it back (ADR 0032). A field named as an identifier is implied by the kind of event only, never by another field; an IP address or a port is never implied. |
| **Emptied object** (`Plan::emptiable_objects`) | A nested object whose every field the savings removed. It goes too, rather than being sent as `{}`; an object that came empty stays (ADR 0033). |
| **Mode** (`--mode`) | A kind of saving: `rules` (the recipes) or `implied` (implied values). Both run by default; the report gives the saving of each. |
| **Rule** | A detection rule or query the SIEM runs: Sigma, Wazuh XML, Sentinel KQL, or Elastic's KQL, EQL or ES\|QL. |
| **Rule inventory** (`inventory.json`) | The rules a SIEM runs, read from its API by `sluice rules fetch`. It marks the rule set complete, which summaries need. |
| **Requirements** (`requirements`) | What a rule needs from the data: the log source it applies to, the fields it reads, whether it searches free text, whether it counts events, and its pre-filter. |
| **Pre-filter** (`prefilter`) | Every event a rule could possibly match: wider rather than narrower. What Sluice does not understand counts as "every event". |
| **Field naming convention** (`schema`) | Which names a source's records use: `sigma`, `ecs`, `asim`, `ocsf`, `udm` or `sentinel`. A Sigma rule is compared only with sources that declare `sigma`, or with a pipeline that maps it. |

## Safety

| Term | Meaning |
|---|---|
| **Safety contract** | Unknown data passes through. Everything is archived first. Anything a rule could match is forwarded whole. Rare events are never saved on. Every saving is proven first. AI proposes, the guardrails decide. |
| **Guardrails** | The code that narrows a recipe to what the contract and the rules allow, and records why for every refusal. |
| **Effective recipe** (`EffectiveRecipe`) | What is left of a recipe after the guardrails. Only that goes into a configuration. |
| **Rarity floor** | Nothing is saved on a template with fewer than 100 events, or under 0.1 % of its source. A rare shape of a frequent kind of event keeps a template of its own. |
| **Conditional protection** (`keep_whole_when`) | A field a rule reads stays on every event the rule could match, and may be removed elsewhere. |
| **Proof** (shadow proof) | The rules run on the full and on the forwarded events. Only the same alerts, in both directions, count as proof; a recipe that changes an alert is left out. |
| **Fail closed** | When in doubt, remove nothing and forward everything unchanged. A rule Sluice cannot read counts as reading everything. |
| **Known limit** | A place where Sluice falls short today, listed in the architecture and addressed in PLAN.md. |

## Formats and integrations

| Term | Meaning |
|---|---|
| **VRL** | Vector Remap Language, in which Sluice writes reductions. The same code runs in Vector and in the proof. |
| **`vector.yaml`** | The Vector configuration `sluice analyze` writes: Sluice's programs, routes and summaries between sources and sinks you make your own, with tests. |
| **DCR** | An Azure Monitor data collection rule: decides which columns reach a Sentinel table. `sluice connect sentinel` writes them, and `--native sentinel` adds the proven transformation. |
