# Glossary

The words the [architecture](architecture.md) and the console use, with the name the code and the
configuration use in brackets where it differs.

## Data and Vector

| Term | Meaning |
|---|---|
| **Source** (`source`) | A log stream you configure, such as `windows-security`. It has a log source (Sigma's `product`, `service`, `category`), a format (JSON or text) and the field naming convention of its records (`schema`). |
| **Data path** (data plane) | Vector: everything that happens to each single event, steps 1 to 7. |
| **Decision path** (control plane, `sluice up`) | Sluice: it looks at a sample and decides every five minutes what Vector does, steps A to H. |
| **Archive** (`archive_dir`) | A full copy of every event, written before anything changes it: gzip NDJSON per source and UTC hour. Safety contract rule 2. |
| **Shape** (`shape`) | Turning an event into the record a SIEM table stores, such as Sentinel's `SecurityEvent`. It runs after the archive, so the original is kept. |
| **Tap** (`tap_rate`) | A copy of one in ten events (by default) sent to Sluice. Sluice decides on this sample; Vector handles every event. |
| **Route** (`forward`, `summarize`) | What the generated program does with an event: forward it, whole or trimmed, or count it into a summary. |
| **Summary** | A count per minute, per template and per combination of the recipe's key fields. Rules never see summaries; the originals are in the archive. |

## Deciding

| Term | Meaning |
|---|---|
| **Window** (`window`) | The sample a cycle works on, per source: at most 20,000 events and an hour old. A cycle runs every five minutes. |
| **Template** | One kind of event in one source, such as `windows-security:5156:…`. For JSON: the values of its event-type fields and the key sets it comes in. For text: a Drain cluster, split where a few words alternate. Recipes target templates and the rarity floor counts them. |
| **Event-type fields** (`event_type`) | Fields whose value names the kind of event: `EventID`, `event.code`, `event.action`, `action`, product defaults such as CloudTrail's `eventName`, and a source's own. |
| **Drain** | An online algorithm that groups log lines into patterns; positions that differ become `<*>`, numbers `<NUM>`. |
| **Recipe** (`recipes/*.yaml`) | A proposal in YAML: which reductions for which kind of event. From the community, your own, or the AI advisor. Never trusted. |
| **L1, L2, L3** (`drop_fields`, `forward_matching`, `summarize`) | L1 removes fields or empty fields. L2 forwards what a rule could match and counts the rest. L3 only counts, for templates no rule sees. |
| **Rule** | A detection rule the SIEM runs: Sigma, Wazuh XML or Sentinel KQL. |
| **Requirements** (`requirements`) | What a rule needs from the data: the log source it applies to, the fields it reads, whether it searches free text, whether it counts events, and its pre-filter. |
| **Pre-filter** (`prefilter`) | Every event a rule could possibly match: wider rather than narrower. What Sluice does not understand counts as "every event". |
| **Field naming convention** (`schema`) | Which names a source's records use: `sigma`, `ecs`, `cim`, `asim`, `ocsf`, `udm` or `sentinel`. A Sigma rule is compared only with sources that declare `sigma`. |
| **Rule profile** (`sluice_rules`) | The rule sets a destination's SIEM runs. Each profile has its own proof, lifecycle and pipeline. |
| **Shadow, enforced, rollback** (lifecycle) | A proven recipe goes into shadow, where nothing changes yet. After 24 hours and 3 proofs in a row it is enforced. One failed proof rolls it back at once. |
| **Operator actions** (`POST /actions`) | Hold a template, approve a recipe, keep a field, acknowledge a rollback: from the console, the API or MCP, with an audit log. |

## Safety

| Term | Meaning |
|---|---|
| **Safety contract** | Unknown data passes through. Everything is archived first. Anything a rule could match is forwarded whole. Rare is never cut. Every cut is proven first. AI proposes, the guardrails decide. |
| **Guardrails** | The code that narrows a recipe to what the contract and the rules allow, and records why for every refusal. |
| **Effective recipe** (`EffectiveRecipe`) | What is left of a recipe after the guardrails. Only that is ever enforced. |
| **Rarity floor** | A template with fewer than 100 events, or under 0.1 % of its source, is never cut. A rare shape of a frequent kind of event keeps a template of its own. |
| **Conditional protection** (`keep_whole_when`) | A field a rule reads stays on every event the rule could match, and may be removed elsewhere. |
| **Proof** (shadow proof) | The rules run on the full and on the forwarded events. Only the same alerts, in both directions, count as proof. |
| **Fail closed** | When in doubt, cut nothing and forward everything unchanged. A rule Sluice cannot read counts as reading everything. |
| **Known limit** | A place where Sluice falls short today, listed in the architecture and addressed in PLAN.md (M9, M10). |

## Formats and integrations

| Term | Meaning |
|---|---|
| **VRL** | Vector Remap Language, in which Sluice writes shapes and reductions. The same code runs in Vector and in the proof. |
| **`vector.yaml`** (`vector_config`) | The configuration Sluice writes and Vector runs: the actual product, with tests. |
| **MCP** (`sluice mcp`) | Model Context Protocol: lets an AI assistant ask what was cut and why. |
| **DCR** | An Azure Monitor data collection rule: decides which columns reach a Sentinel table. `sluice connect sentinel` writes them. |
