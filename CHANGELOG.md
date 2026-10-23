# Changelog

All notable changes to Sluice are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-23

First public version, an alpha. Linux only (x86_64 and aarch64), including WSL2: one static
binary per architecture, with its SHA-256 sum.

### What 0.1.0 does

- **Reads the rules your SIEM runs**, read-only: `sluice rules fetch sentinel|wazuh|elastic|splunk`.
  Sigma rules from a directory stand in for any other SIEM.
- **Analyzes a sample** of your data (`sluice analyze`): groups it into kinds of event, proposes
  savings from community recipes (and optionally an AI model), narrows them with the safety
  contract, and proves that the rules raise exactly the same alerts on what would still be sent.
- **Writes the advice and the configurations**: `report.html` (largest saving first, with the
  proof), `plan.json`, `vector.yaml`, and on request a Microsoft Sentinel data collection rule,
  an Elasticsearch ingest pipeline, a Fluent Bit filter or OpenTelemetry Collector statements,
  each proven in its real engine. Sluice changes nothing itself.
- **Proves a configuration again in CI**: `sluice prove` and its GitHub Action.
- Proven against the real product: Microsoft Sentinel (end to end on a live workspace), Elastic
  Security, Wazuh, Vector, Fluent Bit and the OpenTelemetry Collector. Experimental: Splunk, and
  rules read from files instead of fetched.
- `sluice demo` shows it all on synthetic data in a minute.

Documentation: the README has a guide per SIEM; `docs/architecture.md` has diagrams of the
analysis and of what each configuration does, and one Windows event followed through every step;
`docs/glossary.md` explains the terms.

Nothing was released before 0.1.0. The sections below record how this version was built, in the
order it happened, including features that were removed again before the release; "Breaking"
marks a change between two development states.

### Advice only

- Sluice only looks, advises and writes the configurations. It never runs in the data path, so
  it does not become the kind of pipeline platform it means to make unnecessary (ADR 0030).
  What stays: `sluice rules fetch` and `rules requirements`, `sluice analyze` and `sluice demo`
  with the report, `plan.json`, `vector.yaml` and the native generators, `sluice recipes`,
  `sluice prove` with its GitHub Action, and `sluice connect sentinel`.
- Built during development and removed before the release (first moved to `archive/`, then
  deleted; the code is in the Git history): `sluice up` (crate
  `sluice-server`, with its console, operator actions, single sign-on, proposals and
  `--reload-rules`), `sluice status`, `sluice search` and `sluice replay` (crate
  `sluice-archive`), `sluice mcp` (crate `sluice-mcp`), `sluice agent`, `sluice connect
  sentinel --standard-table` with the VRL that shaped records for Sentinel's standard tables
  (`Syslog`, `CommonSecurityLog`, the ASIM tables, `SecurityEvent`, `WindowsEvent`), which only
  `sluice up` and `sluice agent` ran (2026-10-18), the `sluice up` configuration keys (`shape`,
  `sluice_rules`, `sluice_records`, `sluice_formats`, `sluice_sources`), the Helm chart, the
  container image, `examples/up`, `examples/docker`, `scripts/helm-check.sh`, `scripts/live-smoke.sh`, `scripts/replay-smoke.sh`,
  `scripts/load-test.sh`, `scripts/real-data/send-sentinel.sh`, the live cycle and recipe
  lifecycle of `sluice-autopilot`, `sluice prove --profile` and the diagrams of the live design.
- **Breaking:** `sluice connect` takes `sentinel` only and writes files only: `--sample` with
  `--table`, and `--summary-table`. It no longer prints a destination.
- The entries below record what was built, the archived features included. The documentation
  describes the advice-only product; `docs/architecture.md` now draws its diagrams in Mermaid,
  since the SVGs show the live loop.

### Fixed in the 2026-10-17 review

- A rule file whose name ends in `inventory.json` (such as `rules-inventory.json`), at any
  depth under `--elastic-rules` or `--splunk-rules`, was skipped as if it were the fetch
  manifest, so its rules protected nothing. Only the manifest itself is skipped now.
- What a fetch could not model (Kibana's or Splunk's counts, enabled ML rules, `KV_MODE`) is in
  the report for Elastic and Splunk too, not only for Wazuh and Sentinel.
- `sluice rules requirements --sigma-pipeline` prints the fields the cuts are checked against.
- A Sentinel transformation no longer panics on a column name with a control character (the
  records stay as they come), empties a boolean column with `bool(null)` instead of
  `boolean(null)`, which data collection rules refuse, and leaves a column without a typed null
  (`timespan`) out.
- A rule that matches raw text (a bare Splunk term, `_raw`, `rex`) protected only the fields
  discovery marks as text on a JSON record. Its raw text is the whole serialized record, so a
  term can match any value: such a rule now protects every field of a JSON record, on the
  events its pre-filter may match.
- A network value (`source.ip: 10.0.0.0/8` in Elastic KQL, `src=10.0.0.0/8` in SPL) was read as
  text, while both engines match addresses in the network: it now widens to the field having a
  value.
- `sluice rules fetch elastic|splunk` without credentials names both ways to give them.
- **Breaking:** `sluice prove --profile` and the Action's `profile` input are gone; rule profiles
  were a `sluice up` setting.

### Fixed in the review, 2026-10-18

- **The native generators no longer hand a record to the wrong template.** A discriminator the
  engine could not render as VRL does (a number 0, a fraction, one of 10^15 or more, and in
  OTTL a null for `""`) made its test false. A later template with the same key set then took
  the record and removed fields Vector keeps. The Lua filters, ingest pipelines and OTTL
  statements now stop the search there, and nothing is removed. In a Sentinel transformation, a
  template it cannot recognise blocks the groups its records could fall into. In an ingest
  pipeline, a template with a field named like Elasticsearch metadata does the same. OTTL no
  longer compares `0` as a number, because that also took `-0.0`.
- **Sentinel rules on custom tables.** `search`, `find`, `union *`, `table()`, ASIM parsers and
  unknown functions were bounded to records shaped for the standard tables. They may read custom
  tables too, so they now keep every row. A function that reads only a custom table now counts
  for the rule that calls it.
- **Fields parsed from a text line.** On a text line, a rule in the SIEM's own field names
  (Wazuh's decoder outputs, the columns Sentinel's agent fills) tests fields the line does not
  have. The rule is now bounded by its keyword tests only, and it reads the line.
- **Wazuh rule attributes.** `maxsize` (rule 1003) now reads every field: removing one may bring
  an event under the size. `ignore` is stateful. An unknown attribute widens the rule.
- **Splunk.** A value written as a function (`user=CASE(Admin)`) was read as the word `case`. It
  now needs only its field.
- **Elastic KQL numbers.** `a : 4.0` required the text `0`, which a stored `4` lacks. A number
  now tests its significant digits, as Elasticsearch compares numeric fields by value.
- **Sigma pipelines.** A rule's copy mapped onto the records' naming convention stood in for the
  rule even where the copy's log source could not apply (after `change_logsource`), so the rule
  protected nothing there. The copy now counts only where it can apply.
- **Sentinel workspace functions in lower case.** Only a call with an upper-case letter counted
  as a workspace function. Now a lower-case call where only a tabular function can stand
  (`| invoke f()`, a statement that starts with `f()`) widens the rule as well.
- **Rules Sluice could not read** show as "not read" in the report whatever their id says, and
  an unreadable Elastic rule keeps its name.
- **Flags that did nothing are refused**, naming what is missing:
  - `--fluent-bit` and `--otel-collector` without their `--*-native`;
  - the demo's `--elasticsearch` without `--elastic-native`;
  - `--wazuh-user` and `--wazuh-insecure` without `--wazuh-api`;
  - `analyze --elasticsearch` with neither `--elastic-rules` nor `--elastic-native`.
- **One HTTP client** (`sluice-http`) for every adapter. A large Azure query log is no longer cut
  off at 10 MB, refusals quote a short excerpt instead of whole answers, and the Kibana space is
  percent-encoded.
- **The Sentinel proof** matched transformed records with the sample's events by position, which
  a data flow's own `where` shifts. Records are now matched by row number. Every column a record
  loses is checked, and dropped or added events are refused.
- **The Elasticsearch proof** also refuses a pipeline that changes a value.
- **Error messages.**
  - Errors from Elastic and Kibana name the URL and give the answer's reason in short; they no
    longer say "refused the pipeline" for a bad Kibana key.
  - Wazuh errors show Wazuh's own message.
  - `connect --sample` numbers lines as an editor does.
  - A missing `--sigma-pipeline` file is named.
- **Kibana fetch.** Reading the rules ends when a page adds nothing new.
- **Report.** "N rules loaded" and `plan.json`'s `proof.rules` count each rule once: a Sigma
  rule mapped through a pipeline, or an Elastic rule per index pattern, has several
  requirements. A rule is a coverage gap only when none of its requirements sees data.

### What the workspace knows, and problems as data (2026-10-18)

- **A fetched Sentinel workspace bounds its rules by the tables it has** (ADR 0031). `sluice
  rules fetch sentinel` also writes `tables.json`, the tables the workspace has. A rule, or a
  parser branch, over a table that is not there reads nothing; before, a custom table nobody
  created (`CiscoMeraki_CL` in an ASIM parser) kept every row of every source. The tables
  `--sentinel-table` names count as existing. Without the list (a role that may not read it,
  rules from files) every table counts as existing, as before.
- **Lower-case workspace functions.** In a fetched inventory, a lower-case call that is none of
  the workspace's functions is KQL's own, wherever it stands. For rules from files, the
  lower-case names Sluice could not check are listed in one problem, with how to make sure.
- **Problems are data** (`sluice_core::problem`): each has a kind and, where it has one, its
  rule. The report groups them and says per kind what to do. A function whose source is missing
  is listed once, with the rules that call it and how to give its source (a YAML file with
  `FunctionName` and `FunctionQuery`, or `sluice rules fetch sentinel`); the command line says
  the same in one line.
- **Rule ids are written in one place** (`RuleId::of`, `RuleId::unreadable`). Sigma's stand-in
  for a document that does not parse is `sigma:unreadable:N` (was `sigma:unparsed:N`), and a
  Wazuh rule without an id `wazuh:unreadable:FILE#RULE` (was `wazuh:unknown:N`, which two files
  could share). Sigma rules that share an id are reported: the proof cannot tell their alerts
  apart.
- **Case-insensitive tests** are folded by one function for every generator
  (`codegen::folded_values`); OTTL and KQL now compare the lowercased values too, which match
  the same.

### Before the first release (2026-10-22)

- `archive/` is deleted, with the notes only it needed (`docs/notes/mcp.md`, `docs/notes/oidc.md`).
  The code stays in the Git history (ADR 0030, update of 2026-10-22).
- **Security:** `rustls-webpki` 0.103.16 and `webpki-roots` 1.0.10 (RUSTSEC-2026-0382 and
  RUSTSEC-2026-0381). The older versions could trust certificate paths through distrusted emSign
  intermediates, whose private keys are public. This affects every HTTPS connection Sluice
  makes: the rule fetches, the sample checks and the AI advisor.
- **`--sentinel-dcr` reads the Azure CLI's export.** `az monitor data-collection rule show`
  prints the rule with its `properties` flattened into the top level, and the README's deploy
  step failed on it ("no data flow into Microsoft-SecurityEvent"). Both shapes are read now, and
  the rule is written in the shape `az rest --method put` sends back. Found by following the
  README on a live workspace.
- **The report reads as advice.** It opens with what it means for a reader without context
  (savings on data no rule uses, a full copy kept, nothing changes until it is deployed), the
  saving at a glance, then the kinds of event that make 90 % of the saving, largest first, each
  with what to change, the fields removed on the sample with their bytes, and why. Savings by
  source follow as coloured bars; smaller savings, data sent unchanged, the rules and the
  problems are folded away. Bytes show in the largest unit below 1,000 ("8.7 MB", not
  "8703 KB"), rounded as the command line rounds them, and a reason two adjustments share is
  listed once. `Proof::removed` records, per kind of event, which fields the data plane removed.
- **Words.** The report and the documentation speak of savings, not cuts: contract rule 4 reads
  "rare events are never saved on", and a rare kind of event says "so nothing is saved on it".
  The summary line names every file an analysis writes, `rules.json` included. The README's
  Sentinel deploy step says what the first run of the Azure CLI installs, what to do when the
  new archive table is not ready yet, and that a changed rule can take ten minutes to apply.
- **Wazuh `maxsize` verified** with `logtest` on Wazuh 4.14.0. A rule with `maxsize` fires on the
  size of the whole event, JSON lines included, so reading it as a rule on every field is right.

### Trying it on your own SIEM (2026-10-19)

- The README has a guide per SIEM, for Microsoft Sentinel, Wazuh and Elastic Security. Each one
  creates a read-only account, fetches the rules, exports a sample, analyzes and deploys. The
  Wazuh and Elastic steps were checked against Wazuh 4.14.0 and Kibana 9.1.0; the accounts they
  create may read and nothing else.
- `scripts/real-data/collect-elastic.sh` exports an Elasticsearch index pattern as a sample, and
  `collect-sentinel.sh` takes the tables to export.
- **Wazuh's rate limit.** The manager allows 300 API requests a minute, and the fetch reads one
  file per request: with a few files more than the stock ruleset's 289, or a second fetch
  within the minute, it failed with HTTP 429. The fetch and the `logtest` spot check now wait a
  minute and try again, up to three times.

### Offline autopilot

- `sluice demo` and `sluice analyze`: template discovery (JSON key sets, Drain for text with
  BSD and ISO syslog headers), community recipes, guardrails, shadow proof against Sigma rules,
  `report.html` and a `vector.yaml` with Vector unit tests.
- Sigma rules via rsigma, including correlations and filters; Wazuh `rules.xml` requirements,
  read as leniently as Wazuh reads them and bounded by decoders (`--wazuh-decoders`) and
  `<if_sid>` chains (including literal `prematch`, `<category>`, `<if_fts/>`, and rules that
  only ever see syslog lines, so they do not hold JSON templates). A `<match>`/`<regex>` rule
  that may see JSON reads every field, since Wazuh matches it against the whole JSON line,
  keys included (verified with `logtest`); an optional live Wazuh
  `logtest` spot check (`--wazuh-api`), with text sources sent as raw lines.
- An optional AI advisor (`--llm`: Anthropic, Ollama, LM Studio, any OpenAI-compatible API) with
  redacted samples. Its proposals pass the same guardrails as any other.
- Guardrails scope rules by log source and per template, protect what a rule reads only on events
  the rule could match, and support complete log sources (ADR 0009). `sluice analyze` hints at
  sources whose description keeps extra rules in scope.
- Field names are part of the safety contract (ADR 0018): a source declares the convention its
  records follow with `schema` (`sigma`, `ecs`, `cim`, `asim`, `ocsf`, `udm`, `sentinel`,
  `splunk`). A Sigma
  rule is compared with a JSON source only when it declares `sigma`; for any other value, or none,
  the rule is read as reading every field of every event of its log source, so nothing it could
  read is cut (`names its fields as sigma does, the records use ecs`). Before, such a rule was
  ruled out and a summarizing recipe could take its matches while the proof compared two empty
  alert sets. Sources with a `shape` follow the shape's convention; `sluice analyze` and
  `sluice up` hint at JSON sources that declare none.
- Templates follow the kind of event (ADR 0019). Text templates split where only a few words
  alternate, so sshd's `Accepted` and `Failed` lines no longer share one and rare failures stay
  rare; Cisco message ids (`%ASA-6-302013:`) keep their digits. JSON sources take extra
  event-type fields with `event_type`, with defaults for AWS CloudTrail, Okta, Microsoft 365,
  Azure, Google Cloud and Kubernetes. One kind of JSON event shares a template across its
  frequent key sets (with and without an optional field), while a rare key set keeps its own;
  an agent update that adds a field no longer sends every recipe of its source back to shadow.
- Sigma processing pipelines (ADR 0020): `--sigma-pipeline ecs=ecs_windows` (a pySigma pipeline
  file, or one built into rsigma) maps every Sigma rule onto a convention, so an ECS source is
  cut where no mapped rule can match, and the proof runs the mapped rule. A Sigma rule that tests
  named fields keeps a text source's lines whole, since the SIEM parses those fields out of the
  line (`fields the SIEM parses out of the line`); keyword rules are compared as before.
  Summary keys are read where a shaped record keeps them, `EventData` object or XML included, so
  `SecurityEvent` summaries no longer lose their keys.
- The rule inventory comes from the SIEM (ADR 0021). `sluice rules fetch sentinel` reads a
  workspace's enabled analytics rules, hunting queries, workspace functions and, with
  `--query-log-days`, the queries people ran; `sluice rules fetch wazuh` reads the rule and
  decoder files the manager loads. Both are read-only and write an `inventory.json`.
  **Breaking:** events are only summarized (L2, L3) when every rule set is complete: fetched, or
  claimed with `--rules-complete`; otherwise Sluice makes lossless cuts only
  (`not summarized: the rules are not known to be complete`). `sluice analyze` takes
  `--sentinel-rules`, `--kusto` and `--sentinel-table` to prove against Sentinel rules and
  queries in the Kusto emulator, as `sluice up` does.
- **Breaking:** `sluice up` proposes instead of applying (ADR 0022). Proven configurations go
  to `<data_dir>/proposals` (`vector.yaml`, `proposal.json`); you deploy one by writing it over
  `vector_config`. Every cycle Sluice proves what runs and switches Vector to the safe
  configuration (everything sent unchanged) the moment that proof fails. `auto_apply: true`
  lets Sluice apply its own proposals, for demos and labs.
- Reports say when a proof is empty ("The sample raised no alerts, so this proof could not
  show that your detections still work."), on what grounds the rules count as complete, and
  list every rule next to what Sluice made of it ("Rules in the SIEM", `rules.json`).
  `sluice prove` fails an empty proof unless `--allow-no-alerts`.
- **Breaking:** `sluice mcp --allow-replay` is now `--replay-to URL` (repeatable): the replay tool sends only to the endpoints given at start, so an instruction injected in a log line cannot make an assistant send archived events elsewhere.
- Configurations as the product (ADR 0022). `sluice prove` proves a generated Vector
  configuration as it is, reading its programs back from the file, and exits 1 when it would
  change a detection; it refuses wiring Sluice did not generate. A GitHub Action
  (`action.yml`) runs it in CI. `proposals_dir` makes `sluice up` write proven configurations
  for review (`vector.yaml` and `proposal.json`) instead of applying them.
  `scripts/load-test.sh` measures a configuration on a stock Vector next to its savings.

### Live operation

- `sluice up`: Vector with a generated pipeline, a full-fidelity gzip archive, a sampled tap to the
  control plane, shadow, promotion, continuous re-proof and rollback, with SIGHUP reloads.
- `sluice status`, `sluice search`, `sluice replay` (ADR 0006).
- Per-destination proofs: `sluice_rules` on a destination names the rules its SIEM runs; each
  rule profile gets its own proof, lifecycle and Vector pipeline, so dual-shipping to Wazuh and
  Sentinel saves on the Sentinel side (ADR 0012).
- Operator actions (ADR 0016): hold or release a template, approve a recipe, keep a field of a
  source, acknowledge a rollback, from the console or `POST /actions`. Each is audited
  (`audit.ndjson`) and in the history; holds and kept fields survive restarts. Conservative mode
  (`promotion.approval: true`) enforces nothing without approval. `sluice mcp --allow-actions`
  offers the same actions to AI assistants. Named operator tokens (`operators_file`) and single
  sign-on with any OIDC provider (`oidc`, verified against Keycloak) let the audit log name who
  acted.
- A read-only web console at the control plane's address: overview with the proof, sources and
  templates by stage, per-template recipe, guardrail reasons, lifecycle and one real event before
  and after its recipe, and archive search
  (`GET /archive/search`). Built into the binary, no third-party assets, strict CSP (ADR 0011).
- `sluice connect` for Splunk, Elastic, Microsoft Sentinel, Google SecOps, Wazuh (JSON and raw-line
  files) and HTTP, validated against Vector 0.59.

### Collection agents

- `sluice agent windows`: the Vector configuration for a Windows host that sends Security
  channel events and every other channel to their own `sluice up` source; with `--dcr`, the
  Sentinel data collection rule that stores them unchanged (ADR 0014).
- `shape` on a `sluice up` source (`sentinel_security_event`, `sentinel_windows_event`): events
  are archived as they arrive, then shaped as the Sentinel table's record before the tap and
  the reductions.
- `sluice_sources` on a destination: only those sources reach it.
- The control plane needs about half the memory per windowed event: a cycle no longer copies
  the window, and the proof borrows events the data plane leaves unchanged.
- Guardrails: a rule's bare field also protects the same field nested under an object
  (`EventData.ScriptBlockText`), as Sentinel's `WindowsEvent` stores it.

- `sluice connect sentinel --sample FILE --table NAME --out DIR` derives a custom table
  (`NAME_CL`, typed columns from the sample, invalid names made valid) and the data collection
  rule that fills it, for sources without a standard Sentinel table; checked end to end with
  firewall, Linux auth and DNS records in a real workspace.

- `SecurityEvent` records carry `Account`, `AccountType`, `SubjectAccount` and `TargetAccount`
  (`DOMAIN\name`, `Machine` for names ending in `$`), which many Microsoft rules filter on.
- `shape: sentinel_asim_web_session` for web server access logs (combined-format lines or ECS)
  into `ASimWebSessionLogs`, for nginx, which has no Microsoft ASIM parser;
  `--standard-table asim-web-session`.
- `shape: sentinel_asim_dns` for DNS query records (ECS fields) into `ASimDnsActivityLogs`
  and `--standard-table asim-dns`; rules on the table apply and run in the emulator.
- `shape: sentinel_asim_network_session` for the same firewall records into the normalized
  `ASimNetworkSessionLogs` (ASIM values as Microsoft's parsers set them) and
  `--standard-table asim-network-session`; rules on the table apply and run in the emulator.
- `shape: sentinel_common_security_log` for firewall records: raw OPNsense/pfSense `filterlog`
  lines (CSV, inside syslog or not) and parsed records (flat `src_ip`/`dst_port` naming or ECS) and `sluice connect sentinel --standard-table common-security-log`; rules on
  `CommonSecurityLog` apply to such records and run in the emulator proof. Checked end to end.
- `shape: sentinel_syslog` on a `sluice up` source (Vector's `syslog` source or raw lines) and
  `sluice connect sentinel --standard-table syslog --out DIR` (the DCR into `Syslog`); Sentinel rules on
  `Syslog` apply to such records, and the emulator proof runs them. Checked end to end in a
  real workspace.

### Sentinel analytics rules (in progress)

- `SentinelRules`: Microsoft Sentinel analytics rules (KQL) as requirements: tables, fields,
  `EventID` pre-filters and statefulness, widening wherever the query is not understood
  (`sluice rules requirements --sentinel-rules`, ADR 0015).
- The proof runs Sentinel rules themselves: `sluice up --sentinel-rules DIR --kusto URL` loads
  each window, full and forwarded, into the Kusto emulator with the real `SecurityEvent` and
  `WindowsEvent` schemas and compares every rule's result rows. Destinations name the rule set
  `sentinel` in `sluice_rules`; rules the emulator cannot run (other tables, watchlists) are
  listed and still constrain cuts through their requirements.
- Sentinel rule files with several YAML documents are read per document, and problems name the
  file (a leading byte order mark is skipped); `EventID`s written as strings, and equality on
  `EventSourceName`, `Channel` and `Provider`, bound a rule.
- A Sentinel rule that reads an ASIM parser or calls a workspace function applies to every
  Windows source with unknown fields; it was treated as a rule on other tables (fail open).
  ASIM parsers and helpers whose source is among the rule files are resolved, so their callers
  get the parsers' bounds. `search` and `union *` read every table; columns named as strings
  (`column_ifexists`, `['X']`) are read.
- Recipes that drop `SecurityEvent`'s `EventData` XML for 4672 and 4798, where every data item
  has its own column.

### Native transformations (in progress)

- `sluice-kql`: pre-filters as KQL for Azure Monitor DCR transformations (Sentinel), compiled to
  match at least what Vector's VRL matches and checked against the Kusto emulator
  (`scripts/kql-check.sh`, ADR 0013).

### Security

- Destination credentials through Vector secret backends (`vector_secrets`, `SECRET[…]`); Vector
  0.59 does not expand `${VAR}` (ADR 0010).
- An optional bearer token for the control plane (`SLUICE_CONTROL_TOKEN`), handed to Vector as a
  secret file; without one, `sluice up` only listens on loopback.
- Hardening from the unit-test phase (`docs/testing-plan.md`, "Bugs found"):
  - The Sentinel client follows a `nextLink` only on its own host and never twice.
  - The client secret is kept out of error messages.
  - An alert rule without an `enabled` flag is read.
  - The Wazuh inventory fails when its file listing doesn't add up to the reported total.
  - `logtest` renews an expired JWT.
  - Rule directories with symbolic link loops are read once.
  - Rule files with upper-case extensions are no longer skipped.
  - Single sign-on refuses an `email` the provider marks as not verified.
  - Wazuh rule text keeps the spaces next to an entity or a bare `&` (`user &quot;root&quot;`).
  - In proposal mode, a deployed configuration Sluice cannot read switches to the safe one.
  - Sentinel destinations batch at most 900 KB: Azure refuses larger requests and Vector dropped
    them. `sluice up` sets the limit when a destination has none and refuses one above 1 MB.
  - A template's pattern and field names are redacted and fenced as untrusted in the AI prompt,
    like the samples (cached answers from the old prompt are not reused).
- `oidc.enabled` (default `true`) switches single sign-on off without removing its settings.

### Interfaces and packaging

- `sluice mcp`: an MCP server over stdio or bearer-token HTTP with `status`, `templates`,
  `explain`, `what_breaks`, `coverage_gaps`, `source_health`, `search_archive` and gated `replay`.
- `sluice recipes schema|export` and a JSON Schema for recipes; `sluice rules requirements`.
- Static musl binaries, a Docker image on Vector's distroless image, a compose example (ADR 0007),
  and a Helm chart.
- `plan.json` (`sluice.plan/1`, ADR 0023), written by `sluice analyze` and `sluice demo`: the
  savings plan for any tool, per source and kind of event what may be removed or counted, which
  events keep every field, where each saving can run (a pipeline tool, or also the SIEM's own
  ingestion), and the proof.
- `sluice analyze --sentinel-native`: per `--sentinel-table` source, a data collection rule
  `transformKql` that makes the plan's field removals in Sentinel's own ingestion, without
  Vector, written only after the Kusto emulator shows it empties nothing the proven data plane
  keeps and changes no alert of Microsoft's rules (ADR 0013). `--sentinel-dcr RULE.json`
  gives the data flow's stream and its own transformation; the result stays within the 15,360
  characters a rule takes. Tried in a real rule: Azure emptied exactly what the emulator did.
  With `--sentinel-dcr`, Sluice writes `sentinel/dcr.json`: that rule with every proven
  transformation in its table's flow and, next to each, an untransformed flow of the same stream
  into a `Sluice<Table>Archive_CL` table on the Auxiliary plan, defined in a `.table.json`
  (contract rule 2). Only tables where something is removed change, and a rule Sluice wrote
  before gets its part replaced, not doubled.
- `sluice analyze --elasticsearch URL --elastic-native` (and `sluice demo`): per source, an Elasticsearch ingest
  pipeline (`elastic/SOURCE.pipeline.json`, one Painless script) that makes the plan's field
  removals in Elastic's own ingestion, nested fields included, written only after the
  Elasticsearch at URL shows it removes nothing the proven data plane keeps and the Sigma rules
  raise the same alerts (ADR 0024, crate `sluice-elastic`). `scripts/elastic-check.sh` runs the
  differential tests against a real Elasticsearch; `check.sh` and CI run it.
- Elastic Security detection rules (`--elastic-rules DIR` for `analyze`, `up` and `rules
  requirements`; ADR 0025): Kibana's export or Elastic's prebuilt rules package, read for the
  ECS fields each rule names and a superset pre-filter from its KQL or EQL, scoped by its index
  patterns. ES|QL, Lucene and machine learning rules are read broadly; only enabled, current
  versions count. Destinations can name `elastic` in `sluice_rules`. With `--elasticsearch
  URL` the proof runs the rules themselves in Elasticsearch (EQL, ES|QL, and KQL and Lucene as
  the query Kibana builds), on full and on
  forwarded documents; `--elastic-native` (now a switch) proves its pipelines there.
- `sluice rules fetch elastic --kibana URL`: the detection rules of a Kibana space, as a
  complete inventory for `--elastic-rules` (ADR 0021, ADR 0025).
- Splunk saved searches (`--splunk-rules DIR` for `analyze`, `up` and `rules requirements`;
  ADR 0026): `savedsearches.conf` and `macros.conf`, or the REST API's JSON. Scheduled searches
  and correlation searches count; macros are expanded, the base search becomes a superset
  pre-filter, and every name in the pipeline may be a field the search reads. Subsearches,
  `tstats`, data models and unknown macros read everything. Fields are named as Splunk extracts
  them (new source `schema: splunk`). No engine runs them in the proof yet.
- `sluice rules fetch splunk --api URL`: the saved searches, macros, props and transforms of
  every app, through Splunk's REST API, as a complete inventory for `--splunk-rules` (ADR 0021,
  ADR 0026).
- Summaries in Sentinel get a table of their own (ADR 0029): `sluice connect sentinel
  --summary-table` writes `SluiceSummary_CL`, its rule, a destination for summaries and the
  `SluiceCounts` function, and a destination takes only the records it names
  (`sluice_records: [events]` or `[summaries]`). Before, summary records went to the events'
  table, whose rule dropped every field of them: the counts were lost.
- `sluice analyze --llm` writes the recipes the AI proposed and the proof kept to
  `OUT/ai-recipes`, as community recipes (matched by log source, schema and discriminators or
  pattern; no sample values), and `sluice recipes contribute --from DIR --into REPO` copies them
  into a recipe repository after checking them against the recipe book, never replacing a file.
- `runs_in` in `plan.json` and the report names the collection agent (`agent`: Fluent Bit, the
  OpenTelemetry Collector) next to the pipeline tool and the SIEM's ingestion, and no longer
  claims a text template's saving can run outside a pipeline tool (ADR 0023).
- OpenTelemetry Collector `transform` statements (`--otel-native` with `--otel-collector CMD`
  for `analyze` and `demo`; ADR 0028, crate `sluice-otel`): per source, OTTL statements that
  make the plan's field removals in the collector, for records whose body is the parsed JSON.
  Recognition counts each map's keys exactly (null ones too), keep-whole holds unless its test
  is false, and nothing is removed before everything is decided. Proven in a real collector;
  `scripts/otel-check.sh` runs the tests against otelcol-contrib 0.128.0, `check.sh` and CI run
  it.
- Fluent Bit Lua filters (`--fluent-bit-native` with `--fluent-bit CMD` for `analyze` and
  `demo`; ADR 0027, crate `sluice-fluentbit`): per source, a Lua filter that makes the plan's
  field removals in the agent, recognising records as Vector does and keeping whole every one
  a rule could match. Proven in a real Fluent Bit: nothing goes that Vector keeps, no other
  value changes, the rules raise the same alerts. A record the filter does not change is not
  touched. `scripts/fluentbit-check.sh` runs the tests against Fluent Bit 4.0.3; `check.sh`
  and CI run it.
- `sluice analyze --sentinel-native` for JSON sources in a custom table: `--sentinel-table
  SOURCE=<Name>_CL` with the rule `sluice connect sentinel --sample` wrote as `--sentinel-dcr`.
  The emulator holds the table as that rule fills it (renamed columns included), Sentinel rules
  on it run there, and Sluice's part runs before the rule's own renames (ADR 0013).
  `scripts/sentinel-custom-check.sh` proves it end to end; `kql-check.sh` runs it.
- `sluice up --reload-rules SECS`: rules fetched anew (`sluice rules fetch` on a timer) are
  loaded without a restart and guard from the next cycle on (ADR 0021). A fetch now replaces
  its directory in one rename, so no reader sees half of one.
- The proof of what Vector runs (proposal mode) now runs the Elastic rules too, when
  `--elasticsearch` is given; it ran Sigma and Sentinel only.
- A Sentinel rule on a custom table (`<Name>_CL`) applies to every source and keeps every
  record its query reads (ADR 0015). Before, it counted as a rule on tables no source has, so
  a JSON source sent to that table with `sluice connect sentinel --sample` was not protected
  by it. A column `connect` renamed (`user_agent` from `user-agent`) protects the field it
  came from too.
- Splunk's derived fields (`props.conf`, `transforms.conf`): a search's test on an alias tests
  what it copies, one on a computed, looked-up or extracted field matches every event, and the
  search reads what those fields are made from. Before, a test on such a field, which no record
  carries, would have let its events be cut.
- Recipes can name the field naming convention they are written in (`match.schema`, such as
  `ecs`); five ECS recipes drop the rendered `message` of Windows System, Application,
  Security and PowerShell events as Elastic stores them.
- Elasticsearch pipelines share keep-whole conditions across a source's templates and test
  `exists` exactly, so they fit Elasticsearch's script limit with large rule sets and save
  about what Vector saves.
- Pre-filters search an array's members instead of taking any array as a match, and take a
  float as a match only for a value a number could be written as: ECS documents, which always
  have arrays, are no longer kept whole by every keyword rule.
- Empty-field removal keeps a field a rule names on every event instead of keeping every event
  the rule may match whole (ADR 0009, decision 6).
- `sluice up` proposals carry the savings plan too: `plan-<profile>.json` per rule profile,
  exactly what the proposal enforces, named in `proposal.json`.
- The report says per kind of event where its saving can run.
- `scripts/real-data/`: collects real Windows, Linux and Sentinel events (kept outside the
  repository), sends Windows events through `sluice up` to a Sentinel workspace, and runs
  `sluice analyze` on them with SigmaHQ, the stock Wazuh ruleset and Microsoft's rules in the
  Kusto emulator.
- `sluice up --check`: validates a configuration and prints the Vector configuration it starts
  with, without starting anything.
- AGPL-3.0-only (ADR 0008).

### Documentation

- [Using Sluice](docs/usage.md): step-by-step paths from the demo to running in front of a SIEM,
  Microsoft Sentinel (Windows, syslog, firewalls, DNS, custom tables, proving against its rules),
  several SIEMs at once, the archive, MCP, AI recipes and deployment.
- [Architecture and technologies](docs/architecture.md): the parts, how an event travels through
  them, and what each is built on and why.

### Verification

- Quality gates: fmt, clippy (pedantic, warnings as errors), tests including property tests,
  docs, cargo-deny, and `vector validate`/`vector test` against the real Vector.
- Live smoke and replay tests against Vector; a differential test of rule requirements against
  pySigma on the full SigmaHQ rule set; a Helm chart check.
- Property tests for the safety claims: the guardrails alone (without the proof) keep every
  alert; hostile field names, values and text lines always compile and keep every alert; no
  rule, decoder, recipe, condition or time input makes a parser panic.

[Unreleased]: https://github.com/Dr1nS0menOp/SLUICE/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Dr1nS0menOp/SLUICE/releases/tag/v0.1.0
