# Changelog

All notable changes to Sluice are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

First public version (0.1.0). Linux only (x86_64 and aarch64), including WSL2.

Documentation: `docs/architecture.md` has diagrams of the data and decision paths
(`docs/images/*.svg`) and one Windows event followed through every step; `docs/glossary.md`
explains the terms.

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
  records follow with `schema` (`sigma`, `ecs`, `cim`, `asim`, `ocsf`, `udm`, `sentinel`). A Sigma
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
  - A template's pattern and field names are redacted and fenced as untrusted in the AI prompt,
    like the samples (cached answers from the old prompt are not reused).
- `oidc.enabled` (default `true`) switches single sign-on off without removing its settings.

### Interfaces and packaging

- `sluice mcp`: an MCP server over stdio or bearer-token HTTP with `status`, `templates`,
  `explain`, `what_breaks`, `coverage_gaps`, `source_health`, `search_archive` and gated `replay`.
- `sluice recipes schema|export` and a JSON Schema for recipes; `sluice rules requirements`.
- Static musl binaries, a Docker image on Vector's distroless image, a compose example (ADR 0007),
  and a Helm chart.
- `scripts/real-data/`: collects real Windows, Linux and Sentinel events (kept outside the
  repository) and runs `sluice analyze` on them with SigmaHQ, the stock Wazuh ruleset and
  Microsoft's rules in the Kusto emulator.
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
