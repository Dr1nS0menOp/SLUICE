# Sluice — open-source autopilot for security data

Standalone project at `C:\Users\ward\SLUICE`. It has nothing to do with the homelab repo.
[CLAUDE.md](CLAUDE.md) has the conventions and [docs/adr/](docs/adr/) has the decisions.

**Decisions on 2026-10-09:**

- **Rust, not Python** ([ADR 0001](docs/adr/0001-rust-core.md)). The shadow proof runs the exact
  VRL that Vector enforces, through the `vrl` crate. Sigma runs at runtime through `rsigma`.
  pySigma is only a CI test oracle.
- **Linux only, WSL2 included** ([ADR 0003](docs/adr/0003-linux-only.md)). There are no Windows or
  macOS builds.
- **Dev environment.** Sources stay on Windows. Every cargo command runs in WSL through
  `scripts/wsl.ps1`, because Smart App Control blocks native builds.

**Decisions from the planning session (2026-10-08):**

- **Goal.** A free, open-source tool that makes Cribl-style pipelines and SIEM lock-in obsolete.
  Adoption and the open-source ecosystem matter; customers and money don't.
- **Must have:** a zero-work autopilot (no review/deploy/maintenance burden on SOC engineers); every
  SIEM *including Wazuh*; an MCP server; runs on a laptop or simple VM; scales out.
- **Rejected:**
  - Glovebox (AI-SOC agent containment gateway): too niche.
  - Detection-assurance tool: commercial tools already exist.
  - "Show-what-to-cut" planner: still creates work.
- **Runner-up:** an open-source Venafi/Keyfactor alternative, driven by 47-day certificates. Less
  SOC-centric.
- **Still open:**
  - License: decided, AGPL-3.0-only (ADR 0008).
  - ~~Install method for the Vector binary~~. Decided 2026-10-09: `scripts/install-vector.sh`
    installs the pinned release (0.59.0, which embeds `vrl` 0.36.0) into `~/.local` with SHA-256
    verification.
- **Style:** concise replies in chat (Dutch). Code and docs in English.

## Context

**User feedback on the previous plan (rejected):**

- A tool that *shows* what to cut still leaves the SOC engineer to review, deploy and maintain it.
  That is the very work to remove.
- Not a commercial product, so no customer focus.
- Must be open source, integrate with every SIEM including Wazuh, and be so good people abandon
  Cribl and SIEM lock-in.
- "Isn't finding fat in a dataset something you (the AI) are good at?" Yes, so let AI do the
  judging.

**Why people buy Cribl**

| Reason | Evidence |
|---|---|
| Cut SIEM bills | Packs for Windows, Palo Alto and others; a typical case cut ingest by about 25% (1 TB → 750 GB/day of Splunk) |
| Route anywhere, dual-ship | Run old and new SIEM in parallel during a migration; one migration went from 6 months to 3 weeks (Volkswagen, UKHS) |
| Cheap full copy plus replay | Raw data in object storage gives the confidence to cut |
| Shape data | Parse, normalize, enrich, mask |
| UX | Live data preview, Packs, Copilot Editor (AI writes pipelines from prompts), free up to 1 TB/day |

**What Cribl still makes people do:** decide what to cut, build pipelines (Copilot only helps write
them), and maintain them when formats change. A human owns every decision and every regression.
That is the opening.

**Sluice's answer:** an autopilot. The user points sources at it and connects their SIEM(s).
Sluice then discovers the data, decides what is fat, *proves* on their own traffic and rules that
no detection changes, enforces the cut, keeps verifying it, rolls back on its own, and adapts when
formats drift.

Strategically this attacks how SIEM vendors lock customers in:

- Data lives in the user's own archive.
- Sigma and rule-awareness keep detections portable.
- Dual-ship makes switching SIEMs trivial.
- Ingest volume (the bill) drops.

## Safety contract (non-negotiable, enforced in code)

1. **Unknown data passes through untouched.** Only known, verified templates are ever reduced, so
   format drift makes Sluice fail open for forwarding.
2. **Everything is archived at full fidelity before any cut.** Any slice can be replayed into any
   SIEM.
3. **Anything any rule could match is forwarded in full.** Every field a rule references, including
   fields in its `not filter` parts, is kept for that event type.
4. **Rare is never cut.** Attacks are rare; noise is repetitive. Templates below the frequency
   floor are always forwarded.
5. **Every cut is proven before it is enforced.** It runs in shadow against the user's traffic and
   rules, needs an identical alert set, and is re-verified continuously after enforcement. A
   mismatch triggers automatic rollback plus an event.
6. **AI proposes; guardrails decide.** AI output can never override 1–5.

## How fat is cut: three levels, safest first

**L1 Lossless (format fat).** This is the big, safe win and is enforced after a short shadow
(default 24h).

- Strip rendered boilerplate that duplicates structured fields, such as the Windows `Message`
  explanatory text. The Drain template's constant parts identify it.
- Drop empty or null fields.
- Remove duplicate representations: `event.original` next to parsed fields, multiple timestamp
  formats.
- Move per-host constant envelope fields (agent/os/cloud metadata) to a side table.
- Exact deduplication within a window.
- Detection-aware: if a rule matches on stripped text (Wazuh `<match>`, Sigma keywords), that text
  is kept.

**L2 Rule-guided (volume fat).** This targets high-volume event types such as Sysmon 7/10/3/22,
WFP 5156, firewall allows and CloudTrail read-only calls.

- Sluice compiles a **superset pre-filter** from all rules for that type. It is the OR of each
  rule's positive selections, with `not filter` parts ignored and unsupported modifiers treated as
  `true` (broadening is safe).
- Events that could match a rule are forwarded in full. The rest are archived and sent to the SIEM
  as **summaries**: counts per window per key (for example src/dst/port/action, or
  SourceImage/TargetImage/GrantedAccess), with an archive pointer for replay.
- **Aggregation and correlation** rules (Sigma correlations, Wazuh `frequency`/`timeframe`, Splunk
  `stats` thresholds) only count events their own conditions match. All of those are inside the
  pre-filter and are forwarded unchanged and in order, so they need no extra protection
  ([ADR 0004](docs/adr/0004-stateful-rules-and-routing.md)). Unbounded ones still forward
  everything.

**L3 AI-judged (semantic fat).** This covers templates no rule covers and that statistics plus AI
judge low-value, such as health checks, debug chatter and probes.

- Default action is archive plus summary, never a plain drop.
- Only allowed for frequent templates (the rarity floor applies), so it fits the safety contract.

## Where AI fits

**Build time.** Claude authors **community recipes** for the 15–20 most common security sources:

- Windows Security, Sysmon, Linux auth/sudo/auditd.
- Palo Alto, Fortinet, Cisco ASA, OPNsense/pfSense filterlog.
- Suricata EVE, Zeek, nginx/Apache.
- CloudTrail, Entra ID, M365, Okta, Kubernetes audit, DNS.

Most users then need **no AI key at all**. Recipes are tested against synthetic samples and, as the
user base grows, refined by the community. This is "Sigma for pipelines".

**Runtime, unknown sources only.**

- AI runs **once per new log template, never per event**, which keeps it cheap and fast.
- Providers: local models (Ollama, LM Studio; the default for privacy) or an API (Anthropic, or any
  OpenAI-compatible endpoint).
- Samples are redacted before any model sees them (format-preserving masking of IPs, users, hosts,
  tokens) and wrapped as untrusted data.
- Output is schema-constrained (enums) and covers: security value, field classes, a parser for
  unstructured templates, aggregation keys, and a rationale.
- The result compiles into a deterministic, versioned recipe that is cached and can be exported
  (values stripped) for contribution.

**Threat: log text is written by attackers** (see the Glovebox research). An attacker could craft
log lines that persuade the AI to call their activity noise. Mitigations:

- Guardrails always dominate the AI.
- L3 never applies to rare templates.
- A volume spike on any template emits an event.

## Lifecycle (zero-touch)

discover templates (Drain for text; keyset plus type fields for JSON) → resolve a recipe
(community, then local cache, then AI) → apply guardrails, giving the effective recipe → shadow
(proof) → auto-enforce → continuous verification → auto-rollback → drift detection (new template,
format change, silent source) → rediscover.

`autopilot: on` is the default. `conservative` requires one confirmation per recipe.

## Architecture

```
sources ──▶ Vector data plane (Rust, MPL-2.0; scaled out with the user's own tooling, ADR 0017)
  syslog, Splunk HEC (drop-in),      ├─ tap (sampled, pre-reduction) ──▶ Sluice control plane (Rust)
  Beats/Lumberjack, OTLP, Kafka,     ├─ archive sink (full fidelity)        templates+stats (SQLite)
  files, http                        ├─ effective recipes (VRL remap,       recipes, guardrails, AI compiler
                                     │   route, dedupe, reduce→summaries)   shadow + continuous verification
                                     └─ destinations (any/all SIEMs)        config compiler, status/MCP API
archive (disk / S3 / MinIO / Blob / GCS, NDJSON.gz partitioned dt/hour/source/template) ◀── DuckDB search, replay
```

The control plane works on a sampling budget, so its cost scales with the number of templates, not
the number of events. Throughput comes from Vector.

## Integration

| Area | v0.1 | Later |
|---|---|---|
| **Destinations** (Vector sinks) | Splunk HEC; Elasticsearch/OpenSearch (incl. Wazuh indexer); Microsoft Sentinel (`azure_logs_ingestion`); Google SecOps/Chronicle; CrowdStrike LogScale; Datadog; QRadar (syslog/LEEF); Graylog (GELF); Loki; Kafka; S3/Blob/GCS; Wazuh manager (syslog remote or JSON file for agent `localfile`) | — |
| **Rule awareness** | Sigma (rsigma, incl. correlations); Wazuh `rules.xml`; exact Wazuh verification via the Wazuh API `PUT /logtest` | Sentinel KQL (since M6, ADR 0015); Splunk SPL, Elastic, Chronicle YARA-L, QRadar AQL, read from the SIEM itself (M10; best effort, fail closed) |

**Wazuh specifics.** Agent→manager traffic uses Wazuh's own encrypted protocol, so Sluice sits
in two other places:

- Between non-agent sources (firewalls, cloud) and the manager's syslog input.
- Between the manager's filebeat output and the indexer, to reduce indexer storage.

Generating Wazuh decoders from recipes is v0.2.

**Sigma evaluation** uses `rsigma-eval`, which covers detections and correlations. Events are fed
with explicit timestamps, so proofs are deterministic. The alert sets over the full data and over
the forwarded data are then compared. In CI, a differential test checks rsigma against pySigma on
the same events.

**One implementation of each reduction.**

- Stateless reductions (strip, drop, keep, route and pre-filter) compile to VRL. The proof runs
  that VRL with the `vrl` crate, the same code Vector runs.
- Stateful operations (window dedupe, summaries) are Vector transforms, not VRL. Sluice models them
  in Rust, and the generated `vector test` cases check that model against Vector.
- Summaries never feed rules. Rules only see forwarded full events, so summaries can't change an
  alert set.

## v0.1 milestones

**M1 — Offline autopilot.** Fully demoable from a single `sluice` binary, with no network.

- `sluice demo` and `sluice analyze --input samples/ --rules rules/ [--wazuh-rules dir] [--llm none|ollama:<m>|anthropic:<m>]`.
- Pipeline: Drain/keyset discovery → community recipes → L1/L2/L3 → guardrails → shadow proof
  (Sigma via rsigma, with VRL executed by the `vrl` crate; Wazuh logtest if configured).
- Outputs: effective recipes, `vector.yaml` with generated Vector unit tests, and `report.html`
  (savings, proof, coverage gaps such as rules whose data is missing, source health).
- Synthetic generator (deterministic seed) producing realistic volumes and fat for Windows
  Security (with Message), Sysmon 1/3/7/10/11/22, sshd/sudo, firewall, DNS and nginx. It includes a
  few rule-matching events, e.g. LSASS-access pattern and failed-logon burst, that must survive.
- Self-written example Sigma rules (including one correlation rule) and Wazuh rules (including one
  frequency rule).

**M1 build order.** Each step ends green on all quality gates. Status 2026-10-09: all nine steps
done (AI: see `docs/notes/ai.md`).
Demo: 75.3% ingest saved, 41 = 41 alerts, reproduced exactly by Vector 0.59.

1. Workspace scaffold: lints, toolchain, `deny.toml`, CI, README, LICENSE.
2. `sluice-core` domain model and the safety-contract guardrails, with tests named after each
   contract rule.
3. `sluice-synth`: a deterministic generator for the demo sources and rule-matching attack events.
4. `sluice-discover`: Drain (text) and keyset (JSON) templates, plus frequency stats.
5. `sluice-rules`:
   - The Sigma adapter.
   - Rule requirements (referenced fields, including `not filter` parts).
   - The superset pre-filter.
   - Wazuh `rules.xml` requirements.
6. `sluice-vector`: reductions → VRL; VRL execution; `vector.yaml` and `vector test` generation.
7. The shadow proof in core: full vs forwarded alert sets, plus the property test.
8. `sluice-cli`: `analyze` and `demo`, plus `report.html`.
9. AI provider (L3) behind a trait, with `--llm none` as the default.

**M2 — Live.** Status 2026-10-09: the live control loop is done (ADR 0005): `sluice up`,
`sluice status`, shadow → promote → SIGHUP reload, continuous verification with rollback, and
`scripts/live-smoke.sh` against Vector 0.59. `sluice search` and `sluice replay` are done with a
streaming scan instead of DuckDB (ADR 0006). `sluice connect splunk|elastic|sentinel|chronicle|wazuh|http`
prints a destination whose sink `vector validate` checks in every gate run. M2 is complete.

- `sluice up`: generates the Vector config (sources, tap, archive, recipes, destinations), runs
  Vector (binary path), and starts the control plane (axum: tap ingest, config provider, status
  API).
- Online Drain and stats.
- Shadow → promote → regenerate → Vector reload.
- Continuous verification: on each tapped sample, compare the alert sets of full vs effective
  recipe, and auto-rollback on mismatch.
- `sluice search` (DuckDB over the archive) and `sluice replay --from --to --where --to <destination>`
  (archive → Vector `http_server` replay source → sink).
- `sluice connect wazuh|splunk|sentinel|elastic|...` writes destination and rule-import config.

**M3 — Interfaces and ecosystem.** Status 2026-10-09: `sluice mcp` serves `status`, `templates`,
`explain`, `what_breaks`, `coverage_gaps`, `source_health`, `search_archive` and gated `replay`
over stdio (rmcp 3.5.1, `docs/notes/mcp.md`). The recipe
spec is `recipes/recipe.schema.json`, generated from the parser's types (`sluice recipes schema`,
`sluice recipes export`). Packaging (ADR 0007): static
musl binaries for x86_64 and aarch64 via cargo-zigbuild, a Dockerfile on Vector's
distroless-static image, compose example, CI image build, draft releases on tags. MCP also runs over
streamable HTTP behind a mandatory bearer token (`--http`). The differential test against pySigma
covers all 3152 SigmaHQ rules. License: AGPL-3.0-only (ADR 0008). Real data (2026-10-10, this
machine's Windows System, Application and PowerShell logs, 22,448 events, all SigmaHQ rules):
23.8 % saved, 206 = 206 alerts, after conditional protection, per-template scoping and complete
log sources (ADR 0009). Real Linux logs of the Wazuh server (177,008 lines): 28.6 % saved.

- MCP server (`rmcp`, the official Rust SDK; stdio and HTTP) with these tools: `status`, `savings`, `sources`,
  `templates`, `explain`, `what_breaks`, `coverage_gaps`, `source_health`, `search_archive`
  (bounded), and `replay` (gated by `mcp.allow_replay`).
- `sluice status`.
- Community recipes for the top sources, plus a recipe spec and JSON Schema, plus
  `sluice recipes export`.
- Packaging:
  - Static Linux release binaries (musl, x86_64 and aarch64).
  - `cargo install sluice`.
  - Dockerfile and compose (Sluice plus Vector).
  - Docs.

**Also shipped in v0.1** (beyond the original milestones):

- Read-only web console at the control plane's address, with a before/after example per
  template and archive search (ADR 0011).
- Helm chart (`deploy/helm/sluice`), checked by `scripts/helm-check.sh`.
- Throughput benchmark: `scripts/bench.sh`, about 16k events/s per vCPU, near-linear to four
  threads (docs/notes/benchmarks.md).
- Wazuh: lenient rule files, decoders, `<if_sid>` chains, `<if_fts/>`, syslog-only rules skipped
  on JSON, and raw-text rules reading the whole JSON line, each verified with `logtest`
  (docs/notes/wazuh.md).

## Roadmap after v0.1 (added 2026-10-10)

The vision stays the same: an autopilot that cuts SIEM bills with zero work, for every SIEM, with
data and detections that stay portable. v0.1 proved the core on real data: 24% (Windows) and 29%
(Linux) less ingest against all of SigmaHQ, with an identical alert set. It also showed where the
model must grow:

- **Rules belong to the SIEM that runs them.** v0.1 applies every loaded rule to every
  destination. With the stock Wazuh ruleset loaded, nothing on a JSON event can be cut (generic
  rules such as 1002 read the whole line), so a Sentinel destination that never runs Wazuh rules
  also saves nothing. Each destination must be proven against its own rules.
- **Each platform has its own matching semantics.** Wazuh `<match>` sees keys and punctuation;
  Sigma keywords see values. A proof is only as good as the model of the engine, so every new
  engine needs a verified model and, where it exists, a differential test against the real one.
- **Reductions should run where the bill is.** Today Vector must sit in the path. Many teams
  cannot add a hop, but every SIEM has an ingest-time transformation language of its own.

The milestones below follow from that, in order. Each keeps the safety contract unchanged, and
each ends with the same release bar as v0.1: gates green, a real-data run, docs and an ADR.

**M4 — Per-destination proofs.** Each destination names the rule sets its SIEM runs
(`rules: [sigma, wazuh]`, default: all loaded). The guardrails and the proof run per
destination, and Vector gets one route and one effective recipe per destination, all fed from
the same archive. Dual-shipping to an old and a new SIEM then saves on each side independently.
Done when: a Wazuh plus Sentinel run saves on the Sentinel route while the Wazuh route stays
proven, and the console and MCP show savings per destination.
Status 2026-10-10: done (ADR 0012). `sluice_rules` on destinations, one proof, lifecycle and
Vector pipeline per profile, `/status?profile=`, a profile picker in the console,
`sluice status --profile`, and a `profile` parameter on every MCP tool that reads the status.
The two-profile configuration passes `vector validate` (0.59); the single-profile path is
unchanged (live smoke test); `examples/up/sluice-dual.yaml` shows a dual-ship live. Open:
`sluice analyze` (offline) per profile.

**M5 — Native transformations, proven like VRL.** Sluice emits the proven reductions in each
platform's own ingest language, so the cut can run without Vector in the path:

- A small, closed reduction IR (drop fields, drop empty fields, keep where predicate, summarize)
  that the guardrails already speak. Each backend compiles only that IR, never free-form code.
- Backends, in order: Azure Monitor DCR `transformKql` (Sentinel), Elastic ingest pipelines,
  Splunk ingest actions / `props`+`transforms`, Google SecOps parser extensions, and for Wazuh
  generated decoders for sources that have none.
- The same rule as for VRL: the proof runs the semantics the platform runs. Each backend gets a
  differential test against the real engine in CI where one can run offline: the Kusto emulator
  container for KQL, Elasticsearch's `_ingest/pipeline/_simulate`, Splunk in a container. A
  backend without such a test ships as "advisory" (generated, not applied).
- Archive-first still holds: native transforms only run where a full copy is kept, through
  Vector, a DCR with a second destination, or the platform's own cheap tier, and Sluice checks
  that before it emits a cut.
- Done when: a Sentinel deployment without Vector receives a generated DCR whose KQL passes the
  emulator differential test, and a real-data run shows the same savings as the Vector path.
- Status 2026-10-10: design in ADR 0013 (proposed). DCR transformations allow no `summarize`
  and no `bag_remove_keys`, so the native Sentinel path is L1 only, on a column model. Step 1
  is done: `sluice-kql` compiles predicates to KQL that matches at least what the VRL matches,
  checked against the real KQL engine (Kusto emulator) on 1,324 predicates. Next: template
  recognition and L1 reductions as `transformKql`, then the DCR with an archive flow.

**M6 — Rule awareness for native detections.** Native transforms are only safe if Sluice knows
the platform's own detections, not just Sigma. Read Sentinel analytics rules (KQL), Splunk
saved searches (SPL), Elastic detection rules (EQL/KQL/ES|QL), Chronicle YARA-L and QRadar AQL
into the same `RuleRequirements` (fields read, pre-filter, raw text, stateful), with the same
fail-closed rule: anything not understood reads every field everywhere. Order by user demand,
starting with KQL, which M5 needs anyway. Differential tests against each vendor's own parser
where it is available offline (Kusto.Language for KQL).

- Status 2026-10-11 (ADR 0015): Sentinel analytics rules are read into requirements (step 1) and
  run in the Kusto emulator as part of the proof (step 2, `sluice up --sentinel-rules --kusto`):
  91 of Microsoft's 105 Windows rules run there, and planted events fire them on the forwarded
  records. Later the same day: callers of ASIM parsers and workspace functions apply to every
  Windows source (fail closed), and `EventData` recipes for 4672 and 4798 were proven end to
  end (window -11% against the "Windows Security Events" solution). Next: resolve ASIM parsers
  from their source (`Parsers/` in Azure/Azure-Sentinel), so their callers get bounds again.

**M7 — Ingest-agent builder.** Help operators build the collection side, with Sluice as the
author of the config rather than another hop:

- Generate agent configs from sources, recipes and rules: Azure Monitor Agent DCRs (XPath
  filters plus the M5 transform), Splunk UF `inputs.conf`, Elastic Agent integrations,
  OpenTelemetry Collector pipelines, Wazuh agent `localfile` blocks.
- Agent-side filtering may only drop what no rule and no recipe needs *and* what the archive
  still receives through a second output. Where an agent cannot dual-ship, it forwards
  everything and the cut happens downstream: archive-first is not negotiable.
- Windows data for Wazuh lands here: Wazuh's Windows rules only match the agent's eventchannel
  format, so those events can only be shaped on the agent side.
- An `agents` view in the console: which hosts send what, which collected data no detection
  uses, and the config that fixes it.
- Status 2026-10-11 (ADR 0014): `sluice agent windows` generates the Vector configuration for a
  Windows host (Vector's `windows_event_log` source, shaping as Sentinel's `SecurityEvent`, a
  disk-buffered send to `sluice up`) and, with `--dcr`, the Sentinel DCR that stores the records
  unchanged. Checked with the official Vector 0.59.0 Windows build on this machine (193 real
  events, all valid `SecurityEvent` columns). Later the same day: other channels shaped as
  `WindowsEvent`, `sluice_sources` on destinations, nested-field protection in the guardrails,
  and an end-to-end run agent → `sluice up` → per-table destinations on real events. Open:
  Security channel events from an elevated run, `Account`/`AccountType` compared with AMA
  records, community recipes for the two table shapes, and a send into a real workspace.

**Backlog (added 2026-10-11, from testing in a real Sentinel workspace):**

- **Any source to Sentinel.** Done for custom tables (2026-10-11): `sluice connect sentinel
  --sample FILE --table NAME --out DIR` writes a `NAME_CL` table and its DCR, checked end to end
  with firewall, Linux auth and DNS records (docs/notes/sentinel-dcr.md). Open: deriving the
  sample from `sluice up`'s discovered templates instead of a file, real OPNsense data, and
  mapping to standard tables where Sentinel has one, as for Windows: Linux syslog to `Syslog` is
  done (`shape: sentinel_syslog`), and parsed firewall records to `CommonSecurityLog`
  (`shape: sentinel_common_security_log`) or `ASimNetworkSessionLogs`
  (`shape: sentinel_asim_network_session`), DNS to `ASimDnsActivityLogs`
  (`shape: sentinel_asim_dns`), web access logs to `ASimWebSessionLogs`
  (`shape: sentinel_asim_web_session`); rules on each apply and run in the emulator.
  Authentication and process events need no table of their own: Microsoft's ASIM parsers read
  them from `Syslog`, `SecurityEvent` and `WindowsEvent`. Raw `filterlog` lines (CSV over syslog) are
  parsed by the shape itself; other firewall vendors need a parsed record or their own parser.
- **`Account` and `AccountType` in `SecurityEvent`.** Derived since 2026-10-11 (ADR 0014,
  update), with the account columns; left: compare edge cases with records the Azure Monitor Agent
  collected on the same machine.
- **The 14 Sentinel rules that read `EventData` without an `EventID` bound** (ADR 0015): most
  filter through `let` lists or `union`s that step 1 does not resolve yet.

**M8 — Operate without the CLI.** Write actions in the console and MCP, behind the token and an
audit log: pause or force a recipe, keep-list a field or template per destination, approve
recipes in `conservative` mode, and acknowledge a rollback. Every action is an event in the
history, and none can override the safety contract. Then multi-user access (OIDC), since a team
console needs to know who acted.

- Status 2026-10-11 (ADR 0016): hold/release, approve, keep/unkeep a field and acknowledge a
  rollback, from the console and `POST /actions`, audited and stored; conservative mode
  (`promotion.approval`). Checked live with demo traffic. The same actions as an MCP tool
  (`sluice mcp --allow-actions`), and named operator tokens (`operators_file`) so the audit
  log names people. Single sign-on with any OIDC provider (`oidc`), verified against Keycloak. M8 is done.

**Review 2026-10-11: the foundation under the proof.** The safety core holds up: superset
pre-filters, field claims, per-template scoping, the proof in the real engine and the archive.
What it rests on does not, and that is also what makes custom rules hard. Four findings, the
first three reproduced with synthetic `sluice analyze` runs (the third also in Vector):

- **Field names are compared literally (fail open).** The guardrails and the rsigma proof match a
  rule's field names against the data's own. Sigma names `Image`; Elastic stores
  `process.executable` (ECS), Splunk CIM names, Sentinel ASIM names. A SIEM converts Sigma with
  a pySigma processing pipeline that maps those names; Sluice applies none. On ECS data a
  `whoami` rule therefore "did not apply": its fields were unprotected, a summarize recipe took
  600 of 600 events including the 3 matches, and the proof read 0 = 0. The same events with
  Sysmon names gave 3 = 3 with the matches forwarded. The built-in recipes use Windows names, so
  ECS data mostly gets no recipe today, but AI-proposed (L3) and operator recipes run straight
  into this.
- **A template is a shape, not a meaning.** Drain routes on the program name alone and merges at
  40 % equal tokens, so sshd's "Accepted password" and "Failed password" become one template
  (`sshd <*> password for <*> from …`): 3 failures among 597 accepted logons were not rare, and
  were summarized with the rest. Contract rule 4 protects rare shapes, not rare events. Digit
  masking also hides message ids (`%ASA-6-302013` becomes `%ASA-<NUM>-<NUM>`). JSON key sets
  split the other way: every combination of optional fields is its own template (many end up
  under the rarity floor, and agent updates reset them), and the four discriminator names
  (`EventID`, `event.code`, `event.action`, `action`) are fixed, while CloudTrail, Okta, Entra
  and Suricata name the event type in other fields. Whitespace tokens also suit CSV,
  `key=value` and CEF lines poorly.
- **Summary keys use the source's field names.** A recipe names its summary keys as the event
  arrives (`Application`, `DestPort`), but a Sentinel shape moves them: `SecurityEvent` keeps
  most event data only in its `EventData` XML, `WindowsEvent` under the `EventData` object. The
  built-in 5156 recipe on `SecurityEvent` records summarized 600 events from two applications and
  two ports into one count with empty keys, in the real Vector 0.59. No detection changes (no
  rule saw those events), but the summary loses what it was for.
- **Rules that are not loaded do not exist.** Sigma, Wazuh and Sentinel rules come from
  directories; nothing reads the rules a SIEM actually runs (`sluice rules fetch` in ADR 0015 was
  never built), Splunk, Elastic, Chronicle and QRadar rules are not modeled, and neither are
  hunting queries, dashboards, workbooks or saved searches. A destination's `sluice_rules`
  defaults to every loaded set, which treats "loaded" as "complete". A custom rule is written in
  the SIEM's names and event categories; protecting it needs its scope as event types, its fields
  as source fields and its filter in source terms, so it depends on the first two findings.

M9 and M10 below fix the foundation, in that order; the configuration and CI milestones follow,
since `sluice prove` in CI would otherwise inherit the same gaps.

**M9 — Know the data: event types, schemas and field lineage.**

1. **Fail-closed field namespaces (a safety fix, first).** Each source declares the field names
   its records use (`schema: sigma | ecs | cim | asim | udm | ocsf`), and so does each rule set
   (Sigma: Sigma's own names, unless a processing pipeline maps them). A rule whose names differ
   from a source's, without a known mapping, applies to that source with unknown fields, so it
   blocks cuts instead of being ignored. A test named after contract rule 3 reproduces the ECS
   case. Then pySigma processing pipelines (field mappings and log source conditions), so Sigma
   rules read the names the SIEM stores, as its own conversion does.
   - Status 2026-10-12 (ADR 0018): the fail-closed part is done. `Schema` on sources, templates
     and rules; a rule whose convention a JSON source does not follow is read as reading every
     field of every event of its log source (`Reason::FieldNamesDiffer`); only `schema: sigma`
     matches Sigma rules for now; shapes bring their own convention; `sluice analyze` and
     `sluice up` hint at undeclared JSON sources. The ECS and undeclared cases are reproduced in
     `sluice-core` and `sluice-autopilot` tests, which fail with the check switched off. Open:
     the pySigma pipelines that let other conventions be cut.
2. **Event types instead of clusters.** The fields that name the event type are set per source
   (`event_type: [eventSource, eventName]`), with defaults per source family. A template becomes
   an event type with its shape variants under it; rarity is also counted per variant, so a rare
   variant or field of a frequent type is forwarded. The classifier keys on the event type and
   the fields a recipe touches, so an agent update does not reset every template. Drain stays for
   unknown text only, made security-aware: route on more than the program name, keep the first
   content tokens (verbs such as Accepted and Failed) constant, keep message ids unmasked, and
   raise the similarity threshold.
   - Status 2026-10-12 (ADR 0019): `event_type` per source plus product defaults (CloudTrail,
     Okta, M365, Azure, GCP, Kubernetes); Drain clusters split at categorical positions (at most
     6 values, or message ids), which keeps the review's three failed sshd logons in a template
     of their own and forwards them; Cisco message ids are no longer masked. Routing on more
     tokens and a higher threshold were not needed. Demo: 75.0 % saved, 41 = 41. Open: grouping
     JSON key-set variants under their event type, so an agent update that adds a field does
     not reset every template.
3. **A schema layer with field lineage.** Per source a declared parser and a mapping to the
   destination's schema (ECS and ASIM first, then CIM, UDM and OCSF), shipped as community parser
   packs next to the recipes. The guardrails and the proof work in the names the destination
   stores; the lineage maps a rule's fields back to the source fields to protect, and a recipe's
   summary keys to where the shaped record keeps them (`EventData` included). For unknown
   text, the AI may propose a parser (a VRL regex), accepted only when it parses every line of
   its cluster and rebuilds each line exactly.

Done when: the ECS case keeps the rule's matches with a pipeline and refuses the cut without one,
sshd failures form a template of their own, and the real-data runs save at least as much as
before.

**M10 — Know the rules: the inventory comes from the SIEM.**

1. **Rule inventory over read-only APIs** instead of rule directories: Sentinel (`alertRules`,
   scheduled and NRT; `savedSearches` for hunting queries and functions), Splunk
   (`saved/searches` including Enterprise Security correlation searches, macros, event types,
   data models and search-time extractions), Elastic (detection rules API, ingest pipelines, ML
   jobs), the Wazuh API (`/rules`, `/decoders`) and Chronicle's rules API. Polled: a new rule is
   guarded from the next cycle on, and its lookback can be replayed from the archive. This is
   where `sluice rules fetch` (ADR 0015) lands.
2. **One extractor per query language**, on the pattern of the KQL one: scope (tables, indexes,
   sourcetypes), fields (a superset), pre-filter (the first filter), stateful parts and
   unbounded constructs, with a coverage report. A rule that cannot be read blocks cuts only
   within its own scope.
3. **Completeness gate.** A destination states where its rules come from; without an inventory
   it gets no rule-guided or semantic cuts (L2/L3), only a report of what they would save.
4. **The proof in the real engine** where one runs offline (the Kusto emulator; Elasticsearch in
   a container for ES|QL and EQL); elsewhere the cut ships as advisory.
5. **Queries beyond detections.** Hunting queries, workbooks, dashboards and saved searches from
   the same inventory, proven the same way: "same alerts" becomes "same query result", which
   `KustoEngine` already compares row by row. Query logs (`LAQueryLogs`, Splunk `_audit`,
   Elastic's audit log) show which fields people actually query: those are protected, and what
   nobody queries is offered as the safest field cuts. Summaries become data of their own (a
   table or index with window, keys, count and an archive pointer), with generated helpers (a
   KQL function, a Splunk macro) that count raw events and summaries together.

Done when: a Sentinel workspace's enabled rules and hunting queries are read over the API and
proven in the emulator, a Splunk or Elastic destination without an inventory gets no L2/L3, and
a dashboard that counts events either passes the proof or keeps its data.

**M11 — Configs as the product.** Sluice's output scales; Sluice itself does not run a fleet
(ADR 0017). Vector already runs pipelines at scale, so Sluice does not reinvent that. What
Sluice delivers is the configuration and the proof that it saves data without changing a
detection:

- Every generated artifact (Vector pipeline, DCRs, agent configurations) written to a directory
  that can live in Git. `sluice up` can write a proposed change there instead of applying it, so
  a recipe reaches production as a reviewable diff.
- `sluice prove` for CI: given a sample, the rules and a configuration, it fails when the alert
  set over the forwarded data differs from the alert set over the full data, and prints the
  savings. A GitHub Action wraps it.
- A load test of the generated configuration on a stock Vector: events per second next to the
  savings, so the numbers are about the configuration, not about Sluice.

- Status 2026-10-11: a first draft, remote nodes pulling their configuration from the control
  plane, worked end to end but was rejected and removed (ADR 0017): it would have made Sluice
  the kind of platform it means to make unnecessary.

**M12 — Community and ecosystem.** The flywheel that makes recipes "Sigma for pipelines":

- A recipe hub repository with CI that runs every recipe against its samples and SigmaHQ.
- `sluice recipes contribute`: export a locally proven, AI-written recipe (values stripped) as a
  pull request.
- Signed recipe releases that `sluice up` can follow, with the same shadow and proof before
  anything enforces.
- Parser packs (M9) in the same hub, with the same CI.
- Normalization for teams that want it, on M9's schema layer (OCSF, ECS, CIM, ASIM, UDM
  mappings), proven against the rules that read the mapped names, and PII masking with the same
  proof.

**Out of scope, on purpose:** a hosted service and paid tiers (AGPL, adoption over revenue);
running or steering a fleet of pipeline nodes (Vector and the user's own deployment tooling do
that; ADR 0017);
agent-side cuts without a full copy; any reduction the proof cannot run with the platform's
own semantics.

## Project layout (Rust Cargo workspace)

Dependencies point inward. `sluice-core` defines the domain types and the traits; the adapter
crates implement those traits around third-party engines. Only `sluice-cli` wires everything
together and does process I/O.

```
sluice/
  Cargo.toml            # [workspace] + [workspace.dependencies] + [workspace.lints]
  rust-toolchain.toml   deny.toml   rustfmt.toml   .github/workflows/ci.yml
  LICENSE               # AGPL-3.0-only (ADR 0008)
  crates/
    sluice-core/        # domain model, safety contract/guardrails, reduction plan, shadow proof
                        #   (pure: no I/O, no async; engines injected via traits)
    sluice-synth/       # deterministic synthetic log generator (demo + tests)
    sluice-discover/    # Drain (text) and keyset (JSON) template discovery, frequency stats
    sluice-rules/       # Sigma adapter (rsigma), Wazuh rules.xml, requirements, superset pre-filter
    sluice-vector/      # reductions → VRL, VRL execution (vrl crate), vector.yaml + vector tests
    sluice-autopilot/   # analysis pipeline, recipe book, lifecycle, live cycle, report
    sluice-ai/          # L3 advisor: redaction, prompt, Anthropic and OpenAI-compatible models
    sluice-wazuh/       # Wazuh logtest client (spot check)
    sluice-server/      # control plane for `sluice up` (axum): tap, status, Vector supervision
    sluice-cli/         # `sluice` binary: demo, analyze, recipes, up, status
    sluice-archive/     # streaming search over the gzip NDJSON archive (search, replay)
    sluice-mcp/         # MCP server (rmcp, stdio): status, templates, archive search, replay
  recipes/<vendor>/<product>/<event>.yaml + samples/   # community recipes (YAML)
  examples/{rules/, sluice.example.yaml}
  docs/{adr/, notes/, compatibility.md}
  scripts/wsl.ps1       # run cargo in WSL on machines where code-integrity policy blocks builds
```

## Implementation notes

- **Verified so far** (spike, 2026-10-09): `vrl =0.36.0` compile and run; `rsigma =0.24.0`
  detection, correlation and public AST. See `docs/notes/`.
- **Check before use, then pin:** Vector sink, transform and provider names
  (`azure_logs_ingestion`, `gcp_chronicle_unstructured`, `reduce`, `dedupe`, HTTP config provider,
  `vector test`), and which Vector release embeds `vrl` 0.36.
- **One implementation of each reduction.** VRL is the single source of truth for stateless
  operations. Stateful operations have one Rust model, cross-checked with `vector test`.
- **Load the `claude-api` skill before writing the AI provider and the MCP code** (its trigger
  covers both). Don't hardcode model names or prices from memory.
- **No third-party rule content in the repo.** `sluice rules fetch sigmahq` clones into a user
  cache (SigmaHQ is under the DRL licence).
- **Build environment.**
  - Rust 1.99, in WSL2 Ubuntu 24.04 through `scripts/wsl.ps1`.
  - Native Windows builds are blocked by Smart App Control.
  - Vector 0.59 (`scripts/install-vector.sh`), zig and helm live in `~/.local` in WSL. Docker
    works in WSL since 2026-10-10 (the user is in the `docker` group).
- `git init`, no commits; the user commits. Write a ready commit message at the end.

## Verification

- All quality gates in [CLAUDE.md](CLAUDE.md) pass (fmt, clippy `-D warnings`, tests, cargo-deny).
  Tests run fully offline.
- **Property test (proptest):** for every effective recipe on the synthetic data, the Sigma alert
  set over the full data equals the alert set over the forwarded data, in **both directions**.
- **Fail-closed tests** cover correlation/frequency rules, unparseable rules and rare templates.
- **Differential test (CI):** Sluice's rule requirements vs pySigma on the example rules and
  the full SigmaHQ set (`scripts/sigma-differential.sh`; alerts cannot be compared, as pySigma
  does not evaluate rules).
- `sluice demo` prints the reduction %, **0 detection regressions** and the coverage gaps, and
  writes `report.html` and `vector.yaml`.
- If Vector is installed, run `vector validate` and `vector test` on the generated config.
- Live smoke test (M2): `scripts/live-smoke.sh` (`sluice up --demo-traffic`, also in CI).
  - Recipes move from shadow to enforced in `sluice status`.
  - A test hook breaks a recipe, and auto-rollback plus an event are observed.
  - `sluice replay` restores archived events.
- Wazuh: mocked logtest tests; optionally a real run against a user-provided Wazuh API with
  read-only credentials.
- MCP: `claude mcp add sluice -- sluice mcp`, then ask "what did you cut and why?".

## Honest limits

- Rule parsing is never complete. Failing closed protects detections but costs savings.
- Sigma rules are compared with a JSON source only when it declares `schema: sigma` (ADR 0018).
  Records in ECS, CIM, ASIM or any undeclared convention get no cuts a Sigma rule of their log
  source could object to, until the pySigma pipelines of M9 step 1. Declaring `sigma` for records
  that use other names is unsafe, and the proof cannot notice (both sides raise no alert).
- Until M10, a rule Sluice was not given does not exist for it. Load every rule the SIEM runs,
  for each destination.
- Detections aren't the only consumers of data; dashboards, hunts and compliance also use it.
  Archive, replay, summaries, the keep-list and a per-destination "no reduction" switch mitigate
  this until M10 brings them into the proof.
- Savings shown are estimates from samples; check them against the SIEM's license usage.
- Throughput is measured on one machine (about 16k events/s per vCPU); the load test of the
  generated configuration on a stock Vector waits for M11.
- With the stock Wazuh ruleset loaded, JSON events are not reduced at all, by design (generic
  raw-text rules read the whole line). Until M4, load Wazuh rules only when Wazuh receives the
  data.

## Sources

- Cribl ARR $305M: https://sacra.com/c/cribl/
- Cribl free license, 1 TB/day: https://docs.cribl.io/stream/licensing
- Cribl Copilot Editor: https://docs.cribl.io/edge/copilot-editor-pipelines
- SIEM migrations with Cribl: https://cribl.io/blog/cribl-to-the-rescue-for-siem-migrations
- Cribl Detect: https://www.techtarget.com/it-infrastructure/news/366651477/Cribl-targets-SIEM-data-costs-with-new-Detect-tool
- CrowdStrike–Onum: https://www.builtinaustin.com/articles/crowdstrike-acquires-spanish-startup-onum-20250829
- SentinelOne–Observo: https://www.securityweek.com/sentinelone-to-acquire-observo-ai-in-225-million-deal/
- Splunk pricing: https://cipherssecurity.com/splunk-pricing-is-it-worth-it/
- Vector azure_logs_ingestion: https://rust-doc.vector.dev/vector/sinks/azure_logs_ingestion/index.html
- Drain algorithm (He et al., ICWS 2017); reference implementation Drain3 (MIT): https://github.com/logpai/Drain3
- rsigma (MIT): https://github.com/timescale/rsigma
- VRL crate (MPL-2.0): https://crates.io/crates/vrl
- Log-substrate prompt injection: https://arxiv.org/abs/2605.24421
