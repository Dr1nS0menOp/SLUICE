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
sources ──▶ Vector data plane (Rust, MPL-2.0; scale-out nodes pull config via Vector's HTTP provider)
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
| **Rule awareness** | Sigma (rsigma, incl. correlations); Wazuh `rules.xml`; exact Wazuh verification via the Wazuh API `PUT /logtest` | Splunk SPL, Sentinel KQL, Elastic, Chronicle YARA-L, QRadar AQL (best effort, fail closed) |

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

**M6 — Rule awareness for native detections.** Native transforms are only safe if Sluice knows
the platform's own detections, not just Sigma. Read Sentinel analytics rules (KQL), Splunk
saved searches (SPL), Elastic detection rules (EQL/KQL/ES|QL), Chronicle YARA-L and QRadar AQL
into the same `RuleRequirements` (fields read, pre-filter, raw text, stateful), with the same
fail-closed rule: anything not understood reads every field everywhere. Order by user demand,
starting with KQL, which M5 needs anyway. Differential tests against each vendor's own parser
where it is available offline (Kusto.Language for KQL).

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

**M8 — Operate without the CLI.** Write actions in the console and MCP, behind the token and an
audit log: pause or force a recipe, keep-list a field or template per destination, approve
recipes in `conservative` mode, and acknowledge a rollback. Every action is an event in the
history, and none can override the safety contract. Then multi-user access (OIDC), since a team
console needs to know who acted.

**M9 — Scale out.** Several Vector data-plane nodes pulling config from the control plane
(Vector's HTTP config provider), a sharded tap, the archive on S3/Blob/GCS with Parquet for
search, and a load test that publishes events per second per node next to the savings. A Helm
chart with an HPA for the data plane.

**M10 — Community and ecosystem.** The flywheel that makes recipes "Sigma for pipelines":

- A recipe hub repository with CI that runs every recipe against its samples and SigmaHQ.
- `sluice recipes contribute`: export a locally proven, AI-written recipe (values stripped) as a
  pull request.
- Signed recipe releases that `sluice up` can follow, with the same shadow and proof before
  anything enforces.
- Normalization for teams that want it (OCSF, ECS, CIM, ASIM, UDM mappings), proven against
  the rules that read the mapped names, and PII masking with the same proof.

**Out of scope, on purpose:** a hosted service and paid tiers (AGPL, adoption over revenue);
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
- Detections aren't the only consumers of data; dashboards, hunts and compliance also use it.
  Archive, replay, summaries, the keep-list and a per-destination "no reduction" switch mitigate
  this.
- Savings shown are estimates from samples; check them against the SIEM's license usage.
- Throughput is measured on one machine (about 16k events/s per vCPU); multi-node numbers wait
  for M9.
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
