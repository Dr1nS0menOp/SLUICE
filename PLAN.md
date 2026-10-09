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
  - License: Apache-2.0 vs AGPL-3.0. Decide before the first public push.
  - Install method for the Vector binary, needed for M2.
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
- Any **aggregation or correlation** rule on the type protects the whole type: Sigma correlations,
  Wazuh `frequency`/`timeframe`, Splunk `stats` thresholds.

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

**M1 build order.** Each step ends green on all quality gates.

1. Workspace scaffold: lints, toolchain, `deny.toml`, CI, README, LICENSE placeholder.
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

**M2 — Live.**

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

**M3 — Interfaces and ecosystem.**

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

**v0.2+.**

- Web UI with live before/after preview and toggles.
- SPL/KQL/EQL/YARA-L/AQL parsers.
- OCSF canonical schema plus ECS/CIM/ASIM/UDM output mappers.
- PII masking.
- Wazuh decoder generation.
- Recipe-hub PR bot.
- OpenTelemetry Collector runtime.
- Parquet archive.
- Helm chart.
- Throughput benchmarks (EPS per vCPU).

## Project layout (Rust Cargo workspace)

Dependencies point inward. `sluice-core` defines the domain types and the traits; the adapter
crates implement those traits around third-party engines. Only `sluice-cli` wires everything
together and does process I/O.

```
sluice/
  Cargo.toml            # [workspace] + [workspace.dependencies] + [workspace.lints]
  rust-toolchain.toml   deny.toml   rustfmt.toml   .github/workflows/ci.yml
  LICENSE               # final call (Apache-2.0 vs AGPL-3.0) before first public push
  crates/
    sluice-core/        # domain model, safety contract/guardrails, reduction plan, shadow proof
                        #   (pure: no I/O, no async; engines injected via traits)
    sluice-synth/       # deterministic synthetic log generator (demo + tests)
    sluice-discover/    # Drain (text) and keyset (JSON) template discovery, frequency stats
    sluice-rules/       # Sigma adapter (rsigma), Wazuh rules.xml, requirements, superset pre-filter
    sluice-vector/      # reductions → VRL, VRL execution (vrl crate), vector.yaml + vector tests
    sluice-cli/         # `sluice` binary: analyze, demo, report.html
    # later: sluice-ai (M1 step 9), sluice-server + sluice-archive (M2), sluice-mcp (M3)
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
  - Docker, Vector, Go and Node are missing. M2 needs the Vector binary, which is easiest in WSL.
- `git init`, no commits; the user commits. Write a ready commit message at the end.

## Verification

- All quality gates in [CLAUDE.md](CLAUDE.md) pass (fmt, clippy `-D warnings`, tests, cargo-deny).
  Tests run fully offline.
- **Property test (proptest):** for every effective recipe on the synthetic data, the Sigma alert
  set over the full data equals the alert set over the forwarded data, in **both directions**.
- **Fail-closed tests** cover correlation/frequency rules, unparseable rules and rare templates.
- **Differential test (CI only):** rsigma vs pySigma on the same rules and events.
- `sluice demo` prints the reduction %, **0 detection regressions** and the coverage gaps, and
  writes `report.html` and `vector.yaml`.
- If Vector is installed, run `vector validate` and `vector test` on the generated config.
- Live smoke test (M2): `sluice up --demo-traffic --shadow 5m`.
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
- Throughput targets are unmeasured until the v0.2 benchmarks.

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
