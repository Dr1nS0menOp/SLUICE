# Sluice

**Sluice looks at the rules your SIEM runs and a sample of your data, finds where you can send
less without changing a detection, and writes the configurations that do it: for Vector,
Microsoft Sentinel, Elasticsearch, Fluent Bit and the OpenTelemetry Collector. It proves every
saving on your own data and rules. Sluice itself changes nothing: you decide what runs.**

> Status: early development. Nothing here is ready for production yet.

## The idea

Security teams pay for every byte their SIEM ingests, yet much of that data is padding: rendered
boilerplate, empty fields, duplicates, and high-volume events no rule will ever match.

Pipeline tools can remove it, but a person still has to decide what to remove, build the
pipeline and maintain it. Sluice does the deciding and the proving, and hands you the result:

1. **Reads your rules** from the SIEM, read-only.
2. **Discovers** the kinds of events in a sample of your traffic.
3. **Proposes savings**: format padding it can drop without losing anything, events no rule
   could match that it can count instead of sending (rule-guided), and, with AI, more.
4. **Proves** on your sample that your rules raise exactly the same alerts on what would still
   be sent as on everything.
5. **Writes** the savings plan, a report, and the configurations that carry the plan out. You
   review them and deploy them with your own tooling, through Git and CI if you like
   (`sluice prove`).

Sluice never sits in your data path ([ADR 0030](docs/adr/0030-advice-only.md)).

## Safety contract

These rules are enforced in code, and AI output can never override them:

1. Unknown data passes through untouched.
2. Everything is archived at full fidelity before any saving.
3. Anything a rule could match is sent in full.
4. Rare events are never saved on.
5. Every saving is proven before it is proposed, and `sluice prove` proves a configuration again
   when it changes.
6. AI proposes; the guardrails decide.

## Which rules it protects

Sluice protects the rules your SIEM actually runs, read in their own language:

- **Microsoft Sentinel**: analytics rules, hunting queries and workspace functions in KQL, read
  from the workspace with `sluice rules fetch sentinel` and run in the Kusto emulator for the
  proof.
- **Wazuh**: the rule and decoder files the manager loads, read with `sluice rules fetch wazuh`.
- **Elastic Security**: the detection rules of a Kibana space (KQL, EQL, ES|QL), read with
  `sluice rules fetch elastic` and run in Elasticsearch for the proof.
- **Splunk**: scheduled and correlation searches with their macros, read with `sluice rules
  fetch splunk`. No engine runs them in the proof yet; what they read still limits every saving.
- **Sigma** rules stand in for SIEMs whose query language Sluice cannot read yet. For those, you
  declare with `--rules-complete` that the rules you give are all of them; Sluice cannot check
  that, and says so in every report.

Sluice only counts events instead of sending them when it knows it has every rule: a rule it was
not given could match what it would not send. Without that, it makes only savings that keep every
event. Each report lists every rule next to what Sluice made of it.

Be aware: with Wazuh's standard ruleset, Sluice saves almost nothing on the data Wazuh itself
receives, because generic rules such as 1002 read every line whole. The savings are on data that
goes to other SIEMs, or with a tuned ruleset.

## Try it

```sh
cargo build --release
./target/release/sluice demo --scale 100
```

The demo generates an hour of synthetic traffic from a small company network (Windows Security,
Sysmon, Linux auth, a firewall, DNS and nginx) with six planted attacks, and runs Sluice with
example Sigma rules:

```
80,536 events from 6 sources, 29 templates
  ingest  121.0 MB → 29.8 MB  (75.3% saved, 44,562 events summarized)
  proof   41 alerts on full data, 41 on forwarded data  ✓ no detection changed
```

It writes `out/report.html` (what is saved, why, the proof, and every rule), `out/plan.json` (the
same decisions, for tools) and `out/vector.yaml`. Run that configuration with
[Vector](https://vector.dev) 0.59 (`scripts/install-vector.sh`), and Vector archives all 80,536
events, sends exactly the 35,974 the proof sent, and turns the other 44,562 into 460 summary
records.

On your own data:

```sh
sluice analyze --input samples/ --sources sluice.yaml --rules sigma-rules/ --rules-complete
sluice analyze --input samples/ --sources sluice.yaml --sentinel-rules inventory/sentinel \
  --kusto http://127.0.0.1:8090 --sentinel-table windows-security=SecurityEvent
```

`sluice.yaml` lists each source with its Sigma log source. Describe it as precisely as you can:
an attribute you leave out counts as "unknown", so every rule that names it still applies. Add
`complete: true` when the attributes you give are all there are, as for a single Windows
channel:

```yaml
sources:
  - id: system
    logsource: { product: windows, service: system, complete: true }
    format: { kind: json }
    schema: sigma
```

`schema` says which field names the records use. Sigma rules name fields in Sigma's convention
(`Image`, `TargetUserName`). Say `sigma` only when the records really carry Sigma's names; for
another convention (`ecs`, `cim`, `asim`, …), give the pySigma pipeline your SIEM converts Sigma
with (`--sigma-pipeline ecs=ecs_windows`). Otherwise no field a Sigma rule could read is removed
from that source (ADR 0018, ADR 0020).

On this project's development machine (Windows System, Application and PowerShell logs, 22,448
events) with all 3,152 SigmaHQ rules declared complete, that gives 24.2 % less ingest with
206 = 206 alerts; on a Linux server's auth.log and syslog (177,008 lines), 28.6 % less.

## Put the savings to work

Sluice proves each configuration in the engine it is for before it writes it:

| Where the saving runs | What `sluice analyze` writes | Proven in |
|---|---|---|
| [Vector](https://vector.dev) | `vector.yaml`, always: every saving, counting included | the `vrl` crate Vector embeds; its tests let `vector test` check Vector itself |
| Microsoft Sentinel's ingestion | with `--sentinel-native --sentinel-dcr RULE.json`: that data collection rule with a `transformKql` per table and an untransformed flow into an archive table | the Kusto emulator |
| Elasticsearch's ingestion | with `--elastic-native`: an ingest pipeline per source | Elasticsearch |
| Fluent Bit | with `--fluent-bit-native`: a Lua filter per source | Fluent Bit |
| OpenTelemetry Collector | with `--otel-native`: `transform` statements per source | the collector |

Outside Vector only field removals run, because counting needs state across events, which only a
pipeline tool keeps. `plan.json` says per kind of event where its saving can run.

`vector.yaml` reads files and writes files. Point its sources and sinks at your own, and roll it
out with the tooling you already use (Git, CI, Ansible, Kubernetes). In CI, `sluice prove` proves
the configuration in a pull request as it is, and fails when it would change a detection or when
the sample raises no alert at all (`action.yml` runs it on GitHub; ADR 0022).

For Microsoft Sentinel, `sluice connect sentinel` writes the tables and data collection rules: a
custom table derived from a sample (`--sample`), and a table for summaries with a function that
counts them in (`--summary-table`).

Until 2026-10-17, Sluice could also run Vector itself (`sluice up`), with a live control plane,
archive search and replay, and an MCP server. That code is in [`archive/`](archive/), outside the
build ([ADR 0030](docs/adr/0030-advice-only.md)).

## Platform

Sluice runs on Linux (x86_64 and aarch64), including WSL2. Windows and macOS aren't supported. On
those systems, run Sluice in WSL2, a VM or a container.

## Installing

Release binaries are static (musl) and run on any Linux distribution, on x86_64 and aarch64. To
build from source instead:

```sh
cargo install --path crates/sluice-cli
```

## Building

Sluice is a Rust workspace. The toolchain is pinned in `rust-toolchain.toml`.

```sh
cargo build --release
bash scripts/check.sh        # every quality gate: fmt, clippy, tests, docs, cargo-deny
scripts/install-zig.sh && scripts/build-release.sh   # static binaries for both architectures
```

## Documentation

- [Using Sluice](docs/usage.md): step by step, from a first look to the configurations for your
  SIEM and your tools, including Microsoft Sentinel
- [User guide](docs/guide.md): concepts, source descriptions, every command and what it writes
- [Architecture and technologies](docs/architecture.md): diagrams of the analysis and of what
  each configuration does, one event followed step by step, the parts, and what each is built on
- [Glossary](docs/glossary.md): the terms Sluice uses
- [Architecture decisions](docs/adr/)
- [Compatibility](docs/compatibility.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)

## License

Sluice is licensed under the [GNU Affero General Public License v3.0 only](LICENSE)
(AGPL-3.0-only). You may use, modify and sell it, but if you distribute a modified version or
offer it to others over a network, you must publish its complete source under the same license.
[ADR 0008](docs/adr/0008-license.md) explains the choice.
