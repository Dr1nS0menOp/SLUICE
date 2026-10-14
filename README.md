# Sluice

**Sluice writes Vector configurations that send less data to your SIEM, and proves on your own
traffic and rules that no detection changes. You decide what runs.**

> Status: early development. Nothing here is ready for production yet.

## The idea

Security teams pay for every byte their SIEM ingests, yet much of that data is padding: rendered
boilerplate, empty fields, duplicates, and high-volume events no rule will ever match.

Pipeline tools can remove it, but a person still has to decide what to remove, build the
pipeline and maintain it. Sluice does the deciding and the proving, and hands you the result:

1. **Discovers** the kinds of events in your traffic.
2. **Proposes savings**: format padding it can drop without losing anything, events no rule
   could match that it can count instead of sending (rule-guided), and, with AI, more.
3. **Proves** on your traffic that your rules raise exactly the same alerts on what would still
   be sent as on everything.
4. **Writes** the [Vector](https://vector.dev) configuration and the proof. You review it and
   deploy it, through Git and CI if you like (`sluice prove`).
5. **Keeps checking** what runs. If a check ever fails, Sluice switches Vector to the safe
   configuration, which sends everything unchanged, until you deploy a new proposal. That is
   the only thing it does without asking: it can switch savings off, never on.

Every event is archived at full fidelity first, so any slice can be replayed into any SIEM.

## Safety contract

These rules are enforced in code, and AI output can never override them:

1. Unknown data passes through untouched.
2. Everything is archived at full fidelity before any saving.
3. Anything a rule could match is sent in full.
4. Rare events are never saved on.
5. Every saving is proven before it is proposed, and what runs is re-checked continuously.
6. AI proposes; the guardrails decide.

## Which rules it protects

Sluice protects the rules your SIEM actually runs, read in their own language:

- **Microsoft Sentinel**: analytics rules, hunting queries and workspace functions in KQL, read
  from the workspace with `sluice rules fetch sentinel` and run in the Kusto emulator for the
  proof.
- **Wazuh**: the rule and decoder files the manager loads, read with `sluice rules fetch wazuh`.
- **Sigma** rules stand in for SIEMs whose query language Sluice cannot read yet (Elastic and
  Splunk are next). For those, you declare with `--rules-complete` that the rules you give are
  all of them; Sluice cannot check that, and says so in every report.

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

It writes `out/report.html` (what is saved, why, the proof, and every rule) and
`out/vector.yaml`. Run that configuration with [Vector](https://vector.dev) 0.59
(`scripts/install-vector.sh`), and Vector archives all 80,536 events, sends exactly the 35,974
the proof sent, and turns the other 44,562 into 460 summary records.

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

## Run it in front of your SIEM

`sluice up` runs Vector and a control plane next to it. Vector archives every event and sends a
sample to Sluice. Sluice proves its proposals on that sample, keeps each in shadow until it has
held long enough, and writes the configuration as a proposal (`vector.yaml` with
`proposal.json`) under `data_dir/proposals`. You review it and deploy it by copying it over
`vector_config`; every cycle Sluice proves what runs and switches to the safe configuration if
the proof fails.

```sh
scripts/install-vector.sh
sluice up --config examples/up/sluice-up.yaml --rules examples/rules/sigma --demo-traffic
sluice status        # in another shell: mode, what runs, lifecycle per template
```

The example sets `auto_apply: true`, so the demo applies its own proposals; leave it out for
real data. Open `http://127.0.0.1:8686/` for the web console: whether the proof holds, what each
source and template saves, why each field was kept, each recipe's lifecycle, and a search over
the archive (ADR 0011; with `SLUICE_CONTROL_TOKEN` set it asks for the token). Every operator
action is audited and none can weaken the safety contract (ADR 0016).

In CI, `sluice prove` proves the configuration in a pull request as it is, and fails when it
would change a detection or when the sample raises no alert at all (`action.yml` runs it on
GitHub; ADR 0022).

With your own sources, list them in the config (any Vector source that emits JSON objects) and
point the destinations at your SIEM: `sluice connect splunk` (or `elastic`, `sentinel`,
`chronicle`, `wazuh`, `http`) prints a destination to add; credentials stay in secret files,
never in the configuration. To reach the control plane from other hosts, set
`SLUICE_CONTROL_TOKEN`. `scripts/live-smoke.sh` runs this end to end and checks the result.

Every event is in the archive as it arrived, so whatever was not sent can always be found and
sent on:

```sh
sluice search --archive out/up/archive --source windows-security --where EventID=4624 --from 2026-10-09
sluice replay --archive out/up/archive --source sysmon --where Image~powershell --url http://siem-ingest:9000
```
## Ask your assistant

`sluice mcp` is an MCP server, so an AI assistant can answer "what does Sluice save, and does it
still hold?" from the live status and look up original events in the archive:

```sh
claude mcp add sluice -- sluice mcp --archive /var/lib/sluice/archive
```

Replay is only offered with `--allow-replay`. For a remote assistant, `sluice mcp --http
127.0.0.1:8687` serves MCP over HTTP; every request needs `Authorization: Bearer
$SLUICE_MCP_TOKEN` (at least 32 characters).

## Platform

Sluice runs on Linux (x86_64 and aarch64), including WSL2. Windows and macOS aren't supported. On
those systems, run Sluice in WSL2, a VM or a container.

## Installing

Release binaries are static (musl) and run on any Linux distribution, on x86_64 and aarch64. A
container image bundles Sluice with the Vector release it is verified against:

```sh
docker compose -f examples/docker/compose.yaml up --build    # Sluice + Vector with demo traffic
helm install sluice deploy/helm/sluice --set controlToken.secretName=sluice-token
```

## Building

Sluice is a Rust workspace. The toolchain is pinned in `rust-toolchain.toml`.

```sh
cargo build --release
bash scripts/check.sh        # every quality gate: fmt, clippy, tests, docs, cargo-deny
scripts/install-zig.sh && scripts/build-release.sh   # static binaries for both architectures
```

## Documentation

- [Using Sluice](docs/usage.md): step by step, from a first look to running it in front of your
  SIEM, including Microsoft Sentinel
- [User guide](docs/guide.md): concepts, source descriptions, every command and setting
- [Architecture and technologies](docs/architecture.md): diagrams of the data and decision paths,
  one event followed step by step, the parts, and what each is built on
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
