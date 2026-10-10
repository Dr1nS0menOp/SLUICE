# Sluice

**An open-source autopilot for security data.** Sluice cuts what you send to your SIEM, and it
proves on your own traffic and rules that no detection changes.

> Status: early development. Nothing here is ready for production yet.

## The idea

Security teams pay for every byte their SIEM ingests, yet much of that data is padding: rendered
boilerplate, empty fields, duplicates, and high-volume events no rule will ever match.

Pipeline tools can cut it, but a person still has to decide what to cut, build the pipeline and
maintain it. Sluice does that work itself:

1. **Discovers** the log templates in your traffic.
2. **Decides** what is fat: format fat (lossless), volume fat (rule-guided) and semantic fat
   (AI-judged).
3. **Proves** that the cut leaves the alert set of your rules unchanged, both ways.
4. **Enforces** the cut with [Vector](https://vector.dev), keeps checking it, and rolls back by
   itself on any mismatch.

Every event is archived at full fidelity before any cut, so any slice can be replayed into any
SIEM.

## Safety contract

These rules are enforced in code, and AI output can never override them:

1. Unknown data passes through untouched.
2. Everything is archived at full fidelity before any cut.
3. Anything a rule could match is forwarded in full.
4. Rare is never cut.
5. Every cut is proven before it is enforced, and is re-verified continuously afterwards.
6. AI proposes; the guardrails decide.

## Try it

```sh
cargo build --release
./target/release/sluice demo --scale 100
```

The demo generates an hour of synthetic traffic from a small company network (Windows Security,
Sysmon, Linux auth, a firewall, DNS and nginx) with six planted attacks, and runs the autopilot
with example Sigma rules:

```
80,536 events from 6 sources, 29 templates
  ingest  121.0 MB → 29.8 MB  (75.3% saved, 44,562 events summarized)
  proof   41 alerts on full data, 41 on forwarded data  ✓ no detection changed
```

It writes `out/report.html` (what is cut, why, and the proof) and `out/vector.yaml`. Run that
config with [Vector](https://vector.dev) 0.59 (`scripts/install-vector.sh`), and Vector archives all
80,536 events, forwards exactly the 35,974 the proof forwarded, and turns the other 44,562 into 460
summary records.

On your own data:

```sh
sluice analyze --input samples/ --sources sluice.yaml --rules sigma-rules/ [--wazuh-rules dir]
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
```

Don't mark a source complete if Sigma maps categories onto it: Sysmon carries
`process_creation`, `network_connection` and more, and the Security channel carries
`process_creation` (4688). Leaving those open keeps every such rule in scope, which is the safe
side. `sluice analyze` prints a hint for each source where undeclared attributes keep rules in
scope.

On this project's development machine (Windows System, Application and PowerShell logs, 22,448
events) with all 3,152 SigmaHQ rules, that gives 23.8 % less ingest with 206 = 206 alerts; on a
Linux server's auth.log and syslog (177,008 lines), 28.6 % less.

## Run it live

`sluice up` runs Vector with a generated pipeline and a control plane next to it. Vector archives
every event and sends a sample to Sluice. Sluice discovers templates, proves recipes on that
sample, keeps each new recipe in shadow until it has held long enough, then enforces it and
reloads Vector. A recipe that later fails a proof is rolled back on the next cycle.

```sh
scripts/install-vector.sh
sluice up --config examples/up/sluice-up.yaml --rules examples/rules/sigma --demo-traffic
sluice status        # in another shell: lifecycle per template, last cycle
```

`--demo-traffic` posts synthetic traffic to the example's six local `http_server` sources. With
your own sources, list them in the config (any Vector source that emits JSON objects) and point
the destinations at your SIEM: `sluice connect splunk` (or `elastic`, `sentinel`, `chronicle`,
`wazuh`, `http`) prints a destination to add; credentials stay in secret files, never in the
configuration. To reach the control plane from other hosts, set `SLUICE_CONTROL_TOKEN`.
`scripts/live-smoke.sh` runs this end to end and checks the result.

Every event is in the archive as it arrived, so what was cut can always be found and sent on:

```sh
sluice search --archive out/up/archive --source windows-security --where EventID=4624 --from 2026-10-09
sluice replay --archive out/up/archive --source sysmon --where Image~powershell --url http://siem-ingest:9000
```

## Ask your assistant

`sluice mcp` is an MCP server, so an AI assistant can answer "what did Sluice cut, and does it
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

- [User guide](docs/guide.md): concepts, source descriptions, every command and setting
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
