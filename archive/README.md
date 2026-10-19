# Archive

Code that no longer fits what Sluice is, kept here so it can be deleted later (ADR 0030).

Sluice is advice-only: it reads a SIEM's rules and a sample of its data, works out where ingest
can be saved without changing a detection, and writes the configuration that makes the saving
(`plan.json`, `vector.yaml`, Sentinel DCR transformations, Elasticsearch ingest pipelines, Fluent
Bit filters, OpenTelemetry Collector statements). It does not run anything in the data path
itself. What is here did:

| Path | What it was |
|---|---|
| `crates/sluice-server` | `sluice up`: the live control plane that ran Vector, tapped events, shadowed and promoted recipes, proposed configurations and switched to the safe one; its operator UI, OIDC and audit log |
| `crates/sluice-archive` | The event archive behind `sluice search` and `sluice replay` |
| `crates/sluice-mcp` | `sluice mcp`: MCP server over the control plane and the archive |
| `sluice-cli/src/live.rs`, `archive.rs`, `agent.rs`, `tests/mcp.rs` | The CLI commands `up`, `status`, `mcp`, `search`, `replay` and `agent` |
| `sluice-vector/src/live.rs`, `connect.rs`, `tests/connect.rs` | The live Vector configuration and the destination blocks of `sluice connect` |
| `sluice-vector/src/syslog.rs`, `common_security_log.rs`, `asim_*.rs`, `windows/` | The VRL that shaped records as Sentinel's standard tables (`Syslog`, `CommonSecurityLog`, the ASIM tables, `SecurityEvent`, `WindowsEvent`) for `sluice up` sources and `sluice agent windows`, and those tables' data collection rules (`sluice connect sentinel --standard-table`; archived 2026-10-18) |
| `sluice-autopilot/src/live.rs`, `lifecycle.rs`, `tests/live.rs` | The live cycle and the shadow, promotion and rollback of recipes `sluice up` ran |
| `deploy/helm`, `examples/up`, `examples/docker`, `Dockerfile`, `.dockerignore` | Deployments of `sluice up` |
| `scripts/` | Their checks: Helm, live smoke, replay smoke and load tests, filling a Sentinel workspace through `sluice up`, and the diagrams of the live design (`docs/images`) |

None of it is in the Cargo workspace (`members = ["crates/*"]`), so it is neither built nor
tested. Its git history is intact (`git log --follow archive/<path>`). To bring a part back, move
it under `crates/` again and add its dependencies to the workspace.
