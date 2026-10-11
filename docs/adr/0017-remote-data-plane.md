# ADR 0017: Sluice does not host a fleet of data-plane nodes

- Status: Rejected (remote nodes pulling their configuration from the control plane)
- Date: 2026-10-11

## Context

`sluice up` runs one Vector next to the control plane. Larger sites have more traffic than one
host can handle, and their logs arrive at several places. The first draft of M9 had the control
plane steer many Vector nodes: each node pulls its pipeline over Vector's `http` config provider
from `GET /data-plane/config`. `sluice node` writes the bootstrap, and the control plane fills in
every secret. It was built and worked end to end: one node with no Vector on the control plane,
69 % less ingest, and enforced recipes reached the node.

## Decision

Rejected. Sluice will not run or steer a fleet of pipeline nodes. Its product is the
configuration: Vector pipelines, data collection rules and agent configurations, each with a
proof that no detection changes. People deploy that configuration with the tooling they already
have, such as Git, CI, Ansible, Kubernetes or Vector's own providers.

The reasons:

1. **Lock-in.** The project aims to make Cribl-style pipeline platforms and SIEM lock-in
   obsolete. A control plane that every node depends on to start and to change would be a new
   platform of exactly that kind.
2. **Vector already does this better.** Vector's providers, its reload behaviour and the
   ecosystem around it handle running pipelines at scale. A Sluice-specific transport would
   duplicate them and do the job worse.
3. **Secrets would travel.** The HTTP provider does not resolve `SECRET[...]` (see below), so the
   control plane had to serve SIEM credentials over the network. Configuration files leave
   secrets where the operator already keeps them.

Instead, the plan makes the output scale (PLAN.md, "Configs as the product"). Configurations go to a directory or a Git repository, so a
change becomes a reviewable diff or pull request rather than a live push. A CI check proves each
change: the alert set over full data equals the alert set over forwarded data. A load test
measures the generated configuration on a stock Vector.

## Consequences

- `sluice up` keeps its single local Vector (ADR 0005) as the way to try Sluice and to run it on
  one host. The `data_plane` setting, `sluice node` and `/data-plane/config` were removed before
  release.
- Anyone who wants Vector to pull its configuration over HTTP can point the provider at a file
  server or a Git host that serves Sluice's output. The facts below tell them what to expect.

### Vector's HTTP config provider (verified 2026-10-11, Vector 0.59.0)

These facts were verified with probes in WSL and in the end-to-end run.

- **TOML only.** A YAML body fails with a TOML parse error.
- **Sends its headers on every poll**, so a bearer token authenticates each fetch.
- **Reloads the topology on every poll**, even when nothing changed. The pipeline keeps running;
  the reloads are the cost of a short poll interval.
- **Exits at startup if the URL is unreachable** ("Configuration error. error=HTTP error") and
  does not retry. Run it under a supervisor that restarts it.
- **Does not resolve `SECRET[...]` in the pulled configuration**, not even with a `directory`
  secret backend defined in the same configuration. The reference is sent literally.
