# ADR 0005: The live control loop

- Status: Accepted
- Date: 2026-10-09

## Context

In M1 Sluice analyzes a static sample. M2 runs it live (`sluice up`): Vector carries the traffic,
and Sluice must discover, prove, enforce, keep verifying and roll back on its own (PLAN:
"Lifecycle (zero-touch)"). That needs a process model, a way to see traffic, and a promotion
policy.

## Decision

1. **Two processes.** `sluice up` runs the control plane and spawns Vector as a child process.
   The data plane never depends on the control plane being up: if Sluice dies, Vector keeps
   running the last enforced config.
2. **Config by file, reload by signal.** Sluice writes `vector.yaml` atomically (temp file plus
   rename) and sends Vector SIGHUP. `--watch-config` is not used: its watcher follows the
   replaced inode and misses the change (`docs/notes/vrl.md`). Scale-out nodes can later pull
   the same file through Vector's HTTP config provider.
3. **Tap before reduction.** Each source's parsed stream goes to the archive and the reduction
   program as before. A sampled copy (`sample` transform) goes to the control plane through an
   `http` sink (`POST /tap`, NDJSON). The control plane keeps a bounded rolling window per
   source, and its cost is bounded by that window, not by traffic.
4. **Promotion is a pure state machine** (`sluice_autopilot::lifecycle`):
   - `Candidate`: proposed by the autopilot, not enforced.
   - `Shadow { since, proofs }`: proven on consecutive windows, still not enforced.
   - `Enforced`: in the deployed VRL.

   A candidate becomes enforced after the shadow period *and* a minimum number of consecutive
   proofs (defaults: 24 h, 3). Any failed proof, whether in shadow or after enforcement, demotes
   the template to `Candidate`. If it was enforced, that is a **rollback**: the config is
   regenerated without it and an event is emitted.
5. **Every cycle re-proves the enforced set** on the newest window (continuous verification,
   contract rule 5). A failure there wins over everything else.
6. **Time is an input.** The state machine takes `now` as a parameter, so tests drive it through
   days of shadow in microseconds.
7. **HTTP API on the control plane** (axum): `POST /tap`, `GET /status`, `GET /healthz`. The
   `sluice status` command and the MCP server (M3) read `/status`.

## Consequences

- Drift needs no special case. A changed format is a new template id, which has no recipe and
  passes through (contract rule 1) until it earns one through the same lifecycle.
- A rollback is effective at Vector's next config reload, typically within a second.
- The control plane needs `tokio` and `axum`. Both live only in the server crate; core and the
  autopilot stay synchronous and pure.
- Archive search and replay follow in ADR 0006; `sluice connect` follows as a separate step.
