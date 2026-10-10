# Changelog

All notable changes to Sluice are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

First public version (0.1.0). Linux only (x86_64 and aarch64), including WSL2.

### Offline autopilot

- `sluice demo` and `sluice analyze`: template discovery (JSON key sets, Drain for text with
  BSD and ISO syslog headers), community recipes, guardrails, shadow proof against Sigma rules,
  `report.html` and a `vector.yaml` with Vector unit tests.
- Sigma rules via rsigma, including correlations and filters; Wazuh `rules.xml` requirements,
  read as leniently as Wazuh reads them and bounded by decoders (`--wazuh-decoders`) and
  `<if_sid>` chains; an optional live Wazuh `logtest` spot check (`--wazuh-api`), with text
  sources sent as raw lines.
- An optional AI advisor (`--llm`: Anthropic, Ollama, LM Studio, any OpenAI-compatible API) with
  redacted samples. Its proposals pass the same guardrails as any other.
- Guardrails scope rules by log source and per template, protect what a rule reads only on events
  the rule could match, and support complete log sources (ADR 0009). `sluice analyze` hints at
  sources whose description keeps extra rules in scope.

### Live operation

- `sluice up`: Vector with a generated pipeline, a full-fidelity gzip archive, a sampled tap to the
  control plane, shadow, promotion, continuous re-proof and rollback, with SIGHUP reloads.
- `sluice status`, `sluice search`, `sluice replay` (ADR 0006).
- `sluice connect` for Splunk, Elastic, Microsoft Sentinel, Google SecOps, Wazuh (JSON and raw-line
  files) and HTTP, validated against Vector 0.59.

### Security

- Destination credentials through Vector secret backends (`vector_secrets`, `SECRET[…]`); Vector
  0.59 does not expand `${VAR}` (ADR 0010).
- An optional bearer token for the control plane (`SLUICE_CONTROL_TOKEN`), handed to Vector as a
  secret file; without one, `sluice up` only listens on loopback.

### Interfaces and packaging

- `sluice mcp`: an MCP server over stdio or bearer-token HTTP with `status`, `templates`,
  `explain`, `what_breaks`, `coverage_gaps`, `source_health`, `search_archive` and gated `replay`.
- `sluice recipes schema|export` and a JSON Schema for recipes; `sluice rules requirements`.
- Static musl binaries, a Docker image on Vector's distroless image, a compose example (ADR 0007),
  and a Helm chart.
- `sluice up --check`: validates a configuration and prints the Vector configuration it starts
  with, without starting anything.
- AGPL-3.0-only (ADR 0008).

### Verification

- Quality gates: fmt, clippy (pedantic, warnings as errors), tests including property tests,
  docs, cargo-deny, and `vector validate`/`vector test` against the real Vector.
- Live smoke and replay tests against Vector; a differential test of rule requirements against
  pySigma on the full SigmaHQ rule set; a Helm chart check.
- Property tests for the safety claims: the guardrails alone (without the proof) keep every
  alert; hostile field names, values and text lines always compile and keep every alert; no
  rule, decoder, recipe, condition or time input makes a parser panic.
