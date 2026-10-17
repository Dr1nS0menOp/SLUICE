# Compatibility

Sluice proves its reductions by running the same VRL that Vector runs. That only holds when the
`vrl` crate embedded in Sluice matches the one in the Vector release that enforces the config.

| Sluice | `vrl` crate | Vector release | Status |
|--------|-------------|----------------|--------|
| 0.1.0 (unreleased) | 0.36.0 | 0.59.0 | `vrl = "0.36.0"` confirmed in Vector v0.59.0's `Cargo.toml` (2026-10-09) |

When bumping `vrl`, look up which Vector release pins that version (its `Cargo.toml`, workspace
`vrl` entry) and update this table, `scripts/install-vector.sh`, the `Dockerfile` base image (tag
and digest) and `Cargo.toml` in the same change.

Code generated for a SIEM's own ingestion is proven in that SIEM's engine:

| Target | Engine the proof runs in | Verified with |
|--------|--------------------------|---------------|
| Sentinel DCR `transformKql` (ADR 0013) | Kusto emulator (`kustainer-linux:latest`) | a real Log Analytics workspace, 2026-10-17 |
| Elasticsearch ingest pipeline (ADR 0024) | Elasticsearch 9.1.0 (`scripts/elastic-check.sh`) | the same, single node, 2026-10-17 |
| Fluent Bit Lua filter (ADR 0027) | Fluent Bit 4.0.3 (`scripts/fluentbit-check.sh`) | the same, `fluent/fluent-bit:4.0.3`, 2026-10-17 |
| OpenTelemetry Collector `transform` statements (ADR 0028) | otelcol-contrib 0.128.0 (`scripts/otel-check.sh`) | the same, `otel/opentelemetry-collector-contrib:0.128.0`, 2026-10-17 |
