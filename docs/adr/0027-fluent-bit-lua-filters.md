# ADR 0027: Fluent Bit Lua filters, proven like VRL

- Status: Accepted
- Date: 2026-10-17

## Context

PLAN.md M12, step 2 of "advice first, configs for every tool": after Vector, Sentinel DCRs
(ADR 0013) and Elasticsearch ingest pipelines (ADR 0024), generators for agents such as Fluent
Bit and the OpenTelemetry Collector. Many teams already run Fluent Bit on their hosts; a saving
made there leaves the host smaller and needs no pipeline tool in between. Fluent Bit's `lua`
filter runs a script per record (LuaJIT), which can express what the other generators do.

## Decision

1. **One Lua filter per source** (`sluice_fluentbit::lua_filter`, `--fluent-bit-native` for
   `analyze` and `demo`, with `--fluent-bit CMD`): the same three rules as the ingest pipeline.
   Recognition is exact and in Vector's order (leaf paths equal to a key set, discriminators
   rendered as VRL renders them), the keep-whole condition is a superset of the VRL
   (`sluice_fluentbit::compile`), and everything is decided before anything is removed. Only
   field removals run there: text templates and counting stay with a pipeline tool.
2. **An unchanged record is not touched.** The filter returns code 0, and Fluent Bit forwards
   the record exactly as it was. Lua cannot give every value back: a changed record loses its
   nulls without `enable_flb_null` (the filter section Sluice writes sets it), integers past
   2^53 lose precision, `-0` becomes `0`. A record holding such a number is never changed.
   A whole float comes back as an integer (`2.0` as `2`): the same number, accepted.
3. **Lua cannot tell what VRL can, and widens.** An integral number may have been a float, so a
   test on one matches when a float would; an empty table may be an object (no leaf) or an
   array (a leaf), so a record holding one is not recognised; a case-insensitive test on
   non-ASCII text matches; regexes match.
4. **The proof runs Fluent Bit itself** (`sluice_fluentbit::FluentBit`, any command that takes
   Fluent Bit's arguments: the binary, or a container wrapper). The records go through Fluent
   Bit without the filter and with it, because Fluent Bit changes some on its own (`1e21` is read
   as `1`): with the filter, no field goes that the proven data plane keeps, no other value
   changes, and the rules raise the same alerts.
5. **Tests against the real engine** (`scripts/fluentbit-check.sh`, in `check.sh` when the image
   `fluent/fluent-bit:4.0.3` is present, and in CI): edge records through the filter lose
   exactly what they lose in Vector or stay whole, the differential test of 2,474 predicates
   (Lua true wherever VRL is), and the demo with `--fluent-bit-native`.

## Consequences

- On the synthetic sample the filters save what the Elasticsearch pipelines save (Windows
  Security 32.0 %, DNS 34.1 %), with the same alerts.
- Lua is less precise than Painless: 9,447 tests true where VRL is false against 3,117, mostly
  integral numbers that might have been floats. That keeps more whole, never less.
- The filter runs per record on the host; its cost grows with the keep-whole conditions. Large
  rule sets make it slower, not wrong.
- The OpenTelemetry Collector (OTTL) is next on the same pattern.
