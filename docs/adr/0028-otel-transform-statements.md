# ADR 0028: OpenTelemetry Collector transform statements, proven like VRL

- Status: Accepted
- Date: 2026-10-17

## Context

PLAN.md M12, step 2 of "advice first, configs for every tool": after Fluent Bit (ADR 0027), the
OpenTelemetry Collector. Its `transform` processor runs OTTL statements on each log record. OTTL
has no loops and no functions of one's own, reads a null and a missing key alike, and fails a
statement that indexes into a string.

## Decision

1. **OTTL statements per source** (`sluice_otel::transform`, `--otel-native` for `analyze` and
   `demo`, with `--otel-collector CMD`), for records whose body is the parsed JSON record (the
   `filelog` receiver's `json_parser` with `parse_to: body`). Only field removals: text
   templates and counting stay with a pipeline tool.
2. **Decisions go into `log.cache` first, then removals.** The statements, in order: copy each
   map the key sets have into the cache with the expected keys deleted (`delete_matching_keys`);
   set the template's number where none is set yet and the record is, level by level, a map of
   exactly the expected number of keys with none left in its copy, in template id order; set
   each keep-whole alternative to hold, then not to where its condition is false; set the
   decision to remove; then `delete_key` where that decision is set.
3. **A statement that fails keeps the record whole.** The processor runs with
   `error_mode: ignore`: a recognition that fails sets no template, a keep-whole alternative that
   fails still holds, a removal that fails removes nothing. Every path into a map is guarded
   with `IsMap` on each map above it, so no condition indexes into a string.
4. **Superset conditions** (`sluice_otel::compile`): field tests through `IsMatch` with
   literally quoted RE2 patterns behind type checks; an object or array, a number past 2^53, and
   case-insensitive tests on non-ASCII text widen to `true`, as does any number when a value
   could be a float's text (the collector makes every number a double). `exists` also looks for
   `"key":null` in the parent's JSON text. Keywords search the record's JSON text, and widen
   when they hold a character Go's JSON writer escapes or the record has an array that may hold
   an object or array.
5. **The proof runs the collector** (`sluice_otel::Collector`): the records through `filelog`,
   the statements (with `error_mode: propagate`, so a failing statement shows) and the `file`
   exporter, ordered by their line numbers, against the same records without the statements:
   nothing goes that Vector keeps, no other value changes, the rules raise the same alerts.
6. **Tests against the real engine** (`scripts/otel-check.sh`, in `check.sh` when the image
   `otel/opentelemetry-collector-contrib:0.128.0` is present, and in CI).

## Consequences

- On the synthetic sample the statements save what Vector, the Elasticsearch pipelines and the
  Fluent Bit filters save (Windows Security 32.0 %, DNS 34.1 %), with the same alerts.
- The differential test found a fail-open bug before anything shipped: a condition on a path
  below a string failed, and with errors ignored, its keep-whole alternative would have counted
  as false. Paths are guarded since, and an alternative now holds unless shown false.
- Keep-whole conditions are written per template set, not shared as functions; very large rule
  sets make long statement lists.
