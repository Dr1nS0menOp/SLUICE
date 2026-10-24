# OpenTelemetry Collector notes

Facts about the collector and OTTL that `sluice-otel` relies on, verified 2026-10-17 against
`otelcol-contrib` 0.128.0 (`otel/opentelemetry-collector-contrib:0.128.0`) with the `filelog`
receiver, the `transform` processor and the `file` exporter.

## filelog and json_parser

- `json_parser` with `parse_to: body` makes the body a map. Every JSON number becomes a double
  (`4624` → `doubleValue: 4624`), so integers past 2^53 lose precision there. So `IsInt` is
  false for every JSON number (verified 2026-10-24: `IsInt(log.body["Level"])` on `"Level": 0`),
  and an implied whole number cannot be tested as VRL's `is_integer(.x) && .x == 0` tests it:
  the transform statements leave such a value in place.
- A JSON null becomes an empty value; empty arrays and objects keep their kind.
- `include_file_record_number: true` adds `log.file.record_number` (the line, from 1). The file
  exporter writes one OTLP JSON document per batch, and batches need not keep the input's order.
- `log.file.name` is always added as an attribute.

## OTTL in the transform processor

- Comparisons may only appear in a `where` clause, not as a value of `set`.
- Boolean conditions are evaluated left to right and stop early: `IsMap(x) and x["a"] == 1` does
  not fail when `x` is a string.
- Indexing into a string fails the statement: `type Str does not support string indexing`. With
  `error_mode: propagate` the batch is dropped; with `ignore` the statement is skipped.
- A null value and a missing key both read as `nil`; `Len(map)` counts null keys.
- `set(log.cache["c"], log.body)` copies the map: deleting from the copy leaves the body as it
  was. `delete_matching_keys(map, regex)` deletes by key.
- `String(map)` is the map's JSON with keys sorted; it escapes `<`, `>` and `&` as `<`,
  `>`, `&`. `String(4624.0)` is `"4624"`, `String(2.0)` is `"2"`.
- `IsMatch` takes RE2 patterns; on a number it matches its text. `ToLowerCase` folds Unicode.
- There is no `Keys` converter in 0.128.0; `flatten` flattens arrays too (`a.0`), unlike VRL.
- `log.cache` is a per-record scratch map that is not exported.
