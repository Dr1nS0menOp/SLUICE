# VRL crate: verified notes

These notes were verified against `vrl = "=0.36.0"` (MPL-2.0, edition 2024, MSRV 1.95) on
2026-10-09, with Linux (WSL2 Ubuntu 24.04) and Rust 1.99.

## Embedding: compile and run

```rust
use vrl::compiler::{compile, runtime::Runtime, TargetValue, TimeZone};
use vrl::value::{Secrets, Value};

let fns = vrl::stdlib::all();
let compiled = compile(src, &fns)?;           // CompilationResult { program, warnings, .. }
let mut target = TargetValue {
    value: Value::from(serde_json_value),      // From<serde_json::Value> exists
    metadata: Value::Object(Default::default()),
    secrets: Secrets::default(),
};
Runtime::default().resolve(&mut target, &compiled.program, &TimeZone::default())?;
// target.value now holds the transformed event; it serializes with serde_json.
```

- Use `compile_with_external` / `Compiler::compile` with a `TypeState` when the input schema is
  known, so type checking can catch more mistakes.
- `Runtime` keeps variable state. Create a fresh one, or call `clear()`, between events.

## Features

- Use `default-features = false, features = ["compiler", "stdlib-base"]`. The defaults also pull in
  the `cli` (clap, rustyline) and network functions (reqwest), which we don't need.
- `stdlib-base` turns on `datadog`, which compiles `onig` (C), so the build needs a C compiler
  (gcc).

## Verified behaviour

- `del(.Message)` removes the field.
- `. = compact(.)` removes both `null` values and empty strings by default. This is not the same as
  "drop null only": L1 must decide whether an empty string carries meaning. Rules may match `''`
  (Sigma `field: ''`), so the guardrails must keep fields that a rule matches as empty.

## Gotchas for generated VRL

These were verified against 0.36.0 while building `sluice-vector`, on 2026-10-09.

- **String literals are templates.** `"…{{ x }}…"` interpolates. Generated strings escape every
  brace as `\{`/`\}`, which never forms a marker. Don't use `\{{`: the scanner reads `\\{{` (an
  escaped backslash followed by `{{`) as an escaped template.
- **Escapes the lexer accepts:** `\" \\ \n \r \t \0 \{ \} \'` and `\u{HEX}`. Rust's
  `char::escape_unicode()` produces exactly `\u{…}`. An unknown escape panics in
  `unescape_string_literal` if the lexer lets it through, so only these are emitted.
- **Regex literals are `r'…'`.** A `'` inside is written as the regex escape `\x27`. VRL compiles
  them with the `regex` crate, so Sluice validates patterns with the same crate first; anything
  unsupported, such as lookaround, widens the test instead of failing compilation.
- **`flatten(.)`** flattens nested objects with `.`. Arrays stay leaves and **empty objects
  vanish**. `keys()` of the result is sorted, because VRL objects are B-trees. Discovery's key
  sets follow the same rules, so the classifier is an exact string comparison.
- **Fallibility.** On an `any`-typed value, `to_string`, `flatten` and `keys` are fallible. The
  generated code uses `!` (a runtime abort becomes a `ReduceError`, so the proof fails closed) or
  `?? ""` where a default is safe.
- **Blocks in expressions.** `{ … }` in expression position can parse as an object literal.
  Generated predicates assign each test to a variable with statements, and then combine the
  variables.
- **Metadata** (`%sluice.route`) is readable and writable from VRL. After `Runtime::resolve` it
  is in `TargetValue::metadata`. Sluice routes on it.
- **Long operator chains overflow the stack** (found 2026-10-10 with the full SigmaHQ set). VRL
  parses and type-checks `a || b || c …` one recursion level per operand; a pre-filter over a
  few thousand rules aborted the process. Generated chains are balanced trees of parentheses
  (depth log₂ n).
- **Many `contains` calls are slow on large values.** `contains(x, y, case_sensitive: false)`
  lowercases `x` on every call; hundreds of rules against 20 KB PowerShell script blocks took
  minutes. Generated code lowercases once and matches one alternation of escaped literals
  (`match(downcase(x), r'(?:a|b|…)')`, anchored for equality and prefixes/suffixes), which the
  `regex` crate runs as one Aho-Corasick scan. Lowercasing value and literals with Rust's
  `to_lowercase` is what VRL's case-insensitive functions do, so both forms decide alike.

## Vector runtime facts for `sluice up`

These were found in the live smoke test against Vector 0.59.0 on 2026-10-09.

- **The `sample` transform adds a `sample_rate` field** by default. The tapped events then have
  a different key set than the pipeline's, so no classifier matched and everything passed
  through. Set `sample_rate_key: ""`.
- **`--watch-config` misses atomic renames.** The watcher follows the old inode. Sluice writes
  through a temp file and rename, then sends **SIGHUP**. Vector logs "Reloading running topology
  … New configuration loaded successfully."
- **`reduce` closes a group only after `expire_after_ms` of silence.** A steady stream never
  closes, so set `end_every_period_ms` as well.
- **Stopping:** Vector flushes its sinks (including the gzip archive) on SIGTERM. A SIGKILL
  loses buffered events, so `sluice up` sends SIGTERM and waits up to 60 s.
- **YAML merge keys** (`<<: *anchor`) are resolved by Vector's parser but not by `serde`.
  `sluice up` calls `apply_merge()` before deserializing its own config.
- **`http_server` adds `path`, `source_type` and `timestamp`** (receive time, RFC 3339 UTC) to
  each event with the default log namespace. They are archived with the event, and a replay into
  another `http_server` source overwrites them. `sluice search` uses `timestamp` as the event's
  archive time.
- **File sink path templates (`%Y`, `%H`) render in UTC** by default, but the global `timezone`
  option changes that. The archive sink sets `timezone: UTC` so the path layout is fixed.
- **A gzip file sink holds one gzip stream per open file.** While Vector writes the current hour
  the stream has no trailer yet, so a reader gets the flushed events and then an unexpected end
  of file. `sluice search` reports such files instead of failing, and reads concatenated gzip
  members, which appear if a file is reopened.

## Destination sinks (`sluice connect`)

Checked with `vector validate` against Vector 0.59.0 on 2026-10-09 (`scripts/vector-check.sh`
validates all of them on every run). `vector generate --format yaml '//<sink>'` prints a sink's
full default configuration, which is the quickest way to see its real field names.

- `splunk_hec_logs`: `endpoint`, `default_token`, `encoding`.
- `elasticsearch`: `endpoints` (a list), `mode: bulk`, `bulk.index`, `auth.strategy: basic`.
- `azure_logs_ingestion` (Sentinel): `endpoint`, `dcr_immutable_id`, `stream_name`, and the
  credentials nested under `auth` with `azure_credential_kind: client_secret_credential` (the
  default kind is `managed_identity`). Top-level `azure_client_id` is rejected.
- `gcp_chronicle_unstructured`: `endpoint`, `customer_id`, `credentials_path`, `log_type`,
  `encoding`.
- **`${VAR}` is not interpolated** in Vector 0.59 unless it runs with
  `--dangerously-allow-env-var-interpolation`: a probe server received `Bearer ${PROBE_TOKEN}`
  literally (2026-10-10). `vector validate` does not notice. Credentials therefore go through a
  secret backend: `secret: {siem: {type: directory, path: /run/secrets/siem}}` and
  `SECRET[siem.splunk_hec_token]` read the file `/run/secrets/siem/splunk_hec_token` (verified
  with the same probe). Vector resolves every referenced secret at load time, so a missing file
  fails validation.

## Version coupling

Vector embeds a specific `vrl` version. The VRL that Sluice proves must be the VRL that Vector
runs, so we pin `vrl` to the version used by the targeted Vector release (see
`docs/compatibility.md`).
