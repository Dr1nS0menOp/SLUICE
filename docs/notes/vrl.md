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

## Version coupling

Vector embeds a specific `vrl` version. The VRL that Sluice proves must be the VRL that Vector
runs, so we pin `vrl` to the version used by the targeted Vector release (see
`docs/compatibility.md`).
