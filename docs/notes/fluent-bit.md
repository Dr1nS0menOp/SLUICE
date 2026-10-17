# Fluent Bit notes

Facts about Fluent Bit that `sluice-fluentbit` relies on, verified 2026-10-17 against Fluent Bit
4.0.3 (`fluent/fluent-bit:4.0.3`, Git commit `f5f5f3c`) with the `stdin` input and the `stdout`
output in `json_lines` format.

## The Lua filter

- `Call` names a global function `(tag, timestamp, record)`. It returns a code and the
  timestamp and record: `0` keeps the record exactly as it was (the script's table is not
  used), `1` takes the new timestamp and record, `2` the new record with the old timestamp, `-1`
  drops the record.
- A record arrives as Lua values: strings, numbers (LuaJIT: doubles, integers and floats
  alike), booleans, tables for objects and arrays alike.
- A returned record goes back through those values:
  - a JSON `null` is `nil` and the key is gone, unless the filter sets `enable_flb_null true`:
    then it is `flb_null` and comes back as `null`;
  - an integer past 2^53 loses precision (`9007199254740993` → `9007199254740992`), and past
    2^63 it comes back as `-9223372036854775808`;
  - `-0.0` comes back as `0`, a whole float as an integer (`2.0` → `2`, `1500.0` → `1500`);
  - empty arrays and objects keep their kind; key order is not kept.
- A script that does not load makes Fluent Bit exit with an error (no record is forwarded).

## Fluent Bit itself

- The `stdin` input reads one JSON object per line. It reads `1e21` as `1` and saturates
  integers past 2^63 at `9223372036854775807`, with or without a filter. Its `Buffer_Size`
  (default 16 KB) bounds a line.
- Records leave in the order they came in, through one input and one output.
- `-q` keeps the banner off stdout; errors go to stderr.
