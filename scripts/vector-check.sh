#!/usr/bin/env bash
# Generates the test Vector configurations and checks them with the real Vector binary:
# `vector validate` (config is well-formed), `vector test` (Vector reduces the sample events
# exactly as the vrl crate did for the proof), and `vector validate` of every `sluice connect`
# destination sink. Requires `scripts/install-vector.sh`.
set -euo pipefail

command -v vector >/dev/null || { echo "vector not found; run scripts/install-vector.sh" >&2; exit 1; }
cargo test -q -p sluice-vector --test config --test connect >/dev/null

target_dir="${CARGO_TARGET_DIR:-target}"
config="${target_dir}/tmp/vector.yaml"
echo "==> vector validate ${config}"
vector validate --no-environment "${config}"
echo "==> vector test ${config}"
vector test "${config}"

# The destination sinks read dummy secrets from a directory backend the test wrote.
connect="${target_dir}/tmp/connect.yaml"
echo "==> vector validate ${connect}"
vector validate --no-environment "${connect}"
