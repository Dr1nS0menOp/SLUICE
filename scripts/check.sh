#!/usr/bin/env bash
# Run every quality gate. Exits non-zero on the first failure.
# On Windows with Smart App Control: ./scripts/wsl.ps1 bash scripts/check.sh
set -euo pipefail

step() { printf '\n==> %s\n' "$*"; }

step "fmt"
cargo fmt --all --check

step "clippy"
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

step "test"
cargo test --workspace --all-features --locked

step "doc"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked

step "example report (docs/example-report.html is what the demo writes now)"
bash "$(dirname "$0")/example-report.sh" --check

if command -v cargo-deny >/dev/null 2>&1; then
    step "deny"
    cargo deny --all-features check
else
    printf '\n==> deny: skipped (cargo-deny not installed)\n'
fi

if command -v vector >/dev/null 2>&1; then
    step "vector (validate + unit tests against the real binary)"
    bash "$(dirname "$0")/vector-check.sh"
else
    printf '\n==> vector: skipped (run scripts/install-vector.sh)\n'
fi

if command -v docker >/dev/null 2>&1 \
    && docker image inspect mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest >/dev/null 2>&1; then
    step "kql (differential test against the Kusto emulator)"
    bash "$(dirname "$0")/kql-check.sh"
else
    printf '\n==> kql: skipped (pull mcr.microsoft.com/azuredataexplorer/kustainer-linux)\n'
fi

if [[ -n ${SLUICE_ELASTIC_URL:-} ]] || { command -v docker >/dev/null 2>&1 \
    && docker image inspect docker.elastic.co/elasticsearch/elasticsearch:9.1.0 >/dev/null 2>&1; }; then
    step "elastic (differential test against Elasticsearch)"
    bash "$(dirname "$0")/elastic-check.sh"
else
    printf '\n==> elastic: skipped (docker pull docker.elastic.co/elasticsearch/elasticsearch:9.1.0)\n'
fi

if command -v docker >/dev/null 2>&1 \
    && docker image inspect fluent/fluent-bit:4.0.3 >/dev/null 2>&1; then
    step "fluent-bit (Lua filters and their differential test against Fluent Bit)"
    bash "$(dirname "$0")/fluentbit-check.sh"
else
    printf '\n==> fluent-bit: skipped (docker pull fluent/fluent-bit:4.0.3)\n'
fi

if command -v docker >/dev/null 2>&1 \
    && docker image inspect otel/opentelemetry-collector-contrib:0.128.0 >/dev/null 2>&1; then
    step "otel (transform statements and their differential test against the collector)"
    bash "$(dirname "$0")/otel-check.sh"
else
    printf '\n==> otel: skipped (docker pull otel/opentelemetry-collector-contrib:0.128.0)\n'
fi

printf '\nAll gates passed.\n'
