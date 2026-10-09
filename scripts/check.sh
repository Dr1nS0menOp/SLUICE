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

if command -v cargo-deny >/dev/null 2>&1; then
    step "deny"
    cargo deny --all-features check
else
    printf '\n==> deny: skipped (cargo-deny not installed)\n'
fi

printf '\nAll gates passed.\n'
