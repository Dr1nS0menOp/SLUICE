#!/usr/bin/env bash
# Differential test of Sluice's Sigma rule requirements against pySigma (the reference parser).
#
#   scripts/sigma-differential.sh                  # the example rules
#   scripts/sigma-differential.sh --sigmahq        # the full SigmaHQ rule set, fetched at runtime
#   scripts/sigma-differential.sh <rules_dir>
#
# Needs pySigma 2.0.0: from PYTHON when set, else from python3 when it has pySigma, else fetched
# by uv into its cache (a distribution's own Python, Ubuntu 24.04's say, refuses `pip install`).
# SigmaHQ rules are DRL-licensed, so they are cloned into a cache, never into the repository.
set -euo pipefail

pysigma="pysigma==2.0.0"
if [ -n "${PYTHON:-}" ]; then
    python=("${PYTHON}")
elif python3 -c 'import sigma' 2>/dev/null; then
    python=(python3)
elif command -v uv >/dev/null 2>&1; then
    python=(uv run -q --no-project --with "${pysigma}" python)
else
    echo "needs pySigma: install uv, or \`pip install ${pysigma}\`, or set PYTHON" >&2
    exit 1
fi
rules="${1:-examples/rules/sigma}"
if [ "${rules}" = "--sigmahq" ]; then
    rules="${XDG_CACHE_HOME:-$HOME/.cache}/sluice/sigmahq"
    if [ -d "${rules}/.git" ]; then
        git -C "${rules}" pull -q --ff-only
    else
        git clone -q --depth 1 https://github.com/SigmaHQ/sigma.git "${rules}"
    fi
    rules="${rules}/rules"
fi

target_dir="${CARGO_TARGET_DIR:-target}"
cargo build -q --locked -p sluice-cli
work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT
"${target_dir}/debug/sluice" rules requirements --rules "${rules}" > "${work}/requirements.json" 2> "${work}/warnings"
echo "Sluice warnings: $(wc -l < "${work}/warnings")"
"${python[@]}" scripts/sigma_differential.py "${work}/requirements.json" "${rules}"
