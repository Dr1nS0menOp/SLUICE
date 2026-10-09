#!/usr/bin/env bash
# Differential test of Sluice's Sigma rule requirements against pySigma (the reference parser).
#
#   scripts/sigma-differential.sh                  # the example rules
#   scripts/sigma-differential.sh --sigmahq        # the full SigmaHQ rule set, fetched at runtime
#   scripts/sigma-differential.sh <rules_dir>
#
# Needs a Python with pySigma: `pip install pysigma==2.0.0`, or set PYTHON to one that has it.
# SigmaHQ rules are DRL-licensed, so they are cloned into a cache, never into the repository.
set -euo pipefail

python="${PYTHON:-python3}"
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
"${python}" scripts/sigma_differential.py "${work}/requirements.json" "${rules}"
