#!/usr/bin/env bash
# Runs `sluice analyze` on real data collected by `collect-windows.ps1` and `collect-linux.sh`,
# with SigmaHQ alone and with SigmaHQ plus the stock Wazuh ruleset, and prints each run's
# summary. The numbers to compare with are in docs/testing-plan.md ("Real-data runs").
#
#   scripts/real-data/run.sh [DATA_DIR]
#
# DATA_DIR (default ~/.cache/sluice-realdata) holds `windows/`, `linux/` and, from
# `collect-sentinel.sh`, `sentinel/`. SIGMA_RULES and WAZUH_INVENTORY point at a SigmaHQ `rules`
# directory and a `sluice rules fetch wazuh` directory; SENTINEL_RULES at Azure-Sentinel's
# "Windows Security Events" solution, run in the Kusto emulator at KUSTO.
set -euo pipefail

data=${1:-$HOME/.cache/sluice-realdata}
sigma=${SIGMA_RULES:-$HOME/.cache/sluice/sigmahq/rules}
wazuh=${WAZUH_INVENTORY:-$HOME/.cache/sluice/inventory/wazuh}
sentinel=${SENTINEL_RULES:-$HOME/.cache/sluice/azure-sentinel/Solutions/Windows Security Events}
kusto=${KUSTO:-http://127.0.0.1:8090}

cat >"$data/windows/sources.yaml" <<'EOF'
sources:
  - id: system
    logsource: { product: windows, service: system, complete: true }
    format: { kind: json }
    schema: sigma
  - id: application
    logsource: { product: windows, service: application, complete: true }
    format: { kind: json }
    schema: sigma
  - id: ps-script
    logsource: { product: windows, category: ps_script, complete: true }
    format: { kind: json }
    schema: sigma
  - id: ps-other
    logsource: { product: windows, service: powershell }
    format: { kind: json }
    schema: sigma
EOF
# auth.log and syslog are all their log sources are: without `complete`, rules for any
# category of Linux apply and nothing is summarized.
cat >"$data/linux/sources.yaml" <<'EOF'
sources:
  - id: linux-auth
    logsource: { product: linux, service: auth, complete: true }
    format: { kind: text, field: message }
  - id: linux-syslog
    logsource: { product: linux, service: syslog, complete: true }
    format: { kind: text, field: message }
EOF

cargo build --release --locked -q -p sluice-cli
sluice=${CARGO_TARGET_DIR:-target}/release/sluice

for set in windows linux; do
    for rules in sigma wazuh; do
        args=(--input "$data/$set" --sources "$data/$set/sources.yaml" --rules "$sigma"
            --rules-complete --out "$data/out/$set-$rules")
        if [ "$rules" = wazuh ]; then
            args+=(--wazuh-rules "$wazuh/rules" --wazuh-decoders "$wazuh/decoders")
        fi
        echo "=== $set, $([ "$rules" = wazuh ] && echo 'SigmaHQ + Wazuh' || echo SigmaHQ)"
        /usr/bin/time -f "(%e s, %M KB)" "$sluice" analyze "${args[@]}" 2>&1 \
            | grep -v -e '^hint:' -e '^warning:'
    done
done

if [ -d "$data/sentinel" ]; then
    # The records as the workspace stores them; the source ids are the file names.
    cat >"$data/sentinel/sources.yaml" <<'EOF'
sources:
  - id: SecurityEvent
    logsource: { product: windows, service: security }
    format: { kind: json }
    schema: sentinel
  - id: WindowsEvent
    logsource: { product: windows }
    format: { kind: json }
    schema: sentinel
EOF
    echo "=== Sentinel records, Windows Security Events solution in the emulator + SigmaHQ"
    /usr/bin/time -f "(%e s, %M KB)" "$sluice" analyze --input "$data/sentinel" \
        --sources "$data/sentinel/sources.yaml" --rules "$sigma" --sentinel-rules "$sentinel" \
        --kusto "$kusto" --sentinel-table SecurityEvent=SecurityEvent \
        --sentinel-table WindowsEvent=WindowsEvent --rules-complete \
        --out "$data/out/sentinel" 2>&1 | grep -v -e '^hint:' -e '^warning:'
fi
