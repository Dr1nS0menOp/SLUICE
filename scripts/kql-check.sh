#!/usr/bin/env bash
# Differential test of the KQL backend against the real KQL engine (Kusto emulator, ADR 0013).
# Starts the emulator in Docker if it is not running, then runs the emulator test.
# The image is about 4.5 GB; check.sh runs this only when the image is already present.
set -euo pipefail

image="mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest"
name="sluice-kusto"
port="${SLUICE_KUSTO_PORT:-8090}"
url="http://127.0.0.1:${port}"

ready() {
    curl -fsS -X POST "${url}/v1/rest/query" -H 'Content-Type: application/json' \
        -d '{"db":"NetDefaultDB","csl":"print v=1"}' >/dev/null 2>&1
}

if ! ready; then
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run -d --name "$name" -e ACCEPT_EULA=Y -m 4G -p "127.0.0.1:${port}:8080" "$image" >/dev/null
    for _ in $(seq 1 90); do
        ready && break
        sleep 2
    done
    ready || { echo "the Kusto emulator did not start" >&2; exit 1; }
fi

SLUICE_KUSTO_URL="$url" cargo test --locked -p sluice-kql --test emulator -- --nocapture
