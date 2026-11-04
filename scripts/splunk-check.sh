#!/usr/bin/env bash
# Splunk's searches in a real Splunk (ADR 0037): the engine the proof runs them in, the fetch
# over the REST API, and `sluice analyze --splunk` end to end.
#
# Uses the Splunk at SLUICE_SPLUNK_URL (its management port, with the password of `admin` in
# SLUICE_SPLUNK_PASSWORD and, if its HTTP Event Collector is not on the port it reports, the
# collector's address in SLUICE_SPLUNK_HEC). Otherwise starts a throwaway one in Docker
# (container `sluice-splunk`, on 127.0.0.1 only, ports SLUICE_SPLUNK_PORT and
# SLUICE_SPLUNK_HEC_PORT, default 18089 and 18088). WSL2 distros share one network, so a port
# another distro holds needs another port.
#
# Splunk's image starts only with its licence and the Splunk General Terms accepted
# (https://www.splunk.com/en_us/legal/splunk-general-terms.html). This script accepts nothing on
# your behalf: it starts Splunk only when you have set the image's own variable,
#   export SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com
set -euo pipefail
cd "$(dirname "$0")/.."

image=${SPLUNK_IMAGE:-splunk/splunk:10.6.1.1}
port=${SLUICE_SPLUNK_PORT:-18089}
hec_port=${SLUICE_SPLUNK_HEC_PORT:-18088}
password=${SLUICE_SPLUNK_PASSWORD:-sluice-proof-1}

if [[ -z ${SLUICE_SPLUNK_URL:-} ]]; then
    url=https://127.0.0.1:${port}
    hec=https://127.0.0.1:${hec_port}
    answers() {
        [[ $(curl -ks -o /dev/null -w '%{http_code}' -u "admin:${password}" \
            "$url/services/server/info") == 200 ]]
    }
    if ! answers; then
        if ! command -v docker >/dev/null || ! docker image inspect "$image" >/dev/null 2>&1; then
            echo "==> splunk: skipped (docker pull $image to run it)"
            exit 0
        fi
        if [[ ${SPLUNK_GENERAL_TERMS:-} != --accept-sgt-current-at-splunk-com ]]; then
            echo "==> splunk: skipped (Splunk's image needs the Splunk General Terms accepted:"
            echo "    export SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com)"
            exit 0
        fi
        # Started and still starting on this port: wait for it; anything else: start it afresh.
        if [[ $(docker port sluice-splunk 8089 2>/dev/null) != "127.0.0.1:${port}" ]]; then
            docker rm -f sluice-splunk >/dev/null 2>&1 || true
            docker run -d --name sluice-splunk \
                -p "127.0.0.1:${port}:8089" -p "127.0.0.1:${hec_port}:8088" \
                -e SPLUNK_START_ARGS=--accept-license \
                -e SPLUNK_GENERAL_TERMS="$SPLUNK_GENERAL_TERMS" \
                -e SPLUNK_PASSWORD="$password" \
                "$image" >/dev/null \
                || { echo "cannot start Splunk on port $port: set SLUICE_SPLUNK_PORT" >&2; exit 1; }
        fi
        # Ready when the image's own provisioning is done, not only when splunkd answers.
        for _ in $(seq 1 120); do
            [[ $(docker inspect -f '{{.State.Health.Status}}' sluice-splunk 2>/dev/null) == healthy ]] \
                && answers && break
            sleep 5
        done
    fi
    answers || { echo "Splunk at $url does not answer" >&2; exit 1; }
    export SLUICE_SPLUNK_URL=$url
    export SLUICE_SPLUNK_HEC=${SLUICE_SPLUNK_HEC:-$hec}
fi
export SLUICE_SPLUNK_PASSWORD=$password
cargo test --locked -p sluice-splunk -- --nocapture
# End to end: `sluice analyze` with the demo's rules as saved searches, proven in Splunk.
cargo test --locked -p sluice-cli --test splunk -- --nocapture
