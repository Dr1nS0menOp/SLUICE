#!/usr/bin/env bash
# Differential test of the Elasticsearch ingest pipelines Sluice generates (ADR 0024): runs them
# in a real Elasticsearch through `_ingest/pipeline/_simulate` and checks that they remove what
# the proven VRL removes, never more.
#
# Uses the Elasticsearch at SLUICE_ELASTIC_URL, or the one answering on localhost port
# SLUICE_ELASTIC_PORT (default 9201); otherwise starts a throwaway single-node one there in Docker
# (container `sluice-elastic`, security off). WSL2 distros share one network, so a port another
# distro holds needs SLUICE_ELASTIC_PORT.
set -euo pipefail
cd "$(dirname "$0")/.."

image=${ELASTIC_IMAGE:-docker.elastic.co/elasticsearch/elasticsearch:9.1.0}
port=${SLUICE_ELASTIC_PORT:-9201}
url=${SLUICE_ELASTIC_URL:-http://127.0.0.1:${port}}
if [[ -z ${SLUICE_ELASTIC_URL:-} ]] && ! curl -fsS "$url" >/dev/null 2>&1; then
    if ! command -v docker >/dev/null || ! docker image inspect "$image" >/dev/null 2>&1; then
        echo "==> elastic: skipped (docker pull $image to run it)"
        exit 0
    fi
    # Started and still starting on this port: wait for it; anything else: start it afresh.
    if [[ $(docker port sluice-elastic 9200 2>/dev/null) != "127.0.0.1:${port}" ]]; then
        docker rm -f sluice-elastic >/dev/null 2>&1 || true
        docker run -d --name sluice-elastic -p "127.0.0.1:${port}:9200" \
            -e discovery.type=single-node -e xpack.security.enabled=false \
            -e ES_JAVA_OPTS="-Xms1g -Xmx1g" "$image" >/dev/null \
            || { echo "cannot start Elasticsearch on port $port: set SLUICE_ELASTIC_PORT" >&2; exit 1; }
    fi
    for _ in $(seq 1 90); do
        curl -fsS "$url/_cluster/health" >/dev/null 2>&1 && break
        sleep 2
    done
fi
curl -fsS "$url" >/dev/null || { echo "Elasticsearch at $url does not answer" >&2; exit 1; }
export SLUICE_ELASTIC_URL=$url
cargo test --locked -p sluice-elastic -- --nocapture
# End to end: the demo's pipelines and the runtime fields that put implied values back, proven in
# Elasticsearch on the synthetic sample.
cargo test --locked -p sluice-cli --test natives elastic -- --nocapture
