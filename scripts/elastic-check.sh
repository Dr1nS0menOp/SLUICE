#!/usr/bin/env bash
# Differential test of the Elasticsearch ingest pipelines Sluice generates (ADR 0024): runs them
# in a real Elasticsearch through `_ingest/pipeline/_simulate` and checks that they remove what
# the proven VRL removes, never more.
#
# Starts a throwaway single-node Elasticsearch in Docker (container `sluice-elastic`, port 9201
# on localhost, security off) unless SLUICE_ELASTIC_URL points at one already.
set -euo pipefail
cd "$(dirname "$0")/.."

image=${ELASTIC_IMAGE:-docker.elastic.co/elasticsearch/elasticsearch:9.1.0}
url=${SLUICE_ELASTIC_URL:-}
if [[ -z $url ]]; then
    if ! command -v docker >/dev/null || ! docker image inspect "$image" >/dev/null 2>&1; then
        echo "==> elastic: skipped (docker pull $image to run it)"
        exit 0
    fi
    if ! docker ps --format '{{.Names}}' | grep -qx sluice-elastic; then
        docker rm -f sluice-elastic >/dev/null 2>&1 || true
        docker run -d --name sluice-elastic -p 127.0.0.1:9201:9200 \
            -e discovery.type=single-node -e xpack.security.enabled=false \
            -e ES_JAVA_OPTS="-Xms1g -Xmx1g" "$image" >/dev/null
    fi
    url=http://127.0.0.1:9201
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
