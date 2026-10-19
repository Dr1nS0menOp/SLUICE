#!/usr/bin/env bash
# Copies recent documents of an index pattern from Elasticsearch as NDJSON for `sluice analyze`:
# each document's `_source` on a line, as the index stores it.
#
#   ELASTIC_API_KEY=… scripts/real-data/collect-elastic.sh https://es.example:9200 \
#       'logs-system.security-*' OUT/windows-security.ndjson [HOURS] [DOCS]
#
# ELASTIC_API_KEY is an API key's `encoded` value; ELASTIC_USER and ELASTIC_PASSWORD work too.
# Either needs `read` and `view_index_metadata` on the indices and nothing else. ELASTIC_CA_CERT
# names a CA certificate to trust (a self-managed cluster's `http_ca.crt`). The documents are
# real: keep OUT outside the repository. Nothing here prints the key or the password.
set -euo pipefail

url=${1:?usage: collect-elastic.sh URL INDEX_PATTERN OUT.ndjson [HOURS] [DOCS]}
index=${2:?usage: collect-elastic.sh URL INDEX_PATTERN OUT.ndjson [HOURS] [DOCS]}
out=${3:?usage: collect-elastic.sh URL INDEX_PATTERN OUT.ndjson [HOURS] [DOCS]}
hours=${4:-24}
docs=${5:-50000}
if [ -z "${ELASTIC_API_KEY:-}" ] && [ -z "${ELASTIC_USER:-}" ]; then
    echo "set ELASTIC_API_KEY, or ELASTIC_USER and ELASTIC_PASSWORD" >&2
    exit 2
fi

mkdir -p "$(dirname "$out")"
python3 -I - "$url" "$index" "$out" "$hours" "$docs" <<'EOF'
import base64
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request

url, index, out, hours, docs = sys.argv[1].rstrip("/"), sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
if os.environ.get("ELASTIC_API_KEY"):
    auth = "ApiKey " + os.environ["ELASTIC_API_KEY"]
else:
    pair = f"{os.environ['ELASTIC_USER']}:{os.environ.get('ELASTIC_PASSWORD', '')}"
    auth = "Basic " + base64.b64encode(pair.encode()).decode()
context = ssl.create_default_context(cafile=os.environ.get("ELASTIC_CA_CERT") or None)


def call(method, path, body=None):
    request = urllib.request.Request(url + path, method=method)
    request.add_header("Authorization", auth)
    if body is not None:
        request.add_header("Content-Type", "application/json")
        request.data = json.dumps(body).encode()
    with urllib.request.urlopen(request, timeout=120, context=context) as answer:
        return json.load(answer)


# A point in time keeps the pages consistent while the index grows.
pit = call("POST", f"/{urllib.parse.quote(index, safe='*,')}/_pit?keep_alive=2m")["id"]
written, after = 0, None
with open(out, "w", encoding="utf-8") as file:
    while written < docs:
        body = {
            "size": min(5000, docs - written),
            "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
            "pit": {"id": pit, "keep_alive": "2m"},
            "sort": [{"_shard_doc": "asc"}],
        }
        if after is not None:
            body["search_after"] = after
        answer = call("POST", "/_search", body)
        pit = answer.get("pit_id", pit)
        hits = answer["hits"]["hits"]
        if not hits:
            break
        for hit in hits:
            file.write(json.dumps(hit["_source"], ensure_ascii=False) + "\n")
        written += len(hits)
        after = hits[-1]["sort"]
try:
    call("DELETE", "/_pit", {"id": pit})
except OSError:
    pass  # the point in time expires by itself
print(f"{out}: {written} documents")
EOF
