#!/usr/bin/env bash
# Copies recent records of a Log Analytics workspace's tables as NDJSON for `sluice analyze`,
# one record per line as the workspace stores them, into OUT/<TABLE>.ndjson.
#
#   AZURE_TENANT_ID=… AZURE_CLIENT_ID=… AZURE_CLIENT_SECRET=… \
#     scripts/real-data/collect-sentinel.sh /subscriptions/…/workspaces/NAME OUT [DAYS] [ROWS] [TABLE…]
#
# The tables default to `SecurityEvent` and `WindowsEvent`. The app registration needs Log
# Analytics Reader on the workspace. The records are real: keep OUT outside the repository.
# Nothing here prints a token or the secret.
set -euo pipefail

usage="usage: collect-sentinel.sh WORKSPACE_RESOURCE_ID OUT [DAYS] [ROWS] [TABLE...]"
workspace=${1:?$usage}
out=${2:?$usage}
days=${3:-30}
rows=${4:-20000}
shift $(($# < 4 ? $# : 4))
: "${AZURE_TENANT_ID:?}" "${AZURE_CLIENT_ID:?}" "${AZURE_CLIENT_SECRET:?}"

mkdir -p "$out"
python3 -I - "$workspace" "$out" "$days" "$rows" "$@" <<'EOF'
import json
import os
import sys
import urllib.parse
import urllib.request

workspace, out, days, rows = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
tables = sys.argv[5:] or ["SecurityEvent", "WindowsEvent"]


def token(scope):
    form = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": os.environ["AZURE_CLIENT_ID"],
        "client_secret": os.environ["AZURE_CLIENT_SECRET"],
        "scope": scope,
    }).encode()
    url = f"https://login.microsoftonline.com/{os.environ['AZURE_TENANT_ID']}/oauth2/v2.0/token"
    with urllib.request.urlopen(url, form, timeout=30) as answer:
        return json.load(answer)["access_token"]


def call(url, bearer, body=None):
    request = urllib.request.Request(url, method="POST" if body else "GET")
    request.add_header("Authorization", f"Bearer {bearer}")
    if body:
        request.add_header("Content-Type", "application/json")
        request.data = json.dumps(body).encode()
    with urllib.request.urlopen(request, timeout=300) as answer:
        return json.load(answer)


arm = token("https://management.azure.com/.default")
customer = call(
    f"https://management.azure.com{workspace}?api-version=2022-10-01", arm
)["properties"]["customerId"]
logs = token("https://api.loganalytics.io/.default")
for table in tables:
    query = f"{table} | where TimeGenerated > ago({days}d) | take {rows}"
    result = call(
        f"https://api.loganalytics.io/v1/workspaces/{customer}/query", logs, {"query": query}
    )["tables"][0]
    names = [c["name"] for c in result["columns"]]
    path = os.path.join(out, f"{table}.ndjson")
    with open(path, "w", encoding="utf-8") as file:
        for row in result["rows"]:
            record = {n: v for n, v in zip(names, row) if v not in (None, "")}
            file.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"{table:14} {len(result['rows']):7} records")
EOF
