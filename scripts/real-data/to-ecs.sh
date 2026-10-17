#!/usr/bin/env bash
# Turns the Windows sample of `collect-windows.ps1` into documents as Elastic stores them (ECS),
# to measure Elastic's rules and Sluice's ingest pipelines on (ADR 0024, ADR 0025): each event
# as Elastic Agent's winlog input sends it (`winlog.*`, `event.code`, `log.level`, …), run in
# Elasticsearch through the ingest pipeline of its integration's data stream (System's
# `system.system` and `system.application`, Windows' `windows.powershell_operational`).
#
#   scripts/real-data/to-ecs.sh [DATA_DIR] [ELASTICSEARCH_URL]
#
# Reads DATA_DIR/windows (default ~/.cache/sluice-realdata), writes DATA_DIR/windows-ecs with a
# sources.yaml of `schema: ecs`. Downloads the two integration packages (Elastic License 2.0)
# into ~/.cache/sluice/elastic-integrations; nothing of them enters the repository.
set -euo pipefail

data=${1:-$HOME/.cache/sluice-realdata}
url=${2:-${SLUICE_ELASTIC_URL:-http://127.0.0.1:9201}}
packages=$HOME/.cache/sluice/elastic-integrations
mkdir -p "$packages" "$data/windows-ecs"
for package in system windows; do
    download=$(curl -fsS "https://epr.elastic.co/search?package=$package&prerelease=false" \
        | python3 -I -c 'import json, sys; print(json.load(sys.stdin)[-1]["download"])')
    name=$(basename "$download" .zip)
    if [ ! -d "$packages/$name" ]; then
        curl -fsS -o "$packages/$name.zip" "https://epr.elastic.co$download"
        python3 -I -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' \
            "$packages/$name.zip" "$packages"
        rm "$packages/$name.zip"
    fi
    echo "$name"
done

python3 -I - "$data" "$url" "$packages" <<'EOF'
import glob, json, os, sys, urllib.request

data, url, packages = sys.argv[1:4]
import yaml  # PyYAML, for the integrations' pipeline files

def pipeline(package, stream):
    [path] = glob.glob(f"{packages}/{package}-*/data_stream/{stream}/elasticsearch/ingest_pipeline/default.yml")
    return yaml.safe_load(open(path))

def simulate(body, docs):
    out = []
    for at in range(0, len(docs), 500):
        request = urllib.request.Request(f"{url}/_ingest/pipeline/_simulate",
            data=json.dumps({"pipeline": body, "docs": [{"_source": d} for d in docs[at:at + 500]]}).encode(),
            headers={"content-type": "application/json"})
        answer = json.load(urllib.request.urlopen(request, timeout=300))
        for doc in answer["docs"]:
            if "error" in doc:
                raise SystemExit(f"the integration pipeline failed: {doc['error']}")
            out.append(doc["doc"]["_source"])
    return out

LEVELS = {0: "information", 1: "critical", 2: "error", 3: "warning", 4: "information", 5: "verbose"}
SYSTEM = {"@timestamp", "Channel", "Computer", "EventID", "Keywords", "Level", "ProcessID",
          "Provider_Name", "Task", "ThreadID", "Message", "Opcode", "EventRecordID"}

def winlog(event, dataset):
    """The event as the winlog input sends it."""
    return {
        "@timestamp": event["@timestamp"],
        "message": event.get("Message", ""),
        "event": {"code": str(event["EventID"]), "provider": event.get("Provider_Name"),
                  "kind": "event", "module": dataset.split(".")[0]},
        "log": {"level": LEVELS.get(event.get("Level"), "information")},
        "host": {"name": str(event.get("Computer", "")).lower()},
        "winlog": {
            "api": "wineventlog",
            "channel": event.get("Channel"),
            "computer_name": event.get("Computer"),
            "event_id": str(event["EventID"]),
            "provider_name": event.get("Provider_Name"),
            "task": str(event.get("Task", "")),
            "process": {"pid": event.get("ProcessID"), "thread": {"id": event.get("ThreadID")}},
            "event_data": {k: v if isinstance(v, str) else json.dumps(v)
                           for k, v in event.items() if k not in SYSTEM},
        },
        "data_stream": {"type": "logs", "dataset": dataset, "namespace": "default"},
    }

streams = {
    "system": ("system", "system", "system.system", {"product": "windows", "service": "system"}),
    "application": ("system", "application", "system.application", {"product": "windows", "service": "application"}),
    "ps-script": ("windows", "powershell_operational", "windows.powershell_operational", {"product": "windows", "category": "ps_script"}),
    "ps-other": ("windows", "powershell_operational", "windows.powershell_operational", {"product": "windows", "service": "powershell"}),
}
sources = []
for source, (package, stream, dataset, logsource) in streams.items():
    path = f"{data}/windows/{source}.ndjson"
    if not os.path.exists(path):
        continue
    events = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
    docs = simulate(pipeline(package, stream), [winlog(e, dataset) for e in events])
    # What only the pipeline run adds.
    for doc in docs:
        doc.get("event", {}).pop("ingested", None)
    with open(f"{data}/windows-ecs/{source}.ndjson", "w", encoding="utf-8") as out:
        for doc in docs:
            out.write(json.dumps(doc, ensure_ascii=False) + "\n")
    print(f"{source}: {len(docs)} documents ({dataset})")
    sources.append({"id": source, "logsource": dict(logsource, complete=True),
                    "format": {"kind": "json"}, "schema": "ecs"})
with open(f"{data}/windows-ecs/sources.yaml", "w") as out:
    yaml.safe_dump({"sources": sources}, out, sort_keys=False)
EOF
