#!/usr/bin/env bash
# Tries a `sluice analyze --native sentinel --sentinel-dcr RULE.json` transformation in that real
# data collection rule: makes it the transformKql of one stream's data flow, sends a few records
# read back from the table, and compares what Azure stored with what the Kusto emulator makes of
# the same records with the same KQL. The rule is restored afterwards.
#
#   AZURE_TENANT_ID=… AZURE_CLIENT_ID=… AZURE_CLIENT_SECRET=… AZURE_SUBSCRIPTION_ID=… \
#     scripts/real-data/try-dcr-native.sh RESOURCE_GROUP DCR STREAM TRANSFORM.kql RECORDS.ndjson WORKSPACE
#
# RECORDS are rows as `collect-sentinel.sh` writes them; up to 50 of each of the EventIDs in
# TRY_IDS (default 4672 4798 4624) are sent, one per EventRecordId, marked by one TimeGenerated:
# Azure fills that column, so it is not part of what the transformation recognises a record by.
# Needs a Kusto emulator at KUSTO (default http://127.0.0.1:8090). Changes the rule for a few
# minutes.
set -euo pipefail

group=${1:?usage: try-dcr-native.sh RG DCR STREAM TRANSFORM.kql RECORDS.ndjson WORKSPACE}
dcr=${2:?} stream=${3:?} transform=${4:?} records=${5:?} workspace=${6:?}
: "${AZURE_TENANT_ID:?}" "${AZURE_CLIENT_ID:?}" "${AZURE_CLIENT_SECRET:?}" "${AZURE_SUBSCRIPTION_ID:?}"
export TRY_GROUP=$group TRY_DCR=$dcr TRY_STREAM=$stream TRY_TRANSFORM=$transform \
    TRY_RECORDS=$records TRY_WORKSPACE=$workspace TRY_IDS=${TRY_IDS:-"4672 4798 4624"} \
    KUSTO=${KUSTO:-http://127.0.0.1:8090}
python3 -I -u - <<'EOF'
import collections, json, os, time, urllib.error, urllib.parse, urllib.request

env = os.environ
sub = env["AZURE_SUBSCRIPTION_ID"]
rg = f"/subscriptions/{sub}/resourceGroups/{env['TRY_GROUP']}"
rule_url = (f"https://management.azure.com{rg}/providers/Microsoft.Insights/dataCollectionRules/"
            f"{env['TRY_DCR']}?api-version=2023-03-11")

def token(scope):
    form = urllib.parse.urlencode({"grant_type": "client_credentials",
        "client_id": env["AZURE_CLIENT_ID"], "client_secret": env["AZURE_CLIENT_SECRET"],
        "scope": scope}).encode()
    url = f"https://login.microsoftonline.com/{env['AZURE_TENANT_ID']}/oauth2/v2.0/token"
    return json.load(urllib.request.urlopen(url, form, timeout=30))["access_token"]

def call(method, url, bearer, body=None):
    request = urllib.request.Request(url, method=method,
        headers={"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"})
    if body is not None:
        request.data = json.dumps(body).encode()
    try:
        with urllib.request.urlopen(request, timeout=120) as answer:
            text = answer.read().decode()
            return json.loads(text) if text else None
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{method} {url.split('?')[0]}: {e.code} {e.read().decode()[:800]}")

def kusto(csl, db="NetDefaultDB", kind="query"):
    request = urllib.request.Request(f"{env['KUSTO']}/v1/rest/{kind}",
        data=json.dumps({"db": db, "csl": csl}).encode(),
        headers={"Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(request, timeout=300))
    except urllib.error.HTTPError as e:
        raise SystemExit(f"Kusto ({csl[:80]!r}): {e.code} {e.read().decode()[:400]}")

arm = token("https://management.azure.com/.default")
original = call("GET", rule_url, arm)
stream = env["TRY_STREAM"]
flow = next(f for f in original["properties"]["dataFlows"] if stream in f["streams"])
columns = {c["name"]: c["type"] for c in original["properties"]["streamDeclarations"][stream]["columns"]}
native = open(env["TRY_TRANSFORM"], encoding="utf-8").read().strip()
assert native.startswith("source"), "a transformation starts with `source`"
combined = native  # sluice already put the flow's own transformation first
print(f"transformKql: {len(combined)} characters")

# The records to send: up to 50 per EventID, marked, with only the stream's columns.
wanted = env["TRY_IDS"].split()
picked = collections.defaultdict(list)
seen = set()
for line in open(env["TRY_RECORDS"], encoding="utf-8"):
    row = json.loads(line)
    key = str(row.get("EventID"))
    record_id = str(row.get("EventRecordId"))
    if str(row.get("Computer", "")).startswith("sluice-") or record_id in seen:
        continue  # test records of earlier runs, and repeats
    if key in wanted and len(picked[key]) < 50:
        seen.add(record_id)
        picked[key].append(row)
marker = time.strftime("%Y-%m-%dT%H:%M:07.123Z", time.gmtime())
batch = []
for row in (r for key in wanted for r in picked[key]):
    record = {k: v for k, v in row.items() if k in columns}
    record["TimeGenerated"] = marker
    batch.append(record)
print(f"records: {len(batch)} ({', '.join(f'{k}: {len(picked[k])}' for k in wanted)})")

# What the emulator makes of them with the same KQL.
db = f"sluice_try_{os.getpid()}"
kusto(f".create database {db} volatile", kind="mgmt")
try:
    kusto_types = {"boolean": "bool"}
    declared = ", ".join(f"['{name}']:{kusto_types.get(kind, kind)}" for name, kind in columns.items())
    kusto(f".create table Input ({declared})", db, "mgmt")
    kusto(".ingest inline into table Input with (format='multijson') <|\n"
          + "\n".join(json.dumps(r) for r in batch), db, "mgmt")
    query = combined.replace("source", "Input", 1) + "\n| project EventRecordId, EventData"
    table = kusto(query, db)["Tables"][0]
    emulator = {str(row[0]): bool(row[1]) for row in table["Rows"]}
finally:
    kusto(f".drop database {db} ifexists", kind="mgmt")

changed = json.loads(json.dumps(original))
for f in changed["properties"]["dataFlows"]:
    if stream in f["streams"]:
        f["transformKql"] = combined
for key in ("id", "name", "type", "etag", "systemData"):
    changed.pop(key, None)
changed["properties"].pop("immutableId", None)
changed["properties"].pop("endpoints", None)
print("putting the transformation in the rule …")
call("PUT", rule_url, arm, changed)
try:
    time.sleep(90)  # a changed rule takes a while to apply
    rule = original["properties"]
    ingest = (f"{rule['endpoints']['logsIngestion']}/dataCollectionRules/{rule['immutableId']}"
              f"/streams/{stream}?api-version=2023-01-01")
    call("POST", ingest, token("https://monitor.azure.com/.default"), batch)
    print("sent; waiting for the records to arrive …")
    logs = token("https://api.loganalytics.io/.default")
    ws = call("GET", f"https://management.azure.com{env['TRY_WORKSPACE']}?api-version=2022-10-01", arm)
    customer = ws["properties"]["customerId"]
    stored = {}
    for _ in range(40):
        time.sleep(30)
        answer = call("POST", f"https://api.loganalytics.io/v1/workspaces/{customer}/query", logs,
            {"query": f"SecurityEvent | where TimeGenerated == datetime({marker})"
                      " | project EventRecordId, EventID, HasEventData = isnotempty(EventData), _BilledSize"})
        rows = answer["tables"][0]["rows"]
        if len(rows) >= len(batch):
            stored = {str(r[0]): (r[1], r[2], r[3]) for r in rows}
            break
    if not stored:
        raise SystemExit("the records did not arrive within 20 minutes")
finally:
    print("restoring the rule …")
    restore = json.loads(json.dumps(original))
    for key in ("id", "name", "type", "etag", "systemData"):
        restore.pop(key, None)
    restore["properties"].pop("immutableId", None)
    restore["properties"].pop("endpoints", None)
    call("PUT", rule_url, arm, restore)

differ = [n for n, (_, has, _) in stored.items() if emulator.get(n) != has]
by_id = collections.defaultdict(lambda: [0, 0, 0])
for n, (event_id, has, billed) in stored.items():
    counts = by_id[event_id]
    counts[0] += 1
    counts[1] += 0 if has else 1
    counts[2] += billed
for event_id, (count, emptied, billed) in sorted(by_id.items()):
    print(f"EventID {event_id}: {count} stored, EventData emptied on {emptied}, "
          f"{billed / count:.0f} bytes billed on average")
print("Azure and the emulator agree on every record" if not differ
      else f"Azure and the emulator differ on {len(differ)} records: {differ[:5]}")
raise SystemExit(1 if differ else 0)
EOF
