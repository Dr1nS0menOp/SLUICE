#!/usr/bin/env bash
# Deploys what `sluice analyze --native sentinel --sentinel-dcr RULE.json` wrote into OUT/sentinel
# to that real data collection rule, and checks contract rule 2 in Azure: creates each archive
# table from its `.table.json`, puts `dcr.json` in the rule, sends records read back from the
# table, and checks that every one arrives whole in the archive table and transformed in the
# analytics table. The rule is restored afterwards; the archive tables are deleted unless
# KEEP_ARCHIVE=1.
#
#   AZURE_TENANT_ID=… AZURE_CLIENT_ID=… AZURE_CLIENT_SECRET=… AZURE_SUBSCRIPTION_ID=… \
#     scripts/real-data/deploy-dcr-native.sh RESOURCE_GROUP DCR OUT/sentinel STREAM RECORDS.ndjson WORKSPACE
#
# RECORDS are rows as `collect-sentinel.sh` writes them; up to 50 of each of the EventIDs in
# TRY_IDS (default 4672 4798 4624) are sent to STREAM, one per EventRecordId, marked by one
# TimeGenerated, APPLY_WAIT seconds (default 600) after the rule was put. Changes the rule for
# up to 40 minutes. What was learned doing so is in docs/notes/sentinel-dcr.md.
set -euo pipefail

group=${1:?usage: deploy-dcr-native.sh RG DCR OUT/sentinel STREAM RECORDS.ndjson WORKSPACE}
dcr=${2:?} dir=${3:?} stream=${4:?} records=${5:?} workspace=${6:?}
: "${AZURE_TENANT_ID:?}" "${AZURE_CLIENT_ID:?}" "${AZURE_CLIENT_SECRET:?}" "${AZURE_SUBSCRIPTION_ID:?}"
export TRY_GROUP=$group TRY_DCR=$dcr TRY_DIR=$dir TRY_STREAM=$stream TRY_RECORDS=$records \
    TRY_WORKSPACE=$workspace TRY_IDS=${TRY_IDS:-"4672 4798 4624"} KEEP_ARCHIVE=${KEEP_ARCHIVE:-0} \
    APPLY_WAIT=${APPLY_WAIT:-600}
python3 -I -u - <<'EOF'
import collections, glob, json, os, time, urllib.error, urllib.parse, urllib.request

env = os.environ
sub = env["AZURE_SUBSCRIPTION_ID"]
rg = f"/subscriptions/{sub}/resourceGroups/{env['TRY_GROUP']}"
rule_url = (f"https://management.azure.com{rg}/providers/Microsoft.Insights/dataCollectionRules/"
            f"{env['TRY_DCR']}?api-version=2023-03-11")
workspace = f"https://management.azure.com{env['TRY_WORKSPACE']}"

def token(scope):
    form = urllib.parse.urlencode({"grant_type": "client_credentials",
        "client_id": env["AZURE_CLIENT_ID"], "client_secret": env["AZURE_CLIENT_SECRET"],
        "scope": scope}).encode()
    url = f"https://login.microsoftonline.com/{env['AZURE_TENANT_ID']}/oauth2/v2.0/token"
    return json.load(urllib.request.urlopen(url, form, timeout=30))["access_token"]

def call(method, url, bearer, body=None, fail=True):
    request = urllib.request.Request(url, method=method,
        headers={"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"})
    if body is not None:
        request.data = json.dumps(body).encode()
    try:
        with urllib.request.urlopen(request, timeout=120) as answer:
            text = answer.read().decode()
            return json.loads(text) if text else None
    except urllib.error.HTTPError as e:
        message = f"{method} {url.split('?')[0]}: {e.code} {e.read().decode()[:800]}"
        if fail:
            raise SystemExit(message)
        print(message)
        return None

def plain(rule):
    rule = json.loads(json.dumps(rule))
    for key in ("id", "name", "type", "etag", "systemData"):
        rule.pop(key, None)
    for key in ("immutableId", "endpoints", "provisioningState"):
        rule["properties"].pop(key, None)
    return rule

arm = token("https://management.azure.com/.default")
original = call("GET", rule_url, arm)
stream = env["TRY_STREAM"]
columns = {c["name"] for c in original["properties"]["streamDeclarations"][stream]["columns"]}
generated = json.load(open(os.path.join(env["TRY_DIR"], "dcr.json"), encoding="utf-8"))
flows = [f for f in generated["properties"]["dataFlows"] if stream in f["streams"]]
analytics = next(f["outputStream"].removeprefix("Microsoft-") for f in flows
                 if f["outputStream"].startswith("Microsoft-"))
archive = next(f["outputStream"].removeprefix("Custom-") for f in flows
               if f["outputStream"].endswith("Archive_CL"))
print(f"{stream}: {analytics}, archived whole into {archive}")

wanted = env["TRY_IDS"].split()
picked = collections.defaultdict(list)
seen = set()
for line in open(env["TRY_RECORDS"], encoding="utf-8"):
    row = json.loads(line)
    key, record_id = str(row.get("EventID")), str(row.get("EventRecordId"))
    if str(row.get("Computer", "")).startswith("sluice-") or record_id in seen:
        continue  # test records of earlier runs, and repeats
    if key in wanted and len(picked[key]) < 50:
        seen.add(record_id)
        picked[key].append(row)
# Nine decimals, as Vector writes a timestamp.
second = time.strftime("%Y-%m-%dT%H:%M:09Z", time.gmtime())
marker = second.replace("Z", ".456789123Z")
batch = []
for row in (r for key in wanted for r in picked[key]):
    record = {k: v for k, v in row.items() if k in columns}
    record["TimeGenerated"] = marker
    batch.append(record)
had = {str(r["EventRecordId"]): bool(r.get("EventData")) for r in batch}
print(f"records: {len(batch)} ({', '.join(f'{k}: {len(picked[k])}' for k in wanted)})")

def settled(name):
    # A table is created and deleted asynchronously; a rule naming it is refused until then.
    for _ in range(60):
        table = call("GET", f"{workspace}/tables/{name}?api-version=2023-01-01-preview", arm,
                     fail=False)
        if table and table["properties"].get("provisioningState") != "Updating":
            return
        time.sleep(10)
    raise SystemExit(f"{name} is still updating after 10 minutes")

tables = []
for path in sorted(glob.glob(os.path.join(env["TRY_DIR"], "*Archive_CL.table.json"))):
    name = os.path.basename(path).removesuffix(".table.json")
    if not any(f["outputStream"] == f"Custom-{name}" for f in generated["properties"]["dataFlows"]):
        continue  # left from an earlier run
    print(f"creating {name} …")
    call("PUT", f"{workspace}/tables/{name}?api-version=2023-01-01-preview", arm,
         json.load(open(path, encoding="utf-8")))
    tables.append(name)
    settled(name)

try:
    print("putting the generated rule …")
    call("PUT", rule_url, arm, plain(generated))
    # A changed rule takes a while to apply; with a new output table, more than two minutes.
    time.sleep(int(env["APPLY_WAIT"]))
    rule = original["properties"]
    ingest = (f"{rule['endpoints']['logsIngestion']}/dataCollectionRules/{rule['immutableId']}"
              f"/streams/{stream}?api-version=2023-01-01")
    call("POST", ingest, token("https://monitor.azure.com/.default"), batch)
    print("sent; waiting for the records to arrive …")
    logs = token("https://api.loganalytics.io/.default")
    customer = call("GET", f"{workspace}?api-version=2022-10-01", arm)["properties"]["customerId"]

    def rows(table):
        # `/query` answers an Auxiliary table with no rows and no error; `/search` reads it.
        search = f"https://api.loganalytics.io/v1/workspaces/{customer}/search?timespan=PT6H"
        answer = call("POST", search, logs,
            # An Auxiliary table keeps the time to the microsecond, so not `== marker`.
            {"query": f"{table} | where TimeGenerated between (datetime({second}) .. 1s)"
                      " | project EventRecordId, EventID, HasEventData = isnotempty(EventData)"},
            fail=False)
        return answer["tables"][0]["rows"] if answer else []

    stored, archived = [], []
    for _ in range(60):
        time.sleep(30)
        stored = stored if len(stored) >= len(batch) else rows(analytics)
        archived = archived if len(archived) >= len(batch) else rows(archive)
        if len(stored) >= len(batch) and len(archived) >= len(batch):
            break
finally:
    print("restoring the rule …")
    call("PUT", rule_url, arm, plain(original))
    if env["KEEP_ARCHIVE"] != "1":
        for name in tables:
            settled(name)
            call("DELETE", f"{workspace}/tables/{name}?api-version=2023-01-01-preview", arm, fail=False)

print(f"{analytics}: {len(stored)} of {len(batch)} arrived; {archive}: {len(archived)}")
emptied = collections.Counter(str(r[1]) for r in stored if not r[2] and had.get(str(r[0])))
print(f"{analytics}: EventData emptied on {dict(emptied) or 'none'}")
whole = {str(r[0]) for r in archived if r[2] == had.get(str(r[0]))}
missing = [n for n in had if n not in whole]
print(f"{archive}: every record whole" if not missing
      else f"{archive}: {len(missing)} records missing or not whole: {missing[:5]}")
raise SystemExit(1 if missing or len(stored) < len(batch) else 0)
EOF
