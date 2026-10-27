#!/usr/bin/env bash
# Checks implied values in a real data collection rule: what emptying them saves in
# `_BilledSize`, and whether the `<Table>Full` function Sluice writes puts every one back.
#
# Reads the live rule, runs `sluice analyze --native sentinel --sentinel-dcr` on it, then sends
# the same records twice into SecurityEvent: first through the rule as it is (the baseline),
# then, after putting Sluice's transformation in the rule, through that. It compares what Azure
# billed for each record, and runs `SecurityEventFull.kql` on the second batch: every column it
# puts back must hold what the baseline holds. The rule is restored afterwards.
#
#   AZURE_TENANT_ID=… AZURE_CLIENT_ID=… AZURE_CLIENT_SECRET=… AZURE_SUBSCRIPTION_ID=… \
#     scripts/real-data/try-dcr-implied.sh DCR_RESOURCE_ID SAMPLES SOURCES.yaml SENTINEL_RULES
#
# SAMPLES holds `SecurityEvent.ndjson` as `collect-sentinel.sh` writes it; up to 20 records of
# each EventID in TRY_IDS are sent, marked by one TimeGenerated per batch. Needs the Kusto
# emulator at KUSTO (default http://127.0.0.1:8090, `scripts/kql-check.sh` starts one). Changes
# the rule for APPLY_WAIT seconds (default 600: a changed rule took five to ten minutes to apply)
# plus the time the records take to arrive. Each batch is checked against the emulator's run of the
# rule version meant for it, so one that went through another version stops the run.
# TRY_TRANSFORM sends another transformation instead of Sluice's, to narrow down a difference.
# Nothing here prints a token, the secret or a resource ID.
set -euo pipefail

rule=${1:?usage: try-dcr-implied.sh DCR_RESOURCE_ID SAMPLES SOURCES.yaml SENTINEL_RULES}
samples=${2:?} sources=${3:?} rules=${4:?}
: "${AZURE_TENANT_ID:?}" "${AZURE_CLIENT_ID:?}" "${AZURE_CLIENT_SECRET:?}" "${AZURE_SUBSCRIPTION_ID:?}"
cd "$(dirname "$0")/../.."
cargo build --locked -q -p sluice-cli
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export TRY_RULE=$rule TRY_SAMPLES=$samples TRY_SOURCES=$sources TRY_RULES=$rules TRY_WORK=$work \
    TRY_IDS=${TRY_IDS:-"4624 4672 4688 4798 5379"} KUSTO=${KUSTO:-http://127.0.0.1:8090} \
    APPLY_WAIT=${APPLY_WAIT:-600} SLUICE=${CARGO_TARGET_DIR:-target}/debug/sluice
python3 -I -u - <<'EOF'
import collections, json, os, re, subprocess, time, urllib.error, urllib.parse, urllib.request

env = os.environ
work = env["TRY_WORK"]
rule_url = f"https://management.azure.com{env['TRY_RULE']}?api-version=2023-03-11"
STREAM = "Custom-SluiceSecurityEvent"

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
        with urllib.request.urlopen(request, timeout=300) as answer:
            text = answer.read().decode()
            return json.loads(text) if text else None
    except urllib.error.HTTPError as e:
        where = urllib.parse.urlparse(url).path.split("/")[-1]
        raise SystemExit(f"{method} …/{where}: {e.code} {e.read().decode()[:600]}")

def writable(rule):
    out = json.loads(json.dumps(rule))
    for key in ("id", "name", "type", "etag", "systemData"):
        out.pop(key, None)
    out["properties"].pop("immutableId", None)
    out["properties"].pop("endpoints", None)
    return out

arm = token("https://management.azure.com/.default")
original = call("GET", rule_url, arm)
props = original["properties"]
columns = {c["name"] for c in props["streamDeclarations"][STREAM]["columns"]}
workspace = props["destinations"]["logAnalytics"][0]["workspaceResourceId"]
with open(f"{work}/rule.json", "w") as f:
    json.dump(original, f)

# Sluice's transformation and function, from the live rule.
analysis = subprocess.run([env["SLUICE"], "analyze", "--input", env["TRY_SAMPLES"],
    "--sources", env["TRY_SOURCES"], "--sentinel-rules", env["TRY_RULES"],
    "--kusto", env["KUSTO"], "--sentinel-table", "SecurityEvent=SecurityEvent",
    "--native sentinel", "--sentinel-dcr", f"{work}/rule.json", "--no-examples",
    "--out", f"{work}/out"], capture_output=True, text=True)
if analysis.returncode != 0:
    raise SystemExit(f"sluice analyze failed:\n{analysis.stderr[-2000:]}")
for line in analysis.stdout.splitlines():
    if line.startswith(("  ingest", "  modes", "  proof", "  native")):
        print(line[:220])
transform = open(env.get("TRY_TRANSFORM") or f"{work}/out/sentinel/SecurityEvent.transform.kql"
                 ).read().strip()
full = open(f"{work}/out/sentinel/SecurityEventFull.kql").read()
implied = re.findall(r"^\| extend \['([^']+)'\] = case\(", full, re.M)
print(f"transformKql: {len(transform)} characters; SecurityEventFull puts back {len(implied)} "
      f"column(s): {', '.join(implied)}")

# The records: up to 20 per EventID, each sent twice under its own marker.
wanted = env["TRY_IDS"].split()
picked, seen = collections.defaultdict(list), set()
for line in open(os.path.join(env["TRY_SAMPLES"], "SecurityEvent.ndjson"), encoding="utf-8"):
    row = json.loads(line)
    key, record_id = str(row.get("EventID")), str(row.get("EventRecordId"))
    if str(row.get("Computer", "")).startswith("sluice-") or record_id in seen:
        continue
    if key in wanted and len(picked[key]) < 20:
        seen.add(record_id)
        picked[key].append({k: v for k, v in row.items() if k in columns})
records = [r for key in wanted for r in picked[key]]
print(f"records: {len(records)} ({', '.join(f'{k}: {len(picked[k])}' for k in wanted)})")

# What each version of the rule must leave empty, per record, as the emulator runs it. A
# changed rule takes up to ten minutes to apply in Azure, so a batch can go through another
# version than meant; comparing with these tells.
def kusto(csl, db="NetDefaultDB", kind="query"):
    request = urllib.request.Request(f"{env['KUSTO']}/v1/rest/{kind}",
        data=json.dumps({"db": db, "csl": csl}).encode(),
        headers={"Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(request, timeout=300))
    except urllib.error.HTTPError as e:
        raise SystemExit(f"Kusto ({csl[:80]!r}): {e.code} {e.read().decode()[:400]}")

def empty(value):
    return value in ("", None)

def emptied_by(kql):
    db = f"sluice_try_{os.getpid()}"
    kusto(f".create database {db} volatile", kind="mgmt")
    try:
        kinds = {"boolean": "bool"}
        declared = ", ".join(f"['{c['name']}']:{kinds.get(c['type'], c['type'])}"
                             for c in props["streamDeclarations"][STREAM]["columns"])
        kusto(f".create table Input ({declared})", db, "mgmt")
        kusto(".ingest inline into table Input with (format='multijson') <|\n"
              + "\n".join(json.dumps(r) for r in records), db, "mgmt")
        table = kusto(kql.replace("source", "Input", 1), db)["Tables"][0]
    finally:
        kusto(f".drop database {db} ifexists", kind="mgmt")
    names = [c["ColumnName"] for c in table["Columns"]]
    out = {}
    for row in table["Rows"]:
        row = dict(zip(names, row))
        out[str(row["EventRecordId"])] = {c for c, v in row.items() if empty(v)}
    return out

flow_kql = next(f for f in props["dataFlows"] if STREAM in f["streams"]).get("transformKql",
                                                                            "source")
expected = {"baseline": emptied_by(flow_kql), "implied": emptied_by(transform)}
stamp = time.gmtime()
markers = {name: time.strftime(f"%Y-%m-%dT%H:%M:{second}.123Z", stamp)
           for name, second in (("baseline", "03"), ("implied", "41"))}
ingest = (f"{props['endpoints']['logsIngestion']}/dataCollectionRules/{props['immutableId']}"
          f"/streams/{STREAM}?api-version=2023-01-01")

def send(marker):
    batch = [dict(r, TimeGenerated=marker) for r in records]
    call("POST", ingest, token("https://monitor.azure.com/.default"), batch)

logs = token("https://api.loganalytics.io/.default")
customer = call("GET", f"https://management.azure.com{workspace}?api-version=2022-10-01",
                arm)["properties"]["customerId"]

def query(kql):
    answer = call("POST", f"https://api.loganalytics.io/v1/workspaces/{customer}/query", logs,
                  {"query": kql})
    table = answer["tables"][0]
    names = [c["name"] for c in table["columns"]]
    return [dict(zip(names, row)) for row in table["rows"]]

def at(marker):
    return f"where TimeGenerated == datetime({marker})"

def arrived(*names):
    """Waits until every batch named is in the table: ingestion runs after the request
    returns, so a rule changed before then would transform it."""
    for _ in range(40):
        times = ", ".join(f"datetime({markers[n]})" for n in names)
        rows = query(f"SecurityEvent | where TimeGenerated in ({times}) "
                     "| summarize count() by TimeGenerated")
        if len(rows) == len(names) and all(r["count_"] >= len(records) for r in rows):
            return
        time.sleep(30)
    raise SystemExit("the records did not arrive within 20 minutes")

send(markers["baseline"])
print("baseline sent through the rule as it is; waiting for it to arrive …")
arrived("baseline")
changed = writable(original)
for flow in changed["properties"]["dataFlows"]:
    if STREAM in flow["streams"]:
        flow["transformKql"] = transform
call("PUT", rule_url, arm, changed)
print(f"Sluice's transformation is in the rule; waiting {env['APPLY_WAIT']} s for it to apply …")
try:
    time.sleep(int(env["APPLY_WAIT"]))
    send(markers["implied"])
    print("sent again through Sluice's transformation; waiting for it to arrive …")
    arrived("implied")
finally:
    call("PUT", rule_url, arm, writable(original))
    print("the rule is restored")

def by_record(rows):
    return {str(r["EventRecordId"]): r for r in rows}

billed = by_record(query(f"SecurityEvent | {at(markers['baseline'])} | project EventRecordId, "
                         "EventID, Base = _BilledSize")
                   )
for record_id, row in by_record(query(f"SecurityEvent | {at(markers['implied'])} | project "
                                      "EventRecordId, Sent = _BilledSize")).items():
    billed[record_id]["Sent"] = row["Sent"]
baseline = by_record(query(f"SecurityEvent | {at(markers['baseline'])}"))
sent = by_record(query(f"SecurityEvent | {at(markers['implied'])}"))
for name, stored in (("baseline", baseline), ("implied", sent)):
    off = [record_id for record_id, row in stored.items()
           if {c for c, v in row.items() if c in columns and c != "TimeGenerated" and empty(v)}
           != {c for c in expected[name].get(record_id, set()) if c in row and c != "TimeGenerated"}]
    if off:
        raise SystemExit(f"the {name} batch did not go through the rule version meant for it "
                         f"({len(off)} of {len(stored)} records differ from the emulator): a "
                         "changed rule takes up to ten minutes to apply; wait and run again")
print("each batch went through the rule version meant for it, as the emulator runs it")
function = full.replace("\nSecurityEvent\n", f"\nSecurityEvent | {at(markers['implied'])}\n", 1)
rebuilt = by_record(query(function))

skip = {"TimeGenerated"}
emptied = collections.Counter()
wrong = collections.Counter()
other = collections.Counter()
for record_id, base in baseline.items():
    for column, value in base.items():
        if column in skip:
            continue
        if sent.get(record_id, {}).get(column) in ("", None) and value not in ("", None):
            (emptied if column in implied else other)[column] += 1
        if column in implied and rebuilt.get(record_id, {}).get(column) != value:
            wrong[column] += 1

print("\nBilled, average per record (the rule as it is → with Sluice's transformation):")
per_id = collections.defaultdict(lambda: [0, 0, 0])
for row in billed.values():
    counts = per_id[str(row["EventID"])]
    counts[0] += 1
    counts[1] += row["Base"]
    counts[2] += row.get("Sent", 0)
for event_id, (n, base, after) in sorted(per_id.items()):
    print(f"  {event_id}: {n} records, {base / n:,.0f} → {after / n:,.0f} bytes "
          f"({100 * (base - after) / base:.1f} % less)")
base_total = sum(c[1] for c in per_id.values())
after_total = sum(c[2] for c in per_id.values())
print(f"  all: {base_total:,} → {after_total:,} bytes ({100 * (base_total - after_total) / base_total:.1f} % less)")
print("\nImplied columns emptied by Azure (records):",
      ", ".join(f"{c} {n}" for c, n in sorted(emptied.items())) or "none")
print("Other columns emptied (the recipes):",
      ", ".join(f"{c} {n}" for c, n in sorted(other.items())) or "none")
for column in ("Activity", "EventLevelName", "Account", "SubjectAccount", "TargetAccount"):
    if column in columns:
        state = "emptied" if emptied[column] else "never emptied"
        print(f"  {column}: in the stream, {'implied' if column in implied else 'not implied'}, {state}")
if not emptied:
    raise SystemExit("nothing was emptied: the rule had not applied yet; try a longer APPLY_WAIT")
if wrong:
    raise SystemExit("SecurityEventFull differs from the baseline: "
                     + ", ".join(f"{c} on {n} records" for c, n in sorted(wrong.items())))
print(f"\nSecurityEventFull gives back every emptied implied value: {sum(emptied.values())} values "
      f"in {len(implied)} column(s), on {len(baseline)} records")
EOF
