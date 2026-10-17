#!/usr/bin/env bash
# Sends Windows events in the agent's format (`collect-windows.ps1 -Format agent`) through
# `sluice up` to a Sentinel workspace's `SecurityEvent` and `WindowsEvent` tables: the path a
# host running `sluice agent windows` takes. `sluice up` proposes by default, so what reaches the
# workspace is every event, shaped and unreduced; `collect-sentinel.sh` reads it back.
#
#   AZURE_TENANT_ID=… AZURE_CLIENT_ID=… AZURE_CLIENT_SECRET=… \
#     scripts/real-data/send-sentinel.sh /subscriptions/…/resourceGroups/RG DCR_NAME DIR
#
# DIR holds `security.ndjson` and/or `events.ndjson`. The data collection rule needs the streams
# Custom-SluiceSecurityEvent and Custom-SluiceWindowsEvent (`sluice agent windows --dcr`), and
# the app registration Monitoring Metrics Publisher on it. SECURITY_LINES and EVENTS_LINES cap
# what is sent (default 20000 each): a workspace's daily cap drops whatever comes after it.
set -euo pipefail

group=${1:?usage: send-sentinel.sh RESOURCE_GROUP_ID DCR_NAME DIR}
dcr=${2:?usage: send-sentinel.sh RESOURCE_GROUP_ID DCR_NAME DIR}
dir=${3:?usage: send-sentinel.sh RESOURCE_GROUP_ID DCR_NAME DIR}
: "${AZURE_TENANT_ID:?}" "${AZURE_CLIENT_ID:?}" "${AZURE_CLIENT_SECRET:?}"
security_lines=${SECURITY_LINES:-20000}
events_lines=${EVENTS_LINES:-20000}

work=$(mktemp -d)
trap 'kill "$up" 2>/dev/null || true; wait "$up" 2>/dev/null || true; rm -rf "$work"' EXIT
mkdir -m 700 "$work/secrets"
printf '%s' "$AZURE_CLIENT_SECRET" >"$work/secrets/azure_client_secret"

# The rule's immutable id and its own ingestion endpoint.
read -r immutable endpoint < <(python3 -I - "$group" "$dcr" <<'EOF'
import json, os, sys, urllib.parse, urllib.request
group, name = sys.argv[1], sys.argv[2]
form = urllib.parse.urlencode({
    "grant_type": "client_credentials", "client_id": os.environ["AZURE_CLIENT_ID"],
    "client_secret": os.environ["AZURE_CLIENT_SECRET"],
    "scope": "https://management.azure.com/.default"}).encode()
url = f"https://login.microsoftonline.com/{os.environ['AZURE_TENANT_ID']}/oauth2/v2.0/token"
token = json.load(urllib.request.urlopen(url, form, timeout=30))["access_token"]
request = urllib.request.Request(
    f"https://management.azure.com{group}/providers/Microsoft.Insights/dataCollectionRules/"
    f"{name}?api-version=2023-03-11", headers={"Authorization": f"Bearer {token}"})
rule = json.load(urllib.request.urlopen(request, timeout=30))["properties"]
print(rule["immutableId"], rule["endpoints"]["logsIngestion"])
EOF
)

sink() {
    cat <<EOF
    type: azure_logs_ingestion
    endpoint: $endpoint
    dcr_immutable_id: $immutable
    stream_name: $1
    auth:
      azure_credential_kind: client_secret_credential
      azure_tenant_id: $AZURE_TENANT_ID
      azure_client_id: $AZURE_CLIENT_ID
      azure_client_secret: SECRET[siem.azure_client_secret]
    sluice_sources: [$2]
EOF
}
cat >"$work/sluice.yaml" <<EOF
listen: 127.0.0.1:8687
vector_config: $work/vector.yaml
archive_dir: $work/archive
data_dir: $work/data
vector_secrets:
  siem: { type: directory, path: $work/secrets }
sources:
  - id: windows-security
    logsource: { product: windows, service: security }
    format: { kind: json }
    shape: sentinel_security_event
    vector: { type: http_server, address: 127.0.0.1:9110, decoding: { codec: json },
              framing: { method: newline_delimited } }
  - id: windows-events
    logsource: { product: windows }
    format: { kind: json }
    shape: sentinel_windows_event
    vector: { type: http_server, address: 127.0.0.1:9111, decoding: { codec: json },
              framing: { method: newline_delimited } }
destinations:
  security_event:
$(sink Custom-SluiceSecurityEvent windows-security)
  windows_event:
$(sink Custom-SluiceWindowsEvent windows-events)
EOF

cargo build --release --locked -q -p sluice-cli
sluice=${CARGO_TARGET_DIR:-target}/release/sluice
rules=$(dirname "$0")/../../examples/rules/sigma
"$sluice" up --config "$work/sluice.yaml" --rules "$rules" >"$work/up.log" 2>&1 &
up=$!
listening() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
for _ in $(seq 60); do
    listening 9110 && listening 9111 && break
    sleep 1
done

post() {
    local file=$1 port=$2 lines=$3
    [ -f "$file" ] || return 0
    head -n "$lines" "$file" | split -l 1000 - "$work/batch-$port-"
    local sent=0
    for batch in "$work"/batch-"$port"-*; do
        curl -sf --data-binary @"$batch" "http://127.0.0.1:$port/" >/dev/null
        sent=$((sent + $(wc -l <"$batch")))
    done
    echo "$(basename "$file"): $sent events, $(head -n "$lines" "$file" | wc -c) bytes"
}
post "$dir/security.ndjson" 9110 "$security_lines"
post "$dir/events.ndjson" 9111 "$events_lines"

# Vector batches what it sends; give it time to deliver, then stop.
sleep 90
grep -i -E 'error|warn' "$work/up.log" | grep -v -i 'secret' | tail -5 || true
