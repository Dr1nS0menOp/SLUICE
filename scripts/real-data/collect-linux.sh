#!/usr/bin/env bash
# Copies the newest lines of a Linux host's auth.log and syslog over SSH, as NDJSON for
# `scripts/real-data/run.sh`: one `{"message": "<line>"}` object per line.
#
#   scripts/real-data/collect-linux.sh admin@logs.example ~/.cache/sluice-realdata/linux
#
# Reads only, with `sudo -n` (the logs belong to `adm`). The lines are real: keep OUT outside the
# repository.
set -euo pipefail

host=${1:?usage: collect-linux.sh USER@HOST OUT [AUTH_LINES] [SYSLOG_LINES]}
out=${2:?usage: collect-linux.sh USER@HOST OUT [AUTH_LINES] [SYSLOG_LINES]}
auth_lines=${3:-77008}
syslog_lines=${4:-100000}

mkdir -p "$out"
as_ndjson() {
    python3 -I -c 'import json, sys
for line in sys.stdin:
    line = line.rstrip("\n")
    if line:
        print(json.dumps({"message": line}, ensure_ascii=False))'
}
ssh -o BatchMode=yes "$host" "sudo -n tail -n $auth_lines /var/log/auth.log" \
    | as_ndjson >"$out/linux-auth.ndjson"
ssh -o BatchMode=yes "$host" "sudo -n tail -n $syslog_lines /var/log/syslog" \
    | as_ndjson >"$out/linux-syslog.ndjson"
wc -l "$out"/*.ndjson
