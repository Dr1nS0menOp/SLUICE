#!/usr/bin/env bash
# Load test of a Vector configuration Sluice generated, on a stock Vector (M11): per source, the
# sample's events go through the configuration's own transforms into blackhole sinks, read from
# stdin so Vector exits when the input ends. Next to the events per second it prints what
# `sluice prove` says about the same configuration and sample: the savings and the proof.
#
#   scripts/load-test.sh CONFIG SAMPLES_DIR SOURCES_FILE [SIGMA_RULES_DIR]
#   scripts/load-test.sh                    # the demo at scale 300, as a self-check
#   THREADS=4 scripts/load-test.sh ...      # limit Vector's worker threads
#
# CONFIG is a `vector.yaml` from `sluice analyze` or a `sluice up` proposal; SAMPLES_DIR holds
# `<source>.ndjson` as the configuration's programs see them. Requires Vector
# (scripts/install-vector.sh) and PyYAML. Numbers depend on the machine; record them with its
# CPU. Times include Vector's start-up, so small samples understate throughput.
set -euo pipefail

target_dir="${CARGO_TARGET_DIR:-target}"
cargo build -q --release -p sluice-cli
sluice="${target_dir}/release/sluice"
work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT

if [ $# -eq 0 ]; then
    "${sluice}" demo --out "${work}/demo" --scale 300 > /dev/null
    set -- "${work}/demo/vector.yaml" "${work}/demo/samples" "${work}/demo/sluice.yaml" \
        "$(dirname "$0")/../examples/rules/sigma"
fi
config="$1" samples="$2" sources="$3" rules="${4:-}"

prove=(prove --config "${config}" --input "${samples}" --sources "${sources}" --json)
[ -n "${rules}" ] && prove+=(--rules "${rules}")
"${sluice}" "${prove[@]}" > "${work}/proof.json" || true

threads=()
[ -n "${THREADS:-}" ] && threads=(--threads "${THREADS}")
printf '%-28s %10s %9s %9s %10s %8s\n' source events MB seconds events/s MB/s
for input in "${samples}"/*.ndjson; do
    source_id=$(basename "${input}" .ndjson)
    if ! python3 - "${config}" "${source_id}" "${work}/load.yaml" "${work}/data" <<'EOF'
import sys
import yaml  # PyYAML, present on Ubuntu and GitHub runners

config_path, source_id, out_path, data_dir = sys.argv[1:5]
stem = "sluice_" + "".join(c.lower() if c.isascii() and c.isalnum() else "_" for c in source_id)
config = yaml.safe_load(open(config_path))
transforms = {k: v for k, v in config.get("transforms", {}).items() if k.startswith(stem)}
if stem not in transforms and not any(k.startswith(stem + "_") and v.get("drop_on_error")
                                      for k, v in transforms.items()):
    sys.exit(1)  # the configuration does not reduce this source
# `sluice analyze` configurations parse raw lines (`_parse`); live ones read JSON objects.
codec = "bytes" if f"{stem}_parse" in transforms else "json"
out = {
    "data_dir": data_dir,
    "sources": {f"{stem}_input": {"type": "stdin", "decoding": {"codec": codec}}},
    "transforms": transforms,
    "sinks": {},
}
for name, sink in config.get("sinks", {}).items():
    inputs = [i for i in sink.get("inputs", []) if i.startswith(stem)]
    if inputs:
        out["sinks"][name] = {"type": "blackhole", "inputs": inputs, "print_interval_secs": 0}
for key in ("secret",):
    if key in config:
        out[key] = config[key]
yaml.safe_dump(out, open(out_path, "w"))
EOF
    then
        printf '%-28s not reduced by this configuration\n' "${source_id}"
        continue
    fi
    mkdir -p "${work}/data"
    events=$(grep -c . "${input}" || true)
    bytes=$(wc -c < "${input}")
    start=$(date +%s.%N)
    vector --quiet "${threads[@]}" --config "${work}/load.yaml" < "${input}" 2> "${work}/vector.err"
    end=$(date +%s.%N)
    if grep -q ERROR "${work}/vector.err"; then
        echo "FAIL: Vector reported errors for ${source_id}, so this is not the normal path:" >&2
        head -3 "${work}/vector.err" >&2
        exit 1
    fi
    python3 - "${source_id}" "${events}" "${bytes}" "${start}" "${end}" <<'EOF'
import sys
name, events, size, start, end = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4]), float(sys.argv[5])
seconds = max(end - start, 1e-9)
print(f"{name:<28} {events:>10,} {size / 1e6:>9.1f} {seconds:>9.2f} {events / seconds:>10,.0f} {size / 1e6 / seconds:>8.1f}")
EOF
done
python3 - "${work}/proof.json" <<'EOF'
import json, sys
try:
    p = json.load(open(sys.argv[1]))
except ValueError:
    print("proof: the configuration could not be proven (run `sluice prove` for the reason)")
    sys.exit(0)
verdict = "no detection changed" if p["holds"] else "DETECTIONS CHANGED"
print(f"savings: {p['saved_percent']} % of {p['bytes_in'] / 1e6:.1f} MB; "
      f"proof: {p['alerts_full']} = {p['alerts_forwarded']} alerts, {verdict}")
EOF
echo "CPUs: $(nproc), $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs), Vector $(vector --version | cut -d' ' -f2)"
