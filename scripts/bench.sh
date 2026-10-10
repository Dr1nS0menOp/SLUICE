#!/usr/bin/env bash
# Throughput of the data plane Sluice generates, measured with the real Vector: one demo source's
# events through its generated transforms (classify, reduce, route, summarize) into a blackhole,
# read from stdin so Vector exits when the input ends. Prints events per second.
#
#   scripts/bench.sh [source] [scale]       # defaults: windows-security 300
#   THREADS=4 scripts/bench.sh               # limit Vector's worker threads
#
# Requires scripts/install-vector.sh. Numbers depend on the machine; record them with its CPU.
set -euo pipefail

source_id="${1:-windows-security}"
scale="${2:-300}"
target_dir="${CARGO_TARGET_DIR:-target}"
cargo build -q --release -p sluice-cli
work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT

"${target_dir}/release/sluice" demo --out "${work}/demo" --scale "${scale}" > /dev/null
input="${work}/demo/samples/${source_id}.ndjson"
python3 - "${work}/demo/vector.yaml" "${source_id}" "${work}/bench.yaml" "${work}" <<'EOF'
import sys
import yaml  # PyYAML, present on Ubuntu and GitHub runners

config_path, source_id, out_path, data_dir = sys.argv[1:5]
stem = "sluice_" + source_id.replace("-", "_")
config = yaml.safe_load(open(config_path))
config["data_dir"] = data_dir
config.pop("tests", None)
# Raw lines in `message`, as the file source the demo configuration reads delivers them.
config["sources"] = {f"{stem}_input": {"type": "stdin"}}
config["transforms"] = {k: v for k, v in config.get("transforms", {}).items() if k.startswith(stem)}
sinks = {}
for name, sink in config.get("sinks", {}).items():
    inputs = [i for i in sink.get("inputs", []) if i.startswith(stem)]
    if inputs:
        sinks[name] = {"type": "blackhole", "inputs": inputs, "print_interval_secs": 0}
config["sinks"] = sinks
yaml.safe_dump(config, open(out_path, "w"))
EOF

events=$(wc -l < "${input}")
bytes=$(wc -c < "${input}")
start=$(date +%s.%N)
threads=()
[ -n "${THREADS:-}" ] && threads=(--threads "${THREADS}")
vector --quiet "${threads[@]}" --config "${work}/bench.yaml" < "${input}" 2> "${work}/vector.err"
end=$(date +%s.%N)
if grep -q ERROR "${work}/vector.err"; then
    echo "FAIL: Vector reported errors, so this is not a measurement of the normal path:" >&2
    head -3 "${work}/vector.err" >&2
    exit 1
fi
python3 - "${events}" "${bytes}" "${start}" "${end}" <<'EOF'
import sys
events, size, start, end = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4])
seconds = end - start
print(f"{events} events, {size / 1e6:.1f} MB in {seconds:.2f} s: "
      f"{events / seconds:,.0f} events/s, {size / 1e6 / seconds:.1f} MB/s (including Vector start-up)")
EOF
nproc | xargs -I{} echo "CPUs: {}, $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
