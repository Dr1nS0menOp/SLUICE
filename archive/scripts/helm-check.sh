#!/usr/bin/env bash
# Checks the Helm chart: `helm lint`, a refused render without a control token, and the
# configuration it ships through `sluice up --check` and `vector validate`.
# Requires helm and Vector (scripts/install-vector.sh).
set -euo pipefail

chart=deploy/helm/sluice
target_dir="${CARGO_TARGET_DIR:-target}"
cargo build -q --release -p sluice-cli
work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT

helm lint "${chart}" --set controlToken.secretName=t --set rules.configMap=r --set siemSecrets.secretName=s
if helm template demo "${chart}" > /dev/null 2>&1; then
    echo "FAIL: the chart rendered without a control token" >&2
    exit 1
fi

helm template demo "${chart}" --set controlToken.secretName=t > "${work}/chart.yaml"
python3 - "${work}/chart.yaml" > "${work}/sluice.yaml" <<'EOF'
import sys
import yaml  # PyYAML, present on Ubuntu and GitHub runners

docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
print(next(d for d in docs if d["kind"] == "ConfigMap")["data"]["sluice.yaml"])
EOF
# The pod's paths, pointed at the work directory so Vector resolves the token secret here.
sed -i "s#/var/lib/sluice#${work}/lib#g; s#/usr/local/bin/vector#vector#" "${work}/sluice.yaml"
export SLUICE_CONTROL_TOKEN
SLUICE_CONTROL_TOKEN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
"${target_dir}/release/sluice" up --check --config "${work}/sluice.yaml" > "${work}/vector.yaml"
mkdir -p "${work}/lib/vector-data/sluice-secrets"
printf '%s' "${SLUICE_CONTROL_TOKEN}" > "${work}/lib/vector-data/sluice-secrets/control_token"
vector validate --no-environment "${work}/vector.yaml"
echo "helm chart check passed"
