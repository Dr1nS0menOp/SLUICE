#!/usr/bin/env bash
# Downloads Elastic's prebuilt detection rules (the `security_detection_engine` package from the
# Elastic Package Registry, Elastic License 2.0) into a cache outside the repository, and prints
# the directory `--elastic-rules` and SLUICE_ELASTIC_RULES take.
#
#   scripts/real-data/fetch-elastic-rules.sh [CACHE_DIR]
#
# The package installs every rule disabled, and only enabled rules count (ADR 0025): for a real
# analysis, export your own rules from Kibana instead.
set -euo pipefail

cache=${1:-$HOME/.cache/sluice/elastic-prebuilt}
mkdir -p "$cache"
download=$(curl -fsS 'https://epr.elastic.co/search?package=security_detection_engine&prerelease=false' \
    | python3 -I -c 'import json, sys; print(json.load(sys.stdin)[-1]["download"])')
version=$(basename "$download" .zip)
if [ ! -d "$cache/$version" ]; then
    curl -fsS -o "$cache/$version.zip" "https://epr.elastic.co$download"
    python3 -I -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' \
        "$cache/$version.zip" "$cache"
    rm "$cache/$version.zip"
fi
echo "$cache/$version/kibana/security_rule"
