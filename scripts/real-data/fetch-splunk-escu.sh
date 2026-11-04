#!/usr/bin/env bash
# Downloads Splunk's ES Content Update app (`DA-ESS-ContentUpdate` from splunk/security_content,
# Apache-2.0) into a cache outside the repository, and prints the directory `--splunk-rules` and
# SLUICE_SPLUNK_RULES take.
#
#   scripts/real-data/fetch-splunk-escu.sh [CACHE_DIR]
#
# The app ships every search disabled, and only enabled searches count (ADR 0026): for a real
# analysis, use your own `savedsearches.conf` and `macros.conf` instead.
set -euo pipefail

cache=${1:-$HOME/.cache/sluice/splunk-escu}
mkdir -p "$cache"
release=$(curl -fsS https://api.github.com/repos/splunk/security_content/releases/latest)
tag=$(python3 -I -c 'import json, sys; print(json.load(sys.stdin)["tag_name"])' <<<"$release")
if [ ! -d "$cache/$tag" ]; then
    url=$(python3 -I -c 'import json, sys
assets = json.load(sys.stdin)["assets"]
print(next(a["browser_download_url"] for a in assets
           if a["name"].startswith("DA-ESS-ContentUpdate") and a["name"].endswith(".tar.gz")))' \
        <<<"$release")
    mkdir -p "$cache/$tag"
    curl -fsSL "$url" | tar -xz -C "$cache/$tag"
fi
echo "$cache/$tag/DA-ESS-ContentUpdate/default"
