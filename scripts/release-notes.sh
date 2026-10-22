#!/usr/bin/env bash
# Prints the CHANGELOG section of one version, the notes of its GitHub release. Fails when the
# CHANGELOG has no section for that version, so no release goes out without one.
#
#   bash scripts/release-notes.sh 0.1.0 > notes.md
set -euo pipefail

version=${1:?usage: release-notes.sh VERSION}
awk -v heading="## [${version}]" '
    index($0, heading) == 1 { found = 1; next }
    found && /^## \[/ { exit }
    found { print }
    END { if (!found) exit 1 }
' CHANGELOG.md || { echo "CHANGELOG.md has no section ## [${version}]" >&2; exit 1; }
