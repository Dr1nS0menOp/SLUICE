#!/usr/bin/env bash
# Tests against a real Fluent Bit (ADR 0027): the Lua filter's tests, the differential test of its
# pre-filters against the VRL ones, and `sluice demo --native fluent-bit`. Fluent Bit runs in
# Docker; check.sh runs this only when the image is already present.
set -euo pipefail

image="fluent/fluent-bit:4.0.3"
wrapper=$(mktemp)
trap 'rm -f "$wrapper"' EXIT
# Fluent Bit's own arguments, with the temporary directory (where the configuration and the
# filter are written) mounted at the same path.
cat >"$wrapper" <<EOF
#!/usr/bin/env bash
exec docker run --rm -i -v "\${TMPDIR:-/tmp}:\${TMPDIR:-/tmp}" "$image" /fluent-bit/bin/fluent-bit "\$@"
EOF
chmod +x "$wrapper"

SLUICE_FLUENT_BIT="$wrapper" cargo test --locked -p sluice-fluentbit -- --nocapture
# The plan's filters for the synthetic sources, proven end to end.
SLUICE_FLUENT_BIT="$wrapper" cargo test --locked -p sluice-cli --test natives fluent_bit -- --nocapture
