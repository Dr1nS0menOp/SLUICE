#!/usr/bin/env bash
# Tests against a real OpenTelemetry Collector (ADR 0028): the transform statements' tests, the
# differential test of their conditions against the VRL ones, and `sluice demo --native otel`.
# The collector runs in Docker; check.sh runs this only when the image is already present.
set -euo pipefail

image="otel/opentelemetry-collector-contrib:0.128.0"
wrapper=$(mktemp)
trap 'rm -f "$wrapper"' EXIT
# The collector's own arguments, with the temporary directory (where the configuration, the
# records and the output are written) mounted at the same path. SIGTERM reaches the collector
# through `docker run`, which stops it.
cat >"$wrapper" <<EOF
#!/usr/bin/env bash
exec docker run --rm -v "\${TMPDIR:-/tmp}:\${TMPDIR:-/tmp}" "$image" "\$@"
EOF
chmod +x "$wrapper"

SLUICE_OTEL_COLLECTOR="$wrapper" cargo test --locked -p sluice-otel -- --nocapture
# The plan's statements for the synthetic sources, proven end to end.
SLUICE_OTEL_COLLECTOR="$wrapper" cargo test --locked -p sluice-cli --test natives otel -- --nocapture
