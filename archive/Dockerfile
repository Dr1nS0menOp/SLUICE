# Sluice and the Vector release it is verified against, in one image: `sluice up` runs Vector
# as its child process (ADR 0005).
#
# The image packages the static release binaries instead of compiling, so what runs in a
# container is byte for byte what is released:
#
#   scripts/build-release.sh
#   docker buildx build --platform linux/amd64,linux/arm64 -t sluice:0.1.0 .
#
# Base: Vector 0.59.0 distroless-static (see docs/compatibility.md), pinned by digest.
FROM timberio/vector:0.59.0-distroless-static@sha256:2138c72ef15477d3a60126da851407a198ec61d2ff4cd600a4e69db5f6a29ff7

ARG TARGETARCH
# Next to Vector, which the base image installs as /usr/local/bin/vector.
COPY dist/docker/${TARGETARCH}/sluice /usr/local/bin/sluice

# Configuration, rules and recipes are mounted read-only under /etc/sluice; the archive, the
# generated vector.yaml and Vector's data go to the volume.
VOLUME ["/var/lib/sluice"]
EXPOSE 8686

ENTRYPOINT ["/usr/local/bin/sluice"]
CMD ["up", "--config", "/etc/sluice/sluice.yaml", "--rules", "/etc/sluice/rules"]
