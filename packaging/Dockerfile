# The container image of a release: the static binary on a distroless base, as a user without
# privileges. scripts/package.sh puts the binaries in the build context as sluice-<arch>.
#
#   docker run --rm -u "$(id -u)" -v "$PWD:/work" ghcr.io/dr1ns0menop/sluice demo
#
# The proof's engines (Vector, Fluent Bit, the collector, the Kusto emulator, Elasticsearch) are
# not in the image: give their addresses, or run Sluice from the binary next to them.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG TARGETARCH
COPY sluice-${TARGETARCH} /usr/local/bin/sluice
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/sluice"]
CMD ["--help"]
