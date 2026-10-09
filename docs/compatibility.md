# Compatibility

Sluice proves its reductions by running the same VRL that Vector runs. That only holds when the
`vrl` crate embedded in Sluice matches the one in the Vector release that enforces the config.

| Sluice | `vrl` crate | Vector release | Status |
|--------|-------------|----------------|--------|
| 0.1.0 (unreleased) | 0.36.0 | 0.59.0 | `vrl = "0.36.0"` confirmed in Vector v0.59.0's `Cargo.toml` (2026-10-09) |

When bumping `vrl`, look up which Vector release pins that version (its `Cargo.toml`, workspace
`vrl` entry) and update this table, `scripts/install-vector.sh`, the `Dockerfile` base image (tag
and digest) and `Cargo.toml` in the same change.
