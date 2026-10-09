# Compatibility

Sluice proves its reductions by running the same VRL that Vector runs. That only holds when the
`vrl` crate embedded in Sluice matches the one in the Vector release that enforces the config.

| Sluice | `vrl` crate | Vector release | Status |
|--------|-------------|----------------|--------|
| 0.1.0 (unreleased) | 0.36.0 | to be determined | not yet verified |

When bumping `vrl`, look up which Vector release embeds that version (Vector's `Cargo.lock`) and
update this table in the same change.
