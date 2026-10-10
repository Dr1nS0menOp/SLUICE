# ADR 0010: Secrets through Vector secret backends; a token for the control plane

- Status: Accepted
- Date: 2026-10-10

## Context

Two gaps showed up while writing the security policy and testing it against Vector 0.59.0:

1. **`${VAR}` references are not interpolated.** Vector 0.59 interpolates environment variables
   in configuration files only with `--dangerously-allow-env-var-interpolation`. The sinks
   `sluice connect` printed (`default_token: "${SPLUNK_HEC_TOKEN}"`) therefore sent the literal
   text as the credential. `vector validate` does not catch this; a probe server receiving
   `Authorization: Bearer ${PROBE_TOKEN}` did.
2. **The control plane had no access control.** Anyone who can reach `/tap` shapes the sample
   the proofs run on (for example, pushing a rare template over the rarity floor), and
   `/status` and `/rules` describe the deployment. Loopback was the only protection, and the
   container example listened on `0.0.0.0`.

## Decision

1. **Credentials go through Vector secret backends.** The `sluice up` configuration takes
   `vector_secrets` (rendered as Vector's top-level `secret:`), and `sluice connect` writes
   destinations that reference `SECRET[siem.<key>]` with a `directory` backend at
   `/run/secrets/siem`: one file per secret, the layout Docker and Kubernetes secrets mount.
   Sluice never enables environment interpolation.
2. **An optional control token.** With `SLUICE_CONTROL_TOKEN` set (at least 32 characters),
   every control plane route except `/healthz` requires `Authorization: Bearer <token>`.
   `sluice up` writes the token to `<data_dir>/sluice-secrets/control_token` (directory 0700,
   file 0600), the tap sinks reference it as `SECRET[sluice.control_token]`, and `sluice status`
   and `sluice mcp` send it. The backend name `sluice` is reserved.
3. **No token, no exposure.** Without a token, `sluice up` refuses a listen address that is not
   loopback.

## Consequences

- Generated configuration files hold no secrets, and neither do process environments of
  Vector.
- Operators put each SIEM credential in its own file; the container example mounts them.
- The token file's permissions only hold on a Linux file system; a Windows drive mounted into
  WSL (`/mnt/c`) ignores them, so keep `data_dir` on the Linux side.
- `scripts/vector-check.sh` validates every `sluice connect` sink with dummy secret files, so a
  sink that references something Vector cannot resolve fails the gates.
