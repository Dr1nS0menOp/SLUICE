# ADR 0035: An MCP server for assistants: Sluice's advice to read, Sluice's proof to pass

- Status: Accepted
- Date: 2026-10-27

## Context

Sluice writes the configurations it can prove: `vector.yaml`, and with `--native` a data
collection rule transformation, ingest pipelines, Lua filters and collector statements. What a
platform needs beyond that varies too much per source to write by hand, such as a changed program
after review, or the transformation and shaping that bring a new source into a standard Sentinel
table (PLAN.md M12, the idea of 2026-10-18). An AI assistant can draft those, but a draft is only
as safe as its check: contract rule 6 says AI proposes and the guardrails decide.

The MCP server Sluice had before (`sluice-mcp`, 2026-10) was a view of `sluice up`'s control plane
and went with it to `archive/` (ADR 0030). It ran on `rmcp` and `tokio`.

## Decision

1. **`sluice mcp` serves one analysis to an assistant**, over the Model Context Protocol on stdin
   and stdout. `--out DIR` is what `sluice analyze` or `sluice demo` wrote. With `--input`,
   `--sources` and rules (`--rules`, or `--sentinel-rules` with `--kusto` and `--sentinel-table`,
   as for `sluice prove`) it can also prove drafts on that sample.
2. **Seven tools, all read-only** (`readOnlyHint`, no open world):
   - `summary`: the saving, the proof, the problems by kind, and per source its saving and its
     largest savings.
   - `source_plan`: a source's part of `plan.json`, or one kind of event.
   - `problems`: the problems, with the advice the report gives per kind (`problem_advice`).
   - `files` and `read_file`: the files the analysis wrote, except the sample (`samples/`) and the
     report. `read_file` reads only a path `files` lists, up to 1 MB, so no argument can reach
     outside the directory.
   - `prove_vector`: `sluice prove` on a configuration the assistant gives, in Sluice's layout
     with its programs as generated or changed. `holds` only when the rules raise exactly the
     same alerts on what it forwards.
   - `prove_transform_kql`: a `transformKql` run in the Kusto emulator on a source's records, as
     the table stores them without it and with it. `holds` only when it drops no record and the
     Sentinel rules raise the same alerts; it also gives the bytes before and after and the
     columns it empties, and refuses one over 15,360 characters or not starting with `source`.
     Functions beyond the few Sluice's own transformations use are named
     (`unverified_functions`), not refused: Azure accepts more, and refuses one it does not
     support when the rule is deployed, visibly.
3. **Nothing is applied.** The server writes no file, deploys nothing, and reaches no engine but
   those it was started with. An assistant reads text whoever writes a log line controls, so no
   tool acts on the world on an argument's say-so (ADR 0030 holds: Sluice is the assistant's
   tool, not a control plane).
4. **The protocol is Sluice's own, small crate** (`sluice-mcp`): JSON-RPC 2.0, one message per
   line, `initialize`, `ping`, `tools/list` and `tools/call`, synchronous, with `serde_json` and
   `thiserror` only. That is all a tools-only server over stdio needs, and it keeps `tokio` and a
   fast-moving SDK out of the build. It speaks the versions that open with `initialize`:
   2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05, and answers any other with the newest.
   2026-07-28, which drops the handshake (stateless, `server/discover`), is not spoken yet; the
   SDK that speaks it (2.3.0) still opens stdio with `initialize` at 2025-11-25.
5. **Proven against a real client.** `scripts/mcp-check.sh` (in the gates when `uv` is installed,
   and in CI) runs the official Python SDK, 1.30.0 and 2.3.0, against `sluice mcp` on a demo:
   it lists the tools, reads the summary, proves the analysis's own `vector.yaml` and is refused
   a path outside the directory. `prove_transform_kql` is tested in the Kusto emulator
   (`scripts/kql-check.sh`): emptying `Message` holds; dropping the failed logons a rule
   detects does not.

## Consequences

- An assistant (Claude Code, Claude Desktop, any MCP client) can work the advice out further,
  and what it proposes has passed the same proof as Sluice's own output.
- A transformation that shapes a new source into a standard table cannot be proven this way yet:
  the rules read the table's names, which the raw records do not have, so there is no full side
  to compare with. `prove_transform_kql` proves transformations over records already in the
  table's shape; shaping stays advisory.
- When clients move to 2026-07-28 for stdio, the crate needs `server/discover` and the
  per-request version; the tools stay as they are.
