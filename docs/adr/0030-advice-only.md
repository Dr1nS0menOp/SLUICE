# ADR 0030: Advice only: Sluice looks, advises and writes the configurations

- Status: Accepted
- Date: 2026-10-17

## Context

The maintainer stated the product on 2026-10-17: an app that looks into your SIEM, finds where
you can save, advises you, and gives you the templates, configurations and transformations to
save right away. The tool itself does nothing: it only looks, advises and works the advice out.

That follows a line drawn earlier. The project aims to make Cribl-style pipeline platforms and
SIEM lock-in obsolete, so Sluice emits configuration files and does not host pipelines (ADR
0017, 2026-10-11). ADR 0022 then made `sluice up` propose instead of apply.

`sluice up` had grown into a pipeline host all the same. It started and reloaded the Vector that
carried every event, tapped a sample, kept recipes in shadow and promoted them, and switched
Vector to a safe configuration on its own (ADR 0005, ADR 0022). Around it came a control plane
with a token (ADR 0010), a web console (ADR 0011), operator actions, named operators and single
sign-on (ADR 0016), an archive with search and replay (ADR 0006), an MCP server, a Windows agent
that sent to it (ADR 0014), destination blocks for six targets, a container image and a Helm chart
(ADR 0007). That is the largest part of the code to maintain and to secure, and it puts Sluice
in the data path. The product no longer needs it: since M12, `plan.json` and the generators for
Vector, Sentinel, Elasticsearch, Fluent Bit and the OpenTelemetry Collector, each proven in the
real engine, carry the advice out (ADR 0023, 0013, 0024, 0027, 0028).

## Decision

1. **Sluice only looks, advises and works the advice out.** It reads the rules a SIEM runs and a
   sample of the data, proves where it can save, and writes the plan and the configurations that
   save it. It never runs in the data path and changes nothing in the user's environment. People
   deploy what it writes with their own tooling.
2. **What stays is the product:**
   - `sluice rules fetch sentinel|wazuh|elastic|splunk` (read-only) and `sluice rules
     requirements`.
   - `sluice analyze` and `sluice demo`: discovery, guardrails, the proof on the sample,
     `report.html`, `plan.json`, and a `vector.yaml` for the user's own Vector.
   - The native generators, each proven in its real engine: `--sentinel-native` (data collection
     rule `transformKql`, custom tables included), `--elastic-native` (Elasticsearch ingest
     pipelines), `--fluent-bit-native` (Fluent Bit Lua filters) and `--otel-native`
     (OpenTelemetry Collector `transform` statements).
   - `sluice recipes` (list, `schema`, `export`, `contribute`) and the AI advisor (`--llm`).
   - `sluice prove`, which checks that a Vector configuration still raises the same alerts on a
     sample, and the GitHub Action that runs it.
   - `sluice connect sentinel`, which now only writes Sentinel-side files: `--sample` with
     `--table` (a custom table and its data collection rule), `--standard-table` (the rule of a
     standard table) and `--summary-table` (`SluiceSummary_CL`, its rule and `SluiceCounts.kql`).
     It no longer prints a destination.
3. **Everything whose purpose is running in the data path moves to `archive/`**, a top-level
   directory outside the Cargo workspace:
   - `sluice up` and crate `sluice-server`: the control plane that ran Vector, the tap, shadow
     and promotion, proposals, the switch to the safe configuration, `--reload-rules`, the web
     console and status page, operator actions, `operators_file`, single sign-on and the control
     token. With it, `sluice status`.
   - `sluice search`, `sluice replay` and crate `sluice-archive`.
   - `sluice mcp` and crate `sluice-mcp`.
   - `sluice agent windows`, the configuration of a collection agent that sent to `sluice up`.
   - The `sluice up` configuration, with its source `shape` and the destination keys
     `sluice_rules`, `sluice_records`, `sluice_formats` and `sluice_sources`; the destination
     blocks `sluice connect` printed for it; and every `sluice connect` target but `sentinel`.
   - The Helm chart (`deploy/helm`), the container image that bundled Vector for `sluice up`
     (`Dockerfile`), `examples/up`, `examples/docker`, and the scripts `helm-check.sh`,
     `live-smoke.sh`, `load-test.sh` and `real-data/send-sentinel.sh`.
4. **Superseded ADRs.** These describe the archived code, not Sluice:
   - ADR 0005 (the live control loop), 0006 (archive search and replay), 0010 (secrets and
     control plane access), 0011 (the web console), 0012 (per-destination proofs: rule profiles
     are a `sluice up` destination setting) and 0016 (operator actions).
   - In part:
     - ADR 0007: the container image. The static binaries and draft releases stay.
     - ADR 0014: the Windows agent and the shaping in `sluice up`. Decision 6 (a rule's field
       also protects the same field nested under an object) stays in the guardrails.
     - ADR 0021: completeness per rule profile, and `--reload-rules`. The fetch and the
       completeness gate stay.
     - ADR 0022: decisions 1, 2 and 6 (proposals, the switch to the safe configuration, the load
       test). `sluice prove`, its refusals and the Action stay.
     - ADR 0023: the `plan-<profile>.json` next to `sluice up` proposals.
     - ADR 0029: decision 1 (`sluice_records`) and the destination for summaries. The table, its
       rule and `SluiceCounts` stay.

   ADR 0017's reasons against hosting a fleet now apply to the single local Vector it kept too.

## Consequences

- A smaller surface. Sluice serves nothing: no port, token, console, sessions or MCP endpoint,
  and it reads no archive of event content. The credentials it takes are for reading rules
  (`sluice rules fetch`) and, for the optional Wazuh spot check, for `logtest`. The workspace
  loses three crates.
- Counting instead of sending (L2, L3) needs state across events. A data collection rule, an
  ingest pipeline and the agents' filters see one record at a time, so the native generators make
  field removals (L1) only. Counting still needs a pipeline tool: the user runs Sluice's
  `vector.yaml` in their own Vector, as ADR 0017 intended.
- Nothing watches what runs. The continuous re-check of contract rule 5, and the switch to the
  safe configuration when it failed, were `sluice up`'s. Now every saving is proven before it is
  proposed, and `sluice prove` proves a configuration again when it changes. A format that
  changes later fits no template and passes through unchanged (contract rule 1), which costs
  savings, not detections. A rule added in the SIEM, however, protects its data only from the
  next `sluice rules fetch` and analysis on. Until then, a deployed configuration may remove
  fields or count events that the new rule needs.
- Dual-shipping to two SIEMs no longer gets a proof per destination (ADR 0012). An analysis
  proves against every rule set it is given.
- Contract rule 2 is carried by the configurations: the archive sink in `vector.yaml`, and the
  untransformed flow into an Auxiliary table in a Sentinel rule (ADR 0013). Sluice no longer
  reads the archive back.
- The archived code sits in `archive/` as it was, and Git keeps its history (`git log --follow`).
  It is not built, tested or linted, so it will drift from the workspace. Bringing a part back
  takes a new ADR and the quality gates.
- To delete later, in one change: `archive/`, and the notes only it needs
  (`docs/notes/mcp.md`, `docs/notes/oidc.md`). The superseded ADRs stay as the record of why.
