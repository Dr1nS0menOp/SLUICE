# ADR 0034: Splunk is removed

- Status: Accepted
- Date: 2026-10-27
- Supersedes: [ADR 0026](0026-splunk-saved-searches.md)

## Context

ADR 0026 made Splunk's scheduled and correlation searches requirements: `--splunk-rules` read
`savedsearches.conf`, `macros.conf`, `props.conf` and `transforms.conf`, and `sluice rules fetch
splunk` read them over the REST API (crate `sluice-splunk`). It stopped there. A Splunk engine for
the proof and a Splunk generator need Splunk itself, whose image needs the Splunk General Terms
accepted; that waited on a decision from 2026-10-17 on. The fetch only ever ran against a
stand-in, never a real Splunk. So the code was the only part of Sluice that was neither proven in
the real engine nor on its way to it, while it had to be kept up with every change to the rule
model, the analysis and the report.

## Decision

The maintainer decided on 2026-10-27 that Sluice does not support Splunk, not even as an
experiment, and that its code goes:

1. The SPL reader (`sluice-rules`' `splunk` module: saved searches, macros, the base search's
   pre-filter, `props` and `transforms`), the crate `sluice-splunk`, `--splunk-rules`, `sluice
   rules fetch splunk`, `Engine::Splunk` (rule ids `splunk:…`), and the ESCU test with its fetch
   script are removed.
2. The field conventions that only Splunk has go with them: `schema: splunk` (the fields as
   Splunk extracts them) and `schema: cim` (Splunk's Common Information Model). A source or a
   `--sigma-pipeline` that names either is now refused as an unknown convention.
3. What Splunk prompted but every SIEM uses stays: a rule that matches raw text reads every field
   of a JSON record (Wazuh's full log, Sigma keyword rules), and CIDR values widen to the field
   having a value (Elastic's KQL).
4. A Splunk user can still use Sluice through Sigma rules (`--rules` with `--rules-complete`, the
   route for any SIEM whose rules Sluice does not read), and `vector.yaml` works in front of any
   destination.

## Consequences

- The workspace loses one crate and about 2,800 lines of code and tests that had no proof behind
  them.
- ADR 0026 stays as the record of what was built and measured (2,223 ESCU searches read, 845
  bounded); the code is in the Git history (last in `614cf90`) if Splunk ever comes back. That
  would start from a new decision on the licence, with a Splunk engine for the proof from the
  start.
- Sentinel, Elastic, Wazuh, Vector, Fluent Bit and the OpenTelemetry Collector are what Sluice
  supports, each proven in its real engine.
