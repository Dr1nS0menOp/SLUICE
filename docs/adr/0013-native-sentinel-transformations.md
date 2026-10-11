# ADR 0013: Native Sentinel transformations, proven like VRL

- Status: Proposed
- Date: 2026-10-10

## Context

PLAN.md M5: emit the proven reductions in each platform's own ingest language, so the cut can
run without Vector in the path. Sentinel comes first: a data collection rule (DCR) can carry a
KQL `transformKql` per data flow.

The constraints (docs/notes/sentinel-dcr.md) shape everything:

- No `summarize`: only L1 reductions (removing fields) can run natively.
- No `bag_remove_keys` or `bag_keys`: fields can only be removed as whole columns, so a record
  must arrive with one column per top-level field, and a template can only be recognised by its
  columns.
- The KQL engine differs from VRL (RE2 regexes, .NET case folding), and the DCR runtime accepts
  only a subset of KQL.

## Decision

1. **Column model.** For a JSON source sent to Sentinel, Sluice generates the stream declaration
   from its discovered templates: one column per top-level field (dynamic for objects and arrays,
   otherwise typed from the samples), plus `TimeGenerated`. Nested fields are only removable as
   their whole top-level column.
2. **Recognition on columns.** A template is recognised by its discriminator values and by which
   of the source's columns are non-null. That is the view Sentinel's own rules have, so two
   records that look the same in columns are the same to every Sentinel rule. A record that fits
   no template passes through unchanged (contract rule 1).
3. **L1 only, per row.** For a recognised record outside its recipe's `keep_whole_when`, each
   dropped column is set to null with `extend Col = iff(cond, <null of its type>, Col)`; columns
   no template keeps anywhere use `project-away`. Routing and summaries stay with Vector.
4. **Superset compilation.** Predicates compile to KQL that matches *at least* what the VRL
   matches, never less: a keep-whole condition may only keep more. Anything KQL cannot express
   the same way widens to `true`: regexes (RE2 differs from Rust's engine), non-ASCII values in
   case-insensitive tests, floats, booleans, arrays and objects. Keywords test the concatenated
   text of every column, which also includes object keys: a superset.
5. **Archive first, inside the DCR.** The generated DCR has two data flows from the same stream:
   the transformed one to the analytics table, and an untransformed one to a low-cost table
   (Auxiliary or Basic logs). Sluice refuses to emit a transformation without the second flow.
6. **Proof on what KQL produces.** A differential gate (like `vector-check.sh`) runs the
   generated transformation in the Kusto emulator on the sample, then evaluates the Sigma rules
   on its output and requires the same alert set as on the full data. A static check rejects any
   operator or function outside the DCR list. Without the emulator, the backend only generates,
   marked advisory.
7. **Only the `sigma` profile's recipes** (ADR 0012) are used for a Sentinel DCR, since those are
   the rules Sentinel runs.

## Consequences

- Native Sentinel savings are L1 only: the rendered `Message` and empty fields, which were most
  of the 24% measured on real Windows data. L2 still needs Vector.
- Generated DCRs change the user's table schema (one column per field). Existing analytics rules
  that expect another schema need the same column names; Sluice keeps source field names as
  column names.
- The emulator image is 4.5 GB, so the differential gate is optional locally and runs in CI only
  where Docker can pull it.
- Whether nulled columns cost ingestion must be measured in a real workspace before savings are
  reported as more than estimates.

## Steps

1. `sluice-kql`: predicate → KQL (superset), with unit tests and an emulator differential test
   against the VRL predicates on the synthetic sample. **Done 2026-10-10**
   (`scripts/kql-check.sh`, part of `check.sh` when the emulator image is present; results in
   docs/notes/sentinel-dcr.md).
2. Template recognition and L1 reductions → `transformKql`; static allowlist check.
3. Stream declaration and DCR JSON with the archive flow; `sluice connect sentinel --native`.
4. The proof gate on emulator output; a real-workspace measurement of `_BilledSize`.
