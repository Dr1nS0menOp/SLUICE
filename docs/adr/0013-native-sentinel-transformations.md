# ADR 0013: Native Sentinel transformations, proven like VRL

- Status: Accepted (steps 1 to 4 done, custom tables included)
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
2. Template recognition and L1 reductions → `transformKql`; static allowlist check. **Done
   2026-10-17** (`sluice_kql::transformation`, from the plan of ADR 0023). Recognition is on a
   signature: one bit per column the source's templates have (empty or not), plus a test that
   every other column is empty, and the discriminator values. That is exact only where an empty
   column and a missing one are the same, so `sluice analyze --sentinel-native` generates only
   from samples without empty fields: records read back from the table. Columns Azure fills
   itself are not part of the signature; templates it cannot tell apart remove what all of them
   remove and keep every column where any keeps the event whole. Nested fields, counting and
   text templates stay with a pipeline tool and are listed. Empty-field removal is left out: an
   empty column is not billed.
3. Stream declaration and DCR JSON with the archive flow; `sluice connect sentinel --native`.
   **DCR done 2026-10-17**: with `--sentinel-dcr RULE.json`, `sluice analyze --sentinel-native`
   writes `sentinel/dcr.json`, that rule with each proven transformation in its table's data
   flow and, for each changed table, an untransformed flow of the same stream into
   `Sluice<Table>Archive_CL`, plus `sentinel/Sluice<Table>Archive_CL.table.json`, the table on
   the Auxiliary plan with the stream's columns (decision 5). One file for all tables, because
   a rule is updated as a whole; tables where nothing is removed keep their flow, and a rule
   Sluice wrote before has its part replaced (`SLUICE_PART`). Deployed in the test workspace
   (`scripts/real-data/deploy-dcr-native.sh`): every record arrived transformed in
   `SecurityEvent` and whole in the archive (docs/notes/sentinel-dcr.md). Without a rule,
   nothing is written. **Custom tables 2026-10-17** (decision 1): a JSON source that `sluice
   connect sentinel --sample` sends to `<Name>_CL` takes `--sentinel-table SOURCE=<Name>_CL`
   and that rule as `--sentinel-dcr`. The table's columns are inferred from the sample as
   `connect` infers them, so the emulator holds each field under the column the rule renames it
   to, and Sentinel rules on the table run there. Sluice's part runs *before* the flow's own
   transformation, on the stream's names: the flow renames fields that are no valid column
   names (`@timestamp`), and Vector, too, removes fields before the flow sees them. The proof
   compares the rules on the records as the table gets them without Sluice's part and with it,
   both from one emulator query, because the flow's transformation reads the clock (`now()`).
   `scripts/sentinel-custom-check.sh` (run by `kql-check.sh`) does this end to end on the
   synthetic Windows records sent as flat JSON: `Message` emptied, 54 % saved, 27 = 27 alerts,
   and the same transformation again on the rule it wrote. Nested objects are dynamic columns
   and stay with a pipeline tool. `sluice connect sentinel --native` is not needed: `connect`
   writes the rule, `analyze --sentinel-native` adds the proven part.
4. The proof gate on emulator output; a real-workspace measurement of `_BilledSize`. **Proof
   done 2026-10-17**: `--sentinel-native` runs the transformation on the sample in the emulator,
   checks that every column it empties on a record the proven data plane removes from it too,
   and that Microsoft's rules raise the same alerts on the transformed records; only then is
   anything written. The transformation names only columns of the data
   flow's stream (from `--sentinel-dcr RULE.json`, else the table's), runs after the flow's own
   transformation, and is refused above the 15,360 characters a rule takes
   (docs/notes/sentinel-dcr.md). On the 40,590 records of the test workspace (Windows
   Security Events solution): `SecurityEvent` 33.5 → 32.1 MB (4.1 %, `EventData` of 4672 and
   4798), `WindowsEvent` unchanged, 9.7 KB of KQL. The emulator test in `transform/tests.rs`
   (run by `scripts/kql-check.sh`) checks recognition on records built for each edge. **In a
   real rule 2026-10-17**: Azure accepted the transformation and, on 150 real records, emptied
   exactly the columns the emulator did (docs/notes/sentinel-dcr.md;
   `scripts/real-data/try-dcr-native.sh`).
