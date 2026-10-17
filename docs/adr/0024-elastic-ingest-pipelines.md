# ADR 0024: Elasticsearch ingest pipelines, proven like VRL

- Status: Accepted
- Date: 2026-10-17

## Context

PLAN.md M12: one generator per tool, each turning the savings plan (ADR 0023) into that tool's
configuration, labelled proven or advisory. After the Sentinel DCR (ADR 0013), Elastic is next.
Elastic ingests without a pipeline tool through ingest pipelines: processors that run in
Elasticsearch on each document before it is indexed. Elastic's integrations end every pipeline
with a call to a `@custom` pipeline the user owns, which is where a reduction can run last, on
documents as they will be stored.

An ingest pipeline sees one document at a time and keeps no state, so like a DCR it can only
remove fields (L1). Unlike a DCR it can remove nested fields, and its `script` processor runs
Painless, a full language, so templates can be recognised exactly as VRL recognises them.

## Decision

1. **One `script` processor per pipeline** (`sluice_elastic::ingest_pipeline`), Painless, that
   first finds the document's template and evaluates its keep-whole condition, and only then
   removes. With `ignore_failure`, a script that fails is skipped, keeping what it changed so
   far; since every decision comes before the first change, a failure there leaves the document
   unchanged (contract rule 1).
2. **Recognition is VRL's.** The document's leaf paths (nested objects joined with `.`, arrays
   and scalars as leaves, empty objects absent, Elasticsearch's metadata left out) must be
   exactly one of the template's key sets, compared as sets so Java's sort order does not
   matter, and each discriminator must render as VRL's `to_string` renders it. Templates are
   tested in the order of the VRL program. Only templates that remove something are tested,
   plus any template that comes before one of them and could fit the same document (a shared
   key set with compatible discriminators), so no document is claimed by another template than
   in Vector.
3. **Superset predicates** (`sluice_elastic::compile`), as for KQL: what Painless cannot decide
   like VRL widens to `true` (regular expressions, case-insensitive tests on non-ASCII text,
   where Java's case folding is not Rust's). Arrays, objects and floats are `true` and nulls
   `false`, as in VRL; `exists` is the path being there, as VRL's. The templates of a source
   repeat the same rules' pre-filters in their keep-whole conditions, so each distinct
   alternative is a Painless function once, and a template's empty-field exceptions are only
   those that touch its fields: with Elastic's prebuilt rules that took a real System pipeline
   from 484 KB to below the limit.
4. **Left to a pipeline tool:** text templates (recognised by a Rust regex), counting, templates
   with a field named like Elasticsearch metadata (`_id`, `_index`, …), and a pipeline whose
   script would exceed the 65,535 bytes Elasticsearch compiles. Each is listed.
5. **Proven in a real Elasticsearch.** `sluice analyze --elasticsearch URL --elastic-native` (and `sluice demo`)
   runs each pipeline on the sample with `_ingest/pipeline/_simulate`, strictly (a failing
   script is an error), and writes `elastic/SOURCE.pipeline.json` only if every field removed
   from a document is one the proven data plane removes from it too, and the Sigma rules raise
   the same alerts on the output as on the full documents.
6. **Gates.** `scripts/elastic-check.sh` starts Elasticsearch in Docker and runs the
   differential tests (every predicate's Painless matches whatever its VRL matches; documents
   leave the pipeline exactly as they leave Vector, across the edges of recognition; an
   installed pipeline stores what the simulation showed) and the demo end to end. `check.sh`
   runs it when the image is present; CI runs it in its own job.

## Consequences

- Elastic users get field removals without Vector, on everything but text templates and
  counting. On the author's real Windows sample with SigmaHQ: System −24.8 %, Application
  −39.3 %, with 60 = 60 and 176 = 176 alerts.
- The sample must be documents as the index stores them (`_source`), the way a `@custom`
  pipeline sees them. A sample taken before Elastic's integration pipelines parse it would
  recognise other key sets: then documents fit no template and pass whole, which is safe but
  saves nothing.
- Elastic's own detection rules (KQL, EQL, ES|QL) are not modelled yet; the proof uses Sigma.
  They come with M12's rule-language work.
- Archive-first (contract rule 2) is not part of the pipeline: Elasticsearch has no second
  output. The full documents must be kept by what sends them, as with Vector's archive.
