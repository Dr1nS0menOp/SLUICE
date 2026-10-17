# Elasticsearch ingest pipelines: verified behaviour

Verified against Elasticsearch 9.1.0 (`docker.elastic.co/elasticsearch/elasticsearch:9.1.0`,
single node, security off) on 2026-10-17, through `POST _ingest/pipeline/_simulate` and an
installed pipeline. ADR 0024 uses these facts.

## What a Painless ingest script sees

- **`ctx.keySet()` includes the metadata:** `_index`, `_id` and `_version` are keys of `ctx`
  next to the document's fields (and `_routing` and the like when set). `_ingest` is not.
  Sluice leaves out the names in `sluice_elastic::METADATA_FIELDS`.
- **Value types:** JSON integers arrive as `Integer` or `Long`, decimals as `Double` (`4624.0`
  stays a `Double` and `String.valueOf` renders it `4624.0`, where VRL renders `4624`), strings
  as `String`, `true` as `Boolean`, objects as `Map`, arrays as `List`, `null` as null.
- An integer beyond `Long` (`12345678901234567890`) fails the document before any processor
  runs: `unexpected value type [class java.math.BigInteger]`.
- `getClass()` is not allowed (`dynamic method [java.lang.Integer, getClass/0] not found`); use
  `instanceof`.
- `'İSTANBUL'.toLowerCase(Locale.ROOT)` is `i̇stanbul` (with a combining dot): Java and Rust fold
  non-ASCII case differently, so case-insensitive tests on non-ASCII text widen.
- Painless string literals in single quotes escape only `\\` and `\'`; any other character,
  a line break included, stands for itself.
- `==` on strings compares values.

## Limits

- **An inline script may be at most 65,535 bytes:** `exceeded max allowed inline script size in
  bytes [65535] with size [65994]` (`script.max_size_in_bytes`). A script of 65,000 bytes
  compiles. Recognising every one of 151 templates of a real Windows System log took 83 KB;
  recognising only those that remove something (and those that could claim their documents
  first) fits.
- **`ignore_failure: true` keeps what a script changed before it failed:** `ctx.a = 1; ctx.b =
  ctx.missing.length();` stores the document with `a` and no error. So Sluice's script makes
  every decision before its first change, and the proof turns `ignore_failure` off so a failure
  on the sample is an error.
- A script that does not compile is refused for the whole request (HTTP 400, `compile error`),
  whatever `ignore_failure` says.

## Deploying

- `PUT _ingest/pipeline/NAME` takes the generated file as it is; indexing with
  `?pipeline=NAME` stored exactly what `_simulate` returned (test
  `c1_an_installed_pipeline_stores_what_the_simulation_showed`).
- Elastic's integration pipelines call `<type>-<dataset>@custom` (and `global@custom`,
  `<type>@custom`) at their end if it exists (Elastic's documentation, not tried here): a
  `pipeline` processor there calling Sluice's pipeline runs it last, on documents as stored.
