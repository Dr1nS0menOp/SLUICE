# Sluice user guide

This guide explains how Sluice decides what to cut, how to describe your data, and every command.
The [README](../README.md) is the short version; the [ADRs](adr/) explain why things are built
the way they are.

## How Sluice decides

1. **Templates.** Sluice groups events by shape. A JSON event's template is its set of field
   names plus a few discriminating values, such as `EventID=4624`. A text line's template comes
   from [Drain](notes/drain.md): `sshd Failed password for <*> from <NUM>…`. Template ids are
   hashes of that shape, so the same kind of event gets the same id every time.
2. **Recipes.** A recipe proposes reductions for a kind of event, at one of three levels:
   - **L1, lossless:** drop fields that repeat others (a rendered `Message`) or are empty.
   - **L2, rule-guided:** forward in full every event a rule could match; summarize the rest.
   - **L3, semantic:** summarize a template no rule cares about.

   Proposals come from the community recipes in [`recipes/`](../recipes/), your own recipes
   (`--recipes DIR`), or an AI model (`--llm`). None of them is trusted.
3. **Guardrails.** For each template, Sluice works out which of your rules could see it (by log
   source, and by the template's fixed values) and what each rule reads. A field a rule reads is
   never removed from an event that rule could match; such events are forwarded whole (ADR
   0009). Rare templates are never cut, and nothing is cut without an archive.
4. **Proof.** Sluice runs your Sigma rules over the sample twice, on the full events and on
   what the reduced pipeline would forward. Only if both raise exactly the same alerts is a
   recipe kept; otherwise it is rolled back, per template. The proof runs the same VRL code
   Vector will run.
5. **Live.** With `sluice up`, a proven recipe waits in shadow (24 hours and 3 proofs by
   default) before Vector enforces it, and every cycle proves the enforced set again.

## Describing your sources

`sluice analyze` reads a sources file; `sluice up` reads the same entries under `sources:`.

```yaml
sources:
  - id: windows-system                 # your name for it; also the archive directory
    logsource: { product: windows, service: system, complete: true }
    format: { kind: json }             # JSON objects
  - id: linux-auth
    logsource: { product: linux, service: auth }
    format: { kind: text, field: message }   # one log line per event, in `message`
```

- `logsource` uses Sigma's attributes `product`, `service` and `category`. A rule applies to a
  source unless one of its attributes provably differs.
- An attribute you leave out counts as **unknown**, so rules that name it still apply. Add
  `complete: true` when the attributes you give are all there are. That is right for a single
  channel such as Windows System or Linux auth.log, and wrong for Sysmon or the Windows Security
  channel, onto which Sigma maps categories such as `process_creation`.
- `sluice analyze` prints a **hint** for each source where undeclared attributes keep rules in
  scope, with the number of rules involved.

## Commands

| Command | What it does |
|---------|--------------|
| `sluice demo` | Generates an hour of synthetic traffic with planted attacks and runs the whole autopilot on it. |
| `sluice analyze --input DIR --sources FILE --rules DIR` | Runs the autopilot on your sample (`DIR/<source>.ndjson`), writes `report.html` and `vector.yaml` (with Vector unit tests). `--wazuh-rules` (with `--wazuh-decoders` to bound them), `--wazuh-api` (logtest spot check), `--recipes`, `--llm` are optional. |
| `sluice up --config FILE --rules DIR` | Runs the control plane and Vector live: tap, shadow, promote, verify, roll back. `--check` validates the configuration and prints the Vector configuration instead of starting. |
| `sluice status` | The live control plane's status: savings, proof, stage per template, recent transitions. |
| `sluice search --archive DIR [--source S] [--from T] [--to T] [--where C]…` | Prints archived events (full fidelity) as NDJSON; `--count`, `--limit`. |
| `sluice replay … --url URL` | Sends archived events to an HTTP endpoint as NDJSON. |
| `sluice connect TARGET` | Prints a destination for `sluice up`: `splunk`, `elastic`, `sentinel`, `chronicle`, `wazuh`, `http`. |
| `sluice mcp [--archive DIR] [--allow-replay] [--http ADDR]` | An MCP server for AI assistants, over stdio or bearer-token HTTP. |
| `sluice recipes [schema \| export --out DIR]` | Lists the built-in recipes, prints their JSON Schema, or exports them to edit. |
| `sluice rules requirements --rules DIR` | Prints, as JSON, what each rule needs: log source, fields, raw text, state. |

Conditions for `search` and `replay` are `field=value`, `field!=value` and `field~text`
(contains, ignoring case); times are RFC 3339 or a `YYYY-MM-DD` date (UTC).

## The `sluice up` configuration

```yaml
listen: 127.0.0.1:8686          # control plane API (default)
vector_binary: vector           # default: found on PATH
vector_config: /var/lib/sluice/vector.yaml
archive_dir: /var/lib/sluice/archive
data_dir: /var/lib/sluice/vector-data
tap_rate: 10                    # keep 1 in 10 events for analysis (default)
cycle_secs: 300                 # seconds between cycles (default)
window: { max_events_per_source: 20000, max_age_secs: 3600 }   # defaults
promotion: { shadow_secs: 86400, min_proofs: 3 }               # defaults
sources:
  - id: windows-system
    logsource: { product: windows, service: system, complete: true }
    format: { kind: json }
    vector: { type: http_server, address: 0.0.0.0:9101, decoding: { codec: json } }
destinations:                   # Vector sinks; Sluice sets their inputs
  siem: { type: splunk_hec_logs, endpoint: https://splunk:8088, default_token: "SECRET[siem.splunk_hec_token]", encoding: { codec: json } }
vector_secrets:                 # Vector secret backends for destination credentials
  siem: { type: directory, path: /run/secrets/siem }   # one file per secret
```

- `vector:` is any Vector source configuration that produces JSON objects (one line of text in
  `message` for text sources).
- A destination may carry `sluice_formats: [json]` or `[text]` to take only events of those
  source formats; Sluice removes the key before Vector sees it. `sluice connect wazuh` uses this
  to write JSON sources to one file and raw text lines to another.
- Credentials go in secret files, referenced as `SECRET[backend.key]` through `vector_secrets`
  ([ADR 0010](adr/0010-secrets-and-control-plane-access.md)). Vector 0.59 does not expand
  `${VAR}` in its configuration, so environment references do not work.
- **Control plane access.** With `SLUICE_CONTROL_TOKEN` set (at least 32 characters), every
  route but `/healthz` needs `Authorization: Bearer <token>`; `sluice status` and `sluice mcp`
  send it from the same variable. Without a token, `sluice up` only listens on loopback.
- The archive is gzip NDJSON per source and UTC hour; nothing in it is ever reduced.

## Why is nothing cut?

The report lists, per template, every reduction that was refused or narrowed, and why. The
common reasons:

- **"no recipe"**: no community or own recipe matches the template. Write one
  ([recipes/README.md](../recipes/README.md)) or use `--llm`.
- **"rare … so never cut"**: the template has fewer than 100 events, or less than 0.1 % of its
  source, in the sample. A larger sample or a longer live window fixes this.
- **"may read any field"** or **"could match any event"**: a rule whose fields or matches cannot
  be bounded (an unparsable rule, or a keyword search Sluice cannot narrow) applies to the
  template. Check the **hints**: often the rule only applies because the source's log source is
  incomplete.
- **"kept: … rule tests could apply"**: so many rules apply that testing them per event would
  cost more than it saves. Describing the source more precisely reduces the number.
