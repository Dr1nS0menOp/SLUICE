# AI proposals (L3): how they work

These notes cover `crates/sluice-ai`, written on 2026-10-09. The Claude API shapes are from the
bundled `claude-api` skill (cached 2026-10-06).

## When a model is asked

- **Only** about templates with no community recipe that are frequent enough to cut (rare ones
  would be refused anyway) and that have a classifier (no mixed-header text templates).
- Once per template, with up to 5 samples. Never per event.
- Answers are cached per template, model and prompt version (`prompt::VERSION`) under
  `~/.cache/sluice/ai`. The cache holds the *answer*, and the recipe is rebuilt from it against
  the current template on every run.

## What a model can and cannot do

- **Allowed:** name boilerplate fields, and say whether the template is routine noise to
  summarize (with keys).
- **Ignored or overridden:**
  - Field names that don't exist in the template are dropped.
  - Summarizing requires `security_value` `none` or `low`.
  - Then the guardrails apply: summarizing on a rule-covered template becomes rule-guided, rule
    fields are kept, and rare templates are never cut.
  - Then the shadow proof applies.

  An eager or manipulated model costs savings, never detections. This is tested with an
  `Eager` advisor that tries to summarize everything.

## Prompt injection

Log text can be attacker-written. Samples are:

- **redacted** (`redact.rs`): identity fields, IPv4, e-mail and long tokens are replaced with
  consistent pseudonyms;
- **fenced** in `<untrusted_samples>`, with the fence string itself neutralised inside the samples;
- **declared untrusted** in the system prompt.

The structural defence is that the guardrails and the proof never consult the model.

## Providers

| `--llm` | Endpoint | Notes |
|---|---|---|
| `none` (default) | — | No AI; community recipes only |
| `anthropic[:MODEL]` | `POST /v1/messages` | Raw HTTP (no official Rust SDK). Default model `claude-opus-5-5`, `output_config.effort: medium`, `output_config.format: {type: json_schema, schema}`. Checks `stop_reason` (`refusal`, `max_tokens`) before reading the text block. Server-side `fallbacks: "default"` + beta `server-side-fallback-2026-07-01` on models that support it. Auth: `ANTHROPIC_API_KEY` (`x-api-key`) or `ANTHROPIC_AUTH_TOKEN` (Bearer). |
| `ollama:MODEL` | `http://localhost:11434/v1/chat/completions` | Local; samples never leave the machine |
| `lmstudio:MODEL` | `http://localhost:1234/v1/chat/completions` | Local |
| `openai:BASE_URL#MODEL` | `BASE_URL/chat/completions` | Any OpenAI-compatible server; `OPENAI_API_KEY` optional |

All providers use JSON-schema-constrained output with `additionalProperties: false`.

## Not yet done

- No live run against a real model yet. Request shapes and response handling are covered offline
  (`model/tests.rs`). A local check is possible: `lms server start`, load a model, then
  `sluice demo --llm lmstudio:<model>`.
- TLS uses the bundled Mozilla roots (`webpki-roots`). Enterprises with an intercepting proxy
  need the system trust store: switch ureq to its platform verifier.
- Recipe export for community contribution (PLAN M3) isn't implemented.
