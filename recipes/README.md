# Community recipes

A recipe proposes reductions for one kind of log event. Proposals are never trusted: the
guardrails narrow them to what the loaded rules allow, and the shadow proof rolls back anything
that changes an alert. A recipe that is too eager costs nothing but its own savings.

```yaml
id: microsoft/windows/security/logon          # unique; mirrors the file path
description: Windows logon success (4624)
match:
  logsource: { product: windows, service: security }
  discriminators: { EventID: "4624" }         # JSON templates: discriminator values
  # pattern: "CRON pam_unix(cron:session)"    # text templates: substring of the template pattern
reductions:
  - op: drop_fields                           # L1: remove format fat
    fields: [Message]
  - op: drop_empty_fields                     # L1: remove null and "" fields
  - op: forward_matching                      # L2: forward what rules could match, summarize the rest
    summary_keys: [TargetUserName, IpAddress]
  # - op: summarize                           # L3: summaries only (narrowed to L2 if rules apply)
  #   summary_keys: [host.name]
rationale: >-
  Why these reductions are safe and worthwhile.
```

A recipe without `discriminators` or `pattern` applies to every template of its log source. It
may only use lossless (L1) reductions.

## Schema and editing

[`recipe.schema.json`](recipe.schema.json) is the JSON Schema of a recipe file. It is generated
from the parser's own types (`sluice recipes schema`), and a test fails if the copy here is
stale. Editors with a YAML language server validate a recipe that starts with:

```yaml
# yaml-language-server: $schema=../../../recipe.schema.json
```

To change a built-in recipe for your own deployment, export them, edit, and pass the directory
to `--recipes`. A recipe with the id of a built-in one replaces it:

```sh
sluice recipes export --out my-recipes
sluice analyze ... --recipes my-recipes
```

Only state facts in a rationale that hold for every deployment of the source. For example, "Message
is rendered from the event's own fields" holds everywhere; "nobody uses this field" does not.
