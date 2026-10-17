# ADR 0016: Operator actions in the console and the API

- Status: Superseded by ADR 0030 (advice only); the code is in `archive/`
- Date: 2026-10-11

## Context

Until now Sluice decided everything itself and people could only watch: the console and
`GET /status` are read-only (ADR 0011). Running it for real needs a few interventions without a
restart or a config edit: stop a recipe someone distrusts, keep a field an analyst relies on that
no rule reads, let a recipe go live before its shadow period ends, or, in a cautious team, let no
recipe go live without a person agreeing. Each of these must leave a trace, and none may weaken
the safety contract.

## Decision

1. **Four kinds of action, per rule profile** (each profile has its own lifecycle and pipeline,
   ADR 0012):
   - **Hold / release a template.** A held template is forwarded unchanged and its recipe does
     not advance, whatever the proof says, until it is released. This is also the keep-list for
     templates.
   - **Keep / unkeep a field of a source.** The field is never removed from that source's events.
     It enters the guardrails as an operator rule (`operator:keep:<source>:<field>`) that reads
     the field, so the existing protection does the work and the status explains it like any
     other kept field.
   - **Approve a template's recipe.** An approved recipe in shadow is enforced at the next cycle
     in which it is proven, without waiting out the shadow time and proof count. With
     `promotion.approval: true` (conservative mode), no recipe is enforced without approval.
   - **Acknowledge a rollback**, so the console stops flagging it.
2. **No action can override the contract.** Hold and keep only add protection. Approval only
   shortens the wait: the recipe must still be proven on the same cycle it is enforced in, and
   every later cycle proves it again.
3. **Every action is recorded twice:** in the profile's history (shown in the console and
   `sluice status`) and in an append-only audit log, `audit.ndjson` in the data directory, with
   the time, the action, its target, the reason given and who acted. Holds and kept fields are
   stored in `operator.json` there and survive a restart; approvals and acknowledgements belong
   to the running lifecycle.
4. **Access:** the console and `sluice mcp --allow-actions` (tool `operator_action`) both call
   `POST /actions`, which sits behind the same bearer token as every other route (ADR
   0010) and only accepts `Content-Type: application/json`, which a cross-site form cannot send.
   Without a token the control plane only listens on loopback.
5. **Who acted.** Each operator can get their own bearer token in `operators_file`, a secret
   file of `name token` lines that only its owner may read (Sluice refuses to start otherwise).
   The history and the audit log then name the operator; the shared control token is recorded as
   `token`, and requests without any token configured as `local`.
6. **Single sign-on.** With `oidc` configured, operators sign in to the console with their
   organization's provider (authorization code with PKCE, `state`, `nonce`; ID tokens verified
   against the provider's keys, RS256 or ES256). Only names listed in `oidc.operators` get a
   session, kept in an `HttpOnly`, `SameSite=Strict` cookie; the audit log names them as the
   name claim does. The control token stays required, since Vector authenticates its tap with it.
   Verified against Keycloak ([notes](../notes/oidc.md)).

## Consequences

- Operators can steer Sluice from the console, and a team can require a person's approval before
  anything is cut.
- The audit log is the answer to "who changed what, and why".
- A held template that someone forgets costs savings, never detections; the console lists holds
  and kept fields so they stay visible.
