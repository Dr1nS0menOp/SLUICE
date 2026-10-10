# ADR 0012: Each destination is proven against its own SIEM's rules

- Status: Accepted
- Date: 2026-10-10

## Context

Until now every loaded rule set applied to every destination. Real data showed the cost: with
the stock Wazuh ruleset loaded, nothing on a JSON event can be cut, because generic raw-text rules
such as 1002 read the whole JSON line (docs/notes/wazuh.md). A deployment that dual-ships to
Wazuh and Sentinel then saved nothing on the Sentinel side either, although Sentinel never runs
a Wazuh rule. Dual-shipping during a SIEM migration is a core use case (PLAN.md, "Why people
buy Cribl"), so this is not an edge case.

## Decision

1. **Rule profiles.** A destination names the rule sets its SIEM runs with `sluice_rules`
   (`[sigma]`, `[wazuh]`, or both; default: every loaded set). Each distinct set is a profile,
   named by its sorted members joined with `+` (`sigma+wazuh`). A name that is not loaded is a
   configuration error, refused at start.
2. **One proof per profile.** Each cycle analyzes the same window once per profile, against that
   profile's rules only, with its own lifecycle (shadow, promotion, rollback) and status. If any
   profile's cycle fails, the configuration is not rewritten.
3. **One pipeline per profile.** In Vector each source keeps one input, one archive sink and one
   tap; each profile adds its own program, route and summaries, and feeds only its own
   destinations. With a single profile, component names are unchanged, so existing deployments
   see no difference.
4. **Visible per profile.** `GET /status?profile=…` (default: the first profile), a profile
   picker in the console, `sluice status --profile`, and a `profile` parameter on the MCP tools.

## Consequences

- Safety is unchanged per destination: each one receives only what was proven against the
  rules it runs. A destination whose profile has no proven pipeline gets every source unreduced.
- A profile without Sigma shows `0 = 0` alerts: the offline proof evaluates Sigma only. Wazuh
  rules are protected by the guardrails (what they read, where they may match), and verified on
  real events by the optional `logtest` spot check. Live run (demo traffic,
  `examples/up/sluice-dual.yaml`): the `sigma` destination received 17.3 → 4.9 MB per cycle
  with 741 = 741 alerts, the `wazuh` destination every event unchanged.
- More rules can never allow more cuts; a server test checks that the `sigma` profile forwards no
  more than `sigma+wazuh` on the same window.
- Cost grows with the number of profiles (one analysis each per cycle). In practice there are one
  or two.
- Every MCP tool that reads the status (`status`, `templates`, `explain`, `what_breaks`,
  `coverage_gaps`, `source_health`) takes an optional `profile`; without one it describes the
  first profile.
- Native transformations (PLAN.md, M5) build on this: a Sentinel DCR is generated from the
  `sigma` profile's recipes, never from a profile that includes rules Sentinel does not run.
