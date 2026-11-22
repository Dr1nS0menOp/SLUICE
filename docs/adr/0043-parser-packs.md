# ADR 0043: Parser packs: text lines read as the SIEM reads them

- Status: Accepted
- Date: 2026-11-22

## Context

A text source's event is one line, but a SIEM parses fields out of it before its rules run: a web
server rule tests `cs-uri-query`, a firewall rule `dst_port`. Sluice did not know the parser, so
since ADR 0020 a Sigma rule that names a field keeps every line of its log source whole. That is
safe, but text sources then save almost nothing once real rules are loaded. ADR 0020 named the way
out: parser packs that Sluice can replay.

## Decision

1. **A parser pack** is a YAML file: an id, a description, the Sigma log source it is for, the
   convention of its field names, regular expressions with named groups, the field each group
   gives (or several), and example lines with the fields they must give. Patterns are tried in
   order; the first that matches gives its fields, and a group that took no part gives none. A
   pack may `include` others, for a log that mixes programs (`linux/auth`: sshd, sudo, PAM, cron).
   Packs live in `parsers/`, embedded in the binary like the recipes. Loading refuses a pack whose
   pattern does not compile, names a group it lacks, contains `\'` (VRL cannot quote it), or
   whose examples do not parse as they say. `sluice parsers` lists them.
2. **A source names its pack**: `format: {kind: text, field: message, parser: nginx/combined}`,
   or a pack file of its own by its path (`parser: packs/my-firewall.yaml`, relative to the
   sources file). As with a `--sigma-pipeline`, naming a pack is the operator's claim that the
   SIEM parses the lines that way. The proof parses them with the same pack, so it cannot notice
   a different parser in the SIEM. A pack that is named but not resolved parses nothing.
3. **Guardrails.** On a text template whose source has a pack, a rule in a convention the pack's
   names can be compared with is read through the pack when every field it reads is one the pack
   gives or one the template's events carry. Its pre-filter is then tested on the parsed fields,
   and the fields it reads become the line, so the line stays whole on every event the rule could
   match. Any other rule is read as before (ADR 0020).
4. **The data plane.** The VRL program parses the line into a variable with the pack's patterns,
   the first that matches, before any route is decided. A test on a parsed field reads it there.
   A field that is missing makes the test true: the line did not parse, or the group took no
   part, and the SIEM may parse it otherwise (fail closed). Summary keys may be parsed fields.
   The parsed values go through JSON once, so VRL types them as it types an event's: the tests
   written for event fields apply unchanged.
5. **The proof.** The Sigma engine gives a rule on an event of such a source the parsed fields
   before the event's own. VRL and the proof both run Rust's `regex`, so a line is parsed alike
   on both sides.
6. **Recipes count parsed lines.** Web, proxy and DNS lines no rule could match are counted per
   minute, per host or client and the parsed fields that say what happened (`cs-method`,
   `sc-status`; `query`, `record_type`): `nginx/access/requests`, `apache/access/requests`,
   `squid/access/requests`, `bind/dns/query`, `dnsmasq/dns/query`.
7. **Built-in packs** (18): nginx and Apache access logs (`combined`, `common`), IIS W3C,
   HAProxy HTTP, Squid native, Linux netfilter (iptables, nftables, UFW), pf `filterlog`
   (pfSense, OPNsense), Cisco ASA, FortiGate, BIND, dnsmasq, Unbound, and Linux auth (sshd, sudo,
   PAM, cron, and `linux/auth` with all four). Field names follow Sigma's taxonomy per category
   (`c-ip`, `cs-uri-query`, `src_ip`, `dst_port`, `query`).

## Consequences

- On the demo, nginx's lines are counted where a rule could not match them (80.6 % saved, from
  78.2 %). An example rule on the parsed user agent (`cs-user-agent`) fires on the scanner's four
  requests in the proof, 45 = 45 alerts.
- A pack that parses differently from the SIEM is the same risk as a wrong `schema` or pipeline.
  The documentation says so, and each pack's examples are its test.
- Text templates and counting still run in a pipeline tool only: a SIEM's ingestion or an agent
  reads key sets (ADR 0013).
