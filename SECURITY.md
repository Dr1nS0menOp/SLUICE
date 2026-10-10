# Security policy

Sluice decides which security data reaches a SIEM, so a bug that lets it drop or alter data a
detection needs is a security issue, even without an attacker. So is anything that exposes the
archive, the control plane or the MCP server to someone who should not reach them.

## Reporting a vulnerability

Please report it privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository ("Report a vulnerability" under the Security tab), not in a public issue.

Include what you ran (version, configuration without secrets, rules), what you expected and what
happened. A minimal set of events and rules that shows an alert being lost is the most useful
report there is.

## What counts

- A reduction that changes the alerts of a loaded rule, which the shadow proof did not catch.
- A guardrail that lets a field or event through the cut that a rule reads.
- Archive data that is lost, altered, or readable without access to the archive directory.
- The control plane or the MCP HTTP server answering without the expected restrictions (the MCP
  HTTP transport requires a bearer token and checks the `Host` header).
- Secrets ending up in generated files, logs or the report.

## Supported versions

Sluice is in early development; fixes go into the latest release only.
