# Security policy

Sluice writes the configurations that decide which security data reaches a SIEM, so a bug that
makes one drop or alter data a detection needs is a security issue, even without an attacker. So
is anything that leaks the credentials it reads rules with.

## Reporting a vulnerability

Please report it privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository ("Report a vulnerability" under the Security tab), not in a public issue.

Include what you ran (version, command line without secrets, rules), what you expected and what
happened. A minimal set of events and rules that shows an alert being lost is the most useful
report there is.

## What counts

- A configuration Sluice writes (`vector.yaml`, a data collection rule transformation, an
  ingest pipeline, a Fluent Bit or OpenTelemetry Collector filter) that changes the alerts of a
  loaded rule, which the proof did not catch.
- A guardrail that lets a field or event through the cut that a rule reads.
- A configuration that loses or alters the full-fidelity copy it is meant to archive.
- Secrets ending up in generated files, logs or the report.

## Supported versions

Sluice is in early development; fixes go into the latest release only.
