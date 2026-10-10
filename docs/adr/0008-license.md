# ADR 0008: AGPL-3.0-only

- Status: Accepted
- Date: 2026-10-09

## Context

Sluice should be as open as possible: anyone may read, run, change and self-host it. The author
also does not want others to take it and sell it as their own closed product or hosted service.

No OSI-approved license forbids selling: every open source license allows commercial use. The
options were:

- **Apache-2.0**: maximally permissive. Anyone, including a competitor, may ship Sluice inside a
  closed product or a paid service.
- **AGPL-3.0**: open source copyleft. Selling is allowed, but whoever distributes a modified
  version *or offers it to users over a network* must publish the complete source under the
  AGPL.
- **Source-available licenses** (FSL, PolyForm Noncommercial, BSL): can forbid competing sale,
  but are not open source, which deters contributors and some users.

## Decision

Sluice is licensed under **AGPL-3.0-only**. `LICENSE` holds the unmodified text from
<https://www.gnu.org/licenses/agpl-3.0.txt>, and the workspace sets `license = "AGPL-3.0-only"`
for every crate. Contributions are accepted under the same license (inbound = outbound,
`CONTRIBUTING.md`).

`-only` rather than `-or-later` keeps the decision on future GNU license versions with the
project.

## Consequences

- Sluice stays open source. A closed fork or a hosted "Sluice as a service" without published
  source is not allowed; an open one is.
- Dependencies must be AGPL-compatible. The `deny.toml` allow-list (MIT, Apache-2.0, BSD, ISC,
  MPL-2.0, Zlib, and similar) already only contains compatible licenses.
- Organizations that run Sluice internally, unmodified or modified, have no obligation unless
  they offer it to others over a network or distribute it.
- Relicensing later (for example dual licensing) requires the consent of every contributor, or a
  contributor license agreement introduced before outside contributions arrive.
