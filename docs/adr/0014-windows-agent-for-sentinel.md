# ADR 0014: Vector as the Windows agent, shaping events as Sentinel stores them

- Status: Accepted
- Date: 2026-10-11

## Context

Sentinel collects Windows events through the Azure Monitor Agent (AMA), where the only control
before ingestion is a DCR transformation, and those cannot summarize or remove keys from objects
(ADR 0013, docs/notes/sentinel-dcr.md). The user wants that control back. The Logs Ingestion API
accepts the built-in `SecurityEvent` table from any client, and Vector, which Sluice already
runs and proves, has a `windows_event_log` source (beta) that runs on Windows
(docs/notes/vector-windows.md).

## Decision

1. **Vector is the Windows agent.** `sluice agent windows --to <url>` prints its configuration:
   the `windows_event_log` source, a remap that shapes each event as a `SecurityEvent` record,
   and an HTTP sink with a disk buffer to an `http_server` source of `sluice up`.
2. **Archive the original, then shape, then prove.** The agent sends events as Vector reads
   them. A `sluice up` source with `shape: sentinel_security_event` (or
   `sentinel_windows_event`) archives each event as it arrived (contract rule 2: the rendered
   message, user name and provider GUID have no table column and would otherwise be lost) and
   only then shapes it, before the tap and the reductions. So the record Sluice discovers,
   proves and reduces is the one Sentinel will store, with the field names Sigma and Sentinel's
   analytics use (`TargetUserName`, `LogonType`), while search and replay keep the original.
   (A first version shaped on the host, before the archive; it was changed the same day for
   this reason.)
3. **No guessing.** Columns the AMA derives by unpublished rules (`Account`, `AccountType`) are
   left out until they can be compared with AMA-collected records. A failed shaping sends the
   event unshaped rather than dropping it (`drop_on_error: false`).
4. **Sentinel stores it unchanged.** `sluice agent windows --dcr FILE --workspace ID` writes a
   DCR whose stream declares exactly the columns the shaping writes, with `transformKql: source`
   into `Microsoft-SecurityEvent`.
5. **One table per channel kind.** The Security channel becomes `SecurityEvent`; every other
   channel becomes `WindowsEvent`, whose `EventData` is the data as an object. The agent routes
   them to two `sluice up` sources (`--to`, `--events-to`), and a destination's
   `sluice_sources: [...]` gives each Sentinel table only its own records. The Security source
   can then declare `service: security`, so Sigma rules for other services do not apply to it.
6. **Nested fields count.** `WindowsEvent` keeps provider fields under `EventData`, while Sigma
   names them bare. A rule's field now also denotes the same path nested under an object
   (`FieldPath::may_denote`): the guardrails treat such a rule as applicable and keep the
   nested field and its parents. Without this, a recipe could have dropped
   `EventData.ScriptBlockText` while the proof saw no difference, because the rule never matched
   the nested name. On the real Windows sample with all of SigmaHQ the savings stayed 24.2%.

## Consequences

- With Vector instead of the AMA, Windows security events get every Sluice reduction (L1 and
  L2) before Sentinel bills them, and the archive keeps them whole.
- The agent must run as LocalSystem (a service) or another account that may read the Security
  log.
- Built-in analytics rules that read `Account` or `AccountType` need those columns; comparing
  AMA-collected records with Sluice-shaped ones is the next verification step.
- Vector's source is beta; the pinned release (0.59.0) was checked on Windows 11.
- End to end on this machine (2026-10-11): the Windows agent sent 747 System, Application and
  PowerShell events to `sluice up` (`examples/up/sluice-windows.yaml`) with all of SigmaHQ; the
  archive held all 747 originals (with `event_data`, `message`, `user_name`), and only the
  `WindowsEvent` destination received them, as table records, proven 12 = 12 alerts.
- Into a real workspace (2026-10-11, Sentinel on): the DCR `sluice agent windows --dcr`
  generates was accepted after typing five GUID columns (docs/notes/sentinel-dcr.md), and 154
  real Security events and 267 other-channel events sent through the Logs Ingestion API
  arrived in `SecurityEvent` and `WindowsEvent` as sent (`Activity`, `LogonType` as int,
  `EventData` as XML and as an object).
- Replaying from the archive sends originals: replay them through a source with the same
  `shape` to reach a Sentinel table. No
  recipe matches the table shapes yet, so they passed through unchanged: recipes for
  `SecurityEvent` and `WindowsEvent` are the next step.
Update 2026-10-11: the account columns are derived now, not left out. Microsoft's rules read them
widely (on the rules cached from Azure/Azure-Sentinel: `Account` in 38 rule files, `AccountType`
in 15, `SubjectAccount` in 12, `TargetAccount` in 11), so leaving them empty made those rules
blind to Sluice's records. Following Microsoft's column reference: `SubjectAccount` and
`TargetAccount` as `DOMAIN\name` from the event's data, `Account` as the target account when
there is one and the subject otherwise, `AccountType` `Machine` for a name ending in `$` and
`User` otherwise. When in doubt the type is `User`, which the rules filter for, so a rule sees
more rather than less. Comparing with records the Azure Monitor Agent wrote on the same machine
is still the way to confirm the edge cases (for example which account 4798 reports).
