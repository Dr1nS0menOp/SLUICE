# ADR 0042: Implied values hold on every machine and every sample

- Status: Accepted
- Date: 2026-11-22

## Context

Implied values (ADR 0032) are learned from the sample: a field that holds one value on nine in
ten events of a kind, or whenever another field holds a given one. On a sample of one machine,
the machine's name, domain and agent look implied too, since nothing in the data tells them from
a value the kind of event fixes (architecture, "Implied values are learned from one sample").
Removing them stays lossless, because a value guard sends any other value. But the saving is too
high for a fleet, and the put-back step (`<Table>Full`, runtime fields) may give a value to a
record that never had the field. Until now the report only asked the reader to check such
values.

## Decision

1. **More than one sample.** `sluice analyze --input` may be given once per sample, such as one
   per machine or per day. The events of all samples are analyzed together, and each keeps the
   sample it came from. A source may be missing from some samples, but not from all.
2. **Origins.** An event's origin is its sample and the machine it names. The machine is read
   per source from the field among `Computer`, `host.name`, `host.hostname`, `agent.hostname`,
   `hostname`, `host`, `ComputerName`, `DeviceName`, `Hostname`, `dvc` and `observer.hostname`
   that has the most distinct values. OTRF's samples carry the log collector in `host` and the
   machine in `Hostname`: the first field in the list would have been the collector.
3. **A value holds in every origin.** A value is learned only where it holds, at the share it
   was learned with, in every origin that has at least 20 of the events it applies to. A value
   one machine or one day had and another lacked was that machine's or that day's.
4. **A value alike on every kind of event needs more than one machine.** Some values are the same
   on more than one kind of event of a source, and no other field implies them. Such a value is
   learned only when the source's events name more than one machine, or, naming none, come from
   more than one sample. Otherwise it is held back, sent as it is, and the report says so with
   how to learn it: a sample of more machines.

## Consequences

- On OTRF's APT29 sample (four machines) the example report still saves 78.1 %. The per-origin
  check takes back 0.2 MB of the implied values' 61.3 MB, and every alert stays the same. The demo
  (several machines) goes from 11.0 % to 10.7 % for implied values.
- A sample of one machine saves less on implied values than before, by exactly the values that
  might be its own. That is the point.
- `plan.json` is unchanged. The report gives what was held back per source.
