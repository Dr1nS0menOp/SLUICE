# Field theory: when a byte may go, and what keeps its value

Study of 2026-10-30, branch `study/theory`. The question: can the theory say *why* Sluice may send
something less, and does it show where the algorithm saves too little? The aim is a SIEM that
costs less and loses nothing: every detection the same, and every event still there to search,
in the expensive table or in a cheaper one.

The measurements are from `scripts/research/fields.py` (standard library Python, aggregates only)
on OTRF's APT29 (day 1 and day 2, four machines), OTRF's APT3 (a second network) and this
project's own Windows and Linux samples, and from `sluice analyze` itself. Prices are from the
Azure Retail Prices API (`prices.azure.com`, West Europe, 2026-10-30).

## Three guarantees

Write an event as a record `e` of fields, a rule `r` as a function from the events to its alerts,
and what Sluice sends as `T(e)`. Sluice may make three promises, and each byte it saves rests on
one of them.

### 1. The detections are the same (sufficiency)

Each rule reads a set of fields `F(r)` and could match only events in its pre-filter `P(r)`, a
superset of the events it matches (`RuleRequirements`). The guardrails keep `F(r)` on every event
in `P(r)`, and keep events of a stateful rule's pre-filter whole.

*Claim.* If `T(e)` agrees with `e` on `F(r)` for every `e` in `P(r)`, and `T` sends every event in
`P(r)`, then `r(T(E)) = r(E)` for every sample `E`.

*Why.* `r` decides each event from the fields it reads, so on `P(r)` it sees the same values. Off
`P(r)` it matched nothing before; it could match something after only if removing a field made
an event match (a test for a field's absence). That is the one case the claim does not cover,
which is why Sluice also runs the rules on the full and the forwarded sample (the proof, contract
rule 5) instead of trusting the claim alone. In statistics this is *sufficiency*: what is sent is
a sufficient statistic of the data for the rules.

### 2. Nothing is lost (reconstruction)

A field `X` is *implied* by fields `Y` (possibly none: the kind of event alone) when a rule
`v = f(y)` gives its value. Sluice removes `X` only from an event where `X = f(Y)` holds (the
*value guard*), and puts `f(Y)` back where `X` is missing (`plan.json`, `<Table>Full`, the
Elasticsearch runtime fields).

*Claim.* For every event `e` of a kind whose every key set has `X`, putting back gives `e` again:
`R(T(e)) = e`. This holds whatever `f` is.

*Why.* Two cases. `X = f(Y)`: `X` is removed and `f(Y)` put back, the same value. `X ≠ f(Y)`: `X`
is not removed and nothing is put back. `Y` is never removed while it implies something, so `f(Y)`
can be computed. And `X` is in every key set of the kind, so a missing `X` can only mean it was
removed: no event arrives without it that `R` would wrongly fill in.

*What follows.* Being lossless does not depend on the dependency holding, on the sample or later.
How often it holds only says how much is saved. So an **approximate** dependency (the value holds
on most events with that `Y`) is exactly as safe as an exact one. In database terms an implied
value is a functional dependency `Y → X` (approximate ones as in Kivinen and Mannila, 1995, and
TANE, Huhtala et al., 1999), and removing it is normalisation: the dependent value is stored once,
in the plan, instead of in every row. In information-theoretic terms, `X` carries no information
given `Y` (`H(X | Y) = 0`) on the events where it is removed.

The rendered `Message` of a Windows event is the strongest case: Windows builds it from the
event's message template and the event's own values (Microsoft's event reference documents every
template). If that holds, `H(Message | the other fields) = 0`, and `Message` can always be looked
up again.

### 3. The value stays (tiers)

A SIEM bills by the table a byte lands in. Microsoft Sentinel, West Europe, 2026-10-30:

| Plan | Per GB in | What it is for |
|---|---:|---|
| Analytics | $5.59 | Analytics rules, fast queries, 90 days included |
| Basic | $1.15 (+ queries) | Searching, no analytics rules |
| Auxiliary / data lake | $0.065 + $0.13 processing (+ $0.024 per GB per month) | Searching and jobs, slower, cheap |

A byte moved from Analytics to the data lake costs about **3.5 %** of what it cost, and stays
searchable. So the cheapest arrangement that keeps both guarantees is: the analytics table holds
exactly what the rules need (guarantee 1), and a cheap table holds everything whole (guarantee 2
for the rest, and contract rule 2: everything is archived first). Sluice's data collection rule
already has that second flow into an Auxiliary table (ADR 0013). What it did not do yet was keep
out of the analytics table the events *no rule could match*: those it counted in Vector, which a
data collection rule cannot do, so in Sentinel they were sent in full.

## Measurements

### Where the bytes go

`fields.py`, per kind of event (EventID and key set), with Sluice's learner's limits: 2 to 32
values for an implying field, 20 events per value, no identifier or network field, and kinds of
fewer than 50 events left alone. "Implied" counts what a value guard would remove; the columns
say on what share of its events a rule's value must hold.

| Sample | Message | of it, provably the event's values in a fixed text | Implied, exact | at ≥ 99 % | at ≥ 90 % | at ≥ 50 % |
|---|---:|---:|---:|---:|---:|---:|
| APT29 day 1, Security (41,002 events) | 36.4 % | 29.5 % | 28.4 % | 30.9 % | 33.0 % | 40.1 % |
| APT29 day 1, Sysmon (83,230) | 32.5 % | 23.3 % | 27.4 % | 27.6 % | 30.8 % | 33.5 % |
| APT3, Sysmon (33,168, first half) | 33.9 % | 32.5 % | 29.1 % | 30.2 % | 32.1 % | 35.5 % |
| Windows PC, System (20,000) | 32.2 % | 29.5 % | 39.7 % | 39.7 % | 40.2 % | 42.2 % |
| Windows PC, Application (20,000) | 44.4 % | 1.7 % | 18.0 % | 22.4 % | 22.9 % | 25.8 % |
| Windows PC, PowerShell (other) | 18.8 % | 18.8 % | 49.2 % | 49.2 % | 49.2 % | 49.2 % |
| Linux `auth.log`, `syslog` | 100 % (the line) | 0 % | 0 % | 0 % | 0 % | 0 % |

"Implied" is the best of the kind of event alone and one other field; two other fields add at
most 0.1 point anywhere, so Sluice's learner does not need them. "Provably the event's values in
a fixed text" means: with the values of the fields that vary from event to event masked in the
message (ignoring case, since Windows writes hex in capitals), events whose other fields agree
carry the same message. It is a lower bound; Application's messages are written by each program
and are mostly free text.

### Does it last?

The rules learned on APT29 day 1, applied to day 2 (the same four machines, the next day's
attack); APT3 and the PC learned on the first half and applied to the second:

| Sample | exact | ≥ 99 % | ≥ 90 % | ≥ 50 % |
|---|---:|---:|---:|---:|
| APT29 Security, day 1 → day 2 | 29.7 % | 31.2 % | 34.0 % | 36.8 % |
| APT29 Sysmon, day 1 → day 2 | 24.5 % | 24.8 % | 25.8 % | 26.9 % |
| APT3 Sysmon, first → second half | 30.4 % | 31.1 % | 32.8 % | 35.4 % |
| APT3 Security, first → second half | 33.9 % | 34.6 % | 40.2 % | 43.5 % |
| Windows PC System, first → second half | 31.9 % | 31.9 % | 32.5 % | 33.5 % |
| Windows PC Application, first → second half | 24.0 % | 24.0 % | 25.0 % | 25.8 % |

Each approximate rule saves at least as much later as the exact one, and nothing it saves is lost
(guarantee 2). Nine in ten keeps most of the gain and loses little of it the next day; at one in
two the sample promises more than the next day keeps (APT29 Security: 40.1 % → 36.8 %).

## What changes in Sluice

1. **Values that hold on nine in ten events are implied** (`MIN_SHARE_TENTHS`), by the kind of
   event or by another field, instead of only values that hold on every event. Lossless by
   guarantee 2; the threshold is the one that kept most of its saving on the next day. ADR 0032 is
   updated.
2. **In Sentinel, events no rule could match stay out of the analytics table** (ADR 0036): where
   Vector counts them, the data collection rule now leaves them out of the table's flow with
   `where`, and the archive flow next to it keeps them whole in the Auxiliary table. The proof
   accepts a record kept out only if Vector counts it too, and compares the Sentinel rules' alerts
   over every stored record with those over what is left. Tested in the Kusto emulator; not yet
   seen on real data, since none of the Sentinel-shaped samples at hand has kinds of event Sluice
   counts (ADR 0036).
3. **`Message`** stays a recipe's removal, now with the measurement behind the reasoning:
   of its bytes, 92 % on the PC's System log, 81 % on APT29's Security and 72 % on its Sysmon log
   are provably a fixed text of values the event still carries; the rest is what the test cannot
   show (values Windows renders differently, such as `%%1842` as "Yes"), not proof of the
   opposite.

Measured with `sluice analyze` after the change, every alert the same:

| Sample and rules | Before | After |
|---|---:|---:|
| APT29 day 1, the example rules | 77.3 % | 78.3 % |
| APT29 day 1, all of SigmaHQ | 57.6 % | 59.7 % |
| APT29 day 2 Security / Sysmon, all of SigmaHQ | 62.1 % / 57.1 % | 64.8 % / 57.6 % |
| APT3, the example rules | 69.7 % | 73.3 % |
| APT3, all of SigmaHQ | 24.7 % | 28.4 % |
| Windows PC, all of SigmaHQ | 42.3 % | 43.4 % |
| Sentinel `SecurityEvent` (test workspace), Windows Security Events solution | 33.4 % | 36.2 % |
| `sluice demo --scale 100` (synthetic, exact by construction) | 78.5 % | 78.5 % |

### What keeping everything costs

OTRF APT29 day 1 with the example rules, priced in Sentinel's table plans per month at the
sample's rate (`scripts/research/tiers.py`):

| Arrangement | A month | Less than all in Analytics |
|---|---:|---:|
| Everything in the analytics table | $2,615 | |
| Sluice's plan (Vector), analytics table only | $572 | 78.1 % |
| The same, and every event whole in the data lake | $674 | 74.2 % |
| Routing (ADR 0036), and every event whole in the data lake | $636 | 75.7 % |

Keeping every event searchable costs 2 to 4 points of the saving: the price of guarantee 3 is
small because the lake costs 3.5 % of the analytics table.

## Limits

- The kind of event here is an approximation of Sluice's templates (EventID and key set); Sluice
  discovers its own, so its numbers differ a little.
- The measurements leave out the rules: a field a rule reads stays on the events it could match,
  so Sluice saves less than "Implied" on a sample with many rules.
- Prices change and differ per region and per commitment tier; the ratio between the plans is
  what the argument uses.
- An event kept out of the analytics table is searched in the archive: slower, and charged per GB
  scanned ($0.0065). Rules never need it, by guarantee 1; people investigating do.

## Sources

- Kivinen, J. and Mannila, H. (1995). *Approximate inference of functional dependencies from
  relations.* Theoretical Computer Science 149(1).
- Huhtala, Y., Kärkkäinen, J., Porkka, P. and Toivonen, H. (1999). *TANE: An efficient algorithm
  for discovering functional and approximate dependencies.* The Computer Journal 42(2).
- Shannon, C. E. (1948). *A Mathematical Theory of Communication* (conditional entropy).
- Fisher, R. A. (1922). *On the mathematical foundations of theoretical statistics* (sufficiency).
- Azure Retail Prices API, `https://prices.azure.com/api/retail/prices`, services Sentinel and
  Azure Monitor, West Europe.
- Microsoft, *Azure Monitor Logs table plans* (Analytics, Basic, Auxiliary).
