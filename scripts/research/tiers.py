"""What a savings plan costs in Microsoft Sentinel's table plans: the field theory's tier model.

    python3 -I scripts/research/tiers.py PLAN.json [--hot 5.59] [--lake 0.195] [--days 30]

Prices per GB in (defaults: West Europe, 2026-10-30, Azure Retail Prices API: Analytics $5.59,
the data lake's ingestion and processing $0.065 + $0.13) and the lake's storage per GB per month
($0.024). Compares, for the sample's volume scaled to one day:

- everything in the analytics table;
- Sluice's plan with Vector: what it sends in the analytics table, summary records included;
- the same, plus every event whole in the lake (the archive flow, contract rule 2);
- routing (ADR 0036): the analytics table gets only the kinds of event it sends and the events of
  counting kinds no rule could match stay in the lake alone, with their removals; no summaries.

The sample's duration is taken from --sample-hours (default 1).
"""

import argparse
import json


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("plan")
    p.add_argument("--hot", type=float, default=5.59)
    p.add_argument("--lake", type=float, default=0.065 + 0.13)
    p.add_argument("--storage", type=float, default=0.024)
    p.add_argument("--sample-hours", type=float, default=1.0)
    a = p.parse_args()
    plan = json.load(open(a.plan, encoding="utf-8"))
    per_day = 24 / a.sample_hours / 1e9  # bytes in the sample -> GB per day
    total_in = plan["total"]["bytes_in"]
    total_out = plan["total"]["bytes_out"]
    counted_in = counted_out = 0
    for source in plan["sources"]:
        for t in source["templates"]:
            if "count_instead" in t:
                counted_in += t["volume"]["bytes_in"]
                counted_out += t["volume"]["bytes_out"]
    # Routing: counting kinds send only what a rule could match. Their bytes out minus the summary
    # records is what Vector forwards of them; approximate it by their share of forwarded events.
    forwarded_share = 0.0
    events = summarized = 0
    for source in plan["sources"]:
        for t in source["templates"]:
            if "count_instead" in t:
                events += t["volume"]["events"]
                summarized += t["volume"]["summarized"]
    forwarded_share = (events - summarized) / events if events else 0
    routed_hot = total_out - counted_out + counted_in * forwarded_share
    rows = [
        ("everything in Analytics", total_in, 0),
        ("Sluice (Vector), Analytics only", total_out, 0),
        ("Sluice (Vector) + every event whole in the lake", total_out, total_in),
        ("routing: Analytics + every event whole in the lake", routed_hot, total_in),
    ]
    print(f"sample: {total_in / 1e6:.1f} MB in, scaled to {total_in * per_day:.2f} GB a day")
    base = total_in * per_day * a.hot * 30
    for name, hot, lake in rows:
        month = (hot * per_day * a.hot + lake * per_day * a.lake) * 30 + lake * per_day * 30 * a.storage
        print(f"  {name:52s} ${month:10,.0f} a month  ({100 * (1 - month / base):5.1f} % less)")


if __name__ == "__main__":
    main()
