"""Where the bytes of a sample go, by how much they tell: the field theory's measurements.

    python3 -I scripts/research/fields.py SAMPLE.ndjson [...] [--test LATER.ndjson [...] | --split] [--json]

For each kind of event (approximated by its EventID and its key set) and each field it measures
how far the field is determined by the kind of event, or by one or two other fields: exactly on
the sample (a functional dependency) or for the most frequent value per group (an approximate
one). A value guard removes a field only while it holds the value the rule gives, so both are
lossless; they differ in how many events they save on. The sample's bytes are split into:

- the rendered message, and whether it is a fixed text with the event's own values filled in;
- empty fields (null, "", [], {});
- what each dependency removes, per threshold of the share of events its value holds;
- rare kinds of event, which are never saved on.

With --test, the rules learned on the samples are applied to a later sample of the same systems,
to see how much of each saving lasts. Only aggregate numbers are printed, never values, so it can
run on real data. Standard library only; run it with `python3 -I` (docs/notes/field-theory.md).
"""

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict

# As Sluice's learner (crates/sluice-autopilot/src/implied.rs).
MIN_SUPPORT = 20  # events per value of an implying field
MAX_IMPLYING = 32  # distinct values a category may have
MIN_TEMPLATE = 50  # smaller kinds of event are rare: never saved on
MAX_EVENTS = 20000  # events per kind of event that are read, for time
THRESHOLDS = (1.0, 0.99, 0.95, 0.9, 0.5)
SCOPES = ("kind", "one", "two")
DISCRIMINATORS = ("EventID", "event_id", "EventCode", "winlog.event_id")
EMPTY = ("null", '""', "[]", "{}")


def is_message(path):
    name = path.rsplit(".", 1)[-1].lower()
    return name in ("message", "renderedmessage", "rendered_message")


def flatten(record, prefix=""):
    for key, value in record.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict) and value:
            yield from flatten(value, path + ".")
        else:
            yield path, value


def literal(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def size(path, value):
    """Bytes the field takes in compact JSON: `"key":value,`."""
    key = path.rsplit(".", 1)[-1]
    return len(json.dumps(key, ensure_ascii=False)) + 2 + len(
        json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )


def identifier(path):
    name = path.rsplit(".", 1)[-1]
    return any(name.endswith(s) for s in ("Id", "ID", "Guid", "GUID", "_id", "_guid"))


IP = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F]*:[0-9a-fA-F:.]*$")


def network(path, values):
    name = path.rsplit(".", 1)[-1]
    if name == "port" or name.endswith("Port") or name.endswith("_port"):
        return True
    return bool(values) and all(isinstance(v, str) and IP.match(v) for v in values)


def kind_of(record):
    event_id = next((record[d] for d in DISCRIMINATORS if d in record), None)
    return (literal(event_id), tuple(sorted(record)))


def read(paths, cap=MAX_EVENTS):
    kinds = defaultdict(list)
    for path in paths:
        with open(path, encoding="utf-8") as lines:
            for line in lines:
                if line.strip():
                    record = dict(flatten(json.loads(line)))
                    group = kinds[kind_of(record)]
                    if len(group) < cap:
                        group.append(record)
    return kinds


def closed(column):
    half = len(column) // 2
    return set(column[half:]) <= set(column[:half])


def mode_rule(column, keys):
    """Per key with MIN_SUPPORT events: the most frequent value and the share of events with it."""
    groups = defaultdict(Counter)
    for key, value in zip(keys, column):
        groups[key][value] += 1
    rule = {}
    for key, counter in groups.items():
        n = sum(counter.values())
        if n >= MIN_SUPPORT:
            value, count = counter.most_common(1)[0]
            rule[key] = (value, count / n)
    return rule


def saved_by(rule, column, sizes, keys, threshold):
    return sum(
        s
        for s, v, k in zip(sizes, column, keys)
        if k in rule and rule[k][1] >= threshold and rule[k][0] == v
    )


class Kind:
    """One kind of event: its fields and, per field, the best rule of each scope."""

    def __init__(self, events):
        self.fields = sorted(events[0])
        self.n = len(events)
        self.columns = {f: [literal(e[f]) for e in events] for f in self.fields}
        self.sizes = {f: [size(f, e[f]) for e in events] for f in self.fields}
        self.bytes = sum(sum(s) for s in self.sizes.values())
        self.message = next((f for f in self.fields if is_message(f)), None)
        self.empty = {f for f in self.fields if all(v in EMPTY for v in self.columns[f])}
        usable = [
            f
            for f in self.fields
            if f not in DISCRIMINATORS
            and f != self.message
            and f not in self.empty
            and not network(f, [e[f] for e in events])
        ]
        self.categories = [
            f
            for f in usable
            if not identifier(f)
            and 2 <= len(set(self.columns[f])) <= MAX_IMPLYING
            and closed(self.columns[f])
        ]
        # field -> scope -> threshold -> (implying fields, rule, bytes saved)
        self.rules = {f: self.learn(f) for f in usable}

    def keys(self, implying):
        if not implying:
            return [()] * self.n
        return list(zip(*(self.columns[g] for g in implying)))

    def learn(self, f):
        column, sizes = self.columns[f], self.sizes[f]
        best = {scope: {} for scope in SCOPES}
        candidates = {"kind": [()], "one": [(g,) for g in self.categories if g != f]}
        # Pairs only for fields that hold 2 % of the kind's bytes: they are slow.
        if sum(sizes) * 50 >= self.bytes:
            others = [g for g in self.categories if g != f]
            candidates["two"] = [(a, b) for i, a in enumerate(others) for b in others[i + 1 :]]
        for scope in SCOPES:
            for implying in candidates.get(scope, []):
                keys = self.keys(implying)
                rule = mode_rule(column, keys)
                for t in THRESHOLDS:
                    saved = saved_by(rule, column, sizes, keys, t)
                    if saved > best[scope].get(t, ((), {}, 0))[2]:
                        best[scope][t] = (implying, rule, saved)
        # A wider scope may always fall back to a narrower one.
        for wide, narrow in (("one", "kind"), ("two", "one")):
            for t in THRESHOLDS:
                if best[narrow].get(t, ((), {}, 0))[2] > best[wide].get(t, ((), {}, 0))[2]:
                    best[wide][t] = best[narrow][t]
        return best

    def message_determined(self, events):
        """Whether the message is a fixed text of the event's own values: with the values of the
        fields that vary from event to event (times, ids, command lines: more than half distinct)
        masked in it, events whose other fields are the same carry the same message. `None` when
        no rest repeats, so the sample cannot tell."""
        if not self.message:
            return None
        varying = [
            f
            for f in self.fields
            if f != self.message and len(set(self.columns[f])) * 2 > self.n
        ]
        steady = [f for f in self.fields if f != self.message and f not in varying]
        groups = defaultdict(set)
        for e in events:
            text = e[self.message]
            if not isinstance(text, str):
                return None
            values = sorted({str(e[f]) for f in varying if len(str(e[f])) > 1}, key=len, reverse=True)
            for v in values:
                # Windows writes a hex value in capitals in the message (`0x5B65FF` for `0x5b65ff`).
                text = re.sub(re.escape(v), "\x00", text, flags=re.IGNORECASE)
            groups[tuple(literal(e[f]) for f in steady)].add(text)
        if all(len(g) == 1 for g in groups.values()) and len(groups) < self.n:
            return True
        return False

def analyse(kinds):
    total = Counter()
    saved = Counter()
    message = Counter()
    learned = {}
    for key, events in kinds.items():
        if not events:
            continue
        kind = Kind(events)
        total["bytes"] += kind.bytes
        total["events"] += kind.n
        if kind.n < MIN_TEMPLATE:
            total["rare"] += kind.bytes
            continue
        learned[key] = kind
        total["empty"] += sum(sum(kind.sizes[f]) for f in kind.empty)
        if kind.message:
            m = sum(kind.sizes[kind.message])
            message["bytes"] += m
            if kind.message_determined(events):
                message["template"] += m
        for best in kind.rules.values():
            for scope in SCOPES:
                for t, (_, _, b) in best[scope].items():
                    saved[(scope, t)] += b
    return total, saved, message, learned


def transfer(learned, kinds):
    """Bytes the learned rules save on a later sample, per scope and threshold."""
    total, saved = 0, Counter()
    for key, events in kinds.items():
        bytes_ = sum(size(f, v) for e in events for f, v in e.items())
        total += bytes_
        kind = learned.get(key)
        if not kind:
            continue
        columns = {f: [literal(e[f]) for e in events] for f in kind.rules}
        for f, best in kind.rules.items():
            sizes = [size(f, e[f]) for e in events]
            for scope in SCOPES:
                for t, (implying, rule, _) in best[scope].items():
                    keys = (
                        list(zip(*(columns[g] if g in columns else [literal(e[g]) for e in events]
                                   for g in implying)))
                        if implying
                        else [()] * len(events)
                    )
                    saved[(scope, t)] += saved_by(rule, columns[f], sizes, keys, t)
    return total, saved


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("samples", nargs="+")
    parser.add_argument("--test", nargs="+", default=[])
    parser.add_argument("--split", action="store_true", help="learn on the first half of each kind of event, test on the second")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    kinds = read(args.samples, cap=2 * MAX_EVENTS if args.split else MAX_EVENTS)
    later = None
    if args.split:
        later = {k: v[len(v) // 2 :] for k, v in kinds.items()}
        kinds = {k: v[: len(v) // 2] for k, v in kinds.items()}
    total, saved, message, learned = analyse(kinds)
    result = {
        "events": total["events"],
        "bytes": total["bytes"],
        "rare": total["rare"],
        "empty": total["empty"],
        "message": dict(message),
        "saved": {f"{s}@{t}": b for (s, t), b in sorted(saved.items())},
    }
    if args.test:
        later = read(args.test, cap=50000)
    if later is not None:
        test_total, test_saved = transfer(learned, later)
        result["test"] = {"bytes": test_total, "saved": {f"{s}@{t}": b for (s, t), b in sorted(test_saved.items())}}
    if args.json:
        print(json.dumps(result, indent=1))
        return
    b = total["bytes"]
    pct = lambda x, of=b: f"{100 * x / of:5.1f} %" if of else "    -"
    print(f"{total['events']:,} events, {len(learned)} frequent kinds of event, {b / 1e6:.1f} MB")
    print(f"  rendered message   {pct(message['bytes'])}, of which provably a fixed text of the event's values {pct(message['template'])}")
    print(f"  empty fields       {pct(total['empty'])}")
    print(f"  rare kinds         {pct(total['rare'])}")
    print("  implied (lossless with a value guard), by scope, for rules whose value holds on at least:")
    for t in THRESHOLDS:
        cells = "  ".join(f"{s} {pct(saved.get((s, t), 0))}" for s in SCOPES)
        tail = ""
        if later is not None:
            cells_later = "  ".join(
                f"{s} {pct(test_saved.get((s, t), 0), test_total)}" for s in SCOPES
            )
            tail = f"   | later sample: {cells_later}"
        print(f"    {t:4.0%}  {cells}{tail}")


if __name__ == "__main__":
    sys.exit(main())
