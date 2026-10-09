"""Compares the fields Sluice derives from Sigma rules with pySigma, the reference parser.

Usage: sigma_differential.py <requirements.json> <rules_dir>

<requirements.json> is the output of `sluice rules requirements --rules <rules_dir>`. For every
rule both parse, each field pySigma finds in the detection (including filters and nested
conditions) must be covered by a field Sluice requires, and a rule with keywords must be marked
as matching raw text. Sluice folds a correlation into the rules it references: each must be
stateful and require the group-by fields. A rule pySigma parses must be known to Sluice, or kept
opaque. Anything else would let a reduction remove data a rule reads, so it fails the run.
Sluice requiring more than pySigma finds is safe and only reported.
"""

import json
import pathlib
import sys

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaDetection, SigmaRule


def detection_fields(detection, fields, keywords):
    for item in detection.detection_items:
        if isinstance(item, SigmaDetection):
            keywords = detection_fields(item, fields, keywords)
        elif item.field is None:
            keywords = True
        else:
            fields.add(item.field)
    return keywords


def key_of(rule):
    return f"sigma:{rule.id or rule.title}"


def reference(rules_dir):
    """Rule id -> (fields, has keywords), and correlations as (id, group-by, base rule ids)."""
    found, correlations, errors = {}, [], 0
    for path in sorted(pathlib.Path(rules_dir).rglob("*.y*ml")):
        collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"), collect_errors=True)
        errors += len(collection.errors)
        for rule in collection.rules:
            key = key_of(rule)
            fields, keywords = set(), False
            if isinstance(rule, SigmaRule) and not rule.errors:
                for detection in rule.detection.detections.values():
                    keywords = detection_fields(detection, fields, keywords)
            elif isinstance(rule, SigmaCorrelationRule):
                bases = [key_of(ref.rule) for ref in rule.rules if getattr(ref, "rule", None)]
                correlations.append((key, set(rule.group_by or []), bases))
                continue
            else:
                errors += 1
                continue
            found[key] = (fields, keywords)
    return found, correlations, errors


def covered(field, required):
    return any(field == r or field.startswith(r + ".") for r in required)


def main(requirements_path, rules_dir):
    sluice = {r["rule"]: r for r in json.loads(pathlib.Path(requirements_path).read_text())}
    opaque = sum(1 for key in sluice if key.startswith("sigma:unparsed:"))
    expected, correlations, pysigma_errors = reference(rules_dir)

    unsafe, wider, compared = [], 0, 0
    for key, (fields, keywords) in sorted(expected.items()):
        rule = sluice.get(key)
        if rule is None:
            continue
        compared += 1
        if rule["fields"] == "unknown":
            continue
        required = rule["fields"]["known"]
        missing = sorted(f for f in fields if not covered(f, required))
        if missing:
            unsafe.append(f"{key}: Sluice misses fields {missing}")
        if keywords and not rule["matches_raw_text"]:
            unsafe.append(f"{key}: has keywords but is not marked as matching raw text")
        if any(not covered(r, fields) and not any(covered(f, [r]) for f in fields) for r in required):
            wider += 1

    for key, group_by, bases in correlations:
        if key in sluice:  # kept opaque by Sluice: protects everything
            continue
        if not bases:
            unsafe.append(f"{key}: correlation whose rules pySigma could not resolve")
        for base in bases:
            rule = sluice.get(base)
            if rule is None:
                unsafe.append(f"{key}: references {base}, which Sluice does not know")
                continue
            if not rule["stateful"]:
                unsafe.append(f"{key}: {base} is not marked stateful")
            if rule["fields"] != "unknown":
                missing = sorted(f for f in group_by if not covered(f, rule["fields"]["known"]))
                if missing:
                    unsafe.append(f"{key}: {base} misses group-by fields {missing}")

    only_pysigma = sorted(set(expected) - set(sluice))
    if len(only_pysigma) > opaque:
        unsafe.append(f"rules Sluice does not know at all: {only_pysigma}")
    print(f"compared {compared} rules and {len(correlations)} correlations; Sluice requires more "
          f"fields than pySigma for {wider}")
    print(f"{opaque} rules Sluice could not parse are kept opaque (they protect every field)")
    print(f"pySigma could not parse {pysigma_errors} rules")
    for problem in unsafe:
        print(f"UNSAFE {problem}")
    return 1 if unsafe else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
