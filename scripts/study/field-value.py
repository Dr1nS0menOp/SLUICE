"""Per kind of event and per field: bytes, constants, fields determined by another field,
placeholders. The question: what can be removed losslessly, guarded by its value, beyond rules?

  python3 -I scripts/study/field-value.py SAMPLE.ndjson KIND_FIELD [--text]

KIND_FIELD names the field that gives the kind of event (EventID, event_id, ...). With --text,
records are syslog lines in `message`, split into host, program, pid and the rest.
Values are printed only for fields that hold no personal data (SAFE) or that are placeholders.
"""
import collections
import json
import re
import sys

PLACEHOLDERS = {"-", "", "0x0", "0", "{00000000-0000-0000-0000-000000000000}", "S-1-0-0", "%%1843",
                "%%1842", "NULL SID", "None", "null"}
SAFE = re.compile(r"^(Keywords|Level|Task|Opcode|Version|Channel|EventSourceName|Provider.*|"
                  r"provider_.*|channel|keywords|level.*|task.*|opcode|version|source_type|"
                  r"Type|EventLevel.*|EventOriginId|SourceSystem|Activity|AccessMask.*|"
                  r"LogonType|ElevatedToken|ImpersonationLevel|VirtualAccount|RestrictedAdminMode|"
                  r"KeyLength|LmPackageName|AuthenticationPackageName|LogonProcessName|"
                  r"TransmittedServices|TokenElevationType|MandatoryLabel|.*Guid|"
                  r"program|facility|event_data\.(LogonType|KeyLength|LmPackageName|"
                  r"AuthenticationPackageName|LogonProcessName|ElevatedToken|ImpersonationLevel|"
                  r"VirtualAccount|RestrictedAdminMode|TransmittedServices|TokenElevationType|"
                  r"MandatoryLabel)|EventID|event_id)$")
SYSLOG = re.compile(r"^(?P<ts>\S+\s+\d+\s+[\d:]+|\S+T\S+)\s+(?P<host>\S+)\s+"
                    r"(?P<program>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<rest>.*)$")
MIN_SUPPORT = 20      # events per determinant value before a dependency counts
MAX_DETERMINANT = 32  # distinct values a determinant may have


def flatten(record, prefix=""):
    out = {}
    for key, value in record.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(flatten(value, path + "."))
        else:
            out[path] = value if isinstance(value, str) else json.dumps(value)
    return out


def member(key, value):
    return len(json.dumps({key: value})) - 1


def show(field, value):
    if value in PLACEHOLDERS or SAFE.match(field):
        return repr(value[:40])
    return "<value>"


def load(path, kind_field, text):
    groups = collections.defaultdict(list)
    for line in open(path, encoding="utf-8"):
        record = json.loads(line)
        if text:
            m = SYSLOG.match(record.get("message", ""))
            if not m:
                continue
            fields = {k: v for k, v in m.groupdict().items() if v is not None}
            kind = fields["program"]
        else:
            fields = flatten(record)
            kind = fields.get(kind_field, "?")
        groups[kind].append(fields)
    return groups


def analyze(events):
    total = sum(member(k, v) for e in events for k, v in e.items())
    names = sorted({k for e in events for k in e})
    values = {f: [e.get(f) for e in events] for f in names}
    distinct = {f: set(v for v in vs if v is not None) for f, vs in values.items()}
    rows = []
    for f in names:
        present = [v for v in values[f] if v is not None]
        size = sum(member(f, v) for v in present)
        kind, detail = "varies", ""
        if len(distinct[f]) == 1:
            kind, detail = "constant", show(f, next(iter(distinct[f])))
        else:
            for g in names:
                if g == f or not (2 <= len(distinct[g]) <= MAX_DETERMINANT):
                    continue
                by = collections.defaultdict(set)
                count = collections.Counter()
                for e in events:
                    if f in e and g in e:
                        by[e[g]].add(e[f])
                        count[e[g]] += 1
                if by and all(len(s) == 1 for s in by.values()) \
                        and all(c >= MIN_SUPPORT for c in count.values()):
                    pairs = sorted((gv, next(iter(s))) for gv, s in by.items())
                    kind = f"follows {g}"
                    detail = ", ".join(f"{show(g, gv)}→{show(f, fv)}" for gv, fv in pairs[:4])
                    if len(pairs) > 4:
                        detail += ", …"
                    break
        placeholder = sum(1 for v in present if v in PLACEHOLDERS)
        rows.append((size, f, len(present), kind, detail, placeholder))
    return total, rows


def main():
    path, kind_field = sys.argv[1], sys.argv[2]
    text = "--text" in sys.argv
    groups = load(path, kind_field, text)
    grand = collections.Counter()
    print(f"# {path}")
    for kind, events in sorted(groups.items(), key=lambda kv: -len(kv[1]))[:8]:
        if len(events) < 100:
            continue
        total, rows = analyze(events)
        print(f"\n## kind {kind}: {len(events)} events, {total / 1e6:.2f} MB")
        print("| field | bytes % | present % | kind | detail | placeholders % |")
        print("|---|---:|---:|---|---|---:|")
        for size, f, present, k, detail, ph in sorted(rows, reverse=True)[:22]:
            print(f"| {f} | {100 * size / total:.1f} | {100 * present / len(events):.0f} | {k} | "
                  f"{detail} | {100 * ph / max(present, 1):.0f} |")
        grand["total"] += total
        for size, f, _, k, _, _ in rows:
            if k == "constant":
                grand["constant"] += size
            elif k.startswith("follows"):
                grand["follows"] += size
            if f.split(".")[-1].lower() in ("message", "renderedtext", "eventdata"):
                grand["rendered"] += size
    if grand["total"]:
        t = grand["total"]
        print(f"\n**Summary over the kinds shown:** constants {100 * grand['constant'] / t:.1f} %, "
              f"fields that follow another {100 * grand['follows'] / t:.1f} %, "
              f"rendered text or XML {100 * grand['rendered'] / t:.1f} % of the bytes.")


main()
