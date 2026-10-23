"""Bytes that are implied, per source: schema constants per kind of event, rendered text, and the
4624 placeholders Microsoft documents as implied by another field. Value-guarded: a value only
counts when it equals what is implied.

  python3 -I scripts/study/implied-bytes.py SAMPLE.ndjson sentinel|agent|sigma KIND_FIELD

The shape says how the records came: read from Sentinel's SecurityEvent, as Vector's
windows_event_log source emits them, or in Sigma's names (scripts/real-data/collect-windows.ps1).
See docs/notes/field-value.md."""
import collections
import json
import sys

ENVELOPE = {
    "sentinel": ["EventSourceName", "Channel", "Task", "Level", "EventLevelName", "Keywords",
                 "Activity", "SourceSystem", "EventOriginId", "ManagementGroupName"],
    "agent": ["provider_guid", "provider_name", "channel", "keywords", "keyword_names", "level",
              "level_value", "task", "task_name", "opcode", "version", "source_type"],
    "sigma": ["Channel", "Keywords", "Level", "Task", "Provider_Name", "Opcode", "Version"],
}
RENDERED = {"sentinel": ["EventData"], "agent": ["message"], "sigma": ["Message"]}
NOT_BILLED = {"Type"}


def member(key, value):
    return len(json.dumps({key: value})) - 1


def implied_4624(e, get):
    """Fields whose value Microsoft documents as implied by another field (event 4624)."""
    out = []
    logon_type, package = str(get(e, "LogonType")), get(e, "AuthenticationPackageName")
    if logon_type != "10" and get(e, "RestrictedAdminMode") == "-":
        out.append("RestrictedAdminMode")
    if logon_type != "9":
        out += [f for f in ("TargetOutboundUserName", "TargetOutboundDomainName") if get(e, f) == "-"]
    if package != "NTLM" and get(e, "LmPackageName") == "-":
        out.append("LmPackageName")
    if package == "Kerberos" and str(get(e, "KeyLength")) == "0":
        out.append("KeyLength")
    if get(e, "TransmittedServices") == "-":
        out.append("TransmittedServices")
    if str(get(e, "LogonGuid")).strip("{}") == "00000000-0000-0000-0000-000000000000":
        out.append("LogonGuid")
    if get(e, "TargetLinkedLogonId") == "0x0":
        out.append("TargetLinkedLogonId")
    return out


def main():
    path, shape, kind_field = sys.argv[1], sys.argv[2], sys.argv[3]
    nested = shape == "agent"
    get = (lambda e, f: e.get("event_data", {}).get(f)) if nested else (lambda e, f: e.get(f))
    events = [json.loads(l) for l in open(path, encoding="utf-8")]
    total = sum(len(json.dumps(e)) for e in events)
    by_kind = collections.defaultdict(list)
    for e in events:
        by_kind[str(e.get(kind_field))].append(e)
    constant = rendered = implied = not_billed = 0
    for kind, group in by_kind.items():
        for f in ENVELOPE[shape]:
            values = {json.dumps(e.get(f)) for e in group if f in e}
            if len(values) == 1:
                constant += sum(member(f, e[f]) for e in group if f in e)
        for f in RENDERED[shape]:
            rendered += sum(member(f, e[f]) for e in group if f in e)
        for f in NOT_BILLED:
            not_billed += sum(member(f, e[f]) for e in group if f in e)
        if kind == "4624":
            for e in group:
                for f in implied_4624(e, get):
                    implied += member(f, get(e, f))
    n4624 = sum(len(json.dumps(e)) for e in by_kind.get("4624", []))
    print(f"{path.split('/')[-2]}/{path.split('/')[-1]}: {len(events)} events, {total / 1e6:.1f} MB")
    print(f"  rendered text or XML:       {100 * rendered / total:5.1f} %")
    print(f"  schema constants per kind:  {100 * constant / total:5.1f} %")
    if shape == "sentinel":
        print(f"  of which not billed (Type): {100 * not_billed / total:5.1f} % (not counted above)")
    if n4624:
        print(f"  4624 implied placeholders:  {100 * implied / n4624:5.1f} % of 4624's bytes "
              f"({len(by_kind['4624'])} events)")


main()
