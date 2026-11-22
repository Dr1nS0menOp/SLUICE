# Parser packs in VRL and in the proof

Facts verified while building parser packs (ADR 0043), with `vrl` 0.36.0 (Vector 0.59.0) and
the `regex` crate both sides use.

- **VRL types a literal regex's named groups.** `x, err = parse_regex(line, r'(?P<a>…)')` gives
  `x` an object type with a string field `a`. A test that then calls `to_string!(x.a)` fails to
  compile without warnings ("can't abort infallible function"). Sluice puts the parsed fields
  through JSON once (`object(parse_json!(encode_json({…}))) ?? {}`), so VRL types them as
  anything, as it types an event's fields. The tests written for event fields then apply
  unchanged.
- **An empty `else {}` is a syntax error in VRL.** The chain of patterns is built from the last
  one back, so the last has no `else`.
- **A group that took no part in the match.** In Rust's `regex`, `captures.name(group)` is
  `None`; Sluice gives no field then. In VRL the value is `null` after the JSON round trip, and a
  test on a missing parsed field is true (fail closed): the line is kept.
- **A quote in a pattern.** VRL regex literals are delimited by `'`. Sluice writes a quote as
  `\x27` (`syntax::regex`) and refuses a pack whose pattern contains `\'`.
- **nginx and Apache write the same `combined` line.** Only the envelope tells them apart
  (`log.file.path: /var/log/nginx/access.log`), so `sluice init` looks there on a tie.
- **OTRF's samples** carry the log collector's address in `host` and the machine in `Hostname`.
  The machine of an event is read from the host field with the most distinct values (ADR 0042).
