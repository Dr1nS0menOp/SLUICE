//! Painless syntax: literals, and the helper functions every generated script starts with.

use sluice_core::field::FieldPath;
use sluice_core::recipe::Literal;

/// A Painless string literal. Inside single quotes only a backslash and a quote are escaped;
/// every other character, a line break included, stands for itself.
pub(crate) fn string(text: &str) -> String {
    format!("'{}'", text.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// A list literal of the path's segments, as `sluiceGet` and `sluiceRemove` take them.
pub(crate) fn segments(path: &FieldPath) -> String {
    list(path.segments())
}

/// A list literal of strings.
pub(crate) fn list<'a>(items: impl IntoIterator<Item = &'a str>) -> String {
    let items: Vec<String> = items.into_iter().map(string).collect();
    format!("[{}]", items.join(", "))
}

/// The functions a generated script calls. Painless functions come before the first statement
/// and cannot see `ctx`, so it is passed in.
///
/// - `sluiceMeta(k)`: whether a top-level key of `ctx` is Elasticsearch's metadata, not a field.
/// - `sluiceLeaves(v, p, out)`: the leaf paths below `v`, as VRL's `flatten` makes them: nested
///   objects joined with `.`, arrays and scalars (null included) as leaves, empty objects absent.
/// - `sluiceGet(root, segments)`: the value at a path, or null when a step is not an object.
/// - `sluiceHas(root, segments)`: whether the path is there, its value null or not, as VRL's
///   `exists`.
/// - `sluiceDisc(v)`: a discriminator's text, as `to_string(v) ?? ""` renders it in VRL; null
///   for a float that is not a whole number below 10^15, whose text may differ, so it matches
///   no recorded value and the document is not recognised.
/// - `sluiceMay(v, s)`: whether VRL may render `v` as `s`: it does, or Painless cannot know.
/// - `sluiceAscii(s)`: whether `s` is ASCII, where Java and Rust fold case alike.
/// - `sluiceTest(v, op, cs, floats, values)`: a field test, as in VRL: true on an object, on a
///   float when `floats` (a value could be a number's text), false on null; an array when a
///   member is (a nested object or array is true); otherwise the value's text against the
///   values (`op`: 0 equals, 1 contains, 2 starts with, 3 ends with). Case-insensitive tests on
///   non-ASCII text are true. Case-insensitive values come lowercased.
/// - `sluiceWords(v, cs, floats, values)`: Sigma keywords over every leaf value below `v`:
///   strings and integers are searched, an array's members too (a nested object or array is
///   true), floats when `floats`, booleans and nulls never match. `sluiceDocWords(ctx, cs,
///   floats, values)` does so for the document, metadata left out.
/// - `sluiceKeys(ctx)`: the document's leaf paths, metadata left out.
/// - `sluiceRemove(root, segments)` and `sluiceRemoveEmpty(root, segments)`: VRL's `del`, and
///   `del` of a null or empty-string value.
/// - `sluiceRemoveEmptyExcept(ctx, keys, keep, drop)`: `sluiceRemoveEmpty` on each of `keys`
///   that is not in `drop` and neither covers nor is covered by a path in `keep`.
/// - `sluiceIsInt(v, i)`: whether `v` is the whole number `i`, as an `Integer` or a `Long`.
pub(crate) const FUNCTIONS: &str = r"boolean sluiceMeta(String k) {
  return k == '_index' || k == '_id' || k == '_version' || k == '_routing' || k == '_version_type' || k == '_if_seq_no' || k == '_if_primary_term' || k == '_dynamic_templates' || k == '_type' || k == '_ingest';
}
void sluiceLeaves(def v, String p, Set out) {
  if (v instanceof Map) {
    for (def e : ((Map) v).entrySet()) { sluiceLeaves(e.getValue(), p + '.' + e.getKey(), out); }
  } else {
    out.add(p);
  }
}
def sluiceGet(def root, List path) {
  def v = root;
  for (def s : path) {
    if (!(v instanceof Map)) { return null; }
    v = ((Map) v).get(s);
  }
  return v;
}
boolean sluiceHas(def root, List path) {
  def v = root;
  for (int i = 0; i < path.size() - 1; ++i) {
    if (!(v instanceof Map)) { return false; }
    v = ((Map) v).get(path.get(i));
  }
  return v instanceof Map && ((Map) v).containsKey(path.get(path.size() - 1));
}
String sluiceDisc(def v) {
  if (v == null || v instanceof Map || v instanceof List) { return ''; }
  if (v instanceof String) { return (String) v; }
  if (v instanceof Double || v instanceof Float) {
    double d = ((Number) v).doubleValue();
    if (d != 0.0 && Math.abs(d) < 1e15 && d == Math.floor(d)) { return String.valueOf((long) d); }
    return null;
  }
  return String.valueOf(v);
}
boolean sluiceMay(def v, String s) {
  String d = sluiceDisc(v);
  return d == null || d == s;
}
boolean sluiceAscii(String s) {
  for (int i = 0; i < s.length(); ++i) { if (s.charAt(i) > 127) { return false; } }
  return true;
}
boolean sluiceMatch(String s, int op, boolean cs, List values) {
  if (!cs) {
    if (!sluiceAscii(s)) { return true; }
    s = s.toLowerCase(Locale.ROOT);
  }
  for (def w : values) {
    if (op == 0 && s == w) { return true; }
    if (op == 1 && s.contains(w)) { return true; }
    if (op == 2 && s.startsWith(w)) { return true; }
    if (op == 3 && s.endsWith(w)) { return true; }
  }
  return false;
}
boolean sluiceTest(def v, int op, boolean cs, boolean floats, List values) {
  if (v == null) { return false; }
  if (v instanceof Map) { return true; }
  if (v instanceof Double || v instanceof Float) { return floats; }
  if (v instanceof List) {
    for (def m : (List) v) {
      if (m == null) { continue; }
      if (m instanceof Map || m instanceof List) { return true; }
      if (m instanceof Double || m instanceof Float) {
        if (floats) { return true; }
        continue;
      }
      if (sluiceMatch(String.valueOf(m), op, cs, values)) { return true; }
    }
    return false;
  }
  return sluiceMatch(String.valueOf(v), op, cs, values);
}
boolean sluiceWord(def v, boolean cs, boolean floats, List values) {
  if (v instanceof Double || v instanceof Float) { return floats; }
  if (v instanceof String || v instanceof Integer || v instanceof Long) { return sluiceMatch(String.valueOf(v), 1, cs, values); }
  return false;
}
boolean sluiceWords(def v, boolean cs, boolean floats, List values) {
  if (v instanceof Map) {
    for (def e : ((Map) v).entrySet()) {
      if (sluiceWords(e.getValue(), cs, floats, values)) { return true; }
    }
    return false;
  }
  if (v instanceof List) {
    for (def m : (List) v) {
      if (m instanceof Map || m instanceof List) { return true; }
      if (sluiceWord(m, cs, floats, values)) { return true; }
    }
    return false;
  }
  return sluiceWord(v, cs, floats, values);
}
boolean sluiceDocWords(Map doc, boolean cs, boolean floats, List values) {
  for (def e : doc.entrySet()) {
    if (!sluiceMeta(e.getKey()) && sluiceWords(e.getValue(), cs, floats, values)) { return true; }
  }
  return false;
}
Set sluiceKeys(Map doc) {
  Set out = new HashSet();
  for (def e : doc.entrySet()) {
    if (!sluiceMeta(e.getKey())) { sluiceLeaves(e.getValue(), e.getKey(), out); }
  }
  return out;
}
void sluiceRemove(def root, List path) {
  def v = root;
  for (int i = 0; i < path.size() - 1; ++i) {
    if (!(v instanceof Map)) { return; }
    v = ((Map) v).get(path.get(i));
  }
  if (v instanceof Map) { ((Map) v).remove(path.get(path.size() - 1)); }
}
void sluiceRemoveEmpty(def root, List path) {
  def v = sluiceGet(root, path);
  if (v == null || v == '') { sluiceRemove(root, path); }
}
void sluiceRemoveEmptyExcept(Map doc, Set keys, List keep, List drop) {
  for (def p : keys) {
    boolean kept = drop.contains(p);
    for (def e : keep) {
      if (p == e || p.startsWith(e + '.') || e.startsWith(p + '.')) { kept = true; }
    }
    if (!kept) { sluiceRemoveEmpty(doc, Arrays.asList(p.splitOnToken('.'))); }
  }
}
boolean sluiceIsInt(def v, long i) {
  return (v instanceof Integer || v instanceof Long) && ((Number) v).longValue() == i;
}
";

/// A test that the value at `path` is `value`, of its type: a string equals only a string, an
/// integer only an integer (`sluiceIsInt`), as VRL's `==` compares them.
pub(crate) fn equals(path: &FieldPath, value: &Literal) -> String {
    let at = format!("sluiceGet(ctx, {})", segments(path));
    match value {
        Literal::Text(text) => format!("({at} instanceof String && {at} == {})", string(text)),
        Literal::Integer(i) => format!("sluiceIsInt({at}, {i}L)"),
        Literal::Bool(b) => format!("({at} instanceof Boolean && {at} == {b})"),
    }
}
