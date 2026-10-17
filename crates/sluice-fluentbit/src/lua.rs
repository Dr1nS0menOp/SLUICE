//! Lua syntax: literals, and the helper functions every generated filter starts with.
//!
//! Fluent Bit's Lua filter (`LuaJIT`, Lua 5.1) sees a record as Lua values: a string, a number
//! (integers and floats alike), a boolean, `flb_null` for a JSON null (with `enable_flb_null`), or
//! a table, for objects and arrays alike. The helpers keep the meaning of the VRL compilation
//! where Lua can tell, and widen where it cannot: an integral number may be a float, an empty
//! table may be an object or an array.

use std::fmt::Write as _;

use sluice_core::field::FieldPath;

/// A Lua string literal. Every byte outside printable ASCII, and `"` and `\`, is a decimal
/// escape, so the literal is the exact bytes of `text` whatever they are.
pub(crate) fn string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for byte in text.bytes() {
        match byte {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(char::from(byte));
            }
            0x20..=0x7e => out.push(char::from(byte)),
            _ => {
                let _ = write!(out, "\\{byte}");
            }
        }
    }
    out.push('"');
    out
}

/// A list literal of the path's segments, as `sluice_get` and `sluice_remove` take them.
pub(crate) fn segments(path: &FieldPath) -> String {
    list(path.segments())
}

/// A list literal of strings.
pub(crate) fn list<'a>(items: impl IntoIterator<Item = &'a str>) -> String {
    let items: Vec<String> = items.into_iter().map(string).collect();
    format!("{{{}}}", items.join(", "))
}

/// A set literal (`{["a"] = true}`) of strings.
pub(crate) fn set<'a>(items: impl IntoIterator<Item = &'a str>) -> String {
    let items: Vec<String> = items
        .into_iter()
        .map(|item| format!("[{}] = true", string(item)))
        .collect();
    format!("{{{}}}", items.join(", "))
}

/// The functions a generated filter calls, all local to its chunk.
///
/// - `sluice_null(v)`: whether `v` is a JSON null (`nil` or `flb_null`).
/// - `sluice_kind(t)`: of a table, `"map"`, `"array"` (keys `1..n`) or `"empty"`.
/// - `sluice_keys(r)`: the record's leaf paths as a set, as VRL's `flatten` makes them (nested
///   objects joined with `.`, arrays and scalars as leaves), and their number; `nil` when an
///   empty table makes them unknown (an empty object is no leaf, an empty array is one).
/// - `sluice_is(keys, n, set, m)`: whether the `n` keys are exactly the `m` of `set`.
/// - `sluice_get(r, path)`, `sluice_has(r, path)`: the value at a path, and whether it is there
///   (null or not, as VRL's `exists`).
/// - `sluice_disc(v)`: a discriminator's text, as VRL renders it; `nil` where Lua cannot know
///   it (a number that is not a whole one below 10^15, or zero), so the record is not
///   recognised.
/// - `sluice_test(v, op, cs, floats, values)`: a field test, as in VRL: true on an object or an
///   empty table, on a fractional number when `floats`, false on null; an array when a member
///   is; otherwise the value's text against the values (`op`: 0 equals, 1 contains, 2 starts
///   with, 3 ends with). A whole number is compared as an integer and, when `floats`, is true
///   too: it may have been a float. Case-insensitive tests on non-ASCII text are true.
/// - `sluice_words(v, cs, floats, values)`, `sluice_doc_words(r, ...)`: Sigma keywords over
///   every leaf value below `v`, or of the record.
/// - `sluice_safe(v)`: whether every number below `v` comes back from Lua as it was: not past
///   2^53, not `-0`, not NaN or infinite. A record that is not safe is never changed.
/// - `sluice_remove(r, path)`, `sluice_remove_empty(r, path)`: VRL's `del`, and `del` of a null
///   or empty-string value; each says whether it removed something.
/// - `sluice_remove_empty_except(r, keys, keep, drop)`: `sluice_remove_empty` on each of `keys`
///   that is not in `drop` and neither covers nor is covered by a path in `keep`.
pub(crate) const FUNCTIONS: &str = r#"local sluice_flb_null = flb_null
local function sluice_null(v)
  return v == nil or (sluice_flb_null ~= nil and v == sluice_flb_null)
end
local function sluice_kind(t)
  local n = 0
  for k in pairs(t) do
    if type(k) ~= "number" then return "map" end
    n = n + 1
  end
  if n == 0 then return "empty" end
  for i = 1, n do if t[i] == nil then return "map" end end
  return "array"
end
local function sluice_leaves(v, p, out)
  if type(v) == "table" and not sluice_null(v) then
    local kind = sluice_kind(v)
    if kind == "empty" then return false end
    if kind == "map" then
      for k, m in pairs(v) do
        if not sluice_leaves(m, p .. "." .. k, out) then return false end
      end
      return true
    end
  end
  out[p] = true
  return true
end
local function sluice_keys(r)
  local out, n = {}, 0
  for k, v in pairs(r) do
    if type(k) ~= "string" then return nil, 0 end
    if not sluice_leaves(v, k, out) then return nil, 0 end
  end
  for _ in pairs(out) do n = n + 1 end
  return out, n
end
local function sluice_is(keys, n, set, m)
  if n ~= m then return false end
  for k in pairs(set) do if not keys[k] then return false end end
  return true
end
local function sluice_get(r, path)
  local v = r
  for i = 1, #path do
    if type(v) ~= "table" then return nil end
    v = v[path[i]]
  end
  return v
end
local function sluice_has(r, path)
  local v = r
  for i = 1, #path - 1 do
    if type(v) ~= "table" then return false end
    v = v[path[i]]
  end
  return type(v) == "table" and v[path[#path]] ~= nil
end
local function sluice_whole(v)
  return v == v and v ~= math.huge and v ~= -math.huge and v == math.floor(v)
end
local function sluice_disc(v)
  if sluice_null(v) or type(v) == "table" then return "" end
  if type(v) == "string" then return v end
  if type(v) == "boolean" then return tostring(v) end
  if type(v) == "number" and v ~= 0 and math.abs(v) < 1e15 and sluice_whole(v) then
    return string.format("%d", v)
  end
  return nil
end
local function sluice_match(s, op, cs, values)
  if not cs then
    if s:find("[\128-\255]") then return true end
    s = s:lower()
  end
  for _, w in ipairs(values) do
    if op == 0 and s == w then return true end
    if op == 1 and s:find(w, 1, true) then return true end
    if op == 2 and s:sub(1, #w) == w then return true end
    if op == 3 and (#w == 0 or s:sub(-#w) == w) then return true end
  end
  return false
end
local function sluice_scalar(v, op, cs, floats, values)
  local t = type(v)
  if t == "number" then
    if not sluice_whole(v) then return floats end
    if floats or math.abs(v) >= 2^53 then return true end
    return sluice_match(string.format("%d", v), op, cs, values)
  end
  if t == "boolean" then return sluice_match(tostring(v), op, cs, values) end
  if t == "string" then return sluice_match(v, op, cs, values) end
  return true
end
local function sluice_test(v, op, cs, floats, values)
  if sluice_null(v) then return false end
  if type(v) == "table" then
    if sluice_kind(v) ~= "array" then return true end
    for _, m in ipairs(v) do
      if not sluice_null(m) then
        if type(m) == "table" then return true end
        if sluice_scalar(m, op, cs, floats, values) then return true end
      end
    end
    return false
  end
  return sluice_scalar(v, op, cs, floats, values)
end
local function sluice_word(v, cs, floats, values)
  local t = type(v)
  if t == "number" then
    if not sluice_whole(v) then return floats end
    if floats or math.abs(v) >= 2^53 then return true end
    return sluice_match(string.format("%d", v), 1, cs, values)
  end
  if t == "string" then return sluice_match(v, 1, cs, values) end
  return false
end
local function sluice_words(v, cs, floats, values)
  if type(v) == "table" and not sluice_null(v) then
    local kind = sluice_kind(v)
    if kind == "map" then
      for _, m in pairs(v) do
        if sluice_words(m, cs, floats, values) then return true end
      end
      return false
    end
    for _, m in ipairs(v) do
      if type(m) == "table" and not sluice_null(m) then return true end
      if sluice_word(m, cs, floats, values) then return true end
    end
    return false
  end
  return sluice_word(v, cs, floats, values)
end
local function sluice_doc_words(r, cs, floats, values)
  for _, v in pairs(r) do
    if sluice_words(v, cs, floats, values) then return true end
  end
  return false
end
local function sluice_safe(v)
  if type(v) == "number" then
    return v == v and math.abs(v) < 2^53 and not (v == 0 and 1 / v < 0)
  end
  if type(v) == "table" and not sluice_null(v) then
    for _, m in pairs(v) do if not sluice_safe(m) then return false end end
  end
  return true
end
local function sluice_remove(r, path)
  local v = r
  for i = 1, #path - 1 do
    if type(v) ~= "table" then return false end
    v = v[path[i]]
  end
  local last = path[#path]
  if type(v) == "table" and v[last] ~= nil then
    v[last] = nil
    return true
  end
  return false
end
local function sluice_remove_empty(r, path)
  local v = sluice_get(r, path)
  if v ~= nil and (sluice_null(v) or v == "") then return sluice_remove(r, path) end
  return false
end
local function sluice_split(p)
  local out = {}
  for s in (p .. "."):gmatch("(.-)%.") do out[#out + 1] = s end
  return out
end
local function sluice_remove_empty_except(r, keys, keep, drop)
  local changed = false
  for p in pairs(keys) do
    local kept = drop[p] == true
    for _, e in ipairs(keep) do
      if p == e or p:sub(1, #e + 1) == e .. "." or e:sub(1, #p + 1) == p .. "." then kept = true end
    end
    if not kept and sluice_remove_empty(r, sluice_split(p)) then changed = true end
  end
  return changed
end
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_are_exact_bytes_whatever_they_hold() {
        assert_eq!(string("a\"b\\c"), r#""a\"b\\c""#);
        assert_eq!(string("é\n"), r#""\195\169\10""#);
        assert_eq!(string("]]"), r#""]]""#);
        assert_eq!(list(["a", "b"]), r#"{"a", "b"}"#);
        assert_eq!(set(["a"]), r#"{["a"] = true}"#);
        assert_eq!(segments(&FieldPath::new("a.b")), r#"{"a", "b"}"#);
    }
}
