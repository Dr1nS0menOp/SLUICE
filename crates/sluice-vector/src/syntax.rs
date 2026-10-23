//! Rendering values as VRL source.
//!
//! Everything Sluice puts into generated VRL that came from data (field names, rule values,
//! template ids) goes through here, so escaping lives in one place.

use sluice_core::field::FieldPath;
use sluice_core::recipe::Literal;

/// A VRL string literal for `text`.
///
/// VRL string literals support `{{ … }}` templating, so a value containing `{{` would be
/// evaluated as a template. Every brace is escaped (`\{`, `\}`), which can never form a template
/// marker; control characters use `\u{…}`.
pub(crate) fn string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '{' => out.push_str("\\{"),
            '}' => out.push_str("\\}"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.extend(c.escape_unicode()),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A VRL test that the value at `path` is `value`, of its type. VRL's `==` takes a string only
/// for a string and a boolean only for a boolean, but an integer also for an equal float (`0`
/// for `0.0`), so an integer is tested as one: put back, the value would otherwise change type.
pub(crate) fn equals(path: &str, value: &Literal) -> String {
    match value {
        Literal::Bool(b) => format!("{path} == {b}"),
        Literal::Integer(i) => format!("(is_integer({path}) && {path} == {i})"),
        Literal::Text(s) => format!("{path} == {}", string(s)),
    }
}

/// A VRL event path with every segment quoted: `a.b` → `."a"."b"`.
pub(crate) fn path(field: &FieldPath) -> String {
    let mut out = String::new();
    for segment in field.segments() {
        out.push('.');
        out.push_str(&string(segment));
    }
    out
}

/// A VRL regex literal, or `None` if the pattern cannot be written as one.
///
/// VRL regex literals are delimited by `'`, so a quote in the pattern is replaced by the regex
/// escape `\x27`. That is only sound when the quote is not itself escaped, so a pattern
/// containing `\'` is refused.
pub(crate) fn regex(pattern: &str) -> Option<String> {
    if pattern.contains("\\'") {
        return None;
    }
    Some(format!("r'{}'", pattern.replace('\'', "\\x27")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_escape_quotes_backslashes_braces_and_controls() {
        assert_eq!(string(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(string("{{ .x }}"), r#""\{\{ .x \}\}""#);
        assert_eq!(string("a\nb\u{1}"), r#""a\nb\u{1}""#);
    }

    #[test]
    fn paths_quote_every_segment() {
        assert_eq!(path(&"@timestamp".into()), r#"."@timestamp""#);
        assert_eq!(path(&"agent.id".into()), r#"."agent"."id""#);
    }

    #[test]
    fn regex_literals_avoid_the_delimiter() {
        assert_eq!(regex("a'b").as_deref(), Some(r"r'a\x27b'"));
        assert_eq!(regex(r"a\'b"), None);
    }

    use serde_json::{Map, Value, json};

    use crate::runtime::CompiledProgram;

    /// Text that has broken, or could break, generated code.
    const HOSTILE: [&str; 16] = [
        "",
        "plain",
        "a\"b",
        "back\\slash\\",
        "{{ .secret }}",
        "}{",
        "%meta",
        "$var ${x} #{y}",
        "new\nline\r\ttab",
        "\u{0}\u{1}\u{1b}",
        "ünïcödé",
        "emoji 🔥",
        "\u{2028}\u{2029}",
        "'single'",
        "r'not a regex'",
        "a.b",
    ];

    /// Runs `source` on `event` and returns `.out`.
    fn run(source: &str, event: Value) -> Value {
        let program = CompiledProgram::compile("syntax", format!("{source}\n"))
            .unwrap_or_else(|e| panic!("{source}: {e}"));
        let Value::Object(fields) = event else {
            unreachable!()
        };
        let (body, _) = program.run(&fields).expect("runs");
        let Value::Object(out) = serde_json::to_value(&body).expect("json") else {
            panic!("an object")
        };
        out.get("out").cloned().unwrap_or(Value::Null)
    }

    #[test]
    fn every_hostile_string_round_trips_through_vrl() {
        for text in HOSTILE {
            let long = text.repeat(200);
            for candidate in [text, long.as_str()] {
                assert_eq!(
                    run(&format!(".out = {}", string(candidate)), json!({})),
                    json!(candidate),
                    "{candidate:?}"
                );
            }
        }
    }

    #[test]
    fn every_hostile_field_name_is_addressed_exactly() {
        for name in HOSTILE.iter().filter(|n| !n.is_empty() && !n.contains('.')) {
            let mut event = Map::new();
            event.insert((*name).to_owned(), json!("value"));
            event.insert(format!("{name}x"), json!("other"));
            assert_eq!(
                run(
                    &format!(".out = {}", path(&FieldPath::new(*name))),
                    Value::Object(event)
                ),
                json!("value"),
                "{name:?}"
            );
        }
    }

    #[test]
    fn regex_literals_match_as_the_regex_crate_does() {
        let patterns = [
            "^a'b$",
            "x\\d+",
            "(?i)ÉCHEC",
            "a\\.b",
            "[\"{}]",
            "\\x27",
            "a\nb",
        ];
        let inputs = ["a'b", "x42", "échec", "a.b", "aXb", "{", "'", "a\nb", ""];
        for pattern in patterns {
            let quoted = regex(pattern).expect("quotable");
            let expected = ::regex::Regex::new(pattern).expect("a valid regex");
            for input in inputs {
                assert_eq!(
                    run(
                        &format!(".out = match(string!(.x), {quoted})"),
                        json!({"x": input})
                    ),
                    json!(expected.is_match(input)),
                    "{pattern:?} on {input:?}"
                );
            }
        }
    }
}
