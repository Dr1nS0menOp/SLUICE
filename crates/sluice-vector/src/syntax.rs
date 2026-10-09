//! Rendering values as VRL source.
//!
//! Everything Sluice puts into generated VRL that came from data (field names, rule values,
//! template ids) goes through here, so escaping lives in one place.

use sluice_core::field::FieldPath;

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
}
