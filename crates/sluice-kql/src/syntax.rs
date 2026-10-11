//! KQL literals and identifiers.

use sluice_core::field::FieldPath;

/// A KQL string literal, or `None` if `value` holds a control character other than tab,
/// newline or carriage return, which the generated query does not try to escape.
pub(crate) fn string(value: &str) -> Option<String> {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => return None,
            c => out.push(c),
        }
    }
    out.push('"');
    Some(out)
}

/// The value at `path` in the column model: the first segment is a column, the rest index into
/// it as a dynamic object (`['process']['name']`). Every name is quoted, so any field name is a
/// valid identifier.
pub(crate) fn path(path: &FieldPath) -> String {
    path.segments().map(quoted_name).collect()
}

/// A bracket-quoted name: `['a b']`.
pub(crate) fn quoted_name(name: &str) -> String {
    format!("['{}']", name.replace('\\', "\\\\").replace('\'', "\\'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_escape_quotes_and_refuse_control_characters() {
        assert_eq!(string(r#"a"b\c"#).as_deref(), Some(r#""a\"b\\c""#));
        assert_eq!(string("a\nb").as_deref(), Some(r#""a\nb""#));
        assert_eq!(string("a\u{1}b"), None);
    }

    #[test]
    fn paths_quote_every_segment() {
        assert_eq!(path(&"process.name".into()), "['process']['name']");
        assert_eq!(path(&"it's".into()), r"['it\'s']");
    }
}
