//! KQL literals and identifiers.

use sluice_core::field::FieldPath;

/// A KQL string literal, or `None` if `value` holds a control character other than tab,
/// newline or carriage return, which the generated query does not try to escape.
pub(crate) fn string(value: &str) -> Option<String> {
    quoted(value, '"')
}

/// The value at `path` in the column model: the first segment is a column, the rest index into
/// it as a dynamic object (`['process']['name']`). Every name is quoted, so any field name is a
/// valid identifier; `None` if a segment holds a control character [`string`] refuses.
pub(crate) fn path(path: &FieldPath) -> Option<String> {
    path.segments().map(quoted_name).collect()
}

/// A bracket-quoted name: `['a b']`, or `None` as for [`string`].
pub(crate) fn quoted_name(name: &str) -> Option<String> {
    quoted(name, '\'').map(|q| format!("[{q}]"))
}

fn quoted(value: &str, delimiter: char) -> Option<String> {
    let mut out = String::with_capacity(value.len() + 2);
    out.push(delimiter);
    for c in value.chars() {
        match c {
            c if c == delimiter => {
                out.push('\\');
                out.push(c);
            }
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => return None,
            c => out.push(c),
        }
    }
    out.push(delimiter);
    Some(out)
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
        assert_eq!(
            path(&"process.name".into()).as_deref(),
            Some("['process']['name']")
        );
        assert_eq!(path(&"it's".into()).as_deref(), Some(r"['it\'s']"));
    }

    #[test]
    fn names_escape_what_a_literal_escapes_and_refuse_the_rest() {
        assert_eq!(quoted_name("a\nb\t\\").as_deref(), Some(r"['a\nb\t\\']"));
        assert_eq!(
            quoted_name("say \"hi\"").as_deref(),
            Some(r#"['say "hi"']"#)
        );
        assert_eq!(quoted_name("a\u{7}b"), None);
        assert_eq!(path(&"ok.a\u{1b}b".into()), None);
    }

    #[test]
    fn literals_keep_unicode_and_single_quotes() {
        assert_eq!(string("é'✓").as_deref(), Some("\"é'✓\""));
        assert_eq!(string("").as_deref(), Some("\"\""));
    }
}
