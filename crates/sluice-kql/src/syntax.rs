//! KQL literals and identifiers.

use sluice_core::field::FieldPath;

/// A KQL string literal, or `None` if `value` holds a control character other than tab,
/// newline or carriage return, which the generated query does not try to escape.
pub(crate) fn string(value: &str) -> Option<String> {
    quoted(value, '"')
}

/// The value at `path` in the column model: the first segment is a column, the rest index into
/// it as a dynamic object (`columnifexists("process", dynamic(null))['name']`). Every name is
/// quoted, so any field name is a valid identifier; `None` if a segment holds a control
/// character [`string`] refuses. With `known` (every column the record can have), a column in
/// it is read by name (shorter), and one outside it is `dynamic(null)`, as missing as it can be.
pub(crate) fn path_in(path: &FieldPath, known: Option<&Columns>) -> Option<String> {
    let mut segments = path.segments();
    let name = segments.next()?;
    let first = match known {
        None => column(name)?,
        Some(known) if known.contains(name) => quoted_name(name)?,
        Some(_) => return Some("dynamic(null)".to_owned()),
    };
    let rest: Option<Vec<String>> = segments.map(quoted_name).collect();
    rest.map(|rest| first + &rest.concat())
}

/// The columns a record can have, when they are known.
pub(crate) type Columns = std::collections::BTreeSet<String>;

/// A column read that is null where the record has no such column. A DCR transformation sees
/// only the columns of its stream, and naming any other is an error (checked 2026-10-17), so
/// every column is read this way: where it exists, it is the column itself.
pub(crate) fn column(name: &str) -> Option<String> {
    string(name).map(|name| format!("columnifexists({name}, dynamic(null))"))
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
    fn paths_read_their_column_if_it_exists_and_quote_every_segment() {
        assert_eq!(
            path_in(&"process.name".into(), None).as_deref(),
            Some(r#"columnifexists("process", dynamic(null))['name']"#)
        );
        assert_eq!(
            path_in(&"it's.a\"b".into(), None).as_deref(),
            Some(r#"columnifexists("it's", dynamic(null))['a"b']"#)
        );
        assert_eq!(
            column("x\"y").as_deref(),
            Some(r#"columnifexists("x\"y", dynamic(null))"#)
        );
    }

    #[test]
    fn names_escape_what_a_literal_escapes_and_refuse_the_rest() {
        assert_eq!(quoted_name("a\nb\t\\").as_deref(), Some(r"['a\nb\t\\']"));
        assert_eq!(
            quoted_name("say \"hi\"").as_deref(),
            Some(r#"['say "hi"']"#)
        );
        assert_eq!(quoted_name("a\u{7}b"), None);
        assert_eq!(path_in(&"ok.a\u{1b}b".into(), None), None);
    }

    #[test]
    fn literals_keep_unicode_and_single_quotes() {
        assert_eq!(string("é'✓").as_deref(), Some("\"é'✓\""));
        assert_eq!(string("").as_deref(), Some("\"\""));
    }
}
