//! OTTL syntax: literals, paths into a log record, and regular expressions that match text
//! literally.

use std::fmt::Write as _;

use sluice_core::field::FieldPath;

/// An OTTL string literal (Go's quoted string): `"` and `\` escaped, control characters as
/// `\u` escapes, everything else as it is.
pub(crate) fn string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The value at `path` below `root` (`log.body`): `log.body["Host"]["name"]`.
pub(crate) fn path(root: &str, path: &FieldPath) -> String {
    let mut out = root.to_owned();
    for segment in path.segments() {
        out.push('[');
        out.push_str(&string(segment));
        out.push(']');
    }
    out
}

/// `text` as an RE2 pattern that matches it literally, as Go's `regexp.QuoteMeta` makes it; a
/// control character as `\x{..}`.
pub(crate) fn quote_meta(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if "\\.+*?()|[]{}^$".contains(c) {
            out.push('\\');
            out.push(c);
        } else if c.is_control() {
            let _ = write!(out, "\\x{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_and_paths_hold_any_text() {
        assert_eq!(string(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(string("é\n"), "\"é\\u000a\"");
        assert_eq!(
            path("log.body", &FieldPath::new("Host.name")),
            r#"log.body["Host"]["name"]"#
        );
    }

    #[test]
    fn patterns_match_literally() {
        assert_eq!(quote_meta("a.b*(c)"), r"a\.b\*\(c\)");
        assert_eq!(quote_meta("C:\\x"), r"C:\\x");
        assert_eq!(quote_meta("\t"), r"\x{9}");
        assert_eq!(quote_meta("Straße"), "Straße");
    }
}
