//! A KQL tokenizer, just precise enough to find table references, `where` conditions and
//! identifiers. It never fails: anything it does not know becomes a symbol token, which the
//! extraction treats as "not understood" (widening).

/// One KQL token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Token {
    /// A name: a table, column, function or keyword.
    Ident(String),
    /// A number, timespan or other literal starting with a digit (`4624`, `1d`).
    Number(String),
    /// A string literal's value.
    Str(String),
    /// Punctuation or an operator (`|`, `(`, `==`, `in~`, …).
    Symbol(String),
}

/// Two-character operators, longest first.
const OPERATORS: [&str; 7] = ["==", "!=", "=~", "!~", "<=", ">=", "=>"];

/// Opens and closes a multi-line string literal.
const FENCE: [char; 3] = ['`'; 3];

pub(super) fn tokens(query: &str) -> Vec<Token> {
    let chars: Vec<char> = query.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if chars[i..].starts_with(&FENCE) {
            // A multi-line string; an unterminated one runs to the end of the query.
            let start = i + FENCE.len();
            let end = (start..chars.len())
                .find(|&j| chars[j..].starts_with(&FENCE))
                .unwrap_or(chars.len());
            out.push(Token::Str(chars[start..end].iter().collect()));
            i = (end + FENCE.len()).min(chars.len());
        } else if (c == '@' || c == 'h' || c == 'H') && matches!(chars.get(i + 1), Some('\'' | '"'))
        {
            // Verbatim (`@'…'`, quotes doubled) or obfuscated (`h'…'`) string.
            let (value, next) = string(&chars, i + 1, c == '@');
            out.push(Token::Str(value));
            i = next;
        } else if c == '\'' || c == '"' {
            let (value, next) = string(&chars, i, false);
            out.push(Token::Str(value));
            i = next;
        } else if c.is_ascii_alphabetic() || c == '_' || c == '$' {
            let start = i;
            while i < chars.len()
                && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '$')
            {
                i += 1;
            }
            out.push(Token::Ident(chars[start..i].iter().collect()));
        } else if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '.') {
                i += 1;
            }
            out.push(Token::Number(chars[start..i].iter().collect()));
        } else {
            let pair: String = chars[i..(i + 2).min(chars.len())].iter().collect();
            if let Some(op) = OPERATORS.iter().find(|op| pair == **op) {
                out.push(Token::Symbol((*op).to_owned()));
                i += 2;
            } else {
                out.push(Token::Symbol(c.to_string()));
                i += 1;
            }
        }
    }
    out
}

/// A string starting with its quote at `at`; returns its value and the index after it.
fn string(chars: &[char], at: usize, verbatim: bool) -> (String, usize) {
    let quote = chars[at];
    let mut value = String::new();
    let mut i = at + 1;
    while i < chars.len() {
        let c = chars[i];
        if c == quote {
            if verbatim && chars.get(i + 1) == Some(&quote) {
                value.push(quote);
                i += 2;
                continue;
            }
            return (value, i + 1);
        }
        if c == '\\'
            && !verbatim
            && let Some(next) = chars.get(i + 1)
        {
            value.push(*next);
            i += 2;
            continue;
        }
        value.push(c);
        i += 1;
    }
    (value, i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_a_query_into_tokens() {
        let t = tokens(
            "SecurityEvent // logons\n| where EventID == 4624 and Account !~ @'x''y' | take 1",
        );
        assert_eq!(t[0], Token::Ident("SecurityEvent".into()));
        assert!(t.contains(&Token::Symbol("==".into())));
        assert!(t.contains(&Token::Number("4624".into())));
        assert!(t.contains(&Token::Symbol("!~".into())));
        assert!(t.contains(&Token::Str("x'y".into())));
        assert!(
            !t.iter().any(|t| *t == Token::Ident("logons".into())),
            "comments are skipped"
        );
    }

    fn ident(s: &str) -> Token {
        Token::Ident(s.into())
    }

    fn symbol(s: &str) -> Token {
        Token::Symbol(s.into())
    }

    fn string(s: &str) -> Token {
        Token::Str(s.into())
    }

    #[test]
    fn a_comment_needs_two_slashes_and_runs_to_the_end_of_its_line() {
        assert_eq!(
            tokens("x/2 // c\nT"),
            [
                ident("x"),
                symbol("/"),
                Token::Number("2".into()),
                ident("T")
            ]
        );
        assert_eq!(tokens("T // no newline"), [ident("T")]);
    }

    #[test]
    fn multi_line_strings_end_at_the_next_fence_or_the_query() {
        assert_eq!(
            tokens("pr ```a`b``c``` x"),
            [ident("pr"), string("a`b``c"), ident("x")]
        );
        assert_eq!(tokens("```abc"), [string("abc")], "unterminated");
        assert_eq!(
            tokens("`a` ``"),
            [
                symbol("`"),
                ident("a"),
                symbol("`"),
                symbol("`"),
                symbol("`")
            ],
            "fewer than three backticks are symbols"
        );
    }

    #[test]
    fn strings_read_escapes_except_verbatim_ones() {
        assert_eq!(
            tokens(r#"@'a\b''c' h"x" H'y' 'p\'q' "r\"s" hx"#),
            [
                string(r"a\b'c"),
                string("x"),
                string("y"),
                string("p'q"),
                string("r\"s"),
                ident("hx"),
            ]
        );
    }

    #[test]
    fn names_numbers_and_operators_are_whole_tokens() {
        assert_eq!(
            tokens("_a$1 1.5d a<=b c<d =>"),
            [
                ident("_a$1"),
                Token::Number("1.5d".into()),
                ident("a"),
                symbol("<="),
                ident("b"),
                ident("c"),
                symbol("<"),
                ident("d"),
                symbol("=>"),
            ]
        );
    }

    #[test]
    fn never_fails_on_odd_input() {
        for odd in ["'unterminated", "```x", "@\"", "h'", "€ | ¿", ""] {
            let _ = tokens(odd);
        }
    }
}
