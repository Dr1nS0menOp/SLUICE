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
        } else if c == '`' && chars.get(i + 1) == Some(&'`') && chars.get(i + 2) == Some(&'`') {
            let start = i + 3;
            let mut end = start;
            while end + 2 < chars.len()
                && !(chars[end] == '`' && chars[end + 1] == '`' && chars[end + 2] == '`')
            {
                end += 1;
            }
            out.push(Token::Str(
                chars[start..end.min(chars.len())].iter().collect(),
            ));
            i = (end + 3).min(chars.len());
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

    #[test]
    fn never_fails_on_odd_input() {
        for odd in ["'unterminated", "```x", "@\"", "h'", "€ | ¿", ""] {
            let _ = tokens(odd);
        }
    }
}
