//! SPL's text as the scope rewrite reads it: which characters stand outside quotes and
//! subsearches, where a subsearch ends, and the tokens of the search language.

/// Each character's byte offset, the character, and whether it stands outside quotes and
/// subsearches (`[…]`; the opening bracket itself counts as outside).
pub(super) fn outside(text: &str) -> Vec<(usize, char, bool)> {
    let mut out = Vec::with_capacity(text.len());
    let (mut quoted, mut escaped, mut depth) = (false, false, 0usize);
    for (i, c) in text.char_indices() {
        out.push((i, c, !quoted && !escaped && depth == 0));
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            quoted = !quoted;
        } else if !quoted && c == '[' {
            depth += 1;
        } else if !quoted && c == ']' {
            depth = depth.saturating_sub(1);
        }
    }
    out
}

/// The position in `chars` of the `]` closing a subsearch whose content starts at `from`.
pub(super) fn closing(chars: &[(usize, char, bool)], from: usize) -> Option<usize> {
    let (mut quoted, mut escaped, mut depth) = (false, false, 0usize);
    for (at, &(_, c, _)) in chars.iter().enumerate().skip(from) {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            quoted = !quoted;
        } else if !quoted && c == '[' {
            depth += 1;
        } else if !quoted && c == ']' {
            if depth == 0 {
                return Some(at);
            }
            depth -= 1;
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Open,
    Close,
    Comma,
    /// `=`, `==`, `!=`, `<`, `<=`, `>` or `>=`.
    Op,
    Word {
        quoted: bool,
    },
    /// A subsearch, brackets included.
    Sub,
}

/// A token and where it is in the text, by byte offsets.
#[derive(Debug, Clone, Copy)]
pub(super) struct Token {
    pub(super) kind: Kind,
    pub(super) start: usize,
    pub(super) end: usize,
}

/// The tokens of search-language `text`, or `None` for an unterminated quote or subsearch,
/// which is then left as it is (Splunk refuses it, and the proof sets the search aside).
pub(super) fn lex(text: &str) -> Option<Vec<Token>> {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let end_of = |at: usize| chars.get(at).map_or(text.len(), |&(i, _)| i);
    let mut tokens = Vec::new();
    let mut at = 0;
    while let Some(&(start, c)) = chars.get(at) {
        let next = chars.get(at + 1).map(|&(_, c)| c);
        let (kind, len) = match c {
            c if c.is_whitespace() => {
                at += 1;
                continue;
            }
            '(' => (Kind::Open, 1),
            ')' => (Kind::Close, 1),
            ',' => (Kind::Comma, 1),
            '!' | '<' | '>' | '=' if c != '!' || next == Some('=') => {
                (Kind::Op, if next == Some('=') { 2 } else { 1 })
            }
            '"' => {
                let mut i = at + 1;
                loop {
                    match chars.get(i)?.1 {
                        '\\' => i += 2,
                        '"' => break,
                        _ => i += 1,
                    }
                }
                (Kind::Word { quoted: true }, i + 1 - at)
            }
            '[' => {
                let marks: Vec<(usize, char, bool)> =
                    chars.iter().map(|&(i, c)| (i, c, false)).collect();
                let close = closing(&marks, at + 1)?;
                (Kind::Sub, close + 1 - at)
            }
            _ => {
                let mut i = at;
                while let Some(&(_, c)) = chars.get(i) {
                    let operator = c == '!' && chars.get(i + 1).map(|&(_, c)| c) == Some('=');
                    if c.is_whitespace() || "()=,\"<>[]".contains(c) || operator {
                        break;
                    }
                    i += if c == '\\' { 2 } else { 1 };
                }
                (Kind::Word { quoted: false }, i.min(chars.len()) - at)
            }
        };
        tokens.push(Token {
            kind,
            start,
            end: end_of(at + len),
        });
        at += len;
    }
    Some(tokens)
}
