//! Tokenizing and masking raw log lines before clustering.
//!
//! Masking replaces values that obviously vary (numbers, hex identifiers) with placeholders, so
//! Drain clusters lines by their constant text. It is purely an aid: Drain still turns any token
//! that differs between lines into a wildcard.

/// Placeholder for a run of decimal digits.
pub(crate) const NUM: &str = "<NUM>";
/// Placeholder for a hex identifier (hashes, GUID parts, `0x` values).
pub(crate) const HEX: &str = "<HEX>";

/// Masks one token. Surrounding punctuation (quotes, brackets, colons) is kept, so `[1234]:`
/// becomes `[<NUM>]:`.
pub(crate) fn mask(token: &str) -> String {
    let start = token.find(|c: char| c.is_ascii_alphanumeric());
    let end = token.rfind(|c: char| c.is_ascii_alphanumeric());
    if let (Some(start), Some(end)) = (start, end) {
        let core = &token[start..=end];
        if is_hex_identifier(core) {
            return format!("{}{HEX}{}", &token[..start], &token[end + 1..]);
        }
    }
    mask_digit_runs(token)
}

fn is_hex_identifier(core: &str) -> bool {
    if let Some(rest) = core.strip_prefix("0x").or_else(|| core.strip_prefix("0X")) {
        return !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_hexdigit());
    }
    core.len() >= 8
        && core.bytes().all(|b| b.is_ascii_hexdigit())
        && core.bytes().any(|b| b.is_ascii_digit())
}

fn mask_digit_runs(token: &str) -> String {
    let mut out = String::with_capacity(token.len());
    let mut in_digits = false;
    for c in token.chars() {
        if c.is_ascii_digit() {
            if !in_digits {
                out.push_str(NUM);
                in_digits = true;
            }
        } else {
            out.push(c);
            in_digits = false;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_digit_runs_inside_tokens() {
        assert_eq!(mask("sshd[7107]:"), "sshd[<NUM>]:");
        assert_eq!(mask("10.10.1.21"), "<NUM>.<NUM>.<NUM>.<NUM>");
        assert_eq!(mask("08:00:02"), "<NUM>:<NUM>:<NUM>");
        assert_eq!(mask("publickey"), "publickey");
    }

    #[test]
    fn masks_hex_identifiers_whole() {
        assert_eq!(mask("0x1010"), HEX);
        assert_eq!(mask("844d7f3d6c98"), HEX);
        assert_eq!(mask("(deadbeef01)"), "(<HEX>)");
        // Short or digit-free words are not identifiers.
        assert_eq!(mask("cafe"), "cafe");
        assert_eq!(mask("deadbeefcafe"), "deadbeefcafe");
    }
}
