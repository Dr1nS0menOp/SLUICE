//! Tokenizing and masking raw log lines before clustering.
//!
//! Masking replaces values that obviously vary (numbers, hex identifiers) with placeholders, so
//! Drain clusters lines by their constant text. It is purely an aid: Drain still turns any token
//! that differs between lines into a wildcard.

use sluice_core::template::token::{HEX, NUM};

/// Masks one token. Surrounding punctuation (quotes, brackets, colons) is kept, so `[1234]:`
/// becomes `[<NUM>]:`.
pub(crate) fn mask(token: &str) -> String {
    if is_message_tag(token) {
        return token.to_owned();
    }
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

/// A Cisco-style message id, `%FACILITY-SEVERITY-MNEMONIC:` (`%ASA-6-302013:`,
/// `%SEC_LOGIN-5-LOGIN_SUCCESS:`). Its digits name the event type, so they are not masked.
pub(crate) fn is_message_tag(token: &str) -> bool {
    let Some(rest) = token.strip_prefix('%') else {
        return false;
    };
    let word = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    match rest.trim_end_matches(':').split('-').collect::<Vec<_>>()[..] {
        [facility, severity, mnemonic] => {
            word(facility)
                && facility.bytes().any(|b| b.is_ascii_alphabetic())
                && severity.len() == 1
                && severity.bytes().all(|b| b.is_ascii_digit())
                && word(mnemonic)
        }
        _ => false,
    }
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
    fn message_ids_keep_their_digits() {
        assert_eq!(mask("%ASA-6-302013:"), "%ASA-6-302013:");
        assert_eq!(
            mask("%SEC_LOGIN-5-LOGIN_SUCCESS:"),
            "%SEC_LOGIN-5-LOGIN_SUCCESS:"
        );
        assert_eq!(mask("%-6-302013:"), "%-<NUM>-<NUM>:", "no facility");
        assert_eq!(
            mask("%ASA-16-302013:"),
            "%ASA-<NUM>-<NUM>:",
            "severity is one digit"
        );
        assert_eq!(mask("50%-6-1"), "<NUM>%-<NUM>-<NUM>");
    }

    #[test]
    fn hex_identifiers_start_at_eight_characters_with_a_digit() {
        assert_eq!(
            mask("abcdef1"),
            "abcdef<NUM>",
            "seven characters: digits only"
        );
        assert_eq!(mask("abcdef12"), HEX);
        assert_eq!(mask("ABCDEF12"), HEX, "upper case");
        assert_eq!(mask("0X1F"), HEX);
        assert_eq!(mask("0x"), "<NUM>x", "a bare prefix is not an identifier");
        assert_eq!(mask("0xZZ"), "<NUM>xZZ");
    }

    #[test]
    fn tokens_without_alphanumerics_and_non_ascii_digits_stay() {
        assert_eq!(mask("--"), "--");
        assert_eq!(mask(""), "");
        assert_eq!(mask("٣٤٥"), "٣٤٥", "only ASCII digits are masked");
        assert_eq!(mask("ünï42"), "ünï<NUM>");
    }

    #[test]
    fn masking_is_idempotent() {
        for token in ["sshd[7107]:", "10.0.0.1", "0x1F", "%ASA-6-302013:", "a1b2"] {
            assert_eq!(mask(&mask(token)), mask(token), "{token}");
        }
    }

    #[test]
    fn message_tags_need_three_parts_and_a_letter_in_the_facility() {
        assert!(is_message_tag("%ASA-6-302013"));
        assert!(is_message_tag("%ASA-6-302013::"));
        assert!(
            !is_message_tag("%123-6-302013:"),
            "a facility with no letter"
        );
        assert!(!is_message_tag("%ASA-6:"));
        assert!(!is_message_tag("%ASA-6-30-2013:"));
        assert!(!is_message_tag("ASA-6-302013:"), "no percent sign");
        assert!(!is_message_tag("%ASA-6-:"), "an empty mnemonic");
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
