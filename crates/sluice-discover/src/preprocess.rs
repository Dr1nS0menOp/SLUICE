//! Splitting raw lines into header and content before clustering.
//!
//! The Drain paper clusters only the *content* of a log line: headers such as timestamps and
//! hostnames are extracted first, because they vary on every line but say nothing about the
//! event type. Left in, they inflate similarity between unrelated lines and make the tree route
//! on meaningless tokens like a month name.
//!
//! We recognise the syslog header (RFC 3164 and the ISO-timestamp form rsyslog writes) and keep
//! only the program name from it, as the first token. That is also what Wazuh's pre-decoder
//! extracts as `program_name`. Lines without a recognised header are clustered whole.

use crate::mask;

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Tokens Drain clusters on: the program name (if a syslog header was found) followed by the
/// masked content.
pub(crate) fn content_tokens(line: &str) -> Vec<String> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    match syslog_header_len(&tokens) {
        Some(header) => {
            let program = program_name(tokens[header - 1]);
            std::iter::once(program.to_owned())
                .chain(tokens[header..].iter().map(|t| mask::mask(t)))
                .collect()
        }
        None => tokens.iter().map(|t| mask::mask(t)).collect(),
    }
}

/// Number of header tokens (timestamp, host, `program[pid]:`), if the line has a syslog header.
fn syslog_header_len(tokens: &[&str]) -> Option<usize> {
    let timestamp_len = if tokens.len() >= 3
        && MONTHS.contains(&tokens[0])
        && tokens[1]
            .parse::<u8>()
            .is_ok_and(|day| (1..=31).contains(&day))
        && is_clock(tokens[2])
    {
        3
    } else if tokens.first().is_some_and(|t| is_iso_timestamp(t)) {
        1
    } else {
        return None;
    };
    // Host, then a tag ending in ':' such as `sshd[123]:` or `kernel:`.
    let tag = tokens.get(timestamp_len + 1)?;
    (tag.len() > 1 && tag.ends_with(':')).then_some(timestamp_len + 2)
}

fn is_clock(token: &str) -> bool {
    let parts: Vec<&str> = token.split(':').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// `2026-10-10T08:00:02.123+00:00` and similar: a date, a `T`, and a clock.
fn is_iso_timestamp(token: &str) -> bool {
    let Some((date, time)) = token.split_once('T') else {
        return false;
    };
    let date_ok = date.len() == 10
        && date.bytes().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                b == b'-'
            } else {
                b.is_ascii_digit()
            }
        });
    // `get` rather than slicing: byte 8 may fall inside a multi-byte character of hostile input.
    date_ok && time.get(..8).is_some_and(is_clock)
}

/// `sshd[123]:` → `sshd`, `kernel:` → `kernel`.
fn program_name(tag: &str) -> &str {
    let tag = tag.trim_end_matches(':');
    tag.split_once('[').map_or(tag, |(name, _)| name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bsd_syslog_header_is_replaced_by_program() {
        assert_eq!(
            content_tokens("Oct 10 08:00:02 web01 sshd[7107]: Accepted publickey for alice"),
            ["sshd", "Accepted", "publickey", "for", "alice"]
        );
        assert_eq!(
            content_tokens("Oct  9 08:00:02 web01 kernel: eth0 link up"),
            ["kernel", "eth<NUM>", "link", "up"]
        );
    }

    #[test]
    fn iso_syslog_header_is_replaced_by_program() {
        assert_eq!(
            content_tokens("2026-10-10T08:00:02.123+00:00 web01 CRON[42]: session opened"),
            ["CRON", "session", "opened"]
        );
    }

    #[test]
    fn multibyte_input_never_panics() {
        for line in [
            "2026-10-10T08:0é:02 h p: x",
            "2026-10-10Tééééé h p: x",
            "Oct 10 0é:00:02 h p: x",
        ] {
            assert!(content_tokens(line).iter().any(|t| t == "x"), "{line}");
        }
    }

    #[test]
    fn lines_without_header_are_kept_whole() {
        assert_eq!(
            content_tokens("10.0.0.1 - - GET /"),
            ["<NUM>.<NUM>.<NUM>.<NUM>", "-", "-", "GET", "/"]
        );
        // Looks like a date but has no program tag.
        assert_eq!(
            content_tokens("Oct 10 08:00:02 hello"),
            ["Oct", "<NUM>", "<NUM>:<NUM>:<NUM>", "hello"]
        );
    }
}
