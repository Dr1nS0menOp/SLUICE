//! Named operator tokens (ADR 0016): each person gets their own bearer token, so the history
//! and the audit log say who acted. They live in a secret file, one `name token` per line, that
//! only its owner may read.

use std::path::Path;

use crate::error::ServerError;

/// The shortest operator token accepted, as for the control token.
pub(crate) const MIN_TOKEN_LEN: usize = 32;

/// Who made a request: an operator's name, `token` (the shared control token) or `local`
/// (no token configured; the control plane only listens on loopback then).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Actor(pub(crate) String);

/// One operator and their token.
#[derive(Debug, Clone)]
pub(crate) struct Operator {
    pub(crate) name: String,
    pub(crate) token: String,
}

/// Reads the operators file. Lines are `name token`; empty lines and `#` comments are skipped.
/// Names use letters, digits, `.`, `_`, `-` and `@`.
///
/// # Errors
///
/// Returns [`ServerError::Config`] if the file is readable by others than its owner, or a line
/// is malformed, a name repeats or a token is too short (the message never contains a token).
pub(crate) fn load(path: &Path) -> Result<Vec<Operator>, ServerError> {
    use std::os::unix::fs::PermissionsExt;
    let config = |why: String| ServerError::Config(format!("{}: {why}", path.display()));
    let metadata = std::fs::metadata(path).map_err(|e| config(e.to_string()))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(config(
            "readable by others than its owner; restrict it (chmod 600)".to_owned(),
        ));
    }
    let text = std::fs::read_to_string(path).map_err(|e| config(e.to_string()))?;
    parse(&text).map_err(config)
}

fn parse(text: &str) -> Result<Vec<Operator>, String> {
    let mut operators: Vec<Operator> = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(name), Some(token), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(format!("line {}: expected `name token`", n + 1));
        };
        let valid_name = name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'));
        if !valid_name || name == "token" || name == "local" {
            return Err(format!("line {}: invalid operator name `{name}`", n + 1));
        }
        if token.chars().count() < MIN_TOKEN_LEN {
            return Err(format!(
                "line {}: the token of {name} is shorter than {MIN_TOKEN_LEN} characters",
                n + 1
            ));
        }
        if operators.iter().any(|o| o.name == name) {
            return Err(format!("line {}: {name} appears twice", n + 1));
        }
        if operators.iter().any(|o| o.token == token) {
            return Err(format!(
                "line {}: {name} shares a token with another operator",
                n + 1
            ));
        }
        operators.push(Operator {
            name: name.to_owned(),
            token: token.to_owned(),
        });
    }
    Ok(operators)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn operators_are_read_one_per_line() {
        let text = format!("# SOC\nalice@example.org {A}\n\nbob {B}\n");
        let operators = parse(&text).expect("valid");
        let names: Vec<&str> = operators.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(names, ["alice@example.org", "bob"]);
    }

    #[test]
    fn bad_lines_are_refused_without_showing_tokens() {
        for (text, why) in [
            (format!("alice {A} extra"), "expected"),
            ("alice short".to_owned(), "shorter"),
            (format!("token {A}"), "invalid operator name"),
            (format!("al ice {A}"), "expected"),
            (format!("alice {A}\nalice {B}"), "twice"),
            (format!("alice {A}\nbob {A}"), "shares a token"),
        ] {
            let error = parse(&text).expect_err(&text);
            assert!(error.contains(why), "{error}");
            assert!(!error.contains(A) && !error.contains(B), "{error}");
        }
    }

    #[test]
    fn a_file_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("sluice-operators-{}", std::process::id()));
        std::fs::write(&path, format!("alice {A}\n")).expect("written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(load(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        assert_eq!(load(&path).expect("private").len(), 1);
        let _ = std::fs::remove_file(&path);
    }
}
