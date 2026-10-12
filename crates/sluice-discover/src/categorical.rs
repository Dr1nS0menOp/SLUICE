//! Splitting a Drain cluster at the positions where only a few words alternate (ADR 0019).
//!
//! Drain turns every position where lines differ into `<*>`. That is right for a user name or a
//! path, and wrong for a word that says what happened: sshd's `Accepted password for …` and
//! `Failed password for …` become one template, so a handful of failures among thousands of
//! successful logons are no longer rare to the guardrails. A wildcard position with few distinct
//! values is such a word, as is one holding message ids such as Cisco's `%ASA-6-302013:`. Each of
//! its values gets a template of its own; other wildcards stay wildcards.

use std::collections::BTreeSet;

use sluice_core::template::token::WILDCARD;

use crate::mask;

/// The wildcard positions of `cluster` that are categorical among the masked `lines` of its
/// members: at most `max_values` distinct values, or message ids only.
pub(crate) fn positions(cluster: &[String], lines: &[&[String]], max_values: usize) -> Vec<usize> {
    cluster
        .iter()
        .enumerate()
        .filter(|(_, token)| token.as_str() == WILDCARD)
        .map(|(position, _)| position)
        .filter(|&position| {
            let values: BTreeSet<&str> = lines
                .iter()
                .filter_map(|line| line.get(position).map(String::as_str))
                .collect();
            values.len() <= max_values || values.iter().all(|v| mask::is_message_tag(v))
        })
        .collect()
}

/// The template of one line within its cluster: the cluster's tokens, with the line's own token
/// at every categorical position.
pub(crate) fn specialize(cluster: &[String], line: &[String], positions: &[usize]) -> Vec<String> {
    let mut tokens = cluster.to_vec();
    for &position in positions {
        if let (Some(slot), Some(token)) = (tokens.get_mut(position), line.get(position)) {
            slot.clone_from(token);
        }
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(line: &str) -> Vec<String> {
        line.split(' ').map(str::to_owned).collect()
    }

    #[test]
    fn a_word_that_alternates_is_categorical_a_parameter_is_not() {
        let cluster = tokens("sshd <*> password for <*> from <NUM>");
        let mut lines: Vec<Vec<String>> = (0..20)
            .map(|n| tokens(&format!("sshd Accepted password for user{n} from <NUM>")))
            .collect();
        lines.push(tokens("sshd Failed password for root from <NUM>"));
        let refs: Vec<&[String]> = lines.iter().map(Vec::as_slice).collect();
        let found = positions(&cluster, &refs, 6);
        assert_eq!(found, [1], "the verb, not the user");
        assert_eq!(
            specialize(&cluster, &lines[20], &found).join(" "),
            "sshd Failed password for <*> from <NUM>"
        );
    }

    #[test]
    fn message_ids_are_categorical_however_many_there_are() {
        let cluster = tokens("<*> Built connection");
        let lines: Vec<Vec<String>> = (0..30)
            .map(|n| tokens(&format!("%ASA-6-3020{n:02}: Built connection")))
            .collect();
        let refs: Vec<&[String]> = lines.iter().map(Vec::as_slice).collect();
        assert_eq!(positions(&cluster, &refs, 6), [0]);
    }
}
