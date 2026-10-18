//! What every generator of predicate code (VRL, KQL, Painless, Lua, OTTL) shares, so that a
//! promise such as "keeps a float whole exactly where the VRL compilation does" holds by
//! construction, not by copy.

/// Whether one of `values` could be part of how an engine writes a float (`4625.0`, `1e21`,
/// `-inf`, `NaN`): only then may a float value match a test for them, and a generated test
/// widens to true on a float.
#[must_use]
pub fn float_may_match(values: &[String]) -> bool {
    values.iter().any(|value| {
        let value = value.to_ascii_lowercase();
        value.chars().all(|c| "0123456789.-+e".contains(c))
            || ["-infinity", "+infinity", "nan"]
                .iter()
                .any(|word| word.contains(value.as_str()))
    })
}

/// `parts` joined with the binary `operator` as a balanced tree of parentheses. Parsers that
/// recurse once per operand (VRL's, OTTL's) overflowed on a pre-filter over the thousands of
/// `SigmaHQ` rules; halving keeps the depth logarithmic. `empty` is what joining nothing gives:
/// the operator's neutral element (`false` for an "or", `true` for an "and").
#[must_use]
pub fn balanced(parts: &[String], operator: &str, empty: &str) -> String {
    match parts {
        [] => empty.to_owned(),
        [one] => one.clone(),
        _ => {
            let (left, right) = parts.split_at(parts.len() / 2);
            format!(
                "({}{operator}{})",
                balanced(left, operator, empty),
                balanced(right, operator, empty)
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joining_nothing_gives_the_neutral_element_and_the_tree_is_balanced() {
        assert_eq!(balanced(&[], " || ", "false"), "false");
        assert_eq!(balanced(&["a".into()], " || ", "false"), "a");
        assert_eq!(
            balanced(&["a".into(), "b".into(), "c".into()], " && ", "true"),
            "(a && (b && c))"
        );
        let many: Vec<String> = (0..1024).map(|n| n.to_string()).collect();
        let joined = balanced(&many, " or ", "false");
        let depth = joined
            .chars()
            .scan(0i32, |level, c| {
                *level += match c {
                    '(' => 1,
                    ')' => -1,
                    _ => 0,
                };
                Some(*level)
            })
            .max();
        assert_eq!(depth, Some(10));
    }

    #[test]
    fn only_what_a_float_may_be_written_as_lets_a_float_match() {
        for value in ["4625", "4625.0", "1e21", "-inf", "NaN", "+"] {
            assert!(float_may_match(&[value.into()]), "{value}");
        }
        for value in ["admin", "4625a", "C:\\Windows"] {
            assert!(!float_may_match(&[value.into()]), "{value}");
        }
    }
}
