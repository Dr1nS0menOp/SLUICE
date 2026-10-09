//! The Drain online log parser (He, Zhu, Zheng & Lyu, "Drain: An Online Log Parsing Approach with
//! Fixed Depth Tree", ICWS 2017), following the behaviour of the Drain3 reference implementation.
//!
//! Lines are routed through a fixed-depth tree: first by token count, then by their leading
//! tokens. At a leaf, a line joins the most similar cluster if that cluster's similarity reaches
//! the threshold, and positions where they differ become wildcards. Otherwise it starts a new
//! cluster.

use std::collections::BTreeMap;

/// Token that matches anything in a template.
pub(crate) const WILDCARD: &str = "<*>";

/// Drain parameters. The defaults are Drain3's, except `depth`. Drain3 uses 4, which routes on
/// the first two tokens. Our first token is already the program name split off the syslog header
/// (see `preprocess.rs`), so depth 3 routes on the program alone and lets similarity decide the
/// rest. At depth 4 the second routing token was often a variable, such as the user in
/// `sudo alice : …`, which never merges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainConfig {
    /// Tree depth including the root and length layers; at least 3.
    pub depth: usize,
    /// Minimum share of equal tokens to join a cluster, in per mille.
    pub similarity_permille: u32,
    /// Maximum children per tree node; extra tokens route through a wildcard child.
    pub max_children: usize,
}

impl Default for DrainConfig {
    fn default() -> Self {
        Self {
            depth: 3,
            similarity_permille: 400,
            max_children: 100,
        }
    }
}

/// Index of a cluster within one [`Drain`] instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ClusterIndex(usize);

#[derive(Debug, Default)]
struct Node {
    children: BTreeMap<String, Node>,
    clusters: Vec<ClusterIndex>,
}

/// One Drain parse tree and its clusters.
#[derive(Debug)]
pub(crate) struct Drain {
    config: DrainConfig,
    by_length: BTreeMap<usize, Node>,
    templates: Vec<Vec<String>>,
}

impl Drain {
    pub(crate) fn new(config: DrainConfig) -> Self {
        Self {
            config,
            by_length: BTreeMap::new(),
            templates: Vec::new(),
        }
    }

    /// Adds a tokenized line and returns the cluster it joined.
    pub(crate) fn add(&mut self, tokens: Vec<String>) -> ClusterIndex {
        let prefix_depth = self.config.depth.saturating_sub(2).max(1);
        let max_children = self.config.max_children.max(2);
        let mut node = self.by_length.entry(tokens.len()).or_default();
        for token in tokens.iter().take(prefix_depth) {
            let key = if node.children.contains_key(token) {
                token.clone()
            } else if has_digit(token) || node.children.len() + 1 >= max_children {
                WILDCARD.to_owned()
            } else {
                token.clone()
            };
            node = node.children.entry(key).or_default();
        }

        let threshold = f64::from(self.config.similarity_permille) / 1000.0;
        let best = node
            .clusters
            .iter()
            .map(|&index| (index, similarity(&self.templates[index.0], &tokens)))
            .filter(|&(_, (sim, _))| sim >= threshold)
            // Highest similarity, then most wildcards (the more general template), then oldest.
            .max_by(|(a_index, a), (b_index, b)| {
                a.0.total_cmp(&b.0)
                    .then(a.1.cmp(&b.1))
                    .then(b_index.cmp(a_index))
            })
            .map(|(index, _)| index);

        if let Some(index) = best {
            generalize(&mut self.templates[index.0], &tokens);
            index
        } else {
            let index = ClusterIndex(self.templates.len());
            self.templates.push(tokens);
            node.clusters.push(index);
            index
        }
    }

    /// The current template of a cluster.
    pub(crate) fn template(&self, index: ClusterIndex) -> &[String] {
        &self.templates[index.0]
    }
}

/// Share of positions where the template has a constant equal to the line's token, and the
/// number of wildcards in the template. Both lines have the same length by construction.
fn similarity(template: &[String], tokens: &[String]) -> (f64, usize) {
    if template.is_empty() {
        return (1.0, 0);
    }
    let mut equal = 0_u32;
    let mut wildcards = 0;
    for (t, token) in template.iter().zip(tokens) {
        if t == WILDCARD {
            wildcards += 1;
        } else if t == token {
            equal += 1;
        }
    }
    // Token counts of log lines are far below 2^32, so the conversion cannot fail in practice.
    let len = u32::try_from(template.len()).unwrap_or(u32::MAX);
    (f64::from(equal) / f64::from(len), wildcards)
}

fn generalize(template: &mut [String], tokens: &[String]) {
    for (t, token) in template.iter_mut().zip(tokens) {
        if t != token {
            WILDCARD.clone_into(t);
        }
    }
}

fn has_digit(token: &str) -> bool {
    token.bytes().any(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preprocess::content_tokens as tokens;

    fn drain() -> Drain {
        Drain::new(DrainConfig::default())
    }

    #[test]
    fn identical_lines_share_a_cluster() {
        let mut d = drain();
        let a = d.add(tokens("session opened for user root"));
        let b = d.add(tokens("session opened for user root"));
        assert_eq!(a, b);
    }

    #[test]
    fn varying_token_becomes_wildcard() {
        let mut d = drain();
        let a = d.add(tokens("Accepted publickey for alice from host"));
        let b = d.add(tokens("Accepted publickey for bob from host"));
        assert_eq!(a, b);
        assert_eq!(
            d.template(a).join(" "),
            "Accepted publickey for <*> from host"
        );
    }

    #[test]
    fn different_lengths_never_merge() {
        let mut d = drain();
        let a = d.add(tokens("Failed password for alice"));
        let b = d.add(tokens("Failed password for invalid user alice"));
        assert_ne!(a, b);
    }

    #[test]
    fn dissimilar_lines_of_equal_length_stay_apart() {
        let mut d = drain();
        let a = d.add(tokens("session opened for user root"));
        let b = d.add(tokens("New session of user deploy."));
        assert_ne!(a, b);
    }

    #[test]
    fn leading_tokens_with_digits_route_through_wildcard() {
        let mut d = drain();
        let a = d.add(vec!["pid42".into(), "started".into(), "worker".into()]);
        let b = d.add(vec!["pid7".into(), "started".into(), "worker".into()]);
        assert_eq!(a, b);
    }
}
