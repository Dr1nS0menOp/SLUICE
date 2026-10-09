//! Errors of the rules crate.

/// Rules could not be loaded at all. Problems with *individual* rules are not errors: those
/// rules become opaque requirements, which block every cut they might affect.
#[derive(Debug, thiserror::Error)]
pub enum RulesError {
    /// A Sigma file is not valid YAML.
    #[error("cannot parse Sigma rules: {0}")]
    SigmaParse(String),
    /// rsigma rejected the rule collection.
    #[error("cannot compile Sigma rules: {0}")]
    SigmaCompile(String),
    /// A Wazuh rules file is not well-formed XML.
    #[error("cannot parse Wazuh rules: {0}")]
    WazuhXml(String),
}
