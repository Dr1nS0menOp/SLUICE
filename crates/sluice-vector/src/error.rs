//! Errors of the Vector crate.

/// Generated VRL did not compile. This is a bug in Sluice's code generation, never a property
/// of the data, so it surfaces with VRL's own diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum VectorError {
    /// VRL rejected a generated program.
    #[error("generated VRL for {program} does not compile:\n{diagnostics}")]
    Compile {
        /// Which program (a source id, or `predicate`).
        program: String,
        /// VRL's formatted diagnostics.
        diagnostics: String,
    },
    /// The Vector configuration could not be rendered.
    #[error("cannot render the Vector configuration: {0}")]
    Config(String),
    /// A configuration read back for `sluice prove` is not one Sluice generated, so what it does
    /// cannot be proven.
    #[error("cannot prove this configuration: {0}")]
    NotProvable(String),
}
