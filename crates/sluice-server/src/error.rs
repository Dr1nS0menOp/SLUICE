//! Errors of the control plane.

/// The control plane could not start or keep running.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// A file or socket operation failed.
    #[error("{0}")]
    Io(String),
    /// The Vector configuration could not be rendered.
    #[error("cannot render the Vector configuration: {0}")]
    Config(String),
    /// A control cycle failed; the previous configuration stays in force.
    #[error("control cycle failed: {0}")]
    Cycle(String),
    /// Vector could not be started or stopped.
    #[error("Vector: {0}")]
    Vector(String),
}
