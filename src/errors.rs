use thiserror::Error;

/// Errors returned by Sangria
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SangriaError {
    /// returned if the supplied row or col in (row,col,val) tuple is out of range
    #[error("Index is out of bounds")]
    IndexOutOfBounds,
}
