//! Domain errors.
use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum DomainError {
    #[error("entity not found: {0}")]
    NotFound(String),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("invalid state transition: {0}")]
    InvalidState(String),
    #[error("policy violation: {0}")]
    Policy(String),
}
