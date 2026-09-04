//! Domain layer (DDD): core entities, value objects & domain services.
//! Depends only on std + chrono + thiserror + uuid — no infra concerns.

pub mod audit;
pub mod vulnerability;
pub mod compliance;
pub mod error;

pub use audit::*;
pub use vulnerability::*;
pub use compliance::*;
pub use error::DomainError;
