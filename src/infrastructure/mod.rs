//! Infrastructure layer: persistence (rusqlite) + HTTP (actix) adapters.
pub mod repository;
pub mod http;
pub mod crdb_repository;
pub mod cache;
