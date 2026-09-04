//! Industrial Security Audit System (DDD).
//!
//! Layers:
//! - `domain`: pure entities, value objects, domain services (audit, vuln, compliance)
//! - `application`: use cases (AuditService) orchestrating domain + repository port
//! - `infrastructure`: SQLite repository + Actix-Web REST adapter

pub mod domain;
pub mod application;
pub mod infrastructure;
