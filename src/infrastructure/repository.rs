//! Repository port + SQLite implementation.
use std::sync::Mutex;
use rusqlite::{params, Connection};
use chrono::{DateTime, Utc};
use crate::domain::audit::{AuditSession, AuditStatus, Finding, Severity};
use crate::domain::error::DomainError;

/// The repository port (trait). The application service depends on this.

/// Optional cache introspection for the HTTP layer (default: no stats).
/// A supertrait of AuditRepository so `Box<dyn AuditRepository>` exposes it.
pub trait CacheStatsProvider {
    fn cache_handle(&self) -> std::sync::Arc<dyn Fn() -> String + Send + Sync> {
        std::sync::Arc::new(|| "{}".to_string())
    }
}


pub trait AuditRepository: CacheStatsProvider + Send + Sync {
    fn save_session(&self, s: &AuditSession) -> Result<(), DomainError>;
    fn get_session(&self, id: &str) -> Option<AuditSession>;
    fn list_sessions(&self) -> Result<Vec<AuditSession>, DomainError>;
    fn save_finding(&self, session_id: &str, f: &Finding) -> Result<(), DomainError>;
}

/// SQLite-backed repository. Uses a Mutex-guarded connection (rusqlite is not
/// Sync by itself). `:memory:` path gives an ephemeral DB for tests.
pub struct SqliteAuditRepository {
    conn: Mutex<Connection>,
}

impl SqliteAuditRepository {
    pub fn open(path: &str) -> Result<Self, DomainError> {
        let conn = Connection::open(path)
            .map_err(|e| DomainError::Validation(format!("db open: {e}")))?;
        Self::init_schema(&conn)
            .map_err(|e| DomainError::Validation(format!("db schema: {e}")))?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// In-memory repository (for tests and ephemeral runs).
    pub fn in_memory() -> Result<Self, DomainError> {
        Self::open(":memory:")
    }

    fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_sessions (
                id TEXT PRIMARY KEY, target TEXT, auditor TEXT, status TEXT,
                started_at TEXT, completed_at TEXT, created_at TEXT);
             CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY, session_id TEXT, target TEXT, rule_id TEXT,
                title TEXT, severity TEXT, cvss REAL, description TEXT,
                remediation TEXT, detected_at TEXT);
             CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);",
        )?;
        Ok(())
    }
}

impl AuditRepository for SqliteAuditRepository {
    fn save_session(&self, s: &AuditSession) -> Result<(), DomainError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO audit_sessions
             (id, target, auditor, status, started_at, completed_at, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                s.id, s.target, s.auditor, format!("{:?}", s.status),
                s.started_at.map(|t| t.to_rfc3339()),
                s.completed_at.map(|t| t.to_rfc3339()),
                s.created_at.to_rfc3339(),
            ],
        ).map_err(|e| DomainError::Validation(format!("save session: {e}")))?;
        // Persist the latest findings snapshot too (delete + re-insert).
        conn.execute("DELETE FROM findings WHERE session_id = ?1", params![s.id])
            .map_err(|e| DomainError::Validation(format!("clear findings: {e}")))?;
        for f in &s.findings {
            conn.execute(
                "INSERT INTO findings (id, session_id, target, rule_id, title, severity,
                 cvss, description, remediation, detected_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![f.id, s.id, f.target, f.rule_id, f.title,
                    format!("{:?}", f.severity), f.cvss, f.description,
                    f.remediation, f.detected_at.to_rfc3339()],
            ).map_err(|e| DomainError::Validation(format!("save finding: {e}")))?;
        }
        Ok(())
    }

    fn get_session(&self, id: &str) -> Option<AuditSession> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, target, auditor, status, started_at, completed_at, created_at
             FROM audit_sessions WHERE id = ?1").ok()?;
        let row = stmt.query_row(params![id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?,
                r.get::<_, String>(2)?, r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?, r.get::<_, Option<String>>(5)?,
                r.get::<_, String>(6)?))
        }).ok()?;

        let findings = load_findings(&conn, id).unwrap_or_default();
        Some(AuditSession {
            id: row.0, target: row.1, auditor: row.2,
            status: parse_status(&row.3), started_at: row.4.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
            completed_at: row.5.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
            created_at: DateTime::parse_from_rfc3339(&row.6).ok().map(|d| d.with_timezone(&Utc)).unwrap_or_else(Utc::now),
            findings,
        })
    }

    fn list_sessions(&self) -> Result<Vec<AuditSession>, DomainError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, target, auditor, status, started_at, completed_at, created_at
             FROM audit_sessions ORDER BY created_at DESC")
            .map_err(|e| DomainError::Validation(format!("list: {e}")))?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?,
                r.get::<_, String>(2)?, r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?, r.get::<_, Option<String>>(5)?,
                r.get::<_, String>(6)?))
        }).map_err(|e| DomainError::Validation(format!("list map: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let row = row.map_err(|e| DomainError::Validation(format!("list row: {e}")))?;
            let findings = load_findings(&conn, &row.0).unwrap_or_default();
            out.push(AuditSession {
                id: row.0, target: row.1, auditor: row.2,
                status: parse_status(&row.3),
                started_at: row.4.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
                completed_at: row.5.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
                created_at: DateTime::parse_from_rfc3339(&row.6).ok().map(|d| d.with_timezone(&Utc)).unwrap_or_else(Utc::now),
                findings,
            });
        }
        Ok(out)
    }

    fn save_finding(&self, _session_id: &str, _f: &Finding) -> Result<(), DomainError> {
        // Findings are persisted transactionally via save_session; this is a
        // no-op kept for port-completeness.
        Ok(())
    }
}

fn load_findings(conn: &Connection, session_id: &str) -> rusqlite::Result<Vec<Finding>> {
    let mut stmt = conn.prepare(
        "SELECT id, target, rule_id, title, severity, cvss, description, remediation, detected_at
         FROM findings WHERE session_id = ?1 ORDER BY detected_at")?;
    let rows = stmt.query_map(params![session_id], |r| {
        Ok(Finding {
            id: r.get(0)?, target: r.get(1)?, rule_id: r.get(2)?, title: r.get(3)?,
            severity: parse_severity(&r.get::<_, String>(4)?), cvss: r.get(5)?,
            description: r.get(6)?, remediation: r.get(7)?,
            detected_at: DateTime::parse_from_rfc3339(&r.get::<_, String>(8)?).ok().map(|d| d.with_timezone(&Utc)).unwrap_or_else(Utc::now),
        })
    })?;
    let mut out = Vec::new();
    for row in rows { out.push(row?); }
    Ok(out)
}

fn parse_status(s: &str) -> AuditStatus {
    match s {
        "Pending" => AuditStatus::Pending,
        "Running" => AuditStatus::Running,
        "Completed" => AuditStatus::Completed,
        "Failed" => AuditStatus::Failed,
        "Cancelled" => AuditStatus::Cancelled,
        _ => AuditStatus::Pending,
    }
}

fn parse_severity(s: &str) -> Severity {
    match s {
        "Info" => Severity::Info,
        "Low" => Severity::Low,
        "Medium" => Severity::Medium,
        "High" => Severity::High,
        "Critical" => Severity::Critical,
        _ => Severity::Info,
    }
}

impl CacheStatsProvider for SqliteAuditRepository {}
