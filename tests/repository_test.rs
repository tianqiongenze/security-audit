//! Integration tests for the SQLite repository (in-memory).
use security_audit::domain::audit::{AuditSession, Finding, Severity};
use security_audit::infrastructure::repository::{AuditRepository, SqliteAuditRepository};

fn repo() -> SqliteAuditRepository { SqliteAuditRepository::in_memory().unwrap() }

#[test]
fn save_and_get_session() {
    let r = repo();
    let mut s = AuditSession::new("plc-1", "alice").unwrap();
    s.start().unwrap();
    let f = Finding::new("plc-1", "R1", "Default creds", Severity::Critical, 9.8, "desc", "fix").unwrap();
    s.add_finding(f.clone()).unwrap();
    r.save_session(&s).unwrap();

    let got = r.get_session(&s.id).expect("session should exist");
    assert_eq!(got.target, "plc-1");
    assert_eq!(got.auditor, "alice");
    assert_eq!(got.findings.len(), 1);
    assert_eq!(got.findings[0].rule_id, "R1");
    assert_eq!(got.findings[0].severity, Severity::Critical);
}

#[test]
fn get_missing_session_returns_none() {
    let r = repo();
    assert!(r.get_session("nope").is_none());
}

#[test]
fn list_sessions_returns_all() {
    let r = repo();
    let s1 = AuditSession::new("a", "x").unwrap();
    let s2 = AuditSession::new("b", "y").unwrap();
    r.save_session(&s1).unwrap();
    r.save_session(&s2).unwrap();
    let list = r.list_sessions().unwrap();
    assert_eq!(list.len(), 2);
}

#[test]
fn save_session_updates_findings_snapshot() {
    let r = repo();
    let mut s = AuditSession::new("d", "a").unwrap();
    s.start().unwrap();
    s.add_finding(Finding::new("d", "r", "t", Severity::High, 7.0, "x", "y").unwrap()).unwrap();
    r.save_session(&s).unwrap();
    // add another finding and re-save
    s.add_finding(Finding::new("d", "r2", "t2", Severity::Low, 2.0, "x", "y").unwrap()).unwrap();
    r.save_session(&s).unwrap();
    let got = r.get_session(&s.id).unwrap();
    assert_eq!(got.findings.len(), 2);
}

#[test]
fn schema_idempotent_on_reopen() {
    let r1 = repo();
    let mut s = AuditSession::new("d", "a").unwrap();
    s.start().unwrap();
    r1.save_session(&s).unwrap();
    // re-saving the same session (UPSERT) must not error
    r1.save_session(&s).unwrap();
}
