//! Domain tests for the audit aggregate (state machine, invariants, metrics).
use security_audit::domain::audit::{AuditSession, AuditStatus, Finding, Severity};
use security_audit::domain::error::DomainError;

#[test]
fn create_audit_validates_target() {
    assert!(matches!(AuditSession::new("", "auditor"), Err(DomainError::Validation(_))));
    let s = AuditSession::new("plc-1", "alice").unwrap();
    assert_eq!(s.status, AuditStatus::Pending);
    assert!(s.findings.is_empty());
    assert!(s.started_at.is_none());
}

#[test]
fn state_machine_start_complete() {
    let mut s = AuditSession::new("d", "a").unwrap();
    s.start().unwrap();
    assert_eq!(s.status, AuditStatus::Running);
    assert!(s.started_at.is_some());
    s.complete().unwrap();
    assert_eq!(s.status, AuditStatus::Completed);
    assert!(s.completed_at.is_some());
}

#[test]
fn cannot_complete_without_starting() {
    let mut s = AuditSession::new("d", "a").unwrap();
    assert!(matches!(s.complete(), Err(DomainError::InvalidState(_))));
}

#[test]
fn cannot_start_twice() {
    let mut s = AuditSession::new("d", "a").unwrap();
    s.start().unwrap();
    assert!(matches!(s.start(), Err(DomainError::InvalidState(_))));
}

#[test]
fn add_finding_only_while_running() {
    let mut s = AuditSession::new("d", "a").unwrap();
    let f = Finding::new("d", "R1", "t", Severity::High, 7.0, "desc", "fix").unwrap();
    // Pending -> cannot add
    assert!(matches!(s.add_finding(f.clone()), Err(DomainError::InvalidState(_))));
    s.start().unwrap();
    s.add_finding(f).unwrap();
    assert_eq!(s.findings.len(), 1);
}

#[test]
fn cancel_from_pending_or_running() {
    let mut s = AuditSession::new("d", "a").unwrap();
    s.cancel().unwrap();
    assert_eq!(s.status, AuditStatus::Cancelled);

    let mut s2 = AuditSession::new("d", "a").unwrap();
    s2.start().unwrap();
    s2.cancel().unwrap();
    assert_eq!(s2.status, AuditStatus::Cancelled);

    // cannot cancel a completed audit
    let mut s3 = AuditSession::new("d", "a").unwrap();
    s3.start().unwrap();
    s3.complete().unwrap();
    assert!(matches!(s3.cancel(), Err(DomainError::InvalidState(_))));
}

#[test]
fn finding_validates_cvss_range() {
    assert!(matches!(Finding::new("d", "r", "t", Severity::Low, -1.0, "x", "y"), Err(DomainError::Validation(_))));
    assert!(matches!(Finding::new("d", "r", "t", Severity::Low, 11.0, "x", "y"), Err(DomainError::Validation(_))));
    let f = Finding::new("d", "r", "t", Severity::Critical, 9.8, "x", "y").unwrap();
    assert_eq!(f.severity, Severity::Critical);
}

#[test]
fn severity_from_score_mapping() {
    assert_eq!(Severity::from_score(9.5), Severity::Critical);
    assert_eq!(Severity::from_score(7.5), Severity::High);
    assert_eq!(Severity::from_score(5.0), Severity::Medium);
    assert_eq!(Severity::from_score(2.0), Severity::Low);
    assert_eq!(Severity::from_score(0.0), Severity::Info);
}

#[test]
fn risk_score_scales_with_findings() {
    let mut s = AuditSession::new("d", "a").unwrap();
    s.start().unwrap();
    assert_eq!(s.risk_score(), 0.0);
    s.add_finding(Finding::new("d", "r", "t", Severity::High, 7.0, "x", "y").unwrap()).unwrap();
    s.add_finding(Finding::new("d", "r2", "t2", Severity::Critical, 9.5, "x", "y").unwrap()).unwrap();
    let rs = s.risk_score();
    assert!(rs > 0.0 && rs <= 10.0);
    // critical (rank4+1=5) * 9.5 + high (rank3+1=4) * 7 = 47.5 + 28 = 75.5; /5 = 15.1 -> capped 10
    assert_eq!(rs, 10.0);
}

#[test]
fn count_by_severity() {
    let mut s = AuditSession::new("d", "a").unwrap();
    s.start().unwrap();
    s.add_finding(Finding::new("d", "r", "t", Severity::High, 7.0, "x", "y").unwrap()).unwrap();
    s.add_finding(Finding::new("d", "r2", "t", Severity::High, 7.5, "x", "y").unwrap()).unwrap();
    s.add_finding(Finding::new("d", "r3", "t", Severity::Low, 2.0, "x", "y").unwrap()).unwrap();
    assert_eq!(s.count_by_severity(Severity::High), 2);
    assert_eq!(s.count_by_severity(Severity::Low), 1);
    assert_eq!(s.count_by_severity(Severity::Critical), 0);
}
