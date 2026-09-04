//! Application service tests (use case orchestration with in-memory repo).
use security_audit::application::AuditService;
use security_audit::infrastructure::repository::{AuditRepository, SqliteAuditRepository};
use security_audit::domain::audit::AuditStatus;

fn svc() -> AuditService {
    AuditService::new(Box::new(SqliteAuditRepository::in_memory().unwrap()))
}

#[test]
fn full_audit_lifecycle() {
    let svc = svc();
    // create
    let session = svc.create_audit("plc-1", "alice").unwrap();
    assert_eq!(session.status, AuditStatus::Running);
    // scan with known fingerprints
    let findings = svc.run_scan(&session.id, &["hmi-default-creds".to_string()]).unwrap();
    assert_eq!(findings.len(), 1);
    // finalize
    let final_session = svc.finalize(&session.id).unwrap();
    assert_eq!(final_session.status, AuditStatus::Completed);
    assert_eq!(final_session.findings.len(), 1);
    // list
    let list = svc.list_audits().unwrap();
    assert!(list.len() >= 1);
}

#[test]
fn compliance_report_for_clean_audit_is_full_score() {
    let svc = svc();
    let session = svc.create_audit("plc-1", "alice").unwrap();
    let _ = svc.run_scan(&session.id, &[]).unwrap(); // no fingerprints -> no findings
    let _ = svc.finalize(&session.id).unwrap();
    let report = svc.compliance_report(&session.id, 2).unwrap();
    assert_eq!(report.security_level, 2);
    assert_eq!(report.score, 100.0); // zero findings -> zero gaps -> full score
    assert!(report.results.iter().all(|r| r.status != "FAIL"));
}

#[test]
fn compliance_report_for_vulnerable_audit_maps_gaps() {
    let svc = svc();
    let session = svc.create_audit("plc-1", "alice").unwrap();
    let findings = svc.run_scan(&session.id, &[
        "hmi-default-creds".to_string(),   // Critical
        "modbus-plaintext".to_string(),    // High
    ]).unwrap();
    assert_eq!(findings.len(), 2);
    let _ = svc.finalize(&session.id).unwrap();
    let report = svc.compliance_report(&session.id, 2).unwrap();
    assert!(report.score < 100.0); // Critical/High findings -> FR1 gaps
    assert_eq!(report.gap_counts.critical_high, 2);
    assert!(report.results.iter().any(|r| r.status == "FAIL"));
    assert!(report.results.iter().any(|r| r.requirement_id == "SR 1.1" && r.status == "FAIL"));
}

#[test]
fn compliance_rejects_invalid_sl() {
    let svc = svc();
    let session = svc.create_audit("plc-1", "alice").unwrap();
    assert!(svc.compliance_report(&session.id, 5).is_err());
}

#[test]
fn finalize_missing_session_errors() {
    let svc = svc();
    assert!(svc.finalize("ghost").is_err());
}
