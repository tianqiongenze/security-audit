//! Tests for the IEC 62443 compliance checker.
use security_audit::domain::compliance::{evaluate, compliance_score, validate_sl, requirements_catalog};

#[test]
fn catalog_has_requirements_across_levels() {
    let cat = requirements_catalog();
    assert!(cat.iter().any(|r| r.level == 1));
    assert!(cat.iter().any(|r| r.level == 3));
    assert!(cat.iter().all(|r| r.id.starts_with("SR")));
}

#[test]
fn validate_sl_range() {
    assert!(validate_sl(0).is_err());
    assert!(validate_sl(5).is_err());
    assert!(validate_sl(1).is_ok());
    assert!(validate_sl(4).is_ok());
}

#[test]
fn evaluate_marks_unsatisfied_required_as_fail() {
    let results = evaluate(&[], 2); // nothing satisfied
    // SR 1.1 is required level 1 -> applies at SL2 -> FAIL
    let sr11 = results.iter().find(|r| r.requirement_id == "SR 1.1").unwrap();
    assert_eq!(sr11.status, "FAIL");
    assert!(sr11.required);
}

#[test]
fn evaluate_marks_satisfied_as_pass() {
    let satisfied = vec!["SR 1.1".to_string()];
    let results = evaluate(&satisfied, 1);
    let sr11 = results.iter().find(|r| r.requirement_id == "SR 1.1").unwrap();
    assert_eq!(sr11.status, "PASS");
}

#[test]
fn evaluate_marks_higher_level_as_na_at_lower_sl() {
    let results = evaluate(&[], 1);
    // SR 7.1 is level 3 -> N/A at SL1
    let sr71 = results.iter().find(|r| r.requirement_id == "SR 7.1").unwrap();
    assert_eq!(sr71.status, "N/A");
}

#[test]
fn compliance_score_zero_when_nothing_satisfied() {
    let results = evaluate(&[], 2);
    let score = compliance_score(&results);
    assert!(score < 100.0);
}

#[test]
fn compliance_score_100_when_all_satisfied() {
    let cat = requirements_catalog();
    let satisfied: Vec<String> = cat.iter().map(|r| r.id.to_string()).collect();
    let results = evaluate(&satisfied, 3);
    assert_eq!(compliance_score(&results), 100.0);
}
