//! IEC 62443 compliance checker domain service.
use crate::domain::error::DomainError;

/// A single IEC 62443 requirement (subset, for demonstration).
#[derive(Debug, Clone)]
pub struct Requirement {
    pub id: &'static str,
    pub title: &'static str,
    pub level: u8, // Security Level 1..4
    pub required: bool,
}

pub fn requirements_catalog() -> Vec<Requirement> {
    vec![
        Requirement { id: "SR 1.1", title: "Human user identification", level: 1, required: true },
        Requirement { id: "SR 1.2", title: "Software and device identification", level: 1, required: true },
        Requirement { id: "SR 2.1", title: "Authorization enforcement", level: 1, required: true },
        Requirement { id: "SR 3.1", title: "Communication integrity", level: 2, required: true },
        Requirement { id: "SR 4.1", title: "Information confidentiality", level: 2, required: true },
        Requirement { id: "SR 5.1", title: "Network segmentation", level: 2, required: true },
        Requirement { id: "SR 6.1", title: "Audit log accessibility", level: 2, required: true },
        Requirement { id: "SR 7.1", title: "Denial of service protection", level: 3, required: false },
        Requirement { id: "SR 7.2", title: "Resource availability", level: 3, required: false },
    ]
}

/// A compliance result per requirement.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceResult {
    pub requirement_id: String,
    pub title: String,
    pub required: bool,
    pub satisfied: bool,
    pub status: String, // PASS, FAIL, N/A
}

/// Evaluate the set of satisfied requirement IDs against the catalog for a
/// given target security level (SL). Returns per-requirement results + score.
pub fn evaluate(satisfied_ids: &[String], target_sl: u8) -> Vec<ComplianceResult> {
    let cat = requirements_catalog();
    cat.iter().map(|r| {
        // A requirement applies if its SL <= target SL.
        let applies = r.level <= target_sl;
        let satisfied = satisfied_ids.iter().any(|s| s == r.id);
        let status = if !applies {
            "N/A".to_string()
        } else if satisfied {
            "PASS".to_string()
        } else if r.required {
            "FAIL".to_string()
        } else {
            "PASS".to_string() // optional, satisfied or not counts as pass at this level
        };
        ComplianceResult {
            requirement_id: r.id.to_string(),
            title: r.title.to_string(),
            required: r.required && applies,
            satisfied,
            status,
        }
    }).collect()
}

/// Compute the compliance percentage (passed / applicable-required).
pub fn compliance_score(results: &[ComplianceResult]) -> f64 {
    let applicable: Vec<&ComplianceResult> = results.iter()
        .filter(|r| r.required).collect();
    if applicable.is_empty() {
        return 100.0;
    }
    let passed = applicable.iter().filter(|r| r.status == "PASS").count();
    passed as f64 / applicable.len() as f64 * 100.0
}

/// Validate that a target security level is in 1..=4.
pub fn validate_sl(sl: u8) -> Result<u8, DomainError> {
    if (1..=4).contains(&sl) {
        Ok(sl)
    } else {
        Err(DomainError::Validation("security level must be 1..=4".into()))
    }
}
