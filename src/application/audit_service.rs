//! Application layer: orchestrates the audit use-cases over the repository port.
use crate::domain::audit::{AuditSession, Finding, Severity};
use crate::domain::compliance::{evaluate, validate_sl, compliance_score, requirements_catalog, ComplianceResult};
use crate::domain::error::DomainError;
use crate::domain::vulnerability::scan;
use crate::infrastructure::repository::AuditRepository;

pub struct AuditService {
    repo: Box<dyn AuditRepository>,
}

impl AuditService {
    pub fn new(repo: Box<dyn AuditRepository>) -> Self {
        Self { repo }
    }

    /// Create and persist a new audit session.
    pub fn create_audit(&self, target: &str, auditor: &str) -> Result<AuditSession, DomainError> {
        let mut session = AuditSession::new(target, auditor)?;
        session.start()?;
        self.repo.save_session(&session)?;
        Ok(session)
    }

    /// Fetch a single audit session by id.
    pub fn get_audit(&self, session_id: &str) -> Result<AuditSession, DomainError> {
        self.repo.get_session(session_id)
            .ok_or_else(|| DomainError::NotFound(format!("session {}", session_id)))
    }

    /// Run a vulnerability scan against a target's fingerprints and attach findings.
    pub fn run_scan(&self, session_id: &str, fingerprints: &[String]) -> Result<Vec<Finding>, DomainError> {
        let mut session = self.repo.get_session(session_id)
            .ok_or_else(|| DomainError::NotFound(format!("session {}", session_id)))?;
        let findings = scan(&session.target, fingerprints)?;
        for f in &findings {
            session.add_finding(f.clone())?;
            self.repo.save_finding(session_id, f)?;
        }
        self.repo.save_session(&session)?;
        Ok(findings)
    }

    /// Complete the audit and return the final session.
    pub fn finalize(&self, session_id: &str) -> Result<AuditSession, DomainError> {
        let mut session = self.repo.get_session(session_id)
            .ok_or_else(|| DomainError::NotFound(format!("session {}", session_id)))?;
        session.complete()?;
        self.repo.save_session(&session)?;
        Ok(session)
    }

    /// IEC 62443 compliance report: each SL requirement is satisfied when no
    /// finding of that severity band (mapped per zone-and-conduit model) is open.
    pub fn compliance_report(&self, session_id: &str, target_sl: u8) -> Result<ComplianceReport, DomainError> {
        validate_sl(target_sl)?;
        let session = self.repo.get_session(session_id)
            .ok_or_else(|| DomainError::NotFound(format!("session {}", session_id)))?;

        // Map finding severities onto IEC 62443 requirement IDs:
        // Critical/High -> FR1 (identification & access control) gaps,
        // Medium        -> FR3 (system integrity) gaps,
        // Low           -> FR7 (resource availability) gaps.
        let mut crit_or_high = 0usize;
        let mut medium = 0usize;
        let mut low = 0usize;
        // Full catalog: a requirement is satisfied unless findings in its
        // severity band exist (evidence-based gap model for the demo rules).
        let all: Vec<&str> = requirements_catalog().iter().map(|r| r.id).collect();
        let mut gaps: Vec<String> = Vec::new();
        for f in &session.findings {
            match f.severity {
                Severity::Critical | Severity::High => {
                    crit_or_high += 1;
                    for id in ["SR 1.1", "SR 1.2", "SR 2.1"] { gaps.push(id.into()); }
                }
                Severity::Medium => {
                    medium += 1;
                    for id in ["SR 3.1", "SR 4.1", "SR 5.1"] { gaps.push(id.into()); }
                }
                Severity::Low => {
                    low += 1;
                    for id in ["SR 6.1", "SR 7.1", "SR 7.2"] { gaps.push(id.into()); }
                }
                Severity::Info => {}
            }
        }
        let unique: std::collections::HashSet<String> = gaps.into_iter().collect();
        let satisfied: Vec<String> = all.into_iter()
            .map(String::from)
            .filter(|r| !unique.contains(r))
            .collect();

        let results = evaluate(&satisfied, target_sl);
        let score = compliance_score(&results);
        Ok(ComplianceReport {
            session_id: session.id.clone(),
            target: session.target.clone(),
            security_level: target_sl,
            score,
            results,
            risk_score: session.risk_score(),
            findings_by_severity: SeveritySummary::from_session(&session),
            gap_counts: GapCounts { critical_high: crit_or_high, medium, low },
        })
    }

    pub fn list_audits(&self) -> Result<Vec<AuditSession>, DomainError> {
        self.repo.list_sessions()
    }
}

#[derive(Debug, serde::Serialize)]
pub struct ComplianceReport {
    pub session_id: String,
    pub target: String,
    pub security_level: u8,
    pub score: f64,
    pub results: Vec<ComplianceResult>,
    pub risk_score: f64,
    pub findings_by_severity: SeveritySummary,
    pub gap_counts: GapCounts,
}

#[derive(Debug, serde::Serialize)]
pub struct GapCounts {
    pub critical_high: usize,
    pub medium: usize,
    pub low: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct SeveritySummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SeveritySummary {
    pub fn from_session(s: &AuditSession) -> Self {
        let mut sum = SeveritySummary { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        for f in &s.findings {
            match f.severity {
                Severity::Critical => sum.critical += 1,
                Severity::High => sum.high += 1,
                Severity::Medium => sum.medium += 1,
                Severity::Low => sum.low += 1,
                Severity::Info => sum.info += 1,
            }
        }
        sum
    }
}
