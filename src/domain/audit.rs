//! Audit aggregate root + related value objects.
use chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::domain::error::DomainError;

/// Severity of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            s if s > 0.0 => Severity::Low,
            _ => Severity::Info,
        }
    }
}

/// A single security finding produced by the audit engine.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub id: String,
    pub target: String,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub cvss: f64,
    pub description: String,
    pub remediation: String,
    pub detected_at: DateTime<Utc>,
}

impl Finding {
    pub fn new(target: &str, rule_id: &str, title: &str, severity: Severity,
               cvss: f64, description: &str, remediation: &str) -> Result<Self, DomainError> {
        if target.is_empty() {
            return Err(DomainError::Validation("target is required".into()));
        }
        if rule_id.is_empty() {
            return Err(DomainError::Validation("rule_id is required".into()));
        }
        if !(0.0..=10.0).contains(&cvss) {
            return Err(DomainError::Validation("cvss must be in [0,10]".into()));
        }
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            target: target.to_string(),
            rule_id: rule_id.to_string(),
            title: title.to_string(),
            severity,
            cvss,
            description: description.to_string(),
            remediation: remediation.to_string(),
            detected_at: Utc::now(),
        })
    }
}

/// AuditStatus state machine for an AuditSession aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// AuditSession aggregate root — the central entity of the audit domain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditSession {
    pub id: String,
    pub target: String,
    pub auditor: String,
    pub status: AuditStatus,
    pub findings: Vec<Finding>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl AuditSession {
    pub fn new(target: &str, auditor: &str) -> Result<Self, DomainError> {
        if target.is_empty() {
            return Err(DomainError::Validation("target is required".into()));
        }
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            target: target.to_string(),
            auditor: auditor.to_string(),
            status: AuditStatus::Pending,
            findings: Vec::new(),
            started_at: None,
            completed_at: None,
            created_at: Utc::now(),
        })
    }

    /// Transition Pending -> Running. Enforces the state-machine invariant.
    pub fn start(&mut self) -> Result<(), DomainError> {
        if self.status != AuditStatus::Pending {
            return Err(DomainError::InvalidState(format!(
                "cannot start audit in state {:?}", self.status)));
        }
        self.status = AuditStatus::Running;
        self.started_at = Some(Utc::now());
        Ok(())
    }

    /// Add a finding to the audit (only while Running).
    pub fn add_finding(&mut self, finding: Finding) -> Result<(), DomainError> {
        if self.status != AuditStatus::Running {
            return Err(DomainError::InvalidState(
                "can only add findings while audit is running".into()));
        }
        self.findings.push(finding);
        Ok(())
    }

    /// Transition Running -> Completed.
    pub fn complete(&mut self) -> Result<(), DomainError> {
        if self.status != AuditStatus::Running {
            return Err(DomainError::InvalidState(format!(
                "cannot complete audit in state {:?}", self.status)));
        }
        self.status = AuditStatus::Completed;
        self.completed_at = Some(Utc::now());
        Ok(())
    }

    pub fn cancel(&mut self) -> Result<(), DomainError> {
        match self.status {
            AuditStatus::Pending | AuditStatus::Running => {
                self.status = AuditStatus::Cancelled;
                Ok(())
            }
            _ => Err(DomainError::InvalidState(
                "can only cancel pending or running audits".into())),
        }
    }

    /// Risk score = weighted sum of finding CVSS, capped at 10.
    pub fn risk_score(&self) -> f64 {
        let total: f64 = self.findings.iter()
            .map(|f| f.cvss * (f.severity.rank() as f64 + 1.0))
            .sum();
        (total / 5.0).min(10.0)
    }

    pub fn count_by_severity(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == sev).count()
    }
}
