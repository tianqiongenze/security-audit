//! audit-cli: command-line tool to run a one-shot audit + compliance report.
use clap::{Parser, Subcommand};
use security_audit::application::AuditService;
use security_audit::infrastructure::repository::SqliteAuditRepository;

#[derive(Parser)]
#[command(name = "audit-cli", version, about = "Industrial security audit CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new audit session for a target.
    Create { #[arg(short, long)] target: String, #[arg(short, long)] auditor: String },
    /// Run a vulnerability scan using comma-separated fingerprints.
    Scan { #[arg(short, long)] id: String, #[arg(short, long)] fingerprints: String },
    /// Finalize an audit session.
    Finalize { #[arg(short, long)] id: String },
    /// Generate an IEC 62443 compliance report.
    Compliance { #[arg(short, long)] id: String, #[arg(short, long)] level: u8 },
    /// List all audit sessions.
    List,
}

fn main() {
    let db_path = std::env::var("AUDIT_DB").unwrap_or_else(|_| "audit.db".to_string());
    let repo = Box::new(SqliteAuditRepository::open(&db_path).expect("db open"));
    let svc = AuditService::new(repo);
    let cli = Cli::parse();

    match cli.command {
        Command::Create { target, auditor } => {
            let s = svc.create_audit(&target, &auditor).unwrap();
            println!("Created audit {} for target '{}' by '{}'", s.id, s.target, s.auditor);
        }
        Command::Scan { id, fingerprints } => {
            let fps: Vec<String> = fingerprints.split(',').map(|s| s.trim().to_string()).collect();
            let findings = svc.run_scan(&id, &fps).unwrap();
            println!("Scan produced {} findings:", findings.len());
            for f in &findings {
                println!("  [{:?}] {} (cvss {}): {}", f.severity, f.rule_id, f.cvss, f.title);
            }
        }
        Command::Finalize { id } => {
            let s = svc.finalize(&id).unwrap();
            println!("Finalized audit {}: risk_score = {:.2}, findings = {}", s.id, s.risk_score(), s.findings.len());
        }
        Command::Compliance { id, level } => {
            let report = svc.compliance_report(&id, level).unwrap();
            println!("Compliance score (SL{}): {:.1}%", report.security_level, report.score);
            for r in &report.results {
                if r.required {
                    println!("  [{}] {} - {}", r.status, r.requirement_id, r.title);
                }
            }
        }
        Command::List => {
            let sessions = svc.list_audits().unwrap();
            if sessions.is_empty() { println!("No audit sessions."); }
            for s in &sessions {
                println!("{} | target={} | {:?} | findings={}", s.id, s.target, s.status, s.findings.len());
            }
        }
    }
}
