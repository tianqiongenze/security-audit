//! audit-server: Actix-Web REST API backed by CockroachDB (security_audit DB)
//! with a two-level cache (L1 in-process 30s + L2 Redis 300s).
use security_audit::infrastructure::http::run_server;
use security_audit::domain::error::DomainError;
use security_audit::infrastructure::repository::{AuditRepository, CacheStatsProvider};
use security_audit::domain::audit::{AuditSession, Finding};
use std::sync::{Arc, Mutex};

/// Lazily-initializing wrapper so the blocking CRDB connection is opened
/// outside the actix runtime on first request (web::block handles offload).
pub struct LazyCrdbRepo {
    inner: Mutex<Option<Arc<security_audit::infrastructure::crdb_repository::CrdbAuditRepository>>>,
    cache: Arc<security_audit::infrastructure::cache::TwoLevelCache>,
}

impl LazyCrdbRepo {
    pub fn new() -> Self {
        Self { inner: Mutex::new(None),
               cache: Arc::new(security_audit::infrastructure::cache::TwoLevelCache::new()) }
    }
    fn repo(&self) -> Result<Arc<security_audit::infrastructure::crdb_repository::CrdbAuditRepository>, DomainError> {
        let mut guard = self.inner.lock().unwrap();
        if guard.is_none() {
            *guard = Some(Arc::new(security_audit::infrastructure::crdb_repository::CrdbAuditRepository::open()?));
        }
        Ok(guard.as_ref().unwrap().clone())
    }
    pub fn cache(&self) -> Arc<security_audit::infrastructure::cache::TwoLevelCache> { self.cache.clone() }
}

impl AuditRepository for LazyCrdbRepo {
    fn save_session(&self, s: &AuditSession) -> Result<(), DomainError> {
        let r = self.repo()?.save_session(s);
        // write-through: refresh the per-session and list caches
        if r.is_ok() {
            if let Ok(json) = serde_json::to_string(s) {
                self.cache.put(&format!("session:{}", s.id), &json);
            }
            self.cache.invalidate("list:all");
        }
        r
    }
    fn get_session(&self, id: &str) -> Option<AuditSession> {
        // L1/L2
        if let Some(json) = self.cache.get(&format!("session:{id}")) {
            if let Ok(s) = serde_json::from_str::<AuditSession>(&json) {
                if s.id == id { return Some(s); }
            }
        }
        // CRDB + fill cache
        let s = self.repo().ok()?.get_session(id)?;
        if let Ok(json) = serde_json::to_string(&s) {
            self.cache.put(&format!("session:{id}"), &json);
        }
        Some(s)
    }
    fn list_sessions(&self) -> Result<Vec<AuditSession>, DomainError> {
        if let Some(json) = self.cache.get("list:all") {
            if let Ok(v) = serde_json::from_str::<Vec<AuditSession>>(&json) {
                return Ok(v);
            }
        }
        let v = self.repo()?.list_sessions()?;
        if let Ok(json) = serde_json::to_string(&v) {
            self.cache.put("list:all", &json);
        }
        Ok(v)
    }
    fn save_finding(&self, sid: &str, f: &Finding) -> Result<(), DomainError> {
        let r = self.repo()?.save_finding(sid, f);
        if r.is_ok() {
            self.cache.invalidate(&format!("session:{sid}"));
            self.cache.invalidate("list:all");
        }
        r
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    let repo = Box::new(LazyCrdbRepo::new());
    log::info!("starting security-audit server on :8080 (CRDB + L1/L2 cache backend)");
    run_server(repo, "0.0.0.0:8080").await
}

impl CacheStatsProvider for LazyCrdbRepo {
    fn cache_handle(&self) -> std::sync::Arc<dyn Fn() -> String + Send + Sync> {
        let cache = self.cache.clone();
        std::sync::Arc::new(move || cache.stats())
    }
}
