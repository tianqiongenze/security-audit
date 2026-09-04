# 工业安全审计系统 (Industrial Security Audit System)

> Student: `student-rust` — Language: Rust 1.98 + Actix-Web
> Architecture: Domain-Driven Design (DDD)

A security audit platform for industrial control systems (ICS) that runs
vulnerability scans against a signature database, evaluates IEC 62443
compliance, persists audit sessions and findings to SQLite, and exposes the
whole lifecycle through an Actix-Web REST API and a `clap` CLI.

## Architecture (DDD)

```
   Presentation         Application            Domain              Infrastructure
   ┌────────────┐      ┌──────────────┐      ┌──────────────┐      ┌──────────────────┐
   │ actix HTTP │ ──► │ AuditService │ ──► │ AuditSession │ ──► │ SqliteAuditRepo  │
   │ clap CLI    │      │ (use cases)  │      │ Finding       │      │ rusqlite         │
   └────────────┘      └──────────────┘      │ Vuln scanner  │      └──────────────────┘
                                               │ IEC62443 check  │
                                               └──────────────┘
   Domain depends on nothing infrastructural; infra implements the repository trait.
```

## Modules
- `src/domain/` — `AuditSession` aggregate, `Finding`/`Severity` value objects,
  vulnerability signature scanner, IEC 62443 compliance checker, domain errors.
- `src/application/` — `AuditService` use cases (create → scan → finalize → report).
- `src/infrastructure/repository.rs` — `AuditRepository` trait + SQLite impl.
- `src/infrastructure/http.rs` — Actix-Web REST adapter + error mapping.
- `src/bin/cli.rs` — `audit-cli` (clap) for one-shot audits.
- `src/bin/server.rs` — `audit-server` REST API on :8080.

## Build & Test
```bash
cargo build        # build lib + 2 binaries
cargo test         # run the full test suite
cargo run --bin audit-cli -- create -t plc-1 -a alice
cargo run --bin audit-cli -- scan -i <id> -f hmi-default-creds
cargo run --bin audit-cli -- compliance -i <id> -l 2
cargo run --bin audit-server    # REST API on :8080
```
The bundled rusqlite feature compiles SQLite from source, so no system lib is needed.
Crates fetch from the USTC mirror (see `.cargo/config.toml`).

## REST API
```
POST   /api/v1/audits                      {target, auditor}        -> session
GET    /api/v1/audits                                               -> [session]
POST   /api/v1/audits/{id}/scan            {fingerprints[]}         -> [finding]
POST   /api/v1/audits/{id}/finalize                                  -> session
POST   /api/v1/audits/{id}/compliance     {security_level}         -> report
GET    /api/v1/health                                               -> {status}
```

See `docs/SDD.md` for the full Software Design Document.
