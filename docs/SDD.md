# Software Design Document (SDD)
## 工业安全审计系统 — Industrial Security Audit System

**Project:** Security Audit &nbsp; **Student:** student-rust &nbsp;
**Language:** Rust 1.98 (edition 2021) &nbsp; **Framework:** Actix-Web 4 &nbsp;
**Architecture:** Domain-Driven Design (DDD)

> AI-assisted design: the DDD aggregate boundaries and IEC 62443 requirement
> subset were validated against the `qwen2.5-coder:7b` model via the platform
> LiteLLM gateway. Implementation and tests are hand-written.

---

## 1. Introduction

### 1.1 Purpose
A system to audit the security posture of industrial control system (ICS)
assets: it runs a vulnerability scan against a curated signature database,
evaluates compliance with a subset of IEC 62443, and produces a risk-scored
report. Audit sessions and findings are persisted to SQLite and served via a
REST API and CLI.

### 1.2 Scope
Inbound: target identifier + device fingerprints (banner/config strings).
Processing: signature matching (vulnerability), requirement evaluation
(compliance), stateful audit lifecycle, risk scoring, persistence. Outbound:
REST API, CLI report, JSON compliance report. Out of scope: live network
scanning (Nmap-style) and an authenticated multi-tenant backend.

### 1.3 Definitions
- **Aggregate root** — `AuditSession`; the consistency boundary for findings.
- **CVSS** — Common Vulnerability Scoring System (0–10).
- **IEC 62443** — industrial communications network security standard.
- **SL** — Security Level (1–4) in IEC 62443 terminology.
- **Repository trait** — the persistence port (Rust trait).

---

## 2. Architecture (DDD)

### 2.1 Layered Structure
```
[ Presentation: actix-web, clap CLI ] ─►
[ Application: AuditService use cases ] ─►
[ Domain: AuditSession, Finding, scanner, compliance ]   ◄── Repository trait (port)
[ Infrastructure: SqliteAuditRepository (rusqlite) ]     (adapter impl)
```
The domain layer is pure: it depends on no infrastructure crate. The
application layer depends on the domain and on the `AuditRepository` trait
(defined in infrastructure but abstract). Infrastructure implements the trait.
This is the classic DDD dependency inversion — high-level policy does not
depend on low-level details.

### 2.2 Aggregates & Value Objects

| Type | Kind | Notes |
|------|------|-------|
| `AuditSession` | Aggregate root | owns `Finding`s; enforces state machine |
| `Finding` | Entity (within AuditSession) | id, severity, cvss, rule, remediation |
| `Severity` | Value object (enum) | Info/Low/Medium/High/Critical, rank + from_score |
| `AuditStatus` | Value object (enum) | Pending/Running/Completed/Failed/Cancelled |
| `ComplianceResult` | Value object | per-requirement PASS/FAIL/N/A |

### 2.3 Domain Services
- **Vulnerability scanner** (`vulnerability.rs`) — a signature DB + `scan()`
  pure function mapping target fingerprints to `Finding`s.
- **Compliance checker** (`compliance.rs`) — IEC 62443 requirement catalog,
  `evaluate()` for per-requirement status, `compliance_score()` percentage.

---

## 3. Audit Lifecycle (State Machine)

```
   create()              start()           add_finding()*         complete()
   ──────► Pending ──────► Running ───────────────────────► Completed
              │                │
              └─cancel()─► Cancelled   ◄── cancel()
```
Invariants (enforced in `AuditSession`):
- `start()` only from Pending.
- `add_finding()` only while Running.
- `complete()` only from Running.
- `cancel()` only from Pending or Running.

---

## 4. IEC 62443 Compliance Model

A catalog of System Requirements (SR 1.1 … SR 7.2) each tagged with a Security
Level (1–3 in this subset) and `required` flag. Given a target SL, a
requirement *applies* when its level ≤ target SL. Status:
- **N/A** when the requirement's level > target SL.
- **PASS** when required+applies and satisfied, or optional (regardless).
- **FAIL** when required+applies and not satisfied.

Compliance score = passed / applicable-required × 100.

---

## 5. Risk Scoring
`AuditSession::risk_score()` = Σ(cvss × (severity_rank + 1)) / 5, capped at 10.
Severity rank: Info=0, Low=1, Medium=2, High=3, Critical=4. The (rank+1)
weighting makes a Critical finding dominate the score, mirroring qualitative
risk matrices used in OT security.

---

## 6. REST API & CLI

### 6.1 REST
Actix-Web routes under `/api/v1`. Domain errors map to HTTP codes via a
`ResponseError` impl (404 NotFound, 400 Validation, 409 InvalidState, 422
Policy). JSON via serde.

### 6.2 CLI
`clap` derive: `create | scan | finalize | compliance | list`. The CLI reuses
the same `AuditService` as the HTTP adapter, demonstrating the DDD principle
that application logic is presentation-agnostic.

---

## 7. Sequence Diagram

```
CLI/HTTP ─► AuditService.create_audit(target, auditor)
             │ AuditSession::new + start (domain)
             │ repo.save_session                [SQLite]
             └─► session (Running)
CLI/HTTP ─► AuditService.run_scan(id, fingerprints)
             │ repo.get_session
             │ vulnerability::scan(target, fps)  [domain service]
             │ session.add_finding (invariant)
             │ repo.save_finding + repo.save_session
             └─► [Finding]
CLI/HTTP ─► AuditService.finalize(id)
             │ session.complete (state machine)
             │ repo.save_session
             └─► session (Completed)
CLI/HTTP ─► AuditService.compliance_report(id, sl)
             │ compliance::validate_sl + evaluate + score
             └─► ComplianceReport (JSON)
```

---

## 8. Test Strategy

Tests are integration tests in `tests/` exercising the public API:

| File | Tests | Covers |
|------|-------|--------|
| domain_audit_test.rs | 9 | aggregate state machine, invariants, risk score |
| vulnerability_test.rs | 5 | signature DB, scan matching, validation |
| compliance_test.rs | 6 | catalog, SL validation, PASS/FAIL/N/A, score |
| repository_test.rs | 5 | SQLite save/get/list/update (in-memory) |
| application_test.rs | 4 | full lifecycle + compliance + error cases |

Run: `cargo test`. The repository tests use `:memory:` SQLite for isolation.

---

## 9. Non-Functional Requirements
- **Memory safety:** Rust's ownership model eliminates data races; the
  SQLite connection is `Mutex`-guarded.
- **Performance:** zero-cost abstractions; actix-web is a high-throughput
  async runtime.
- **Portability:** bundled rusqlite compiles SQLite from source — no system
  library dependency. The USTC crate mirror handles air-gapped builds.
- **Extensibility:** new vulnerability rules are added to `signature_db()`;
  new IEC requirements to `requirements_catalog()` — no architectural change.

## 10. Revision History
| Version | Date | Author | Notes |
|---------|------|--------|-------|
| 1.0 | 2026-08-31 | student-rust | Initial SDD, DDD, Actix-Web + rusqlite + clap |
---

## 10. Design Rationale & Trade-offs

### 10.1 Why DDD aggregate boundaries
The `AuditSession` is the aggregate root and the only entry point for adding
`Finding`s. This boundary is what makes the state-machine invariants
*unbreakable*: `add_finding` is only callable through the aggregate, which
rejects it unless the session is `Running`. A naive design that let callers
append findings directly to a collection would scatter the invariant checks
across every call site; the aggregate centralises them and the compiler
enforces visibility (the `findings` field is `pub` but mutation is meant to
go through methods). The repository persists whole aggregates, so the on-disk
state can never represent an illegal combination (e.g. findings attached to a
`Pending` session).

### 10.2 Repository trait (port) + concrete SQLite adapter
`AuditRepository` is a Rust trait (the port); `SqliteAuditRepository` is the
adapter. The application service holds a `Box<dyn AuditRepository>`, so it is
constructed against any implementation and tested against the in-memory one.
This is dependency inversion in DDD terms: high-level policy (the use cases)
does not depend on low-level details (rusqlite); both depend on the trait
abstraction. The trait is `Send + Sync` and the connection is `Mutex`-guarded
because rusqlite's `Connection` is `!Sync` — the mutex is the adapter's
concern, invisible to the application.

### 10.3 `bundled` rusqlite feature
The `rusqlite` dependency uses the `bundled` feature, which compiles the SQLite
C amalgamation from source into the binary. This eliminates any runtime
dependency on a system `libsqlite3` — crucial in an air-gapped or minimal
container image where the shared library may be absent. The cost is a longer
initial build (one-time, cached) and a slightly larger binary, both acceptable
for a server that must be relocatable.

### 10.4 Two presentation adapters sharing one application service
The Actix-Web REST adapter and the `clap` CLI both construct an
`AuditService` from the same repository trait and call the same use-case
methods (`create_audit`, `run_scan`, `finalize`, `compliance_report`). This is
the DDD principle that application logic is presentation-agnostic, made
concrete: a new presentation (a gRPC service, a cron job) is added by writing
a new thin adapter, with zero changes to domain or application code. The
`AuditError` → HTTP `ResponseError` mapping is the only HTTP-specific logic,
isolated in the adapter.

### 10.5 IEC 62443 subset modelled declaratively
`requirements_catalog()` returns a static table of SR (System Requirement)
entries each tagged with a level and a `required` flag. Compliance evaluation
is pure set logic: a requirement applies when its level ≤ target SL, is
`FAIL` when required+applicable+unsatisfied, and `N/A` when the level exceeds
the target SL. This declarative model means a security engineer updates the
catalog (a data change) to adopt new requirements — no algorithm change. The
score is simply passed/applicable-required, an honest percentage that cannot
be gamed by counting optional requirements.

---

## 11. Quality Attributes (NFRs) in detail

| Attribute | Strategy |
|-----------|----------|
| Memory safety | Rust ownership; `Mutex<Connection>` for `!Sync` types; no `unsafe` in app code |
| Performance | Zero-cost abstractions; actix-web async runtime; in-process SQLite |
| Portability | `bundled` rusqlite compiles SQLite from source; USTC mirror for air-gapped builds |
| Extensibility | New vuln rules = data in `signature_db()`; new IEC reqs = data in `requirements_catalog()` |
| Correctness | Aggregate invariants enforced by the type system and state-machine methods |

---

## 12. Glossary
- **Aggregate root** — the consistency boundary; here `AuditSession`, the only
  way to mutate its `Finding`s.
- **Repository trait** — the persistence port (Rust trait) that adapters implement.
- **CVSS** — Common Vulnerability Scoring System, 0.0–10.0.
- **IEC 62443** — industrial automation & control systems security standard.
- **SL (Security Level)** — IEC 62443's 1–4 risk tiers; this system models 1–3.
- **DDD** — Domain-Driven Design; modelling software around a rich domain core.
---

## 13. Operational Runbook

### 13.1 Startup sequence
1. `cargo run --bin audit-server` opens (or creates) the SQLite database at
   `AUDIT_DB` (default `audit.db`) and binds Actix-Web to `0.0.0.0:8080`.
2. Create an audit: `POST /api/v1/audits {target, auditor}` returns a
   session id in `Running` state. 3. Run a scan:
   `POST /api/v1/audits/{id}/scan {fingerprints[]}` attaches findings.
4. Finalize: `POST /api/v1/audits/{id}/finalize` transitions to `Completed`.
5. Report: `POST /api/v1/audits/{id}/compliance {security_level}` returns
   the JSON compliance report. The CLI mirrors these steps one-for-one.

### 13.2 Failure modes
- **Invalid state transition**: the aggregate returns `InvalidState`, mapped
  to HTTP 409 so a client retrying `finalize` on an already-completed audit
  gets a clear conflict signal.
- **Missing session**: `NotFound` maps to 404; the client can distinguish
  "never existed" from "wrong state".
- **SQLite locked**: under heavy concurrent writes the mutex serialises
  access; a production deployment with write contention would shard by
  target or move to PostgreSQL behind the same trait.

### 13.3 Schema evolution
The repository uses `CREATE TABLE IF NOT EXISTS`, so the first run of a new
binary against an existing DB is safe for additive changes. Destructive
migrations (column drops, type changes) are out of scope and would be handled
by a migration tool in production — the trait boundary keeps that a
repository-internal concern.

---

## 14. Alternatives Considered
- **SQLite via a query builder (diesel/sqlx)**: rejected in favour of raw
  `rusqlite` to keep the dependency footprint minimal in an air-gapped build;
  the queries are simple enough that the ergonomics loss is small.
- **Stored findings as a separate aggregate**: rejected; findings are always
  mutated through their parent `AuditSession`, so modelling them as part of
  the same aggregate keeps the invariant (findings only on Running sessions)
  locally enforceable.
- **Async repository**: the application service is synchronous because audit
  operations are short and consistency-critical; Actix-Web's handlers are
  async but delegate to blocking repository calls via the standard threadpool
  where needed, keeping the domain code straightforwardly synchronous.

---

## 15. Extending the Vulnerability Feed
`signature_db()` is a hand-curated `Vec<VulnerabilityRule>` for demonstration.
In production this is loaded at startup from an external feed (a JSON/YAML
file or a CVE database) into the same `Vec<VulnerabilityRule>` shape — the
`scan()` function is feed-agnostic and unchanged. New rules simply extend the
vector; the match predicate (`match_substr`) is intentionally simple (a
substring fingerprint) so that a rule can be authored without code. A future
enhancement is a structured match DSL (regex or field-equality) over a
key-value fingerprint map, again without touching the scan orchestration.
---

## 16. Lifecycle & Deployment
`audit-server` is a single binary; `audit-cli` is a single binary. Both
link SQLite statically via the `bundled` feature, so each is a
self-contained executable with no shared-library dependency — ideal for a
distroless container or a bare-metal edge device. In the cluster the server
runs as a Deployment exposing `:8080`; SQLite persistence uses a
`PersistentVolumeClaim` so audit history survives pod restarts. For
multi-replica availability, the repository trait would be re-implemented
over PostgreSQL (a one-adapter change) because a single SQLite file cannot
serve concurrent writers across pods.
