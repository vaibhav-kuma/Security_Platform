# Trust Boundaries

Every boundary lists what crosses it, the controls, and representative failure modes. Security rules derive from `CLAUDE.md` and phases 4, 7–9, 12–14, 16, 18–19.

## B1. Browser ↔ API
- **Crosses:** credentials, tokens, project/scope/target data, WebSocket events.
- **Controls:** Argon2-hashed passwords; access/refresh token handling; secure session management; secure cookies; CSRF protection where applicable; secure headers; login rate limiting; account abuse protection; route protection + auth-state handling client-side (UX only — never a control).
- **Failure modes tested in Phase 4:** authentication bypass, session issues, token validation errors, CSRF.

## B2. API ↔ PostgreSQL (authorization boundary)
- **Crosses:** every CRUD request, scoped by org/project.
- **Controls:** all authorization decisions server-side; RBAC (owner/admin/researcher/viewer) with fine-grained permissions; org isolation so no cross-org access via direct object manipulation or guessed identifiers; structured errors (`FORBIDDEN_RESOURCE_ACCESS`) instead of data leakage.
- **Failure modes tested:** RBAC failures, IDOR-style access control problems, privilege escalation.

## B3. API ↔ Redis / Worker queue
- **Crosses:** ScanJobs.
- **Controls:** job payload carries project context + **immutable scope snapshot** + execution policy + testing profile + rate limits + security metadata; queue-level per-project/per-target rate limiting; cancellation/pause propagation; job recovery without scope drift.
- **Invariant:** a worker may act only on what the job payload authorizes; scope is re-validated, not assumed.

## B4. Worker ↔ External targets (the scope boundary)
- **Crosses:** every outbound probe/request from recon, crawler, API tests, dynamic analysis.
- **Controls:** ScopeEngine validation before any action; ExecutionPolicy (passive/active, safe mode); RateLimiter (project + target); per-scan concurrency and timeout limits; **SSRF protections on all server-side requests**: DNS resolution validation, private-network restriction, loopback restriction, link-local restriction, cloud-metadata protection, DNS-rebinding defense; safe redirect handling that cannot leave the authorized target boundary.
- **Invariants:** never test third-party or out-of-scope targets; relationship/discovery ≠ authorization.

## B5. Platform ↔ Plugins (Phase 18)
- **Crosses:** plugin code, manifests, configuration, scan results.
- **Controls:** manifest schema validation; permission declarations (e.g. `network.request`); integrity verification; version pinning + compatibility checks; execution isolation with CPU/memory/time limits; network policies; secure artifact handling; enable/disable lifecycle + audit logging.
- **Invariant:** plugins cannot obtain unrestricted system access; plugin privilege escalation is an explicit Phase 16 test target.

## B6. Platform ↔ MinIO (artifact storage)
- **Crosses:** evidence, screenshots, APK files, reports.
- **Controls:** least-privilege bucket permissions; cryptographic hashing of uploads (APKs); artifact lifecycle management (Phase 17); secret redaction before evidence is stored; no plaintext credentials anywhere.
- **Failure modes:** data leakage via artifacts, insecure file handling (Phase 16 test target).

## B7. Admin ↔ Knowledge packs (Phase 19)
- **Crosses:** downloaded rule/methodology packs — **untrusted input**.
- **Controls:** integrity verification → schema validation → security validation before install; activate/rollback; audit logging.
- **Invariant:** untrusted packs are never executed blindly.

## B8. Platform ↔ Untrusted data (standing rule)
All scanner input, plugin code, knowledge packs, uploaded files, and discovered infrastructure are **untrusted**. Evidence passes SecretRedactor / PIIRedactor / CredentialDetector / EvidenceSanitizer before logging, storing, or displaying. Reports re-sanitize at render time.

## B9. Infrastructure boundaries (Phases 1, 16)
Docker container privileges, network segmentation between frontend/backend/PostgreSQL/Redis/MinIO/workers, worker isolation, service exposure review, TLS, backup behavior, secret handling, environment configuration.

## Security Invariants (cross-cutting, non-negotiable)
1. Never bypass authentication, authorization, RBAC, ScopeEngine, scope validation, rate limiting, execution policies, worker isolation, resource limits, or sandbox boundaries.
2. Relationship or discovery is never authorization.
3. Observation ≠ Finding; severity ⟂ confidence; "not detected" ≠ "secure".
4. No plaintext credentials or secrets at rest, in logs, or in evidence.
5. Active testing requires controlled limits and explicit authorization; dynamic APK analysis is off by default.
6. External report submission is human-controlled, never automated.