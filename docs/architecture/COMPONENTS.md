# Components & Major Interfaces

One section per component family. Status column: which phase introduces it. No component here exists in code yet — this is the Phase 0 specification.

## 1. Core API Platform (Phases 3, 4, 6)

**Responsibility:** versioned REST API for organizations, projects, project members, scopes, scope rules, targets, assets; server-side validation; structured errors; OpenAPI docs.

Major interfaces:
- `GET/POST /api/v1/orgs`, `/projects`, `/projects/{id}/members`, `/projects/{id}/scopes`, `/scopes/{id}/rules`, `/targets` — CRUD + listing with pagination/filter/sort.
- Scope preview endpoint: `POST /api/v1/scopes/preview` (check whether a candidate target is authorized before execution — Phase 6).
- Error envelope: `{ "error": { "code": "TARGET_OUT_OF_SCOPE" | "FORBIDDEN_RESOURCE_ACCESS" | ..., "message", "request_id" } }`.
- Audit retrieval endpoints (append-oriented records).

## 2. Security Kernel (Phases 4, 7, 8)

**Responsibility:** every authorization decision, enforced server-side. Never bypassable by downstream components.

| Component | Interface / behavior |
|---|---|
| AuthN service | Argon2 password hashing; access + refresh tokens; sessions; password reset / email verification architecture; login rate limiting; abuse protection; secure cookies; CSRF protection; optional OAuth/OIDC integration points |
| RBAC | Roles: `owner`, `admin`, `researcher`, `viewer`; fine-grained permissions over projects, scopes, scans, findings, reports, org admin; cross-org IDOR defense |
| **ScopeEngine** | `validate(target, scope_snapshot) → in_scope / out_of_scope / unknown / third_party`; the single authority consulted before any scan action |
| **ExecutionPolicy** | passive vs active mode, safe-mode compatibility, per-target restrictions, testing profile |
| **RateLimiter** | per-project and per-target limits, enforced in queue + worker |
| **TargetNormalizer** | canonical target identity for dedup and scope matching |
| Audit service | append-oriented records: auth events, project creation, scope changes, scan ops, finding modifications, report generation, permission changes, security events |

## 3. Job & Worker Runtime (Phase 7)

**Responsibility:** reliable async execution of everything scanning-related.

- Entities: `Scan`, `ScanJob`, `ScanEvent`; worker registration; queue management.
- Controls: retries, cancellation, pausing, timeout handling, concurrency control, job recovery, backpressure (Phase 17), idempotency.
- Job payload contract: project context, **scope snapshot**, execution policy, testing profile, rate limits, security metadata.
- WebSocket event bus → frontend: `scan.started`, `scan.progress`, `asset.discovered`, `endpoint.discovered`, `observation.created`, `finding.created`, `scan.completed`, `scan.failed`.
- **Dummy worker** ships first to prove the full lifecycle (cancellation + resource limits actually work) before any real scanner exists.

## 4. Scanner Layer

### 4.1 Recon plugins (Phase 8)
`ReconPlugin` interface: `validate()`, `run()`, `normalize()`. Modules: DNS discovery, subdomain discovery, DNS resolution, IP correlation, controlled service inventory, HTTP/HTTPS detection, TLS analysis, technology fingerprinting, asset relationship discovery. Output: normalized assets with `first_seen`, `last_seen`, `source`, `confidence`, `scope_status`, relationship metadata. Deduplication + rate limiting + timeouts; tests use local controlled domains/fixtures only.

### 4.2 Web mapping engine (Phase 9)
URL normalization, HTTP profiling, controlled crawling (`max_depth`, `max_pages`, `max_concurrency`, `requests_per_second`, timeouts, content-type filters, URL dedup, scope-enforced redirect handling), response metadata, endpoint/parameter/form discovery, JS endpoint discovery, source-map awareness, technology detection, security-header/cookie/TLS/CORS/redirect analysis. Produces the **application model**: pages, endpoints, methods, parameters, headers, cookies, forms, auth flows, session mechanisms, JS artifacts, technologies. All outbound requests pass SSRF protections (see Trust Boundaries).

### 4.3 API security engine (Phase 11)
OpenAPI/Swagger importers; endpoint/method/parameter/schema inventory; auth detection; authorization-context modeling (anonymous / normal-user / privileged-user / administrator / service-account — **only when explicitly configured and authorized**); object-identifier, role/privilege, inventory, rate-limit observations; controlled test planning mapped to OWASP API Security categories. Evidence-driven: observations ≠ confirmed vulnerabilities, especially for authorization behavior. No plaintext credentials, ever.

### 4.4 ScannerPlugin SDK (Phase 18)
Stable external interface: `validate()`, `scan()`, `normalize()`; plugin manifest (name, version, category, capabilities, **permissions** e.g. `network.request`, requirements, configuration); lifecycle: install → validate → enable → execute → disable → version → remove; integrity verification, version pinning, compatibility checks, audit logging, UI management; execution isolation with CPU/memory/time limits and network policies. Sample safe plugin + third-party developer docs.

## 5. Methodology Engine (Phases 10, 11, 13, 19)

- Entities: `Methodology`, `MethodologyVersion`, `TestCase`, `TestCaseRun`, `DetectionRule`, `CoverageEngine`, `TestPlanner`.
- Definitions stored as **versioned data / rule packs**, never hard-coded in scanners.
- Test case contract: id, name, description, category, supported target types, prerequisites, passive/active mode, safe-mode compatibility, evidence requirements, detection rules, references; WSTG categories for web; API Security categories for APIs; MASTG/MASVS analogues for mobile.
- `TestPlanner.select(target_type, technologies, application_model, auth_model, api_model, scope, testing_profile) → test plan`; marks each test `Tested / Not Tested / Needs Review / Not Applicable`; unavailable prerequisites suppress dependent tests deterministically.
- Coverage dashboard — incomplete coverage is never presented as proof of security.
- Phase 19 externalizes all of this into versioned knowledge packs with coexisting methodology versions (historical scans stay reproducible).

## 6. Security Analysis Engine (Phase 12)

- **Observation** vs **Finding** as separate entities and lifecycles.
- Evidence collection: HTTP req/resp, screenshots, DNS, TLS, APK artifacts, static-analysis results, runtime observations, JSON, text, metadata.
- Sanitization pipeline: `SecretRedactor`, `PIIRedactor`, `CredentialDetector`, `EvidenceSanitizer` — applied **before** storage or display.
- `FindingCorrelationEngine` + dedup keyed on normalized asset, vulnerability type, location, parameter, rule identity; correlates across scanners, test cases, domains, web apps, APIs, APKs, runtime data.
- Severity per finding. Confidence: `very_low | low | medium | high | very_high`. Statuses: `open | needs_review | confirmed | false_positive | duplicate | accepted_risk | resolved`.
- CVSS scoring + CWE/OWASP mappings; `ManualReviewQueue` for ambiguous observations.

## 7. APK Subsystem (Phases 13–14)

Static analyzers (each a component with its own interface): `ManifestAnalyzer`, `PermissionAnalyzer`, `CertificateAnalyzer`, `DexAnalyzer`, `NativeLibraryAnalyzer`, `ResourceAnalyzer`, `URLAnalyzer` (embedded domains, API endpoints, WebSocket/Firebase URLs), `ConfigurationAnalyzer`, `ExportedComponentAnalyzer`, `WebViewAnalyzer`, `StorageAnalyzer`, `CryptoAnalyzer`, `NetworkSecurityAnalyzer`.
Pipeline: upload → cryptographic hash → package identification → analyzers → observations with MASTG/MASVS mapping. Suspicious strings/permissions/patterns stay **observations** absent contextual evidence. Artifacts stored securely (hashed, no secret leakage in logs).

Dynamic analysis (Phase 14): **optional, disabled by default, explicit project authorization required**. Isolated emulator/test environment, ADB integration, controlled execution, configurable proxying, runtime event collection, network observation; CPU/memory/time/network/artifact limits; cannot reach unauthorized targets or internal infrastructure; correlates with static + API observations.

## 8. Reporting & Bug-Bounty Workspace (Phase 15)

- Report generation: HTML, Markdown, PDF, JSON. Sections: Executive Summary, Scope, Methodology, Test Coverage, Asset Inventory, Findings Summary, Detailed Findings, Risk Summary, Recommendations, Appendix.
- Finding report fields: title, severity, confidence, affected asset, affected URL/API endpoint, description, impact, evidence, controlled reproduction info, remediation, references, CWE, OWASP refs, methodology test case, CVSS — secrets sanitized.
- Bug-bounty workspace: Program, Policy, Scope, Excluded Targets, Research Notes, Observations, Findings, Reports; notes, evidence attachments, report versioning, finding status tracking.
- **No automatic submission** to third-party programs — submission is human-controlled.

## 9. Knowledge Base (Phase 19)

Versioned packs: WSTG definitions, API Security definitions, MASTG/MASVS mappings, CWE metadata, CVSS metadata, detection rules, remediation content, methodology test cases, technology fingerprints. Rule contract: identity, version, name, methodology, category, target types, prerequisites, evidence requirements, severity/confidence guidance, references, detection behavior. Update pipeline: download → integrity verification → schema validation → security validation → install → activate/rollback → audit log. UI + CLI for admins.

## 10. AssetGraph / RelationshipEngine / FindingGraph (Phase 20)

Entities and edges across domains, subdomains, IPs, certificates, web apps, URLs, API endpoints/specs, technologies, APKs, runtime observations, scanner results, test cases, findings — every entity retains explicit scope + authorization state. Edge types include: APK→communicates_with→API, API→belongs_to→application, domain→resolves_to→IP, application→uses→technology, finding→affects→endpoint, observation→originates_from→test_case. Relationship confidence + `first_seen`/`last_seen`; confirmed vs inferred edges distinguished. **A graph relationship never grants authorization.**

## 11. Frontend (Phases 5–6)

Next.js + React + TypeScript + Tailwind + shadcn/ui + React Query. Security-oriented design system: severity/confidence/authorization-status/scan-state visual distinctions; dark mode; keyboard accessibility; shell with sidebar (Dashboard, Projects, Targets, Assets, Scans, Findings, Methodology, Reports, Plugins, Settings). Typed API hooks, error boundaries, auth state, route protection. **Security-sensitive actions must display target, scope, authorization, testing mode, and rate-limit information before execution.** Scan-creation shows a confirmation view: exact target, applicable scope, testing profile, active-testing status, rate limit, restrictions — server-side validation remains the ultimate authority.