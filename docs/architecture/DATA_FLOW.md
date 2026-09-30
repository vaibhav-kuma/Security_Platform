# Data Flow

All flows are specified against the Phase 0–20 requirements; none are implemented yet. `⟶` denotes a synchronous call, `⇢` an async/queued step.

## 1. Project, Scope, and Target Setup (Phases 3, 6)

```
User (UI) ⟶ API: create org / project / members
User ⟶ API: define scope + scope rules + exclusions
User ⟶ API: register targets (domain, URL, API, OpenAPI spec, APK)
API ⟶ PostgreSQL: persist (server-side validation; org isolation)
API ⟶ Audit: append scope/target events
```

### Scope preview (Phase 6)

```
User ⟶ API: scope-preview(candidate target)
API ⟶ ScopeEngine: validate(candidate, project scope rules)
ScopeEngine ⟶ User: in_scope | out_of_scope | unknown | third_party
```
The preview is advisory UX; **server-side validation at execution time is the authority**.

## 2. Scan Execution Pipeline (Phases 6, 7)

```
User ⟶ UI: create scan → confirmation view shown
        (target, scope, testing profile, active-testing status, rate limit, restrictions)
User ⟶ API: confirm
API ⟶ ScopeEngine: validate target (REJECTED: TARGET_OUT_OF_SCOPE if not authorized)
API ⟶ PostgreSQL: create Scan + immutable scope snapshot
API ⇢ Redis: enqueue ScanJob
     job payload = { project context, scope snapshot, execution policy,
                     testing profile, rate limits, security metadata }
Worker ⟶ Redis: claim job (concurrency + per-project/per-target rate limits)
Worker ⟶ Plugin: validate() → run() (policy + limits enforced throughout)
Plugin ⟶ Worker: normalized events / observations
Worker ⟶ PostgreSQL: persist ScanEvents, assets, observations
Worker ⇢ Redis ⇢ WebSocket: scan.started / scan.progress / scan.completed / scan.failed
```

Cancellation / pause / timeout: API marks Scan → queue drops or tombstones job → worker stops within policy → recovery re-enqueues on worker death.

## 3. Real-Time Frontend Events (Phase 7)

```
Worker ⇢ Redis pub/sub ⇢ API WebSocket gateway ⟶ Frontend
Events: scan.started, scan.progress, asset.discovered, endpoint.discovered,
        observation.created, finding.created, scan.completed, scan.failed
```

## 4. Discovery → Asset Normalization (Phase 8)

```
ReconPlugin.run() → raw results (DNS, subdomains, IPs, ports, TLS, tech)
  ⟶ TargetNormalizer: canonical identity
  ⟶ deduplication (first_seen/last_seen merge)
  ⟶ ScopeEngine: classify each NEW asset
       in_scope | out_of_scope | unknown | third_party
  ⟶ PostgreSQL assets + asset relationships
```
**Invariant:** a newly discovered asset related to an in-scope domain is classified, never auto-authorized for testing.

## 5. Web Attack-Surface Mapping (Phase 9)

```
Crawler(target, limits) — every request ⟶ SSRF guard:
   DNS resolution validation · private/loopback/link-local block ·
   cloud-metadata block · DNS-rebinding defense · scope-enforced redirects
Responses ⟶ endpoint/parameter/form/JS/source-map extraction
          ⟶ security-header / cookie / TLS / CORS / redirect analysis
          ⟶ application model (pages, endpoints, methods, params, auth flows,
              session mechanisms, technologies)
          ⟶ asset DB + observations
```

## 6. Methodology → Test Planning (Phases 10, 11)

```
TestPlanner.inputs = { target type, discovered technologies, application model,
                       auth model, API model, project scope, testing profile }
TestPlanner ⟶ applicable TestCases (deterministic selection)
            ⟶ prerequisites checked → incompatible tests suppressed
            ⟶ TestCaseRuns marked Tested / Not Tested / Needs Review / Not Applicable
TestCaseRun execution ⟶ observations with DetectionRule matches
```

## 7. Observation → Finding Lifecycle (Phase 12)

```
Scanner output ⟶ Observation (something suspicious/relevant detected)
Observation ⟶ sanitization pipeline:
   SecretRedactor → PIIRedactor → CredentialDetector → EvidenceSanitizer
   (BEFORE storage or display)
Observation + evidence ⟶ FindingCorrelationEngine
   dedup key: normalized asset + vulnerability type + location + parameter + rule identity
   correlates across scanners, test cases, domains, web apps, APIs, APKs, runtime data
Finding: severity ⟂ confidence; CVSS + CWE/OWASP mapping
Status: open → needs_review → confirmed | false_positive | duplicate |
        accepted_risk | resolved
Ambiguous ⟶ ManualReviewQueue (human validation)
```
**Invariant:** no heuristic observation becomes a confirmed finding without sufficient evidence.

## 8. APK Static Analysis (Phase 13)

```
Upload ⟶ hash + package identification ⟶ MinIO (secure storage)
APK ⟶ 13 analyzers (Manifest … NetworkSecurity) ⟶ observations
     ⟶ embedded URL/API/WebSocket/Firebase extraction ⟶ asset links
     ⟶ MASTG/MASVS-mapped test cases + detection rules
     ⟶ shared Observation/Finding/Evidence/Correlation engines
```

### Dynamic analysis (Phase 14, optional, off by default)

```
APK ⟶ isolated environment (emulator + ADB) ⟶ controlled execution
    ⟶ proxy + runtime event collection ⟶ normalized events
    ⟶ correlation with static APK observations + authorized API observations
Limits: CPU, memory, execution time, network, artifacts;
        no reach to unauthorized targets or internal infrastructure.
```

## 9. Report Generation (Phase 15)

```
Project + methodology coverage + assets + findings + evidence
⟶ report assembler (sanitizes secrets/sensitive data again at render time)
⟶ HTML / Markdown / PDF / JSON ⟶ MinIO + versioning
```

## 10. Knowledge-Pack Update (Phase 19)

```
Admin/UI/CLI ⟶ download pack ⟶ integrity verification ⟶ schema validation
⟶ security validation ⟶ install ⟶ activate | rollback ⟶ audit log
Multiple methodology versions coexist → historical scans stay reproducible.
Untrusted packs are never executed blindly.
```