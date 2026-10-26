What this repo does: Authorized security-assessment platform (FastAPI backend, Next.js frontend, PostgreSQL, Redis, Celery, MinIO, Docker). Supports domain/web/API/APK targets, scope validation, scanning workers, finding correlation, and advanced asset/finding graphs (Phase 20). Load assumed: multi-user web service with concurrent scan workers and real database connections.

Audit scope: whole repo (`apps/backend/`, `apps/frontend/`, `docs/`, `tests/`, `docker-compose.yml`, CI, key source files). Not checked: full frontend component internals (only package.json/manifests), phase 14 test internals past line 40, plugin SDK design docs in depth.

1. Must fix

1. `.env.example` has empty `SECRET_KEY=` (`.env.example:L24`)
   - What this is: Template for backend env.
   - Problem: `app/config.py` requires `secret_key` with `min_length=32`; empty value raises `ValueError` at import and crashes `dev-up.sh` / `pytest` / any fresh start.
   - Fix: Set a 32+ char placeholder in `.env.example`: `SECRET_KEY=dev-only-change-in-production-32chars`.
   - If we skip it: Every new developer and CI run crashes on startup.

2. Should fix

2. `packages/` is empty except `.gitkeep` (`packages/`)
   - What this is: Monorepo package directory intended for shared libraries / plugin SDK.
   - Problem: `app/config.py` references `plugin_directory` and `plugin_permission_policy`; nothing is installed. Keeps a dead folder in every clone.
   - Fix: Either implement the plugin SDK package or delete `packages/` and the config fields that reference it.
   - If we skip it: Confusion for agents expecting SDK code; extra context cost.

3. Phase 14 dynamic pipeline (`app/core/dynamic_pipeline.py`: 675 lines) is speculative/stub (`app/core/dynamic_pipeline.py`)
   - What this is: Full emulator/ADB pipeline for APK dynamic analysis.
   - Problem: Most steps are comments like "In production, this would..." (line 343, 623-628). The `EmulatorManager.create_instance` is not fully wired; evidence paths are hard-coded (`/evidence/dynamic`). It is 675 lines of mostly unimplemented workflow in production code.
   - Fix: Move to `docs/phase_14_draft/` or delete if not needed until Phase 14 is active. If kept, add `shortcut:` comment naming its limit.
   - If we skip it: Newcomers read it as real code; it increases context and test burden.

4. Phase 14 test file is mock-heavy for unimplemented pipeline (`tests/test_phase14_dynamic_analysis.py`: 572 lines)
   - What this is: Tests for emulator, ADB, pipeline.
   - Problem: Tests mock `AdbClient`, `EmulatorManager`, and pipeline steps extensively. Because the underlying pipeline is not fully implemented, these tests verify mock behavior rather than real integration.
   - Fix: Keep only a small smoke test (`test_dynamic_analysis_smoke`) and archive the rest until the feature lands.
   - If we skip it: False confidence; slow test suite.

5. `app/auth/token.py` creates a new Redis client per call (`token.py`: `_get_redis_client` called repeatedly)
   - What this is: JWT key storage / rotation.
   - Problem: `redis.Redis.from_url()` is called inside `_get_current_key`, `_get_key_for_verification`, `rotate_signing_key`, and blacklisting. No connection pooling; high overhead under concurrent token validation.
   - Fix: Cache one `redis.Redis` instance in a module-level variable (or inject via dependency).
   - If we skip it: Unnecessary latency and Redis connection overhead at scale.

6. `P3_SECURITY_FIXES_SUMMARY.md` references fixes not fully verified in CI (e.g., rate-limit retry headers, audit logging of security events listed as "Not Blocking")
   - What this is: Security hardening summary.
   - Problem: Several listed items are partial or deferred (e.g., `Retry-After` headers missing from rate limit responses, detailed audit logging not implemented). They are documented as complete but not fully delivered.
   - Fix: Update the file: move deferred items to a "Not yet implemented" section rather than "Remaining Non-P3 Items" to avoid confusion.
   - If we skip it: Agents or reviewers may assume fixes are done when they are partial.

3. Nice to have

7. `secret_key` validation raises at import time (`app/config.py:L118-121`)
   - Problem: `ValueError` inside `__init__` makes testing with partial settings harder; a warning or lazy check would be gentler.
   - Fix: Move validation to first use (lazy) or provide a clearer error message with the environment variable name.

8. `app/core/scope_engine.py` has a redundant check (`scope_engine.py:L144`)
   - Problem: `(prefix + suffix == target)` is always true by definition of `prefix = target[:-len(suffix)]`. It is harmless but adds unnecessary complexity.
   - Fix: Remove the redundant condition; keep the non-empty prefix and label-boundary checks.

9. Frontend `components/` is minimal; `package.json` references `shadcn` but installed components are basic (`components.json` + small set). Not a bug, just lean opportunity.

10. `tests/load/locustfile.py` exists but load-test targets/reference URLs are not configured. Could be trimmed to a stub.

Verdict: Not healthy for a fresh clone because `.env.example` crashes startup. Once that is fixed, core auth/scope/rate limits are sound; main risk is speculative phase 14 code adding bloat and false confidence.

Lean: -5 lines (delete `.env` fix is +1 line, removing redundant scope check is -1, trimming phase 14 file references and `.gitkeep` could save more). Real lean win is deleting or archiving 675+ lines of unimplemented pipeline.

Not checked: Full frontend build (`npm run build` not executed), plugin SDK design details, all 572 lines of phase 14 test internals, load-test execution (`locust` not run).
