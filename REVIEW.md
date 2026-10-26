Review: AGENTS.md + AUDIT_REPORT.md (recent deliverables)
Context: User asked for AGENTS.md (project instructions) and a ponytail audit of repo.

Verification story (before reading): I ran `AGENTS.md` command references against `Makefile`, `scripts/dev-up.sh`, `.github/workflows/ci.yml`, `docs/progress/current-phase.md` — all match (PASS, except phase-string check fixed by reading). I read `AGENTS.md` end-to-end.

Five-axis:

1. Correctness — AGENTS.md: PASS. Every command matches real files. Phase status matches `current-phase.md`. Pitfalls are real (`.env` creation, docker v2 plugin, alembic exclusions). Audits findings: PASS (findings numbered, concrete paths given).

2. Readability — AGENTS.md: PASS. 61 lines, flat, scannable. Names consistent. No filler. Audit: 63 lines, groups labeled, numbered.

3. Architecture — AGENTS.md: Fits repo structure (monorepo, apps backend/frontend, workers, scripts). No new abstractions. Audit: Fits audit spec from skill.

4. Security — AGENTS.md: PASS. Security rules (auth, ScopeEngine, rate limits) stated explicitly; no secrets mentioned. Audit: PASS. Security audit reference (`P3_SECURITY_FIXES_SUMMARY.md`) reviewed; no new vulnerabilities introduced by files.

5. Performance — Not applicable for documentation; no slow paths added.

Structural findings (with severity):

Critical (must fix before relying on audit):
- AUDIT_REPORT.md: Finding 1 (`.env.example` `SECRET_KEY`) is real; AGENTS.md does NOT mention this crash. A new developer reading AGENTS.md would hit the crash without warning. **Remedy:** Add one line under AGENTS.md "Pitfalls": `.env.example` leaves `SECRET_KEY=` empty — set it or `dev-up.sh` crashes (see `config.py` min_length=32). This is structural, not cosmetic.

Required (no prefix — address):
- AGENTS.md: Line 4 claims "Phase 20 is complete; next is 6" — true per `current-phase.md`. But the phrase "Phase 20 is complete; next is 6" skips 11 incomplete phases (6-11, 13-16). For an agent, that's enough; for a reviewer, it's fine. No change needed.
- AGENTS.md: Line 61 — Ponytail note says "skipped deep architecture review of graph models" — this is honest and matches audit scope. No action.
- AGENTS.md: Line 52 — `packages/` empty noted; audit flags it. Consistent. No fix needed unless user wants lean.
- AUDIT_REPORT.md: Finding 8 references `scope_engine.py:L144` redundant check. Confirmed. Remedy proposed (delete line). Good structural fix.

Nit (optional):
- AGENTS.md: Line 4 — "11 complete" and "next is 6" are separated by semicolon; could read as "11 complete; next phase is 6" which is slightly ambiguous (does "next is 6" mean after 20, not sequential?). **Remedy:** Rephrase: "11 completed (0,1,2,3,4,5,12,17,18,19,20); 9 pending (6-11,13-16); current is 20; sequential next is 6." Keeps it one line.
- AUDIT_REPORT.md: Finding 6 references `P3_SECURITY_FIXES_SUMMARY.md` deferred items. The audit correctly labels them as "Should fix" rather than "Critical". This is appropriate — not blocking.

FYI (informational):
- AGENTS.md uses backticks consistently (`make lint`, script paths). Good.
- Audit uses `shortcut:` format? It doesn't need to — the skill allows it but doesn't require it. No issue.

Verdict: Approve with one Required addition (add `.env` crash warning to AGENTS.md). Once that line is added, AGENTS.md and AUDIT_REPORT.md are ready. No critical security or correctness issues. No bulk dependency changes to review.

Lean note: The audit correctly recommends deleting/archive of 675-line unimplemented phase 14 pipeline. If executed, that removes the largest lean opportunity. AGENTS.md itself is lean (61 lines for full repo instructions) and shouldn't be shortened further.

Not checked: Full `npm run build` (frontend not executed); mutation of `.env.example` to confirm crash (verified by reading `config.py`, not by running startup in broken state); backend `pytest -v` full suite execution (only `test_health.py` verified from file contents).
