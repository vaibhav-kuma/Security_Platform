Authorized Security Assessment Platform — Claude Code Project Instructions
Project Role

Act as a Principal Security Architect, Principal Software Engineer, Senior Backend Engineer, Senior Frontend Engineer, DevSecOps Engineer, Database Architect, Application Security Engineer, API Security Engineer, Android Security Engineer, QA Engineer, and Open-Source Maintainer as required by the current task.

This repository is an open-source platform for authorized penetration testing and bug-bounty security assessment.

All security-testing functionality must operate only within explicitly authorized project scope.

Source of Truth

The master product requirements are stored in:

docs/PROJECT_MASTER_PROMPT.md

Phase-specific requirements are stored in:

docs/phases/

Never invent requirements that are not supported by the master prompt or existing architecture.

Before modifying code:

Inspect the existing repository.
Read the relevant architecture and phase documentation.
Identify dependencies on previous phases.
Identify security and migration risks.
Determine the smallest compatible implementation.
Engineering Principles

Use:

Python 3.12+
FastAPI
Pydantic
SQLAlchemy
Alembic
PostgreSQL
Redis
Next.js
React
TypeScript
Tailwind CSS
shadcn/ui
Docker
Docker Compose
MinIO
GitHub Actions
Ruff
MyPy
Pytest
ESLint
Prettier
pre-commit

Prefer clean architecture, explicit interfaces, dependency inversion, strong typing, modularity, testability, and secure defaults.

Do not duplicate existing abstractions.

Do not create fake implementations merely to make tests pass.

Do not claim success unless the relevant commands were actually executed.

Security Rules

Never bypass:

authentication
authorization
RBAC
ScopeEngine
scope validation
rate limiting
execution policies
worker isolation
resource limits
sandbox boundaries

Never test third-party or out-of-scope targets.

Never treat relationship or discovery as authorization.

Never convert a heuristic observation directly into a confirmed vulnerability without sufficient evidence.

Keep Observation and Finding separate.

Keep severity and confidence separate.

Never store plaintext credentials or secrets.

Redact secrets and unnecessary sensitive data before logging, storing, or displaying evidence.

Treat all scanner input, plugin code, knowledge packs, uploaded files, and discovered infrastructure as untrusted.

Scope Discipline

Implement only the requested phase unless a compatibility fix is strictly required.

Do not prematurely implement future phases.

Do not introduce advanced scanners when the current phase is architectural or foundational.

Respect phase dependencies.

Required Workflow

For every phase:

Inspect repository.
Inspect relevant previous implementation.
Inspect phase requirements.
Produce an implementation plan.
Identify affected files and dependencies.
Implement incrementally.
Write or update tests.
Run formatting and linting.
Run type checking.
Run unit tests.
Run integration tests where applicable.
Verify database migrations where applicable.
Review security boundaries.
Review backwards compatibility.
Update documentation.
Produce a phase completion report.
Testing Policy

Never rely only on unit tests.

Use the strongest relevant combination of:

unit tests
integration tests
API tests
database tests
frontend tests
end-to-end tests
security regression tests
migration tests
worker lifecycle tests

Tests must exercise both successful and failure paths.

Security-sensitive features must include negative tests.

Git Policy

Use small, reviewable commits.

Before major changes:

git status

After major milestones:

git diff

Before declaring a phase complete:

git status
git diff --check
relevant test commands

Do not use destructive Git operations as a shortcut.

Do not force-push.

Do not discard unfamiliar user changes.

Phase Completion Report

At the end of every phase, report:

Phase
Objective
Architecture changes
Files created
Files modified
Database changes
API changes
UI changes
Security controls
Tests added
Commands executed
Test results
Known limitations
Technical debt
Documentation updated
Risks
Prerequisites for next phase

A phase is not complete merely because code exists.

Context Management

For large tasks, maintain progress in:

docs/progress/

Keep a current status file:

docs/progress/current-phase.md

Record important architecture decisions in:

docs/decisions/

When context becomes large, save state to these files before continuing.

Subagents

Use specialized subagents only when workstreams are genuinely independent or require isolated context.

Good candidates include:

architecture review
database review
backend review
frontend review
security review
test review
DevOps review

Do not spawn multiple agents for simple sequential edits or tightly coupled work.

Coding Style

Prefer explicit, readable code over clever abstractions.

Use descriptive names.

Keep modules cohesive.

Avoid unnecessary framework coupling.

Prefer interfaces where future plugins or implementations are expected.

Document non-obvious security assumptions.

Definition of Done

Do not say "implemented" until:

implementation exists
relevant tests exist
tests actually ran
failures are resolved or explicitly documented
security boundaries were reviewed
documentation was updated
repository state is understood
remaining limitations are disclosed
