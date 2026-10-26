"""API v1 router aggregation."""

from fastapi import APIRouter

from app.api.v1 import (
    api_security,
    apk,
    authorization,
    dynamic,
    findings,
    graph,
    knowledge,
    organizations,
    plugins,
    projects,
    scans,
    scope_evaluation,
    scopes,
    targets,
)
from app.api.v1.reports import reports_router
from app.auth.router import router as auth_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth_router)
api_router.include_router(organizations.router)
api_router.include_router(projects.router)
api_router.include_router(scopes.router)
api_router.include_router(targets.router)
api_router.include_router(scans.router)
api_router.include_router(scope_evaluation.router)
api_router.include_router(authorization.router)
api_router.include_router(api_security.router)
api_router.include_router(apk.router)
api_router.include_router(dynamic.router)
api_router.include_router(findings.router)
api_router.include_router(findings.obs_router)
api_router.include_router(findings.corr_router)
api_router.include_router(findings.review_router)
api_router.include_router(findings.cvss_router)
api_router.include_router(plugins.router)
api_router.include_router(knowledge.router)
api_router.include_router(graph.router)
api_router.include_router(reports_router)
