"""Report generation and bug-bounty workspace service layer."""

import uuid
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.core.evidence_sanitizer import sanitize_evidence
from app.models.enums import (
    ReportStatus,
    ReportType,
    Severity,
    Confidence,
    SecurityEventType,
)
from app.models.reports import (
    BugBountyProgram,
    ExcludedTarget,
    ProgramPolicy,
    ProgramScope,
    Report,
    ReportFinding,
    ReportSection,
    ReportVersion,
    ResearchNote,
    ResearchWorkspace,
    WorkspaceAttachment,
    WorkspaceFinding,
    WorkspaceObservation,
    WorkspaceReport,
)
from app.models.projects import Project
from app.models.identity import User


class ReportService:
    """Service for report generation and management."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, project_id: UUID, data: dict[str, Any], requested_by: UUID | None = None) -> Report:
        """Create a new report."""
        project = self.session.get(Project, project_id)
        if not project:
            raise NotFoundError("Project", str(project_id))

        report = Report(
            project_id=project_id,
            requested_by=requested_by,
            **data,
        )
        self.session.add(report)
        self.session.flush()

        # Create initial version
        self._create_version(report, requested_by, "Initial creation")

        return report

    def get(self, report_id: UUID) -> Report:
        """Get report by ID."""
        report = self.session.get(Report, report_id)
        if not report:
            raise NotFoundError("Report", str(report_id))
        return report

    def get_detail(self, report_id: UUID) -> Report:
        """Get report with sections, findings, and versions."""
        from sqlalchemy.orm import joinedload

        report = self.session.query(Report).options(
            joinedload(Report.sections),
            joinedload(Report.findings).joinedload(ReportFinding.finding),
            joinedload(Report.versions),
        ).filter(Report.id == report_id).first()
        if not report:
            raise NotFoundError("Report", str(report_id))
        return report

    def list(
        self,
        project_id: UUID,
        *,
        limit: int = 20,
        offset: int = 0,
        status: str | None = None,
        report_type: str | None = None,
    ) -> list[Report]:
        """List reports in a project."""
        stmt = select(Report).where(Report.project_id == project_id)

        if status:
            try:
                stmt = stmt.where(Report.status == ReportStatus(status))
            except ValueError:
                pass

        if report_type:
            try:
                stmt = stmt.where(Report.report_type == ReportType(report_type))
            except ValueError:
                pass

        stmt = stmt.order_by(Report.created_at.desc()).limit(limit).offset(offset)
        return self.session.scalars(stmt).all()

    def count(self, project_id: UUID, status: str | None = None, report_type: str | None = None) -> int:
        """Count reports in a project."""
        stmt = select(func.count(Report.id)).where(Report.project_id == project_id)

        if status:
            try:
                stmt = stmt.where(Report.status == ReportStatus(status))
            except ValueError:
                pass

        if report_type:
            try:
                stmt = stmt.where(Report.report_type == ReportType(report_type))
            except ValueError:
                pass

        return self.session.scalar(stmt) or 0

    def update(self, report_id: UUID, data: dict[str, Any]) -> Report:
        """Update report."""
        report = self.get(report_id)

        for key, value in data.items():
            if hasattr(report, key) and key not in ("id", "project_id", "created_at"):
                setattr(report, key, value)

        report.updated_at = datetime.now(UTC)
        self.session.flush()

        # Create version for significant changes
        self._create_version(report, None, "Report updated")

        return report

    def add_section(self, report_id: UUID, data: dict[str, Any]) -> ReportSection:
        """Add a section to a report."""
        report = self.get(report_id)

        # Determine next order
        max_order = self.session.scalar(
            select(func.max(ReportSection.order)).where(ReportSection.report_id == report_id)
        ) or -1

        section = ReportSection(
            report_id=report_id,
            order=max_order + 1,
            **data,
        )
        self.session.add(section)
        self.session.flush()

        # Create version
        self._create_version(report, None, f"Added section: {data.get('title', 'Unknown')}")

        return section

    def update_section(self, section_id: UUID, data: dict[str, Any]) -> ReportSection:
        """Update a report section."""
        section = self.session.get(ReportSection, section_id)
        if not section:
            raise NotFoundError("Report section", str(section_id))

        for key, value in data.items():
            if hasattr(section, key) and key not in ("id", "report_id", "created_at"):
                setattr(section, key, value)

        section.updated_at = datetime.now(UTC)
        self.session.flush()

        # Create version
        self._create_version(section.report, None, f"Updated section: {section.title}")

        return section

    def add_finding(self, report_id: UUID, data: dict[str, Any]) -> ReportFinding:
        """Add a finding to a report."""
        report = self.get(report_id)

        finding = ReportFinding(
            report_id=report_id,
            **data,
        )
        self.session.add(finding)
        self.session.flush()

        return finding

    def update_finding(self, finding_id: UUID, data: dict[str, Any]) -> ReportFinding:
        """Update a report finding."""
        finding = self.session.get(ReportFinding, finding_id)
        if not finding:
            raise NotFoundError("Report finding", str(finding_id))

        for key, value in data.items():
            if hasattr(finding, key) and key not in ("id", "report_id", "finding_id", "created_at"):
                setattr(finding, key, value)

        finding.updated_at = datetime.now(UTC)
        self.session.flush()

        return finding

    def _create_version(self, report: Report, user_id: UUID | None, change_summary: str) -> ReportVersion:
        """Create a version snapshot of the report."""
        report.version += 1

        # Build payload with current state
        payload = {
            "report": {
                "title": report.title,
                "report_type": report.report_type.value if report.report_type else None,
                "status": report.status.value if report.status else None,
                "executive_summary": report.executive_summary,
                "scope_summary": report.scope_summary,
                "methodology_summary": report.methodology_summary,
                "test_coverage_summary": report.test_coverage_summary,
                "asset_inventory_summary": report.asset_inventory_summary,
                "findings_summary": report.findings_summary,
                "risk_summary": report.risk_summary,
                "recommendations_summary": report.recommendations_summary,
                "appendix": report.appendix,
                "configuration": report.configuration,
            },
            "sections": [
                {
                    "slug": s.slug,
                    "title": s.title,
                    "content": s.content,
                    "order": s.order,
                    "is_required": s.is_required,
                    "content_type": s.content_type,
                }
                for s in report.sections
            ],
            "findings": [
                {
                    "finding_id": str(f.finding_id),
                    "custom_title": f.custom_title,
                    "custom_severity": f.custom_severity.value if f.custom_severity else None,
                    "custom_confidence": f.custom_confidence.value if f.custom_confidence else None,
                    "custom_impact": f.custom_impact,
                    "custom_remediation": f.custom_remediation,
                    "reproduction_steps": f.reproduction_steps,
                    "affected_assets": f.affected_assets,
                    "evidence_refs": f.evidence_refs,
                    "cwe_ids": f.cwe_ids,
                    "owasp_refs": f.owasp_refs,
                    "mastg_refs": f.mastg_refs,
                    "cvss_vector": f.cvss_vector,
                    "cvss_score": f.cvss_score,
                }
                for f in report.findings
            ],
        }

        version = ReportVersion(
            report_id=report.id,
            version=report.version,
            payload=payload,
            created_by=user_id,
            change_summary=change_summary,
        )
        self.session.add(version)
        self.session.flush()

        return version

    def generate_report(
        self,
        report_id: UUID,
        formats: list[str] = ["html", "markdown", "pdf", "json"],
        template: str | None = None,
        include_evidence: bool = True,
        sanitize_secrets: bool = True,
    ) -> dict[str, str]:
        """Generate report in specified formats."""
        report = self.get_detail(report_id)

        generated = {}

        # Build structured report content
        content = self._build_report_content(report, include_evidence, sanitize_secrets)

        for fmt in formats:
            if fmt == "html":
                generated["html"] = self._render_html(content, template)
            elif fmt == "markdown":
                generated["markdown"] = self._render_markdown(content)
            elif fmt == "pdf":
                generated["pdf"] = self._render_pdf(content, template)
            elif fmt == "json":
                generated["json"] = self._render_json(content)
            else:
                raise ValueError(f"Unsupported format: {fmt}")

        # Store generated artifacts (in production, would upload to object storage)
        for fmt, data in generated.items():
            object_key = f"reports/{report.id}/{report.version}.{fmt}"
            setattr(report, f"{fmt}_object_key", object_key)

        self.session.flush()

        return generated

    def _build_report_content(
        self,
        report: Report,
        include_evidence: bool,
        sanitize_secrets: bool,
    ) -> dict[str, Any]:
        """Build structured report content."""
        from app.core.evidence_sanitizer import sanitize_evidence

        content = {
            "title": report.title,
            "report_type": report.report_type.value if report.report_type else None,
            "project_id": str(report.project_id),
            "version": report.version,
            "generated_at": datetime.now(UTC).isoformat(),
            "executive_summary": report.executive_summary,
            "scope_summary": report.scope_summary,
            "methodology_summary": report.methodology_summary,
            "test_coverage_summary": report.test_coverage_summary,
            "asset_inventory_summary": report.asset_inventory_summary,
            "findings_summary": report.findings_summary,
            "risk_summary": report.risk_summary,
            "recommendations_summary": report.recommendations_summary,
            "appendix": report.appendix,
            "sections": [
                {
                    "slug": s.slug,
                    "title": s.title,
                    "content": s.content,
                    "order": s.order,
                    "is_required": s.is_required,
                }
                for s in report.sections
            ],
            "findings": [],
        }

        for rf in report.findings:
            finding = rf.finding
            finding_content = {
                "id": str(rf.finding_id),
                "title": rf.custom_title or finding.title,
                "severity": rf.custom_severity.value if rf.custom_severity else finding.severity.value,
                "confidence": rf.custom_confidence.value if rf.custom_confidence else finding.confidence.value,
                "status": finding.status.value,
                "cwe_ids": rf.cwe_ids or (finding.cwe_id and [finding.cwe_id]) or [],
                "owasp_refs": rf.owasp_refs or [],
                "mastg_refs": rf.mastg_refs or [],
                "cvss_vector": rf.cvss_vector,
                "cvss_score": rf.cvss_score,
                "description": finding.description,
                "impact": rf.custom_impact,
                "remediation": rf.custom_remediation or finding.recommendation,
                "reproduction_steps": rf.reproduction_steps,
                "affected_assets": rf.affected_assets,
                "evidence_refs": rf.evidence_refs,
            }

            if sanitize_secrets:
                for key in ["impact", "remediation", "reproduction_steps"]:
                    if finding_content[key]:
                        sanitized = sanitize_evidence(str(finding_content[key]))
                        finding_content[key] = sanitized.redacted

            content["findings"].append(finding_content)

        return content

    def _render_html(self, content: dict[str, Any], template: str | None) -> str:
        """Render report as HTML."""
        # In production, would use Jinja2 template
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{content['title']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        h1 {{ color: #333; border-bottom: 2px solid #333; padding-bottom: 10px; }}
        h2 {{ color: #555; border-bottom: 1px solid #ccc; padding-bottom: 5px; }}
        .finding {{ border: 1px solid #ddd; padding: 20px; margin: 20px 0; border-radius: 5px; }}
        .severity-critical {{ border-left: 5px solid #dc3545; }}
        .severity-high {{ border-left: 5px solid #fd7e14; }}
        .severity-medium {{ border-left: 5px solid #ffc107; }}
        .severity-low {{ border-left: 5px solid #0dcaf0; }}
        .severity-info {{ border-left: 5px solid #6c757d; }}
        .meta {{ color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <h1>{content['title']}</h1>
    <p class="meta">Version: {content.get('version', 1)} | Generated: {content.get('generated_at', '')}</p>
"""
        for section in content.get('sections', []):
            html += f"    <h2>{section['title']}</h2>\n    <div>{section['content'] or ''}</div>\n"

        for finding in content.get('findings', []):
            severity = finding['severity'].lower()
            html += f"""
    <div class="finding severity-{severity}">
        <h3>{finding['title']}</h3>
        <p class="meta">Severity: {finding['severity']} | Confidence: {finding['confidence']} | CVSS: {finding.get('cvss_score', 'N/A')}</p>
        <p><strong>Impact:</strong> {finding.get('impact', 'N/A')}</p>
        <p><strong>Remediation:</strong> {finding.get('remediation', 'N/A')}</p>
        <p><strong>Reproduction:</strong> {finding.get('reproduction_steps', 'N/A')}</p>
        <p><strong>Affected Assets:</strong> {', '.join([str(a) for a in finding.get('affected_assets', [])])}</p>
        <p><strong>CWEs:</strong> {', '.join(finding.get('cwe_ids', []))}</p>
        <p><strong>OWASP Refs:</strong> {', '.join(finding.get('owasp_refs', []))}</p>
    </div>
"""
        html += "</body></html>"
        return html

    def _render_markdown(self, content: dict[str, Any]) -> str:
        """Render report as Markdown."""
        md = f"# {content['title']}\n\n"
        md += f"*Version: {content.get('version', 1)} | Generated: {content.get('generated_at', '')}*\n\n"

        for section in content.get('sections', []):
            md += f"## {section['title']}\n\n{section['content'] or ''}\n\n"

        for finding in content.get('findings', []):
            md += f"### {finding['title']}\n\n"
            md += f"- **Severity**: {finding['severity']}\n"
            md += f"- **Confidence**: {finding['confidence']}\n"
            md += f"- **CVSS**: {finding.get('cvss_score', 'N/A')} ({finding.get('cvss_vector', 'N/A')})\n"
            md += f"- **CWEs**: {', '.join(finding.get('cwe_ids', []))}\n"
            md += f"- **OWASP Refs**: {', '.join(finding.get('owasp_refs', []))}\n\n"
            md += f"**Description**: {content['findings'][0].get('description', 'N/A')}\n\n"
            md += f"**Impact**: {finding.get('impact', 'N/A')}\n\n"
            md += f"**Remediation**: {finding.get('remediation', 'N/A')}\n\n"
            md += f"**Reproduction Steps**: {finding.get('reproduction_steps', 'N/A')}\n\n"
            md += f"**Affected Assets**: {', '.join([str(a) for a in finding.get('affected_assets', [])])}\n\n"
            md += "---\n\n"

        return md

    def _render_pdf(self, content: dict[str, Any], template: str | None) -> bytes:
        """Render report as PDF."""
        # In production, would use weasyprint or similar
        # For now, return placeholder
        return f"PDF report: {content['title']}".encode()

    def _render_json(self, content: dict[str, Any]) -> str:
        """Render report as JSON."""
        import json
        return json.dumps(content, indent=2, default=str)


class BugBountyProgramService:
    """Service for bug-bounty program management."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, organization_id: UUID, data: dict[str, Any]) -> BugBountyProgram:
        """Create a new bug bounty program."""
        from app.models.identity import Organization

        org = self.session.get(Organization, organization_id)
        if not org:
            raise NotFoundError("Organization", str(organization_id))

        program = BugBountyProgram(
            organization_id=organization_id,
            **data,
        )
        self.session.add(program)
        self.session.flush()
        return program

    def get(self, program_id: UUID) -> BugBountyProgram:
        program = self.session.get(BugBountyProgram, program_id)
        if not program:
            raise NotFoundError("Bug bounty program", str(program_id))
        return program

    def list(
        self,
        organization_id: UUID,
        *,
        limit: int = 20,
        offset: int = 0,
        is_active: bool | None = None,
    ) -> list[BugBountyProgram]:
        stmt = select(BugBountyProgram).where(BugBountyProgram.organization_id == organization_id)

        if is_active is not None:
            stmt = stmt.where(BugBountyProgram.is_active == is_active)

        stmt = stmt.order_by(BugBountyProgram.created_at.desc()).limit(limit).offset(offset)
        return self.session.scalars(stmt).all()

    def add_scope(self, program_id: UUID, data: dict[str, Any]) -> ProgramScope:
        """Add a scope to a program."""
        self.get(program_id)

        scope = ProgramScope(
            program_id=program_id,
            **data,
        )
        self.session.add(scope)
        self.session.flush()
        return scope

    def add_excluded_target(self, program_id: UUID, data: dict[str, Any]) -> ExcludedTarget:
        """Add an excluded target."""
        self.get(program_id)

        excluded = ExcludedTarget(
            program_id=program_id,
            **data,
        )
        self.session.add(excluded)
        self.session.flush()
        return excluded

    def add_policy(self, program_id: UUID, data: dict[str, Any]) -> ProgramPolicy:
        """Add a policy to a program."""
        self.get(program_id)

        policy = ProgramPolicy(
            program_id=program_id,
            **data,
        )
        self.session.add(policy)
        self.session.flush()
        return policy


class ResearchWorkspaceService:
    """Service for research workspace management."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, program_id: UUID, user_id: UUID, data: dict[str, Any]) -> ResearchWorkspace:
        """Create a research workspace."""
        program = self.session.get(BugBountyProgram, program_id)
        if not program:
            raise NotFoundError("Bug bounty program", str(program_id))

        user = self.session.get(User, user_id)
        if not user:
            raise NotFoundError("User", str(user_id))

        # Check for existing workspace
        existing = self.session.scalar(
            select(ResearchWorkspace).where(
                ResearchWorkspace.program_id == program_id,
                ResearchWorkspace.user_id == user_id,
            )
        )
        if existing:
            raise ValueError("Workspace already exists for this user and program")

        workspace = ResearchWorkspace(
            program_id=program_id,
            user_id=user_id,
            **data,
        )
        self.session.add(workspace)
        self.session.flush()
        return workspace

    def get(self, workspace_id: UUID) -> ResearchWorkspace:
        workspace = self.session.get(ResearchWorkspace, workspace_id)
        if not workspace:
            raise NotFoundError("Research workspace", str(workspace_id))
        return workspace

    def list(
        self,
        program_id: UUID,
        *,
        limit: int = 20,
        offset: int = 0,
    ) -> list[ResearchWorkspace]:
        stmt = select(ResearchWorkspace).where(
            ResearchWorkspace.program_id == program_id,
            ResearchWorkspace.deleted_at.is_(None),
        ).order_by(ResearchWorkspace.created_at.desc()).limit(limit).offset(offset)
        return self.session.scalars(stmt).all()

    def add_note(self, workspace_id: UUID, user_id: UUID, data: dict[str, Any]) -> ResearchNote:
        """Add a research note."""
        workspace = self.get(workspace_id)

        note = ResearchNote(
            program_id=workspace.program_id,
            workspace_id=workspace_id,
            user_id=user_id,
            **data,
        )
        self.session.add(note)
        self.session.flush()
        return note

    def add_observation(self, workspace_id: UUID, user_id: UUID, data: dict[str, Any]) -> WorkspaceObservation:
        """Add an observation."""
        workspace = self.get(workspace_id)

        obs = WorkspaceObservation(
            workspace_id=workspace_id,
            user_id=user_id,
            **data,
        )
        self.session.add(obs)
        self.session.flush()
        return obs

    def add_finding(self, workspace_id: UUID, user_id: UUID, data: dict[str, Any]) -> WorkspaceFinding:
        """Add a finding."""
        workspace = self.get(workspace_id)

        finding = WorkspaceFinding(
            workspace_id=workspace_id,
            user_id=user_id,
            **data,
        )
        self.session.add(finding)
        self.session.flush()
        return finding

    def promote_finding(self, finding_id: UUID, user_id: UUID) -> WorkspaceFinding:
        """Promote workspace finding to official Finding."""
        finding = self.session.get(WorkspaceFinding, finding_id)
        if not finding:
            raise NotFoundError("Workspace finding", str(finding_id))

        # Create official Finding
        from app.models.detection import Finding, Evidence
        from app.models.enums import FindingStatus

        official_finding = Finding(
            project_id=finding.workspace.project_id,
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            confidence=finding.confidence,
            status=FindingStatus.OPEN,
            cwe_id=finding.cwe_ids[0] if finding.cwe_ids else None,
            cvss_score=finding.cvss_score,
            recommendation=finding.remediation,
        )
        self.session.add(official_finding)
        self.session.flush()

        finding.promoted_to_finding_id = official_finding.id
        finding.status = "reported"
        self.session.flush()

        # Link evidence
        for ev_type, ev_data in finding.evidence.items():
            evidence = Evidence(
                finding_id=official_finding.id,
                evidence_type=ev_type,
                storage="inline",
                content=str(ev_data),
            )
            self.session.add(evidence)

        self.session.flush()
        return finding


def write_audit_log(
    session: Session,
    event_type: SecurityEventType,
    user_id: UUID | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    details: dict[str, Any] | None = None,
    source_ip: str | None = None,
) -> None:
    """Write an audit log entry."""
    from app.models.audit import AuditLog

    audit = AuditLog(
        actor_id=user_id,
        action=event_type.value,
        entity_type=entity_type,
        entity_id=UUID(entity_id) if entity_id else None,
        details=details or {},
        source_ip=source_ip,
    )
    session.add(audit)
    session.flush()