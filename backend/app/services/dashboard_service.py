from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import Finding, Project, Resource, Scan, ScanStatus, Severity


def get_project_or_404(db: Session, project_id: int) -> Project | None:
    return db.execute(select(Project).where(Project.id == project_id)).scalar_one_or_none()


def get_latest_scan(db: Session, project_id: int) -> Scan | None:
    return db.execute(
        select(Scan)
        .where(Scan.project_id == project_id)
        .order_by(Scan.timestamp.desc(), Scan.id.desc())
        .limit(1)
    ).scalar_one_or_none()


def get_dashboard_data(db: Session, project_id: int) -> dict:
    total_resources = db.execute(
        select(func.count(Resource.id)).where(Resource.project_id == project_id)
    ).scalar_one()

    latest_scan = get_latest_scan(db, project_id)
    findings_by_severity = {severity.value: 0 for severity in Severity}

    if latest_scan and latest_scan.status == ScanStatus.COMPLETED:
        severity_rows = db.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.scan_id == latest_scan.id)
            .group_by(Finding.severity)
        ).all()
        for severity, count in severity_rows:
            findings_by_severity[severity.value] = int(count)

        risk_score = int(latest_scan.score)
        compliance_percentage = float(latest_scan.score)
    else:
        risk_score = 0
        compliance_percentage = 0.0

    return {
        "total_resources_count": int(total_resources or 0),
        "risk_score": risk_score,
        "findings_by_severity": findings_by_severity,
        "compliance_percentage": compliance_percentage,
        "latest_scan_id": latest_scan.id if latest_scan else None,
    }


def get_scan_findings(db: Session, scan_id: int) -> list[dict]:
    rows = db.execute(
        select(Finding, Resource)
        .outerjoin(Resource, Finding.resource_id == Resource.id)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.id.asc())
    ).all()

    findings: list[dict] = []
    for finding, resource in rows:
        findings.append(
            {
                "id": finding.id,
                "scan_id": finding.scan_id,
                "resource_id": finding.resource_id,
                "resource_name": resource.name if resource else None,
                "resource_type": resource.type if resource else None,
                "cis_rule_id": finding.cis_rule_id,
                "severity": finding.severity,
                "description": finding.description,
                "remediation_steps": finding.remediation_steps,
            }
        )
    return findings
