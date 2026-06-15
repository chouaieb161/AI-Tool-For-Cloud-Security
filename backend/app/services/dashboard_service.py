from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import Finding, Project, Resource, Scan, ScanResource, ScanStatus, Severity


_CIS_CATEGORY_BY_SECTION = {
    "1": "IAM",
    "2": "Logging",
    "3": "Networking",
    "4": "Compute",
    "5": "Storage",
    "6": "Cloud SQL",
    "7": "BigQuery",
    "8": "Dataproc",
}


def _category_from_cis_rule(cis_rule_id: str | None) -> str:
    if not cis_rule_id:
        return "Unknown"
    major = str(cis_rule_id).split(".", maxsplit=1)[0]
    return _CIS_CATEGORY_BY_SECTION.get(major, "Unknown")


def _project_id_from_uri(uri: str | None) -> str | None:
    if not uri:
        return None
    marker = "/projects/"
    if marker in uri:
        tail = uri.split(marker, maxsplit=1)[1]
        return tail.split("/", maxsplit=1)[0] or None
    if uri.startswith("projects/"):
        return uri.split("/", maxsplit=2)[1] or None
    return None


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
    latest_scan = get_latest_scan(db, project_id)
    findings_by_severity = {severity.value: 0 for severity in Severity}
    resource_count_basis = "no_scan"
    total_resources = 0

    if latest_scan and latest_scan.status == ScanStatus.COMPLETED:
        latest_scan_resources = db.execute(
            select(func.count(ScanResource.resource_id))
            .join(Resource, Resource.id == ScanResource.resource_id)
            .where(
                ScanResource.scan_id == latest_scan.id,
                Resource.type != "PROJECT",
            )
        ).scalar_one()
        if int(latest_scan_resources or 0) > 0:
            total_resources = int(latest_scan_resources or 0)
            resource_count_basis = "latest_scan_observed"
        else:
            total_resources = int(
                db.execute(
                    select(func.count(Resource.id)).where(
                        Resource.project_id == project_id,
                        Resource.type != "PROJECT",
                    )
                ).scalar_one()
                or 0
            )
            resource_count_basis = "project_inventory_fallback"

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
        total_resources = int(
            db.execute(
                select(func.count(Resource.id)).where(
                    Resource.project_id == project_id,
                    Resource.type != "PROJECT",
                )
            ).scalar_one()
            or 0
        )
        if total_resources:
            resource_count_basis = "project_inventory_no_completed_scan"
        risk_score = 0
        compliance_percentage = 0.0

    return {
        "total_resources_count": int(total_resources or 0),
        "resource_count_basis": resource_count_basis,
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
                "resource_gcp_uri": resource.gcp_uri if resource else None,
                "resource_project_id": _project_id_from_uri(resource.gcp_uri if resource else None),
                "category": _category_from_cis_rule(finding.cis_rule_id),
                "cis_rule_id": finding.cis_rule_id,
                "severity": finding.severity,
                "description": finding.description,
                "remediation_steps": finding.remediation_steps,
            }
        )
    return findings
