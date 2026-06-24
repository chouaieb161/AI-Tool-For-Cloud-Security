from __future__ import annotations

from functools import cmp_to_key

from sqlalchemy import func, select, case, text
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

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _category_from_cis_rule(cis_rule_id: str | None) -> str:
    if not cis_rule_id:
        return "Unknown"
    major = str(cis_rule_id).split(".", maxsplit=1)[0]
    return _CIS_CATEGORY_BY_SECTION.get(major, "Unknown")


def _severity_sort_key(f: dict) -> int:
    return _SEVERITY_ORDER.get(f.get("severity", ""), 99)


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


def _enrich_finding_row(finding: Finding, resource: Resource | None) -> dict:
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "resource_id": resource.id if resource else None,
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


def get_scan_findings(db: Session, scan_id: int) -> list[dict]:
    rows = db.execute(
        select(Finding, Resource)
        .outerjoin(Resource, Finding.resource_id == Resource.id)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.id.asc())
    ).all()
    return [_enrich_finding_row(finding, resource) for finding, resource in rows]


# --- NEW ENDPOINT FUNCTIONS ---

def get_scan_history(db: Session, project_id: int, limit: int = 20) -> list[dict]:
    """Return the last N scans with score and findings count for trend chart."""
    scans = db.execute(
        select(Scan, func.count(Finding.id).label("findings_count"))
        .outerjoin(Finding, Finding.scan_id == Scan.id)
        .where(Scan.project_id == project_id)
        .group_by(Scan.id)
        .order_by(Scan.timestamp.asc(), Scan.id.asc())
        .limit(limit)
    ).all()

    return [
        {
            "scan_id": scan.id,
            "score": scan.score,
            "findings_count": int(findings_count),
            "timestamp": scan.timestamp,
        }
        for scan, findings_count in scans
    ]


def get_findings_matrix(db: Session, project_id: int) -> list[dict]:
    """Return findings aggregated by category x severity for heatmap."""
    latest_scan = get_latest_scan(db, project_id)
    if not latest_scan:
        return []

    rows = db.execute(
        select(
            Finding.cis_rule_id,
            Finding.severity,
            func.count(Finding.id).label("cnt"),
        )
        .where(Finding.scan_id == latest_scan.id)
        .group_by(Finding.cis_rule_id, Finding.severity)
    ).all()

    matrix: dict[str, dict[str, int]] = {}
    for cis_rule, severity, cnt in rows:
        cat = _category_from_cis_rule(cis_rule)
        if cat not in matrix:
            matrix[cat] = {"category": cat, "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        sev_key = severity.value.lower()
        if sev_key in matrix[cat]:
            matrix[cat][sev_key] += int(cnt)
            matrix[cat]["total"] += int(cnt)

    return sorted(matrix.values(), key=lambda x: x["total"], reverse=True)


def get_remediation_plan(db: Session, project_id: int) -> list[dict]:
    """Return findings sorted by severity DESC, grouped by CIS rule with affected resource count."""
    latest_scan = get_latest_scan(db, project_id)
    if not latest_scan:
        return []

    rows = db.execute(
        select(
            Finding.cis_rule_id,
            Finding.severity,
            Finding.description,
            Finding.remediation_steps,
            func.count(Finding.resource_id).label("affected_resources"),
        )
        .where(Finding.scan_id == latest_scan.id)
        .group_by(Finding.cis_rule_id, Finding.severity, Finding.description, Finding.remediation_steps)
    ).all()

    items = [
        {
            "cis_rule_id": row.cis_rule_id,
            "severity": row.severity.value,
            "description": row.description,
            "remediation_steps": row.remediation_steps,
            "affected_resources": int(row.affected_resources),
        }
        for row in rows
    ]

    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    items.sort(key=lambda x: (sev_rank.get(x["severity"], 99), -x["affected_resources"]))
    return items


def get_scan_diff(db: Session, project_id: int, from_scan_id: int, to_scan_id: int) -> dict:
    """Compare findings between two scans: new, fixed, persistent."""
    from_findings_result = db.execute(
        select(Finding, Resource)
        .outerjoin(Resource, Finding.resource_id == Resource.id)
        .where(Finding.scan_id == from_scan_id)
    ).all()

    to_findings_result = db.execute(
        select(Finding, Resource)
        .outerjoin(Resource, Finding.resource_id == Resource.id)
        .where(Finding.scan_id == to_scan_id)
    ).all()

    def _make_key(finding: Finding, resource: Resource | None) -> str:
        resource_uri = resource.gcp_uri if resource else ""
        return f"{finding.cis_rule_id}||{resource_uri}"

    from_keys = {_make_key(f, r) for f, r in from_findings_result}
    to_map = {_make_key(f, r): _enrich_finding_row(f, r) for f, r in to_findings_result}
    from_map = {_make_key(f, r): _enrich_finding_row(f, r) for f, r in from_findings_result}

    new_findings = [v for k, v in to_map.items() if k not in from_keys]
    fixed_findings = [v for k, v in from_map.items() if k not in to_map]
    persistent_findings = [v for k, v in to_map.items() if k in from_keys]

    new_findings.sort(key=_severity_sort_key)
    fixed_findings.sort(key=_severity_sort_key)
    persistent_findings.sort(key=_severity_sort_key)

    return {
        "new_findings": new_findings,
        "fixed_findings": fixed_findings,
        "persistent_findings": persistent_findings,
    }