"""OCI scan routes — trigger, query, and retrieve OCI CIS security scans."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import get_db
from app.db.models import Project
from app.schemas.oci_scan_result import (
    OCIScanTriggerResponse,
    OCIFreeformScanRequest,
    OCIScanResult,
    OCIDashboardResponse,
)
from app.services.oci_agent_service import (
    run_oci_langgraph_scan,
    run_oci_scan_with_query,
    persist_oci_scan_result,
)
from app.services.dashboard_service import (
    get_dashboard_data,
    get_project_or_404,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/oci", tags=["oci"])


def _get_oci_project(db: Session, project_id: int) -> Project:
    """Get project and verify it's an OCI project."""
    project = get_project_or_404(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.cloud_provider != "OCI":
        raise HTTPException(status_code=400, detail=f"Project {project_id} is not an OCI project (provider={project.cloud_provider})")
    return project


@router.post("/scans/trigger", response_model=OCIScanTriggerResponse)
def trigger_oci_scan(project_id: int = Query(..., description="OCI project ID"), db: Session = Depends(get_db)):
    """Trigger a full OCI CIS security scan."""
    project = _get_oci_project(db, project_id)

    try:
        result = run_oci_langgraph_scan()
    except Exception as e:
        logger.exception(f"OCI scan failed for project {project_id}")
        raise HTTPException(status_code=500, detail=f"OCI scan failed: {e}")

    try:
        scan_id = persist_oci_scan_result(db, project, result, trigger_type="manual")
        db.commit()
    except Exception as e:
        db.rollback()
        logger.exception(f"Failed to persist OCI scan result for project {project_id}")
        raise HTTPException(status_code=500, detail=f"Failed to persist scan: {e}")

    return OCIScanTriggerResponse(scan_id=scan_id)


@router.post("/scans/freeform", response_model=OCIScanResult)
def freeform_oci_scan(request: OCIFreeformScanRequest, db: Session = Depends(get_db)):
    """Run an OCI scan with a custom query (e.g., 'Check IAM users')."""
    project = _get_oci_project(db, request.project_id)

    try:
        result = run_oci_scan_with_query(request.query)
    except Exception as e:
        logger.exception(f"OCI freeform scan failed for project {request.project_id}")
        raise HTTPException(status_code=500, detail=f"OCI scan failed: {e}")

    try:
        persist_oci_scan_result(db, project, result, trigger_type="freeform")
        db.commit()
    except Exception as e:
        db.rollback()
        logger.exception(f"Failed to persist OCI freeform scan for project {request.project_id}")

    return result


@router.get("/scans/{scan_id}/findings", response_model=OCIScanResult)
def get_oci_scan_findings(scan_id: int, db: Session = Depends(get_db)):
    """Get findings for a specific OCI scan."""
    from app.db.models import Finding, Resource, Scan, ScanResource
    from sqlalchemy import select

    scan = db.execute(
        select(Scan).where(Scan.id == scan_id)
    ).scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    rows = db.execute(
        select(Finding, Resource)
        .outerjoin(Resource, Finding.resource_id == Resource.id)
        .where(Finding.scan_id == scan_id)
    ).all()

    from app.schemas.oci_scan_result import OCIFindingResult, OCIResourceResult
    findings = []
    resources = []
    seen_resources: set[str] = set()
    for finding, resource in rows:
        findings.append(OCIFindingResult(
            cis_rule_id=finding.cis_rule_id,
            severity=finding.severity,
            description=finding.description,
            remediation_steps=finding.remediation_steps,
            resource_ocid=resource.gcp_uri if resource else None,
        ))
        if resource and resource.gcp_uri not in seen_resources:
            seen_resources.add(resource.gcp_uri)
            resources.append(OCIResourceResult(
                type=resource.type,
                name=resource.name,
                ocid=resource.gcp_uri,
            ))

    return OCIScanResult(
        score=scan.score,
        status=scan.status,
        resources=resources,
        findings=findings,
    )


@router.get("/dashboard", response_model=OCIDashboardResponse)
def get_oci_dashboard(project_id: int = Query(..., description="OCI project ID"), db: Session = Depends(get_db)):
    """Get OCI dashboard data for a project."""
    project = _get_oci_project(db, project_id)
    return get_dashboard_data(db, project.id)