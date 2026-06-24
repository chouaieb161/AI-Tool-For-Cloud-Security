from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.db.database import get_db
from app.db.models import Scan
from app.schemas.scan_result import (
    FindingResponse,
    FreeformScanRequest,
    RemediationPlanItem,
    ScanDiffResponse,
    ScanHistoryItem,
    ScanResponse,
    ScanTriggerResponse,
    FindingsMatrixItem,
)
from app.services.agent_service import AgentExecutionError, run_scan_for_project_with_query
from app.services.dashboard_service import (
    get_project_or_404,
    get_scan_findings,
    get_scan_history,
    get_findings_matrix,
    get_remediation_plan,
    get_scan_diff,
)


router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("/scan", response_model=ScanTriggerResponse, status_code=status.HTTP_202_ACCEPTED)
def trigger_freeform_scan(payload: FreeformScanRequest, db: Session = Depends(get_db)):
    project = get_project_or_404(db, payload.project_id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    try:
        scan_id = run_scan_for_project_with_query(db, project, payload.query)
    except AgentExecutionError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc

    return ScanTriggerResponse(scan_id=scan_id)


@router.get("/{scan_id}/findings", response_model=list[FindingResponse])
def scan_findings(scan_id: int, db: Session = Depends(get_db)):
    rows = get_scan_findings(db, scan_id)
    return [FindingResponse(**row) for row in rows]


@router.get("/{scan_id}", response_model=ScanResponse)
def scan_status(scan_id: int, db: Session = Depends(get_db)):
    scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        timestamp=scan.timestamp,
        score=scan.score,
        status=scan.status,
    )


# --- NEW ENDPOINTS ---

@router.get("/history/{project_id}", response_model=list[ScanHistoryItem])
def scan_history(
    project_id: int,
    limit: int = Query(default=20, ge=2, le=100),
    db: Session = Depends(get_db),
):
    """Return scan score trend data for dashboard chart."""
    return [ScanHistoryItem(**row) for row in get_scan_history(db, project_id, limit=limit)]


@router.get("/matrix/{project_id}", response_model=list[FindingsMatrixItem])
def findings_matrix(project_id: int, db: Session = Depends(get_db)):
    """Return findings aggregated by category × severity for heatmap."""
    return [FindingsMatrixItem(**row) for row in get_findings_matrix(db, project_id)]


@router.get("/remediation-plan/{project_id}", response_model=list[RemediationPlanItem])
def remediation_plan(project_id: int, db: Session = Depends(get_db)):
    """Return prioritized remediation plan for the latest scan."""
    return [RemediationPlanItem(**row) for row in get_remediation_plan(db, project_id)]


@router.get("/diff/{project_id}", response_model=ScanDiffResponse)
def scan_diff(
    project_id: int,
    from_scan_id: int = Query(...),
    to_scan_id: int = Query(...),
    db: Session = Depends(get_db),
):
    """Compare findings between two scans: new, fixed, persistent."""
    project = get_project_or_404(db, project_id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    result = get_scan_diff(db, project_id, from_scan_id, to_scan_id)
    return ScanDiffResponse(
        new_findings=[FindingResponse(**f) for f in result["new_findings"]],
        fixed_findings=[FindingResponse(**f) for f in result["fixed_findings"]],
        persistent_findings=[FindingResponse(**f) for f in result["persistent_findings"]],
    )