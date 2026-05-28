from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.schemas.scan_result import FindingResponse, FreeformScanRequest, ScanResponse, ScanTriggerResponse
from app.services.agent_service import AgentExecutionError, run_scan_for_project_with_query
from app.services.dashboard_service import get_project_or_404, get_scan_findings
from app.db.models import Scan
from sqlalchemy import select


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
