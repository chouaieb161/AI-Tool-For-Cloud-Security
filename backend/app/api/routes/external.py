"""
External API endpoints for the company platform's scheduler module.

These endpoints are called by the platform cron/scheduler to:
  - List available providers for an organisation
  - Trigger a scan for a specific provider
  - Check scan status

The scheduler API body always includes: provider + organisation_id
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models import Scan, ScanStatus, Project
from app.schemas.external import (
    ProviderSummary,
    TriggerScanRequest,
    TriggerScanResponse,
)
from app.schemas.scan_result import ScanResponse
from app.services.tenant_service import (
    trigger_scan_service,
    get_organisation_by_id,
)


router = APIRouter(prefix="/external", tags=["external"])


@router.get("/providers", response_model=list[ProviderSummary])
def list_providers(
    organisation_id: int = Query(..., description="Organisation ID"),
    provider_type: str | None = Query(None, pattern=r"^(GCP|OCI|AWS|AZURE)?$"),
    enabled_only: bool = Query(True),
    db: Session = Depends(get_db),
):
    """List all providers for an organisation. Called by the scheduler to discover available targets."""
    org = get_organisation_by_id(db, organisation_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")

    from app.services.tenant_service import list_tenant_providers

    providers = list_tenant_providers(
        db,
        organisation_id=organisation_id,
        provider_type=provider_type,
        enabled_only=enabled_only,
    )
    return [
        ProviderSummary(
            id=p.id,
            organisation_id=p.organisation_id,
            provider_type=p.provider_type,
            provider_label=p.provider_label,
            enabled=p.enabled,
            focus_version=p.focus_version,
            config=p.config,
        )
        for p in providers
    ]


@router.get("/providers/{provider_id}", response_model=ProviderSummary)
def get_provider(
    provider_id: int,
    organisation_id: int = Query(...),
    db: Session = Depends(get_db),
):
    """Get details of a specific provider."""
    from app.services.tenant_service import get_tenant_provider_by_id

    provider = get_tenant_provider_by_id(db, provider_id)
    if provider is None or provider.organisation_id != organisation_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")

    return ProviderSummary(
        id=provider.id,
        organisation_id=provider.organisation_id,
        provider_type=provider.provider_type,
        provider_label=provider.provider_label,
        enabled=provider.enabled,
        focus_version=provider.focus_version,
        config=provider.config,
    )


@router.post("/trigger-scan", response_model=TriggerScanResponse, status_code=status.HTTP_202_ACCEPTED)
def trigger_scan(
    payload: TriggerScanRequest,
    db: Session = Depends(get_db),
):
    """
    Trigger a security scan for a provider.

    Called by the platform scheduler.
    Delegates to tenant_service.trigger_scan_service()
    so cron jobs can call the same logic without HTTP.
    """
    result = trigger_scan_service(
        db=db,
        organisation_id=payload.organisation_id,
        provider_type=payload.provider,
        provider_id=payload.provider_id,
        trigger_type=payload.trigger_type,
        schedule_name=payload.schedule_name,
    )
    return TriggerScanResponse(**result)


@router.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan_status(
    scan_id: int,
    organisation_id: int = Query(...),
    db: Session = Depends(get_db),
):
    """Get scan status. Called by the scheduler to poll scan progress."""
    from sqlalchemy import select

    scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    # Verify the scan belongs to this organisation via the project
    project = db.execute(select(Project).where(Project.id == scan.project_id)).scalar_one_or_none()
    if project is None or project.organisation_id != organisation_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found for this organisation")

    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        timestamp=scan.timestamp,
        score=scan.score,
        status=scan.status,
    )