"""
Admin API endpoints for managing organizations and tenant providers.

These endpoints manage the multi-tenant provider configuration:
  - CRUD for organizations
  - CRUD for tenant providers (GCP/OCI/AWS/Azure accounts per org)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.schemas.external import (
    OrganizationCreate,
    OrganizationResponse,
    TenantProviderCreate,
    TenantProviderCredentials,
    TenantProviderResponse,
    TenantProviderUpdate,
)
from app.services.scheduler_service import run_scheduled_scans
from app.services.tenant_service import (
    create_organisation,
    create_tenant_provider,
    delete_organisation,
    delete_tenant_provider,
    get_organisation_by_id,
    get_tenant_provider_by_id,
    list_organisations,
    list_tenant_providers,
    store_tenant_provider_credentials,
    toggle_tenant_provider,
    update_tenant_provider,
)


router = APIRouter(prefix="/admin", tags=["admin"])


# ─── Organizations ───

@router.post("/organisations", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
def create_org(payload: OrganizationCreate, db: Session = Depends(get_db)):
    existing = get_organisation_by_id(db, 0)  # Dummy, we check by slug
    org = create_organisation(db, payload.name, payload.slug)
    db.commit()
    db.refresh(org)
    return OrganizationResponse(id=org.id, name=org.name, slug=org.slug, created_at=org.created_at)


@router.get("/organisations", response_model=list[OrganizationResponse])
def list_orgs(db: Session = Depends(get_db)):
    orgs = list_organisations(db)
    return [OrganizationResponse(id=o.id, name=o.name, slug=o.slug, created_at=o.created_at) for o in orgs]


@router.get("/organisations/{org_id}", response_model=OrganizationResponse)
def get_org(org_id: int, db: Session = Depends(get_db)):
    org = get_organisation_by_id(db, org_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")
    return OrganizationResponse(id=org.id, name=org.name, slug=org.slug, created_at=org.created_at)


@router.delete("/organisations/{org_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_org(org_id: int, db: Session = Depends(get_db)):
    org = get_organisation_by_id(db, org_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")
    delete_organisation(db, org)
    db.commit()
    return None


# ─── Tenant Providers ───

@router.post("/tenant-providers", response_model=TenantProviderResponse, status_code=status.HTTP_201_CREATED)
def create_provider(payload: TenantProviderCreate, db: Session = Depends(get_db)):
    """Register a new cloud provider for an organisation."""
    org = get_organisation_by_id(db, payload.organisation_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")

    provider = create_tenant_provider(
        db,
        organisation_id=payload.organisation_id,
        provider_type=payload.provider_type,
        provider_label=payload.provider_label,
        focus_version=payload.focus_version,
        enabled=payload.enabled,
        config=payload.config,
        secret_refs=payload.secret_refs,
    )
    db.commit()
    db.refresh(provider)
    return TenantProviderResponse(
        id=provider.id,
        organisation_id=provider.organisation_id,
        provider_type=provider.provider_type,
        provider_label=provider.provider_label,
        enabled=provider.enabled,
        focus_version=provider.focus_version,
        config=provider.config,
        created_at=provider.created_at,
        updated_at=provider.updated_at,
    )


@router.get("/tenant-providers", response_model=list[TenantProviderResponse])
def list_providers(
    organisation_id: int | None = Query(None),
    provider_type: str | None = Query(None, pattern=r"^(GCP|OCI|AWS|AZURE)?$"),
    db: Session = Depends(get_db),
):
    """List all tenant providers, optionally filtered by organisation and/or provider type."""
    providers = list_tenant_providers(
        db,
        organisation_id=organisation_id,
        provider_type=provider_type,
    )
    return [
        TenantProviderResponse(
            id=p.id,
            organisation_id=p.organisation_id,
            provider_type=p.provider_type,
            provider_label=p.provider_label,
            enabled=p.enabled,
            focus_version=p.focus_version,
            config=p.config,
            created_at=p.created_at,
            updated_at=p.updated_at,
        )
        for p in providers
    ]


@router.get("/tenant-providers/{provider_id}", response_model=TenantProviderResponse)
def get_provider(provider_id: int, db: Session = Depends(get_db)):
    provider = get_tenant_provider_by_id(db, provider_id)
    if provider is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant provider not found")
    return TenantProviderResponse(
        id=provider.id,
        organisation_id=provider.organisation_id,
        provider_type=provider.provider_type,
        provider_label=provider.provider_label,
        enabled=provider.enabled,
        focus_version=provider.focus_version,
        config=provider.config,
        created_at=provider.created_at,
        updated_at=provider.updated_at,
    )


@router.put("/tenant-providers/{provider_id}", response_model=TenantProviderResponse)
def update_provider(provider_id: int, payload: TenantProviderUpdate, db: Session = Depends(get_db)):
    provider = get_tenant_provider_by_id(db, provider_id)
    if provider is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant provider not found")

    provider = update_tenant_provider(
        db,
        provider,
        provider_label=payload.provider_label,
        enabled=payload.enabled,
        focus_version=payload.focus_version,
        config=payload.config,
        secret_refs=payload.secret_refs,
    )
    db.commit()
    db.refresh(provider)
    return TenantProviderResponse(
        id=provider.id,
        organisation_id=provider.organisation_id,
        provider_type=provider.provider_type,
        provider_label=provider.provider_label,
        enabled=provider.enabled,
        focus_version=provider.focus_version,
        config=provider.config,
        created_at=provider.created_at,
        updated_at=provider.updated_at,
    )


@router.post("/tenant-providers/{provider_id}/toggle", response_model=TenantProviderResponse)
def toggle_provider(provider_id: int, db: Session = Depends(get_db)):
    """Enable or disable a tenant provider."""
    provider = get_tenant_provider_by_id(db, provider_id)
    if provider is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant provider not found")
    provider = toggle_tenant_provider(db, provider)
    db.commit()
    db.refresh(provider)
    return TenantProviderResponse(
        id=provider.id,
        organisation_id=provider.organisation_id,
        provider_type=provider.provider_type,
        provider_label=provider.provider_label,
        enabled=provider.enabled,
        focus_version=provider.focus_version,
        config=provider.config,
        created_at=provider.created_at,
        updated_at=provider.updated_at,
    )


@router.delete("/tenant-providers/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_provider(provider_id: int, db: Session = Depends(get_db)):
    provider = get_tenant_provider_by_id(db, provider_id)
    if provider is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant provider not found")
    delete_tenant_provider(db, provider)
    db.commit()
    return None


@router.put("/tenant-providers/{provider_id}/credentials", status_code=status.HTTP_200_OK)
def store_credentials(
    provider_id: int,
    payload: TenantProviderCredentials,
    db: Session = Depends(get_db),
):
    provider = get_tenant_provider_by_id(db, provider_id)
    if provider is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant provider not found")

    if not payload.credentials_json and not payload.config_content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide credentials_json (GCP) or config_content + private_key (OCI)",
        )

    store_tenant_provider_credentials(
        db,
        provider,
        credentials_json=payload.credentials_json,
        config_content=payload.config_content,
        private_key=payload.private_key,
    )
    db.commit()
    db.refresh(provider)
    return {"status": "ok", "provider_id": provider.id, "provider_type": provider.provider_type}


@router.post("/scheduler/run", status_code=status.HTTP_200_OK)
def trigger_scheduled_scans(
    provider_id: int | None = Query(None, description="Optional specific provider ID to scan"),
    db: Session = Depends(get_db),
):
    """Run scans for all enabled TenantProviders with stored credentials."""
    scan_ids = run_scheduled_scans(db, provider_id=provider_id, trigger_type="scheduled")
    return {"status": "ok", "scan_ids": scan_ids, "count": len(scan_ids)}