"""
Service layer for organizations and tenant providers.
Handles CRUD operations and provider-to-agent routing.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Organization, TenantProvider, Project, Scan, ScanStatus


# ─── Organizations ───

def create_organisation(db: Session, name: str, slug: str) -> Organization:
    org = Organization(name=name, slug=slug)
    db.add(org)
    db.flush()
    return org


def get_organisation_by_id(db: Session, organisation_id: int) -> Organization | None:
    return db.execute(
        select(Organization).where(Organization.id == organisation_id)
    ).scalar_one_or_none()


def get_organisation_by_slug(db: Session, slug: str) -> Organization | None:
    return db.execute(
        select(Organization).where(Organization.slug == slug)
    ).scalar_one_or_none()


def list_organisations(db: Session) -> list[Organization]:
    return db.execute(
        select(Organization).order_by(Organization.id.asc())
    ).scalars().all()


def delete_organisation(db: Session, org: Organization) -> None:
    db.delete(org)


# ─── Tenant Providers ───

def create_tenant_provider(
    db: Session,
    organisation_id: int,
    provider_type: str,
    provider_label: str,
    focus_version: str,
    enabled: bool = True,
    config: dict | None = None,
    secret_refs: dict | None = None,
) -> TenantProvider:
    provider = TenantProvider(
        organisation_id=organisation_id,
        provider_type=provider_type,
        provider_label=provider_label,
        enabled=enabled,
        focus_version=focus_version,
        config=config or {},
        secret_refs=secret_refs or {},
    )
    db.add(provider)
    db.flush()
    return provider


def get_tenant_provider_by_id(db: Session, provider_id: int) -> TenantProvider | None:
    return db.execute(
        select(TenantProvider).where(TenantProvider.id == provider_id)
    ).scalar_one_or_none()


def list_tenant_providers(
    db: Session,
    organisation_id: int | None = None,
    provider_type: str | None = None,
    enabled_only: bool = False,
) -> list[TenantProvider]:
    stmt = select(TenantProvider).order_by(TenantProvider.id.asc())
    if organisation_id is not None:
        stmt = stmt.where(TenantProvider.organisation_id == organisation_id)
    if provider_type is not None:
        stmt = stmt.where(TenantProvider.provider_type == provider_type)
    if enabled_only:
        stmt = stmt.where(TenantProvider.enabled.is_(True))
    return db.execute(stmt).scalars().all()


def update_tenant_provider(
    db: Session,
    provider: TenantProvider,
    **kwargs,
) -> TenantProvider:
    for key, value in kwargs.items():
        if value is not None and hasattr(provider, key):
            setattr(provider, key, value)
    db.flush()
    return provider


def toggle_tenant_provider(db: Session, provider: TenantProvider) -> TenantProvider:
    provider.enabled = not provider.enabled
    db.flush()
    return provider


def delete_tenant_provider(db: Session, provider: TenantProvider) -> None:
    db.delete(provider)


# ─── External trigger logic ───

class OrganisationNotFoundError(Exception):
    pass

class ProviderNotFoundError(Exception):
    pass

class ScanExecutionError(Exception):
    pass


def trigger_scan_service(
    db: Session,
    organisation_id: int,
    provider_type: str,
    provider_id: int | None = None,
    trigger_type: str = "scheduled",
    schedule_name: str | None = None,
) -> dict:
    """
    Single entry point for triggering a scan.

    Called by the API endpoint OR directly by a cron job / scheduler.

    Returns a dict with scan_id, organisation_id, provider, provider_label.

    Raises HTTPException on errors for direct use in endpoint responses.
    """
    from fastapi import HTTPException, status
    from app.services.agent_service import run_scan_for_project, AgentExecutionError

    org = get_organisation_by_id(db, organisation_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Organisation {organisation_id} not found")

    provider = find_enabled_provider_for_organisation(
        db,
        organisation_id=organisation_id,
        provider_type=provider_type,
        provider_id=provider_id,
    )
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No enabled {provider_type} provider found for organisation {organisation_id}",
        )

    project = get_or_create_project_for_provider(db, provider, org)
    db.commit()

    try:
        scan_id = run_scan_for_project(db, project, trigger_type=trigger_type)
    except AgentExecutionError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {exc}",
        ) from exc

    return {
        "status": "accepted",
        "scan_id": scan_id,
        "organisation_id": organisation_id,
        "provider": provider_type,
        "provider_label": provider.provider_label,
        "estimated_duration_seconds": 120,
    }


# Alias for backwards compatibility
trigger_scan_for_organisation = trigger_scan_service


def find_enabled_provider_for_organisation(
    db: Session,
    organisation_id: int,
    provider_type: str,
    provider_id: int | None = None,
) -> TenantProvider | None:
    """
    Find the best matching enabled provider for a trigger request.
    If provider_id is given, use that specific provider.
    Otherwise, use the first enabled provider of that type.
    """
    if provider_id is not None:
        provider = get_tenant_provider_by_id(db, provider_id)
        if (
            provider
            and provider.organisation_id == organisation_id
            and provider.provider_type == provider_type
            and provider.enabled
        ):
            return provider
        return None

    # Find first enabled provider of this type
    providers = list_tenant_providers(
        db,
        organisation_id=organisation_id,
        provider_type=provider_type,
        enabled_only=True,
    )
    return providers[0] if providers else None


def get_or_create_project_for_provider(
    db: Session,
    provider: TenantProvider,
    organisation: Organization,
) -> Project:
    """
    Get or create a Project linked to this TenantProvider.
    The project name is derived from the provider label + type.
    """
    project_name = f"{provider.provider_label} ({provider.provider_type})"
    gcp_id = provider.config.get("project_id") or provider.config.get("tenancy_ocid") or f"{provider.provider_type.lower()}-{provider.id}"

    existing = db.execute(
        select(Project).where(
            Project.tenant_provider_id == provider.id,
            Project.organisation_id == organisation.id,
        )
    ).scalar_one_or_none()

    if existing:
        return existing

    project = Project(
        name=project_name,
        gcp_project_id=gcp_id,
        cloud_provider=provider.provider_type,
        organisation_id=organisation.id,
        tenant_provider_id=provider.id,
    )
    db.add(project)
    db.flush()
    return project