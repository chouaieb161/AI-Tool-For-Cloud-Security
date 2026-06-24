from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


# --- Organization ---

class OrganizationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$")


class OrganizationResponse(BaseModel):
    id: int
    name: str
    slug: str
    created_at: datetime


# --- Tenant Provider ---

class TenantProviderCreate(BaseModel):
    organisation_id: int
    provider_type: str = Field(..., pattern=r"^(GCP|OCI|AWS|AZURE)$")
    provider_label: str = Field(..., min_length=1, max_length=255)
    focus_version: str = Field(..., pattern=r"^CIS_[A-Z]+_\d+\.\d+$")
    enabled: bool = True
    config: dict = Field(default_factory=dict)
    secret_refs: dict = Field(default_factory=dict)


class TenantProviderUpdate(BaseModel):
    provider_label: str | None = None
    enabled: bool | None = None
    focus_version: str | None = None
    config: dict | None = None
    secret_refs: dict | None = None


class TenantProviderResponse(BaseModel):
    id: int
    organisation_id: int
    provider_type: str
    provider_label: str
    enabled: bool
    focus_version: str
    config: dict
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# --- External trigger (for platform scheduler) ---

class TriggerScanRequest(BaseModel):
    organisation_id: int
    provider: str = Field(..., pattern=r"^(GCP|OCI|AWS|AZURE)$")
    provider_id: int | None = None
    trigger_type: str = Field(default="scheduled", pattern=r"^(scheduled|manual|webhook)$")
    schedule_name: str | None = Field(default=None, max_length=255)


class TriggerScanResponse(BaseModel):
    status: str = "accepted"
    scan_id: int
    organisation_id: int
    provider: str
    provider_label: str | None = None
    estimated_duration_seconds: int = 120


# --- External providers listing (for platform scheduler) ---

class ProviderSummary(BaseModel):
    id: int
    organisation_id: int
    provider_type: str
    provider_label: str
    enabled: bool
    focus_version: str
    config: dict