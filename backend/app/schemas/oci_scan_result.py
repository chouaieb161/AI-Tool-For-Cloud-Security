"""OCI scan result schemas — mirrors GCP schemas but for OCI resources."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.db.models import ScanStatus, Severity


class OCIResourceResult(BaseModel):
    type: str = Field(..., description="Resource type, e.g. COMPUTE_INSTANCE")
    name: str
    ocid: str = Field(..., description="OCI OCID of the resource")


class OCIFindingResult(BaseModel):
    cis_rule_id: str
    severity: Severity
    description: str
    remediation_steps: str
    resource_ocid: str | None = None


class OCIScanResult(BaseModel):
    score: int = Field(..., ge=0, le=100)
    status: ScanStatus = ScanStatus.COMPLETED
    resources: list[OCIResourceResult] = Field(default_factory=list)
    findings: list[OCIFindingResult] = Field(default_factory=list)


class OCIProjectCreate(BaseModel):
    name: str
    compartment_ocid: str
    tenancy_ocid: str | None = None
    region: str | None = None


class OCIProjectResponse(BaseModel):
    id: int
    name: str
    cloud_provider: str
    created_at: datetime


class OCIScanTriggerResponse(BaseModel):
    scan_id: int


class OCIFreeformScanRequest(BaseModel):
    project_id: int
    query: str = Field(..., min_length=1)


class OCIDashboardResponse(BaseModel):
    total_resources_count: int
    resource_count_basis: str = "unknown"
    risk_score: int
    findings_by_severity: dict[str, int]
    compliance_percentage: float
    latest_scan_id: int | None = None
    latest_completed_scan_id: int | None = None


class OCIScanResponse(BaseModel):
    id: int
    project_id: int
    timestamp: datetime
    score: int
    status: ScanStatus


class OCIScanHistoryItem(BaseModel):
    scan_id: int
    score: int
    findings_count: int
    timestamp: datetime


class OCIFindingsMatrixItem(BaseModel):
    category: str
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0


class OCIRemediationPlanItem(BaseModel):
    cis_rule_id: str
    severity: Severity
    description: str
    remediation_steps: str
    affected_resources: int


class OCIScanDiffResponse(BaseModel):
    new_findings: list[dict] = Field(default_factory=list)
    fixed_findings: list[dict] = Field(default_factory=list)
    persistent_findings: list[dict] = Field(default_factory=list)