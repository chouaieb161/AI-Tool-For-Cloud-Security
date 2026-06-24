from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.db.models import ScanStatus, Severity


class GCPResourceResult(BaseModel):
    type: str = Field(..., description="Resource type, e.g. COMPUTE_INSTANCE")
    name: str
    gcp_uri: str


class GCPFindingResult(BaseModel):
    cis_rule_id: str
    severity: Severity
    description: str
    remediation_steps: str
    resource_gcp_uri: str | None = None


class GCPScanResult(BaseModel):
    score: int = Field(..., ge=0, le=100)
    status: ScanStatus = ScanStatus.COMPLETED
    resources: list[GCPResourceResult] = Field(default_factory=list)
    findings: list[GCPFindingResult] = Field(default_factory=list)


class ProjectCreate(BaseModel):
    name: str
    gcp_project_id: str


class ProjectResponse(BaseModel):
    id: int
    name: str
    gcp_project_id: str
    created_at: datetime


class ScanTriggerResponse(BaseModel):
    scan_id: int


class FreeformScanRequest(BaseModel):
    project_id: int
    query: str = Field(..., min_length=1)


class DashboardResponse(BaseModel):
    total_resources_count: int
    resource_count_basis: str = "unknown"
    risk_score: int
    findings_by_severity: dict[str, int]
    compliance_percentage: float
    latest_scan_id: int | None = None


class FindingResponse(BaseModel):
    id: int
    scan_id: int
    resource_id: int | None
    resource_name: str | None
    resource_type: str | None
    resource_gcp_uri: str | None = None
    resource_project_id: str | None = None
    category: str
    cis_rule_id: str
    severity: Severity
    description: str
    remediation_steps: str


class ScanResponse(BaseModel):
    id: int
    project_id: int
    timestamp: datetime
    score: int
    status: ScanStatus


class ScanHistoryItem(BaseModel):
    scan_id: int
    score: int
    findings_count: int
    timestamp: datetime


class FindingsMatrixItem(BaseModel):
    category: str
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0


class RemediationPlanItem(BaseModel):
    cis_rule_id: str
    severity: Severity
    description: str
    remediation_steps: str
    affected_resources: int


class ScanDiffResponse(BaseModel):
    new_findings: list[FindingResponse] = Field(default_factory=list)
    fixed_findings: list[FindingResponse] = Field(default_factory=list)
    persistent_findings: list[FindingResponse] = Field(default_factory=list)