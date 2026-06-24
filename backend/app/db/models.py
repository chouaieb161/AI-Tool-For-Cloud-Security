from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanStatus(str, enum.Enum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    RUNNING = "RUNNING"
    PENDING = "PENDING"


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Organization(Base):
    """Multi-tenant: each organization has its own providers, projects, scans."""
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    tenant_providers: Mapped[list[TenantProvider]] = relationship(
        "TenantProvider", back_populates="organisation", cascade="all, delete-orphan"
    )
    projects: Mapped[list[Project]] = relationship(
        "Project", back_populates="organisation", cascade="all, delete-orphan"
    )


class TenantProvider(Base):
    """
    Stores cloud provider configuration per organization.
    Each row represents a GCP/OCI/AWS/Azure account or scope that can be audited.
    Secrets are stored via secret_refs pointing to an external vault.
    """
    __tablename__ = "tenant_providers"
    __table_args__ = (
        UniqueConstraint("organisation_id", "provider_type", "provider_label", name="uq_org_provider_label"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    organisation_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # GCP, OCI, AWS, AZURE
    provider_label: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    focus_version: Mapped[str] = mapped_column(String(32), nullable=False)  # CIS_GCP_3.0, CIS_OCI_3.0
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    secret_refs: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    organisation: Mapped[Organization] = relationship("Organization", back_populates="tenant_providers")
    projects: Mapped[list[Project]] = relationship("Project", back_populates="tenant_provider")
    scans: Mapped[list[Scan]] = relationship("Scan", back_populates="tenant_provider")


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    gcp_project_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    # Multi-cloud support
    cloud_provider: Mapped[str] = mapped_column(String(16), nullable=False, default="GCP", index=True)
    # Production links
    organisation_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True, index=True
    )
    tenant_provider_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("tenant_providers.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    organisation: Mapped[Organization | None] = relationship("Organization", back_populates="projects")
    tenant_provider: Mapped[TenantProvider | None] = relationship("TenantProvider", back_populates="projects")
    resources: Mapped[list[Resource]] = relationship("Resource", back_populates="project", cascade="all, delete-orphan")
    scans: Mapped[list[Scan]] = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
    chat_sessions: Mapped[list[ChatSession]] = relationship(
        "ChatSession", back_populates="project", cascade="all, delete-orphan"
    )


class ChatSession(Base):
    __tablename__ = "chat_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    project: Mapped[Project] = relationship("Project", back_populates="chat_sessions")
    messages: Mapped[list[ChatMessage]] = relationship(
        "ChatMessage", back_populates="session", cascade="all, delete-orphan"
    )


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("chat_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    citations_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    steps_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    session: Mapped[ChatSession] = relationship("ChatSession", back_populates="messages")


class MemoryNote(Base):
    __tablename__ = "memory_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    session_id: Mapped[int | None] = mapped_column(
        ForeignKey("chat_sessions.id", ondelete="SET NULL"), nullable=True, index=True
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    pinned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    project: Mapped[Project] = relationship("Project")
    session: Mapped[ChatSession | None] = relationship("ChatSession")


class Resource(Base):
    __tablename__ = "resources"
    __table_args__ = (
        UniqueConstraint("project_id", "gcp_uri", name="uq_resource_project_uri"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    gcp_uri: Mapped[str] = mapped_column(String(1024), nullable=False)

    project: Mapped[Project] = relationship("Project", back_populates="resources")
    findings: Mapped[list[Finding]] = relationship("Finding", back_populates="resource")
    scan_resources: Mapped[list[ScanResource]] = relationship(
        "ScanResource", back_populates="resource", cascade="all, delete-orphan"
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_provider_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("tenant_providers.id", ondelete="SET NULL"), nullable=True, index=True
    )
    trigger_type: Mapped[str | None] = mapped_column(String(32), nullable=True)  # 'scheduled', 'manual', 'webhook'
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus, name="scan_status"), nullable=False, index=True)

    project: Mapped[Project] = relationship("Project", back_populates="scans")
    tenant_provider: Mapped[TenantProvider | None] = relationship("TenantProvider", back_populates="scans")
    findings: Mapped[list[Finding]] = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    scan_resources: Mapped[list[ScanResource]] = relationship(
        "ScanResource", back_populates="scan", cascade="all, delete-orphan"
    )


class ScanResource(Base):
    __tablename__ = "scan_resources"
    __table_args__ = (
        UniqueConstraint("scan_id", "resource_id", name="uq_scan_resource"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    resource_id: Mapped[int] = mapped_column(ForeignKey("resources.id", ondelete="CASCADE"), nullable=False, index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    scan: Mapped[Scan] = relationship("Scan", back_populates="scan_resources")
    resource: Mapped[Resource] = relationship("Resource", back_populates="scan_resources")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    resource_id: Mapped[int | None] = mapped_column(ForeignKey("resources.id", ondelete="SET NULL"), nullable=True, index=True)
    cis_rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity, name="finding_severity"), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_steps: Mapped[str] = mapped_column(Text, nullable=False)

    scan: Mapped[Scan] = relationship("Scan", back_populates="findings")
    resource: Mapped[Resource | None] = relationship("Resource", back_populates="findings")