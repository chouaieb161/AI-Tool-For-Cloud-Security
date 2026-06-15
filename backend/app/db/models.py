from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanStatus(str, enum.Enum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    gcp_project_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

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
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus, name="scan_status"), nullable=False, index=True)

    project: Mapped[Project] = relationship("Project", back_populates="scans")
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
