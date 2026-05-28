from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models import Project
from app.schemas.chat import MemoryNoteResponse, MemoryNoteUpdate
from app.schemas.scan_result import DashboardResponse, ProjectCreate, ProjectResponse, ScanTriggerResponse
from app.services.agent_service import AgentExecutionError, run_scan_for_project
from app.services.chat_service import (
    delete_memory_note,
    get_memory_note_or_none,
    list_memory_notes,
    set_memory_pinned,
)
from app.services.dashboard_service import get_dashboard_data, get_project_or_404


router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)):
    existing = db.execute(
        select(Project).where(Project.gcp_project_id == payload.gcp_project_id)
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Project with this gcp_project_id already exists",
        )

    project = Project(name=payload.name, gcp_project_id=payload.gcp_project_id)
    db.add(project)
    db.commit()
    db.refresh(project)
    return ProjectResponse(
        id=project.id,
        name=project.name,
        gcp_project_id=project.gcp_project_id,
        created_at=project.created_at,
    )


@router.get("", response_model=list[ProjectResponse])
def list_projects(db: Session = Depends(get_db)):
    rows = db.execute(select(Project).order_by(Project.id.asc())).scalars().all()
    return [
        ProjectResponse(
            id=p.id,
            name=p.name,
            gcp_project_id=p.gcp_project_id,
            created_at=p.created_at,
        )
        for p in rows
    ]


@router.post("/{id}/scan", response_model=ScanTriggerResponse, status_code=status.HTTP_202_ACCEPTED)
def trigger_project_scan(id: int, db: Session = Depends(get_db)):
    project = get_project_or_404(db, id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    try:
        scan_id = run_scan_for_project(db, project)
    except AgentExecutionError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc

    return ScanTriggerResponse(scan_id=scan_id)


@router.get("/{id}/dashboard", response_model=DashboardResponse)
def project_dashboard(id: int, db: Session = Depends(get_db)):
    project = get_project_or_404(db, id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    payload = get_dashboard_data(db, id)
    return DashboardResponse(**payload)


@router.get("/{id}/memory", response_model=list[MemoryNoteResponse])
def project_memory(
    id: int,
    db: Session = Depends(get_db),
    kind: str | None = None,
    limit: int = 50,
):
    project = get_project_or_404(db, id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    notes = list_memory_notes(db, project_id=project.id, kind=kind, limit=limit)
    return [
        MemoryNoteResponse(
            id=n.id,
            project_id=n.project_id,
            session_id=n.session_id,
            kind=n.kind,
            source=n.source,
            content=n.content,
            pinned=n.pinned,
            created_at=n.created_at,
        )
        for n in notes
    ]


@router.patch("/{id}/memory/{note_id}", response_model=MemoryNoteResponse)
def update_memory_note(
    id: int,
    note_id: int,
    payload: MemoryNoteUpdate,
    db: Session = Depends(get_db),
):
    project = get_project_or_404(db, id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    note = get_memory_note_or_none(db, project_id=project.id, note_id=note_id)
    if note is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Memory note not found")

    note = set_memory_pinned(db, note, payload.pinned)
    db.commit()
    db.refresh(note)
    return MemoryNoteResponse(
        id=note.id,
        project_id=note.project_id,
        session_id=note.session_id,
        kind=note.kind,
        source=note.source,
        content=note.content,
        pinned=note.pinned,
        created_at=note.created_at,
    )


@router.delete("/{id}/memory/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_memory_note_route(
    id: int,
    note_id: int,
    db: Session = Depends(get_db),
):
    project = get_project_or_404(db, id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    note = get_memory_note_or_none(db, project_id=project.id, note_id=note_id)
    if note is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Memory note not found")

    delete_memory_note(db, note)
    db.commit()
