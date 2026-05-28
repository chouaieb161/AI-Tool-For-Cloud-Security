from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


def _empty_list() -> list:
    return []


class ChatSessionCreate(BaseModel):
    project_id: int
    title: str | None = None


class ChatSessionResponse(BaseModel):
    id: int
    project_id: int
    title: str | None
    created_at: datetime


class ChatMessageCreate(BaseModel):
    content: str = Field(..., min_length=1)


class ChatMessageResponse(BaseModel):
    id: int
    session_id: int
    role: str
    content: str
    created_at: datetime
    citations: list[dict] = Field(default_factory=_empty_list)
    steps: list[str] = Field(default_factory=_empty_list)


class MemoryNoteResponse(BaseModel):
    id: int
    project_id: int
    session_id: int | None
    kind: str
    source: str | None
    content: str
    pinned: bool
    created_at: datetime


class MemoryNoteUpdate(BaseModel):
    pinned: bool
