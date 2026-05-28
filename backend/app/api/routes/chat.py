from __future__ import annotations

import json
from typing import Generator

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.schemas.chat import (
    ChatMessageCreate,
    ChatMessageResponse,
    ChatSessionCreate,
    ChatSessionResponse,
)
from app.services.chat_service import (
    create_chat_message,
    create_chat_session,
    generate_chat_response,
    get_chat_session_or_none,
    list_chat_messages,
    message_payload,
)
from app.services.dashboard_service import get_project_or_404


router = APIRouter(prefix="/chat", tags=["chat"])


@router.get("/sessions", response_model=list[ChatSessionResponse])
@router.get("/sessions", response_model=list[ChatSessionResponse])
def list_sessions(project_id: int, db: Session = Depends(get_db)):
    project = get_project_or_404(db, project_id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
        
    from app.services.chat_service import list_chat_sessions
    sessions = list_chat_sessions(db, project.id)
    return [
        ChatSessionResponse(
            id=s.id,
            project_id=s.project_id,
            title=s.title,
            created_at=s.created_at,
        )
        for s in sessions
    ]

@router.post("/sessions", response_model=ChatSessionResponse, status_code=status.HTTP_201_CREATED)
def create_session(payload: ChatSessionCreate, db: Session = Depends(get_db)):
    project = get_project_or_404(db, payload.project_id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    session = create_chat_session(db, project, payload.title)
    db.commit()
    db.refresh(session)
    return ChatSessionResponse(
        id=session.id,
        project_id=session.project_id,
        title=session.title,
        created_at=session.created_at,
    )


@router.post(
    "/sessions/{session_id}/messages",
    response_model=ChatMessageResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_message(session_id: int, payload: ChatMessageCreate, db: Session = Depends(get_db)):
    session = get_chat_session_or_none(db, session_id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Chat session not found")

    create_chat_message(db, session, role="user", content=payload.content)
    response_text, citations, steps = generate_chat_response(db, session, payload.content)
    assistant_message = create_chat_message(
        db,
        session,
        role="assistant",
        content=response_text,
        citations=citations,
        steps=steps,
    )
    db.commit()
    db.refresh(assistant_message)
    return ChatMessageResponse(**message_payload(assistant_message))


@router.get("/sessions/{session_id}/messages", response_model=list[ChatMessageResponse])
def list_messages(session_id: int, db: Session = Depends(get_db)):
    session = get_chat_session_or_none(db, session_id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Chat session not found")

    messages = list_chat_messages(db, session_id)
    return [ChatMessageResponse(**message_payload(m)) for m in messages]


@router.post("/sessions/{session_id}/stream")
def stream_message(session_id: int, payload: ChatMessageCreate, db: Session = Depends(get_db)):
    session = get_chat_session_or_none(db, session_id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Chat session not found")

    def _event_stream() -> Generator[str, None, None]:
        create_chat_message(db, session, role="user", content=payload.content)
        db.commit()
        try:
            response_text, citations, steps = generate_chat_response(db, session, payload.content)
        except Exception as exc:  # pragma: no cover - passthrough to stream
            import traceback
            traceback.print_exc()
            yield f"data: {json.dumps({'type': 'error', 'payload': {'message': str(exc)}})}\n\n"
            return

        chunk_size = 160
        for i in range(0, len(response_text), chunk_size):
            chunk = response_text[i : i + chunk_size]
            yield f"data: {json.dumps({'type': 'token', 'payload': {'text': chunk}})}\n\n"

        for citation in citations:
            yield f"data: {json.dumps({'type': 'citation', 'payload': citation})}\n\n"

        for idx, step in enumerate(steps, start=1):
            yield f"data: {json.dumps({'type': 'step', 'payload': {'index': idx, 'text': step}})}\n\n"

        assistant_message = create_chat_message(
            db,
            session,
            role="assistant",
            content=response_text,
            citations=citations,
            steps=steps,
        )
        db.commit()
        db.refresh(assistant_message)
        yield f"data: {json.dumps({'type': 'done', 'payload': {'message_id': assistant_message.id}})}\n\n"

    return StreamingResponse(_event_stream(), media_type="text/event-stream")
