from __future__ import annotations

import json
import re
from typing import Any

import importlib.util
import sys
from pathlib import Path

from sqlalchemy import desc, or_, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import ChatMessage, ChatSession, MemoryNote, Project


def _dump_json(value: Any) -> str | None:
    if value is None:
        return None
    return json.dumps(value)


def _load_json(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def get_chat_session_or_none(db: Session, session_id: int) -> ChatSession | None:
    return db.execute(
        select(ChatSession).where(ChatSession.id == session_id)
    ).scalar_one_or_none()


def create_chat_session(db: Session, project: Project, title: str | None) -> ChatSession:
    session = ChatSession(project_id=project.id, title=title)
    db.add(session)
    db.flush()
    return session


def create_chat_message(
    db: Session,
    session: ChatSession,
    *,
    role: str,
    content: str,
    citations: list[dict] | None = None,
    steps: list[str] | None = None,
) -> ChatMessage:
    message = ChatMessage(
        session_id=session.id,
        role=role,
        content=content,
        citations_json=_dump_json(citations),
        steps_json=_dump_json(steps),
    )
    db.add(message)
    db.flush()
    return message


def list_chat_messages(db: Session, session_id: int) -> list[ChatMessage]:
    return (
        db.execute(
            select(ChatMessage)
            .where(ChatMessage.session_id == session_id)
            .order_by(ChatMessage.created_at.asc(), ChatMessage.id.asc())
        )
        .scalars()
        .all()
    )


def list_chat_sessions(db: Session, project_id: int) -> list[ChatSession]:
    return (
        db.execute(
            select(ChatSession)
            .where(ChatSession.project_id == project_id)
            .order_by(ChatSession.created_at.desc(), ChatSession.id.desc())
        )
        .scalars()
        .all()
    )


def message_payload(message: ChatMessage) -> dict[str, Any]:
    return {
        "id": message.id,
        "session_id": message.session_id,
        "role": message.role,
        "content": message.content,
        "created_at": message.created_at,
        "citations": _load_json(message.citations_json, []),
        "steps": _load_json(message.steps_json, []),
    }


def _load_gcp_agent_module() -> Any:
    module_path = Path(__file__).resolve().parents[1] / "gcp-agent" / "agent.py"
    if not module_path.exists():
        raise RuntimeError(f"GCP agent not found at {module_path}")

    app_dir = Path(__file__).resolve().parents[1]
    import_paths = [
        app_dir / "gcp-agent",
        app_dir / "mcp",
        app_dir / "rag",
    ]
    for p in import_paths:
        p_str = str(p)
        if p_str not in sys.path:
            sys.path.insert(0, p_str)

    spec = importlib.util.spec_from_file_location("gcp_langgraph_agent", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load GCP agent module")

    module = importlib.util.module_from_spec(spec)
    sys.modules["gcp_langgraph_agent"] = module
    spec.loader.exec_module(module)
    return module


def _compact_history(messages: list[ChatMessage], limit: int = 6) -> str:
    parts: list[str] = []
    for msg in messages[-limit:]:
        role = "User" if msg.role == "user" else "Assistant"
        parts.append(f"{role}: {msg.content}")
    return "\n".join(parts)


def _extract_citations(text: str) -> list[dict[str, Any]]:
    cis_ids = []
    for match in re.findall(r"\b([1-8]\.\d+(?:\.\d+)?)\b", text):
        if match not in cis_ids:
            cis_ids.append(match)
    return [{"cis_id": cid} for cid in cis_ids]


def _extract_steps(text: str) -> list[str]:
    steps: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"^\d+\.\s+", stripped):
            steps.append(re.sub(r"^\d+\.\s+", "", stripped))
    return steps


_STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "that",
    "this",
    "from",
    "into",
    "your",
    "about",
    "what",
    "when",
    "where",
    "how",
    "why",
    "should",
    "could",
    "would",
    "like",
    "have",
    "has",
    "had",
    "you",
    "are",
    "was",
    "were",
}


def _extract_keywords(text: str, limit: int = 6) -> list[str]:
    tokens = re.findall(r"[a-z0-9]{3,}", text.lower())
    keywords: list[str] = []
    seen = set()
    for token in tokens:
        if token in _STOPWORDS or token in seen:
            continue
        seen.add(token)
        keywords.append(token)
        if len(keywords) >= limit:
            break
    return keywords


def _format_memory_notes(notes: list[MemoryNote]) -> str:
    if not notes:
        return ""
    preferences = [n for n in notes if n.kind == "preference"]
    long_term = [n for n in notes if n.kind != "preference"]
    lines = []
    if preferences:
        lines.append("User preferences:")
        for note in preferences:
            lines.append(f"- {note.content}")
    if long_term:
        lines.append("Long-term memory (recent, relevant):")
        for note in long_term:
            lines.append(f"- {note.content}")
    return "\n".join(lines)


def _select_memory_notes(
    db: Session,
    *,
    project_id: int,
    query: str,
    limit: int = 4,
) -> list[MemoryNote]:
    keywords = _extract_keywords(query)
    stmt = select(MemoryNote).where(MemoryNote.project_id == project_id)
    if keywords:
        clauses = [MemoryNote.content.ilike(f"%{kw}%") for kw in keywords]
        stmt = stmt.where(or_(*clauses))
    stmt = stmt.order_by(MemoryNote.created_at.desc()).limit(limit)
    return db.execute(stmt).scalars().all()


def _select_preference_notes(
    db: Session,
    *,
    project_id: int,
    limit: int = 3,
) -> list[MemoryNote]:
    stmt = (
        select(MemoryNote)
        .where(MemoryNote.project_id == project_id, MemoryNote.kind == "preference")
        .order_by(MemoryNote.created_at.desc())
        .limit(limit)
    )
    return db.execute(stmt).scalars().all()


def _extract_preference_note(text: str) -> str | None:
    lower = text.lower()
    if "remember" not in lower and "prefer" not in lower:
        return None
    match = re.search(r"(?:remember|prefer|preference)\s+(.+)$", text, re.I)
    if not match:
        return None
    note = match.group(1).strip().rstrip(".")
    if not note:
        return None
    return note[:240]


def _summarize_for_memory(response_text: str) -> str:
    summary_match = re.search(r"## Summary\n(.+?)(?:\n## |\Z)", response_text, re.S)
    if summary_match:
        summary = summary_match.group(1).strip()
        if summary:
            return summary[:600]
    return response_text.strip()[:400]


def create_memory_note(
    db: Session,
    *,
    project_id: int,
    session_id: int | None,
    kind: str,
    content: str,
    source: str | None = None,
) -> MemoryNote:
    note = MemoryNote(
        project_id=project_id,
        session_id=session_id,
        kind=kind,
        content=content,
        source=source,
    )
    db.add(note)
    db.flush()
    return note


def list_memory_notes(
    db: Session,
    *,
    project_id: int,
    kind: str | None = None,
    limit: int = 50,
) -> list[MemoryNote]:
    stmt = select(MemoryNote).where(MemoryNote.project_id == project_id)
    if kind:
        stmt = stmt.where(MemoryNote.kind == kind)
    stmt = stmt.order_by(desc(MemoryNote.pinned), MemoryNote.created_at.desc()).limit(limit)
    return db.execute(stmt).scalars().all()


def get_memory_note_or_none(
    db: Session,
    *,
    project_id: int,
    note_id: int,
) -> MemoryNote | None:
    return db.execute(
        select(MemoryNote).where(
            MemoryNote.project_id == project_id,
            MemoryNote.id == note_id,
        )
    ).scalar_one_or_none()


def set_memory_pinned(db: Session, note: MemoryNote, pinned: bool) -> MemoryNote:
    note.pinned = pinned
    db.add(note)
    db.flush()
    return note


def delete_memory_note(db: Session, note: MemoryNote) -> None:
    db.delete(note)


def generate_chat_response(
    db: Session,
    session: ChatSession,
    user_content: str,
) -> tuple[str, list[dict[str, Any]], list[str]]:
    if settings.GCP_AGENT_RUNNER == "mock":
        response = (
            "Based on CIS guidance, review IAM and storage controls for this project. "
            "Here is a safe checklist to start.\n"
            "1. Review IAM policy bindings for public members.\n"
            "2. Ensure Cloud Storage buckets are not publicly accessible.\n"
            "3. Verify audit logs are enabled for all services."
        )
        return response, [{"cis_id": "1.1"}, {"cis_id": "5.1"}], _extract_steps(response)

    messages = list_chat_messages(db, session.id)
    project = db.execute(
        select(Project).where(Project.id == session.project_id)
    ).scalar_one_or_none()
    project_hint = project.gcp_project_id if project else str(session.project_id)
    history = _compact_history(messages)
    preference_note = None
    if project is not None:
        preference_note = _extract_preference_note(user_content)
        if preference_note:
            create_memory_note(
                db,
                project_id=project.id,
                session_id=session.id,
                kind="preference",
                content=preference_note,
                source="user",
            )
    memories = []
    if project is not None:
        raw_memories = _select_preference_notes(db, project_id=project.id)
        raw_memories += _select_memory_notes(db, project_id=project.id, query=user_content)
        seen_ids = set()
        for note in raw_memories:
            if note.id in seen_ids:
                continue
            seen_ids.add(note.id)
            memories.append(note)
    memory_block = _format_memory_notes(memories)
    memory_section = f"\n\n{memory_block}\n" if memory_block else ""
    prompt = (
        "You are a GCP security assistant. Always use MCP tool data for audit questions, "
        "and retrieve CIS Benchmark guidance for recommendations. "
        "Answer in a ChatGPT-like tone with clear, step-by-step remediation guidance and cite CIS control IDs.\n\n"
        f"Project ID: {project_hint}\n\n"
        f"{memory_section}"
        f"Conversation:\n{history}\n\n"
        f"User question: {user_content}\n"
    )

    module = _load_gcp_agent_module()
    run_audit = getattr(module, "run_audit", None)
    if not callable(run_audit):
        raise RuntimeError("GCP agent missing run_audit()")

    def memory_sink(payload: dict[str, Any]) -> None:
        if project is None:
            return
        report = payload.get("report_markdown") or ""
        summary = _summarize_for_memory(report)
        if summary:
            create_memory_note(
                db,
                project_id=project.id,
                session_id=session.id,
                kind="long_term",
                content=summary,
                source="assistant_summary",
            )

    response = run_audit(prompt, memory_sink=memory_sink)
    citations = _extract_citations(response)
    steps = _extract_steps(response)
    return response, citations, steps
