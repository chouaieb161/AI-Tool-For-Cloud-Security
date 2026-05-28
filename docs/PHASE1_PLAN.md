# Phase 1: Architecture + API Contracts + Wireframes

This document defines the modular architecture, initial API contracts, and UI wireframes for the security dashboard and GCP chat agent.

## 1) Architecture (Modular Layout)

### Backend modules

- app/api
  - routes for projects, scans, dashboard, chat
- app/services
  - agent_service: scan execution
  - dashboard_service: aggregation
  - chat_service: session + memory + agent orchestration
- app/agents
  - gcp: langgraph agent, tools, prompt templates
- app/rag
  - retriever, embeddings, vector store
- app/mcp
  - mcp server and tool registry
- app/db
  - models, database session
- app/schemas
  - Pydantic contracts for API

### Proposed folder additions

- backend/app/api/routes/chat.py
- backend/app/services/chat_service.py
- backend/app/schemas/chat.py
- backend/app/agents/gcp (move gcp-agent here, or alias it)

### Clear boundaries

- api: request validation + HTTP mapping only
- services: orchestration and business logic
- agents: LLM prompts, MCP tooling, reasoning pipeline
- rag: retrieval and embeddings
- db: persistence only

## 2) API Contracts (Draft)

### Dashboard

- GET /projects/{id}/dashboard
  - Response: DashboardResponse
- GET /scans/{scan_id}/findings
  - Response: list[FindingResponse]

### Projects

- POST /projects
  - Body: ProjectCreate
  - Response: ProjectResponse
- GET /projects
  - Response: list[ProjectResponse]

### Chat

- POST /chat/sessions
  - Body: ChatSessionCreate
  - Response: ChatSessionResponse
- POST /chat/sessions/{session_id}/messages
  - Body: ChatMessageCreate
  - Response: ChatMessageResponse (non-streaming)
- GET /chat/sessions/{session_id}/stream
  - Server-Sent Events (SSE) stream

### Pydantic schema sketches

```python
# backend/app/schemas/chat.py
from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel, Field

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
    role: str  # user|assistant|tool
    content: str
    created_at: datetime
    citations: list[dict] = []  # optional CIS references
    steps: list[str] = []  # step-by-step guidance
```

### SSE event envelope

Each event is JSON with a "type" and "payload":

```json
{ "type": "token", "payload": { "text": "..." } }
{ "type": "citation", "payload": { "cis_id": "1.1", "title": "..." } }
{ "type": "step", "payload": { "index": 1, "text": "..." } }
{ "type": "done", "payload": { "message_id": 123 } }
```

## 3) UI Wireframes (Text)

### Dashboard (desktop)

- Header: Project selector, date, action button (Run Scan)
- KPI row: Risk Score, Compliance %, Total Resources, Findings Count
- Charts row: Severity bar chart, Resource type breakdown
- Findings table: Filter by severity, CIS ID, resource type
- Finding detail drawer: CIS summary, remediation steps, references

### Chat (desktop)

- Left column: Sessions list (project scoped)
- Main panel: Chat transcript
- Right panel: CIS citations + Step-by-step guidance
- Input bar: Ask about GCP config, toggle "Use findings context"

### Mobile

- Tabs: Dashboard | Findings | Chat
- Chat uses a bottom sheet for citations/steps

## 4) Phase 1 Deliverables

- Architecture doc (this file)
- API schemas (backend/app/schemas/chat.py)
- API routes stub (chat endpoints)
- UI wireframes (text-based)
- Task breakdown for Phase 2

## 5) Phase 2 Task Breakdown (Preview)

- Add DB models for chat sessions + messages
- Add chat_service with session memory buffer
- Add agent chat handler with RAG + MCP tool usage
- Implement SSE streaming endpoint
- Add tests for chat endpoints
