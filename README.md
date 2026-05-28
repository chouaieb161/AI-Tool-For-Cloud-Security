# AI Tool for Cloud Security (GCP First)

Backend-first multi-cloud security platform using a multi-agent design:
- **High-level orchestrator agent** (planned) routes requests to the right cloud agent.
- **Cloud-specific agents** (GCP implemented first) run CIS-style audits.
- **FastAPI + PostgreSQL persistence layer** stores scans, resources, and findings for dashboard consumption.

---

## Current Status

✅ GCP agent logic available (LangGraph + MCP + RAG)  
✅ Persistence/API layer implemented with FastAPI and SQLAlchemy  
✅ Mock scan runner available for dashboard/API testing without LLM calls  
🚧 Orchestrator agent and frontend dashboard are next phases

---

## Project Structure

```text
AI-tool-for-cloud-security/
├── backend/
│   └── app/
│       ├── api/
│       │   ├── routes/
│       │   │   ├── projects.py
│       │   │   └── scans.py
│       │   └── router.py
│       ├── core/
│       │   └── config.py
│       ├── db/
│       │   ├── database.py
│       │   └── models.py
│       ├── schemas/
│       │   └── scan_result.py
│       ├── services/
│       │   ├── agent_service.py
│       │   └── dashboard_service.py
│       ├── gcp-agent/
│       │   └── agent.py
│       ├── mcp-tools/
│       │   └── mcp_server.py
│       ├── rag/
│       │   ├── embeddings.py
│       │   ├── ingestion.py
│       │   ├── retriever.py
│       │   └── vector_store.py
│       ├── main.py
│       └── mock_agent_run.py
├── requirements.txt
└── ...
```

---

## Backend Architecture (Implemented)

### 1) Database Models
Defined in `backend/app/db/models.py`:
- **Project**: `id`, `name`, `gcp_project_id`, `created_at`
- **Resource**: `id`, `project_id`, `type`, `name`, `gcp_uri`
- **Scan**: `id`, `project_id`, `timestamp`, `score`, `status` (`COMPLETED`/`FAILED`)
- **Finding**: `id`, `scan_id`, `resource_id`, `cis_rule_id`, `severity`, `description`, `remediation_steps`

### 2) Agent Bridge Service
Implemented in `backend/app/services/agent_service.py`:
- Defines `GCPScanResult` contract (via schemas)
- Runs the GCP LangGraph agent (or mock mode)
- Parses scan output
- Persists scan/resources/findings in a single transaction

### 3) API Layer
Implemented endpoints:
- `POST /projects/{id}/scan` → trigger scan, return `scan_id`
- `GET /projects/{id}/dashboard` → aggregate metrics for dashboard
- `GET /scans/{scan_id}/findings` → detailed findings for table view

---

## Prerequisites

- Python 3.12+
- PostgreSQL running locally or remotely
- (Optional for real agent mode) GCP credentials + Groq/OpenAI keys

---

## Environment Variables

Create `.env` (or use system env vars) with at least:

```env
DATABASE_URL=postgresql+psycopg2://postgres:postgres@localhost:5432/gcp_security_agent
GCP_AGENT_RUNNER=mock
```

Optional for real GCP LangGraph runs:

```env
GCP_AGENT_RUNNER=real
GOOGLE_APPLICATION_CREDENTIALS=./your-service-account.json
GCP_PROJECT_ID=your-project-id
GROQ_API_KEY=your_groq_key
```

---

## Installation

From repository root:

```bash
pip install -r requirements.txt
```

If using the existing virtual environment on Windows:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

---

## Run the API

From `backend/`:

```bash
uvicorn app.main:app --reload
```

Open docs:
- Swagger UI: `http://127.0.0.1:8000/docs`

---

## Mock Testing Workflow (No LLM Calls)

### 1) Seed a project + mock scan
From `backend/`:

```bash
python -m app.mock_agent_run --project-name "Demo GCP Project" --gcp-project-id "demo-gcp-001"
```

### 2) Test endpoints
- `GET /projects/{id}/dashboard`
- `GET /scans/{scan_id}/findings`

### 3) Trigger new scan from API
- `POST /projects/{id}/scan`

When `GCP_AGENT_RUNNER=mock`, scan execution uses synthetic output and is fast/repeatable.

---

## Notes for Real Agent Mode

- `GCP_AGENT_RUNNER=real` makes `agent_service` call `backend/app/gcp-agent/agent.py`.
- Ensure all required keys/credentials are set before using real mode.
- The agent is expected to return strict JSON matching `GCPScanResult`.

---

## Next Recommended Steps

1. Add **Project CRUD endpoints** (`POST/GET/PUT/DELETE /projects`)  
2. Add **Alembic migrations** for production-safe schema evolution  
3. Add **orchestrator agent service** to route by provider (`gcp`, `azure`, `aws`)  
4. Add authentication/authorization before exposing dashboard APIs publicly

---

## Security Reminder

A service-account key JSON appears to exist in the repository. For safety:
- rotate/revoke exposed keys immediately
- remove key files from git history
- keep credentials in secure secret management
- enforce `.gitignore` rules for all key files
