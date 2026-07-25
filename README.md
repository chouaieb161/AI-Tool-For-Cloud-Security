# AI Tool for Cloud Security

Multi-cloud security audit platform with AI-powered CIS benchmark scanning. Uses LangGraph agents (Groq LLM + MCP tools + RAG) to assess GCP and OCI environments, persist findings to PostgreSQL, and present results in a real-time dashboard.

| Layer | Stack |
|-------|-------|
| **Backend** | Python 3.12, FastAPI, SQLAlchemy, LangGraph, LangChain, Groq |
| **Frontend** | React 19, TypeScript 6, Vite 8, Tailwind CSS 3, React Router 7 |
| **Database** | PostgreSQL 16 |
| **Vector Stores** | ChromaDB (GCP CIS RAG), Supabase pgvector (OCI CIS RAG) |
| **Cloud SDKs** | google-cloud-*, OCI Python SDK |
| **Tracing** | Langfuse (optional) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Frontend (React + Vite)                                    │
│  ┌───────────┐ ┌──────────┐ ┌───────────┐                  │
│  │ Dashboard  │ │   Chat   │ │   Setup   │                  │
│  └─────┬─────┘ └────┬─────┘ └─────┬─────┘                  │
│        └────────────┼──────────────┘                        │
│                     │ HTTP /api/*                            │
├─────────────────────┼───────────────────────────────────────┤
│  Backend (FastAPI)  │                                        │
│  ┌──────────────────┴────────────────────┐                   │
│  │         API Router                     │                  │
│  │  /projects /scans /chat /admin /oci    │                  │
│  └──────────────────┬────────────────────┘                   │
│                     │                                        │
│  ┌──────────────────┴────────────────────┐                   │
│  │       Agent Services                   │                  │
│  │  ┌──────────────┐  ┌────────────────┐  │                  │
│  │  │  GCP Agent   │  │   OCI Agent    │  │                  │
│  │  │ (LangGraph)  │  │  (LangGraph)   │  │                  │
│  │  ├──────────────┤  ├────────────────┤  │                  │
│  │  │ MCP Tools    │  │ MCP Tools      │  │                  │
│  │  │ ChromaDB RAG │  │ Supabase RAG   │  │                  │
│  │  └──────────────┘  └────────────────┘  │                  │
│  └──────────────────┬────────────────────┘                   │
│                     │                                        │
│  ┌──────────────────┴────────────────────┐                   │
│  │         PostgreSQL + SQLAlchemy       │                   │
│  │  organisations / tenant_providers     │                   │
│  │  projects / resources / scans /       │                   │
│  │  findings / scan_resources            │                   │
│  └───────────────────────────────────────┘                   │
│                                                               │
│  ┌───────────────────────────────────────┐                   │
│  │  Scheduler Service                     │                   │
│  │  (autonomous periodic scans)           │                   │
│  └───────────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

### Multi-Agent Design

- **GCP Agent** (`backend/app/gcp-agent/agent.py`) — LangGraph workflow using Groq (`llama-3.3-70b-versatile`), MCP tools for GCP Resource Manager / Asset Inventory / Compute / IAM / Storage, and ChromaDB-backed CIS benchmark RAG.
- **OCI Agent** (`backend/app/oci_agent/agent.py`) — LangGraph mirror for OCI using the same agent pattern, OCI SDK MCP tools, and Supabase pgvector for CIS RAG.
- **Both agents** support inline credentials passed from the scheduler/API (no env-var dependency at scan time).

### Multi-Tenancy

```
Organisation ──has many──► TenantProvider ──has many──► Project ──has many──► Scan ──has many──► Finding
```

- `tenant_providers` table stores cloud account metadata + encrypted credentials in `config` (JSON column).
- External scheduler API (`/external/*`) enables cron-job-triggered scans per provider.
- Admin CRUD endpoints (`/admin/*`) manage organisations, providers, and credentials.

---

## Database Schema

| Table | Key Fields | Purpose |
|-------|-----------|---------|
| `organizations` | id, name, slug | Multi-tenant root |
| `tenant_providers` | id, org_id, provider_type, provider_label, enabled, config (JSON) | Cloud account + credentials |
| `projects` | id, name, gcp_project_id, cloud_provider, org_id, tenant_provider_id | Logical scan target |
| `resources` | id, project_id, type, name, gcp_uri | Cloud resources found during scans |
| `scans` | id, project_id, tenant_provider_id, trigger_type, timestamp, score, status (Enum) | Scan runs |
| `scan_resources` | id, scan_id, resource_id | Many-to-many: scan ↔ resource |
| `findings` | id, scan_id, resource_id, cis_rule_id, severity (Enum), description, remediation_steps | CIS findings |
| `chat_sessions` / `chat_messages` / `memory_notes` | — | AI chat + persistent memory |

See `backend/app/db/models.py` for full column definitions.

---

## API Endpoints

### Projects
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/projects` | Create project |
| `GET` | `/projects` | List all projects |
| `POST` | `/projects/{id}/scan` | Trigger GCP scan |
| `GET` | `/projects/{id}/dashboard` | Dashboard KPIs |
| `GET` | `/projects/{id}/memory` | List memory notes |
| `PATCH` | `/projects/{id}/memory/{note_id}` | Pin/unpin note |
| `DELETE` | `/projects/{id}/memory/{note_id}` | Delete note |

### Scans
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scans/scan` | Freeform scan |
| `GET` | `/scans/{scan_id}` | Scan status |
| `GET` | `/scans/{scan_id}/findings` | Scan findings |
| `GET` | `/scans/history/{project_id}` | Score trend |
| `GET` | `/scans/matrix/{project_id}` | Category × severity matrix |
| `GET` | `/scans/remediation-plan/{project_id}` | Prioritized remediation |
| `GET` | `/scans/diff/{project_id}` | Compare two scans |

### Chat
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/chat/sessions` | List sessions |
| `POST` | `/chat/sessions` | Create session |
| `DELETE` | `/chat/sessions/{id}` | Delete session |
| `POST` | `/chat/sessions/{id}/messages` | Send message |
| `GET` | `/chat/sessions/{id}/messages` | List messages |
| `PATCH` | `/chat/sessions/{id}/messages/{mid}` | Edit message |
| `DELETE` | `/chat/sessions/{id}/messages/{mid}` | Delete message |
| `POST` | `/chat/sessions/{id}/stream` | SSE streaming response |

### OCI
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/oci/scans/trigger` | Trigger OCI scan |
| `POST` | `/oci/scans/freeform` | Freeform OCI scan |
| `GET` | `/oci/scans/{scan_id}/findings` | OCI findings |
| `GET` | `/oci/dashboard` | OCI dashboard |

### Admin (Multi-Tenant)
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/admin/organisations` | Create org |
| `GET` | `/admin/organisations` | List orgs |
| `POST` | `/admin/tenant-providers` | Register provider |
| `GET` | `/admin/tenant-providers` | List providers |
| `PUT` | `/admin/tenant-providers/{id}/credentials` | Store credentials |
| `POST` | `/admin/scheduler/run` | Trigger scheduled scan |

### External (Scheduler Integration)
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/external/providers` | List providers for cron |
| `POST` | `/external/trigger-scan` | Trigger scan from cron |

### Credentials
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/credentials/status` | Check credential status |
| `POST` | `/credentials/upload` | Upload SA JSON / OCI config |

---

## Frontend Features

- **Dashboard** (`/`) — Score trend sparkline, findings matrix heatmap, KPI cards (risk score, compliance %, resources, high/critical counts), findings table with search/filter/pagination, remediation plan, scan diffing.
- **AI Chat** (`/chat`) — Multi-session chat with AI security assistant, SSE streaming with token-by-token rendering, step-by-step reasoning display, CIS citation badges, memory notes sidebar with pinning.
- **Setup** (`/setup`) — Register cloud providers (GCP or OCI), upload service account JSON (GCP) or config + private key (OCI), trigger scans via scheduler.
- **Multi-Provider** — Sidebar dropdown selects which `TenantProvider` to view; Dashboard and Chat react to the selection.

---

## Project Structure

```
AI-tool-for-cloud-security/
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI app factory
│   │   ├── cli.py                      # Scheduler CLI entry
│   │   ├── api/
│   │   │   ├── router.py               # API router assembly
│   │   │   └── routes/
│   │   │       ├── projects.py         # Project + GCP dashboard
│   │   │       ├── scans.py            # Scan + enhanced dashboard
│   │   │       ├── chat.py             # Chat sessions + streaming
│   │   │       ├── credentials.py      # Credential upload
│   │   │       ├── oci_scans.py        # OCI scan + dashboard
│   │   │       ├── admin.py            # Multi-tenant CRUD + scheduler
│   │   │       └── external.py         # External scheduler API
│   │   ├── schemas/                    # Pydantic models
│   │   │   ├── scan_result.py          # GCP scan schemas
│   │   │   ├── oci_scan_result.py      # OCI scan schemas
│   │   │   ├── chat.py                 # Chat schemas
│   │   │   ├── credentials.py          # Credential schemas
│   │   │   └── external.py             # Multi-tenant schemas
│   │   ├── db/
│   │   │   ├── database.py             # SQLAlchemy engine + session
│   │   │   └── models.py               # All ORM models
│   │   ├── services/
│   │   │   ├── agent_service.py        # GCP agent runner
│   │   │   ├── dashboard_service.py    # Dashboard aggregation
│   │   │   ├── chat_service.py         # Chat response generation
│   │   │   ├── oci_agent_service.py    # OCI agent runner
│   │   │   ├── scheduler_service.py    # Autonomous scan scheduler
│   │   │   └── tenant_service.py       # Multi-tenant CRUD
│   │   ├── gcp-agent/
│   │   │   └── agent.py                # GCP LangGraph agent
│   │   ├── oci_agent/
│   │   │   ├── agent.py                # OCI LangGraph agent
│   │   │   ├── mcp/oci_mcp_server.py   # OCI MCP tools
│   │   │   └── rag/                    # OCI CIS vector store
│   │   ├── mcp/
│   │   │   └── mcp_server.py           # GCP MCP tools
│   │   └── rag/
│   │       ├── embeddings.py           # Embedding models
│   │       ├── ingestion.py            # CIS PDF ingestion
│   │       ├── retriever.py            # Hybrid search retriever
│   │       └── vector_store.py         # ChromaDB wrapper
│   └── tests/                          # Test suite
├── frontend/
│   ├── src/
│   │   ├── main.tsx                    # React entry point
│   │   ├── App.tsx                     # Shell + routing
│   │   ├── api.ts                      # Axios client + types
│   │   ├── hooks/
│   │   │   ├── useDashboard.ts         # Dashboard state
│   │   │   ├── useChat.ts              # Chat + streaming
│   │   │   ├── useMemory.ts            # Memory notes
│   │   │   └── useCredentials.ts       # Credential upload
│   │   └── pages/
│   │       ├── DashboardPage.tsx        # Full dashboard UI
│   │       ├── ChatPage.tsx            # AI chat UI
│   │       └── SetupPage.tsx           # Provider management
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   └── package.json
├── requirements.txt
└── .env.example
```

---

## Quick Start

### Prerequisites
- Python 3.12+, Node 20+
- PostgreSQL 16 running locally
- (Real agent mode) Groq API key + cloud credentials

### Backend Setup

```powershell
# Activate venv
.\.venv\Scripts\Activate.ps1

# Install deps
pip install -r requirements.txt

# Configure (copy and edit)
cp .env.example .env
```

**Minimal `.env`:**
```env
DATABASE_URL=postgresql+psycopg2://postgres:your_password@localhost:5432/cloud-security
GCP_AGENT_RUNNER=mock
```

**Real agent mode:**
```env
GCP_AGENT_RUNNER=real
GOOGLE_APPLICATION_CREDENTIALS=./fldr-network-prj-ba77-a45d5a5801b1.json
GROQ_API_KEY=gsk_...
GROQ_MODEL=llama-3.3-70b-versatile
```

### Run Backend

```powershell
cd backend
uvicorn app.main:app --reload
```

Swagger UI: `http://localhost:8000/docs`

### Seed Mock Data

```powershell
cd backend
python -m app.mock_agent_run --project-name "Demo GCP Project" --gcp-project-id "demo-gcp-001"
```

### Frontend Setup

```powershell
cd frontend
npm install
npm run dev
```

Frontend: `http://localhost:5173`

---

## Workflows

### 1. Manual GCP Scan (via API)

```bash
# Create project
curl -X POST http://localhost:8000/projects \
  -H "Content-Type: application/json" \
  -d '{"name":"GCP Real Scan","gcp_project_id":"fldr-network-prj-ba77"}'

# Trigger scan
curl -X POST http://localhost:8000/projects/1/scan

# View results
curl http://localhost:8000/projects/1/dashboard
curl http://localhost:8000/scans/{scan_id}/findings
```

### 2. Multi-Tenant Credential Setup (via Frontend)

1. Open `http://localhost:5173/setup`
2. Select **GCP** or **OCI**
3. Enter a label (e.g. "Production GCP")
4. Upload service account JSON (GCP) or paste config + private key (OCI)
5. Click **Save** → provider is created with credentials stored in DB
6. Click **Scan** → triggers scheduler for that provider

### 3. Scheduler (Autonomous Scans)

```powershell
# One-shot scan for specific provider
curl -X POST "http://localhost:8000/admin/scheduler/run?provider_id=1"

# CLI (for Windows Task Scheduler)
cd backend
python -m app.cli scheduler
```

The scheduler:
1. Reads `tenant_providers` with stored credentials
2. Creates/finds a `Project` linked to the provider
3. Passes inline credentials to the LangGraph agent
4. Runs CIS audit + persists results
5. Repeats for all enabled providers

### 4. Real GCP Agent

When `GCP_AGENT_RUNNER=real`:
1. Agent uses `google-cloud-*` SDK clients via MCP tools
2. Discovers projects under the organisation scope
3. Enumerates resources (IAM, Compute, Storage, etc.)
4. Retrieves matching CIS rules from ChromaDB vector store
5. LLM analyzes findings and generates remediation

### 5. Real OCI Agent

OCI agent mirrors the GCP pattern but:
- Uses OCI SDK via `oci_mcp_server.py`
- CIS RAG backed by Supabase pgvector
- Reads tenancy/compartment config from stored credentials

---

## Dashboard API Response

```json
{
  "total_resources_count": 434,
  "resource_count_basis": "latest_scan_observed",
  "risk_score": 70,
  "findings_by_severity": {
    "CRITICAL": 0,
    "HIGH": 88,
    "MEDIUM": 256,
    "LOW": 0
  },
  "compliance_percentage": 70.0,
  "latest_scan_id": 225,
  "latest_completed_scan_id": 212
}
```

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **LangGraph agents** | State-machine workflow with tool calling, step-by-step reasoning, and human-in-the-loop support |
| **MCP (Model Context Protocol)** | Standardized tool interface; agents call cloud SDKs through MCP servers |
| **Groq inference** | Fast LLM inference (Llama 3.3 70B) at 1200+ tok/s; free tier limited to 12k TPM |
| **ChromaDB + Supabase** | ChromaDB for GCP CIS RAG (local), Supabase pgvector for OCI (cloud-managed) |
| **Vite + Tailwind** | Fast HMR, zero-config TypeScript, utility-first CSS |
| **SSE streaming** | Token-by-token AI response rendering in chat UI |

---

## Branches

| Branch | Purpose |
|--------|---------|
| `main` | Stable baseline |
| `feat/store-creds-backend` | Credential storage + scheduler + OCI agent MCP override |
| `feat/creds-frontend` | Frontend provider management + selector |

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `GCP_AGENT_RUNNER` | No | `mock` | `mock` or `real` |
| `GOOGLE_APPLICATION_CREDENTIALS` | GCP real | — | Path to SA JSON |
| `GROQ_API_KEY` | Real agents | — | Groq API key |
| `GROQ_MODEL` | No | `llama-3.3-70b-versatile` | Groq model name |
| `CHROMA_CIS_PATH` | No | `../.chroma_cis` | ChromaDB persist dir |
| `CIS_EMBED_DEVICE` | No | `cpu` | Embedding model device |
| `CIS_ENABLE_RERANK` | No | `1` | Enable cross-encoder reranking |
| `LANGFUSE_HOST` | No | — | Langfuse tracing host |
| `LANGFUSE_PUBLIC_KEY` | Tracing | — | Langfuse public key |
| `LANGFUSE_SECRET_KEY` | Tracing | — | Langfuse secret key |
| `HF_TOKEN` | OCI RAG | — | HuggingFace token |
| `OCI_SUPABASE_URL` | OCI RAG | — | Supabase project URL |
| `OCI_SUPABASE_KEY` | OCI RAG | — | Supabase anon key |
| `OCI_TENANCY_OCID` | OCI agent | — | OCI tenancy OCID |
| `OCI_CONFIG_FILE` | OCI file auth | — | Path to OCI config |

---

## Development

### Running Tests

```powershell
cd backend
python -m pytest tests/ -v
```

### Frontend Build

```powershell
cd frontend
npm run build
```

### Adding a New Agent (Azure/AWS)

1. Create `backend/app/<cloud>_agent/` with `agent.py` and `mcp/`
2. Add `<cloud>_agent_service.py` in `services/`
3. Add routes in `api/routes/`
4. Register in `api/router.py`
5. Add schemas in `schemas/`
6. Extend `scheduler_service.py` to support the new provider type
7. Frontend: add provider type to `CloudProvider` union in `api.ts`

---

## Security Notes

- Service account keys and OCI private keys stored in `tenant_providers.config` JSON column — encrypt at rest in production
- Groq API key and other secrets in `.env` — never commit
- Routes are unauthenticated — add auth middleware before exposing publicly
- GCP audit scope (`GCP_AUDIT_SCOPE`) restricts resource discovery to a specific organisation folder
