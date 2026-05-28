# Backend (FastAPI + PostgreSQL)

Short developer guide for running and testing the backend API.

## 1) Setup

From repository root:

```bash
pip install -r requirements.txt
```

Recommended env vars:

```env
DATABASE_URL=postgresql+psycopg2://postgres:postgres@localhost:5432/gcp_security_agent
GCP_AGENT_RUNNER=mock
```

You can place these in `backend/.env` (recommended) or export them in your shell.

- `mock` = no LLM calls (fast local testing)
- `real` = calls the LangGraph GCP agent

## 2) Run API

From `backend/`:

```bash
uvicorn app.main:app --reload
```

- Swagger: `http://127.0.0.1:8000/docs`

### If you get `password authentication failed for user "postgres"`

Your local PostgreSQL password is different from the example URL.

1. Update `DATABASE_URL` with your real credentials in `backend/.env`, for example:

```env
DATABASE_URL=postgresql+psycopg2://postgres:YOUR_REAL_PASSWORD@localhost:5432/gcp_security_agent
```

2. Re-run the API.

PowerShell one-run override example:

```powershell
$env:DATABASE_URL="postgresql+psycopg2://postgres:YOUR_REAL_PASSWORD@localhost:5432/gcp_security_agent"
uvicorn app.main:app --reload
```

## 3) Seed Mock Data

From `backend/`:

```bash
python -m app.mock_agent_run --project-name "Demo GCP Project" --gcp-project-id "demo-gcp-001"
```

This creates/uses a project and inserts a mock scan + findings.

## 4) Main Endpoints

- `POST /projects`
- `GET /projects`
- `POST /projects/{id}/scan`
- `GET /projects/{id}/dashboard`
- `GET /scans/{scan_id}/findings`

### Real GCP-agent flow (persist to PostgreSQL)

1. Set in `backend/.env`:

```env
GCP_AGENT_RUNNER=real
GOOGLE_APPLICATION_CREDENTIALS=YOUR_PATH_TO_SERVICE_ACCOUNT_JSON
```

2. Create a project via API:

```bash
curl -X POST http://127.0.0.1:8000/projects \
	-H "Content-Type: application/json" \
	-d '{"name":"GCP Real Scan Project","gcp_project_id":"your-gcp-project-id"}'
```

3. Trigger scan:

```bash
curl -X POST http://127.0.0.1:8000/projects/{id}/scan
```

4. Read stored results:

```bash
curl http://127.0.0.1:8000/projects/{id}/dashboard
curl http://127.0.0.1:8000/scans/{scan_id}/findings
```

## 5) Notes

- Tables are auto-created at app startup via SQLAlchemy metadata.
- For production, add Alembic migrations and project CRUD endpoints.
