from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


_BACKEND_DIR = Path(__file__).resolve().parents[2]
_REPO_ROOT = Path(__file__).resolve().parents[3]

# Load backend-local .env first, then repo-root .env as fallback.
load_dotenv(_BACKEND_DIR / ".env")
load_dotenv(_REPO_ROOT / ".env")


class Settings:
    APP_NAME: str = os.environ.get("APP_NAME", "GCP Security Agent API")
    DATABASE_URL: str = os.environ.get(
        "DATABASE_URL",
        "postgresql+psycopg2://postgres:postgres@localhost:5432/gcp_security_agent",
    )
    GCP_AGENT_RUNNER: str = os.environ.get("GCP_AGENT_RUNNER", "mock").lower()


settings = Settings()
