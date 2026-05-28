from __future__ import annotations

from pydantic import BaseModel


class CredentialStatusResponse(BaseModel):
    configured: bool
    project_id: str | None = None
    credentials_path: str | None = None
