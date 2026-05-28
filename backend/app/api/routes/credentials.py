from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.schemas.credentials import CredentialStatusResponse


router = APIRouter(prefix="/credentials", tags=["credentials"])


def _get_credentials_path() -> str | None:
    return os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")


def _get_project_id() -> str | None:
    return os.environ.get("GCP_PROJECT_ID")


def _load_project_id_from_file(path: Path) -> str | None:
    try:
        raw = path.read_text(encoding="utf-8")
        payload = json.loads(raw)
    except Exception:
        return None
    if isinstance(payload, dict):
        value = payload.get("project_id")
        return value if isinstance(value, str) and value.strip() else None
    return None


@router.get("/status", response_model=CredentialStatusResponse)
def credentials_status() -> CredentialStatusResponse:
    path = _get_credentials_path()
    path_obj = Path(path) if path else None
    if not path_obj or not path_obj.exists():
        fallback = Path(__file__).resolve().parents[2] / "credentials" / "service_account.json"
        if fallback.exists():
            path_obj = fallback
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(fallback)

    configured = bool(path_obj and path_obj.exists())
    project_id = _get_project_id()
    if configured and not project_id:
        project_id = _load_project_id_from_file(path_obj)
        if project_id:
            os.environ["GCP_PROJECT_ID"] = project_id
    return CredentialStatusResponse(
        configured=configured,
        project_id=project_id,
        credentials_path=str(path_obj) if configured else None,
    )


@router.post("/upload", response_model=CredentialStatusResponse, status_code=status.HTTP_201_CREATED)
def upload_credentials(file: UploadFile = File(...)) -> CredentialStatusResponse:
    if not file.filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing file name")

    try:
        payload = json.loads(file.file.read())
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON file") from exc

    if not isinstance(payload, dict) or payload.get("type") != "service_account":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Expected a GCP service account JSON file",
        )

    project_id = payload.get("project_id")
    if not project_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Service account JSON missing project_id",
        )

    creds_dir = Path(__file__).resolve().parents[2] / "credentials"
    creds_dir.mkdir(parents=True, exist_ok=True)
    save_path = creds_dir / "service_account.json"
    save_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(save_path)
    os.environ["GCP_PROJECT_ID"] = project_id
    os.environ["GCP_AGENT_RUNNER"] = "real"

    return CredentialStatusResponse(
        configured=True,
        project_id=project_id,
        credentials_path=str(save_path),
    )
