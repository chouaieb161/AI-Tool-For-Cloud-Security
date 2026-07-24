from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.database import Base, get_db
from app.main import app

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_oci_flow.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(autouse=True)
def cleanup():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    for key in ["OCI_CONFIG_FILE", "OCI_CONFIG_PROFILE", "OCI_TENANCY_OCID", "OCI_COMPARTMENT_OCID", "OCI_REGION"]:
        os.environ.pop(key, None)
    yield
    for key in ["OCI_CONFIG_FILE", "OCI_CONFIG_PROFILE", "OCI_TENANCY_OCID", "OCI_COMPARTMENT_OCID", "OCI_REGION"]:
        os.environ.pop(key, None)


def test_create_project_accepts_cloud_provider():
    response = client.post(
        "/projects",
        json={"name": "OCI Test", "gcp_project_id": "oci-123", "cloud_provider": "OCI"},
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["cloud_provider"] == "OCI"


def test_upload_oci_credentials_sets_config_file(tmp_path):
    config_path = tmp_path / "config"
    config_path.write_text("[DEFAULT]\nregion=us-phoenix-1\n", encoding="utf-8")

    with config_path.open("rb") as handle:
        response = client.post(
            "/credentials/upload?provider=OCI",
            files={"file": ("oci-config", handle, "text/plain")},
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["configured"] is True
    assert payload["provider"] == "OCI"
    assert os.environ.get("OCI_CONFIG_FILE")
    assert Path(os.environ["OCI_CONFIG_FILE"]).exists()
