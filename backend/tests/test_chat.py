from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.database import Base, get_db
from app.db.models import Project
from app.main import app

# Use an in-memory SQLite for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
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
    # Clean up after each test
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield

def test_create_session():
    db = TestingSessionLocal()
    project = Project(name="Test Project", gcp_project_id="test-gcp-123")
    db.add(project)
    db.commit()
    db.refresh(project)

    response = client.post("/chat/sessions", json={"project_id": project.id, "title": "Test Chat"})
    assert response.status_code == 201
    assert response.json()["project_id"] == project.id
    assert response.json()["title"] == "Test Chat"

def test_list_messages_empty():
    db = TestingSessionLocal()
    project = Project(name="Test Project", gcp_project_id="test-gcp-123")
    db.add(project)
    db.commit()
    db.refresh(project)

    session_res = client.post("/chat/sessions", json={"project_id": project.id})
    session_id = session_res.json()["id"]

    response = client.get(f"/chat/sessions/{session_id}/messages")
    assert response.status_code == 200
    assert response.json() == []
