from __future__ import annotations

import argparse

from sqlalchemy import select

from app.db.database import Base, SessionLocal, engine
from app.db.models import Project
from app.services.agent_service import _mock_scan_result, persist_scan_result


def get_or_create_project(db, name: str, gcp_project_id: str) -> Project:
    project = db.execute(
        select(Project).where(Project.gcp_project_id == gcp_project_id)
    ).scalar_one_or_none()
    if project:
        return project

    project = Project(name=name, gcp_project_id=gcp_project_id)
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


def main() -> None:
    parser = argparse.ArgumentParser(description="Populate DB with mock GCP scan results")
    parser.add_argument("--project-name", default="Demo GCP Project")
    parser.add_argument("--gcp-project-id", default="demo-gcp-project-001")
    args = parser.parse_args()

    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        project = get_or_create_project(db, args.project_name, args.gcp_project_id)
        mock_result = _mock_scan_result(project)
        scan_id = persist_scan_result(db, project, mock_result)
        db.commit()
        print(f"Mock scan created successfully. project_id={project.id}, scan_id={scan_id}")


if __name__ == "__main__":
    main()
