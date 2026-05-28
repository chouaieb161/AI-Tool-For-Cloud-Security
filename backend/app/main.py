from __future__ import annotations

from fastapi import FastAPI

from app.api.router import api_router
from app.core.config import settings
from app.db.database import Base, engine


def create_app() -> FastAPI:
    app = FastAPI(title=settings.APP_NAME)
    app.include_router(api_router)

    @app.on_event("startup")
    def on_startup() -> None:
        Base.metadata.create_all(bind=engine)

    return app


app = create_app()
