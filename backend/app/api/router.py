from __future__ import annotations

from fastapi import APIRouter

from app.api.routes.chat import router as chat_router
from app.api.routes.credentials import router as credentials_router
from app.api.routes.projects import router as projects_router
from app.api.routes.scans import router as scans_router
from app.api.routes.external import router as external_router
from app.api.routes.admin import router as admin_router


api_router = APIRouter()
api_router.include_router(chat_router)
api_router.include_router(credentials_router)
api_router.include_router(projects_router)
api_router.include_router(scans_router)
api_router.include_router(external_router)
api_router.include_router(admin_router)