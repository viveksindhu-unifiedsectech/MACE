from fastapi import APIRouter
from .endpoints import auth, assets, correlation, incidents, admin, billing, auth_extensions, files

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(assets.router)
api_router.include_router(correlation.router)
api_router.include_router(incidents.router)
api_router.include_router(admin.router)
api_router.include_router(billing.router)
api_router.include_router(auth_extensions.router)
api_router.include_router(files.router)
