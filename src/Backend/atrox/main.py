from contextlib import asynccontextmanager

from fastapi import FastAPI

from atrox.api.discovery import router as discovery_router
from atrox.api.health import router as health_router
from atrox.api.vulnscan import router as vulnscan_router
from atrox.config import get_settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        lifespan=lifespan,
    )
    application.include_router(health_router)
    application.include_router(discovery_router)
    application.include_router(vulnscan_router)
    return application


app = create_app()
