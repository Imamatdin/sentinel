"""FastAPI application factory.

Creates the FastAPI app with:
- CORS middleware (open for dev, restrictable for prod)
- REST routes
- WebSocket endpoint
- Lifespan management (startup/shutdown)
- EngagementManager dependency injection
"""

import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware

from sentinel.config import Settings, get_settings
from sentinel.api.routes import router, get_manager
from sentinel.api.genome_routes import router as genome_router
from sentinel.api.export_routes import router as export_router
from sentinel.api.dashboard_routes import router as dashboard_router, dashboard_websocket_handler
from sentinel.api.websocket import websocket_handler
from sentinel.api.manager import EngagementManager
from sentinel.logging_config import setup_logging, get_logger

logger = get_logger(__name__)

# Module-level reference for the manager (set during lifespan)
_manager: Optional[EngagementManager] = None


def _get_manager() -> EngagementManager:
    """Dependency override that returns the actual manager."""
    if _manager is None:
        raise RuntimeError("App not started. EngagementManager is not available.")
    return _manager


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        settings: Optional Settings override (for testing)

    Returns:
        Configured FastAPI app
    """
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Manage app startup and shutdown."""
        global _manager

        # Startup
        setup_logging(
            log_level=settings.log_level,
            log_format=settings.log_format,
        )

        _manager = EngagementManager(settings=settings)

        logger.info(
            "api_server_starting",
            version=app.version,
        )

        yield

        # Shutdown
        if _manager and _manager.state.value == "running":
            logger.info("shutting_down_active_engagement")
            await _manager.stop_engagement()

        logger.info("api_server_stopped")

    app = FastAPI(
        title="SENTINEL",
        description=(
            "Autonomous AI pentesting platform. "
            "Red team AI agents attack targets while blue team AI agents defend in real-time."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS - open for development
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Override the dependency
    app.dependency_overrides[get_manager] = _get_manager

    # Mount REST routes
    app.include_router(router, prefix="/api")
    app.include_router(genome_router, prefix="/api/genome", tags=["genome"])
    app.include_router(export_router, prefix="/api/export", tags=["export"])
    app.include_router(dashboard_router, prefix="/api", tags=["dashboard"])

    # WebSocket endpoint (not under /api prefix for cleaner URL)
    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await dashboard_websocket_handler(websocket)

    return app


def run_server(host: str = "0.0.0.0", port: int = 8000) -> None:
    """Run the server directly (for development).

    Usage:
        python -m sentinel.api.app
        # or
        poetry run python -m sentinel.api.app
    """
    import uvicorn

    app = create_app()
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    run_server()