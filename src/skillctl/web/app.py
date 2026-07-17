from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import RequestResponseEndpoint

from skillctl.web.routes import (
    ApprovalRecorder,
    ReadService,
    RuntimeInventoryReader,
    RuntimeInventoryRefresher,
    build_router,
)
from skillctl.web.readiness import ReadinessProvider
from skillctl.web.security import DecisionTokenStore, InventoryRefreshTokenStore


@dataclass(frozen=True)
class PortalReadProviders:
    readiness: ReadinessProvider
    runtime_inventory: RuntimeInventoryReader
    runtime_inventory_refresher: RuntimeInventoryRefresher | None = None
    inventory_refresh_tokens: InventoryRefreshTokenStore | None = None


def create_app(
    read_service: ReadService,
    approval_service: ApprovalRecorder,
    decision_tokens: DecisionTokenStore,
    readiness_provider: ReadinessProvider | PortalReadProviders,
) -> FastAPI:
    if isinstance(readiness_provider, PortalReadProviders):
        readiness = readiness_provider.readiness
        runtime_inventory_reader: RuntimeInventoryReader | None = (
            readiness_provider.runtime_inventory
        )
        runtime_inventory_refresher = readiness_provider.runtime_inventory_refresher
        inventory_refresh_tokens = readiness_provider.inventory_refresh_tokens
    else:
        readiness = readiness_provider
        runtime_inventory_reader = None
        runtime_inventory_refresher = None
        inventory_refresh_tokens = None
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.mount(
        "/static",
        StaticFiles(directory=Path(__file__).parent / "static"),
        name="static",
    )
    app.include_router(
        build_router(
            read_service,
            approval_service,
            decision_tokens,
            readiness,
            runtime_inventory_reader,
            runtime_inventory_refresher,
            inventory_refresh_tokens,
        )
    )

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        try:
            response = await call_next(request)
        except Exception:
            response = HTMLResponse("Portal unavailable", status_code=500)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; img-src 'self' data:; "
            "script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

    return app
