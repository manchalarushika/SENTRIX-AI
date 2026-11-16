"""SENTRIX AI FastAPI application."""

from __future__ import annotations

import asyncio
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from sentrix import APP_DESCRIPTION, APP_NAME, __version__
from sentrix.api.routes import core, intelligence, soc
from sentrix.core.config import get_settings
from sentrix.core.logging import configure_logging, get_logger
from sentrix.core.realtime import hub
from sentrix.core.security import require_api_key
from sentrix.db.session import SessionLocal, init_db
from sentrix.intel.knowledge import seed_knowledge

log = get_logger("app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level, json_output=settings.app_env == "production")
    init_db()
    with SessionLocal() as db:
        seed_knowledge(db)
    hub.bind(asyncio.get_running_loop())
    if settings.app_env == "production" and not (settings.api_key and settings.api_key.get_secret_value()):
        log.warning("Running in production without API_KEY - all endpoints are unauthenticated")
    log.info("%s v%s started (LLM provider: %s, configured: %s)", APP_NAME, __version__,
             settings.llm_provider, settings.llm_configured)
    yield
    log.info("%s shutdown", APP_NAME)


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=APP_NAME, version=__version__, description=APP_DESCRIPTION, lifespan=lifespan,
                  docs_url="/docs", redoc_url="/redoc", openapi_url="/openapi.json")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-API-Key", "X-Actor"],
    )

    @app.middleware("http")
    async def request_logging(request: Request, call_next):
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
        t0 = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            log.exception("unhandled error %s %s [%s]", request.method, request.url.path, rid)
            return JSONResponse({"detail": "Internal server error", "request_id": rid}, status_code=500)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        response.headers["X-Request-ID"] = rid
        response.headers["X-Content-Type-Options"] = "nosniff"
        if request.url.path.startswith("/api"):
            log.info("%s %s -> %s (%sms)", request.method, request.url.path, response.status_code, ms,
                     extra={"request_id": rid, "duration_ms": ms})
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, exc: RequestValidationError):
        errors = [{"loc": list(e.get("loc", [])), "msg": e.get("msg"), "type": e.get("type")}
                  for e in exc.errors()]
        return JSONResponse({"detail": "Validation failed", "errors": errors}, status_code=422)

    api = APIRouter(prefix="/api", dependencies=[Depends(require_api_key)])
    api.include_router(core.router)
    api.include_router(soc.router)
    api.include_router(intelligence.router)
    app.include_router(api)

    @app.get("/", include_in_schema=False)
    def root():
        return {"application": APP_NAME, "description": APP_DESCRIPTION, "version": __version__,
                "docs": "/docs", "health": "/api/health"}

    @app.websocket("/ws/live")
    async def live(ws: WebSocket):
        key = settings.api_key.get_secret_value() if settings.api_key else ""
        if key and settings.app_env == "production" and ws.query_params.get("api_key") != key:
            await ws.close(code=4401)
            return
        await hub.connect(ws)
        await ws.send_json({"type": "connected", "data": {"service": APP_NAME}})
        try:
            while True:
                msg = await ws.receive_text()
                if msg == "ping":
                    await ws.send_json({"type": "pong", "data": {}})
        except WebSocketDisconnect:
            pass
        finally:
            hub.disconnect(ws)

    return app


app = create_app()
