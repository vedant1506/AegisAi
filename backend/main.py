"""
AegisAI — FastAPI Application Entry Point
==========================================
Initialises the FastAPI app with:
  - CORS middleware (reads allowed origins from .env)
  - Structured logging via structlog
  - API router registration
  - Lifespan context manager for startup/shutdown hooks
  - Health check endpoint

Run: uvicorn main:app --reload --port 8000
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.scan_router import router as scan_router
from app.core.config import settings

# ── Structlog configuration ────────────────────────────────────
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

# ── Lifespan ──────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and graceful shutdown hooks."""
    logger.info("aegisai.startup", version=settings.app_version)
    # TODO: Initialise DB connection pool, Redis, LangGraph engine here
    yield
    logger.info("aegisai.shutdown")
    # TODO: Close connection pools gracefully

# ── App factory ───────────────────────────────────────────────
def create_app() -> FastAPI:
    application = FastAPI(
        title="AegisAI API",
        description=(
            "Autonomous Multi-Agent Framework for Hybrid Application Security (VAPT). "
            "Provides endpoints for triggering SAST, DAST, and AI exploit reasoning scans."
        ),
        version=settings.app_version,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ── CORS Middleware ────────────────────────────────────────
    # Origins are comma-separated in .env: CORS_ORIGINS=http://localhost:3000,...
    cors_origins: list[str] = [
        origin.strip()
        for origin in settings.cors_origins.split(",")
        if origin.strip()
    ]

    application.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Router Registration ────────────────────────────────────
    application.include_router(scan_router, prefix="/api/v1")

    return application


app = create_app()


# ── Health Check ──────────────────────────────────────────────
@app.get(
    "/health",
    tags=["system"],
    summary="Service health check",
    response_description="Returns service status and version.",
)
async def health_check() -> JSONResponse:
    """
    Lightweight health check used by Docker and load balancers.
    Returns 200 OK when the service is ready to accept requests.
    """
    return JSONResponse(
        content={
            "status": "healthy",
            "service": "aegisai-backend",
            "version": settings.app_version,
        }
    )
