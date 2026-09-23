"""
AegisAI — Celery Application Factory
======================================
Configures the Celery distributed task queue with Redis as
the broker and result backend.

Workers are started with:
    celery -A app.tasks.celery_app worker --loglevel=info

For local dev without Docker:
    Start Redis: redis-server (or use docker-compose up redis)
    Then start worker in a separate terminal.
"""

from __future__ import annotations

from celery import Celery

from app.core.config import settings

# -- Celery app factory ----------------------------------------
celery_app = Celery(
    "aegisai",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.tasks.scan_tasks"],
)

celery_app.conf.update(
    # Serialisation
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    # Timing
    task_soft_time_limit=1800,   # 30 min soft limit
    task_time_limit=3600,        # 60 min hard kill
    result_expires=86400,        # 24 h result TTL
    # Retry behaviour
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    # Routing
    task_routes={
        "app.tasks.scan_tasks.run_full_scan": {"queue": "aegis_scans"},
    },
    # Beat schedule (future use)
    beat_schedule={},
)
