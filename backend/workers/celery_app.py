from __future__ import annotations

import os
from celery import Celery

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "mcas_workers",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["backend.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_soft_time_limit=90,
    task_time_limit=120,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_routes={
        "backend.workers.tasks.run_site_audit_task": {"queue": "audits_research"},
        "backend.workers.tasks.reap_stuck_reservations": {"queue": "billing"},
    },
    beat_schedule={
        "reap-stuck-credit-reservations-every-5m": {
            "task": "backend.workers.tasks.reap_stuck_reservations",
            "schedule": 300.0,
        },
    },
)
