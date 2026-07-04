"""
Celery workers — async background jobs:
  - connector_sync: pull from CrowdStrike/Tenable/Axonius → MACE ingest
  - epss_refresh: daily EPSS score updates from FIRST.org
  - acs_decay_sweep: recalculate ACS for all assets every hour
  - compliance_sla_check: flag breached SLA deadlines every 15 min
"""
from celery import Celery
from celery.schedules import crontab
from app.core.config import settings

celery = Celery(
    "mace_platform",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.tasks"],
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    beat_schedule={
        # Sync all active connectors every hour
        "connector-sync-hourly": {
            "task": "app.workers.tasks.sync_all_connectors",
            "schedule": crontab(minute=0),
        },
        # Refresh EPSS scores daily at 2 AM UTC
        "epss-refresh-daily": {
            "task": "app.workers.tasks.refresh_epss_scores",
            "schedule": crontab(hour=2, minute=0),
        },
        # Recalculate ACS for all tenant assets every 30 minutes
        "acs-decay-sweep": {
            "task": "app.workers.tasks.acs_decay_sweep",
            "schedule": crontab(minute="*/30"),
        },
        # Check SLA breaches every 15 minutes
        "sla-breach-check": {
            "task": "app.workers.tasks.check_sla_breaches",
            "schedule": crontab(minute="*/15"),
        },
    },
)
