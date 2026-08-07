import os

from celery import Celery

REDIS_URL = os.environ.get("REDIS_URL")

celery_app = Celery(
    "easm",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["app.tasks", "app.orchestrator"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    # acks_late=False (default): tasks acknowledged before execution.
    # If a worker crashes mid-task the job stays RUNNING forever.
    # Recovery: the reap_stuck_jobs periodic task (see tasks.py)
    # marks timed-out RUNNING jobs as FAILED.
    #
    # Switching to acks_late=True would redeliver tasks after worker
    # crashes but requires every task to be idempotent (run_tool_scan
    # currently is not — duplicate ScanResults without a unique
    # constraint on version).  Deferred until task idempotency is
    # fully verified.
    beat_schedule={
        # Every 5 minutes, mark RUNNING jobs as FAILED if they've been
        # stuck for more than 30 minutes (worker crash / lost).
        "reap-stuck-jobs": {
            "task": "app.tasks.reap_stuck_jobs",
            "schedule": 300.0,  # seconds
        },
    },
)
