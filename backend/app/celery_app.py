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
        # Every 2 minutes, mark RUNNING jobs as FAILED if they've been
        # stuck for more than 5 minutes (worker crash / lost task due to
        # acks_late=False).  Shorter than the old 30-min window because
        # no legitimate tool takes > 2 min, and the wave orchestrator
        # needs prompt recovery.  The orchestrator's collector also has
        # a 3-min stuck cutoff as a first line of defense.
        "reap-stuck-jobs": {
            "task": "app.tasks.reap_stuck_jobs",
            "schedule": 120.0,  # seconds
        },
    },
)
