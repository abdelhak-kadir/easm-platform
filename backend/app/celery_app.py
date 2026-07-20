import os

from celery import Celery

REDIS_URL = os.environ.get("REDIS_URL")

celery_app = Celery(
    "easm",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["app.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
)
