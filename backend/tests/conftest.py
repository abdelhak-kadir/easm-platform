import os

# app.database creates a real SQLAlchemy engine at import time, which requires
# DATABASE_URL to be set. That's fine inside Docker (env_file provides it),
# but a bare `pytest` invocation -- locally or in CI -- has no .env sourced
# into the process environment, so importing app.models (needed even for
# pure unit tests like the shodan parse tests) blows up before a single
# test runs.
#
# `setdefault` only fills the gap: if a real DATABASE_URL/REDIS_URL is
# already present (docker-compose, a developer's exported .env, a future
# CI service container), it's left untouched.
os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
