from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.api.routers import assets, scans
from app.database import Base, engine

app = FastAPI(title="EASM Platform", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(assets.router)
app.include_router(scans.router)


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

    # Partial unique index: only one active job per (asset, tool) pair.
    # SQLAlchemy's Enum type uses member *names* (uppercase) for the
    # native PG enum, so raw SQL literals must match that casing.
    with engine.connect() as conn:
        conn.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_job_active "
                "ON scan_jobs (asset_id, tool) "
                "WHERE status = 'PENDING' OR status = 'RUNNING'"
            )
        )
        conn.commit()


@app.get("/health")
def health():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database unavailable: {e}") from e
