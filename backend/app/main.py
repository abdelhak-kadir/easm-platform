import logging
import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.api.routers import assets, scans
from app.database import Base, engine

_logger = logging.getLogger(__name__)

app = FastAPI(title="EASM Platform", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(assets.router)
app.include_router(scans.router)

# API keys that tools need to function.  Missing keys are WARNING-logged
# at startup so operators know which tools will degrade or fail.
_EXPECTED_API_KEYS = {
    "SHODAN_API_KEY": "Shodan, Censys (reverse IP lookup)",
    "CENSYS_API_ID": "Censys host search",
    "CENSYS_API_SECRET": "Censys host search",
    "MERKLEMAP_API_KEY": "MerkleMap certificate search",
    "PUBLICWWW_API_KEY": "PublicWWW source-code search",
    "CERTSPOTTER_API_KEY": "CertSpotter (optional, higher limits)",
}


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

    # Warn about missing API keys so operators know which tools will be degraded.
    missing = [k for k, _tools in _EXPECTED_API_KEYS.items() if not os.environ.get(k)]
    if missing:
        _logger.warning(
            "Missing API keys — these tools will fail or return no data: %s. "
            "Copy backend/.env.example to backend/.env and fill in the keys.",
            ", ".join(missing),
        )
    else:
        _logger.info("All expected API keys are set — full tool coverage available.")


@app.get("/health")
def health():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database unavailable: {e}") from e
