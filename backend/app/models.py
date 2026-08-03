import enum
from datetime import UTC, datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class AssetType(enum.StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"


class ScanStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ToolName(enum.StrEnum):
    WHOIS = "whois"
    AMASS = "amass"
    THEHARVESTER = "theharvester"
    HTTPX = "httpx"
    NMAP = "nmap"
    SHODAN = "shodan"
    CENSYS = "censys"
    EMAIL_SECURITY = "email_security"
    HIBP = "hibp"
    REVERSE_DNS = "reverse_dns"
    SUBFINDER = "subfinder"


class Severity(enum.StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    value: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    asset_type: Mapped[AssetType] = mapped_column(Enum(AssetType), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (UniqueConstraint("value", "asset_type", name="uq_asset_value_type"),)

    scan_jobs: Mapped[list["ScanJob"]] = relationship(
        back_populates="asset", foreign_keys="[ScanJob.asset_id]"
    )


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), nullable=False)
    tool: Mapped[ToolName] = mapped_column(Enum(ToolName), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False
    )
    error_message: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    spawned_asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    spawned_job_id: Mapped[int | None] = mapped_column(ForeignKey("scan_jobs.id"), nullable=True)

    asset: Mapped["Asset"] = relationship(back_populates="scan_jobs", foreign_keys=[asset_id])
    results: Mapped[list["ScanResult"]] = relationship(back_populates="scan_job")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    raw_data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan_job: Mapped["ScanJob"] = relationship(back_populates="results")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan_result")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_result_id: Mapped[int] = mapped_column(ForeignKey("scan_results.id"), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.INFO)
    data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan_result: Mapped["ScanResult"] = relationship(back_populates="findings")
