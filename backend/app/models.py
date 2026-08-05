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
    EMAIL = "email"
    SERVICE = "service"
    TECHNOLOGY = "technology"


class AssetStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"


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
    MERKLEMAP = "merklemap"
    NMAP = "nmap"
    SHODAN = "shodan"
    CENSYS = "censys"
    EMAIL_SECURITY = "email_security"
    HIBP = "hibp"
    REVERSE_DNS = "reverse_dns"
    SUBFINDER = "subfinder"
    HOLEHE = "holehe"


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
    status: Mapped[AssetStatus] = mapped_column(
        Enum(AssetStatus), default=AssetStatus.PENDING, nullable=False
    )
    discovery_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("discovery_runs.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (UniqueConstraint("value", "asset_type", name="uq_asset_value_type"),)

    scan_jobs: Mapped[list["ScanJob"]] = relationship(
        back_populates="asset", foreign_keys="[ScanJob.asset_id]"
    )
    discovery_run: Mapped["DiscoveryRun"] = relationship(
        back_populates="assets", foreign_keys=[discovery_run_id]
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


class DiscoveryRun(Base):
    __tablename__ = "discovery_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    root_asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), nullable=False)
    round_number: Mapped[int] = mapped_column(Integer, default=0)
    max_rounds: Mapped[int] = mapped_column(Integer, default=5)
    status: Mapped[str] = mapped_column(String(20), default="running")
    current_round_asset_ids: Mapped[list[int] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    root_asset: Mapped["Asset"] = relationship(foreign_keys=[root_asset_id])
    assets: Mapped[list["Asset"]] = relationship(
        back_populates="discovery_run", foreign_keys="[Asset.discovery_run_id]"
    )
