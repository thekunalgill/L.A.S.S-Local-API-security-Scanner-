from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from sqlalchemy import DateTime, Float, Integer, JSON, String, Text, create_engine, desc
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .schemas import ScanResponse


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    score: Mapped[int | None] = mapped_column(Integer)
    status_code: Mapped[int | None] = mapped_column(Integer)
    latency_ms: Mapped[float | None] = mapped_column(Float)
    findings: Mapped[list[dict[str, str]]] = mapped_column(JSON, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def _default_database_url() -> str:
    configured_path = os.getenv("LASS_DB_PATH")
    database_path = (
        Path(configured_path).expanduser()
        if configured_path
        else Path.home() / ".local" / "share" / "lass" / "scans.sqlite3"
    )
    database_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{database_path.resolve().as_posix()}"


class ScanStorage:
    def __init__(self, database_url: str | None = None):
        self.engine = create_engine(
            database_url or _default_database_url(),
            connect_args={"check_same_thread": False},
        )
        self._session_factory = sessionmaker(self.engine, expire_on_commit=False)
        Base.metadata.create_all(self.engine)

    def save(self, scan: ScanResponse) -> ScanResponse:
        record = ScanRecord(
            id=scan.id,
            target_url=scan.target_url,
            status=scan.status,
            score=scan.score,
            status_code=scan.status_code,
            latency_ms=scan.latency_ms,
            findings=scan.findings,
            error=scan.error,
            timestamp=scan.timestamp,
        )
        with Session(self.engine) as session:
            session.add(record)
            session.commit()
        return scan

    def recent(self, limit: int = 20) -> list[ScanResponse]:
        with Session(self.engine) as session:
            records = session.query(ScanRecord).order_by(desc(ScanRecord.timestamp)).limit(limit).all()
            return [
                ScanResponse(
                    id=record.id,
                    target_url=record.target_url,
                    status=record.status,
                    score=record.score,
                    status_code=record.status_code,
                    latency_ms=record.latency_ms,
                    findings=record.findings,
                    error=record.error,
                    timestamp=record.timestamp,
                )
                for record in records
            ]