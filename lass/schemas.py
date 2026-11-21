from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target_url: str = Field(min_length=1, max_length=2048)
    authorized: bool = False


class ScanResponse(BaseModel):
    id: str
    target_url: str
    status: str
    score: int | None
    status_code: int | None
    latency_ms: float | None
    findings: list[dict[str, str]]
    error: str | None
    timestamp: datetime
