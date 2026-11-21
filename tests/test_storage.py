from datetime import datetime, timezone

from lass.schemas import ScanResponse
from lass.storage import ScanStorage


def test_scan_storage_round_trips_history(tmp_path):
    storage = ScanStorage(f"sqlite:///{tmp_path / 'history.sqlite3'}")
    scan = ScanResponse(
        id="scan-1",
        target_url="http://192.168.1.5:8000/health",
        status="completed",
        score=85,
        status_code=200,
        latency_ms=12.5,
        findings=[
            {
                "code": "missing_header",
                "severity": "low",
                "title": "Missing header",
                "detail": "Header is absent.",
                "recommendation": "Add the header.",
            }
        ],
        error=None,
        timestamp=datetime(2026, 11, 21, tzinfo=timezone.utc),
    )

    storage.save(scan)
    history = storage.recent()

    assert len(history) == 1
    assert history[0].model_dump(exclude={"timestamp"}) == scan.model_dump(
        exclude={"timestamp"}
    )
    assert history[0].timestamp.replace(tzinfo=timezone.utc) == scan.timestamp