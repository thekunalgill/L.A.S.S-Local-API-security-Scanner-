from __future__ import annotations


DEDUCTIONS = {"high": 20, "medium": 10, "low": 5}


def score_findings(findings: list[dict[str, str]]) -> int:
    return max(0, 100 - sum(DEDUCTIONS.get(item["severity"], 0) for item in findings))