from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ExpectedAlert:
    rule_id: str
    must_include_event_types: List[str]
    must_have_any_entity: List[str]  # entity keys expected in matched_entities
    min_confidence: float
    min_severity_score: int


def expected_alerts() -> List[ExpectedAlert]:
    return [
        ExpectedAlert(
            rule_id="R001",
            must_include_event_types=["phishing_detected", "malware_download"],
            must_have_any_entity=["user", "domain"],
            min_confidence=0.60,
            min_severity_score=6,
        ),
        ExpectedAlert(
            rule_id="R002",
            must_include_event_types=["port_scan", "exploit_attempt"],
            must_have_any_entity=["dst_ip"],
            min_confidence=0.65,
            min_severity_score=8,
        ),
    ]
