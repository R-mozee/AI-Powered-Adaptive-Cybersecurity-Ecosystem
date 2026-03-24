from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class SyntheticStep:
    event_type: str
    source: str
    severity: int
    confidence: float
    # entity keys to populate (they become entities.* after normalization)
    entities: Dict[str, Any]
    # optional tags
    tags: List[str]


@dataclass(frozen=True)
class SyntheticTemplate:
    name: str
    steps: Tuple[SyntheticStep, ...]


def template_phish_to_download() -> SyntheticTemplate:
    return SyntheticTemplate(
        name="phish_to_download",
        steps=(
            SyntheticStep(
                event_type="phishing_detected",
                source="phishing_detector",
                severity=6,
                confidence=0.9,
                entities={"user": "alice", "domain": "evil.com", "url": "https://evil.com/login"},
                tags=["phishing"],
            ),
            SyntheticStep(
                event_type="malware_download",
                source="network_analysis",
                severity=7,
                confidence=0.8,
                entities={"user": "alice", "domain": "evil.com", "url": "https://evil.com/payload.exe"},
                tags=["download"],
            ),
        ),
    )


def template_scan_to_exploit() -> SyntheticTemplate:
    return SyntheticTemplate(
        name="scan_to_exploit",
        steps=(
            SyntheticStep(
                event_type="port_scan",
                source="network_analysis",
                severity=4,
                confidence=0.75,
                entities={"src_ip": "192.168.1.50", "dst_ip": "10.0.0.5"},
                tags=["recon"],
            ),
            SyntheticStep(
                event_type="exploit_attempt",
                source="network_analysis",
                severity=9,
                confidence=0.9,
                entities={"src_ip": "192.168.1.50", "dst_ip": "10.0.0.5"},
                tags=["exploit"],
            ),
        ),
    )
