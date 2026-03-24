from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class CorrelatedAlert:
    alert_id: str
    created_at: str  # ISO timestamp (UTC)
    rule_id: str
    rule_name: str
    severity: str  # low/medium/high/critical
    confidence: float
    description: str

    # Evidence
    event_ids: List[str]
    events: List[Dict[str, Any]]  # normalized events (small number, OK to include)

    # Helpful correlation context
    matched_entities: Dict[str, Any]
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "created_at": self.created_at,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "event_ids": self.event_ids,
            "events": self.events,
            "matched_entities": self.matched_entities,
            "notes": self.notes,
        }
