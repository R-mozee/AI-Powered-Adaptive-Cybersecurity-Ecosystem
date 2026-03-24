from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Protocol, List, Optional

from agents.vigil.correlation_engine.replay.io import append_jsonl


class AlertSink(Protocol):
    def handle(self, alert: Dict[str, Any]) -> None:
        ...


@dataclass
class JsonlAlertSink:
    path: str

    def handle(self, alert: Dict[str, Any]) -> None:
        append_jsonl(self.path, alert)


@dataclass
class InMemoryAlertSink:
    alerts: List[Dict[str, Any]]

    def handle(self, alert: Dict[str, Any]) -> None:
        self.alerts.append(alert)
