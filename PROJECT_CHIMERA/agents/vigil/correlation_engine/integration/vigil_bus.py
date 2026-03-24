from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from agents.vigil.correlation_engine.normalizer import normalize_event, EventNormalizationError
from agents.vigil.correlation_engine.rules.loader import load_rule_file
from agents.vigil.correlation_engine.rules.validator import validate_ruleset_or_raise
from agents.vigil.correlation_engine.rules.matcher import compile_rules
from agents.vigil.correlation_engine.engine import CorrelationEngine

from agents.vigil.correlation_engine.integration.adapters import (
    adapt_network_anomaly,
    adapt_phishing_alert,
    adapt_url_intel,
)
from agents.vigil.correlation_engine.integration.sinks import AlertSink
from agents.vigil.correlation_engine.integration.config import CorrelationIntegrationConfig


@dataclass
class EmitResult:
    normalized_event: Optional[Dict[str, Any]]
    alerts: List[Dict[str, Any]]
    error: Optional[str] = None


class VigilCorrelationBus:
    """
    One object held by VIGIL:
      bus = VigilCorrelationBus.from_config(...)
      bus.emit(event, kind="network")
    """

    def __init__(
        self,
        *,
        engine: CorrelationEngine,
        sink: Optional[AlertSink],
        strict_normalization: bool = True,
    ):
        self.engine = engine
        self.sink = sink
        self.strict_normalization = strict_normalization

    @staticmethod
    def from_config(cfg: CorrelationIntegrationConfig, sink: Optional[AlertSink]) -> "VigilCorrelationBus":
        ruleset = load_rule_file(cfg.rule_yaml_path)
        validate_ruleset_or_raise(ruleset, schema_path=cfg.rule_schema_path, strict=True)
        compiled = compile_rules(ruleset)
        engine = CorrelationEngine(compiled, config=cfg.engine_config)
        return VigilCorrelationBus(engine=engine, sink=sink, strict_normalization=cfg.strict_normalization)

    def emit(self, payload: Dict[str, Any], *, kind: str = "raw") -> EmitResult:
        """
        kind:
          - "network"    -> adapt_network_anomaly
          - "phishing"   -> adapt_phishing_alert
          - "url_intel"  -> adapt_url_intel
          - "raw"        -> assumes payload already has event_type/timestamp/source etc.
        """
        try:
            if kind == "network":
                raw = adapt_network_anomaly(payload)
            elif kind == "phishing":
                raw = adapt_phishing_alert(payload)
            elif kind == "url_intel":
                raw = adapt_url_intel(payload)
            elif kind == "raw":
                raw = dict(payload)
                raw.setdefault("source", "vigil_raw")
            else:
                return EmitResult(normalized_event=None, alerts=[], error=f"Unknown kind={kind!r}")

            normalized = normalize_event(raw, source=raw["source"], strict=self.strict_normalization)

            alerts = self.engine.add_event(normalized) or []

            if self.sink:
                for a in alerts:
                    self.sink.handle(a)

            return EmitResult(normalized_event=normalized, alerts=alerts, error=None)

        except EventNormalizationError as ex:
            return EmitResult(normalized_event=None, alerts=[], error=f"Normalization failed: {ex}")
        except Exception as ex:
            return EmitResult(normalized_event=None, alerts=[], error=f"Emit failed: {ex}")
