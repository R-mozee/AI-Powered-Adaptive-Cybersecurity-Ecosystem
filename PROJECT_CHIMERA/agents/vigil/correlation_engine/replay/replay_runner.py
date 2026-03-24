from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import json

from agents.vigil.correlation_engine.normalizer import normalize_event, EventNormalizationError
from agents.vigil.correlation_engine.engine import CorrelationEngine, CorrelationEngineConfig
from agents.vigil.correlation_engine.rules.loader import load_rule_file
from agents.vigil.correlation_engine.rules.validator import validate_ruleset_or_raise
from agents.vigil.correlation_engine.rules.matcher import compile_rules

from agents.vigil.correlation_engine.replay.io import read_jsonl, write_jsonl


@dataclass
class ReplayResult:
    total_input: int
    normalized_ok: int
    normalized_failed: int
    alerts_emitted: int
    errors: List[str]


def build_engine_from_rulefile(
    *,
    rule_yaml_path: str,
    rule_schema_path: str,
    engine_config: Optional[CorrelationEngineConfig] = None,
) -> CorrelationEngine:
    ruleset = load_rule_file(rule_yaml_path)
    validate_ruleset_or_raise(ruleset, schema_path=rule_schema_path, strict=True)
    compiled = compile_rules(ruleset)
    return CorrelationEngine(compiled, config=engine_config)


def _is_normalized_event(e: Dict[str, Any]) -> bool:
    required = {"event_id", "timestamp", "event_type", "source", "entities", "severity", "confidence", "raw"}
    return required.issubset(set(e.keys()))


def replay_events(
    *,
    engine: CorrelationEngine,
    events: List[Dict[str, Any]],
    default_source_if_missing: str = "replay",
    strict_normalization: bool = True,
) -> Tuple[List[Dict[str, Any]], ReplayResult]:
    alerts_out: List[Dict[str, Any]] = []
    errors: List[str] = []

    normalized_ok = 0
    normalized_failed = 0

    for idx, e in enumerate(events):
        try:
            if _is_normalized_event(e):
                normalized = e
            else:
                src = e.get("source") or default_source_if_missing
                normalized = normalize_event(e, source=src, strict=strict_normalization)
            normalized_ok += 1
        except (EventNormalizationError, Exception) as ex:
            normalized_failed += 1
            errors.append(f"event[{idx}] normalize failed: {ex}")
            continue

        # Feed into engine
        try:
            produced = engine.add_event(normalized)
            if produced:
                alerts_out.extend(produced)
        except Exception as ex:
            errors.append(f"event[{idx}] engine failed: {ex}")

    result = ReplayResult(
        total_input=len(events),
        normalized_ok=normalized_ok,
        normalized_failed=normalized_failed,
        alerts_emitted=len(alerts_out),
        errors=errors,
    )
    return alerts_out, result


def replay_jsonl_to_alerts_jsonl(
    *,
    input_events_jsonl: str,
    output_alerts_jsonl: str,
    rule_yaml_path: str,
    rule_schema_path: str,
    strict_normalization: bool = True,
) -> ReplayResult:
    engine = build_engine_from_rulefile(
        rule_yaml_path=rule_yaml_path,
        rule_schema_path=rule_schema_path,
        engine_config=None,
    )

    events = read_jsonl(input_events_jsonl)
    alerts, res = replay_events(
        engine=engine,
        events=events,
        strict_normalization=strict_normalization,
    )

    write_jsonl(output_alerts_jsonl, alerts)
    return res
