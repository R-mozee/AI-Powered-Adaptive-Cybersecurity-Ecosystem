from __future__ import annotations

from typing import Any, Dict, List, Tuple

from agents.vigil.correlation_engine.golden.golden_events import golden_event_stream
from agents.vigil.correlation_engine.replay.replay_runner import build_engine_from_rulefile, replay_events


def run_golden(
    *,
    rule_yaml_path: str,
    rule_schema_path: str,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    engine = build_engine_from_rulefile(
        rule_yaml_path=rule_yaml_path,
        rule_schema_path=rule_schema_path,
    )
    alerts, res = replay_events(engine=engine, events=golden_event_stream(), strict_normalization=True)
    return alerts, res.errors
