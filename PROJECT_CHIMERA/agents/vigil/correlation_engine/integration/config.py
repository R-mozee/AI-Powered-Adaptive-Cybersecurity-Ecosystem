from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Optional, Tuple

from agents.vigil.correlation_engine.engine import CorrelationEngineConfig


@dataclass(frozen=True)
class CorrelationIntegrationConfig:
    # Where your rule files live
    rule_yaml_path: str = "agents/vigil/correlation_engine/rules/basic_rules.yaml"
    rule_schema_path: str = "agents/vigil/correlation_engine/rules/schema/rule_schema.json"

    # Output for your UI / logs (JSONL of alerts)
    alerts_jsonl_path: str = "agents/vigil/correlation_engine/data/processed/correlation_alerts.jsonl"

    # Normalization strictness
    strict_normalization: bool = True

    # Engine buffer/dedupe tuning (safe defaults)
    engine_config: CorrelationEngineConfig = CorrelationEngineConfig(
        buffer_retention=timedelta(hours=6),
        dedupe=True,
        dedupe_bucket=timedelta(minutes=10),
        dedupe_key_entity_preference=(
            "entities.dst_ip",
            "entities.src_ip",
            "entities.ip",
            "entities.domain",
            "entities.url",
            "entities.user",
            "entities.host",
        ),
    )
