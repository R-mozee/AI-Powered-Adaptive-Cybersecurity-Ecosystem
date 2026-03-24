from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import random
import uuid

from agents.vigil.correlation_engine.synthetic.templates import (
    template_phish_to_download,
    template_scan_to_exploit,
    SyntheticTemplate,
)
from agents.vigil.correlation_engine.replay.io import write_jsonl


def _utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _jitter_seconds(min_s: int, max_s: int) -> int:
    return random.randint(min_s, max_s)


def _make_event_from_step(step, ts: datetime, scenario_id: str, step_index: int) -> Dict[str, Any]:
    """
    Returns a *raw* event (not normalized contract), including a 'source'.
    Normalization will happen in replay runner.
    """
    e: Dict[str, Any] = {
        "scenario_id": scenario_id,
        "scenario_step": step_index,
        "timestamp": _utc_iso(ts),
        "event_type": step.event_type,
        "source": step.source,
        "severity": step.severity,
        "confidence": step.confidence,
        "tags": step.tags,
    }
    # put entities in the most likely raw locations (Step 1 normalizer will map)
    # We'll keep them as direct keys to be picked up by _normalize_entities.
    e.update(step.entities)
    return e


def generate_from_template(
    tmpl: SyntheticTemplate,
    *,
    num_scenarios: int = 10,
    start_time_utc: Optional[datetime] = None,
    inter_step_jitter: tuple[int, int] = (30, 300),  # seconds
    between_scenarios_gap: tuple[int, int] = (600, 1800),  # seconds
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    base = start_time_utc or datetime.now(timezone.utc)

    cur = base
    for i in range(num_scenarios):
        scenario_id = f"{tmpl.name.upper()}_{i}_{uuid.uuid4().hex[:6]}"

        # steps
        t = cur
        for si, step in enumerate(tmpl.steps):
            if si > 0:
                t = t + timedelta(seconds=_jitter_seconds(*inter_step_jitter))
            out.append(_make_event_from_step(step, t, scenario_id, si))

        # move forward before next scenario
        cur = t + timedelta(seconds=_jitter_seconds(*between_scenarios_gap))

    return out


def generate_mixed_scenarios(
    *,
    num_each: int = 10,
) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    events.extend(generate_from_template(template_phish_to_download(), num_scenarios=num_each))
    events.extend(generate_from_template(template_scan_to_exploit(), num_scenarios=num_each))
    # shuffle for realism (still time-ordered by timestamps mostly, but might interleave)
    events.sort(key=lambda e: e["timestamp"])
    return events


def write_synthetic_events_jsonl(path: str, *, num_each: int = 10) -> None:
    events = generate_mixed_scenarios(num_each=num_each)
    write_jsonl(path, events)
